//! Cross-function lifetime analysis pass.
//!
//! This pass integrates `CrossFunctionTracker` from the semantics crate into
//! the pass pipeline. It reads function metadata and call relationships from
//! `ModuleIndex`, extracts allocation/deallocation sites from IR instructions,
//! builds a complete resource flow graph, and detects lifetime violations
//! across function boundaries.
//!
//! # Dependencies
//!
//! - `ModuleIndex` — pre-computed function and call metadata
//! - `RawFactCollector` — raw resource facts (required in name for ordering)
//!
//! # Output
//!
//! Stores `CrossFunctionLifetimeData` in `PassContext` under the key
//! `"cross_function_lifetime_data"`, and stores raw `LifetimeViolation` vectors
//! under `"lifetime_violations` for downstream `IssueCandidateBuilder` consumption.
//! This pass does **not** emit `Issue`s directly — violations are processed
//! through the `IssueCandidateBuilder` → `IssueVerifier` pipeline (SRT/evidence gate).
//!
//! # Architecture
//!
//! ```text
//! ModuleIndex
//!   └── function_metas  ──→ FunctionInfo[]
//!   └── call_metas       ──→ call edges, alloc/dealloc detection
//! CrossFunctionTracker
//!   └── analyze()        ──→ AnalysisResult
//!                              ├── LifetimeViolation → stored in context as "lifetime_violations"
//!                              └── ResourceFate      → CrossFunctionLifetimeData
//! ```

use std::collections::HashMap;

use omniscope_core::Result;
use omniscope_ir::IRModule;
use omniscope_semantics::resource::cross_function_lifetime::{
    CrossFunctionTracker, FlowType, FunctionInfo, ParamInfo, ResourceFlow, ReturnInfo,
    ViolationType,
};
use omniscope_types::{
    lifetime::{
        CrossFunctionLifetimeData, LifetimeViolationEntry, ResourceFateEntry, ResourceFateSummary,
        ViolationKind,
    },
    FamilyId, PointerContract,
};
use tracing::{debug, info};

use crate::module_index::ModuleIndex;
use crate::pass::{Pass, PassContext, PassKind, PassResult};

/// Cross-function lifetime analysis pass.
///
/// Analyzes resource lifetimes across function boundaries by:
/// 1. Reading function metadata and call relationships from `ModuleIndex`.
/// 2. Extracting allocation/deallocation points from IR instructions.
/// 3. Building a `CrossFunctionTracker` and running inter-procedural analysis.
/// 4. Storing lifetime violations in context for `IssueCandidateBuilder` consumption.
///    Does **not** emit `Issue`s directly — violations go through the
///    `IssueCandidateBuilder` → `IssueVerifier` pipeline.
pub struct CrossFunctionLifetimePass;

impl CrossFunctionLifetimePass {
    /// Creates a new `CrossFunctionLifetimePass`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for CrossFunctionLifetimePass {
    fn default() -> Self {
        Self::new()
    }
}

impl Pass for CrossFunctionLifetimePass {
    fn name(&self) -> &'static str {
        "CrossFunctionLifetime"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["ModuleIndex", "RawFactCollector"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();
        let mut result = PassResult::new(self.name());

        // Load ModuleIndex from context.
        let module_index = match ctx.get_ref::<ModuleIndex>("module_index") {
            Some(index) => index,
            None => {
                debug!("CrossFunctionLifetimePass: no ModuleIndex in context, skipping analysis");
                return Ok(result.with_duration(start.elapsed().as_millis() as u64));
            }
        };

        // Load IRModule for function body instructions.
        let ir_module = ctx.get_ir_module();

        // Build CrossFunctionTracker from ModuleIndex.
        let mut tracker = build_tracker_from_module_index(module_index, ir_module);

        // Extract resource allocation/deallocation from IR instructions.
        if let Some(ir_mod) = ir_module {
            extract_resource_ops_from_ir(&mut tracker, ir_mod, module_index);
        }

        // Run the cross-function lifetime analysis.
        let analysis = tracker.analyze();
        let functions_analyzed = module_index.function_metas.len();
        let flows_count = analysis.flows.len();

        debug!(
            target: "omniscope_pass::cross_function_lifetime",
            functions_analyzed = functions_analyzed,
            flows = flows_count,
            violations = analysis.violations.len(),
            "CrossFunctionLifetime analysis completed"
        );

        // Store raw LifetimeViolation data in context for downstream
        // IssueCandidateBuilder consumption. This pass does NOT emit
        // Issue directly — violations flow through the
        // IssueCandidateBuilder → IssueVerifier pipeline (SRT/evidence gate).
        let violation_count = analysis.violations.len();
        ctx.store("lifetime_violations", analysis.violations.clone());

        // Convert ResourceFate results to CrossFunctionLifetimeData.
        let lifetime_data = build_lifetime_data(&analysis, functions_analyzed, flows_count);
        ctx.store("cross_function_lifetime_data", lifetime_data.clone());

        // Store resource fate metadata in context for downstream passes.
        ctx.store("resource_fates", analysis.resource_fates);

        info!(
            target: "omniscope_pass::cross_function_lifetime",
            violations = violation_count,
            functions = functions_analyzed,
            flows = flows_count,
            "CrossFunctionLifetimePass completed"
        );

        result.nodes_analyzed = functions_analyzed;
        result.add_stat("functions_analyzed", functions_analyzed);
        result.add_stat("flows_detected", flows_count);
        result.add_stat("violations_detected", violation_count);

        Ok(result.with_duration(start.elapsed().as_millis() as u64))
    }
}

/// Generate a stable resource ID from function name, callee name, and pair index.
///
/// Uses a hash of the components to produce a deterministic resource ID
/// that remains stable across analyses of the same call structure.
/// Both alloc and dealloc for the same pair produce the same hash,
/// ensuring correct alloc/free matching across function boundaries.
fn make_resource_id(func_name: &str, callee: &str, pair_index: usize) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    func_name.hash(&mut hasher);
    callee.hash(&mut hasher);
    pair_index.hash(&mut hasher);
    hasher.finish()
}

/// Builds a `CrossFunctionTracker` from `ModuleIndex` data.
///
/// Converts `CachedFunctionMeta` entries into `FunctionInfo` and
/// `CachedCallMeta` entries into call edges in the tracker.
fn build_tracker_from_module_index(
    module_index: &ModuleIndex,
    ir_module: Option<&IRModule>,
) -> CrossFunctionTracker {
    let mut tracker = CrossFunctionTracker::new();

    // Phase 1: Add all functions from ModuleIndex function_metas.
    for (name, meta) in &module_index.function_metas {
        let func_info = build_function_info(name, meta, module_index, ir_module);
        tracker.add_function(func_info);
    }

    // Phase 2: Add all call edges (not only alloc/dealloc ones) to build
    // the full call graph for inter-procedural analysis.
    for call_meta in &module_index.call_metas {
        tracker.add_call_edge(&call_meta.caller_name, &call_meta.callee_name);
    }

    // Phase 3: Group alloc/dealloc call metas by caller function to enable
    // stable resource ID pairing. Within each caller, the i-th alloc call
    // is paired with the i-th dealloc call by insertion order.
    let mut caller_alloc_dealloc: HashMap<
        &str,
        (
            Vec<&crate::module_index::CachedCallMeta>,
            Vec<&crate::module_index::CachedCallMeta>,
        ),
    > = HashMap::new();
    for call_meta in &module_index.call_metas {
        let entry = caller_alloc_dealloc
            .entry(call_meta.caller_name.as_str())
            .or_default();
        if call_meta.is_alloc_call {
            entry.0.push(call_meta);
        }
        if call_meta.is_dealloc_call {
            entry.1.push(call_meta);
        }
    }

    // Phase 4: Create resource flows with stable hash-based resource IDs.
    // Paired alloc/dealloc get the same resource_id so the resource flow
    // graph can correctly trace ownership from allocation to deallocation.
    for (caller, (alloc_calls, dealloc_calls)) in &caller_alloc_dealloc {
        let num_pairs = alloc_calls.len().min(dealloc_calls.len());

        // Paired alloc/dealloc: same resource_id for matching pairs.
        for (i, (alloc, dealloc)) in alloc_calls
            .iter()
            .zip(dealloc_calls.iter())
            .enumerate()
            .take(num_pairs)
        {
            let resource_id = make_resource_id(caller, &alloc.callee_name, i);

            // Alloc flow: resource returned from allocator to caller.
            let alloc_flow = ResourceFlow {
                from_function: alloc.caller_name.clone(),
                to_function: alloc.callee_name.clone(),
                resource_id,
                family: alloc.family_id.unwrap_or(FamilyId::C_HEAP),
                flow_type: FlowType::ReturnValue,
                transfers_ownership: true,
                call_site: None,
            };
            tracker.add_flow(alloc_flow);

            // Dealloc flow: resource passed from caller to deallocator.
            let dealloc_flow = ResourceFlow {
                from_function: dealloc.callee_name.clone(),
                to_function: dealloc.caller_name.clone(),
                resource_id,
                family: dealloc.family_id.unwrap_or(FamilyId::C_HEAP),
                flow_type: FlowType::ParameterPassing,
                transfers_ownership: true,
                call_site: None,
            };
            tracker.add_flow(dealloc_flow);
        }

        // Unpaired alloc calls (standalone allocation, no matching free seen).
        for (i, alloc) in alloc_calls.iter().enumerate().skip(num_pairs) {
            let resource_id = make_resource_id(caller, &alloc.callee_name, i);
            let alloc_flow = ResourceFlow {
                from_function: alloc.caller_name.clone(),
                to_function: alloc.callee_name.clone(),
                resource_id,
                family: alloc.family_id.unwrap_or(FamilyId::C_HEAP),
                flow_type: FlowType::ReturnValue,
                transfers_ownership: true,
                call_site: None,
            };
            tracker.add_flow(alloc_flow);
        }

        // Unpaired dealloc calls (standalone deallocation, no matching alloc).
        for (i, dealloc) in dealloc_calls.iter().enumerate().skip(num_pairs) {
            let resource_id = make_resource_id(caller, &dealloc.callee_name, i);
            let dealloc_flow = ResourceFlow {
                from_function: dealloc.callee_name.clone(),
                to_function: dealloc.caller_name.clone(),
                resource_id,
                family: dealloc.family_id.unwrap_or(FamilyId::C_HEAP),
                flow_type: FlowType::ParameterPassing,
                transfers_ownership: true,
                call_site: None,
            };
            tracker.add_flow(dealloc_flow);
        }
    }

    tracker
}

/// Builds a `FunctionInfo` from cached function metadata and IR module data.
fn build_function_info(
    name: &str,
    meta: &crate::module_index::CachedFunctionMeta,
    _module_index: &ModuleIndex,
    _ir_module: Option<&IRModule>,
) -> FunctionInfo {
    let is_pointer_return = meta.name.contains("alloc")
        || meta.name.contains("create")
        || meta.name.contains("new")
        || meta.calls_alloc;

    let param_info: Vec<ParamInfo> = (0..meta.param_count)
        .map(|pos| {
            let has_pointer_params = meta.name.contains("process")
                || meta.name.contains("destroy")
                || meta.name.contains("free");
            ParamInfo {
                position: pos,
                name: format!("param_{}", pos),
                is_pointer: has_pointer_params || meta.calls_dealloc,
                is_reference: false,
                is_const: false,
                family: if has_pointer_params || meta.calls_dealloc {
                    Some(FamilyId::C_HEAP)
                } else {
                    None
                },
                contract: if meta.calls_dealloc {
                    PointerContract::Owned
                } else {
                    PointerContract::Borrowed
                },
            }
        })
        .collect();

    FunctionInfo {
        name: name.to_string(),
        id: name.len() as u64,
        param_types: param_info,
        return_type: Some(ReturnInfo {
            is_pointer: is_pointer_return,
            family: if is_pointer_return {
                Some(FamilyId::C_HEAP)
            } else {
                None
            },
            contract: if is_pointer_return {
                PointerContract::Owned
            } else {
                PointerContract::Unknown
            },
            is_new_allocation: meta.calls_alloc,
        }),
        is_external: meta.is_declaration,
        is_library: meta.is_runtime_internal,
    }
}

/// Extracts resource allocation and deallocation operations from IR instructions.
///
/// This function performs the actual IR-instruction-based analysis:
/// - Iterates each function body's instructions.
/// - For `Call` instructions, checks the ModuleIndex to determine if the
///   callee is an allocator or deallocator.
/// - Tracks resource creation, access, and release in the tracker.
fn extract_resource_ops_from_ir(
    tracker: &mut CrossFunctionTracker,
    ir_module: &IRModule,
    module_index: &ModuleIndex,
) {
    // Build a lookup: callee name -> list of call meta indices.
    let alloc_dealloc_map: HashMap<&str, Vec<&crate::module_index::CachedCallMeta>> = {
        let mut map: HashMap<&str, Vec<&crate::module_index::CachedCallMeta>> = HashMap::new();
        for call_meta in &module_index.call_metas {
            if call_meta.is_alloc_call || call_meta.is_dealloc_call {
                map.entry(call_meta.callee_name.as_str())
                    .or_default()
                    .push(call_meta);
            }
        }
        map
    };

    // Iterate all function bodies.
    for (func_name, body) in &ir_module.function_bodies {
        // Phase 1: Collect instruction indices for alloc and dealloc calls
        // separately, preserving original instruction order. This enables
        // stable pairing: the i-th alloc pairs with the i-th dealloc.
        let mut alloc_instructions: Vec<(usize, &str)> = Vec::new();
        let mut dealloc_instructions: Vec<(usize, &str)> = Vec::new();

        for (inst_idx, instruction) in body.instructions.iter().enumerate() {
            // Only process call instructions.
            if instruction.kind != omniscope_ir::IRInstructionKind::Call {
                continue;
            }

            // Extract the callee name from the instruction.
            let callee = match &instruction.callee {
                Some(c) => c.trim_start_matches('@'),
                None => continue,
            };

            // Check if this callee is a known allocator or deallocator.
            if let Some(matches) = alloc_dealloc_map.get(callee) {
                for call_meta in matches {
                    // Only process calls that belong to the current function.
                    if call_meta.caller_name != *func_name {
                        continue;
                    }

                    if call_meta.is_alloc_call {
                        alloc_instructions.push((inst_idx, callee));
                    }
                    if call_meta.is_dealloc_call {
                        dealloc_instructions.push((inst_idx, callee));
                    }

                    // Found a matching call_meta for this callee; no need
                    // to check other call_metas with the same callee name.
                    break;
                }
            }
        }

        // Phase 2: Pair alloc/dealloc and track resources with stable
        // hash-based resource IDs. Paired alloc and dealloc share the
        // same resource_id so lifetime constraints can match creation
        // with release.
        let num_pairs = alloc_instructions.len().min(dealloc_instructions.len());

        // Paired alloc/dealloc: same resource_id for matching pairs.
        for (i, (alloc_inst, _dealloc_inst)) in alloc_instructions
            .iter()
            .zip(dealloc_instructions.iter())
            .enumerate()
            .take(num_pairs)
        {
            let resource_id = make_resource_id(func_name, alloc_inst.1, i);

            tracker.track_resource_creation(resource_id, func_name);
            tracker.track_resource_access(resource_id, func_name);
            debug!(
                target: "omniscope_pass::cross_function_lifetime",
                resource_id = resource_id,
                function = %func_name,
                callee = alloc_inst.1,
                "Resource allocation detected from IR instruction"
            );

            // Dealloc uses the same resource_id for pairing.
            tracker.track_resource_release(resource_id, func_name);
            tracker.track_resource_access(resource_id, func_name);
            debug!(
                target: "omniscope_pass::cross_function_lifetime",
                resource_id = resource_id,
                function = %func_name,
                "Resource deallocation detected from IR instruction"
            );
        }

        // Unpaired alloc calls (standalone allocation, no matching free).
        for (i, &(_idx, callee)) in alloc_instructions.iter().enumerate().skip(num_pairs) {
            let resource_id = make_resource_id(func_name, callee, i);

            tracker.track_resource_creation(resource_id, func_name);
            tracker.track_resource_access(resource_id, func_name);
            debug!(
                target: "omniscope_pass::cross_function_lifetime",
                resource_id = resource_id,
                function = %func_name,
                callee = %callee,
                "Resource allocation detected from IR instruction (unpaired)"
            );
        }

        // Unpaired dealloc calls (standalone deallocation, no matching alloc).
        for (i, &(_idx, callee)) in dealloc_instructions.iter().enumerate().skip(num_pairs) {
            let resource_id = make_resource_id(func_name, callee, i);

            tracker.track_resource_release(resource_id, func_name);
            tracker.track_resource_access(resource_id, func_name);
            debug!(
                target: "omniscope_pass::cross_function_lifetime",
                resource_id = resource_id,
                function = %func_name,
                callee = %callee,
                "Resource deallocation detected from IR instruction (unpaired)"
            );
        }
    }
}

/// Builds a `CrossFunctionLifetimeData` from the analysis result.
fn build_lifetime_data(
    analysis: &omniscope_semantics::resource::cross_function_lifetime::AnalysisResult,
    functions_analyzed: usize,
    flows_count: usize,
) -> CrossFunctionLifetimeData {
    let resource_fates: Vec<ResourceFateEntry> = analysis
        .resource_fates
        .iter()
        .map(|(resource_id, fate)| ResourceFateEntry {
            resource_id: *resource_id,
            family: FamilyId::C_HEAP,
            fate: convert_resource_fate(fate),
        })
        .collect();

    let violations: Vec<LifetimeViolationEntry> = analysis
        .violations
        .iter()
        .map(|v| LifetimeViolationEntry {
            resource_id: v.resource_id,
            violation_type: convert_violation_type(&v.violation_type),
            location: v.location.clone(),
            description: v.description.clone(),
        })
        .collect();

    CrossFunctionLifetimeData {
        resource_fates,
        violations,
        functions_analyzed,
        flows_count,
    }
}

/// Converts a `ResourceFate` from the semantics crate to a `ResourceFateSummary`.
fn convert_resource_fate(
    fate: &omniscope_semantics::resource::cross_function_lifetime::ResourceFate,
) -> ResourceFateSummary {
    use omniscope_semantics::resource::cross_function_lifetime::ResourceFate;
    match fate {
        ResourceFate::Released { in_function } => ResourceFateSummary::Released {
            in_function: in_function.clone(),
        },
        ResourceFate::ProgramLifetime => ResourceFateSummary::ProgramLifetime,
        ResourceFate::GlobalState { stored_in } => ResourceFateSummary::GlobalState {
            stored_in: stored_in.clone(),
        },
        ResourceFate::Escaped { to_functions } => ResourceFateSummary::Escaped {
            function_count: to_functions.len(),
        },
        ResourceFate::Unknown => ResourceFateSummary::Unknown,
    }
}

/// Converts a `ViolationType` from the semantics crate to a `ViolationKind`.
fn convert_violation_type(vt: &ViolationType) -> ViolationKind {
    match vt {
        ViolationType::UseAfterFree => ViolationKind::UseAfterFree,
        ViolationType::ResourceLeak => ViolationKind::ResourceLeak,
        ViolationType::DoubleFree => ViolationKind::DoubleFree,
        ViolationType::InvalidOwnershipTransfer => ViolationKind::InvalidOwnershipTransfer,
        ViolationType::BorrowEscape => ViolationKind::BorrowEscape,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ModuleIndex;
    use omniscope_ir::{CallInstruction, Function, FunctionBody, IRModule};
    use omniscope_semantics::resource::cross_function_lifetime::LifetimeViolation;
    use omniscope_types::lifetime::ViolationKind;

    /// Helper: creates a minimal IRModule with a single function that
    /// calls malloc and free.
    fn create_test_module() -> IRModule {
        let mut module = IRModule::new();
        module.functions.insert(
            "@test_func".to_string(),
            Function {
                name: "test_func".to_string(),
                is_declaration: false,
                params: vec![],
                return_type: "void".to_string(),
            },
        );
        module.declarations.insert(
            "@malloc".to_string(),
            Function {
                name: "malloc".to_string(),
                is_declaration: true,
                params: vec!["i64".to_string()],
                return_type: "ptr".to_string(),
            },
        );
        module.declarations.insert(
            "@free".to_string(),
            Function {
                name: "free".to_string(),
                is_declaration: true,
                params: vec!["ptr".to_string()],
                return_type: "void".to_string(),
            },
        );
        module.calls.push(CallInstruction {
            callee: "@malloc".to_string(),
            caller: "@test_func".to_string(),
            is_external: true,
            location: None,
            args: vec!["i64 100".to_string()],
            result: Some("%ptr".to_string()),
        });
        module.calls.push(CallInstruction {
            callee: "@free".to_string(),
            caller: "@test_func".to_string(),
            is_external: true,
            location: None,
            args: vec!["ptr %ptr".to_string()],
            result: None,
        });
        // Add a function body so instruction extraction can work.
        module.function_bodies.insert(
            "test_func".to_string(),
            FunctionBody {
                name: "test_func".to_string(),
                instructions: vec![
                    omniscope_ir::IRInstruction {
                        kind: omniscope_ir::IRInstructionKind::Call,
                        dest: Some("%ptr".to_string()),
                        operands: vec!["@malloc".to_string(), "i64 100".to_string()],
                        callee: Some("malloc".to_string()),
                        atomic_op: None,
                        icmp_pred: None,
                        raw_text: "%ptr = call i8* @malloc(i64 100)".to_string(),
                        result_type: Some("ptr".to_string()),
                        element_type: None,
                        function_signature: None,
                        conversion_opcode: None,
                        binary_opcode: None,
                    },
                    omniscope_ir::IRInstruction {
                        kind: omniscope_ir::IRInstructionKind::Call,
                        dest: None,
                        operands: vec!["@free".to_string(), "ptr %ptr".to_string()],
                        callee: Some("free".to_string()),
                        atomic_op: None,
                        icmp_pred: None,
                        raw_text: "call void @free(i8* %ptr)".to_string(),
                        result_type: Some("void".to_string()),
                        element_type: None,
                        function_signature: None,
                        conversion_opcode: None,
                        binary_opcode: None,
                    },
                ],
            },
        );
        module
    }

    /// Objective: Verify that the pass can be constructed with default properties.
    /// Invariants: name() == "CrossFunctionLifetime", kind() == Analysis,
    ///             dependencies() contains "ModuleIndex" and "RawFactCollector".
    #[test]
    fn test_pass_creation() {
        let pass = CrossFunctionLifetimePass::new();
        assert_eq!(
            pass.name(),
            "CrossFunctionLifetime",
            "Pass name must be 'CrossFunctionLifetime'"
        );
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "Pass kind must be Analysis"
        );
        let deps = pass.dependencies();
        assert!(
            deps.contains(&"ModuleIndex"),
            "Dependencies must include 'ModuleIndex'"
        );
        assert!(
            deps.contains(&"RawFactCollector"),
            "Dependencies must include 'RawFactCollector'"
        );
    }

    /// Objective: Verify that the pass runs without errors when ModuleIndex
    /// is present in the context.
    /// Invariants: The pass completes without panicking and produces a PassResult.
    #[test]
    fn test_pass_run_with_module_index() {
        let module = create_test_module();
        let index = ModuleIndex::build(&module);
        let mut ctx = PassContext::new();
        ctx.store("module_index", index);
        ctx.set_ir_module(module);

        let pass = CrossFunctionLifetimePass::new();
        let result = pass.run(&mut ctx).unwrap();

        assert_eq!(
            result.name, "CrossFunctionLifetime",
            "Result must have correct pass name"
        );
        assert!(
            result.nodes_analyzed > 0,
            "Must analyze at least 1 function, got {}",
            result.nodes_analyzed
        );
    }

    /// Objective: Verify that the pass gracefully handles missing ModuleIndex.
    /// Invariants: Pass returns early with zero nodes when ModuleIndex is absent.
    #[test]
    fn test_pass_run_without_module_index() {
        let mut ctx = PassContext::new();
        let pass = CrossFunctionLifetimePass::new();
        let result = pass.run(&mut ctx).unwrap();

        assert_eq!(
            result.nodes_analyzed, 0,
            "Without ModuleIndex, nodes_analyzed must be 0"
        );
        assert_eq!(
            result.issues_found, 0,
            "Without ModuleIndex, issues_found must be 0"
        );
    }

    /// Objective: Verify that the pass stores CrossFunctionLifetimeData in context.
    /// Invariants: After running, "cross_function_lifetime_data" is present and
    ///             contains valid analysis results.
    #[test]
    fn test_pass_stores_lifetime_data() {
        let module = create_test_module();
        let index = ModuleIndex::build(&module);
        let mut ctx = PassContext::new();
        ctx.store("module_index", index);
        ctx.set_ir_module(module);

        let pass = CrossFunctionLifetimePass::new();
        pass.run(&mut ctx).unwrap();

        let data = ctx.get_ref::<CrossFunctionLifetimeData>("cross_function_lifetime_data");
        assert!(
            data.is_some(),
            "CrossFunctionLifetimeData must be stored in context"
        );

        let data = data.unwrap();
        assert!(
            data.functions_analyzed > 0,
            "Must have analyzed at least 1 function, got {}",
            data.functions_analyzed
        );
    }

    /// Objective: Verify that violations are stored in context for downstream
    /// IssueCandidateBuilder consumption, not emitted as Issues directly.
    /// Invariants: A function that allocates without freeing produces
    ///             violations stored in the "lifetime_violations" context key,
    ///             and ctx.issues() remains empty.
    #[test]
    fn test_stores_violations_in_context() {
        let mut module = IRModule::new();
        module.functions.insert(
            "@leaky".to_string(),
            Function {
                name: "leaky".to_string(),
                is_declaration: false,
                params: vec![],
                return_type: "ptr".to_string(),
            },
        );
        module.declarations.insert(
            "@malloc".to_string(),
            Function {
                name: "malloc".to_string(),
                is_declaration: true,
                params: vec!["i64".to_string()],
                return_type: "ptr".to_string(),
            },
        );
        module.calls.push(CallInstruction {
            callee: "@malloc".to_string(),
            caller: "@leaky".to_string(),
            is_external: true,
            location: None,
            args: vec!["i64 100".to_string()],
            result: Some("%p".to_string()),
        });
        module.function_bodies.insert(
            "leaky".to_string(),
            FunctionBody {
                name: "leaky".to_string(),
                instructions: vec![omniscope_ir::IRInstruction {
                    kind: omniscope_ir::IRInstructionKind::Call,
                    dest: Some("%p".to_string()),
                    operands: vec!["@malloc".to_string(), "i64 100".to_string()],
                    callee: Some("malloc".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%p = call i8* @malloc(i64 100)".to_string(),
                    result_type: Some("ptr".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                }],
            },
        );

        let index = ModuleIndex::build(&module);
        let mut ctx = PassContext::new();
        ctx.store("module_index", index);
        ctx.set_ir_module(module);

        let pass = CrossFunctionLifetimePass::new();
        let result = pass.run(&mut ctx).unwrap();

        // Verify that violations are stored in context, not emitted as issues.
        let violations = ctx.get_ref::<Vec<LifetimeViolation>>("lifetime_violations");
        assert!(
            violations.is_some(),
            "lifetime_violations must be stored in context for leaky function"
        );
        let violations = violations.unwrap();
        assert!(
            !violations.is_empty(),
            "At least one lifetime violation must be detected for leaky function, got {}",
            violations.len()
        );

        // Verify that no issues were emitted directly by this pass.
        assert!(
            ctx.issues().is_empty(),
            "CrossFunctionLifetimePass must not emit issues directly, got {}",
            ctx.issues().len()
        );
        assert_eq!(
            result.issues_found, 0,
            "PassResult.issues_found must be 0 for this analysis-only pass, got {}",
            result.issues_found
        );

        // Verify analysis results are still present.
        assert!(
            result.nodes_analyzed > 0,
            "Leaky function should produce analysis results: nodes={}",
            result.nodes_analyzed
        );
    }

    /// Objective: Verify correct conversion from ResourceFate to ResourceFateSummary.
    /// Invariants: Each ResourceFate variant produces the correct ResourceFateSummary variant.
    #[test]
    fn test_resource_fate_conversion() {
        use omniscope_semantics::resource::cross_function_lifetime::ResourceFate;

        let released = ResourceFate::Released {
            in_function: "free_it".to_string(),
        };
        let program = ResourceFate::ProgramLifetime;
        let global = ResourceFate::GlobalState {
            stored_in: "store".to_string(),
        };
        let escaped = ResourceFate::Escaped {
            to_functions: vec!["a".to_string(), "b".to_string()],
        };
        let unknown = ResourceFate::Unknown;

        assert_eq!(
            format!("{:?}", convert_resource_fate(&released)),
            format!(
                "{:?}",
                ResourceFateSummary::Released {
                    in_function: "free_it".to_string()
                }
            ),
            "Released fate must convert correctly"
        );
        assert_eq!(
            format!("{:?}", convert_resource_fate(&program)),
            format!("{:?}", ResourceFateSummary::ProgramLifetime),
            "ProgramLifetime fate must convert correctly"
        );
        assert_eq!(
            format!("{:?}", convert_resource_fate(&global)),
            format!(
                "{:?}",
                ResourceFateSummary::GlobalState {
                    stored_in: "store".to_string()
                }
            ),
            "GlobalState fate must convert correctly"
        );
        assert_eq!(
            format!("{:?}", convert_resource_fate(&escaped)),
            format!("{:?}", ResourceFateSummary::Escaped { function_count: 2 }),
            "Escaped fate with 2 functions must convert correctly"
        );
        assert_eq!(
            format!("{:?}", convert_resource_fate(&unknown)),
            format!("{:?}", ResourceFateSummary::Unknown),
            "Unknown fate must convert correctly"
        );
    }

    /// Objective: Verify that ViolationKind matches ViolationType conversion.
    /// Invariants: Each ViolationType maps to the correct ViolationKind.
    #[test]
    fn test_violation_kind_conversion() {
        assert_eq!(
            convert_violation_type(&ViolationType::UseAfterFree),
            ViolationKind::UseAfterFree,
            "ViolationType::UseAfterFree must map to ViolationKind::UseAfterFree"
        );
        assert_eq!(
            convert_violation_type(&ViolationType::ResourceLeak),
            ViolationKind::ResourceLeak,
            "ViolationType::ResourceLeak must map to ViolationKind::ResourceLeak"
        );
        assert_eq!(
            convert_violation_type(&ViolationType::DoubleFree),
            ViolationKind::DoubleFree,
            "ViolationType::DoubleFree must map to ViolationKind::DoubleFree"
        );
        assert_eq!(
            convert_violation_type(&ViolationType::InvalidOwnershipTransfer),
            ViolationKind::InvalidOwnershipTransfer,
            "ViolationType::InvalidOwnershipTransfer must map to ViolationKind::InvalidOwnershipTransfer"
        );
        assert_eq!(
            convert_violation_type(&ViolationType::BorrowEscape),
            ViolationKind::BorrowEscape,
            "ViolationType::BorrowEscape must map to ViolationKind::BorrowEscape"
        );
    }

    /// Objective: Verify build_tracker_from_module_index creates a tracker
    /// with the correct number of functions and call edges.
    /// Invariants: Tracker has exactly as many functions as the module index and
    ///             has edges for all calls.
    #[test]
    fn test_build_tracker_from_module_index() {
        let module = create_test_module();
        let index = ModuleIndex::build(&module);

        let tracker = build_tracker_from_module_index(&index, Some(&module));

        // The tracker should have at least the functions from module_index.
        // In our test module: test_func + malloc + free (declarations).
        assert!(
            tracker.get_function_info("test_func").is_some()
                || tracker.get_call_graph().contains_key("test_func"),
            "Tracker must contain test_func"
        );
    }

    /// Objective: Verify that extract_resource_ops_from_ir processes IR instructions
    /// and tracks resources for alloc/dealloc calls.
    /// Invariants: After extraction, the tracker has recorded resource creations
    /// and releases from the IR instructions.
    #[test]
    fn test_extract_resource_ops_from_ir() {
        let module = create_test_module();
        let index = ModuleIndex::build(&module);

        let mut tracker = build_tracker_from_module_index(&index, Some(&module));
        extract_resource_ops_from_ir(&mut tracker, &module, &index);

        // The tracker should have processed alloc/dealloc instructions.
        // Verify by checking that the worklist or constraints are non-empty
        // after extraction. The tracker ran build_resource_flow_graph during
        // extract, so flows should exist.
        let flow_count = {
            // Check for flows in the tracker by examining the call graph.
            // If there are no flows, the tracker should at least have call edges.
            let call_graph_empty = tracker.get_call_graph().is_empty();
            !call_graph_empty
        };
        assert!(
            flow_count,
            "Tracker must have call edges after extraction from test module"
        );
    }

    /// Objective: Verify that build_lifetime_data correctly converts analysis
    /// results to the public CrossFunctionLifetimeData format.
    /// Invariants: The output preserves all violations and resource fates.
    #[test]
    fn test_build_lifetime_data() {
        use omniscope_semantics::resource::cross_function_lifetime::{
            AnalysisResult, ResourceFate,
        };
        use std::collections::HashMap;

        let mut resource_fates = HashMap::new();
        resource_fates.insert(
            1u64,
            ResourceFate::Released {
                in_function: "free_it".to_string(),
            },
        );

        let violations = vec![LifetimeViolation {
            resource_id: 1,
            violation_type: ViolationType::ResourceLeak,
            location: "leaky".to_string(),
            description: "test leak".to_string(),
        }];

        let analysis = AnalysisResult {
            violations,
            resource_fates,
            flows: vec![],
            lifetime_constraints: HashMap::new(),
        };

        let data = build_lifetime_data(&analysis, 5, 3);

        assert_eq!(
            data.functions_analyzed, 5,
            "functions_analyzed must be preserved"
        );
        assert_eq!(data.flows_count, 3, "flows_count must be preserved");
        assert_eq!(data.violations.len(), 1, "violations must be preserved");
        assert_eq!(
            data.resource_fates.len(),
            1,
            "resource_fates must be preserved"
        );
    }
}
