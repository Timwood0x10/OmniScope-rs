//! Cross-function lifetime tracking for resource lifecycle analysis.
//!
//! This module extends the ownership state machine to track resource
//! lifetimes across function boundaries. It builds a call graph and
//! performs data flow analysis to determine how resources are created,
//! passed, and destroyed across multiple function calls.
//!
//! # Architecture
//!
//! ```text
//! CallGraph ──→ CrossFunctionTracker
//!              ├── parameter passing tracking
//!              ├── return value lifetime analysis
//!              ├── global state tracking
//!              └── inter-procedural data flow
//! ```
//!
//! # Key Concepts
//!
//! - **Resource Flow Graph**: Tracks how resources flow between functions
//! - **Lifetime Propagation**: Propagates lifetime constraints across calls
//! - **Escape Analysis**: Determines if resources escape function boundaries
//! - **Ownership Transfer**: Tracks ownership transfers across functions

use omniscope_types::{FamilyId, PointerContract};
use std::collections::{HashMap, HashSet, VecDeque};

/// Represents a function in the call graph.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function name.
    pub name: String,
    /// Function ID (unique identifier).
    pub id: u64,
    /// Parameter types (by position).
    pub param_types: Vec<ParamInfo>,
    /// Return type information.
    pub return_type: Option<ReturnInfo>,
    /// Whether this function is external (no body).
    pub is_external: bool,
    /// Whether this function is a library function.
    pub is_library: bool,
}

/// Information about a function parameter.
#[derive(Debug, Clone)]
pub struct ParamInfo {
    /// Parameter position (0-based).
    pub position: usize,
    /// Parameter name (if available).
    pub name: String,
    /// Whether this parameter is a pointer.
    pub is_pointer: bool,
    /// Whether this parameter is passed by reference.
    pub is_reference: bool,
    /// Whether this parameter is const.
    pub is_const: bool,
    /// The resource family this parameter belongs to (if known).
    pub family: Option<FamilyId>,
    /// The pointer contract for this parameter.
    pub contract: PointerContract,
}

/// Information about a function's return value.
#[derive(Debug, Clone)]
pub struct ReturnInfo {
    /// Whether the return value is a pointer.
    pub is_pointer: bool,
    /// The resource family of the return value (if known).
    pub family: Option<FamilyId>,
    /// The pointer contract for the return value.
    pub contract: PointerContract,
    /// Whether the return value is newly allocated.
    pub is_new_allocation: bool,
}

/// Represents a resource flow between functions.
#[derive(Debug, Clone)]
pub struct ResourceFlow {
    /// Source function (caller).
    pub from_function: String,
    /// Target function (callee).
    pub to_function: String,
    /// The resource being transferred.
    pub resource_id: u64,
    /// The resource family.
    pub family: FamilyId,
    /// The flow type.
    pub flow_type: FlowType,
    /// Whether ownership is transferred.
    pub transfers_ownership: bool,
    /// The call site location.
    pub call_site: Option<String>,
}

/// Types of resource flows between functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowType {
    /// Resource passed as a parameter.
    ParameterPassing,
    /// Resource returned from a function.
    ReturnValue,
    /// Resource stored in global state.
    GlobalStore,
    /// Resource loaded from global state.
    GlobalLoad,
    /// Resource passed through a callback.
    CallbackPassing,
    /// Resource escaped through a pointer.
    PointerEscape,
}

/// Tracks resource lifetime across function boundaries.
#[derive(Debug)]
pub struct CrossFunctionTracker {
    /// Call graph: function name -> list of callees.
    call_graph: HashMap<String, Vec<String>>,
    /// Function information.
    functions: HashMap<String, FunctionInfo>,
    /// Resource flows between functions.
    flows: Vec<ResourceFlow>,
    /// Global state: resource ID -> storing function.
    global_state: HashMap<u64, String>,
    /// Resource lifetime constraints.
    lifetime_constraints: HashMap<u64, LifetimeConstraint>,
    /// Functions that have been analyzed.
    analyzed_functions: HashSet<String>,
    /// Worklist for iterative analysis.
    worklist: VecDeque<String>,
}

/// Lifetime constraint for a resource.
#[derive(Debug, Clone)]
pub struct LifetimeConstraint {
    /// Resource ID.
    pub resource_id: u64,
    /// The function where the resource was created.
    pub created_in: String,
    /// Functions that have access to this resource.
    pub accessible_in: HashSet<String>,
    /// The expected lifetime.
    pub lifetime: LifetimeDomain,
    /// Whether this resource has been released.
    pub is_released: bool,
    /// The function where the resource was released (if any).
    pub released_in: Option<String>,
    /// Order of function accesses to this resource.
    /// This helps determine if a function accessed the resource before or after release.
    pub access_order: Vec<String>,
}

/// Lifetime domains for resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifetimeDomain {
    /// Resource lives for the entire program lifetime.
    ProgramLifetime,
    /// Resource lives for the duration of a function call.
    FunctionScope,
    /// Resource lives for the duration of an object's lifetime.
    ObjectLifetime,
    /// Resource has explicit lifetime management.
    ExplicitLifetime,
    /// Resource lifetime is unknown.
    Unknown,
}

impl Default for CrossFunctionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFunctionTracker {
    /// Creates a new cross-function lifetime tracker.
    pub fn new() -> Self {
        Self {
            call_graph: HashMap::new(),
            functions: HashMap::new(),
            flows: Vec::new(),
            global_state: HashMap::new(),
            lifetime_constraints: HashMap::new(),
            analyzed_functions: HashSet::new(),
            worklist: VecDeque::new(),
        }
    }

    /// Adds a function to the tracker.
    pub fn add_function(&mut self, func: FunctionInfo) {
        self.functions.insert(func.name.clone(), func);
    }

    /// Adds a call edge to the call graph.
    pub fn add_call_edge(&mut self, caller: &str, callee: &str) {
        self.call_graph
            .entry(caller.to_string())
            .or_default()
            .push(callee.to_string());
    }

    /// Records a resource flow between functions.
    pub fn add_flow(&mut self, flow: ResourceFlow) {
        self.flows.push(flow);
    }

    /// Tracks a resource creation.
    pub fn track_resource_creation(&mut self, resource_id: u64, function: &str) {
        let constraint = LifetimeConstraint {
            resource_id,
            created_in: function.to_string(),
            accessible_in: HashSet::new(),
            lifetime: LifetimeDomain::Unknown,
            is_released: false,
            released_in: None,
            access_order: Vec::new(),
        };
        self.lifetime_constraints.insert(resource_id, constraint);
    }

    /// Tracks a resource access.
    pub fn track_resource_access(&mut self, resource_id: u64, function: &str) {
        if let Some(constraint) = self.lifetime_constraints.get_mut(&resource_id) {
            constraint.accessible_in.insert(function.to_string());
            constraint.access_order.push(function.to_string());
        }
    }

    /// Tracks a resource release.
    pub fn track_resource_release(&mut self, resource_id: u64, function: &str) {
        if let Some(constraint) = self.lifetime_constraints.get_mut(&resource_id) {
            constraint.is_released = true;
            constraint.released_in = Some(function.to_string());
            constraint.access_order.push(function.to_string());
        }
    }

    /// Tracks a global state store.
    pub fn track_global_store(&mut self, resource_id: u64, function: &str) {
        self.global_state.insert(resource_id, function.to_string());
    }

    /// Performs cross-function lifetime analysis.
    pub fn analyze(&mut self) -> AnalysisResult {
        // Phase 1: Build resource flow graph
        self.build_resource_flow_graph();

        // Phase 2: Propagate lifetime constraints
        self.propagate_lifetime_constraints();

        // Phase 3: Detect lifetime violations
        let violations = self.detect_lifetime_violations();

        // Phase 4: Determine resource fates
        let resource_fates = self.determine_resource_fates();

        AnalysisResult {
            violations,
            resource_fates,
            flows: self.flows.clone(),
            lifetime_constraints: self.lifetime_constraints.clone(),
        }
    }

    /// Builds the resource flow graph from call graph and existing flows.
    fn build_resource_flow_graph(&mut self) {
        // Collect all flows first to avoid borrowing conflicts
        let mut all_flows = Vec::new();

        // For each function in the call graph
        for (caller, callees) in &self.call_graph {
            for callee in callees {
                // Check if there are resource flows between caller and callee
                let flows = self.find_flows_between(caller, callee);
                all_flows.extend(flows);
            }
        }

        // Now add all collected flows
        for flow in all_flows {
            self.add_flow(flow);
        }
    }

    /// Finds resource flows between two functions.
    fn find_flows_between(&self, caller: &str, callee: &str) -> Vec<ResourceFlow> {
        let mut flows = Vec::new();

        // Check if callee has parameters that might be resources
        if let Some(callee_info) = self.functions.get(callee) {
            for param in &callee_info.param_types {
                if param.is_pointer && !param.is_const {
                    // This parameter might receive a resource from the caller
                    flows.push(ResourceFlow {
                        from_function: caller.to_string(),
                        to_function: callee.to_string(),
                        resource_id: 0, // Will be assigned later
                        family: param.family.unwrap_or(FamilyId::C_HEAP),
                        flow_type: FlowType::ParameterPassing,
                        transfers_ownership: false, // Conservative assumption
                        call_site: None,
                    });
                }
            }

            // Check if callee returns a resource
            if let Some(return_info) = &callee_info.return_type {
                if return_info.is_pointer {
                    flows.push(ResourceFlow {
                        from_function: callee.to_string(),
                        to_function: caller.to_string(),
                        resource_id: 0, // Will be assigned later
                        family: return_info.family.unwrap_or(FamilyId::C_HEAP),
                        flow_type: FlowType::ReturnValue,
                        transfers_ownership: return_info.is_new_allocation,
                        call_site: None,
                    });
                }
            }
        }

        flows
    }

    /// Propagates lifetime constraints through the call graph.
    fn propagate_lifetime_constraints(&mut self) {
        // Start with all functions that create resources
        for constraint in self.lifetime_constraints.values() {
            if !constraint.created_in.is_empty() {
                self.worklist.push_back(constraint.created_in.clone());
            }
        }

        // Process worklist
        while let Some(function) = self.worklist.pop_front() {
            if self.analyzed_functions.contains(&function) {
                continue;
            }

            self.analyzed_functions.insert(function.clone());
            self.propagate_constraints_for_function(&function);
        }
    }

    /// Propagates lifetime constraints for a specific function.
    fn propagate_constraints_for_function(&mut self, function: &str) {
        // Get all resources accessible in this function
        let accessible_resources: Vec<u64> = self
            .lifetime_constraints
            .iter()
            .filter(|(_, constraint)| constraint.accessible_in.contains(function))
            .map(|(id, _)| *id)
            .collect();

        // For each resource, propagate constraints to callees
        for resource_id in accessible_resources {
            if let Some(callees) = self.call_graph.get(function) {
                for callee in callees {
                    // Update constraint for callee
                    if let Some(constraint) = self.lifetime_constraints.get_mut(&resource_id) {
                        constraint.accessible_in.insert(callee.clone());
                        self.worklist.push_back(callee.clone());
                    }
                }
            }
        }
    }

    /// Detects lifetime violations.
    fn detect_lifetime_violations(&self) -> Vec<LifetimeViolation> {
        let mut violations = Vec::new();

        for (resource_id, constraint) in &self.lifetime_constraints {
            // Check for use-after-free
            if constraint.is_released {
                if let Some(released_in) = &constraint.released_in {
                    // Find the position of the release in access_order
                    let release_pos = constraint
                        .access_order
                        .iter()
                        .position(|f| f == released_in);

                    if let Some(release_pos) = release_pos {
                        // Check for functions that accessed the resource after release
                        for (pos, function) in constraint.access_order.iter().enumerate() {
                            // Skip the releasing function itself
                            if function == released_in {
                                continue;
                            }

                            // If the access happened after release, it's a use-after-free
                            if pos > release_pos {
                                violations.push(LifetimeViolation {
                                    resource_id: *resource_id,
                                    violation_type: ViolationType::UseAfterFree,
                                    location: function.clone(),
                                    description: format!(
                                        "Resource {} used in {} after being released in {}",
                                        resource_id, function, released_in
                                    ),
                                });
                            }
                        }
                    }
                }
            }

            // Check for resource leaks
            if !constraint.is_released && constraint.lifetime != LifetimeDomain::ProgramLifetime {
                violations.push(LifetimeViolation {
                    resource_id: *resource_id,
                    violation_type: ViolationType::ResourceLeak,
                    location: constraint.created_in.clone(),
                    description: format!(
                        "Resource {} created in {} but never released",
                        resource_id, constraint.created_in
                    ),
                });
            }
        }

        violations
    }

    /// Determines the fate of each resource.
    fn determine_resource_fates(&self) -> HashMap<u64, ResourceFate> {
        let mut fates = HashMap::new();

        for (resource_id, constraint) in &self.lifetime_constraints {
            let fate = if constraint.is_released {
                ResourceFate::Released {
                    in_function: constraint.released_in.clone().unwrap_or_default(),
                }
            } else if constraint.lifetime == LifetimeDomain::ProgramLifetime {
                ResourceFate::ProgramLifetime
            } else if self.global_state.contains_key(resource_id) {
                ResourceFate::GlobalState {
                    stored_in: self
                        .global_state
                        .get(resource_id)
                        .cloned()
                        .unwrap_or_default(),
                }
            } else if !constraint.accessible_in.is_empty() {
                ResourceFate::Escaped {
                    to_functions: constraint.accessible_in.iter().cloned().collect(),
                }
            } else {
                ResourceFate::Unknown
            };

            fates.insert(*resource_id, fate);
        }

        fates
    }

    /// Gets all flows for a specific function.
    pub fn get_flows_for_function(&self, function: &str) -> Vec<&ResourceFlow> {
        self.flows
            .iter()
            .filter(|flow| flow.from_function == function || flow.to_function == function)
            .collect()
    }

    /// Gets the call graph.
    pub fn get_call_graph(&self) -> &HashMap<String, Vec<String>> {
        &self.call_graph
    }

    /// Gets function information.
    pub fn get_function_info(&self, function: &str) -> Option<&FunctionInfo> {
        self.functions.get(function)
    }

    /// Gets lifetime constraints for a resource.
    pub fn get_lifetime_constraint(&self, resource_id: u64) -> Option<&LifetimeConstraint> {
        self.lifetime_constraints.get(&resource_id)
    }
}

/// Result of cross-function lifetime analysis.
#[derive(Debug)]
pub struct AnalysisResult {
    /// Lifetime violations detected.
    pub violations: Vec<LifetimeViolation>,
    /// Fate of each resource.
    pub resource_fates: HashMap<u64, ResourceFate>,
    /// Resource flows between functions.
    pub flows: Vec<ResourceFlow>,
    /// Lifetime constraints for each resource.
    pub lifetime_constraints: HashMap<u64, LifetimeConstraint>,
}

/// A lifetime violation detected during analysis.
#[derive(Debug, Clone)]
pub struct LifetimeViolation {
    /// The resource involved.
    pub resource_id: u64,
    /// The type of violation.
    pub violation_type: ViolationType,
    /// The location where the violation occurs.
    pub location: String,
    /// Description of the violation.
    pub description: String,
}

/// Types of lifetime violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationType {
    /// Use after free.
    UseAfterFree,
    /// Resource leak.
    ResourceLeak,
    /// Double free.
    DoubleFree,
    /// Invalid ownership transfer.
    InvalidOwnershipTransfer,
    /// Escape of borrowed resource.
    BorrowEscape,
}

/// The fate of a resource after analysis.
#[derive(Debug, Clone)]
pub enum ResourceFate {
    /// Resource was released in a specific function.
    Released { in_function: String },
    /// Resource lives for the entire program.
    ProgramLifetime,
    /// Resource is stored in global state.
    GlobalState { stored_in: String },
    /// Resource escaped to multiple functions.
    Escaped { to_functions: Vec<String> },
    /// Resource fate is unknown.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_types::FamilyId;

    /// Objective: Verify CrossFunctionTracker creation and basic operations.
    /// Invariants: New tracker should have empty call graph and no flows.
    #[test]
    fn test_tracker_creation() {
        let tracker = CrossFunctionTracker::new();

        assert!(
            tracker.get_call_graph().is_empty(),
            "New tracker should have empty call graph"
        );
        assert!(tracker.flows.is_empty(), "New tracker should have no flows");
        assert!(
            tracker.functions.is_empty(),
            "New tracker should have no functions"
        );
    }

    /// Objective: Verify function addition and call edge creation.
    /// Invariants: Functions should be properly stored and call edges should be recorded.
    #[test]
    fn test_function_and_call_edges() {
        let mut tracker = CrossFunctionTracker::new();

        // Add functions
        let func_a = FunctionInfo {
            name: "function_a".to_string(),
            id: 1,
            param_types: vec![],
            return_type: None,
            is_external: false,
            is_library: false,
        };

        let func_b = FunctionInfo {
            name: "function_b".to_string(),
            id: 2,
            param_types: vec![ParamInfo {
                position: 0,
                name: "ptr".to_string(),
                is_pointer: true,
                is_reference: false,
                is_const: false,
                family: Some(FamilyId::C_HEAP),
                contract: PointerContract::Owned,
            }],
            return_type: None,
            is_external: false,
            is_library: false,
        };

        tracker.add_function(func_a);
        tracker.add_function(func_b);

        // Add call edge
        tracker.add_call_edge("function_a", "function_b");

        // Verify
        let call_graph = tracker.get_call_graph();
        assert!(
            call_graph.contains_key("function_a"),
            "Call graph should contain function_a"
        );

        let callees = call_graph.get("function_a").unwrap();
        assert_eq!(callees.len(), 1, "function_a should have one callee");
        assert_eq!(
            callees[0], "function_b",
            "function_a should call function_b"
        );

        // Verify function info
        let func_info = tracker.get_function_info("function_b").unwrap();
        assert_eq!(
            func_info.param_types.len(),
            1,
            "function_b should have one parameter"
        );
        assert!(
            func_info.param_types[0].is_pointer,
            "Parameter should be a pointer"
        );
    }

    /// Objective: Verify resource tracking across function calls.
    /// Invariants: Resources should be tracked from creation to release.
    #[test]
    fn test_resource_tracking() {
        let mut tracker = CrossFunctionTracker::new();

        // Track resource creation
        tracker.track_resource_creation(100, "create_resource");

        // Track resource access
        tracker.track_resource_access(100, "process_resource");
        tracker.track_resource_access(100, "use_resource");

        // Track resource release
        tracker.track_resource_release(100, "destroy_resource");

        // Get constraint
        let constraint = tracker.get_lifetime_constraint(100).unwrap();

        assert_eq!(constraint.resource_id, 100, "Resource ID should be 100");
        assert_eq!(
            constraint.created_in, "create_resource",
            "Resource should be created in create_resource"
        );
        assert!(
            constraint.is_released,
            "Resource should be marked as released"
        );
        assert_eq!(
            constraint.released_in,
            Some("destroy_resource".to_string()),
            "Resource should be released in destroy_resource"
        );

        // Check accessible functions
        assert!(
            constraint.accessible_in.contains("process_resource"),
            "Resource should be accessible in process_resource"
        );
        assert!(
            constraint.accessible_in.contains("use_resource"),
            "Resource should be accessible in use_resource"
        );
    }

    /// Objective: Verify cross-function lifetime analysis with embedded IR.
    /// Invariants: Analysis should detect resource flows and lifetime violations.
    #[test]
    fn test_cross_function_analysis() {
        // Embedded IR for testing
        let _ir = r#"
            define i8* @create_resource() {
              %ptr = call i8* @malloc(i64 100)
              ret i8* %ptr
            }
            
            define void @process_resource(i8* %ptr) {
              ; Process the resource
              ret void
            }
            
            define void @destroy_resource(i8* %ptr) {
              call void @free(i8* %ptr)
              ret void
            }
            
            define void @test_cross_function() {
              %ptr = call i8* @create_resource()
              call void @process_resource(i8* %ptr)
              call void @destroy_resource(i8* %ptr)
              ret void
            }
        "#;

        // Create tracker and simulate analysis
        let mut tracker = CrossFunctionTracker::new();

        // Add functions
        tracker.add_function(FunctionInfo {
            name: "create_resource".to_string(),
            id: 1,
            param_types: vec![],
            return_type: Some(ReturnInfo {
                is_pointer: true,
                family: Some(FamilyId::C_HEAP),
                contract: PointerContract::Owned,
                is_new_allocation: true,
            }),
            is_external: false,
            is_library: false,
        });

        tracker.add_function(FunctionInfo {
            name: "process_resource".to_string(),
            id: 2,
            param_types: vec![ParamInfo {
                position: 0,
                name: "ptr".to_string(),
                is_pointer: true,
                is_reference: false,
                is_const: false,
                family: Some(FamilyId::C_HEAP),
                contract: PointerContract::Borrowed,
            }],
            return_type: None,
            is_external: false,
            is_library: false,
        });

        tracker.add_function(FunctionInfo {
            name: "destroy_resource".to_string(),
            id: 3,
            param_types: vec![ParamInfo {
                position: 0,
                name: "ptr".to_string(),
                is_pointer: true,
                is_reference: false,
                is_const: false,
                family: Some(FamilyId::C_HEAP),
                contract: PointerContract::Owned,
            }],
            return_type: None,
            is_external: false,
            is_library: false,
        });

        tracker.add_function(FunctionInfo {
            name: "test_cross_function".to_string(),
            id: 4,
            param_types: vec![],
            return_type: None,
            is_external: false,
            is_library: false,
        });

        // Add call edges
        tracker.add_call_edge("test_cross_function", "create_resource");
        tracker.add_call_edge("test_cross_function", "process_resource");
        tracker.add_call_edge("test_cross_function", "destroy_resource");

        // Track resource lifecycle
        tracker.track_resource_creation(200, "create_resource");
        tracker.track_resource_access(200, "process_resource");
        tracker.track_resource_release(200, "destroy_resource");

        // Run analysis
        let result = tracker.analyze();

        // Verify analysis results
        assert!(
            result.resource_fates.contains_key(&200),
            "Analysis should track resource 200"
        );

        let fate = result.resource_fates.get(&200).unwrap();
        match fate {
            ResourceFate::Released { in_function } => {
                assert_eq!(
                    in_function, "destroy_resource",
                    "Resource should be released in destroy_resource"
                );
            }
            _ => panic!("Resource should have been released"),
        }

        // Check for violations
        assert!(
            result.violations.is_empty(),
            "There should be no lifetime violations in this example"
        );
    }

    /// Objective: Verify detection of use-after-free violations.
    /// Invariants: Use-after-free should be detected when resource is used after release.
    #[test]
    fn test_use_after_free_detection() {
        let mut tracker = CrossFunctionTracker::new();

        // Track resource lifecycle with violation
        tracker.track_resource_creation(300, "create");
        tracker.track_resource_access(300, "process");
        tracker.track_resource_release(300, "release");
        tracker.track_resource_access(300, "use_after_release"); // Violation!

        // Run analysis
        let result = tracker.analyze();

        // Should detect violation
        assert!(
            !result.violations.is_empty(),
            "Should detect use-after-free violation"
        );

        let violation = &result.violations[0];
        assert_eq!(
            violation.violation_type,
            ViolationType::UseAfterFree,
            "Violation should be use-after-free"
        );
        assert_eq!(
            violation.resource_id, 300,
            "Violation should involve resource 300"
        );
    }

    /// Objective: Verify detection of resource leaks.
    /// Invariants: Resource leak should be detected when resource is never released.
    #[test]
    fn test_resource_leak_detection() {
        let mut tracker = CrossFunctionTracker::new();

        // Track resource lifecycle with leak
        tracker.track_resource_creation(400, "create");
        tracker.track_resource_access(400, "process");
        // No release!

        // Run analysis
        let result = tracker.analyze();

        // Should detect leak
        assert!(!result.violations.is_empty(), "Should detect resource leak");

        let violation = &result.violations[0];
        assert_eq!(
            violation.violation_type,
            ViolationType::ResourceLeak,
            "Violation should be resource leak"
        );
        assert_eq!(
            violation.resource_id, 400,
            "Violation should involve resource 400"
        );
    }

    /// Objective: Verify global state tracking.
    /// Invariants: Resources stored in global state should be tracked.
    #[test]
    fn test_global_state_tracking() {
        let mut tracker = CrossFunctionTracker::new();

        // Track resource creation and global store
        tracker.track_resource_creation(500, "create");
        tracker.track_global_store(500, "store_global");

        // Run analysis
        let result = tracker.analyze();

        // Check fate
        let fate = result.resource_fates.get(&500).unwrap();
        match fate {
            ResourceFate::GlobalState { stored_in } => {
                assert_eq!(
                    stored_in, "store_global",
                    "Resource should be stored in store_global"
                );
            }
            _ => panic!("Resource should be in global state"),
        }
    }

    /// Objective: Verify resource flow tracking between functions.
    /// Invariants: Flows should be correctly recorded and retrievable.
    #[test]
    fn test_resource_flow_tracking() {
        let mut tracker = CrossFunctionTracker::new();

        // Add a flow
        let flow = ResourceFlow {
            from_function: "caller".to_string(),
            to_function: "callee".to_string(),
            resource_id: 600,
            family: FamilyId::C_HEAP,
            flow_type: FlowType::ParameterPassing,
            transfers_ownership: false,
            call_site: Some("call_site_1".to_string()),
        };

        tracker.add_flow(flow);

        // Get flows for caller
        let caller_flows = tracker.get_flows_for_function("caller");
        assert_eq!(caller_flows.len(), 1, "Should have one flow for caller");

        // Get flows for callee
        let callee_flows = tracker.get_flows_for_function("callee");
        assert_eq!(callee_flows.len(), 1, "Should have one flow for callee");

        // Verify flow details
        let flow = &caller_flows[0];
        assert_eq!(flow.from_function, "caller", "Flow should be from caller");
        assert_eq!(flow.to_function, "callee", "Flow should be to callee");
        assert_eq!(
            flow.flow_type,
            FlowType::ParameterPassing,
            "Flow type should be parameter passing"
        );
    }
}
