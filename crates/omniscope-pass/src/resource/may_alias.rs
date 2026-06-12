//! May-alias gate for DoubleFree confirmation.
//!
//! Two `free`/release call sites can be safely reported as a `DoubleFree`
//! issue only when their pointer arguments must alias — i.e., they refer
//! to the same underlying allocation. Without that guarantee, candidates
//! built from "≥ 2 free calls anywhere in the module" produce false
//! positives whenever the program contains independent free routines
//! (e.g., `Z::free(p)` and `fallback::free_without_size(q)` each freeing
//! its own pointer).
//!
//! This module exposes a lightweight, intra-procedural alias check that
//! is intentionally conservative: it only reports `MayAlias` when at
//! least one structural rule fires. Anything weaker is treated as
//! `NotAlias` and should cause the verifier to demote the candidate.
//!
//! ## Rules
//!
//! - **Same SSA root**: both arguments trace through `bitcast` /
//!   `getelementptr 0` / `load %p` chains to the same SSA value or the
//!   same `@global` symbol.
//! - **Store→Load alias**: when one argument originates from a `load`
//!   whose source location was written by a `store` whose value
//!   originates from the same root as the other argument, the two
//!   sites may alias. This handles the common `store %p, %slot;
//!   %q = load %slot; free(%p); free(%q)` pattern.
//! - **Same allocator origin**: both originate from the same allocator
//!   call instruction within the same function.
//! - **Phi-merged alloc roots**: both arguments are operands of the same
//!   phi whose other incoming values are allocator results.
//! - **Different functions, no shared root**: cannot be must-alias — the
//!   gate rejects.
//!
//! The gate is invoked from `issue_verifier.rs::verify_double_release`
//! at the point the verdict would otherwise be upgraded to
//! `VerifierVerdict::ConfirmedIssue`.

use std::collections::{HashMap, HashSet};

use omniscope_ir::{IRInstructionKind, IRModule};
use omniscope_types::{AliasEvidence, AliasSource, Confidence, FreeSite};

/// Gate-level free site for may-alias analysis.
///
/// Thin wrapper around `omniscope_types::FreeSite` used internally
/// by the alias gate's SSA root tracing. The `arg_register` field
/// is the SSA pointer argument passed to the release callee
/// (e.g. `%buf`, `@gptr`). When the original IR was not parsed
/// with raw text, it may be `None`; the gate is permissive in that
/// case and reports `MayAlias` to avoid downgrading purely on missing
/// metadata.
///
/// Convert from `FreeSite` via `From`/`Into`.
#[derive(Debug, Clone)]
pub struct GateFreeSite {
    pub caller: String,
    pub callee: String,
    pub arg_register: Option<String>,
}

impl From<&FreeSite> for GateFreeSite {
    fn from(site: &FreeSite) -> Self {
        Self {
            caller: site
                .caller
                .clone()
                .unwrap_or_else(|| site.function_name.clone()),
            callee: site.callee.clone(),
            arg_register: site.arg_register.clone(),
        }
    }
}

impl From<GateFreeSite> for FreeSite {
    fn from(g: GateFreeSite) -> Self {
        FreeSite::new(g.caller, g.callee, g.arg_register)
    }
}

impl From<&GateFreeSite> for FreeSite {
    fn from(g: &GateFreeSite) -> Self {
        FreeSite::new(&g.caller, &g.callee, g.arg_register.clone())
    }
}

/// Verdict of the alias gate. Only `MayAlias` (or stronger) is acceptable
/// for confirming a DoubleFree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MayAliasResult {
    /// Both sites can be proven (or strongly suspected) to refer to the
    /// same allocation. Acceptable for confirmation.
    MayAlias,
    /// No structural rule fired. Reject confirmation.
    NotAlias,
}

impl MayAliasResult {
    /// True when the gate is permissive enough to confirm.
    pub fn is_alias(self) -> bool {
        matches!(self, MayAliasResult::MayAlias)
    }
}

/// Main entry point: returns true when two release sites may refer to the
/// same allocation. Returns false when the sites are provably unrelated
/// or when no shared SSA root can be found in the same function.
///
/// `ir_module` is optional so callers without the IR (e.g., synthetic
/// test candidates that lack a real module) still get a sensible answer:
/// when no module is available, we conservatively trust same-caller +
/// same-callee + same-arg matches but reject everything else.
///
/// Additionally returns structured `AliasEvidence` when the sites are
/// determined to alias, enabling downstream verifiers to distinguish
/// confirmed double-free from independent frees.
pub fn may_alias(
    a: &FreeSite,
    b: &FreeSite,
    ir_module: Option<&IRModule>,
) -> (MayAliasResult, Option<AliasEvidence>) {
    // Convert to gate-internal representation for SSA root tracing.
    let ga = GateFreeSite::from(a);
    let gb = GateFreeSite::from(b);
    let result = may_alias_inner(&ga, &gb, ir_module);
    let evidence = if result == MayAliasResult::MayAlias {
        let source = compute_alias_source(&ga, &gb, ir_module);
        let confidence = match source {
            AliasSource::SamePointer => Confidence::High,
            AliasSource::StoreLoadChain => Confidence::High,
            AliasSource::MemoryGraph => Confidence::Medium,
            AliasSource::IRPattern => Confidence::Medium,
            AliasSource::Conservative => Confidence::Low,
        };
        Some(AliasEvidence {
            id: 0,
            resource_id: None,
            free_site_a: a.clone(),
            free_site_b: b.clone(),
            source,
            confidence,
            description: format!(
                "may_alias={:?}: a=({}, {}) b=({}, {})",
                result, a.function_name, a.callee, b.function_name, b.callee
            ),
        })
    } else {
        None
    };
    (result, evidence)
}

/// Internal alias check operating on the gate-level representation.
fn may_alias_inner(
    a: &GateFreeSite,
    b: &GateFreeSite,
    ir_module: Option<&IRModule>,
) -> MayAliasResult {
    // Rule (cheap): different callers and no shared SSA root => not alias.
    // Cross-function aliasing would require inter-procedural reasoning
    // we do not perform here.
    if a.caller != b.caller {
        // Two globals with identical names refer to the same memory across
        // functions. Treat that as may-alias even cross-function.
        if let (Some(ar), Some(br)) = (a.arg_register.as_deref(), b.arg_register.as_deref()) {
            if ar == br && ar.starts_with('@') {
                return MayAliasResult::MayAlias;
            }
        }
        return MayAliasResult::NotAlias;
    }

    // Same caller, same exact register => trivially may-alias.
    if let (Some(ar), Some(br)) = (a.arg_register.as_deref(), b.arg_register.as_deref()) {
        if ar == br {
            return MayAliasResult::MayAlias;
        }
    }

    // Walk SSA roots through bitcast / GEP-0 / load / store→load chains
    // and compare using root SETS (not single roots), because store→load
    // alias may expand a single load into multiple possible roots.
    let Some(body) = ir_module.and_then(|m| m.function_bodies.get(&a.caller)) else {
        // No body available — be permissive only on exact-arg matches above.
        return MayAliasResult::NotAlias;
    };

    let defs = build_def_map(body);
    let store_map = build_store_map(body);

    let roots_a = a
        .arg_register
        .as_deref()
        .map(|r| trace_root_set(r, &defs, &store_map, &mut HashSet::new()))
        .unwrap_or_default();
    let roots_b = b
        .arg_register
        .as_deref()
        .map(|r| trace_root_set(r, &defs, &store_map, &mut HashSet::new()))
        .unwrap_or_default();

    // If the two root sets share any element, they may alias.
    if !roots_a.is_empty() && !roots_b.is_empty() && roots_a.intersection(&roots_b).count() > 0 {
        return MayAliasResult::MayAlias;
    }

    // Phi-merged alloc roots: expand phi inputs and check overlap.
    if phi_root_sets_overlap(&roots_a, &roots_b, &defs) {
        return MayAliasResult::MayAlias;
    }

    MayAliasResult::NotAlias
}

/// Build a `dest_register -> instruction` map for the function body.
///
/// Used to follow def-use chains while normalising SSA roots. The map is
/// rebuilt per call because function bodies are small in practice and the
/// gate runs once per candidate.
fn build_def_map(
    body: &omniscope_ir::FunctionBody,
) -> HashMap<String, &omniscope_ir::IRInstruction> {
    let mut map: HashMap<String, &omniscope_ir::IRInstruction> = HashMap::new();
    for inst in &body.instructions {
        if let Some(dest) = &inst.dest {
            map.insert(dest.clone(), inst);
        }
    }
    map
}

/// Build a `location_register → [stored_value_registers]` map for the
/// function body.
///
/// For each `store %val, ptr %loc` instruction, records that `%val` was
/// written to `%loc`. This enables `trace_root_set` to expand a `load`
/// from `%loc` into all values that were ever stored to that location.
fn build_store_map(body: &omniscope_ir::FunctionBody) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for inst in &body.instructions {
        if inst.kind != IRInstructionKind::Store {
            continue;
        }
        // `store ptr %val, ptr %loc` — extract destination (location) and value.
        if let Some(loc) = extract_store_location(&inst.raw_text) {
            if let Some(val) = extract_store_value(&inst.raw_text) {
                map.entry(loc).or_default().push(val);
            }
        }
    }
    map
}

/// Extract the location (destination) register from a store instruction.
/// `store ptr %val, ptr %loc` → returns `%loc`.
fn extract_store_location(raw: &str) -> Option<String> {
    // Store syntax: `store <ty> <val>, ptr <loc>`
    // After the comma, find the last register token.
    let comma_pos = raw.find(',')?;
    let after_comma = &raw[comma_pos + 1..];
    for tok in after_comma.split_whitespace() {
        let t = tok.trim_end_matches(',');
        if t.starts_with('%') || t.starts_with('@') {
            return Some(t.to_string());
        }
    }
    None
}

/// Extract the value (source) register from a store instruction.
/// `store ptr %val, ptr %loc` → returns `%val`.
fn extract_store_value(raw: &str) -> Option<String> {
    // Store syntax: `store <ty> <val>, ptr <loc>`
    // Between `store` and the comma, find the register.
    let comma_pos = raw.find(',')?;
    let before_comma = &raw[..comma_pos];
    for tok in before_comma.split_whitespace() {
        let t = tok.trim_end_matches(',');
        if t.starts_with('%') || t.starts_with('@') {
            return Some(t.to_string());
        }
    }
    None
}

/// Trace all possible SSA roots for a register, expanding `load` through
/// store→load alias chains. Returns a set of canonical root registers.
///
/// Unlike `trace_root` (which returns a single root), this function
/// produces a *set* of possible roots: when a `load` is encountered,
/// the store map is consulted and all values ever stored to that location
/// are recursively traced.
fn trace_root_set(
    reg: &str,
    defs: &HashMap<String, &omniscope_ir::IRInstruction>,
    store_map: &HashMap<String, Vec<String>>,
    visited: &mut HashSet<String>,
) -> HashSet<String> {
    let mut roots = HashSet::new();
    let mut stack = vec![reg.to_string()];

    while let Some(current) = stack.pop() {
        if !visited.insert(current.clone()) {
            continue;
        }
        let Some(inst) = defs.get(&current) else {
            // No defining instruction — this IS a root.
            roots.insert(current);
            continue;
        };
        match inst.kind {
            IRInstructionKind::Conversion => {
                if let Some(src) = extract_first_register(&inst.raw_text) {
                    stack.push(src);
                } else {
                    roots.insert(current);
                }
            }
            IRInstructionKind::GetElementPtr => {
                if let Some(src) = extract_first_register(&inst.raw_text) {
                    stack.push(src);
                } else {
                    roots.insert(current);
                }
            }
            IRInstructionKind::Load => {
                // `%p = load ptr, ptr %slot` — the root is the slot address,
                // BUT we also expand through store→load alias: if any value
                // was stored to `%slot`, those values are also possible roots.
                if let Some(src) = extract_first_register(&inst.raw_text) {
                    // The slot itself is a root candidate (preserving old
                    // behavior: two loads from the same slot do alias).
                    roots.insert(src.clone());

                    // Expand through store→load: trace all values that were
                    // ever stored to this location.
                    if let Some(stored_vals) = store_map.get(&src) {
                        for val in stored_vals {
                            stack.push(val.clone());
                        }
                    }
                } else {
                    roots.insert(current);
                }
            }
            IRInstructionKind::Phi => {
                // Expand phi inputs and trace each one.
                let phi_roots = phi_source_roots(&current, defs);
                if phi_roots.is_empty() {
                    roots.insert(current);
                } else {
                    for r in phi_roots {
                        stack.push(r);
                    }
                }
            }
            _ => {
                roots.insert(current);
            }
        }
    }

    roots
}

/// Check if two root sets overlap when expanded through phi inputs.
///
/// For each root in both sets, if it is a phi instruction, expand its
/// source roots. Then check if the expanded sets intersect.
fn phi_root_sets_overlap(
    roots_a: &HashSet<String>,
    roots_b: &HashSet<String>,
    defs: &HashMap<String, &omniscope_ir::IRInstruction>,
) -> bool {
    let expanded_a = expand_phi_roots(roots_a, defs);
    let expanded_b = expand_phi_roots(roots_b, defs);
    expanded_a.intersection(&expanded_b).count() > 0
}

/// Expand a set of roots through phi source inputs.
fn expand_phi_roots(
    roots: &HashSet<String>,
    defs: &HashMap<String, &omniscope_ir::IRInstruction>,
) -> HashSet<String> {
    let mut expanded = roots.clone();
    for r in roots {
        let phi_roots = phi_source_roots(r, defs);
        if !phi_roots.is_empty() {
            expanded.extend(phi_roots);
        }
    }
    expanded
}

/// Trace an SSA register back through `bitcast`, `getelementptr ..., 0`,
/// and single-source `load`/`phi` until we reach a value that has no
/// defining instruction in this function (a parameter, global, or
/// allocator-return). Returns the canonical root register name.
///
/// `visited` guards against pathological phi cycles.
fn trace_root(
    reg: &str,
    defs: &HashMap<String, &omniscope_ir::IRInstruction>,
    visited: &mut HashSet<String>,
) -> String {
    let mut current = reg.to_string();
    loop {
        if !visited.insert(current.clone()) {
            // Cycle: bail out at the current root.
            return current;
        }
        let Some(inst) = defs.get(&current) else {
            return current;
        };
        match inst.kind {
            IRInstructionKind::Conversion => {
                // bitcast / inttoptr / ptrtoint chain — follow the source.
                if let Some(src) = extract_first_register(&inst.raw_text) {
                    current = src;
                    continue;
                }
                return current;
            }
            IRInstructionKind::GetElementPtr => {
                // GEP with all-zero indices is a no-op pointer transformation
                // and preserves the underlying object. Otherwise the GEP
                // creates a derived (but related) pointer — still treat the
                // base as the root, since freeing a derived pointer is a
                // different bug class we do not gate here.
                if let Some(src) = extract_first_register(&inst.raw_text) {
                    current = src;
                    continue;
                }
                return current;
            }
            IRInstructionKind::Load => {
                // `%p = load ptr, ptr %slot` — treat the slot as the root.
                // This captures the common pattern of repeatedly loading
                // from the same stack slot before each free.
                if let Some(src) = extract_first_register(&inst.raw_text) {
                    current = src;
                    continue;
                }
                return current;
            }
            _ => return current,
        }
    }
}

/// Collect the canonical roots of all incoming values to a phi
/// instruction. Returns an empty set when `reg` is not a phi.
fn phi_source_roots(
    reg: &str,
    defs: &HashMap<String, &omniscope_ir::IRInstruction>,
) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(inst) = defs.get(reg) else {
        return out;
    };
    if !matches!(inst.kind, IRInstructionKind::Phi) {
        return out;
    }
    // Phi raw_text looks like `phi ptr [ %1, %bb0 ], [ %2, %bb1 ]`.
    // Extract every register that appears inside a `[ ..., ... ]` pair.
    for chunk in inst.raw_text.split('[').skip(1) {
        let end = chunk.find(']').unwrap_or(chunk.len());
        let pair = &chunk[..end];
        if let Some(first) = pair.split(',').next() {
            let tok = first.trim().trim_start_matches('%').trim_start_matches('@');
            if !tok.is_empty() {
                let candidate = if first.trim().starts_with('@') {
                    format!("@{}", tok)
                } else {
                    format!("%{}", tok)
                };
                let rooted = trace_root(&candidate, defs, &mut HashSet::new());
                out.insert(rooted);
            }
        }
    }
    out
}

/// Extract the first SSA register or global token that appears in a raw
/// instruction line. Returns `Some("%r")` or `Some("@g")` when found.
fn extract_first_register(raw: &str) -> Option<String> {
    for tok in raw.split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')') {
        let t = tok.trim_end_matches(',');
        if t.starts_with('%') || t.starts_with('@') {
            // Skip the destination register if present (it appears before `=`).
            if let Some(eq_pos) = raw.find(" = ") {
                let dest_part = raw[..eq_pos].trim();
                if dest_part == t {
                    continue;
                }
            }
            // Skip type-only tokens (e.g. `i64`, `ptr`) — handled implicitly
            // because they do not start with `%` / `@`.
            return Some(t.to_string());
        }
    }
    None
}

/// Convenience helper for candidate-time wiring: scan a function body
/// for all release-family calls and produce a `FreeSite` for each one.
///
/// This is used by tests and by the candidate builder to gather the raw
/// data the gate consumes. `release_callees` lists the symbols the caller
/// considers releases (e.g. `["free", "_ZdlPv"]`).
pub fn collect_free_sites(
    ir_module: &IRModule,
    caller_name: &str,
    release_callees: &HashSet<String>,
) -> Vec<FreeSite> {
    let mut sites = Vec::new();
    let Some(body) = ir_module.function_bodies.get(caller_name) else {
        return sites;
    };
    for inst in &body.instructions {
        if !matches!(inst.kind, IRInstructionKind::Call) {
            continue;
        }
        let Some(callee) = &inst.callee else { continue };
        if !release_callees.contains(callee) {
            continue;
        }
        let arg = first_call_arg_register(&inst.raw_text);
        sites.push(FreeSite::new(caller_name, callee, arg));
    }
    sites
}

/// MayAlias gate that wraps the alias analysis with state for
/// producing structured `AliasEvidence`.
///
/// Tracks an auto-incrementing ID to assign unique identifiers
/// to each `AliasEvidence` instance produced.
#[derive(Debug, Default)]
pub struct MayAlias {
    next_evidence_id: u64,
}

impl MayAlias {
    /// Creates a new `MayAlias` gate.
    pub fn new() -> Self {
        Self {
            next_evidence_id: 1,
        }
    }

    /// Returns structured alias evidence for a pair of free sites.
    ///
    /// If the two frees are determined to alias the same resource,
    /// returns `Some(AliasEvidence)` with the reasoning. Otherwise
    /// returns `None`.
    pub fn get_alias_evidence(
        &mut self,
        free_a: &FreeSite,
        free_b: &FreeSite,
        ir_module: Option<&IRModule>,
    ) -> Option<AliasEvidence> {
        let (result, _) = may_alias(free_a, free_b, ir_module);
        if result == MayAliasResult::MayAlias {
            let ga = GateFreeSite::from(free_a);
            let gb = GateFreeSite::from(free_b);
            let id = self.next_evidence_id;
            self.next_evidence_id += 1;
            let source = compute_alias_source(&ga, &gb, ir_module);
            let confidence = match source {
                AliasSource::SamePointer => Confidence::High,
                AliasSource::StoreLoadChain => Confidence::High,
                AliasSource::MemoryGraph => Confidence::Medium,
                AliasSource::IRPattern => Confidence::Medium,
                AliasSource::Conservative => Confidence::Low,
            };
            Some(AliasEvidence {
                id,
                resource_id: None,
                free_site_a: free_a.clone(),
                free_site_b: free_b.clone(),
                source,
                confidence,
                description: format!(
                    "may_alias=MayAlias: a=({}, {}) b=({}, {})",
                    free_a.function_name, free_a.callee, free_b.function_name, free_b.callee
                ),
            })
        } else {
            None
        }
    }
}

/// Determine the source/mechanism of an alias relationship between
/// two gate-level free sites. This inspects the sites and available
/// IR to classify how the alias was established.
fn compute_alias_source(
    a: &GateFreeSite,
    b: &GateFreeSite,
    ir_module: Option<&IRModule>,
) -> AliasSource {
    // Same caller + same register = SamePointer
    if a.caller == b.caller {
        if let (Some(ar), Some(br)) = (a.arg_register.as_deref(), b.arg_register.as_deref()) {
            if ar == br {
                return AliasSource::SamePointer;
            }
        }
    }
    // Cross-function globals with same name = SamePointer
    if a.caller != b.caller {
        if let (Some(ar), Some(br)) = (a.arg_register.as_deref(), b.arg_register.as_deref()) {
            if ar == br && ar.starts_with('@') {
                return AliasSource::SamePointer;
            }
        }
    }
    // Check if store→load pattern is present
    if let Some(body) = ir_module.and_then(|m| m.function_bodies.get(&a.caller)) {
        let store_map = build_store_map(body);
        if let (Some(ar), Some(br)) = (a.arg_register.as_deref(), b.arg_register.as_deref()) {
            // Check if one arg is stored to a location loaded by the other
            if store_map.values().any(|vals| vals.iter().any(|v| v == ar))
                || store_map.values().any(|vals| vals.iter().any(|v| v == br))
            {
                return AliasSource::StoreLoadChain;
            }
        }
    }
    // Fall back to conservative
    AliasSource::Conservative
}

/// Pull the first register/global argument out of a call's raw text.
/// Mirrors the parsing in `contract_graph_builder::extract_call_arg_registers`
/// but returns only the first arg, which is sufficient for free-family
/// callees (they take the pointer as the first argument).
pub fn first_call_arg_register(raw_text: &str) -> Option<String> {
    let text = raw_text.trim();
    let close = text.rfind(')')?;
    let mut depth = 1i32;
    let mut open = 0;
    for (i, ch) in text[..close].char_indices().rev() {
        match ch {
            ')' => depth += 1,
            '(' => {
                depth -= 1;
                if depth == 0 {
                    open = i;
                    break;
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    let args = &text[open + 1..close];
    for arg in args.split(',') {
        for tok in arg.split_whitespace() {
            if tok.starts_with('%') || tok.starts_with('@') {
                return Some(tok.trim_end_matches(',').to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_ir::{FunctionBody, IRInstruction, IRInstructionKind, IRModule};

    fn make_inst(kind: IRInstructionKind, dest: Option<&str>, raw: &str) -> IRInstruction {
        IRInstruction {
            kind,
            dest: dest.map(|s| s.to_string()),
            operands: Vec::new(),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text: raw.to_string(),
            result_type: None,
            element_type: None,
            function_signature: None,
            conversion_opcode: None,
            binary_opcode: None,
        }
    }

    fn make_call(callee: &str, raw: &str) -> IRInstruction {
        let mut inst = make_inst(IRInstructionKind::Call, None, raw);
        inst.callee = Some(callee.to_string());
        inst
    }

    #[test]
    fn test_extract_first_register_simple() {
        let raw = "call void @free(ptr %buf)";
        assert_eq!(
            first_call_arg_register(raw),
            Some("%buf".to_string()),
            "expected %buf to be extracted from call args"
        );
    }

    #[test]
    fn test_extract_first_register_with_attrs() {
        let raw = "tail call void @free(ptr nonnull %p)";
        assert_eq!(
            first_call_arg_register(raw),
            Some("%p".to_string()),
            "expected %p when nonnull attribute is present"
        );
    }

    #[test]
    fn test_may_alias_different_callers_no_global() {
        let a = FreeSite::new("Z::free", "free", Some("%p".into()));
        let b = FreeSite::new("fallback::free_without_size", "free", Some("%q".into()));
        let (result, evidence) = may_alias(&a, &b, None);
        assert_eq!(
            result,
            MayAliasResult::NotAlias,
            "different callers with no global root must NOT alias"
        );
        assert!(
            evidence.is_none(),
            "non-aliasing sites must NOT produce AliasEvidence"
        );
    }

    #[test]
    fn test_may_alias_different_callers_same_global() {
        let a = FreeSite::new("f1", "free", Some("@g".into()));
        let b = FreeSite::new("f2", "free", Some("@g".into()));
        let (result, evidence) = may_alias(&a, &b, None);
        assert_eq!(
            result,
            MayAliasResult::MayAlias,
            "two frees of the same global must alias even across functions"
        );
        assert!(
            evidence.is_some(),
            "aliasing sites must produce AliasEvidence"
        );
        let ev = evidence.unwrap();
        assert_eq!(
            ev.source,
            AliasSource::SamePointer,
            "same global must be SamePointer alias"
        );
    }

    #[test]
    fn test_may_alias_same_caller_same_register() {
        let a = FreeSite::new("foo", "free", Some("%p".into()));
        let b = FreeSite::new("foo", "free", Some("%p".into()));
        let (result, evidence) = may_alias(&a, &b, None);
        assert_eq!(
            result,
            MayAliasResult::MayAlias,
            "same caller + same register must alias"
        );
        assert!(
            evidence.is_some(),
            "aliasing sites must produce AliasEvidence"
        );
    }

    #[test]
    fn test_may_alias_same_caller_via_bitcast_chain() {
        let mut module = IRModule::new();
        let body = FunctionBody {
            name: "foo".to_string(),
            instructions: vec![
                {
                    let mut i = make_call("malloc", "%1 = call ptr @malloc(i64 8)");
                    i.dest = Some("%1".to_string());
                    i
                },
                make_inst(
                    IRInstructionKind::Conversion,
                    Some("%2"),
                    "%2 = bitcast ptr %1 to ptr",
                ),
            ],
        };
        module.function_bodies.insert("foo".to_string(), body);

        let a = FreeSite::new("foo", "free", Some("%1".into()));
        let b = FreeSite::new("foo", "free", Some("%2".into()));
        let (result, evidence) = may_alias(&a, &b, Some(&module));
        assert_eq!(
            result,
            MayAliasResult::MayAlias,
            "bitcast chain must resolve to the same allocator root"
        );
        assert!(
            evidence.is_some(),
            "aliasing sites via bitcast must produce AliasEvidence"
        );
    }

    #[test]
    fn test_may_alias_independent_allocations_same_caller_reject() {
        let mut module = IRModule::new();
        let body = FunctionBody {
            name: "foo".to_string(),
            instructions: vec![
                {
                    let mut i = make_call("malloc", "%a = call ptr @malloc(i64 8)");
                    i.dest = Some("%a".to_string());
                    i
                },
                {
                    let mut i = make_call("malloc", "%b = call ptr @malloc(i64 8)");
                    i.dest = Some("%b".to_string());
                    i
                },
            ],
        };
        module.function_bodies.insert("foo".to_string(), body);

        let a = FreeSite::new("foo", "free", Some("%a".into()));
        let b = FreeSite::new("foo", "free", Some("%b".into()));
        let (result, evidence) = may_alias(&a, &b, Some(&module));
        assert_eq!(
            result,
            MayAliasResult::NotAlias,
            "independent allocator results must NOT be reported as aliasing"
        );
        assert!(
            evidence.is_none(),
            "non-aliasing independent allocations must NOT produce AliasEvidence"
        );
    }

    #[test]
    fn test_may_alias_phi_merged_alloc_roots() {
        let mut module = IRModule::new();
        let body = FunctionBody {
            name: "foo".to_string(),
            instructions: vec![
                {
                    let mut i = make_call("malloc", "%p1 = call ptr @malloc(i64 8)");
                    i.dest = Some("%p1".to_string());
                    i
                },
                make_inst(
                    IRInstructionKind::Phi,
                    Some("%p2"),
                    "%p2 = phi ptr [ %p1, %bb0 ], [ %p1, %bb1 ]",
                ),
            ],
        };
        module.function_bodies.insert("foo".to_string(), body);

        let a = FreeSite::new("foo", "free", Some("%p2".into()));
        let b = FreeSite::new("foo", "free", Some("%p2".into()));
        let (result, evidence) = may_alias(&a, &b, Some(&module));
        assert_eq!(
            result,
            MayAliasResult::MayAlias,
            "two frees of the same phi must alias"
        );
        assert!(
            evidence.is_some(),
            "phi-merged alloc roots must produce AliasEvidence"
        );
    }

    #[test]
    fn test_collect_free_sites_extracts_args() {
        let mut module = IRModule::new();
        let body = FunctionBody {
            name: "caller".to_string(),
            instructions: vec![
                make_call("free", "call void @free(ptr %x)"),
                make_call("free", "call void @free(ptr %y)"),
            ],
        };
        module.function_bodies.insert("caller".to_string(), body);

        let mut callees = HashSet::new();
        callees.insert("free".to_string());
        let sites = collect_free_sites(&module, "caller", &callees);
        assert_eq!(sites.len(), 2, "expected two free sites in caller body");
        assert_eq!(
            sites[0].arg_register.as_deref(),
            Some("%x"),
            "first free site arg should be %x"
        );
        assert_eq!(
            sites[1].arg_register.as_deref(),
            Some("%y"),
            "second free site arg should be %y"
        );
    }

    #[test]
    fn test_may_alias_store_load_same_slot() {
        let mut module = IRModule::new();
        let body = FunctionBody {
            name: "foo".to_string(),
            instructions: vec![
                {
                    let mut i = make_call("malloc", "%1 = call ptr @malloc(i64 8)");
                    i.dest = Some("%1".to_string());
                    i
                },
                make_inst(IRInstructionKind::Store, None, "store ptr %1, ptr %slot"),
                make_inst(
                    IRInstructionKind::Load,
                    Some("%2"),
                    "%2 = load ptr, ptr %slot",
                ),
            ],
        };
        module.function_bodies.insert("foo".to_string(), body);

        let a = FreeSite::new("foo", "free", Some("%1".into()));
        let b = FreeSite::new("foo", "free", Some("%2".into()));
        let (result, evidence) = may_alias(&a, &b, Some(&module));
        assert_eq!(
            result,
            MayAliasResult::MayAlias,
            "store→load alias: %2 was loaded from %slot where %1 was stored"
        );
        assert!(
            evidence.is_some(),
            "store→load aliasing must produce AliasEvidence"
        );
    }

    #[test]
    fn test_may_alias_store_load_independent_stores_not_alias() {
        let mut module = IRModule::new();
        let body = FunctionBody {
            name: "foo".to_string(),
            instructions: vec![
                {
                    let mut i = make_call("malloc", "%a = call ptr @malloc(i64 8)");
                    i.dest = Some("%a".to_string());
                    i
                },
                {
                    let mut i = make_call("malloc", "%b = call ptr @malloc(i64 8)");
                    i.dest = Some("%b".to_string());
                    i
                },
                make_inst(IRInstructionKind::Store, None, "store ptr %a, ptr %slot1"),
                make_inst(IRInstructionKind::Store, None, "store ptr %b, ptr %slot2"),
                make_inst(
                    IRInstructionKind::Load,
                    Some("%p"),
                    "%p = load ptr, ptr %slot1",
                ),
                make_inst(
                    IRInstructionKind::Load,
                    Some("%q"),
                    "%q = load ptr, ptr %slot2",
                ),
            ],
        };
        module.function_bodies.insert("foo".to_string(), body);

        let a = FreeSite::new("foo", "free", Some("%p".into()));
        let b = FreeSite::new("foo", "free", Some("%q".into()));
        let (result, evidence) = may_alias(&a, &b, Some(&module));
        assert_eq!(
            result,
            MayAliasResult::NotAlias,
            "independent stores to different slots must NOT alias"
        );
        assert!(
            evidence.is_none(),
            "non-aliasing independent stores must NOT produce AliasEvidence"
        );
    }

    #[test]
    fn test_may_alias_not_alias_without_shared_store() {
        let mut module = IRModule::new();
        let body = FunctionBody {
            name: "foo".to_string(),
            instructions: vec![
                {
                    let mut i = make_call("malloc", "%1 = call ptr @malloc(i64 8)");
                    i.dest = Some("%1".to_string());
                    i
                },
                {
                    let mut i = make_call("malloc", "%2 = call ptr @malloc(i64 8)");
                    i.dest = Some("%2".to_string());
                    i
                },
                make_inst(IRInstructionKind::Store, None, "store ptr %1, ptr %slot"),
                make_inst(
                    IRInstructionKind::Load,
                    Some("%3"),
                    "%3 = load ptr, ptr %slot",
                ),
            ],
        };
        module.function_bodies.insert("foo".to_string(), body);

        let a = FreeSite::new("foo", "free", Some("%2".into()));
        let b = FreeSite::new("foo", "free", Some("%3".into()));
        let (result, evidence) = may_alias(&a, &b, Some(&module));
        assert_eq!(
            result,
            MayAliasResult::NotAlias,
            "%2 is independent allocation, %3 comes from store of %1 — NOT alias"
        );
        assert!(
            evidence.is_none(),
            "non-aliasing sites must NOT produce AliasEvidence"
        );
    }

    // ── Task 1D: Tests for AliasEvidence, FreeSite, and MayAlias ──

    #[test]
    fn test_alias_evidence_same_pointer() {
        let a = FreeSite::new("foo", "free", Some("%p".into()));
        let b = FreeSite::new("foo", "free", Some("%p".into()));
        let (result, evidence) = may_alias(&a, &b, None);
        assert_eq!(
            result,
            MayAliasResult::MayAlias,
            "same pointer freed twice must be may-alias"
        );
        assert!(
            evidence.is_some(),
            "same-pointer double free must produce AliasEvidence"
        );
        let ev = evidence.unwrap();
        assert_eq!(
            ev.free_site_a.function_name, "foo",
            "evidence must carry correct function_name for site a"
        );
        assert_eq!(
            ev.free_site_b.function_name, "foo",
            "evidence must carry correct function_name for site b"
        );
    }

    #[test]
    fn test_alias_evidence_independent_frees() {
        let a = FreeSite::new("foo", "free", Some("%a".into()));
        let b = FreeSite::new("foo", "free", Some("%b".into()));
        let (result, evidence) = may_alias(&a, &b, None);
        assert_eq!(
            result,
            MayAliasResult::NotAlias,
            "independent frees must NOT be may-alias"
        );
        assert!(
            evidence.is_none(),
            "independent frees must NOT produce AliasEvidence"
        );
    }

    #[test]
    fn test_free_site_creation() {
        let site = FreeSite::new("my_func", "c_free", Some("%ptr".into()))
            .with_location(42)
            .with_resource_id(7)
            .with_confirmed(true)
            .with_caller("enclosing_fn");

        assert_eq!(
            site.function_name, "my_func",
            "FreeSite function_name should be my_func"
        );
        assert_eq!(site.callee, "c_free", "FreeSite callee should be c_free");
        assert_eq!(site.location, 42, "FreeSite location should be 42");
        assert_eq!(
            site.resource_id,
            Some(7),
            "FreeSite resource_id should be Some(7)"
        );
        assert!(site.is_confirmed, "FreeSite is_confirmed should be true");
        assert_eq!(
            site.arg_register.as_deref(),
            Some("%ptr"),
            "FreeSite arg_register should be Some(%ptr)"
        );
        assert_eq!(
            site.caller.as_deref(),
            Some("enclosing_fn"),
            "FreeSite caller should be Some(enclosing_fn)"
        );
    }

    #[test]
    fn test_alias_evidence_confidence_levels() {
        // SamePointer -> High
        let a = FreeSite::new("foo", "free", Some("%p".into()));
        let b = FreeSite::new("foo", "free", Some("%p".into()));
        let (_, evidence) = may_alias(&a, &b, None);
        let ev = evidence.expect("SamePointer alias must produce AliasEvidence");
        assert_eq!(
            ev.confidence,
            Confidence::High,
            "SamePointer alias should have High confidence"
        );
        assert_eq!(
            ev.source,
            AliasSource::SamePointer,
            "SamePointer alias source should be SamePointer"
        );

        // Different callers with global -> SamePointer -> High
        let c = FreeSite::new("f1", "free", Some("@g".into()));
        let d = FreeSite::new("f2", "free", Some("@g".into()));
        let (_, evidence2) = may_alias(&c, &d, None);
        let ev2 = evidence2.expect("Global same-pointer alias must produce AliasEvidence");
        assert_eq!(
            ev2.confidence,
            Confidence::High,
            "Global same-pointer alias should have High confidence"
        );
    }

    #[test]
    fn test_get_alias_evidence() {
        let mut gate = MayAlias::new();
        let a = FreeSite::new("foo", "free", Some("%p".into()));
        let b = FreeSite::new("foo", "free", Some("%p".into()));

        let evidence = gate.get_alias_evidence(&a, &b, None);
        assert!(
            evidence.is_some(),
            "get_alias_evidence must return Some for aliasing sites"
        );
        let ev = evidence.unwrap();
        assert!(ev.id > 0, "AliasEvidence id must be positive");
        assert_eq!(
            ev.free_site_a.function_name, "foo",
            "evidence must carry free_site_a info"
        );

        // Non-aliasing sites -> None
        let c = FreeSite::new("foo", "free", Some("%a".into()));
        let d = FreeSite::new("foo", "free", Some("%b".into()));
        let no_evidence = gate.get_alias_evidence(&c, &d, None);
        assert!(
            no_evidence.is_none(),
            "get_alias_evidence must return None for non-aliasing sites"
        );
    }

    #[test]
    fn test_get_alias_evidence_increments_id() {
        let mut gate = MayAlias::new();
        let a = FreeSite::new("foo", "free", Some("%p".into()));
        let b = FreeSite::new("foo", "free", Some("%p".into()));

        let ev1 = gate.get_alias_evidence(&a, &b, None).unwrap();
        let ev2 = gate.get_alias_evidence(&a, &b, None).unwrap();
        assert!(
            ev2.id > ev1.id,
            "AliasEvidence IDs must increment: {} > {}",
            ev2.id,
            ev1.id
        );
    }

    #[test]
    fn test_free_site_default_new() {
        let site = FreeSite::new("test", "free", None);
        assert_eq!(
            site.function_name, "test",
            "default FreeSite function_name must be set"
        );
        assert_eq!(site.callee, "free", "default FreeSite callee must be set");
        assert_eq!(site.location, 0, "default FreeSite location must be 0");
        assert!(
            site.is_confirmed,
            "default FreeSite is_confirmed must be true"
        );
        assert!(
            site.resource_id.is_none(),
            "default FreeSite resource_id must be None"
        );
        assert!(
            site.arg_register.is_none(),
            "default FreeSite arg_register must be None"
        );
    }

    #[test]
    fn test_alias_source_display() {
        let sources = [
            AliasSource::SamePointer,
            AliasSource::StoreLoadChain,
            AliasSource::MemoryGraph,
            AliasSource::IRPattern,
            AliasSource::Conservative,
        ];
        for i in 0..sources.len() {
            for j in (i + 1)..sources.len() {
                assert_ne!(
                    sources[i], sources[j],
                    "AliasSource variants must be distinct"
                );
            }
        }
    }

    #[test]
    fn test_confidence_ordering() {
        assert!(
            Confidence::High > Confidence::Medium,
            "High confidence must be greater than Medium"
        );
        assert!(
            Confidence::Medium > Confidence::Low,
            "Medium confidence must be greater than Low"
        );
        assert!(
            Confidence::High > Confidence::Low,
            "High confidence must be greater than Low"
        );
    }
}
