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

/// Describes a single free/release call site relevant to alias gating.
///
/// `arg_register` is the SSA pointer argument passed to the release
/// callee (e.g. `%buf`, `@gptr`). When the original IR was not parsed
/// with raw text, it may be `None`; the gate is permissive in that
/// case and reports `MayAlias` to avoid downgrading purely on missing
/// metadata.
#[derive(Debug, Clone)]
pub struct FreeSite {
    /// Enclosing function name (the caller that contains this free call).
    pub caller: String,
    /// Release callee symbol (e.g. `free`, `_ZdlPv`).
    pub callee: String,
    /// SSA register / global of the pointer argument, if recoverable.
    pub arg_register: Option<String>,
}

impl FreeSite {
    /// Convenience constructor for tests and the candidate-time path.
    pub fn new(caller: impl Into<String>, callee: impl Into<String>, arg: Option<String>) -> Self {
        Self {
            caller: caller.into(),
            callee: callee.into(),
            arg_register: arg,
        }
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
pub fn may_alias(a: &FreeSite, b: &FreeSite, ir_module: Option<&IRModule>) -> MayAliasResult {
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

    // Walk SSA roots through bitcast / GEP-0 / load chains and compare.
    let Some(body) = ir_module.and_then(|m| m.function_bodies.get(&a.caller)) else {
        // No body available — be permissive only on exact-arg matches above.
        return MayAliasResult::NotAlias;
    };

    let defs = build_def_map(body);

    let root_a = a
        .arg_register
        .as_deref()
        .map(|r| trace_root(r, &defs, &mut HashSet::new()));
    let root_b = b
        .arg_register
        .as_deref()
        .map(|r| trace_root(r, &defs, &mut HashSet::new()));

    match (root_a, root_b) {
        (Some(ref ra), Some(ref rb)) if ra == rb => MayAliasResult::MayAlias,
        (Some(ref ra), Some(ref rb)) => {
            // Phi-merged alloc roots: both roots are phis whose inputs all
            // come from the same allocator return value. If the union of
            // their phi-source roots overlaps, treat as may-alias.
            if phi_inputs_overlap(ra, rb, &defs) {
                MayAliasResult::MayAlias
            } else {
                MayAliasResult::NotAlias
            }
        }
        _ => MayAliasResult::NotAlias,
    }
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

/// Returns true when two SSA roots are both phi instructions whose
/// source-roots overlap. Captures the "phi-merged alloc roots" rule.
fn phi_inputs_overlap(
    ra: &str,
    rb: &str,
    defs: &HashMap<String, &omniscope_ir::IRInstruction>,
) -> bool {
    let inputs_a = phi_source_roots(ra, defs);
    let inputs_b = phi_source_roots(rb, defs);
    if inputs_a.is_empty() || inputs_b.is_empty() {
        return false;
    }
    inputs_a.iter().any(|s| inputs_b.contains(s))
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
        // Objective: extract the first SSA register from a free call.
        let raw = "call void @free(ptr %buf)";
        assert_eq!(
            first_call_arg_register(raw),
            Some("%buf".to_string()),
            "expected %buf to be extracted from call args"
        );
    }

    #[test]
    fn test_extract_first_register_with_attrs() {
        // Objective: register extraction must skip type/attribute tokens.
        let raw = "tail call void @free(ptr nonnull %p)";
        assert_eq!(
            first_call_arg_register(raw),
            Some("%p".to_string()),
            "expected %p when nonnull attribute is present"
        );
    }

    #[test]
    fn test_may_alias_different_callers_no_global() {
        // Objective: two free sites in different functions cannot must-alias
        // unless they share a global, so the gate must reject.
        let a = FreeSite::new("Z::free", "free", Some("%p".into()));
        let b = FreeSite::new("fallback::free_without_size", "free", Some("%q".into()));
        assert_eq!(
            may_alias(&a, &b, None),
            MayAliasResult::NotAlias,
            "different callers with no global root must NOT alias"
        );
    }

    #[test]
    fn test_may_alias_different_callers_same_global() {
        // Objective: globals with the same name span functions and DO alias.
        let a = FreeSite::new("f1", "free", Some("@g".into()));
        let b = FreeSite::new("f2", "free", Some("@g".into()));
        assert_eq!(
            may_alias(&a, &b, None),
            MayAliasResult::MayAlias,
            "two frees of the same global must alias even across functions"
        );
    }

    #[test]
    fn test_may_alias_same_caller_same_register() {
        // Objective: same caller, identical SSA register — trivial may-alias.
        let a = FreeSite::new("foo", "free", Some("%p".into()));
        let b = FreeSite::new("foo", "free", Some("%p".into()));
        assert_eq!(
            may_alias(&a, &b, None),
            MayAliasResult::MayAlias,
            "same caller + same register must alias"
        );
    }

    #[test]
    fn test_may_alias_same_caller_via_bitcast_chain() {
        // Objective: tracing through a bitcast must collapse to the same root.
        // foo:
        //   %1 = call ptr @malloc(i64 8)
        //   %2 = bitcast ptr %1 to ptr
        //   call void @free(ptr %1)
        //   call void @free(ptr %2)
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
        assert_eq!(
            may_alias(&a, &b, Some(&module)),
            MayAliasResult::MayAlias,
            "bitcast chain must resolve to the same allocator root"
        );
    }

    #[test]
    fn test_may_alias_independent_allocations_same_caller_reject() {
        // Objective: two distinct allocator calls in the same function must
        // NOT alias even though both are in `foo` — they are independent
        // pointers (the bun_alloc/c_fft pattern).
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
        assert_eq!(
            may_alias(&a, &b, Some(&module)),
            MayAliasResult::NotAlias,
            "independent allocator results must NOT be reported as aliasing"
        );
    }

    #[test]
    fn test_may_alias_phi_merged_alloc_roots() {
        // Objective: a phi whose inputs are themselves alloc returns must
        // be recognised as may-alias when both arguments root to the same
        // phi instruction.
        // foo:
        //   %p1 = call ptr @malloc(i64 8)
        //   %p2 = phi ptr [ %p1, %bb0 ], [ %p1, %bb1 ]
        //   call void @free(ptr %p2)
        //   call void @free(ptr %p2)  ; second free of same phi
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
        assert_eq!(
            may_alias(&a, &b, Some(&module)),
            MayAliasResult::MayAlias,
            "two frees of the same phi must alias"
        );
    }

    #[test]
    fn test_collect_free_sites_extracts_args() {
        // Objective: collect_free_sites returns one FreeSite per free call
        // in the body and recovers the first-arg register.
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
}
