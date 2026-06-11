# OmniScope-rs Extension Guide

This document is for developers who want to extend OmniScope-rs. It covers
adding new analysis passes, FP suppression rules, language adapters, FFI
contract libraries, FamilyId extensions, output formats, and SemanticEngine
refinements.

---

## 1. Adding a new analysis pass

Analysis passes are the basic unit of the OmniScope pipeline. All static
analysis logic is organized and scheduled as passes.

### 1.1 Choose placement

Pass source files live under `crates/omniscope-pass/src/`:

- `analysis/` — FFI boundary identification, function surface classification,
  structural analysis passes.
- `resource/` — Resource contract verification, ownership state tracking,
  allocation/deallocation pairing.

### 1.2 Implement the Pass trait

Every pass must implement `Pass`:

- `name() -> &'static str` — unique string identifier (used as topological sort key).
- `kind() -> PassKind` — `Foundation`, `Analysis`, or `Transformation`.
- `dependencies() -> Vec<&'static str>` — names of passes this depends on.
- `run(&self, ctx: &mut PassContext) -> Result<PassResult>` — core logic.

In `run()`:
- Read upstream output: `ctx.get::<T>("key")`.
- Emit issues: **must** use `ctx.emit_issue(issue)`, never directly push to
  `ctx.issues` (which bypasses the SRT gate).

### 1.3 Export and register

1. Add `pub use` in `crates/omniscope-pass/src/lib.rs`.
2. Add registration in `crates/omniscope-pipeline/src/pipeline.rs`'s
   `register_default_passes()`.

## 2. Adding a new R-N FP suppression rule

The FP suppression system is based on the SRT (Semantic Resolution Tree) gate.

### 2.1 Extend SemanticKind

Add a new variant in `crates/omniscope-semantics/src/resource/semantic_tree/kind.rs`.

### 2.2 Extend GateVerdict

Add a corresponding `Suppress*` variant in
`crates/omniscope-pass/src/resource/issue_gate.rs`.

### 2.3 Add suppression condition

Add a match branch in `issue_gate::check_issue()` mapping the `IssueKind` +
`SemanticKind` combination to the new verdict.

### 2.4 Implement structural inference

Add an inference function in
`crates/omniscope-semantics/src/resource/structural_inference/`, following
the naming convention `infer_<pattern>_summary()`.

### 2.5 Wire into StructuralInferencePass

Call the new inference function in `StructuralInferencePass::run()`.

## 3. Adding a new language adapter

Language adapters bridge language-specific FFI conventions into OmniScope's
unified analysis framework. Existing adapters (Python, Go, C++, C#, Java)
live in `crates/omniscope-semantics/src/resource/<lang>_adapter/`.

Steps:
1. Create adapter directory under `resource/`.
2. Implement language-specific logic (name mangling, allocator semantics,
   FamilyId mapping).
3. Register symbols in `FamilyRegistry::new()`.
4. Add patterns to `LanguageDetector::build_patterns()`.
5. Export the adapter in `crates/omniscope-semantics/src/lib.rs`.

## 4. Adding a new FFI contract library

FFI contract database at `crates/omniscope-semantics/src/resource/ffi_contract/`
records ownership semantics of known C libraries.

Steps:
1. Create contract file in `ffi_contract/builtin/`.
2. Define `FFIContract` entries per function.
3. Register in `ffi_contract/builtin/mod.rs`.
4. Add corresponding `FamilyId` and symbols to `FamilyRegistry`.

## 5. Extending FamilyId

`FamilyId` is a `u16` wrapper. Built-in IDs range from 1 to 24 (as of the
current codebase). User-defined families start at `USER_FAMILY_START = 256`.

```rust
// In crates/omniscope-types/src/resource_family.rs
pub const FAMILY_CUSTOM: FamilyId = FamilyId(25); // Next available ID
```

Then register the family in
`crates/omniscope-semantics/src/resource/family_registry.rs`.

## 6. PassContext KV key conventions

`PassContext.shared` uses string-keyed type-erased storage. Established keys:

| Key | Type | Written by | Read by |
|---|---|---|---|
| `"contract_graph"` | `ContractGraph` | ContractGraphBuilderPass | OwnershipSolverPass |
| `"summary_store"` | `SummaryStore` | SummaryBuilderPass | ContractGraphBuilderPass |
| `"ownership_states"` | `Vec<ResourceInstance>` | OwnershipSolverPass | IssueCandidateBuilderPass, LeakDetectionPass |
| `"issue_candidates"` | `Vec<IssueCandidate>` | IssueCandidateBuilderPass | IssueVerifierPass |
| `"behavior_summaries"` | `HashMap<String, FunctionBehavior>` | IRBehaviorSummaryPass | SummaryBuilderPass |
| `"structural_summaries"` | `Vec<ResourceSummary>` | StructuralInferencePass | ContractGraphBuilderPass |
| `"semantic_tree"` | `SemanticTree` | Multiple Layer 1 passes | IssueVerifierPass, issue_gate |
| `"surface_map"` | `HashMap<String, FunctionSurface>` | SurfaceClassifierPass | DangerSurfacePass, FFIBoundaryPass |
| `"call_graph"` | `CallGraph` | CallGraphPass | FFIBoundaryPass, SurfaceClassifierPass |
| `"raw_facts"` | `Vec<RawResourceFact>` | RawFactCollectorPass | Multiple downstream passes |
| `"module_index"` | `ModuleIndex` | PassManager | FFIBoundaryPass, LanguageAdapterFactPass |
| `"boundary_context"` | `BoundaryContext` | PassManager | IssueVerifierPass, IssueCandidateBuilderPass |
| `"cross_lang_edges"` | `Vec<CrossLangEdge>` | CallGraphPass | FFIBoundaryPass, SurfaceClassifierPass, DangerSurfacePass |
| `"srt_resolutions"` | `HashMap<String, Vec<SemanticKind>>` | StructuralInferencePass | PassContext::emit_issue (SRT gate) |

## 7. Adding a new output format

Output formatters are in `crates/omniscope-cli/src/output/`.

Steps:
1. Implement a formatting function in a new file (e.g., `html.rs`).
2. Add the format variant in `output/mod.rs`.
3. Add the CLI argument in `crates/omniscope-cli/src/main.rs`.

## 8. Extending SemanticEngine's FFIVerdict

`FFIVerdict` is in `crates/omniscope-semantics/src/resource/semantic_engine.rs`.

Steps:
1. Add a new variant to `FFIVerdict`.
2. Implement `safety_score()` and `is_safe()` for the new variant.
3. Add recognition logic in `assess_ffi_safety()`.
4. Update all `FFIVerdict` match branches in
   `crates/omniscope-pass/src/analysis/mod.rs`.

## Common pitfalls

1. **Directly manipulating `ctx.issues`** bypasses the SRT gate — always use
   `ctx.emit_issue()`.
2. **Confusing `ConditionalRelease` with `Release`** causes massive UAF false
   positives in OwnershipSolver.
3. **Forgetting to register a pass** in `register_default_passes()` causes
   silent failures — the pass is never executed.
4. **KV key spelling errors** in `ctx.get::<T>("key")` return `None` silently.
5. **`FamilyId(0)` is invalid** but won't panic — it silently fails all
   family-related checks.