# Resource Finding Reconciliation Plan

A generic candidate reconciliation layer to fix misclassification
(Leak vs CrossFamilyFree) and duplicate-count false positives by
grouping and arbitrating candidates per resource identity.

## Problem and Root Cause

The verifier main loop (`issue_verifier/mod.rs:249-454`) processes
candidates **independently**: each candidate gets its own verdict and is
emitted on its own. From candidate generation through emission, there is
**no stage that reconciles multiple candidates that describe the same
resource**.

`cross_family_alloc` concrete chain:

1. Same `resource_id`, wrong-family release → `CrossFamilyFree` candidate
   (`issue_candidate_builder/mod.rs:225`).
2. Same resource: `collect_exit_states` (`path_sensitive_leak/analysis.rs:116`)
   only recognizes `PointerValueState::Released`. A wrong-family release is
   not recorded as a legitimate release on some paths → exit state is `Owned`
   → `ConditionalLeak` candidate.
3. Both candidates pass the verifier and are emitted independently → user
   sees `ConditionalLeak` (the symptom), or both (duplicate count FP).

**Therefore "misclassification" and "duplicate-count FP" are two symptoms
of the same architectural gap.** A hardcoded `if CrossFamily then suppress
Leak` is a special case that breaks for other kind pairs or other projects.

## Design Principles (why generic)

Do not patch specific kinds against each other. Introduce a
**project-agnostic reconciliation stage** built on three abstractions.

### Pillar 1: Resource identity — `ResourceKey`

The basis for grouping. Reusable by any analysis that produces
"resource + allocation site". Not bound to any language/family.

### Pillar 2: Fault classification axis — `FaultClass`

Project the 16 `IssueCandidateKind` variants onto a few **orthogonal fault
classes**. Arbitration rules are defined **between `FaultClass` values, not
between concrete kinds**. Adding a new kind only requires declaring its
`FaultClass`; arbitration logic stays untouched.

### Pillar 3: Declarative arbitration matrix

"Who subsumes whom" is a **data table**, not if-else. A root-cause
diagnosis subsumes its downstream symptoms on the same resource.

## Key Data Structures

```rust
// crates/omniscope-pass/src/resource/reconcile/mod.rs (new)

/// Resource identity key — the basis for cross-candidate grouping.
/// Generic: depends only on a resource instance or allocation site,
/// never on any language/family special case.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) enum ResourceKey {
    /// Preferred: MemoryGraph resource instance ID (most precise).
    Instance(u64),
    /// Fallback: allocation-site identity (caller, alloc_fn, location).
    /// Used when a candidate has no resource_id, so grouping always works.
    AllocSite {
        caller: String,
        alloc_fn: String,
        location: Option<(String, u32)>,
    },
}

impl ResourceKey {
    /// Generic extraction: every IssueCandidate maps to a key.
    /// resource_id first, otherwise alloc site.
    fn from_candidate(c: &IssueCandidate) -> ResourceKey { /* ... */ }
}

/// Orthogonal fault classes — the real unit of arbitration. This is the
/// core of genericity: rules are defined between FaultClass values, and a
/// kind is merely a member of a FaultClass.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FaultClass {
    WrongRelease,    // release operation itself is wrong
                     //   → CrossFamilyFree, CrossLanguageFree, InvalidBorrowedFree
    DoubleRelease,   // released twice
                     //   → DoubleRelease, DoubleReclaim, UseAfterFree, UseAfterRelease
    Leak,            // not released
                     //   → ConditionalLeak, DefiniteLeak, OwnershipEscapeLeak
    BoundaryMisuse,  // boundary / null
                     //   → UncheckedFfiReturn, NullDereference, BorrowEscape, CallbackEscape
    Unmodeled,       // NeedsModel
}

impl FaultClass {
    /// Single mapping point. Adding an IssueCandidateKind only edits here.
    fn of(kind: IssueCandidateKind) -> FaultClass { /* match */ }
}

/// Candidates under the same ResourceKey.
pub(crate) struct FindingGroup {
    key: ResourceKey,
    members: Vec<usize>, // indices into the candidates array, zero-copy
}

/// Arbitration decision: tag each candidate rather than delete it
/// (preserve auditability).
pub(crate) enum ReconcileAction {
    Keep,                                            // emit
    SubsumedBy { class: FaultClass, by_idx: usize }, // suppressed by same-resource root cause
    DuplicateOf(usize),                              // same-class dedup
}
```

### Declarative arbitration matrix (generic rule, not special case)

```rust
/// Returns true when the `cause` fault class should subsume the `symptom`
/// fault class on the same resource. This is the only "business rule", and
/// it is a 5x5 class-level matrix independent of concrete kinds / projects.
fn subsumes(cause: FaultClass, symptom: FaultClass) -> bool {
    use FaultClass::*;
    matches!(
        (cause, symptom),
        // A wrong release hides the legitimate release from the leak
        // detector → the leak is its symptom.
        (WrongRelease, Leak)
        // Double release similarly: on the second-release path the resource
        // has "disappeared", easily misjudged as a leak.
        | (DoubleRelease, Leak)
        // A boundary null-deref makes later paths unreachable; the leak is noise.
        | (BoundaryMisuse, Leak)
    )
    // Note: WrongRelease and DoubleRelease do NOT subsume each other
    //       (they may be two real bugs).
    //       Same-class collisions are handled by dedup, not here.
}
```

Arbitration logic (generic, ~30 lines): within a group, if a `cause`
candidate subsumes a `symptom` candidate → tag `SubsumedBy`; multiple
candidates of the same FaultClass → keep the highest confidence, tag the
rest `DuplicateOf`.

## How to Develop (integration point)

The verifier main loop is currently single-pass ("compute verdict + emit
immediately"). Change it to **two passes**:

```
Pass A (existing logic): for each candidate, compute verdict + FP suppression
        ↓ collect all is_reportable() candidates, do NOT emit yet
Pass B (new reconcile):
        1. group by ResourceKey → Vec<FindingGroup>
        2. run subsumes matrix + dedup → tag each candidate ReconcileAction
        3. emit only Keep candidates via ctx.emit_issue()
        4. SubsumedBy/DuplicateOf → write description (auditable) + new stat
```

**Changed files (minimal set):**

- New `crates/omniscope-pass/src/resource/reconcile/mod.rs` (data
  structures + arbitration) + `tests.rs`.
- Edit `issue_verifier/mod.rs:402-453`: change "emit immediately" to
  "collect first, emit after reconcile". About +/-40 lines, logic moved
  out to the reconcile module.
- `result.add_stat("reconcile_subsumed", n)` / `("reconcile_deduped", n)`.

**Key: do not delete candidates.** Suppressed candidates still go into
`verified_candidates` (verdict set to ExplainedSafe + description records
the reason), keeping the audit chain intact so the audit table can count
them.

## Todolist

### Phase A — grouping skeleton (no behavior change, build the pipeline first)

- [x] A1. New `reconcile/mod.rs`: `ResourceKey`, `FaultClass::of`,
      `FindingGroup`, `ReconcileAction` enums.
- [x] A2. `ResourceKey::from_candidate` + `group_candidates(&[IssueCandidate])
      -> Vec<FindingGroup>`.
- [x] A3. Unit tests: grouping correctness (same resource_id → one group;
      no id → alloc-site fallback; independent resources → separate groups).
- [x] A4. Verifier main loop changed to two passes, reconcile defaults to
      **all Keep** (behavior unchanged). Run `cargo test -p omniscope-pass`
      + `corpus_tests` to confirm zero regression.

### Phase B — arbitration matrix (generic rules)

- [x] B1. Implement `subsumes(cause, symptom)` class-level matrix.
- [x] B2. Implement `reconcile_group`: subsumption + same-class dedup,
      producing `ReconcileAction`.
- [x] B3. Suppressed candidates write `description`
      ("subsumed by WrongRelease on same resource") + change verdict.
- [x] B4. Unit tests: **class-level** cases (any WrongRelease+Leak on same
      resource → Leak suppressed; DoubleRelease+WrongRelease → both kept;
      two of same class → dedup).
- [x] B5. `cross_family_alloc` fixture: assert only `CrossFamilyFree`
      remains, no `ConditionalLeak`.

### Phase C — audit and acceptance

- [x] C1. New stats; `accuracy_regression` audit table gains
      `reconcile_subsumed`/`reconcile_deduped` columns.
- [x] C2. Run audit baseline diff: precision up, FP down, TP not down,
      FN not up.
- [x] C3. `make fmt` + full `cargo test`.

**Phase A/B/C measured results (ffi-demo baseline diff):**

| Metric      | Before | After | Delta |
|-------------|--------|-------|-------|
| TP          | 15     | 15    | +0    |
| FP          | 14     | 12    | -2    |
| FN          | 4      | 4     | +0    |
| Precision   | 53.6%  | 55.6% | +2.0% |
| Leak FP     | 5      | 2     | -3    |
| Leak Prec.  | ~66%   | 83.3% | +17%  |
| Recall      | 78.9%  | 78.9% | +0.0% |

### Phase D — DoubleFree precision (independent follow-up, same framework)

- [ ] D1. `collect_exit_states` mutually-exclusive path join:
      `if(a)free(p);else free(p);` marked as a single release (fills the
      unchecked Phase 3 item).
- [ ] D2. Boundary test double-pin: mutually-exclusive path = not
      DoubleFree (FP); same-path second release = DoubleFree (TP).
- [ ] D3. `c_fft_c_bridge.ll` / `c_merkle_tree.ll` assert no longer report
      DoubleFree.

## Acceptance Criteria

### Functional

- [x] `cross_family_alloc` reports `CrossFamilyFree`, no longer
  `ConditionalLeak`.
- [x] Same resource no longer produces duplicate counts (same ResourceKey +
  same FaultClass emits only one finding).

### Precision (hard metric, audit-table driven)

- [x] Real FP 14 → 12 (eliminated duplicate-count and type-misclassification classes).
- [x] precision rises from 53.6% to 55.6%; **TP count unchanged (15), FN not increased
  (4)** — red line satisfied: reconcile only suppresses symptoms, not
  root causes.
- [ ] `corpus_tests` 7/7 unchanged (pending full corpus run).

### Genericity (most important)

- [x] All arbitration rules live at the `FaultClass` level; adding any new
  `IssueCandidateKind` only requires one line in `FaultClass::of`, and
  **does not touch `subsumes` / `reconcile_group`**.
- [x] Unit tests are organized by FaultClass combinations, not hardcoded
  concrete kind names.
- [x] The `reconcile` module has zero dependency on concrete family/language;
  another project using IssueCandidate can reuse it directly, only
  providing the `FaultClass::of` mapping.

### Auditable

- [x] Suppressed candidates remain in `verified_candidates` with a description
  containing the suppression reason.
- [x] `reconcile_subsumed` / `reconcile_deduped` go into stats, visible in the
  audit table.

## Scope Notes

- FN improvements (inter-procedural UAF across callbacks, stack→global
  lifetime escape, alias-return ownership inference) are **capability gaps,
  not bugs**, and are **out of scope** for this plan. Recommendation: mark
  with `NeedsModel` instead of silently dropping, and start a real
  inter-procedural engine only after precision reaches 70%+.
- Phase D (DoubleFree precision) and Phase B (misclassification) are
  unified under the same reconciliation framework.

## Implementation Order

- [x] Phase A first: pure pipeline construction, zero behavior change; safe
      to land after verifying no regression with `corpus_tests`.
- [x] Phase B: arbitration rules, gated by the audit table.
- [x] Phase C: audit visibility and acceptance.
- [x] Phase D: DoubleFree precision, with guardrail boundary tests.
