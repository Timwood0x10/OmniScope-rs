# Pull Request

## Description

<!-- Provide a clear and concise description of your changes -->

**Type of Change:**
<!-- Mark the relevant option with an 'x' -->
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Performance improvement
- [ ] Refactoring (no functional changes)
- [ ] Documentation update
- [ ] Test improvement
- [ ] Build/CI improvement

**Component:**
<!-- Mark the relevant option with an 'x' -->
- [ ] Core Infrastructure (Layer 1)
- [ ] IR Abstraction (Layer 2)
- [ ] Dataflow Engine (Layer 3)
- [ ] Semantic Analysis (Layer 4)
- [ ] Analysis Passes (Layer 5)
- [ ] Pipeline Orchestration (Layer 6)
- [ ] CLI & Output (Layer 7)
- [ ] Build System
- [ ] Documentation
- [ ] Other

## Related Issues

<!-- Link to related issues using "Fixes #123" or "Related to #456" -->

Fixes #

## Changes Made

<!-- List the key changes made in this PR -->

1.
2.
3.

## Testing

<!-- Describe the tests you ran to verify your changes -->

**Test Coverage:**
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed
- [ ] Edge cases covered
- [ ] Error handling tested

**Test Details:**
<!-- Provide details about the testing you performed -->

```bash
# Commands run to test the changes
make test
make check
```

## Code Quality Checklist

<!-- Mark completed items with an 'x' -->

**Formatting & Linting:**
- [ ] Code formatted with `make fmt`
- [ ] No clippy warnings (`make check` shows 0 errors)
- [ ] No `#[allow(dead_code)]` used to suppress warnings

**Code Standards:**
- [ ] File size ≤ 1000 lines (including comments and tests)
- [ ] Functional equivalence maintained after refactoring
- [ ] No unnecessary code deletion
- [ ] No git commands used in changes

**Testing Standards (Tier-1):**
- [ ] Tests focus on detecting hidden bugs
- [ ] Positive tests (happy path) included
- [ ] Negative tests (edge cases) included
- [ ] Stress/concurrency tests for atomic/lock-free code
- [ ] No `println!` in tests (use `tracing` test_subscriber)
- [ ] All assertions have meaningful error messages
- [ ] Miri used for raw pointer code
- [ ] Loom used for lock-free code testing

**Documentation:**
- [ ] Code comments in English
- [ ] Public APIs documented with `///` doc comments
- [ ] Module-level docs with `//!` where appropriate
- [ ] README updated if needed

**Safety:**
- [ ] No new unsafe code without safety documentation
- [ ] All unsafe blocks have `// SAFETY:` comments
- [ ] Memory safety verified for unsafe operations
- [ ] Thread safety verified for concurrent code

## Performance Impact

<!-- Describe any performance impact of your changes -->

- [ ] No performance impact
- [ ] Performance improved
- [ ] Performance degraded (explain why acceptable)

**Benchmark Results:**
<!-- If applicable, provide benchmark results -->

```
Before:
After:
```

## Breaking Changes

<!-- If this is a breaking change, describe the impact and migration path -->

**Breaking Change Details:**

- What breaks:
- Why it's necessary:
- Migration path:

## Additional Notes

<!-- Add any other context about the PR here -->

## Reviewer Guidelines

<!-- For reviewers -->

**Please check:**
1. All CI checks pass
2. Code follows project style guidelines
3. Tests are meaningful and comprehensive
4. Documentation is clear and accurate
5. No security vulnerabilities introduced
6. Performance impact is acceptable

---

**By submitting this pull request, I confirm that:**
- I have read and followed the [CONTRIBUTING.md](CONTRIBUTING.md) guidelines
- I have tested my changes thoroughly
- I have not introduced any breaking changes without prior discussion
- I have documented all new public APIs
- I have added appropriate tests for my changes
