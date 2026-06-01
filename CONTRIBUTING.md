# Contributing to OmniScope-rs

Thank you for your interest in contributing to OmniScope-rs! This document provides guidelines and rules for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [License](#license)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Standards](#testing-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Project Architecture](#project-architecture)

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). Please be respectful and constructive in all interactions.

## License

OmniScope-rs is licensed under the Apache License 2.0. By contributing to this project, you agree that your contributions will be licensed under the same license.

## Getting Started

### Prerequisites

- Rust 1.75.0 or later
- LLVM 17.0 or later
- Make

### Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/OmniScope-rs.git
   cd OmniScope-rs
   ```
3. Install development tools:
   ```bash
   make install-tools
   ```
4. Build the project:
   ```bash
   make build
   ```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b bugfix/your-bugfix-name
```

### 2. Make Changes

Follow the [Coding Standards](#coding-standards) and [Testing Standards](#testing-standards).

### 3. Run Checks

Before committing, ensure all checks pass:

```bash
make dev  # Runs fmt, check, and test
```

### 4. Commit Changes

Follow the [Commit Guidelines](#commit-guidelines).

### 5. Push and Create PR

```bash
git push origin your-branch-name
```

Then create a Pull Request on GitHub.

## Coding Standards

### Critical Rules

**⚠️ NEVER:**
- Delete project files without explicit permission
- Execute `rm` commands
- Use `#[allow(dead_code)]` to suppress warnings
- Use any git commands in your changes
- Introduce breaking changes without prior discussion

**✅ ALWAYS:**
- Maintain functional equivalence after refactoring
- Run `make fmt` after modifications
- Ensure `make check` shows 0 errors
- Keep file size ≤ 1000 lines (including comments and tests)

### Rust Style Guide

#### Naming Conventions

- **Functions/Variables**: `snake_case`
- **Types/Traits**: `UpperCamelCase`
- **Constants**: `SCREAMING_SNAKE_CASE`
- **Modules**: `snake_case`

#### Documentation

- Use `///` for documentation comments
- Use `//!` for module-level documentation
- All comments must be in English
- Document all public APIs

#### Error Handling

- Use `thiserror` for library errors
- Use `anyhow` for application errors
- Prefer the `?` operator for error propagation
- Never panic in library code

#### Ownership

- Design APIs considering ownership transfer vs borrowing
- Use `Cow<str>` for flexible string handling
- Prefer references over clones when possible

#### Performance

- Use `Vec::with_capacity()` when size is known
- Avoid frequent allocations
- Use `Arc` for shared ownership across threads
- Use `Rc` for shared ownership in single-threaded context

### Code Organization

```
src/
├── lib.rs           # Library entry point
├── error.rs         # Error types
├── config.rs        # Configuration
└── module_name/     # Module directory
    ├── mod.rs       # Module entry
    ├── types.rs     # Type definitions
    ├── impl.rs      # Implementations
    └── tests.rs     # Module tests
```

## Testing Standards

### Tier-1 Testing Philosophy

**"Proof, Not Prayer"** - Tests must prove code won't crash in extreme cases.

### The Golden Trio of Coverage

Every feature must have:

1. **Positive Tests (Happy Path)**
   - Normal usage scenarios
   - Expected inputs and outputs

2. **Negative Tests (Edge Cases)**
   - Null pointers
   - Zero-length allocations
   - Integer overflow
   - Invalid inputs
   - Empty collections

3. **Stress/Concurrency Tests**
   - 50+ threads for atomic/lock-free logic
   - Large inputs
   - Memory pressure

### Testing Rules

**Required:**
- ✅ Deterministic safety: 100% coverage for all `unsafe` code paths
- ✅ All assertions must have meaningful error messages
- ✅ Use `tracing` test_subscriber (no `println!` in tests)
- ✅ Test module by module sequentially

**Forbidden:**
- ❌ Coverage testing (wastes time and resources)
- ❌ Superficial assertions without meaningful checks
- ❌ `println!` in tests

### Specialized Testing

#### Unsafe Code
```bash
# Run Miri for raw pointer code
make miri
```

#### Lock-Free Code
Use `loom` for testing:
```rust
#[cfg(test)]
mod tests {
    use loom::model::Builder;

    #[test]
    fn test_concurrent_access() {
        Builder::default().check(|| {
            // Your concurrent test
        });
    }
}
```

#### Fuzzing
Required for metadata parsing functions:
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_parse_metadata(input in ".*") {
        // Fuzz test
    }
}
```

### Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Positive tests
    #[test]
    fn test_normal_case() {
        // ...
    }

    // Negative tests
    #[test]
    fn test_edge_case_empty() {
        // ...
    }

    #[test]
    fn test_edge_case_overflow() {
        // ...
    }

    // Stress tests
    #[test]
    fn test_concurrent_access() {
        // ...
    }
}
```

## Commit Guidelines

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `test`: Test changes
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `chore`: Build process or auxiliary tool changes

### Examples

```
feat(analyzer): add FFI boundary detection pass

Implement FFI boundary detection to identify unsafe FFI calls
between Rust and C code. This pass analyzes function signatures
and marks potential safety violations.

Closes #123
```

```
fix(dataflow): correct pointer alias analysis

The alias analysis was incorrectly handling pointer arithmetic
in certain edge cases. This fix ensures correct alias detection
for all pointer operations.

Fixes #456
```

## Pull Request Process

### Before Submitting

1. **Run all checks:**
   ```bash
   make ci
   ```

2. **Ensure tests pass:**
   ```bash
   make test
   ```

3. **Check code quality:**
   ```bash
   make check
   ```

4. **Format code:**
   ```bash
   make fmt
   ```

### PR Requirements

- All CI checks must pass
- Code must follow all coding standards
- Tests must be comprehensive (Golden Trio)
- Documentation must be updated
- No breaking changes without discussion

### Review Process

1. At least one approval required
2. All CI checks must pass
3. No unresolved conversations
4. Squash and merge preferred

## New Features

### Multi-Language Semantic Extensions

OmniScope now supports comprehensive semantic analysis for 7 programming languages with 19 new semantic variants:

#### Python (5 variants)
- `PythonRefcountInc` - Py_INCREF reference count increment
- `PythonRefcountDec` - Py_DECREF reference count decrement
- `PythonBorrowedRef` - PyList_GetItem borrowed reference
- `PythonOwnedRef` - PyBytes_FromString owned reference
- `PythonGilProtected` - PyGILState_Ensure/Release GIL protection

#### Go (4 variants)
- `GoDeferCleanup` - defer C.free(ptr) deferred cleanup
- `GoFinalizer` - runtime.SetFinalizer finalizer pattern
- `GoCgoWrapper` - _Cgo_* wrapper function
- `GoRuntimeAlloc` - runtime.mallocgc runtime allocation

#### C++ (4 variants)
- `CppUniquePtr` - std::unique_ptr exclusive ownership
- `CppSharedPtr` - std::shared_ptr shared ownership
- `CppDestructor` - ~ClassName() destructor pattern
- `CppExceptionPath` - try/catch exception path

#### C# (3 variants)
- `CsharpSafeHandle` - SafeHandle.ReleaseHandle safe handle
- `CsharpFinalizer` - ~Destructor() finalizer
- `CsharpPinvokeMarshal` - P/Invoke marshalling interop

#### Java (3 variants)
- `JavaLocalRef` - JNI LocalRef local reference
- `JavaGlobalRef` - JNI GlobalRef global reference
- `JavaWeakRef` - JNI WeakGlobalRef weak global reference

### Language Adapters

#### Go/CGO Adapter
- Comprehensive Go memory model analysis (GC vs C heap)
- CGO call convention detection and pointer passing rules
- Go-specific function pattern recognition (runtime, cgo)
- FFI safety assessment for Go functions

#### Python C API Adapter
- Python reference counting analysis (Py_INCREF/Py_DECREF)
- Object lifecycle detection (creation, borrowing, stealing)
- GIL (Global Interpreter Lock) management analysis
- Python-specific FFI pattern recognition

## Project Architecture

OmniScope-rs follows a 7-layer architecture:

```
Layer 7: CLI & Output
Layer 6: Pipeline Orchestration
Layer 5: Analysis Pass System (25+ passes)
Layer 4: Semantic Analysis Engine
Layer 3: Dataflow Engine
Layer 2: IR Abstraction Layer
Layer 1: Core Infrastructure
```

### Layer Responsibilities

- **Layer 1**: Error types, diagnostics, fact system, memory pool
- **Layer 2**: IR nodes, type system, metadata
- **Layer 3**: CFG, DFG, alias analysis, call graph
- **Layer 4**: Type inference, scope analysis, symbol resolution
- **Layer 5**: 25+ analysis passes (FFI, memory, taint, concurrency)
- **Layer 6**: Pass scheduling, dependency management, caching
- **Layer 7**: CLI parsing, output formatting, reporting

### When Adding Features

1. Identify the appropriate layer
2. Follow the dependency direction (lower layers first)
3. Maintain layer isolation
4. Add tests at the appropriate level

## Getting Help

- **Documentation**: Check the `aim/` directory for detailed design docs
- **Issues**: Search existing issues before creating new ones
- **Discussions**: Use GitHub Discussions for questions
- **Chat**: Join our community chat (link in README)

## Recognition

Contributors are recognized in:
- Git commit history
- Release notes
- Contributors file

Thank you for contributing to OmniScope-rs! 🎉
