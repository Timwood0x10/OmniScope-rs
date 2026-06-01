# OmniScope-rs Usage Guide

This guide provides detailed usage instructions for OmniScope-rs, including new features and adapters.

## Table of Contents

- [Getting Started](#getting-started)
- [Basic Usage](#basic-usage)
- [Language Adapters](#language-adapters)
  - [Go/CGO Adapter](#gocgo-adapter)
  - [Python C API Adapter](#python-c-api-adapter)
- [Multi-Language Semantic Extensions](#multi-language-semantic-extensions)
- [Advanced Features](#advanced-features)
- [Troubleshooting](#troubleshooting)

## Getting Started

### Installation

```bash
# Build from source
git clone https://github.com/your-username/OmniScope-rs.git
cd OmniScope-rs
make build

# Or install from crates.io (when available)
cargo install omniscope-cli
```

### Prerequisites

- Rust 1.75.0 or later
- LLVM 17+ (for full functionality)
- Make (for C++ pass compilation)

## Basic Usage

### Analyzing IR Files

```bash
# Analyze an LLVM IR file
omniscope analyze -i input.bc -o report.json --format json

# Analyze with specific loading strategy
omniscope analyze -i input.ll --load-strategy llvm-sys

# Boundary-only analysis (cross-language memory safety)
omniscope analyze -i input.bc --boundary-only
```

### Output Formats

- **json**: Machine-readable format for CI integration
- **sarif**: GitHub Code Scanning standard format
- **rich**: Colorized terminal output with detection traces

## Language Adapters

### Go/CGO Adapter

The Go/CGO adapter provides comprehensive analysis of Go memory management, including CGO (C Go) interop patterns.

#### Features

- **Go Memory Model Analysis**: Distinguishes between Go GC-managed heap and C heap memory
- **CGO Call Convention Detection**: Identifies CGO bridge functions and pointer passing rules
- **Go-Specific Pattern Recognition**: Recognizes runtime functions, CGO wrappers, and Go-specific patterns
- **FFI Safety Assessment**: Evaluates safety of Go functions based on memory management balance

#### Usage Examples

```rust
use omniscope_semantics::resource::go_adapter::GoAdapter;
use omniscope_types::Language;

// Create a Go adapter
let adapter = GoAdapter::new();

// Analyze a Go function
let analysis = adapter.analyze_function("runtime.mallocgc", None);
println!("Function: {}", analysis.function_name);
println!("Patterns: {:?}", analysis.patterns);
println!("Is CGO bridge: {}", analysis.is_cgo_bridge);
println!("FFI Safety: {:?}", analysis.ffi_safety);

// Analyze with function body (IR instructions)
let body = Some(function_body); // IR instructions
let analysis = adapter.analyze_function("_cgo_allocate", body);
```

#### Common Go Patterns Detected

| Pattern | Description | Example Functions |
|---------|-------------|-------------------|
| `GoGCAllocation` | Go GC allocation | `runtime.mallocgc`, `runtime.newobject` |
| `CGOAllocation` | CGO memory allocation | `_cgo_allocate`, `_Cfunc_GoMalloc` |
| `CGODesallocation` | CGO memory deallocation | `_cgo_free`, `_Cfunc_GoFree` |
| `RuntimeInternal` | Go runtime internal | `runtime.*` |
| `CGOBridge` | CGO bridge function | `_cgo_*`, `_Cfunc_*` |
| `GoroutineManagement` | Goroutine management | `runtime.newproc`, `runtime.goexit` |

### Python C API Adapter

The Python C API adapter provides semantic analysis for Python C extension code, focusing on Python-specific memory management patterns.

#### Features

- **Reference Counting Analysis**: Tracks Py_INCREF/Py_DECREF operations
- **Object Lifecycle Detection**: Identifies creation, borrowing, and stealing of references
- **GIL Management Analysis**: Analyzes Global Interpreter Lock usage
- **Python-Specific FFI Patterns**: Recognizes Python C API patterns

#### Usage Examples

```rust
use omniscope_semantics::resource::python_adapter::PythonAdapter;

// Create a Python adapter
let adapter = PythonAdapter::new();

// Analyze a Python C API function
let result = adapter.analyze_function("Py_INCREF");
println!("Function: {}", result.function_name);
println!("Pattern: {:?}", result.pattern);
println!("Is Safe: {}", result.is_safe);
println!("Confidence: {}", result.confidence);
println!("Reasoning: {}", result.reasoning);
```

#### Common Python Patterns Detected

| Pattern | Description | Example Functions |
|---------|-------------|-------------------|
| `NewReference` | Object creation with new reference | `PyBytes_FromString`, `PyLong_FromLong` |
| `BorrowedReference` | Borrowed reference | `PyList_GetItem`, `PyTuple_GetItem` |
| `StolenReference` | Stolen reference | `Py_BuildValue` with "N" format |
| `RefCountOp` | Reference counting operation | `Py_INCREF`, `Py_DECREF` |
| `GILAcquire` | GIL acquisition | `PyGILState_Ensure` |
| `GILRelease` | GIL release | `PyGILState_Release` |

## Multi-Language Semantic Extensions

OmniScope now supports 19 semantic variants across 7 programming languages:

### Python Semantic Kinds

- `PythonRefcountInc` - Py_INCREF reference count increment
- `PythonRefcountDec` - Py_DECREF reference count decrement
- `PythonBorrowedRef` - PyList_GetItem borrowed reference
- `PythonOwnedRef` - PyBytes_FromString owned reference
- `PythonGilProtected` - PyGILState_Ensure/Release GIL protection

### Go Semantic Kinds

- `GoDeferCleanup` - defer C.free(ptr) deferred cleanup
- `GoFinalizer` - runtime.SetFinalizer finalizer pattern
- `GoCgoWrapper` - _Cgo_* wrapper function
- `GoRuntimeAlloc` - runtime.mallocgc runtime allocation

### C++ Semantic Kinds

- `CppUniquePtr` - std::unique_ptr exclusive ownership
- `CppSharedPtr` - std::shared_ptr shared ownership
- `CppDestructor` - ~ClassName() destructor pattern
- `CppExceptionPath` - try/catch exception path

### C# Semantic Kinds

- `CsharpSafeHandle` - SafeHandle.ReleaseHandle safe handle
- `CsharpFinalizer` - ~Destructor() finalizer
- `CsharpPinvokeMarshal` - P/Invoke marshalling interop

### Java Semantic Kinds

- `JavaLocalRef` - JNI LocalRef local reference
- `JavaGlobalRef` - JNI GlobalRef global reference
- `JavaWeakRef` - JNI WeakGlobalRef weak global reference

### Using Semantic Kinds

```rust
use omniscope_semantics::resource::semantic_tree::SemanticKind;

// Check if a semantic kind suppresses certain issues
let kind = SemanticKind::CppUniquePtr;
if kind.suppresses_borrow_escape() {
    println!("This pattern suppresses borrow escape issues");
}

// Get safety score
let score = kind.safety_score();
println!("Safety score: {}", score);

// Check if cleanup is required
if kind.requires_cleanup() {
    println!("This pattern requires explicit cleanup");
}
```

## Advanced Features

### Custom Analysis Pipeline

```rust
use omniscope_pipeline::Pipeline;
use omniscope_ir::LoadStrategy;

// Create a pipeline with custom configuration
let pipeline = Pipeline::new()
    .with_load_strategy(LoadStrategy::Auto)
    .with_boundary_only(true);

// Analyze IR
let result = pipeline.analyze("input.bc")?;
println!("Found {} issues", result.issues().len());
```

### Semantic Engine Integration

```rust
use omniscope_semantics::SemanticEngine;

// Create semantic engine with adapters
let engine = SemanticEngine::new()
    .with_go_adapter()
    .with_python_adapter();

// Analyze function semantics
let semantics = engine.analyze_function("Py_INCREF", None);
println!("Detected pattern: {:?}", semantics.pattern);
```

## Troubleshooting

### Common Issues

1. **LLVM not found**
   ```bash
   # Set LLVM prefix
   export LLVM_SYS_221_PREFIX=/path/to/llvm
   ```

2. **C++ pass compilation fails**
   ```bash
   # Install build tools
   make install-tools
   ```

3. **Analysis takes too long**
   ```bash
   # Use boundary-only mode
   omniscope analyze -i input.bc --boundary-only
   ```

### Debug Mode

```bash
# Enable debug logging
RUST_LOG=debug omniscope analyze -i input.bc

# Enable specific module logging
RUST_LOG=omniscope_semantics=debug omniscope analyze -i input.bc
```

### Performance Tuning

- Use `--load-strategy llvm-sys` for fastest analysis
- Use `--boundary-only` for focused FFI analysis
- Use `--format json` for machine-readable output

## API Reference

For detailed API documentation, generate and view the Rust docs:

```bash
cargo doc --open
```

Or visit the generated documentation at `target/doc/omniscope_semantics/`.

## Examples

### Complete Analysis Example

```rust
use omniscope_semantics::resource::go_adapter::GoAdapter;
use omniscope_semantics::resource::python_adapter::PythonAdapter;

fn analyze_ffi_code() {
    // Analyze Go CGO code
    let go_adapter = GoAdapter::new();
    let go_analysis = go_adapter.analyze_function("_cgo_allocate", None);
    
    // Analyze Python C extension code
    let python_adapter = PythonAdapter::new();
    let python_analysis = python_adapter.analyze_function("Py_INCREF");
    
    // Compare safety assessments
    println!("Go safety: {:?}", go_analysis.ffi_safety);
    println!("Python safety: {:?}", python_analysis.is_safe);
}
```

### Custom Pattern Detection

```rust
use omniscope_semantics::resource::semantic_tree::SemanticKind;

fn detect_custom_patterns(function_name: &str) -> Option<SemanticKind> {
    // Use built-in pattern detection
    let kind = SemanticKind::from_function_name(function_name);
    
    // Add custom logic
    match kind {
        SemanticKind::Unknown => {
            // Custom pattern detection
            if function_name.starts_with("my_custom_") {
                Some(SemanticKind::LibraryRelease)
            } else {
                None
            }
        }
        other => Some(other),
    }
}
```

## Best Practices

1. **Start with boundary-only analysis** for quick FFI safety assessment
2. **Use appropriate loading strategy** based on your environment
3. **Review semantic kinds** to understand suppression rules
4. **Combine multiple adapters** for comprehensive analysis
5. **Use JSON output** for CI/CD integration

## Support

- **Documentation**: Check the `docs/` directory for detailed design docs
- **Issues**: Search existing issues before creating new ones
- **Discussions**: Use GitHub Discussions for questions
- **Chat**: Join our community chat (link in README)