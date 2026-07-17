# OmniScope-rs — Archived

> This project is archived and no longer under development.
> Future work has moved to [codescope](https://github.com/TimWood/codescope) (C++).

## Why Archived

OmniScope-rs attempted to do cross-language FFI security analysis at the LLVM IR level. The fundamental problem:

1. **IR loses source context** — distinguishing user code from library code requires guessing namespaces and paths, which is never precise enough
2. **Two analysis stacks** — C++ (codescope) and Rust (OmniScope) analyzed the same thing independently, requiring pointless cross-validation
3. **Inherently imprecise** — source location, type information, and include relationships are all known at compile time (clang level); the IR layer can only guess

## Where We Went Wrong

We spent too much effort on IR-level analysis when the source code already has all the answers. The LLVM IR is a lossy intermediate representation — by the time we're analyzing it, we've already thrown away the information we need (which headers a function came from, whether it's a system include or user include, the exact type layout, etc.).

## New Direction

**codescope** (C++ tree-sitter source analyzer) is the right place for this work:
- All information is available at the source level (include sources, function classification, type layout)
- tree-sitter already covers multiple languages (C, C++, Rust, Go, Java, Python, JS/TS, Swift)
- One analysis engine, not two

The new plan is at `aim/plan/omniscope_1.0_ffi_engine.md`.

## Archive Contents

```
crates/
├── omniscope-pass/           ← IR analysis pass (no longer maintained)
├── omniscope-semantics/      ← semantic analysis (no longer maintained)
├── omniscope-core/           ← core types (no longer maintained)
├── omniscope-ir/             ← IR parsing (no longer maintained)
├── omniscope-types/          ← type definitions (no longer maintained)
├── omniscope-cli/            ← CLI entry (no longer maintained)
└── omniscope-ffi/            ← export library (no longer maintained)

tools/
└── ir_extractor/             ← C++ LLVM pass (no longer maintained)
```

## License

Same as the original project.