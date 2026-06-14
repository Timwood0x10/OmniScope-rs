//! # Rust Adapter
//!
//! Detects Rust-specific FFI ownership patterns, runtime allocator operations,
//! and RAII cleanup semantics from LLVM IR. Produces `SemanticFact` instances
//! for the `LanguageAdapterFactPass`.
//!
//! ## Supported Patterns (Phase 1)
//! - `Box::into_raw` / `CString::into_raw`: ownership transfer to C
//! - `Box::from_raw` / `CString::from_raw`: ownership reclaim from C
//! - `__rust_alloc` / `__rust_dealloc`: runtime allocator fact
//! - drop glue / RAII cleanup fact
//! - panic/unwind boundary suppression fact
//!
//! ## Key Concepts
//! - Rust functions are identified by mangled names starting with `_ZN` or containing
//!   `core::ptr::drop_in_place`, `alloc::`, etc.
//! - Ownership transfer is inferred from `into_raw`/`from_raw` patterns
//! - Runtime allocator calls are identified by `__rust_alloc`/`__rust_dealloc` symbol names
//! - Drop glue functions are identified by symbol patterns

use omniscope_ir::{FunctionBody, IRInstructionKind};

use crate::resource::semantic_tree::{
    FactConfidence, FactSource, SemanticFact, SemanticKey, SemanticKind,
};
use crate::Confidence;

/// Rust-specific semantic patterns detectable from LLVM IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustSemanticPattern {
    /// Box::into_raw or CString::into_raw (ownership transfer to C).
    IntoRawOwnershipTransfer,
    /// Box::from_raw or CString::from_raw (ownership reclaim from C).
    FromRawOwnershipReclaim,
    /// __rust_alloc (Rust runtime allocation).
    RustRuntimeAlloc,
    /// __rust_dealloc (Rust runtime deallocation).
    RustRuntimeDealloc,
    /// Drop glue / RAII cleanup for a specific type.
    DropGlue,
    /// Panic/unwind boundary (function that may unwind across FFI).
    PanicUnwindBoundary,
    /// Rust global allocator wrapper (e.g., custom allocator).
    GlobalAllocatorWrapper,
    /// Unknown Rust pattern.
    Unknown,
}

/// Analysis result for a single Rust function.
#[derive(Debug, Clone)]
pub struct RustFunctionAnalysis {
    /// Function name.
    pub function_name: String,
    /// Detected semantic patterns.
    pub patterns: Vec<RustSemanticPattern>,
    /// Whether this function operates on raw pointers.
    pub has_raw_pointer_ops: bool,
    /// Whether this function transfers ownership to C.
    pub transfers_ownership_to_c: bool,
    /// Whether this function reclaims ownership from C.
    pub reclaims_ownership_from_c: bool,
    /// Whether this is a drop glue function.
    pub is_drop_glue: bool,
    /// Confidence in the analysis.
    pub confidence: Confidence,
}

/// Adapter for detecting Rust-specific FFI patterns in LLVM IR.
pub struct RustAdapter;

impl RustAdapter {
    /// Creates a new Rust adapter.
    pub fn new() -> Self {
        Self
    }

    /// Analyze a function by name and optional body.
    pub fn analyze_function(
        &self,
        func_name: &str,
        body: Option<&FunctionBody>,
    ) -> RustFunctionAnalysis {
        // Collect all detected patterns from both name and IR body analysis
        let mut patterns = Vec::new();

        // Step 1: Analyze function name to detect Rust patterns
        // This is the primary detection mechanism for known function names
        let name_patterns = self.analyze_function_name(func_name);
        patterns.extend(name_patterns);

        // Step 2: Analyze IR body for instruction-level evidence
        // This complements name-based analysis with actual call targets
        if let Some(body) = body {
            let body_patterns = self.analyze_function_body(body);
            patterns.extend(body_patterns);
        }

        // Step 3: Determine flags from collected patterns
        let has_raw_pointer_ops = patterns.iter().any(|p| {
            matches!(
                p,
                RustSemanticPattern::IntoRawOwnershipTransfer
                    | RustSemanticPattern::FromRawOwnershipReclaim
            )
        });

        let transfers_ownership_to_c = patterns
            .iter()
            .any(|p| matches!(p, RustSemanticPattern::IntoRawOwnershipTransfer));

        let reclaims_ownership_from_c = patterns
            .iter()
            .any(|p| matches!(p, RustSemanticPattern::FromRawOwnershipReclaim));

        let is_drop_glue = patterns
            .iter()
            .any(|p| matches!(p, RustSemanticPattern::DropGlue));

        // Step 4: Determine confidence based on evidence strength
        let confidence = if patterns.is_empty() {
            Confidence::Low
        } else if has_raw_pointer_ops || is_drop_glue {
            Confidence::High
        } else {
            Confidence::Medium
        };

        // Assemble final analysis result
        RustFunctionAnalysis {
            function_name: func_name.to_string(),
            patterns,
            has_raw_pointer_ops,
            transfers_ownership_to_c,
            reclaims_ownership_from_c,
            is_drop_glue,
            confidence,
        }
    }

    /// Analyze based on function name only (demangling + pattern matching).
    fn analyze_function_name(&self, name: &str) -> Vec<RustSemanticPattern> {
        let mut patterns = Vec::new();

        // Ownership transfer patterns: into_raw / from_raw
        // Box::into_raw, CString::into_raw transfer ownership to C
        if name.contains("into_raw") {
            patterns.push(RustSemanticPattern::IntoRawOwnershipTransfer);
        }
        // Box::from_raw, CString::from_raw reclaim ownership from C
        if name.contains("from_raw") {
            patterns.push(RustSemanticPattern::FromRawOwnershipReclaim);
        }

        // Runtime allocator patterns
        if name.contains("__rust_alloc") {
            patterns.push(RustSemanticPattern::RustRuntimeAlloc);
        }
        if name.contains("__rust_dealloc") {
            patterns.push(RustSemanticPattern::RustRuntimeDealloc);
        }

        // Drop glue pattern: core::ptr::drop_in_place<T>
        if name.contains("drop_in_place") {
            patterns.push(RustSemanticPattern::DropGlue);
        }

        // Panic/unwind boundary patterns
        if name.contains("panic") || name.contains("catch_unwind") {
            patterns.push(RustSemanticPattern::PanicUnwindBoundary);
        }

        // Global allocator wrapper patterns
        if name.contains("__rg_alloc") || name.contains("__rg_dealloc") {
            patterns.push(RustSemanticPattern::GlobalAllocatorWrapper);
        }

        patterns
    }

    /// Analyze based on IR body instructions.
    fn analyze_function_body(&self, body: &FunctionBody) -> Vec<RustSemanticPattern> {
        let mut patterns = Vec::new();

        // Scan all instructions for call patterns that indicate Rust runtime usage
        for instruction in &body.instructions {
            if let IRInstructionKind::Call = instruction.kind {
                // Extract called function name from instruction's callee field
                if let Some(ref callee) = instruction.callee {
                    // Rust runtime allocation
                    if callee == "__rust_alloc" {
                        patterns.push(RustSemanticPattern::RustRuntimeAlloc);
                    }
                    // Rust runtime deallocation
                    else if callee == "__rust_dealloc" {
                        patterns.push(RustSemanticPattern::RustRuntimeDealloc);
                    }
                }
            }
        }

        patterns
    }

    /// Convert analysis to SemanticFacts for the pass system.
    pub fn to_semantic_facts(&self, analysis: &RustFunctionAnalysis) -> Vec<SemanticFact> {
        let key = SemanticKey::Symbol(analysis.function_name.clone());
        let mut facts = Vec::new();

        for pattern in &analysis.patterns {
            match pattern {
                RustSemanticPattern::IntoRawOwnershipTransfer => {
                    // Ownership transfer via into_raw is by-design
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::IntoRawTransfer,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!(
                            "RustAdapter: into_raw ownership transfer in {}",
                            analysis.function_name
                        ),
                    ));
                }
                RustSemanticPattern::FromRawOwnershipReclaim => {
                    // Reclaiming ownership via from_raw restores Rust-managed memory
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::HeapProvenance,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!(
                            "RustAdapter: from_raw ownership reclaim in {}",
                            analysis.function_name
                        ),
                    ));
                }
                RustSemanticPattern::RustRuntimeAlloc => {
                    // __rust_alloc is the Rust runtime allocation function
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RuntimeInternal,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("RustAdapter: runtime alloc in {}", analysis.function_name),
                    ));
                }
                RustSemanticPattern::RustRuntimeDealloc => {
                    // __rust_dealloc is the Rust runtime deallocation function
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RaiiDropRelease,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("RustAdapter: runtime dealloc in {}", analysis.function_name),
                    ));
                }
                RustSemanticPattern::DropGlue => {
                    // Drop glue is compiler-inserted RAII cleanup
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RaiiDropRelease,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("RustAdapter: drop glue in {}", analysis.function_name),
                    ));
                }
                RustSemanticPattern::PanicUnwindBoundary => {
                    // Panic/unwind boundary — runtime internal suppression
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RuntimeInternal,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!(
                            "RustAdapter: panic/unwind boundary in {}",
                            analysis.function_name
                        ),
                    ));
                }
                RustSemanticPattern::GlobalAllocatorWrapper => {
                    // Global allocator wrapper — runtime internal
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RuntimeInternal,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!(
                            "RustAdapter: global allocator wrapper in {}",
                            analysis.function_name
                        ),
                    ));
                }
                RustSemanticPattern::Unknown => {
                    // Unknown pattern — no fact emitted
                }
            }
        }

        facts
    }

    /// Check if a function name looks like a Rust mangled symbol.
    #[cfg(test)]
    fn looks_like_rust(name: &str) -> bool {
        name.starts_with("_ZN")
            || name.starts_with("_R")
            || name.contains("::")
            || name.contains("core::ptr::drop_in_place")
            || name.contains("alloc::")
    }
}

impl Default for RustAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_ir::parser::{FunctionBody, IRInstruction, IRInstructionKind};

    /// Objective: Verify detection of into_raw ownership transfer pattern
    /// Invariants: Functions containing "into_raw" must be detected as
    ///             IntoRawOwnershipTransfer with has_raw_pointer_ops
    #[test]
    fn test_into_raw_detection() {
        let adapter = RustAdapter::new();
        let analysis = adapter.analyze_function("_ZN3std7boxed7Box8into_raw17h12345678E", None);

        assert!(
            analysis
                .patterns
                .contains(&RustSemanticPattern::IntoRawOwnershipTransfer),
            "into_raw function must be detected as IntoRawOwnershipTransfer, got {:?}",
            analysis.patterns
        );
        assert!(
            analysis.transfers_ownership_to_c,
            "into_raw function must set transfers_ownership_to_c"
        );
        assert!(
            analysis.has_raw_pointer_ops,
            "into_raw function must have has_raw_pointer_ops"
        );
        assert_eq!(
            analysis.confidence,
            Confidence::High,
            "into_raw detection must have High confidence"
        );
    }

    /// Objective: Verify detection of from_raw ownership reclaim pattern
    /// Invariants: Functions containing "from_raw" must be detected as
    ///             FromRawOwnershipReclaim with has_raw_pointer_ops
    #[test]
    fn test_from_raw_detection() {
        let adapter = RustAdapter::new();
        let analysis = adapter.analyze_function("_ZN3std7boxed7Box8from_raw17h87654321E", None);

        assert!(
            analysis
                .patterns
                .contains(&RustSemanticPattern::FromRawOwnershipReclaim),
            "from_raw function must be detected as FromRawOwnershipReclaim, got {:?}",
            analysis.patterns
        );
        assert!(
            analysis.reclaims_ownership_from_c,
            "from_raw function must set reclaims_ownership_from_c"
        );
        assert!(
            analysis.has_raw_pointer_ops,
            "from_raw function must have has_raw_pointer_ops"
        );
        assert_eq!(
            analysis.confidence,
            Confidence::High,
            "from_raw detection must have High confidence"
        );
    }

    /// Objective: Verify detection of __rust_alloc runtime allocation
    /// Invariants: Functions named __rust_alloc must be detected as RustRuntimeAlloc
    #[test]
    fn test_rust_runtime_alloc_detection() {
        let adapter = RustAdapter::new();
        let analysis = adapter.analyze_function("__rust_alloc", None);

        assert!(
            analysis
                .patterns
                .contains(&RustSemanticPattern::RustRuntimeAlloc),
            "__rust_alloc must be detected as RustRuntimeAlloc, got {:?}",
            analysis.patterns
        );
        assert!(
            !analysis.has_raw_pointer_ops,
            "__rust_alloc must not have raw pointer ops"
        );
    }

    /// Objective: Verify detection of drop_in_place drop glue function
    /// Invariants: Functions containing "drop_in_place" must be detected as DropGlue
    #[test]
    fn test_drop_glue_detection() {
        let adapter = RustAdapter::new();
        let analysis = adapter.analyze_function("_ZN4core3ptr13drop_in_place17h12345678E", None);

        assert!(
            analysis.patterns.contains(&RustSemanticPattern::DropGlue),
            "drop_in_place function must be detected as DropGlue, got {:?}",
            analysis.patterns
        );
        assert!(
            analysis.is_drop_glue,
            "drop_in_place function must set is_drop_glue"
        );
        assert_eq!(
            analysis.confidence,
            Confidence::High,
            "drop glue detection must have High confidence"
        );
    }

    /// Objective: Verify that non-Rust functions are not flagged with Rust patterns
    /// Invariants: A plain C function must have empty patterns and Low confidence
    #[test]
    fn test_not_rust_function() {
        let adapter = RustAdapter::new();
        let analysis = adapter.analyze_function("malloc", None);

        assert!(
            analysis.patterns.is_empty(),
            "Non-Rust function must have no patterns, got {:?}",
            analysis.patterns
        );
        assert!(
            !analysis.has_raw_pointer_ops,
            "Non-Rust function must not have raw pointer ops"
        );
        assert!(
            !analysis.transfers_ownership_to_c,
            "Non-Rust function must not transfer ownership"
        );
        assert!(
            !analysis.reclaims_ownership_from_c,
            "Non-Rust function must not reclaim ownership"
        );
        assert!(
            !analysis.is_drop_glue,
            "Non-Rust function must not be drop glue"
        );
        assert_eq!(
            analysis.confidence,
            Confidence::Low,
            "Non-Rust function must have Low confidence"
        );
    }

    /// Objective: Verify SemanticFact generation for ownership transfer
    /// Invariants: IntoRawOwnershipTransfer pattern must produce
    ///             SemanticFact with kind IntoRawTransfer and High confidence
    #[test]
    fn test_to_semantic_facts_ownership_transfer() {
        let adapter = RustAdapter::new();
        let analysis = adapter.analyze_function("Box::into_raw", None);
        let facts = adapter.to_semantic_facts(&analysis);

        let has_into_raw_fact = facts.iter().any(|f| {
            f.kind == SemanticKind::IntoRawTransfer
                && f.confidence == FactConfidence::High
                && f.source == FactSource::LanguageAdapter
                && matches!(&f.key, SemanticKey::Symbol(name) if name == "Box::into_raw")
        });

        assert!(
            has_into_raw_fact,
            "IntoRawOwnershipTransfer must produce IntoRawTransfer fact with High confidence"
        );
    }

    /// Objective: Verify RustFunctionAnalysis fields are correctly populated
    /// Invariants: All analysis fields must correctly reflect the detected patterns
    #[test]
    fn test_rust_function_analysis_fields() {
        let adapter = RustAdapter::new();

        // Test with a function that has both into_raw and panic patterns
        let analysis = adapter.analyze_function("some_rust_fn_with_into_raw_and_panic", None);

        // Should detect both patterns
        assert!(
            analysis
                .patterns
                .contains(&RustSemanticPattern::IntoRawOwnershipTransfer),
            "Must detect into_raw pattern"
        );
        assert!(
            analysis
                .patterns
                .contains(&RustSemanticPattern::PanicUnwindBoundary),
            "Must detect panic pattern"
        );

        // Field consistency
        assert_eq!(
            analysis.function_name,
            "some_rust_fn_with_into_raw_and_panic"
        );
        assert!(analysis.transfers_ownership_to_c);
        assert!(!analysis.reclaims_ownership_from_c);
        assert!(!analysis.is_drop_glue);
        assert!(analysis.has_raw_pointer_ops);
        assert_eq!(analysis.confidence, Confidence::High);

        // Verify SemanticFact conversion
        let facts = adapter.to_semantic_facts(&analysis);
        assert!(!facts.is_empty(), "Must produce at least one fact");

        let into_raw_facts: Vec<_> = facts
            .iter()
            .filter(|f| f.kind == SemanticKind::IntoRawTransfer)
            .collect();
        assert_eq!(
            into_raw_facts.len(),
            1,
            "Must produce exactly one IntoRawTransfer fact"
        );
    }

    /// Objective: Verify detection of CString::into_raw pattern
    /// Invariants: CString::into_raw must be detected as IntoRawOwnershipTransfer
    #[test]
    fn test_cstring_into_raw_detection() {
        let adapter = RustAdapter::new();
        let analysis = adapter.analyze_function("CString::into_raw", None);

        assert!(
            analysis
                .patterns
                .contains(&RustSemanticPattern::IntoRawOwnershipTransfer),
            "CString::into_raw must be detected as IntoRawOwnershipTransfer"
        );
        assert!(analysis.transfers_ownership_to_c);
    }

    /// Objective: Verify detection of __rust_dealloc runtime deallocation
    /// Invariants: __rust_dealloc must be detected as RustRuntimeDealloc
    #[test]
    fn test_rust_runtime_dealloc_detection() {
        let adapter = RustAdapter::new();
        let analysis = adapter.analyze_function("__rust_dealloc", None);

        assert!(
            analysis
                .patterns
                .contains(&RustSemanticPattern::RustRuntimeDealloc),
            "__rust_dealloc must be detected as RustRuntimeDealloc, got {:?}",
            analysis.patterns
        );
    }

    /// Objective: Verify SemanticFact generation for drop glue
    /// Invariants: DropGlue pattern must produce RaiiDropRelease fact with High confidence
    #[test]
    fn test_to_semantic_facts_drop_glue() {
        let adapter = RustAdapter::new();
        let analysis = adapter.analyze_function("_ZN4core3ptr13drop_in_place17h12345678E", None);
        let facts = adapter.to_semantic_facts(&analysis);

        let has_drop_glue_fact = facts.iter().any(|f| {
            f.kind == SemanticKind::RaiiDropRelease
                && f.confidence == FactConfidence::High
                && f.source == FactSource::LanguageAdapter
        });

        assert!(
            has_drop_glue_fact,
            "DropGlue must produce RaiiDropRelease fact with High confidence"
        );
    }

    /// Objective: Verify IR body analysis detects __rust_alloc calls
    /// Invariants: Function bodies calling __rust_alloc must detect RustRuntimeAlloc
    #[test]
    fn test_body_detects_rust_alloc() {
        let adapter = RustAdapter::new();

        let body = FunctionBody {
            name: "test_rust_fn".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%ptr".to_string()),
                    operands: vec!["i64 42".to_string(), "i64 4".to_string()],
                    callee: Some("__rust_alloc".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%ptr = call i8* @__rust_alloc(i64 42, i64 4)".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Ret,
                    dest: None,
                    operands: vec![],
                    callee: None,
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "ret i8* %ptr".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
            ],
        };

        let analysis = adapter.analyze_function("test_rust_fn", Some(&body));

        assert!(
            analysis
                .patterns
                .contains(&RustSemanticPattern::RustRuntimeAlloc),
            "Function body calling __rust_alloc must detect RustRuntimeAlloc"
        );
    }

    /// Objective: Verify IR body analysis detects __rust_dealloc calls
    /// Invariants: Function bodies calling __rust_dealloc must detect RustRuntimeDealloc
    #[test]
    fn test_body_detects_rust_dealloc() {
        let adapter = RustAdapter::new();

        let body = FunctionBody {
            name: "test_rust_free_fn".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: None,
                    operands: vec!["i8*".to_string(), "%ptr".to_string()],
                    callee: Some("__rust_dealloc".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "call void @__rust_dealloc(i8* %ptr)".to_string(),
                    result_type: Some("void".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Ret,
                    dest: None,
                    operands: vec![],
                    callee: None,
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "ret void".to_string(),
                    result_type: Some("void".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
            ],
        };

        let analysis = adapter.analyze_function("test_rust_free_fn", Some(&body));

        assert!(
            analysis
                .patterns
                .contains(&RustSemanticPattern::RustRuntimeDealloc),
            "Function body calling __rust_dealloc must detect RustRuntimeDealloc"
        );
    }

    /// Objective: Verify looks_like_rust correctly identifies Rust mangled names
    /// Invariants: _ZN-prefixed and ::-containing names must be identified as Rust
    #[test]
    fn test_looks_like_rust_mangling() {
        assert!(
            RustAdapter::looks_like_rust("_ZN3std7boxed7Box8into_raw17h12345678E"),
            "_ZN prefix must be identified as Rust"
        );
        assert!(
            RustAdapter::looks_like_rust("std::boxed::Box::into_raw"),
            ":: separator must be identified as Rust"
        );
        assert!(
            RustAdapter::looks_like_rust("core::ptr::drop_in_place"),
            "core::ptr::drop_in_place must be identified as Rust"
        );
        assert!(
            !RustAdapter::looks_like_rust("malloc"),
            "malloc must not be identified as Rust"
        );
        assert!(
            !RustAdapter::looks_like_rust("free"),
            "free must not be identified as Rust"
        );
    }
}
