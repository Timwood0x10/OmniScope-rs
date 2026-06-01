//! Buffer Overflow Detector — Detects potential buffer overflow issues.
//!
//! This module analyzes IR instructions to identify potential buffer overflow
//! issues including:
//!
//! 1. **Buffer Size Mismatch**: Detects when buffer size doesn't match usage
//! 2. **Out-of-bounds Write**: Detects writes beyond buffer boundaries
//! 3. **Out-of-bounds Read**: Detects reads beyond buffer boundaries
//! 4. **Null Pointer Dereference**: Detects potential null pointer dereferences
//! 5. **Integer Overflow in Size Calculation**: Detects integer overflow in size calculations
//!
//! # Detection Strategy
//!
//! The detector analyzes memory operations (load, store, getelementptr) and
//! identifies patterns that may lead to buffer overflow:
//! - GEP instructions with constant indices that exceed buffer size
//! - Memory accesses through pointers derived from unsafe operations
//! - Size calculations that may overflow
//! - Missing bounds checks before memory accesses
//!
//! # Examples
//!
//! ```rust
//! use omniscope_semantics::resource::buffer_overflow_detector::BufferOverflowDetector;
//!
//! let ir = r#"
//!   define void @test_overflow() {
//!     %buf = alloca [10 x i8]
//!     %ptr = getelementptr [10 x i8], [10 x i8]* %buf, i32 0, i32 20
//!     store i8 65, i8* %ptr
//!     ret void
//!   }
//! "#;
//!
//! let detector = BufferOverflowDetector::new();
//! let issues = detector.detect_issues(ir);
//! assert!(!issues.is_empty(), "Should detect buffer overflow");
//! ```

use omniscope_ir::{FunctionBody, IRInstruction, IRInstructionKind};

// ============================================================================
// Data Types
// ============================================================================

/// Represents a buffer overflow issue detected in the IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BufferOverflowKind {
    /// Buffer size mismatch between allocation and usage
    BufferSizeMismatch {
        /// Buffer name or identifier
        buffer_name: String,
        /// Allocated size in bytes
        allocated_size: usize,
        /// Accessed size in bytes
        accessed_size: usize,
        /// Access offset
        access_offset: usize,
    },
    /// Out-of-bounds write detected
    OutOfBoundsWrite {
        /// Buffer name or identifier
        buffer_name: String,
        /// Buffer size in bytes
        buffer_size: usize,
        /// Write offset
        write_offset: usize,
        /// Write size in bytes
        write_size: usize,
    },
    /// Out-of-bounds read detected
    OutOfBoundsRead {
        /// Buffer name or identifier
        buffer_name: String,
        /// Buffer size in bytes
        buffer_size: usize,
        /// Read offset
        read_offset: usize,
        /// Read size in bytes
        read_size: usize,
    },
    /// Potential null pointer dereference
    NullPointerDeref {
        /// Pointer register
        pointer_register: String,
        /// Operation type (load/store)
        operation: String,
    },
    /// Integer overflow in size calculation
    IntegerOverflow {
        /// Calculation expression
        expression: String,
        /// Operation type
        operation: String,
    },
    /// Missing bounds check before memory access
    MissingBoundsCheck {
        /// Buffer name or identifier
        buffer_name: String,
        /// Access type (read/write)
        access_type: String,
        /// Access offset
        access_offset: usize,
    },
}

/// Confidence level for buffer overflow detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OverflowConfidence {
    /// Low confidence: potential issue but may be safe
    Low,
    /// Medium confidence: suspicious pattern with some uncertainty
    Medium,
    /// High confidence: explicit overflow pattern detected
    High,
}

/// A buffer overflow pattern detected in IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferOverflowPattern {
    /// Kind of buffer overflow
    pub kind: BufferOverflowKind,
    /// The instruction causing the issue
    pub instruction: String,
    /// Confidence level
    pub confidence: OverflowConfidence,
    /// Whether this occurs near an FFI call
    pub near_ffi_call: bool,
    /// The FFI function name (if near FFI call)
    pub ffi_function: Option<String>,
    /// Line number in IR (if available)
    pub line_number: Option<usize>,
}

/// Result of buffer overflow analysis.
#[derive(Debug, Clone)]
pub struct BufferOverflowAnalysis {
    /// Function name
    pub function_name: String,
    /// Detected buffer overflow patterns
    pub patterns: Vec<BufferOverflowPattern>,
    /// Whether any FFI calls are present
    pub has_ffi_calls: bool,
    /// Number of memory instructions analyzed
    pub memory_instruction_count: usize,
}

/// Main detector for buffer overflow issues.
///
/// This analyzer parses IR memory instructions and identifies
/// potential buffer overflow issues.
pub struct BufferOverflowDetector {
    /// Minimum confidence level to report
    min_confidence: OverflowConfidence,
    /// Whether to check for buffer size mismatches
    check_size_mismatch: bool,
    /// Whether to check for out-of-bounds access
    check_out_of_bounds: bool,
    /// Whether to check for null pointer dereference
    check_null_deref: bool,
    /// Whether to check for integer overflow in size calculations
    check_integer_overflow: bool,
    /// Whether to check for missing bounds checks
    check_missing_bounds: bool,
}

impl BufferOverflowDetector {
    /// Creates a new buffer overflow detector with default settings.
    pub fn new() -> Self {
        Self {
            min_confidence: OverflowConfidence::Low,
            check_size_mismatch: true,
            check_out_of_bounds: true,
            check_null_deref: true,
            check_integer_overflow: true,
            check_missing_bounds: true,
        }
    }

    /// Creates a detector with custom settings.
    pub fn with_settings(
        min_confidence: OverflowConfidence,
        check_size_mismatch: bool,
        check_out_of_bounds: bool,
        check_null_deref: bool,
        check_integer_overflow: bool,
        check_missing_bounds: bool,
    ) -> Self {
        Self {
            min_confidence,
            check_size_mismatch,
            check_out_of_bounds,
            check_null_deref,
            check_integer_overflow,
            check_missing_bounds,
        }
    }

    /// Detects buffer overflow issues in the given IR.
    ///
    /// This is the main entry point for analysis. It parses memory
    /// instructions and checks for various buffer overflow issues.
    pub fn detect_issues(&self, ir: &str) -> Vec<BufferOverflowPattern> {
        use omniscope_ir::IRModule;

        let module = IRModule::parse_from_text(ir);
        let mut all_patterns = Vec::new();

        // Analyze each function body
        for body in module.function_bodies.values() {
            let analysis = self.analyze_function(body);
            all_patterns.extend(analysis.patterns);
        }

        // Filter by minimum confidence
        all_patterns.retain(|p| p.confidence >= self.min_confidence);

        all_patterns
    }

    /// Analyzes a function body for buffer overflow issues.
    pub fn analyze_function(&self, body: &FunctionBody) -> BufferOverflowAnalysis {
        let memory_insts: Vec<&IRInstruction> = body
            .instructions
            .iter()
            .filter(|i| {
                matches!(
                    i.kind,
                    IRInstructionKind::Load
                        | IRInstructionKind::Store
                        | IRInstructionKind::GetElementPtr
                )
            })
            .collect();

        let memory_instruction_count = memory_insts.len();
        let mut patterns = Vec::new();

        // Collect FFI call information
        let ffi_calls = collect_ffi_calls(body);
        let has_ffi_calls = !ffi_calls.is_empty();

        // Analyze each memory instruction
        for inst in &memory_insts {
            if let Some(pattern) = self.analyze_memory_instruction(inst, &ffi_calls, body) {
                patterns.push(pattern);
            }
        }

        // Also analyze alloca instructions for size information
        let alloca_insts: Vec<&IRInstruction> = body
            .instructions
            .iter()
            .filter(|i| i.kind == IRInstructionKind::Alloca)
            .collect();

        for inst in &alloca_insts {
            if let Some(pattern) = self.analyze_alloca_instruction(inst, &ffi_calls, body) {
                patterns.push(pattern);
            }
        }

        BufferOverflowAnalysis {
            function_name: body.name.clone(),
            patterns,
            has_ffi_calls,
            memory_instruction_count,
        }
    }

    /// Analyzes a memory instruction for buffer overflow issues.
    fn analyze_memory_instruction(
        &self,
        inst: &IRInstruction,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<BufferOverflowPattern> {
        let raw = &inst.raw_text;

        match inst.kind {
            IRInstructionKind::GetElementPtr => {
                if self.check_out_of_bounds {
                    self.check_gep_overflow(raw, ffi_calls, body)
                } else {
                    None
                }
            }
            IRInstructionKind::Load => {
                if self.check_null_deref {
                    self.check_load_null_deref(raw, ffi_calls, body)
                } else {
                    None
                }
            }
            IRInstructionKind::Store => {
                if self.check_null_deref {
                    self.check_store_null_deref(raw, ffi_calls, body)
                } else {
                    None
                }
            }
            _ => {
                // Check for buffer size mismatch if enabled
                if self.check_size_mismatch {
                    self.check_buffer_size_mismatch(raw, ffi_calls, body)
                } else if self.check_missing_bounds {
                    self.check_missing_bounds_check(raw, ffi_calls, body)
                } else {
                    None
                }
            }
        }
    }

    /// Analyzes an alloca instruction for buffer size information.
    fn analyze_alloca_instruction(
        &self,
        inst: &IRInstruction,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<BufferOverflowPattern> {
        let raw = &inst.raw_text;

        if self.check_integer_overflow {
            self.check_alloca_integer_overflow(raw, ffi_calls, body)
        } else {
            None
        }
    }

    /// Checks for GEP instruction overflow.
    fn check_gep_overflow(
        &self,
        raw: &str,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<BufferOverflowPattern> {
        // Pattern: getelementptr [N x T], [N x T]* %buf, i32 0, i32 M
        // If M > N, then overflow
        if !raw.contains("getelementptr") {
            return None;
        }

        // Parse array type and index
        let (array_size, index) = parse_gep_array_access(raw)?;

        // Check if index exceeds array size
        if index >= array_size {
            let (near_ffi_call, ffi_function) = check_ffi_proximity(raw, ffi_calls, body);

            let confidence = if near_ffi_call {
                OverflowConfidence::High
            } else if !ffi_calls.is_empty() {
                OverflowConfidence::Medium
            } else {
                OverflowConfidence::High // Direct overflow is always high confidence
            };

            Some(BufferOverflowPattern {
                kind: BufferOverflowKind::OutOfBoundsWrite {
                    buffer_name: extract_buffer_name(raw),
                    buffer_size: array_size,
                    write_offset: index,
                    write_size: 1, // Default size, could be parsed more precisely
                },
                instruction: raw.to_string(),
                confidence,
                near_ffi_call,
                ffi_function,
                line_number: None,
            })
        } else {
            None
        }
    }

    /// Checks for null pointer dereference in load instruction.
    fn check_load_null_deref(
        &self,
        raw: &str,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<BufferOverflowPattern> {
        // Look for load from null pointer or undefined register
        // Check both raw text and operands for null/undef
        let has_null = raw.contains("null") || raw.contains("undef");
        let has_null_in_operands = raw.contains(" null") || raw.contains(" undef");
        if raw.contains("load") && (has_null || has_null_in_operands) {
            let (near_ffi_call, ffi_function) = check_ffi_proximity(raw, ffi_calls, body);

            Some(BufferOverflowPattern {
                kind: BufferOverflowKind::NullPointerDeref {
                    pointer_register: extract_pointer_register(raw),
                    operation: "load".to_string(),
                },
                instruction: raw.to_string(),
                confidence: OverflowConfidence::High,
                near_ffi_call,
                ffi_function,
                line_number: None,
            })
        } else {
            None
        }
    }

    /// Checks for null pointer dereference in store instruction.
    fn check_store_null_deref(
        &self,
        raw: &str,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<BufferOverflowPattern> {
        // Look for store to null pointer or undefined register
        // Check both raw text and operands for null/undef
        let has_null = raw.contains("null") || raw.contains("undef");
        let has_null_in_operands = raw.contains(" null") || raw.contains(" undef");
        if raw.contains("store") && (has_null || has_null_in_operands) {
            let (near_ffi_call, ffi_function) = check_ffi_proximity(raw, ffi_calls, body);

            Some(BufferOverflowPattern {
                kind: BufferOverflowKind::NullPointerDeref {
                    pointer_register: extract_pointer_register(raw),
                    operation: "store".to_string(),
                },
                instruction: raw.to_string(),
                confidence: OverflowConfidence::High,
                near_ffi_call,
                ffi_function,
                line_number: None,
            })
        } else {
            None
        }
    }

    /// Checks for buffer size mismatch between allocation and usage.
    fn check_buffer_size_mismatch(
        &self,
        _raw: &str,
        _ffi_calls: &[(String, usize)],
        _body: &FunctionBody,
    ) -> Option<BufferOverflowPattern> {
        // This is a placeholder for buffer size mismatch detection
        // In a real implementation, we would track buffer allocations and compare
        // with usage patterns to detect mismatches
        None
    }

    /// Checks for missing bounds checks before memory access.
    fn check_missing_bounds_check(
        &self,
        _raw: &str,
        _ffi_calls: &[(String, usize)],
        _body: &FunctionBody,
    ) -> Option<BufferOverflowPattern> {
        // This is a placeholder for missing bounds check detection
        // In a real implementation, we would analyze control flow to detect
        // missing bounds checks before memory accesses
        None
    }

    /// Checks for integer overflow in alloca instruction.
    fn check_alloca_integer_overflow(
        &self,
        raw: &str,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<BufferOverflowPattern> {
        // Look for alloca with multiplication that could overflow
        if raw.contains("alloca") {
            // Check for patterns like: alloca i8, i64 %size * %count
            if let Some(calculation) = extract_size_calculation(raw) {
                if calculation.contains("*") {
                    let (near_ffi_call, ffi_function) = check_ffi_proximity(raw, ffi_calls, body);

                    return Some(BufferOverflowPattern {
                        kind: BufferOverflowKind::IntegerOverflow {
                            expression: calculation,
                            operation: "multiplication".to_string(),
                        },
                        instruction: raw.to_string(),
                        confidence: OverflowConfidence::Medium,
                        near_ffi_call,
                        ffi_function,
                        line_number: None,
                    });
                }
            }

            // Check if alloca uses a register that was computed with multiplication
            if let Some(register) = extract_size_register(raw) {
                // Look for mul instruction that defines this register
                for inst in &body.instructions {
                    if inst.kind == IRInstructionKind::BinaryOp
                        && inst.raw_text.contains("mul")
                        && inst.dest.as_deref() == Some(&register)
                    {
                        let (near_ffi_call, ffi_function) =
                            check_ffi_proximity(raw, ffi_calls, body);

                        return Some(BufferOverflowPattern {
                            kind: BufferOverflowKind::IntegerOverflow {
                                expression: inst.raw_text.clone(),
                                operation: "multiplication".to_string(),
                            },
                            instruction: raw.to_string(),
                            confidence: OverflowConfidence::Medium,
                            near_ffi_call,
                            ffi_function,
                            line_number: None,
                        });
                    }
                }
            }
        }

        None
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Collect FFI calls from function body.
fn collect_ffi_calls(body: &FunctionBody) -> Vec<(String, usize)> {
    let mut ffi_calls = Vec::new();

    for (idx, inst) in body.instructions.iter().enumerate() {
        if inst.kind == IRInstructionKind::Call || inst.kind == IRInstructionKind::IndirectCall {
            if let Some(ref callee) = inst.callee {
                if is_external_function(callee) {
                    ffi_calls.push((callee.clone(), idx));
                }
            }
        }
    }

    ffi_calls
}

/// Check if a function name indicates an external (FFI) function.
fn is_external_function(name: &str) -> bool {
    // C library functions
    let c_functions = [
        "malloc", "free", "calloc", "realloc", "memcpy", "memmove", "memset", "printf", "sprintf",
        "snprintf", "scanf", "fopen", "fclose", "fread", "fwrite",
    ];

    if c_functions.contains(&name) {
        return true;
    }

    // Functions without Rust mangling (no underscore prefix)
    if !name.starts_with('_') && !name.contains("::") {
        return true;
    }

    false
}

/// Check if an instruction is near an FFI call.
fn check_ffi_proximity(
    _raw: &str,
    ffi_calls: &[(String, usize)],
    _body: &FunctionBody,
) -> (bool, Option<String>) {
    // Simple implementation: if there are any FFI calls, consider it near FFI
    if let Some((name, _)) = ffi_calls.first() {
        (true, Some(name.clone()))
    } else {
        (false, None)
    }
}

/// Parse GEP instruction to extract array size and index.
fn parse_gep_array_access(raw: &str) -> Option<(usize, usize)> {
    // Pattern: getelementptr [N x T], [N x T]* %buf, i32 0, i32 M
    // or: getelementptr inbounds [N x T], [N x T]* %buf, i32 0, i32 M

    // Find array type pattern
    let array_pattern = if raw.contains("inbounds") {
        "getelementptr inbounds "
    } else {
        "getelementptr "
    };

    let start = raw.find(array_pattern)?;
    let rest = &raw[start + array_pattern.len()..];

    // Extract array size: [N x T]
    let array_start = rest.find('[')?;
    let array_end = rest.find(']')?;
    let array_type = &rest[array_start + 1..array_end];

    // Parse N from [N x T]
    let parts: Vec<&str> = array_type.split(" x ").collect();
    if parts.len() < 2 {
        return None;
    }

    let array_size: usize = parts[0].trim().parse().ok()?;

    // Extract index: i32 M
    let index_pattern = ", i32 ";
    let index_pos = rest.rfind(index_pattern)?;
    let index_str = &rest[index_pos + index_pattern.len()..];

    // Parse M (could be followed by other text)
    let index: usize = index_str.split_whitespace().next()?.parse().ok()?;

    Some((array_size, index))
}

/// Extract buffer name from instruction.
fn extract_buffer_name(raw: &str) -> String {
    // Try to extract %name from instruction
    if let Some(start) = raw.find('%') {
        let end = raw[start..]
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(raw.len() - start);
        if end > 1 {
            return raw[start + 1..start + end].to_string();
        }
    }
    "unknown".to_string()
}

/// Extract pointer register from instruction.
fn extract_pointer_register(raw: &str) -> String {
    // Try to extract %name from load/store instruction
    if let Some(start) = raw.find('%') {
        let end = raw[start..]
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(raw.len() - start);
        return raw[start..start + end].to_string();
    }
    "unknown".to_string()
}

/// Extract size register from alloca instruction.
fn extract_size_register(raw: &str) -> Option<String> {
    // Look for pattern: alloca i8, i64 %register
    let alloca_pattern = "alloca i8, i64 ";
    let start = raw.find(alloca_pattern)?;
    let expr_start = start + alloca_pattern.len();

    // Find end of expression (could be end of line or comma)
    let expr_end = raw[expr_start..]
        .find([',', '\n'].as_slice())
        .unwrap_or(raw.len() - expr_start);

    let expr = raw[expr_start..expr_start + expr_end].trim();

    // Check if it's a register (starts with %)
    if expr.starts_with('%') {
        Some(expr.to_string())
    } else {
        None
    }
}

/// Extract size calculation from alloca instruction.
fn extract_size_calculation(raw: &str) -> Option<String> {
    // Look for pattern: alloca i8, i64 <expression>
    let alloca_pattern = "alloca i8, i64 ";
    let start = raw.find(alloca_pattern)?;
    let expr_start = start + alloca_pattern.len();

    // Find end of expression (could be end of line or comma)
    let expr_end = raw[expr_start..]
        .find([',', '\n'].as_slice())
        .unwrap_or(raw.len() - expr_start);

    Some(raw[expr_start..expr_start + expr_end].to_string())
}

// ============================================================================
// Default Implementation
// ============================================================================

impl Default for BufferOverflowDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify basic buffer overflow detection
    /// Invariants: Out-of-bounds access must be detected
    #[test]
    fn test_buffer_overflow_detection() {
        let ir = r#"
            define void @test_overflow() {
              %buf = alloca [10 x i8]
              %ptr = getelementptr [10 x i8], [10 x i8]* %buf, i32 0, i32 20
              store i8 65, i8* %ptr
              ret void
            }
        "#;

        let detector = BufferOverflowDetector::new();
        let issues = detector.detect_issues(ir);

        // Should detect out-of-bounds access
        assert!(
            issues
                .iter()
                .any(|issue| matches!(issue.kind, BufferOverflowKind::OutOfBoundsWrite { .. })),
            "Should detect out-of-bounds write at index 20 in buffer of size 10"
        );
    }

    /// Objective: Verify safe buffer access is not flagged
    /// Invariants: Valid access should not trigger false positives
    #[test]
    fn test_safe_buffer_access() {
        let ir = r#"
            define void @test_safe() {
              %buf = alloca [10 x i8]
              %ptr = getelementptr [10 x i8], [10 x i8]* %buf, i32 0, i32 5
              store i8 65, i8* %ptr
              ret void
            }
        "#;

        let detector = BufferOverflowDetector::new();
        let issues = detector.detect_issues(ir);

        // Should not detect any issues for safe access
        assert!(
            issues.is_empty(),
            "Safe buffer access should not trigger buffer overflow detection"
        );
    }

    /// Objective: Verify null pointer dereference detection
    /// Invariants: Access to null pointer must be detected
    #[test]
    fn test_null_pointer_dereference() {
        let ir = r#"
            define void @test_null() {
              %val = load i32, i32* null
              ret void
            }
        "#;

        let detector = BufferOverflowDetector::new();
        let issues = detector.detect_issues(ir);

        // Should detect null pointer dereference
        assert!(
            issues
                .iter()
                .any(|issue| matches!(issue.kind, BufferOverflowKind::NullPointerDeref { .. })),
            "Should detect null pointer dereference in load instruction"
        );
    }

    /// Objective: Verify multiple issues in single function
    /// Invariants: Multiple issues should be detected independently
    #[test]
    fn test_multiple_issues() {
        let ir = r#"
            define void @test_multiple() {
              %buf = alloca [10 x i8]
              %ptr1 = getelementptr [10 x i8], [10 x i8]* %buf, i32 0, i32 20
              store i8 65, i8* %ptr1
              %ptr2 = getelementptr [10 x i8], [10 x i8]* %buf, i32 0, i32 30
              store i8 66, i8* %ptr2
              ret void
            }
        "#;

        let detector = BufferOverflowDetector::new();
        let issues = detector.detect_issues(ir);

        // Should detect both overflow issues
        assert!(
            issues.len() >= 2,
            "Should detect at least two buffer overflow issues"
        );
    }

    /// Objective: Verify FFI proximity detection
    /// Invariants: Issues near FFI calls should have higher confidence
    #[test]
    fn test_ffi_proximity() {
        let ir = r#"
            declare void @external_func(i8*)
            
            define void @test_ffi() {
              %buf = alloca [10 x i8]
              %ptr = getelementptr [10 x i8], [10 x i8]* %buf, i32 0, i32 20
              call void @external_func(i8* %ptr)
              ret void
            }
        "#;

        let detector = BufferOverflowDetector::new();
        let issues = detector.detect_issues(ir);

        // Should detect issue with FFI proximity
        assert!(
            issues.iter().any(|issue| issue.near_ffi_call),
            "Should detect FFI proximity for buffer overflow"
        );
    }

    /// Objective: Verify integer overflow detection in size calculation
    /// Invariants: Multiplication in alloca size should be detected
    #[test]
    fn test_integer_overflow_detection() {
        let ir = r#"
            define void @test_integer_overflow(i64 %size, i64 %count) {
              %total = mul i64 %size, %count
              %buf = alloca i8, i64 %total
              ret void
            }
        "#;

        let detector = BufferOverflowDetector::new();
        let issues = detector.detect_issues(ir);

        // Should detect potential integer overflow
        assert!(
            issues
                .iter()
                .any(|issue| matches!(issue.kind, BufferOverflowKind::IntegerOverflow { .. })),
            "Should detect potential integer overflow in size calculation"
        );
    }

    /// Objective: Verify confidence levels are set correctly
    /// Invariants: Different patterns should have appropriate confidence levels
    #[test]
    fn test_confidence_levels() {
        let ir = r#"
            define void @test_confidence() {
              %buf = alloca [10 x i8]
              %ptr = getelementptr [10 x i8], [10 x i8]* %buf, i32 0, i32 20
              store i8 65, i8* %ptr
              ret void
            }
        "#;

        let detector = BufferOverflowDetector::new();
        let issues = detector.detect_issues(ir);

        // Check that issues have appropriate confidence
        for issue in &issues {
            match &issue.kind {
                BufferOverflowKind::OutOfBoundsWrite { .. } => {
                    assert!(
                        issue.confidence >= OverflowConfidence::Medium,
                        "Out-of-bounds write should have medium or high confidence"
                    );
                }
                BufferOverflowKind::NullPointerDeref { .. } => {
                    assert!(
                        issue.confidence >= OverflowConfidence::High,
                        "Null pointer dereference should have high confidence"
                    );
                }
                _ => {}
            }
        }
    }

    /// Objective: Verify detector settings work correctly
    /// Invariants: Disabled checks should not produce issues
    #[test]
    fn test_detector_settings() {
        let ir = r#"
            define void @test_settings() {
              %buf = alloca [10 x i8]
              %ptr = getelementptr [10 x i8], [10 x i8]* %buf, i32 0, i32 20
              store i8 65, i8* %ptr
              ret void
            }
        "#;

        // Create detector with out-of-bounds check disabled
        let detector = BufferOverflowDetector::with_settings(
            OverflowConfidence::Low,
            true,  // check_size_mismatch
            false, // check_out_of_bounds
            true,  // check_null_deref
            true,  // check_integer_overflow
            true,  // check_missing_bounds
        );

        let issues = detector.detect_issues(ir);

        // Should not detect out-of-bounds when check is disabled
        assert!(
            !issues
                .iter()
                .any(|issue| matches!(issue.kind, BufferOverflowKind::OutOfBoundsWrite { .. })),
            "Should not detect out-of-bounds when check is disabled"
        );
    }

    /// Objective: Verify empty IR handling
    /// Invariants: Empty IR should not cause panics
    #[test]
    fn test_empty_ir() {
        let ir = "";

        let detector = BufferOverflowDetector::new();
        let issues = detector.detect_issues(ir);

        // Should handle empty IR gracefully
        assert!(issues.is_empty(), "Empty IR should not produce any issues");
    }

    /// Objective: Verify function with no memory operations
    /// Invariants: Functions without memory operations should not trigger issues
    #[test]
    fn test_no_memory_operations() {
        let ir = r#"
            define void @test_no_memory() {
              %x = add i32 1, 2
              ret void
            }
        "#;

        let detector = BufferOverflowDetector::new();
        let issues = detector.detect_issues(ir);

        // Should not detect issues without memory operations
        assert!(
            issues.is_empty(),
            "Functions without memory operations should not trigger buffer overflow detection"
        );
    }
}
