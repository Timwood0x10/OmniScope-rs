//! Type Confusion Detector — Detects cross-language type mapping issues.
//!
//! This module analyzes IR instructions to identify potential type confusion
//! issues across FFI boundaries, including:
//!
//! 1. **Type Width Mismatches**: Different integer/pointer sizes between languages
//! 2. **Signed/Unsigned Confusion**: Misinterpretation of signed vs unsigned types
//! 3. **Pointer Type Confusion**: Unsafe pointer casts between incompatible types
//! 4. **Float/Integer Confusion**: Unsafe conversions between float and integer types
//! 5. **Endianness Issues**: Type conversions that may break on different architectures
//!
//! # Detection Strategy
//!
//! The detector looks for conversion instructions (`bitcast`, `inttoptr`, `ptrtoint`,
//! `zext`, `sext`, `trunc`, `sitofp`, `uitofp`, `fptosi`, `fptoui`) and analyzes
//! their context to identify potential type confusion issues.
//!
//! ## Key Patterns
//!
//! 1. **Cross-language integer width**: `i64` → `i32` at FFI boundaries
//! 2. **Signed/unsigned confusion**: `sext i32 to i64` vs `zext i32 to i64`
//! 3. **Pointer/integer confusion**: `inttoptr` or `ptrtoint` near FFI calls
//! 4. **Float/integer confusion**: `sitofp` or `fptosi` without proper validation
//!
//! # Examples
//!
//! ```rust,no_run
//! use omniscope_semantics::resource::type_confusion_detector::TypeConfusionDetector;
//!
//! let ir = r#"
//!   define void @test_type_confusion(i32 %value) {
//!     %ptr = inttoptr i32 %value to i8*
//!     call void @use_pointer(i8* %ptr)
//!     ret void
//!   }
//! "#;
//!
//! let detector = TypeConfusionDetector::new();
//! let issues = detector.detect_issues(ir);
//! assert!(!issues.is_empty(), "Should detect inttoptr type confusion");
//! ```

use super::type_confusion_detector_helpers::*;
use omniscope_ir::{FunctionBody, IRInstruction, IRInstructionKind};

// ============================================================================
// Data Types
// ============================================================================

/// Represents a type confusion issue detected in the IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeConfusionKind {
    /// Signed/unsigned confusion at FFI boundary
    SignedUnsignedConfusion {
        /// Source type (e.g., "i32")
        source_type: String,
        /// Target type (e.g., "i64")
        target_type: String,
        /// Whether source is signed
        source_signed: bool,
        /// Whether target is signed
        target_signed: bool,
    },
    /// Pointer/integer confusion
    PointerIntegerConfusion {
        /// Conversion direction (inttoptr or ptrtoint)
        direction: String,
        /// Integer type
        integer_type: String,
        /// Pointer type
        pointer_type: String,
    },
    /// Float/integer confusion
    FloatIntegerConfusion {
        /// Conversion direction
        direction: String,
        /// Float type
        float_type: String,
        /// Integer type
        integer_type: String,
    },
    /// Type width mismatch at FFI boundary
    TypeWidthMismatch {
        /// Source type width (in bits)
        source_width: u32,
        /// Target type width (in bits)
        target_width: u32,
        /// Source type name
        source_type: String,
        /// Target type name
        target_type: String,
    },
    /// Unsafe bitcast between incompatible types
    UnsafeBitcast {
        /// Source type
        source_type: String,
        /// Target type
        target_type: String,
    },
    /// Struct width mismatch through void* cast at FFI boundary.
    ///
    /// Detects when an FFI function takes a `void*` or opaque pointer,
    /// and the caller passes a pointer to a struct of size S1, but inside
    /// the function it is cast to a struct of size S2 where S2 < S1.
    /// This causes silent truncation of data (e.g., caller passes `{u64,u64}`
    /// (16 bytes) but callee reads as `{u32,u32}` (8 bytes) through void*).
    StructWidthMismatch {
        /// Caller-side struct size in bytes
        caller_struct_size: u64,
        /// Callee-side struct size in bytes
        callee_struct_size: u64,
        /// Caller-side struct type name (if available)
        caller_type: String,
        /// Callee-side struct type name (if available)
        callee_type: String,
    },
}

/// Confidence level for type confusion detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConfusionConfidence {
    /// Low confidence: type confusion without clear FFI context.
    Low,
    /// Medium confidence: type confusion in function that calls FFI.
    Medium,
    /// High confidence: explicit type confusion near FFI call.
    High,
}

/// A type confusion pattern detected in IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeConfusionPattern {
    /// Kind of type confusion
    pub kind: TypeConfusionKind,
    /// The instruction causing the confusion
    pub instruction: String,
    /// Whether this occurs near an FFI call
    pub near_ffi_call: bool,
    /// The FFI function name (if near FFI call)
    pub ffi_function: Option<String>,
    /// Confidence level
    pub confidence: ConfusionConfidence,
    /// Line number in IR (if available)
    pub line_number: Option<usize>,
}

/// Result of type confusion analysis.
#[derive(Debug, Clone)]
pub struct TypeConfusionAnalysis {
    /// Function name
    pub function_name: String,
    /// Detected type confusion patterns
    pub patterns: Vec<TypeConfusionPattern>,
    /// Whether any FFI calls are present
    pub has_ffi_calls: bool,
    /// Number of conversion instructions analyzed
    pub conversion_count: usize,
}

/// Main detector for type confusion issues.
///
/// This analyzer parses IR conversion instructions and identifies
/// potential type confusion issues at FFI boundaries.
pub struct TypeConfusionDetector {
    /// Minimum confidence level to report
    pub(crate) min_confidence: ConfusionConfidence,
    /// Whether to check for signed/unsigned confusion
    pub(crate) check_signed_unsigned: bool,
    /// Whether to check for pointer/integer confusion
    pub(crate) check_pointer_integer: bool,
    /// Whether to check for float/integer confusion
    pub(crate) check_float_integer: bool,
    /// Whether to check for type width mismatches
    pub(crate) check_width_mismatch: bool,
    /// Whether to check for unsafe bitcasts
    pub(crate) check_unsafe_bitcast: bool,
    /// Whether to check for struct width mismatches through void* casts
    pub(crate) check_struct_width: bool,
}

impl TypeConfusionDetector {
    /// Creates a new type confusion detector with default settings.
    pub fn new() -> Self {
        Self {
            min_confidence: ConfusionConfidence::Low,
            check_signed_unsigned: true,
            check_pointer_integer: true,
            check_float_integer: true,
            check_width_mismatch: true,
            check_unsafe_bitcast: true,
            check_struct_width: true,
        }
    }

    /// Creates a detector with custom settings.
    pub fn with_settings(
        min_confidence: ConfusionConfidence,
        check_signed_unsigned: bool,
        check_pointer_integer: bool,
        check_float_integer: bool,
        check_width_mismatch: bool,
        check_unsafe_bitcast: bool,
        check_struct_width: bool,
    ) -> Self {
        Self {
            min_confidence,
            check_signed_unsigned,
            check_pointer_integer,
            check_float_integer,
            check_width_mismatch,
            check_unsafe_bitcast,
            check_struct_width,
        }
    }

    /// Detects type confusion issues in the given IR.
    ///
    /// This is the main entry point for analysis. It parses conversion
    /// instructions and checks for various type confusion issues.
    pub fn detect_issues(&self, ir: &str) -> Vec<TypeConfusionPattern> {
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

    /// Analyzes a function body for type confusion issues.
    pub fn analyze_function(&self, body: &FunctionBody) -> TypeConfusionAnalysis {
        let conversion_insts: Vec<&IRInstruction> = body
            .instructions
            .iter()
            .filter(|i| i.kind == IRInstructionKind::Conversion)
            .collect();

        let conversion_count = conversion_insts.len();
        let mut patterns = Vec::new();

        // Collect FFI call information
        let ffi_calls = collect_ffi_calls(body);
        let has_ffi_calls = !ffi_calls.is_empty();

        // Analyze each conversion instruction
        for inst in &conversion_insts {
            if let Some(pattern) = self.analyze_conversion(inst, &ffi_calls, body) {
                patterns.push(pattern);
            }
        }

        TypeConfusionAnalysis {
            function_name: body.name.clone(),
            patterns,
            has_ffi_calls,
            conversion_count,
        }
    }

    /// Analyzes a single conversion instruction for type confusion.
    fn analyze_conversion(
        &self,
        inst: &IRInstruction,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<TypeConfusionPattern> {
        // Check for different types of conversions using structured fields
        if self.check_signed_unsigned {
            if let Some(pattern) = self.check_signed_unsigned_confusion(inst, ffi_calls, body) {
                return Some(pattern);
            }
        }

        if self.check_pointer_integer {
            if let Some(pattern) = self.check_pointer_integer_confusion(inst, ffi_calls, body) {
                return Some(pattern);
            }
        }

        if self.check_float_integer {
            if let Some(pattern) = self.check_float_integer_confusion(inst, ffi_calls, body) {
                return Some(pattern);
            }
        }

        if self.check_width_mismatch {
            if let Some(pattern) = self.check_type_width_mismatch(inst, ffi_calls, body) {
                return Some(pattern);
            }
        }

        if self.check_unsafe_bitcast {
            if let Some(pattern) = self.check_unsafe_bitcast(inst, ffi_calls, body) {
                return Some(pattern);
            }
        }

        if self.check_struct_width {
            if let Some(pattern) = self.check_struct_width_mismatch(inst, ffi_calls, body) {
                return Some(pattern);
            }
        }

        None
    }

    /// Checks for signed/unsigned confusion.
    fn check_signed_unsigned_confusion(
        &self,
        inst: &IRInstruction,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<TypeConfusionPattern> {
        // Use structured conversion_opcode instead of raw_text.contains()
        let conv_op = inst.conversion_opcode.as_deref();
        let is_sext = conv_op == Some("sext");
        let is_zext = conv_op == Some("zext");

        if !is_sext && !is_zext {
            return None;
        }

        // Parse source and target types from raw text
        let mut inst_clone = inst.clone();
        inst_clone.ensure_raw();
        let raw = &inst_clone.raw_text;
        let (source_type, target_type) = parse_extension_types(raw)?;

        // Check if this is near an FFI call
        let (near_ffi_call, ffi_function) = check_ffi_proximity(inst, ffi_calls, body);

        // Only flag if near FFI call or if there are FFI calls in the function
        if !near_ffi_call && ffi_calls.is_empty() {
            return None;
        }

        let confidence = if near_ffi_call {
            ConfusionConfidence::High
        } else if !ffi_calls.is_empty() {
            ConfusionConfidence::Medium
        } else {
            ConfusionConfidence::Low
        };

        Some(TypeConfusionPattern {
            kind: TypeConfusionKind::SignedUnsignedConfusion {
                source_type,
                target_type,
                source_signed: is_sext,
                target_signed: is_sext, // sext preserves signedness
            },
            instruction: raw.to_string(),
            near_ffi_call,
            ffi_function,
            confidence,
            line_number: None,
        })
    }

    /// Checks for pointer/integer confusion.
    fn check_pointer_integer_confusion(
        &self,
        inst: &IRInstruction,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<TypeConfusionPattern> {
        // Use structured conversion_opcode instead of raw_text.contains()
        let conv_op = inst.conversion_opcode.as_deref();
        let is_inttoptr = conv_op == Some("inttoptr");
        let is_ptrtoint = conv_op == Some("ptrtoint");

        if !is_inttoptr && !is_ptrtoint {
            return None;
        }

        let direction = if is_inttoptr {
            "inttoptr".to_string()
        } else {
            "ptrtoint".to_string()
        };

        // Parse types from raw text
        let mut inst_clone = inst.clone();
        inst_clone.ensure_raw();
        let raw = &inst_clone.raw_text;
        let (integer_type, pointer_type) = parse_intptr_types(raw, is_inttoptr)?;

        // Check if this is near an FFI call
        let (near_ffi_call, ffi_function) = check_ffi_proximity(inst, ffi_calls, body);

        let confidence = if near_ffi_call {
            ConfusionConfidence::High
        } else if !ffi_calls.is_empty() {
            ConfusionConfidence::Medium
        } else {
            ConfusionConfidence::Low
        };

        Some(TypeConfusionPattern {
            kind: TypeConfusionKind::PointerIntegerConfusion {
                direction,
                integer_type,
                pointer_type,
            },
            instruction: raw.to_string(),
            near_ffi_call,
            ffi_function,
            confidence,
            line_number: None,
        })
    }

    /// Checks for float/integer confusion.
    fn check_float_integer_confusion(
        &self,
        inst: &IRInstruction,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<TypeConfusionPattern> {
        // Use structured conversion_opcode instead of raw_text.contains()
        let conv_op = inst.conversion_opcode.as_deref();
        let is_sitofp = conv_op == Some("sitofp");
        let is_uitofp = conv_op == Some("uitofp");
        let is_fptosi = conv_op == Some("fptosi");
        let is_fptoui = conv_op == Some("fptoui");

        if !is_sitofp && !is_uitofp && !is_fptosi && !is_fptoui {
            return None;
        }

        let direction = if is_sitofp || is_uitofp {
            "int_to_float".to_string()
        } else {
            "float_to_int".to_string()
        };

        // Parse types from raw text
        let mut inst_clone = inst.clone();
        inst_clone.ensure_raw();
        let raw = &inst_clone.raw_text;
        let (float_type, integer_type) = parse_float_int_types(raw)?;

        // Check if this is near an FFI call
        let (near_ffi_call, ffi_function) = check_ffi_proximity(inst, ffi_calls, body);

        let confidence = if near_ffi_call {
            ConfusionConfidence::High
        } else if !ffi_calls.is_empty() {
            ConfusionConfidence::Medium
        } else {
            ConfusionConfidence::Low
        };

        Some(TypeConfusionPattern {
            kind: TypeConfusionKind::FloatIntegerConfusion {
                direction,
                float_type,
                integer_type,
            },
            instruction: raw.to_string(),
            near_ffi_call,
            ffi_function,
            confidence,
            line_number: None,
        })
    }

    /// Checks for type width mismatches.
    fn check_type_width_mismatch(
        &self,
        inst: &IRInstruction,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<TypeConfusionPattern> {
        // Use structured conversion_opcode instead of raw_text.contains()
        let conv_op = inst.conversion_opcode.as_deref();
        let is_trunc = conv_op == Some("trunc");
        let is_zext = conv_op == Some("zext");
        let is_sext = conv_op == Some("sext");

        if !is_trunc && !is_zext && !is_sext {
            return None;
        }

        // Parse source and target types from raw text
        let mut inst_clone = inst.clone();
        inst_clone.ensure_raw();
        let raw = &inst_clone.raw_text;
        let (source_type, target_type) = parse_extension_types(raw)?;

        // Get bit widths
        let source_width = get_type_width(&source_type)?;
        let target_width = get_type_width(&target_type)?;

        // Only flag significant width mismatches (e.g., 64->32, 32->16)
        let width_diff = source_width.abs_diff(target_width);

        if width_diff < 16 {
            return None;
        }

        // Check if this is near an FFI call
        let (near_ffi_call, ffi_function) = check_ffi_proximity(inst, ffi_calls, body);

        // Only flag if near FFI call or if there are FFI calls in the function
        if !near_ffi_call && ffi_calls.is_empty() {
            return None;
        }

        let confidence = if near_ffi_call {
            ConfusionConfidence::High
        } else if !ffi_calls.is_empty() {
            ConfusionConfidence::Medium
        } else {
            ConfusionConfidence::Low
        };

        Some(TypeConfusionPattern {
            kind: TypeConfusionKind::TypeWidthMismatch {
                source_width,
                target_width,
                source_type,
                target_type,
            },
            instruction: raw.to_string(),
            near_ffi_call,
            ffi_function,
            confidence,
            line_number: None,
        })
    }

    /// Checks for unsafe bitcasts.
    fn check_unsafe_bitcast(
        &self,
        inst: &IRInstruction,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<TypeConfusionPattern> {
        // Use structured conversion_opcode instead of raw_text.contains()
        if inst.conversion_opcode.as_deref() != Some("bitcast") {
            return None;
        }

        // Parse source and target types from raw text
        let mut inst_clone = inst.clone();
        inst_clone.ensure_raw();
        let raw = &inst_clone.raw_text;
        let (source_type, target_type) = parse_bitcast_types(raw)?;

        // Check if this is a potentially unsafe bitcast
        if !is_unsafe_bitcast(&source_type, &target_type) {
            return None;
        }

        // Check if this is near an FFI call
        let (near_ffi_call, ffi_function) = check_ffi_proximity(inst, ffi_calls, body);

        let confidence = if near_ffi_call {
            ConfusionConfidence::High
        } else if !ffi_calls.is_empty() {
            ConfusionConfidence::Medium
        } else {
            ConfusionConfidence::Low
        };

        Some(TypeConfusionPattern {
            kind: TypeConfusionKind::UnsafeBitcast {
                source_type,
                target_type,
            },
            instruction: raw.to_string(),
            near_ffi_call,
            ffi_function,
            confidence,
            line_number: None,
        })
    }

    /// Checks for struct width mismatches through void* casts at FFI boundaries.
    ///
    /// Detects the pattern where:
    /// 1. An FFI function takes a `void*`/opaque pointer parameter
    /// 2. The caller passes a pointer to a struct of size S1
    /// 3. Inside the function, the pointer is bitcast to a smaller struct (S2 < S1)
    /// 4. Subsequent GEP/load instructions access fields of the smaller struct
    ///
    /// This is the FN-8 pattern: caller passes `Config{u64, u64}` (16 bytes)
    /// but callee reads as `CConfig{u32, u32}` (8 bytes) through void* cast.
    fn check_struct_width_mismatch(
        &self,
        inst: &IRInstruction,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<TypeConfusionPattern> {
        // Only look for bitcast instructions on pointer types
        let conv_op = inst.conversion_opcode.as_deref();
        if conv_op != Some("bitcast") {
            return None;
        }

        // Parse the bitcast source and target types
        let mut inst_clone = inst.clone();
        inst_clone.ensure_raw();
        let raw = &inst_clone.raw_text;
        let (source_type, target_type) = parse_bitcast_types(raw)?;

        // Check if this is a ptr-to-ptr cast (both are pointer types)
        let source_is_ptr = source_type.ends_with('*') || source_type == "ptr";
        let target_is_ptr = target_type.ends_with('*') || target_type == "ptr";

        if !source_is_ptr || !target_is_ptr {
            return None;
        }

        // Skip same-type casts (e.g., i8* to i8*)
        if source_type == target_type {
            return None;
        }

        // Find the instruction index to look ahead for GEP/load patterns
        let inst_idx = body
            .instructions
            .iter()
            .position(|i| std::ptr::eq(i, inst))?;

        // Look ahead for GEP or load instructions that use the bitcast result
        let dest_reg = inst.dest.as_deref()?;
        let mut found_gep_or_load = false;

        for next_inst in body.instructions.iter().skip(inst_idx + 1).take(5) {
            let next_raw = next_inst.raw_text.clone();

            // Check if this instruction uses our bitcast result
            if !next_raw.contains(dest_reg) {
                // Also check operands
                if !next_inst.operands.iter().any(|op| op == dest_reg) {
                    continue;
                }
            }

            // Found a GEP instruction using the cast result — extract element type
            if next_inst.kind == IRInstructionKind::GetElementPtr
                || next_raw.starts_with("%")
                    && (next_raw.contains("getelementptr")
                        || next_op_matches(next_inst, "getelementptr"))
            {
                found_gep_or_load = true;
                break;
            }

            // Found a load instruction using the cast result
            if next_inst.kind == IRInstructionKind::Load || next_raw.contains("load") {
                found_gep_or_load = true;
                break;
            }
        }

        if !found_gep_or_load {
            return None;
        }

        // Estimate struct sizes from type names
        let caller_size = estimate_struct_size(&source_type);
        let callee_size = estimate_struct_size(&target_type);

        let (Some(caller_size), Some(callee_size)) = (caller_size, callee_size) else {
            return None;
        };

        // Only flag when callee struct is strictly smaller (potential truncation)
        if callee_size >= caller_size {
            return None;
        }

        // Require significant size difference (at least 4 bytes / 32 bits)
        let size_diff = caller_size - callee_size;
        if size_diff < 4 {
            return None;
        }

        // Check FFI proximity
        let (near_ffi_call, ffi_function) = check_ffi_proximity(inst, ffi_calls, body);
        if !near_ffi_call && ffi_calls.is_empty() {
            return None;
        }

        let confidence = if near_ffi_call {
            ConfusionConfidence::High
        } else if !ffi_calls.is_empty() {
            ConfusionConfidence::Medium
        } else {
            ConfusionConfidence::Low
        };

        Some(TypeConfusionPattern {
            kind: TypeConfusionKind::StructWidthMismatch {
                caller_struct_size: caller_size,
                callee_struct_size: callee_size,
                caller_type: source_type,
                callee_type: target_type,
            },
            instruction: raw.to_string(),
            near_ffi_call,
            ffi_function,
            confidence,
            line_number: None,
        })
    }

    /// Converts detected type confusion patterns into SemanticFact records
    /// for pipeline integration.
    ///
    /// Each pattern produces one or more SemanticFact entries that can be
    /// stored in pass context and consumed by downstream issue candidate builders.
    pub fn patterns_to_semantic_facts(
        patterns: &[TypeConfusionPattern],
        func_name: &str,
    ) -> Vec<super::semantic_tree::SemanticFact> {
        use super::semantic_tree::{
            FactConfidence, FactSource, SemanticFact, SemanticKey, SemanticKind,
        };
        let key = SemanticKey::Symbol(func_name.to_string());
        let mut facts = Vec::new();

        for pattern in patterns {
            let confidence = match pattern.confidence {
                ConfusionConfidence::High => FactConfidence::High,
                ConfusionConfidence::Medium => FactConfidence::Medium,
                ConfusionConfidence::Low => FactConfidence::Low,
            };

            match &pattern.kind {
                TypeConfusionKind::StructWidthMismatch {
                    caller_struct_size,
                    callee_struct_size,
                    caller_type,
                    callee_type,
                } => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::NonMemoryResource,
                        confidence,
                        FactSource::IRPattern,
                        format!(
                            "StructWidthMismatch: {} ({}B) cast to {} ({}B) in {} — potential data truncation through void*",
                            caller_type, caller_struct_size, callee_type, callee_struct_size, func_name
                        ),
                    ));
                }
                TypeConfusionKind::TypeWidthMismatch {
                    source_width,
                    target_width,
                    source_type,
                    target_type,
                } => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::NonMemoryResource,
                        confidence,
                        FactSource::IRPattern,
                        format!(
                            "TypeWidthMismatch: {} ({}-bit) -> {} ({}-bit) in {}",
                            source_type, source_width, target_type, target_width, func_name
                        ),
                    ));
                }
                _ => {
                    // Generic type confusion fact for other kinds
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::NonMemoryResource,
                        confidence,
                        FactSource::IRPattern,
                        format!("TypeConfusion: {} in {}", pattern.kind, func_name),
                    ));
                }
            }
        }

        facts
    }
}

impl Default for TypeConfusionDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Display Implementation
// ============================================================================

impl std::fmt::Display for TypeConfusionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeConfusionKind::SignedUnsignedConfusion {
                source_type,
                target_type,
                source_signed,
                target_signed,
            } => {
                write!(
                    f,
                    "Signed/unsigned confusion: {} ({}) -> {} ({})",
                    source_type,
                    if *source_signed { "signed" } else { "unsigned" },
                    target_type,
                    if *target_signed { "signed" } else { "unsigned" }
                )
            }
            TypeConfusionKind::PointerIntegerConfusion {
                direction,
                integer_type,
                pointer_type,
            } => {
                write!(
                    f,
                    "Pointer/integer confusion: {} {} -> {}",
                    direction, integer_type, pointer_type
                )
            }
            TypeConfusionKind::FloatIntegerConfusion {
                direction,
                float_type,
                integer_type,
            } => {
                write!(
                    f,
                    "Float/integer confusion: {} {} -> {}",
                    direction, float_type, integer_type
                )
            }
            TypeConfusionKind::TypeWidthMismatch {
                source_width,
                target_width,
                source_type,
                target_type,
            } => {
                write!(
                    f,
                    "Type width mismatch: {} ({}-bit) -> {} ({}-bit)",
                    source_type, source_width, target_type, target_width
                )
            }
            TypeConfusionKind::UnsafeBitcast {
                source_type,
                target_type,
            } => {
                write!(f, "Unsafe bitcast: {} -> {}", source_type, target_type)
            }
            TypeConfusionKind::StructWidthMismatch {
                caller_struct_size,
                callee_struct_size,
                caller_type,
                callee_type,
            } => {
                write!(
                    f,
                    "Struct width mismatch: {} ({} bytes) -> {} ({} bytes) through void* cast — potential truncation",
                    caller_type, caller_struct_size, callee_type, callee_struct_size
                )
            }
        }
    }
}

impl std::fmt::Display for TypeConfusionPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Type confusion: {} (confidence: {:?})",
            self.kind, self.confidence
        )?;

        if let Some(ref ffi_func) = self.ffi_function {
            write!(f, " near FFI call to '{}'", ffi_func)?;
        }

        Ok(())
    }
}

/// Get the CWE ID for type confusion issues.
pub fn type_confusion_cwe_id() -> u32 {
    843 // CWE-843: Access of Resource Using Incompatible Type
}
