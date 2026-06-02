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
    min_confidence: ConfusionConfidence,
    /// Whether to check for signed/unsigned confusion
    check_signed_unsigned: bool,
    /// Whether to check for pointer/integer confusion
    check_pointer_integer: bool,
    /// Whether to check for float/integer confusion
    check_float_integer: bool,
    /// Whether to check for type width mismatches
    check_width_mismatch: bool,
    /// Whether to check for unsafe bitcasts
    check_unsafe_bitcast: bool,
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
    ) -> Self {
        Self {
            min_confidence,
            check_signed_unsigned,
            check_pointer_integer,
            check_float_integer,
            check_width_mismatch,
            check_unsafe_bitcast,
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
        let raw = &inst.raw_text;

        // Check for different types of conversions
        if self.check_signed_unsigned {
            if let Some(pattern) = self.check_signed_unsigned_confusion(raw, ffi_calls, body) {
                return Some(pattern);
            }
        }

        if self.check_pointer_integer {
            if let Some(pattern) = self.check_pointer_integer_confusion(raw, ffi_calls, body) {
                return Some(pattern);
            }
        }

        if self.check_float_integer {
            if let Some(pattern) = self.check_float_integer_confusion(raw, ffi_calls, body) {
                return Some(pattern);
            }
        }

        if self.check_width_mismatch {
            if let Some(pattern) = self.check_type_width_mismatch(raw, ffi_calls, body) {
                return Some(pattern);
            }
        }

        if self.check_unsafe_bitcast {
            if let Some(pattern) = self.check_unsafe_bitcast(raw, ffi_calls, body) {
                return Some(pattern);
            }
        }

        None
    }

    /// Checks for signed/unsigned confusion.
    fn check_signed_unsigned_confusion(
        &self,
        raw: &str,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<TypeConfusionPattern> {
        // Look for sext (sign extension) or zext (zero extension)
        let is_sext = raw.contains("sext");
        let is_zext = raw.contains("zext");

        if !is_sext && !is_zext {
            return None;
        }

        // Parse source and target types
        let (source_type, target_type) = parse_extension_types(raw)?;

        // Check if this is near an FFI call
        let (near_ffi_call, ffi_function) = check_ffi_proximity(raw, ffi_calls, body);

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
        raw: &str,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<TypeConfusionPattern> {
        let is_inttoptr = raw.contains("inttoptr");
        let is_ptrtoint = raw.contains("ptrtoint");

        if !is_inttoptr && !is_ptrtoint {
            return None;
        }

        let direction = if is_inttoptr {
            "inttoptr".to_string()
        } else {
            "ptrtoint".to_string()
        };

        // Parse types
        let (integer_type, pointer_type) = parse_intptr_types(raw, is_inttoptr)?;

        // Check if this is near an FFI call
        let (near_ffi_call, ffi_function) = check_ffi_proximity(raw, ffi_calls, body);

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
        raw: &str,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<TypeConfusionPattern> {
        let is_sitofp = raw.contains("sitofp");
        let is_uitofp = raw.contains("uitofp");
        let is_fptosi = raw.contains("fptosi");
        let is_fptoui = raw.contains("fptoui");

        if !is_sitofp && !is_uitofp && !is_fptosi && !is_fptoui {
            return None;
        }

        let direction = if is_sitofp || is_uitofp {
            "int_to_float".to_string()
        } else {
            "float_to_int".to_string()
        };

        // Parse types
        let (float_type, integer_type) = parse_float_int_types(raw)?;

        // Check if this is near an FFI call
        let (near_ffi_call, ffi_function) = check_ffi_proximity(raw, ffi_calls, body);

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
        raw: &str,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<TypeConfusionPattern> {
        // Look for trunc or zext/sext that changes width significantly
        let is_trunc = raw.contains("trunc");
        let is_zext = raw.contains("zext");
        let is_sext = raw.contains("sext");

        if !is_trunc && !is_zext && !is_sext {
            return None;
        }

        // Parse source and target types
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
        let (near_ffi_call, ffi_function) = check_ffi_proximity(raw, ffi_calls, body);

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
        raw: &str,
        ffi_calls: &[(String, usize)],
        body: &FunctionBody,
    ) -> Option<TypeConfusionPattern> {
        if !raw.contains("bitcast") {
            return None;
        }

        // Parse source and target types
        let (source_type, target_type) = parse_bitcast_types(raw)?;

        // Check if this is a potentially unsafe bitcast
        if !is_unsafe_bitcast(&source_type, &target_type) {
            return None;
        }

        // Check if this is near an FFI call
        let (near_ffi_call, ffi_function) = check_ffi_proximity(raw, ffi_calls, body);

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
}

impl Default for TypeConfusionDetector {
    fn default() -> Self {
        Self::new()
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
    let c_lib_functions = [
        "malloc",
        "calloc",
        "realloc",
        "free",
        "memcpy",
        "memmove",
        "memset",
        "strlen",
        "strcpy",
        "strncpy",
        "strcmp",
        "strncmp",
        "strcat",
        "strncat",
        "printf",
        "fprintf",
        "sprintf",
        "snprintf",
        "scanf",
        "fscanf",
        "sscanf",
        "fopen",
        "fclose",
        "fread",
        "fwrite",
        "fseek",
        "ftell",
        "rewind",
        "fflush",
        "feof",
        "ferror",
        "perror",
        "exit",
        "abort",
        "atexit",
        "system",
        "getenv",
        "setenv",
        "putenv",
        "atoi",
        "atof",
        "strtol",
        "strtoul",
        "strtod",
        "qsort",
        "bsearch",
        "abs",
        "labs",
        "rand",
        "srand",
        "time",
        "clock",
        "difftime",
        "mktime",
        "localtime",
        "gmtime",
        "strftime",
        "pthread_create",
        "pthread_join",
        "pthread_mutex_init",
        "pthread_mutex_lock",
        "pthread_mutex_unlock",
        "sem_init",
        "sem_wait",
        "sem_post",
        "socket",
        "bind",
        "listen",
        "accept",
        "connect",
        "send",
        "recv",
        "close",
        "read",
        "write",
        "ioctl",
        "fcntl",
        "poll",
        "select",
        "epoll_create",
        "epoll_ctl",
        "epoll_wait",
    ];

    // Check for exact match
    if c_lib_functions.contains(&name) {
        return true;
    }

    // Check for C++ mangled names
    if name.starts_with("_Z") {
        return true;
    }

    // Check for Rust mangled names (not FFI)
    if name.starts_with("_ZN") || name.starts_with("_R") {
        return false;
    }

    // Check for common FFI prefixes
    let ffi_prefixes = [
        "curl_",
        "sqlite3_",
        "SSL_",
        "BIO_",
        "EVP_",
        "OPENSSL_",
        "json_",
        "uv_",
        "uv__",
        "g_",
        "glib_",
        "gobject_",
        "cairo_",
        "pango_",
        "gtk_",
        "GDK_",
        "GTK_",
        "Py_",
        "Py",
        "PyObject_",
        "PyList_",
        "PyDict_",
        "PyTuple_",
        "PyString_",
        "PyBytes_",
        "JNI_",
        "Java_",
        "env->",
    ];

    for prefix in &ffi_prefixes {
        if name.starts_with(prefix) {
            return true;
        }
    }

    // If it's not Rust mangled and looks like a C function name
    if !name.contains("::")
        && !name.contains("<")
        && !name.contains(">")
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
    {
        // Likely a C function
        return true;
    }

    false
}

/// Check if a conversion instruction is near an FFI call.
fn check_ffi_proximity(
    raw: &str,
    ffi_calls: &[(String, usize)],
    body: &FunctionBody,
) -> (bool, Option<String>) {
    // Find the index of the conversion instruction
    let conv_idx = body.instructions.iter().position(|i| i.raw_text == raw);

    if let Some(conv_idx) = conv_idx {
        // Check if any FFI call is within 5 instructions
        for (ffi_name, ffi_idx) in ffi_calls {
            let distance = if *ffi_idx > conv_idx {
                ffi_idx - conv_idx
            } else {
                conv_idx - ffi_idx
            };

            if distance <= 5 {
                return (true, Some(ffi_name.clone()));
            }
        }
    }

    (false, None)
}

/// Parse source and target types from sext/zext instruction.
fn parse_extension_types(raw: &str) -> Option<(String, String)> {
    // Pattern: sext i32 %val to i64
    // Pattern: zext i16 %val to i32
    let parts: Vec<&str> = raw.split_whitespace().collect();

    // Find the keyword
    let keyword_idx = parts
        .iter()
        .position(|&p| p == "sext" || p == "zext" || p == "trunc")?;

    // Next should be source type
    if keyword_idx + 1 >= parts.len() {
        return None;
    }
    let source_type = parts[keyword_idx + 1].to_string();

    // Find "to"
    let to_idx = parts.iter().position(|&p| p == "to")?;

    // Next should be target type
    if to_idx + 1 >= parts.len() {
        return None;
    }
    let target_type = parts[to_idx + 1]
        .trim_end_matches([',', ')', ']'])
        .to_string();

    Some((source_type, target_type))
}

/// Parse integer and pointer types from inttoptr/ptrtoint instruction.
fn parse_intptr_types(raw: &str, is_inttoptr: bool) -> Option<(String, String)> {
    // Pattern: inttoptr i32 %val to i8*
    // Pattern: ptrtoint ptr %val to i64
    let parts: Vec<&str> = raw.split_whitespace().collect();

    // Find the keyword
    let keyword_idx = parts
        .iter()
        .position(|&p| p == "inttoptr" || p == "ptrtoint")?;

    // Next should be first type
    if keyword_idx + 1 >= parts.len() {
        return None;
    }
    let first_type = parts[keyword_idx + 1].to_string();

    // Find "to"
    let to_idx = parts.iter().position(|&p| p == "to")?;

    // Next should be second type
    if to_idx + 1 >= parts.len() {
        return None;
    }
    let second_type = parts[to_idx + 1]
        .trim_end_matches([',', ')', ']'])
        .to_string();

    if is_inttoptr {
        Some((first_type, second_type))
    } else {
        Some((second_type, first_type))
    }
}

/// Parse float and integer types from sitofp/uitofp/fptosi/fptoui instruction.
fn parse_float_int_types(raw: &str) -> Option<(String, String)> {
    // Pattern: sitofp i32 %val to float
    // Pattern: fptosi float %val to i32
    let parts: Vec<&str> = raw.split_whitespace().collect();

    // Find the keyword
    let keyword_idx = parts
        .iter()
        .position(|&p| p == "sitofp" || p == "uitofp" || p == "fptosi" || p == "fptoui")?;

    // Next should be first type
    if keyword_idx + 1 >= parts.len() {
        return None;
    }
    let first_type = parts[keyword_idx + 1].to_string();

    // Find "to"
    let to_idx = parts.iter().position(|&p| p == "to")?;

    // Next should be second type
    if to_idx + 1 >= parts.len() {
        return None;
    }
    let second_type = parts[to_idx + 1]
        .trim_end_matches([',', ')', ']'])
        .to_string();

    // Determine which is float and which is integer
    let is_first_float = is_float_type(&first_type);
    let is_second_float = is_float_type(&second_type);

    if is_first_float && !is_second_float {
        Some((first_type, second_type))
    } else if !is_first_float && is_second_float {
        Some((second_type, first_type))
    } else {
        None // Both or neither are float types
    }
}

/// Parse source and target types from bitcast instruction.
fn parse_bitcast_types(raw: &str) -> Option<(String, String)> {
    // Pattern: bitcast i32* %val to i8*
    // Pattern: bitcast ptr %val to float*
    let parts: Vec<&str> = raw.split_whitespace().collect();

    // Find the keyword
    let keyword_idx = parts.iter().position(|&p| p == "bitcast")?;

    // Next should be source type
    if keyword_idx + 1 >= parts.len() {
        return None;
    }
    let source_type = parts[keyword_idx + 1].to_string();

    // Find "to"
    let to_idx = parts.iter().position(|&p| p == "to")?;

    // Next should be target type
    if to_idx + 1 >= parts.len() {
        return None;
    }
    let target_type = parts[to_idx + 1]
        .trim_end_matches([',', ')', ']'])
        .to_string();

    Some((source_type, target_type))
}

/// Get bit width from type string.
fn get_type_width(type_str: &str) -> Option<u32> {
    match type_str {
        "i1" => Some(1),
        "i8" => Some(8),
        "i16" => Some(16),
        "i32" => Some(32),
        "i64" => Some(64),
        "i128" => Some(128),
        "float" => Some(32),
        "double" => Some(64),
        "fp128" | "ppc_fp128" => Some(128),
        _ => {
            // Check for pointer types
            if type_str.ends_with('*') || type_str == "ptr" {
                Some(64) // Assume 64-bit pointers
            } else {
                None
            }
        }
    }
}

/// Check if a type is a float type.
fn is_float_type(type_str: &str) -> bool {
    matches!(type_str, "float" | "double" | "fp128" | "ppc_fp128")
}

/// Check if a type is a common FFI type.
#[cfg(test)]
fn is_ffi_type(type_str: &str) -> bool {
    // Common FFI types
    matches!(
        type_str,
        "i32" | "i64" | "i16" | "i8" | "float" | "double" | "ptr" | "i8*"
    )
}

/// Check if a bitcast is potentially unsafe.
fn is_unsafe_bitcast(source: &str, target: &str) -> bool {
    // Pointer to non-pointer or vice versa
    let source_is_ptr = source.ends_with('*') || source == "ptr";
    let target_is_ptr = target.ends_with('*') || target == "ptr";

    if source_is_ptr != target_is_ptr {
        return true;
    }

    // Different pointer types (e.g., i32* to i8*)
    if source_is_ptr && target_is_ptr && source != target {
        return true;
    }

    // Integer to pointer or vice versa
    let source_is_int = source.starts_with('i') && source[1..].chars().all(|c| c.is_ascii_digit());
    let target_is_int = target.starts_with('i') && target[1..].chars().all(|c| c.is_ascii_digit());

    if (source_is_int && target_is_ptr) || (source_is_ptr && target_is_int) {
        return true;
    }

    false
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::debug;

    /// Objective: Verify basic type confusion detection with inttoptr.
    /// Invariants: inttoptr conversions must be detected as pointer/integer confusion.
    #[test]
    fn test_inttoptr_type_confusion() {
        let ir = r#"
            define void @test_inttoptr(i32 %value) {
            entry:
                %ptr = inttoptr i32 %value to i8*
                call void @use_pointer(i8* %ptr)
                ret void
            }
        "#;

        let detector = TypeConfusionDetector::new();
        let issues = detector.detect_issues(ir);

        // Debug: Check if IR parsing works
        use omniscope_ir::IRModule;
        let module = IRModule::parse_from_text(ir);

        for (name, body) in &module.function_bodies {
            debug!(
                "Function '{}' has {} instructions:",
                name,
                body.instructions.len()
            );
            for (i, inst) in body.instructions.iter().enumerate() {
                debug!("  {}: {:?} - {}", i, inst.kind, inst.raw_text);
            }

            // Check if use_pointer is recognized as external
            let ffi_calls = collect_ffi_calls(body);
            debug!("FFI calls found: {:?}", ffi_calls);

            // Check if inttoptr is detected
            let conv_insts: Vec<_> = body
                .instructions
                .iter()
                .filter(|i| i.kind == IRInstructionKind::Conversion)
                .collect();
            debug!("Conversion instructions: {:?}", conv_insts);

            // Check proximity
            for inst in &conv_insts {
                let (near_ffi, ffi_func) = check_ffi_proximity(&inst.raw_text, &ffi_calls, body);
                debug!(
                    "Instruction '{}' near FFI: {} (function: {:?})",
                    inst.raw_text, near_ffi, ffi_func
                );

                // Test type parsing
                let is_inttoptr = inst.raw_text.contains("inttoptr");
                debug!("Is inttoptr: {}", is_inttoptr);

                if is_inttoptr {
                    let types = parse_intptr_types(&inst.raw_text, true);
                    debug!("Parsed types: {:?}", types);
                }
            }
        }

        assert!(
            !issues.is_empty(),
            "Must detect inttoptr type confusion, found {} issues",
            issues.len()
        );

        let issue = &issues[0];
        assert!(
            matches!(
                issue.kind,
                TypeConfusionKind::PointerIntegerConfusion { .. }
            ),
            "Must be pointer/integer confusion"
        );
        assert!(issue.near_ffi_call, "Must detect proximity to FFI call");
    }

    /// Objective: Verify signed/unsigned confusion detection.
    /// Invariants: sext/zext conversions near FFI must be detected.
    #[test]
    fn test_signed_unsigned_confusion() {
        let ir = r#"
            define void @test_sign_confusion(i32 %value) {
            entry:
                %extended = sext i32 %value to i64
                call void @ffi_process(i64 %extended)
                ret void
            }
        "#;

        let detector = TypeConfusionDetector::new();
        let issues = detector.detect_issues(ir);

        assert!(
            !issues.is_empty(),
            "Must detect signed/unsigned confusion, found {} issues",
            issues.len()
        );

        let issue = &issues[0];
        assert!(
            matches!(
                issue.kind,
                TypeConfusionKind::SignedUnsignedConfusion { .. }
            ),
            "Must be signed/unsigned confusion"
        );
    }

    /// Objective: Verify float/integer confusion detection.
    /// Invariants: float/integer conversions near FFI must be detected.
    #[test]
    fn test_float_integer_confusion() {
        let ir = r#"
            define void @test_float_confusion(i32 %value) {
            entry:
                %float_val = sitofp i32 %value to float
                call void @ffi_process_float(float %float_val)
                ret void
            }
        "#;

        let detector = TypeConfusionDetector::new();
        let issues = detector.detect_issues(ir);

        assert!(
            !issues.is_empty(),
            "Must detect float/integer confusion, found {} issues",
            issues.len()
        );

        let issue = &issues[0];
        assert!(
            matches!(issue.kind, TypeConfusionKind::FloatIntegerConfusion { .. }),
            "Must be float/integer confusion"
        );
    }

    /// Objective: Verify type width mismatch detection.
    /// Invariants: Significant width changes near FFI must be detected.
    #[test]
    fn test_type_width_mismatch() {
        let ir = r#"
            define void @test_width_mismatch(i64 %value) {
            entry:
                %truncated = trunc i64 %value to i32
                call void @ffi_process(i32 %truncated)
                ret void
            }
        "#;

        let detector = TypeConfusionDetector::new();
        let issues = detector.detect_issues(ir);

        assert!(
            !issues.is_empty(),
            "Must detect type width mismatch, found {} issues",
            issues.len()
        );

        let issue = &issues[0];
        assert!(
            matches!(issue.kind, TypeConfusionKind::TypeWidthMismatch { .. }),
            "Must be type width mismatch"
        );
    }

    /// Objective: Verify unsafe bitcast detection.
    /// Invariants: Pointer type changes must be detected.
    #[test]
    fn test_unsafe_bitcast() {
        let ir = r#"
            define void @test_unsafe_bitcast(ptr %value) {
            entry:
                %casted = bitcast ptr %value to i32*
                call void @ffi_process_ptr(i32* %casted)
                ret void
            }
        "#;

        let detector = TypeConfusionDetector::new();
        let issues = detector.detect_issues(ir);

        assert!(
            !issues.is_empty(),
            "Must detect unsafe bitcast, found {} issues",
            issues.len()
        );

        let issue = &issues[0];
        assert!(
            matches!(issue.kind, TypeConfusionKind::UnsafeBitcast { .. }),
            "Must be unsafe bitcast"
        );
    }

    /// Objective: Verify no false positives for safe conversions.
    /// Invariants: zext without FFI context should not be flagged.
    #[test]
    fn test_no_false_positives() {
        let ir = r#"
            define i64 @test_safe_conversion(i32 %value) {
            entry:
                %extended = zext i32 %value to i64
                ret i64 %extended
            }
        "#;

        let detector = TypeConfusionDetector::new();
        let issues = detector.detect_issues(ir);

        assert!(
            issues.is_empty(),
            "Safe conversion without FFI should not be flagged, found {} issues",
            issues.len()
        );
    }

    /// Objective: Verify multiple type confusions in one function.
    /// Invariants: All type confusions must be detected.
    #[test]
    fn test_multiple_type_confusions() {
        let ir = r#"
            define void @test_multiple(i32 %value1, i64 %value2) {
            entry:
                %ptr = inttoptr i32 %value1 to i8*
                %truncated = trunc i64 %value2 to i32
                call void @ffi_process(i8* %ptr, i32 %truncated)
                ret void
            }
        "#;

        let detector = TypeConfusionDetector::new();
        let issues = detector.detect_issues(ir);

        assert!(
            issues.len() >= 2,
            "Must detect multiple type confusions, found {} issues",
            issues.len()
        );
    }

    /// Objective: Verify confidence levels are correctly assigned.
    /// Invariants: Conversions near FFI calls must have high confidence.
    #[test]
    fn test_confidence_levels() {
        let ir = r#"
            define void @test_confidence(i32 %value) {
            entry:
                %ptr = inttoptr i32 %value to i8*
                call void @ffi_process(i8* %ptr)
                ret void
            }
        "#;

        let detector = TypeConfusionDetector::new();
        let issues = detector.detect_issues(ir);

        assert!(!issues.is_empty(), "Must detect type confusion");

        let issue = &issues[0];
        assert_eq!(
            issue.confidence,
            ConfusionConfidence::High,
            "Must be high confidence near FFI call"
        );
    }

    /// Objective: Verify CWE ID for type confusion.
    /// Invariants: Must return CWE-843.
    #[test]
    fn test_type_confusion_cwe_id() {
        assert_eq!(
            type_confusion_cwe_id(),
            843,
            "Type confusion must map to CWE-843"
        );
    }

    /// Objective: Verify TypeConfusionDetector default settings.
    /// Invariants: Default detector must have all checks enabled.
    #[test]
    fn test_detector_default_settings() {
        let detector = TypeConfusionDetector::new();
        assert!(
            detector.check_signed_unsigned,
            "Default must check signed/unsigned confusion"
        );
        assert!(
            detector.check_pointer_integer,
            "Default must check pointer/integer confusion"
        );
        assert!(
            detector.check_float_integer,
            "Default must check float/integer confusion"
        );
        assert!(
            detector.check_width_mismatch,
            "Default must check type width mismatch"
        );
        assert!(
            detector.check_unsafe_bitcast,
            "Default must check unsafe bitcast"
        );
    }

    /// Objective: Verify TypeConfusionDetector with custom settings.
    /// Invariants: Custom settings must be respected.
    #[test]
    fn test_detector_custom_settings() {
        let detector = TypeConfusionDetector::with_settings(
            ConfusionConfidence::High,
            false, // disable signed/unsigned
            true,  // enable pointer/integer
            false, // disable float/integer
            true,  // enable width mismatch
            false, // disable unsafe bitcast
        );

        assert!(
            !detector.check_signed_unsigned,
            "Must respect custom signed/unsigned setting"
        );
        assert!(
            detector.check_pointer_integer,
            "Must respect custom pointer/integer setting"
        );
        assert!(
            !detector.check_float_integer,
            "Must respect custom float/integer setting"
        );
        assert!(
            detector.check_width_mismatch,
            "Must respect custom width mismatch setting"
        );
        assert!(
            !detector.check_unsafe_bitcast,
            "Must respect custom unsafe bitcast setting"
        );
    }

    /// Objective: Verify helper functions for type parsing.
    /// Invariants: Type parsing must handle common IR patterns.
    #[test]
    fn test_type_parsing_helpers() {
        // Test parse_extension_types
        let (src, tgt) = parse_extension_types("sext i32 %val to i64").unwrap();
        assert_eq!(src, "i32", "Source type must be i32");
        assert_eq!(tgt, "i64", "Target type must be i64");

        // Test parse_intptr_types
        let (int_type, ptr_type) = parse_intptr_types("inttoptr i32 %val to i8*", true).unwrap();
        assert_eq!(int_type, "i32", "Integer type must be i32");
        assert_eq!(ptr_type, "i8*", "Pointer type must be i8*");

        // Test parse_float_int_types
        let (float_type, int_type) = parse_float_int_types("sitofp i32 %val to float").unwrap();
        assert_eq!(float_type, "float", "Float type must be float");
        assert_eq!(int_type, "i32", "Integer type must be i32");
    }

    /// Objective: Verify type width calculation.
    /// Invariants: All standard types must have correct widths.
    #[test]
    fn test_type_width_calculation() {
        assert_eq!(get_type_width("i8"), Some(8), "i8 must be 8 bits");
        assert_eq!(get_type_width("i16"), Some(16), "i16 must be 16 bits");
        assert_eq!(get_type_width("i32"), Some(32), "i32 must be 32 bits");
        assert_eq!(get_type_width("i64"), Some(64), "i64 must be 64 bits");
        assert_eq!(get_type_width("float"), Some(32), "float must be 32 bits");
        assert_eq!(get_type_width("double"), Some(64), "double must be 64 bits");
        assert_eq!(get_type_width("ptr"), Some(64), "ptr must be 64 bits");
        assert_eq!(
            get_type_width("i8*"),
            Some(64),
            "i8* must be 64 bits (pointer)"
        );
    }

    /// Objective: Verify unsafe bitcast detection logic.
    /// Invariants: Pointer type changes must be detected as unsafe.
    #[test]
    fn test_unsafe_bitcast_detection() {
        assert!(
            is_unsafe_bitcast("i32*", "i8*"),
            "Different pointer types must be unsafe"
        );
        assert!(
            is_unsafe_bitcast("i32", "i8*"),
            "Integer to pointer must be unsafe"
        );
        assert!(
            is_unsafe_bitcast("i8*", "i32"),
            "Pointer to integer must be unsafe"
        );
        assert!(!is_unsafe_bitcast("i32", "i32"), "Same type must be safe");
        assert!(
            !is_unsafe_bitcast("i8*", "i8*"),
            "Same pointer type must be safe"
        );
    }

    /// Objective: Verify FFI type detection.
    /// Invariants: Common FFI types must be recognized.
    #[test]
    fn test_ffi_type_detection() {
        assert!(is_ffi_type("i32"), "i32 must be FFI type");
        assert!(is_ffi_type("i64"), "i64 must be FFI type");
        assert!(is_ffi_type("float"), "float must be FFI type");
        assert!(is_ffi_type("double"), "double must be FFI type");
        assert!(is_ffi_type("ptr"), "ptr must be FFI type");
        assert!(is_ffi_type("i8*"), "i8* must be FFI type");
        assert!(!is_ffi_type("i31"), "i31 must not be FFI type");
        assert!(!is_ffi_type("i128"), "i128 must not be FFI type");
    }

    /// Objective: Verify end-to-end type confusion detection.
    /// Invariants: Complete detection flow must work correctly.
    #[test]
    fn test_e2e_type_confusion_detection() {
        let ir = r#"
            define void @process_data(i32 %id, i64 %size, float %value) {
            entry:
                %id_ptr = inttoptr i32 %id to i8*
                %size32 = trunc i64 %size to i32
                %value_int = fptoui float %value to i32
                call void @ffi_process(i8* %id_ptr, i32 %size32, i32 %value_int)
                ret void
            }
        "#;

        let detector = TypeConfusionDetector::new();
        let issues = detector.detect_issues(ir);

        assert!(
            issues.len() >= 3,
            "Must detect all type confusions, found {} issues",
            issues.len()
        );

        // Check for different types of confusions
        let has_inttoptr = issues
            .iter()
            .any(|i| matches!(i.kind, TypeConfusionKind::PointerIntegerConfusion { .. }));
        let has_width_mismatch = issues
            .iter()
            .any(|i| matches!(i.kind, TypeConfusionKind::TypeWidthMismatch { .. }));
        let has_float_confusion = issues
            .iter()
            .any(|i| matches!(i.kind, TypeConfusionKind::FloatIntegerConfusion { .. }));

        assert!(has_inttoptr, "Must detect inttoptr confusion");
        assert!(has_width_mismatch, "Must detect width mismatch");
        assert!(has_float_confusion, "Must detect float/integer confusion");
    }
}
