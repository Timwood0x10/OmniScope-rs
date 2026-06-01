//! Length truncation detector for FFI safety analysis.
//!
//! This module detects length/size truncation issues across FFI boundaries,
//! such as:
//! - `usize` (64-bit) → `uint32_t` (32-bit) truncation
//! - `size_t` (64-bit) → `int` (32-bit) truncation
//! - Array length truncation
//! - Cross-language type width mismatches
//!
//! # Detection Strategy
//!
//! The detector analyzes IR instructions for truncation operations (`trunc`)
//! that involve size/length parameters. It identifies when a 64-bit value
//! (typically from Rust or 64-bit systems) is truncated to 32-bit or smaller
//! for use in C/C++ or other FFI boundaries.
//!
//! ## Key Patterns
//!
//! 1. **Direct truncation**: `trunc i64 %size to i32` before FFI call
//! 2. **Indirect truncation**: Truncation through multiple steps
//! 3. **Implicit truncation**: Truncation via function call parameters
//!
//! ## Example
//!
//! ```rust,ignore
//! // Rust code with potential truncation
//! extern "C" {
//!     fn process_buffer(data: *const u8, len: u32); // C expects u32
//! }
//!
//! let len: usize = some_length; // Rust usize is 64-bit
//! unsafe { process_buffer(ptr, len as u32); } // Truncation!
//! ```

use omniscope_ir::{FunctionBody, IRInstruction, IRInstructionKind};

/// Type width information for truncation detection.
///
/// Represents the bit width of a type involved in truncation operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeWidth {
    /// 64-bit type (usize, size_t, u64, i64)
    Bits64,
    /// 32-bit type (uint32_t, u32, i32, int)
    Bits32,
    /// 16-bit type (uint16_t, u16, i16)
    Bits16,
    /// 8-bit type (uint8_t, u8, i8)
    Bits8,
    /// Unknown width
    Unknown,
}

impl TypeWidth {
    /// Returns the bit width as a number.
    pub fn bits(&self) -> Option<u32> {
        match self {
            TypeWidth::Bits64 => Some(64),
            TypeWidth::Bits32 => Some(32),
            TypeWidth::Bits16 => Some(16),
            TypeWidth::Bits8 => Some(8),
            TypeWidth::Unknown => None,
        }
    }

    /// Returns true if this width can safely hold a value from `source_width`.
    pub fn can_hold(&self, source_width: &TypeWidth) -> bool {
        match (self.bits(), source_width.bits()) {
            (Some(target), Some(source)) => target >= source,
            _ => false,
        }
    }

    /// Create TypeWidth from bit count.
    pub fn from_bits(bits: u32) -> Self {
        match bits {
            64 => TypeWidth::Bits64,
            32 => TypeWidth::Bits32,
            16 => TypeWidth::Bits16,
            8 => TypeWidth::Bits8,
            _ => TypeWidth::Unknown,
        }
    }
}

/// Truncation pattern detected in IR.
///
/// Represents a potential length/size truncation issue found in the code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruncationPattern {
    /// Source type width (before truncation).
    pub source_width: TypeWidth,
    /// Target type width (after truncation).
    pub target_width: TypeWidth,
    /// The register being truncated.
    pub truncated_register: String,
    /// Whether this truncation occurs near an FFI call.
    pub near_ffi_call: bool,
    /// The FFI function name (if near FFI call).
    pub ffi_function: Option<String>,
    /// Confidence level of the detection.
    pub confidence: TruncationConfidence,
    /// Additional risk factors detected.
    pub risk_factors: Vec<TruncationRisk>,
}

/// Confidence level for truncation detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TruncationConfidence {
    /// High confidence: explicit truncation before FFI call.
    High,
    /// Medium confidence: truncation in function that calls FFI.
    Medium,
    /// Low confidence: truncation without clear FFI context.
    Low,
}

/// Risk factors for truncation patterns.
///
/// These represent additional issues that may be present in a truncation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TruncationRisk {
    /// Signed/unsigned conversion: truncation followed by sign extension or zero extension.
    SignedUnsignedConversion,
    /// Missing range check: no bounds checking before truncation.
    MissingRangeCheck,
    /// Boundary condition: truncation result used in boundary comparison.
    BoundaryCondition,
    /// Potential overflow: truncation to smaller type without validation.
    PotentialOverflow,
}

/// Result of length truncation analysis.
///
/// Contains all truncation patterns detected in a function body.
#[derive(Debug, Clone)]
pub struct TruncationAnalysis {
    /// Function name.
    pub function_name: String,
    /// Detected truncation patterns.
    pub patterns: Vec<TruncationPattern>,
    /// Whether any FFI calls are present.
    pub has_ffi_calls: bool,
    /// Number of truncation instructions analyzed.
    pub truncation_count: usize,
}

/// Extract truncation patterns from a function body.
///
/// This is the main entry point for length truncation detection.
/// It analyzes all truncation instructions in the function body
/// and identifies those that may cause length/size truncation issues.
///
/// # Arguments
///
/// * `body` - The function body to analyze.
///
/// # Returns
///
/// A `TruncationAnalysis` containing all detected truncation patterns.
pub fn extract_truncation_patterns(body: &FunctionBody) -> TruncationAnalysis {
    let truncation_insts: Vec<&IRInstruction> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::Conversion && i.raw_text.contains("trunc"))
        .collect();

    let truncation_count = truncation_insts.len();
    let mut patterns = Vec::new();

    // Collect FFI call information
    let ffi_calls = collect_ffi_calls(body);
    let has_ffi_calls = !ffi_calls.is_empty();

    // Analyze each truncation instruction
    for inst in &truncation_insts {
        if let Some(pattern) = analyze_truncation(inst, &ffi_calls, body) {
            patterns.push(pattern);
        }
    }

    TruncationAnalysis {
        function_name: body.name.clone(),
        patterns,
        has_ffi_calls,
        truncation_count,
    }
}

/// Collect FFI calls from function body.
///
/// Returns a list of (function_name, instruction_index) pairs for
/// calls to external functions.
fn collect_ffi_calls(body: &FunctionBody) -> Vec<(String, usize)> {
    let mut ffi_calls = Vec::new();

    for (idx, inst) in body.instructions.iter().enumerate() {
        if inst.kind == IRInstructionKind::Call || inst.kind == IRInstructionKind::IndirectCall {
            if let Some(ref callee) = inst.callee {
                // Check if this is an external call (FFI boundary)
                if is_external_function(callee) {
                    ffi_calls.push((callee.clone(), idx));
                }
            }
        }
    }

    ffi_calls
}

/// Check if a function name indicates an external (FFI) function.
///
/// This checks for common patterns that indicate FFI boundaries:
/// - C library functions (malloc, free, etc.)
/// - Functions without Rust mangling
/// - Functions with C-style naming
pub(crate) fn is_external_function(name: &str) -> bool {
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

    // Check for Rust mangled names (not FFI)
    if name.starts_with("_ZN") || name.starts_with("_R") {
        return false;
    }

    // Check for C++ mangled names
    if name.starts_with("_Z") {
        return true;
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
    // (no namespace, no special characters except underscore)
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

/// Analyze a single truncation instruction for length truncation issues.
///
/// Returns a `TruncationPattern` if the truncation involves size/length types.
fn analyze_truncation(
    inst: &IRInstruction,
    ffi_calls: &[(String, usize)],
    body: &FunctionBody,
) -> Option<TruncationPattern> {
    let raw = &inst.raw_text;

    // Parse truncation instruction: trunc i64 %size to i32
    let (source_width, target_width) = parse_truncation_widths(raw)?;

    // Check if this is a size/length type truncation
    // We focus on 64->32 bit truncations which are most common
    if !is_size_truncation(source_width, target_width) {
        return None;
    }

    // Extract the register being truncated
    let truncated_register = extract_truncated_register(raw)?;

    // Check if this truncation is near an FFI call
    let (near_ffi_call, ffi_function) = check_ffi_proximity(inst, ffi_calls, body);

    // Determine confidence level
    let confidence = if near_ffi_call {
        TruncationConfidence::High
    } else if !ffi_calls.is_empty() {
        TruncationConfidence::Medium
    } else {
        TruncationConfidence::Low
    };

    // Detect risk factors
    let risk_factors = detect_risk_factors(inst, body, source_width, target_width);

    Some(TruncationPattern {
        source_width,
        target_width,
        truncated_register,
        near_ffi_call,
        ffi_function,
        confidence,
        risk_factors,
    })
}

/// Parse source and target widths from a truncation instruction.
///
/// Example: "trunc i64 %size to i32" -> (Bits64, Bits32)
pub(crate) fn parse_truncation_widths(raw: &str) -> Option<(TypeWidth, TypeWidth)> {
    // Look for pattern: trunc iNN ... to iMM
    let trunc_pos = raw.find("trunc")?;
    let after_trunc = &raw[trunc_pos..];

    // Find source type: iNN
    let source_type = after_trunc
        .split_whitespace()
        .find(|s| s.starts_with('i') && s[1..].chars().all(|c| c.is_ascii_digit()))?;

    // Find target type: to iMM
    let to_pos = after_trunc.find(" to ")?;
    let after_to = &after_trunc[to_pos + 4..];
    let target_type = after_to
        .split_whitespace()
        .find(|s| s.starts_with('i') && s[1..].chars().all(|c| c.is_ascii_digit()))?;

    let source_bits = source_type[1..].parse::<u32>().ok()?;
    let target_bits = target_type[1..].parse::<u32>().ok()?;

    Some((
        TypeWidth::from_bits(source_bits),
        TypeWidth::from_bits(target_bits),
    ))
}

/// Check if a truncation is likely a size/length truncation.
///
/// We focus on:
/// - 64-bit to 32-bit (most common: usize -> uint32_t)
/// - 64-bit to 16-bit (size_t -> uint16_t)
/// - 32-bit to 16-bit (uint32_t -> uint16_t)
fn is_size_truncation(source: TypeWidth, target: TypeWidth) -> bool {
    matches!(
        (source, target),
        (TypeWidth::Bits64, TypeWidth::Bits32)
            | (TypeWidth::Bits64, TypeWidth::Bits16)
            | (TypeWidth::Bits64, TypeWidth::Bits8)
            | (TypeWidth::Bits32, TypeWidth::Bits16)
            | (TypeWidth::Bits32, TypeWidth::Bits8)
    )
}

/// Extract the register name being truncated.
///
/// Example: "trunc i64 %size to i32" -> "%size"
pub(crate) fn extract_truncated_register(raw: &str) -> Option<String> {
    let trunc_pos = raw.find("trunc")?;
    let after_trunc = &raw[trunc_pos..];

    // Find the register: starts with % and contains alphanumeric/underscore/dot
    let parts: Vec<&str> = after_trunc.split_whitespace().collect();
    for part in &parts {
        if part.starts_with('%') || part.starts_with('@') {
            // Clean up any trailing characters
            let clean = part.trim_end_matches([',', ')', ']']);
            return Some(clean.to_string());
        }
    }

    None
}

/// Check if a truncation instruction is near an FFI call.
///
/// Returns (is_near, ffi_function_name) tuple.
fn check_ffi_proximity(
    trunc_inst: &IRInstruction,
    ffi_calls: &[(String, usize)],
    body: &FunctionBody,
) -> (bool, Option<String>) {
    // Find the index of the truncation instruction
    let trunc_idx = body
        .instructions
        .iter()
        .position(|i| std::ptr::eq(i, trunc_inst));

    if let Some(trunc_idx) = trunc_idx {
        // Check if any FFI call is within 5 instructions
        for (ffi_name, ffi_idx) in ffi_calls {
            let distance = if *ffi_idx > trunc_idx {
                ffi_idx - trunc_idx
            } else {
                trunc_idx - ffi_idx
            };

            if distance <= 5 {
                return (true, Some(ffi_name.clone()));
            }
        }
    }

    (false, None)
}

/// Detect risk factors for a truncation instruction.
///
/// This function analyzes the context around a truncation instruction to identify
/// additional risk factors such as:
/// - Signed/unsigned conversion
/// - Missing range checks
/// - Boundary conditions
/// - Potential overflow
fn detect_risk_factors(
    inst: &IRInstruction,
    body: &FunctionBody,
    source_width: TypeWidth,
    target_width: TypeWidth,
) -> Vec<TruncationRisk> {
    let mut risks = Vec::new();

    // Find the index of the truncation instruction
    let trunc_idx = body.instructions.iter().position(|i| std::ptr::eq(i, inst));

    if let Some(trunc_idx) = trunc_idx {
        // Check for signed/unsigned conversion
        if check_signed_unsigned_conversion(inst, body, trunc_idx) {
            risks.push(TruncationRisk::SignedUnsignedConversion);
        }

        // Check for missing range check
        if check_missing_range_check(body, trunc_idx, source_width, target_width) {
            risks.push(TruncationRisk::MissingRangeCheck);
        }

        // Check for boundary condition
        if check_boundary_condition(body, trunc_idx) {
            risks.push(TruncationRisk::BoundaryCondition);
        }

        // Check for potential overflow
        if check_potential_overflow(body, trunc_idx, source_width, target_width) {
            risks.push(TruncationRisk::PotentialOverflow);
        }
    }

    risks
}

/// Check for signed/unsigned conversion after truncation.
///
/// Looks for sext (sign extension) or zext (zero extension) operations
/// that follow the truncation, indicating signed/unsigned conversion.
fn check_signed_unsigned_conversion(
    _inst: &IRInstruction,
    body: &FunctionBody,
    trunc_idx: usize,
) -> bool {
    // Look for sext or zext within 5 instructions after truncation
    let search_range = std::cmp::min(trunc_idx + 6, body.instructions.len());
    for i in (trunc_idx + 1)..search_range {
        let next_inst = &body.instructions[i];
        let next_raw = &next_inst.raw_text;

        // Check for sign extension or zero extension
        if next_raw.contains("sext") || next_raw.contains("zext") {
            return true;
        }
    }

    false
}

/// Check for missing range check before truncation.
///
/// Looks for comparison instructions (icmp) that validate the value
/// before truncation to ensure it fits in the target type.
fn check_missing_range_check(
    body: &FunctionBody,
    trunc_idx: usize,
    _source_width: TypeWidth,
    target_width: TypeWidth,
) -> bool {
    // Look for icmp instructions within 10 instructions before truncation
    let search_start = trunc_idx.saturating_sub(10);
    let mut found_range_check = false;

    for i in search_start..trunc_idx {
        let prev_inst = &body.instructions[i];
        let prev_raw = &prev_inst.raw_text;

        // Check for comparison instruction
        if prev_raw.contains("icmp") {
            // Check if it's a range check (comparing against target max value)
            if let Some(target_bits) = target_width.bits() {
                let max_value = (1u64 << target_bits) - 1;
                let max_value_str = max_value.to_string();

                // Check if comparison is against max value or similar
                if prev_raw.contains(&max_value_str)
                    || prev_raw.contains("ult") // Unsigned less than
                    || prev_raw.contains("ule")
                // Unsigned less or equal
                {
                    found_range_check = true;
                    break;
                }
            }
        }
    }

    // If no range check found, this is a risk
    !found_range_check
}

/// Check for boundary condition after truncation.
///
/// Looks for comparison instructions that use the truncated value
/// for boundary checking.
fn check_boundary_condition(body: &FunctionBody, trunc_idx: usize) -> bool {
    // Look for icmp instructions within 5 instructions after truncation
    let search_range = std::cmp::min(trunc_idx + 6, body.instructions.len());
    for i in (trunc_idx + 1)..search_range {
        let next_inst = &body.instructions[i];
        let next_raw = &next_inst.raw_text;

        // Check for comparison instruction
        if next_raw.contains("icmp") {
            return true;
        }
    }

    false
}

/// Check for potential overflow in truncation.
///
/// This checks if the truncation could cause overflow based on the
/// source and target widths.
fn check_potential_overflow(
    body: &FunctionBody,
    trunc_idx: usize,
    source_width: TypeWidth,
    target_width: TypeWidth,
) -> bool {
    // If source is larger than target, there's potential for overflow
    if let (Some(source_bits), Some(target_bits)) = (source_width.bits(), target_width.bits()) {
        if source_bits > target_bits {
            // Check if there's any validation before truncation
            let search_start = trunc_idx.saturating_sub(10);
            let mut found_validation = false;

            for i in search_start..trunc_idx {
                let prev_inst = &body.instructions[i];
                let prev_raw = &prev_inst.raw_text;

                // Check for validation instructions
                if prev_raw.contains("icmp") || 
                   prev_raw.contains("br") || // Branch instruction
                   prev_raw.contains("switch")
                // Switch instruction
                {
                    found_validation = true;
                    break;
                }
            }

            return !found_validation;
        }
    }

    false
}

/// Get a human-readable description of a truncation pattern.
pub fn describe_truncation(pattern: &TruncationPattern) -> String {
    let source_bits = pattern
        .source_width
        .bits()
        .map(|b| format!("{}-bit", b))
        .unwrap_or_else(|| "unknown".to_string());

    let target_bits = pattern
        .target_width
        .bits()
        .map(|b| format!("{}-bit", b))
        .unwrap_or_else(|| "unknown".to_string());

    let mut description = if let Some(ref ffi_func) = pattern.ffi_function {
        format!(
            "Length truncation: {} {} -> {} near FFI call to '{}'",
            pattern.truncated_register, source_bits, target_bits, ffi_func
        )
    } else {
        format!(
            "Length truncation: {} {} -> {}",
            pattern.truncated_register, source_bits, target_bits
        )
    };

    // Add risk factors to description
    if !pattern.risk_factors.is_empty() {
        let risk_descriptions: Vec<String> = pattern
            .risk_factors
            .iter()
            .map(|risk| match risk {
                TruncationRisk::SignedUnsignedConversion => {
                    "signed/unsigned conversion".to_string()
                }
                TruncationRisk::MissingRangeCheck => "missing range check".to_string(),
                TruncationRisk::BoundaryCondition => "boundary condition".to_string(),
                TruncationRisk::PotentialOverflow => "potential overflow".to_string(),
            })
            .collect();

        description.push_str(&format!(" [{}]", risk_descriptions.join(", ")));
    }

    description
}

/// Get the CWE ID for length truncation issues.
pub fn truncation_cwe_id() -> u32 {
    197 // CWE-197: Numeric Truncation Error
}
