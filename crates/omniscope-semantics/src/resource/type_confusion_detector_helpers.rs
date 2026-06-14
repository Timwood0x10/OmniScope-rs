//! Helper functions for type confusion detector.
//!
//! This module contains internal helper functions used by TypeConfusionDetector
//! for FFI call collection, type parsing, and struct size estimation.
//! All functions are `pub(crate)` to allow access from tests.

use omniscope_ir::{FunctionBody, IRInstruction, IRInstructionKind};

/// Collect FFI calls from function body.
pub(crate) fn collect_ffi_calls(body: &FunctionBody) -> Vec<(String, usize)> {
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
        && !name.contains('<')
        && !name.contains('>')
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
    {
        return true;
    }

    false
}

/// Check if a conversion instruction is near an FFI call.
///
/// Uses pointer comparison to find the instruction index instead of
/// comparing raw_text strings, avoiding the need for ensure_raw().
pub(crate) fn check_ffi_proximity(
    inst: &IRInstruction,
    ffi_calls: &[(String, usize)],
    body: &FunctionBody,
) -> (bool, Option<String>) {
    let conv_idx = body.instructions.iter().position(|i| std::ptr::eq(i, inst));

    if let Some(conv_idx) = conv_idx {
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
pub(crate) fn parse_extension_types(raw: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = raw.split_whitespace().collect();
    let keyword_idx = parts
        .iter()
        .position(|&p| p == "sext" || p == "zext" || p == "trunc")?;

    if keyword_idx + 1 >= parts.len() {
        return None;
    }
    let source_type = parts[keyword_idx + 1].to_string();

    let to_idx = parts.iter().position(|&p| p == "to")?;
    if to_idx + 1 >= parts.len() {
        return None;
    }
    let target_type = parts[to_idx + 1]
        .trim_end_matches([',', ')', ']'])
        .to_string();

    Some((source_type, target_type))
}

/// Parse integer and pointer types from inttoptr/ptrtoint instruction.
pub(crate) fn parse_intptr_types(raw: &str, is_inttoptr: bool) -> Option<(String, String)> {
    let parts: Vec<&str> = raw.split_whitespace().collect();
    let keyword_idx = parts
        .iter()
        .position(|&p| p == "inttoptr" || p == "ptrtoint")?;

    if keyword_idx + 1 >= parts.len() {
        return None;
    }
    let first_type = parts[keyword_idx + 1].to_string();

    let to_idx = parts.iter().position(|&p| p == "to")?;
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
pub(crate) fn parse_float_int_types(raw: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = raw.split_whitespace().collect();
    let keyword_idx = parts
        .iter()
        .position(|&p| p == "sitofp" || p == "uitofp" || p == "fptosi" || p == "fptoui")?;

    if keyword_idx + 1 >= parts.len() {
        return None;
    }
    let first_type = parts[keyword_idx + 1].to_string();

    let to_idx = parts.iter().position(|&p| p == "to")?;
    if to_idx + 1 >= parts.len() {
        return None;
    }
    let second_type = parts[to_idx + 1]
        .trim_end_matches([',', ')', ']'])
        .to_string();

    let is_first_float = is_float_type(&first_type);
    let is_second_float = is_float_type(&second_type);

    if is_first_float && !is_second_float {
        Some((first_type, second_type))
    } else if !is_first_float && is_second_float {
        Some((second_type, first_type))
    } else {
        None
    }
}

/// Parse source and target types from bitcast instruction.
pub(crate) fn parse_bitcast_types(raw: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = raw.split_whitespace().collect();
    let keyword_idx = parts.iter().position(|&p| p == "bitcast")?;

    if keyword_idx + 1 >= parts.len() {
        return None;
    }
    let source_type = parts[keyword_idx + 1].to_string();

    let to_idx = parts.iter().position(|&p| p == "to")?;
    if to_idx + 1 >= parts.len() {
        return None;
    }
    let target_type = parts[to_idx + 1]
        .trim_end_matches([',', ')', ']'])
        .to_string();

    Some((source_type, target_type))
}

/// Get bit width from type string.
pub(crate) fn get_type_width(type_str: &str) -> Option<u32> {
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
            if type_str.ends_with('*') || type_str == "ptr" {
                Some(64)
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
pub(crate) fn is_ffi_type(type_str: &str) -> bool {
    matches!(
        type_str,
        "i32" | "i64" | "i16" | "i8" | "float" | "double" | "ptr" | "i8*"
    )
}

/// Check if a bitcast is potentially unsafe.
pub(crate) fn is_unsafe_bitcast(source: &str, target: &str) -> bool {
    let source_is_ptr = source.ends_with('*') || source == "ptr";
    let target_is_ptr = target.ends_with('*') || target == "ptr";

    if source_is_ptr != target_is_ptr {
        return true;
    }

    if source_is_ptr && target_is_ptr && source != target {
        return true;
    }

    let source_is_int = source.starts_with('i') && source[1..].chars().all(|c| c.is_ascii_digit());
    let target_is_int = target.starts_with('i') && target[1..].chars().all(|c| c.is_ascii_digit());

    if (source_is_int && target_is_ptr) || (source_is_ptr && target_is_int) {
        return true;
    }

    false
}

/// Estimate the size of a struct type from its LLVM IR type name.
pub(crate) fn estimate_struct_size(type_str: &str) -> Option<u64> {
    let inner = type_str.trim_end_matches('*').trim();

    if let Some(size) = parse_anonymous_struct_size(inner) {
        return Some(size);
    }

    let cleaned = inner.trim_start_matches('%');

    if let Some(size) = estimate_named_struct_size(cleaned) {
        return Some(size);
    }

    None
}

/// Parse an anonymous struct literal like `{ i64, i64 }` or `{ i32, i32, i8 }`.
fn parse_anonymous_struct_type(type_str: &str) -> Option<Vec<String>> {
    let trimmed = type_str.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return None;
    }
    let inner = trimmed[1..trimmed.len() - 1].trim();
    if inner.is_empty() {
        return None;
    }
    let fields: Vec<String> = inner.split(',').map(|s| s.trim().to_string()).collect();
    Some(fields)
}

/// Calculate total byte size from parsed anonymous struct fields.
pub(crate) fn parse_anonymous_struct_size(type_str: &str) -> Option<u64> {
    let fields = parse_anonymous_struct_type(type_str)?;
    let mut total_bits: u64 = 0;
    for field in &fields {
        let width = get_type_width(field)?;
        total_bits += width as u64;
    }
    Some(total_bits.div_ceil(8))
}

/// Estimate struct size from named struct types using common conventions.
pub(crate) fn estimate_named_struct_size(struct_name: &str) -> Option<u64> {
    // C-style small structs checked FIRST (before generic Config)
    if struct_name.starts_with("C")
        || struct_name.starts_with("c_")
        || struct_name == "CConfig"
        || struct_name == "c_config"
    {
        return Some(8);
    }

    // Config structs (often {u64,u64} = 16 bytes)
    if struct_name.contains("Config") || struct_name.contains("config") {
        return Some(16);
    }

    // Info/Desc structs are typically larger
    if struct_name.contains("Info")
        || struct_name.contains("Desc")
        || struct_name.contains("Descriptor")
    {
        return Some(24);
    }

    // State/Context structs
    if struct_name.contains("State") || struct_name.contains("Context") {
        return Some(32);
    }

    // Buffer/Header structs
    if struct_name.contains("Buffer") || struct_name.contains("Header") {
        return Some(16);
    }

    // Default assumption for unknown named structs
    if struct_name.starts_with("struct.") || struct_name.starts_with("class.") {
        return Some(16);
    }

    None
}

/// Check if an instruction's opcode matches the given string.
pub(crate) fn next_op_matches(inst: &IRInstruction, expected: &str) -> bool {
    inst.conversion_opcode.as_deref() == Some(expected) || inst.raw_text.starts_with(expected)
}
