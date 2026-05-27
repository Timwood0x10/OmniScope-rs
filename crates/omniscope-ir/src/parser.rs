//! LLVM IR text format parser
//!
//! Simple parser for LLVM IR textual representation (.ll files)

use std::collections::HashMap;
use std::path::Path;

/// Function in LLVM IR
#[derive(Debug, Clone)]
pub struct Function {
    /// Function name
    pub name: String,
    /// Is this a declaration (extern)?
    pub is_declaration: bool,
    /// Parameters (simplified)
    pub params: Vec<String>,
    /// Return type
    pub return_type: String,
}

/// Call instruction
#[derive(Debug, Clone)]
pub struct CallInstruction {
    /// Called function name
    pub callee: String,
    /// Caller function name
    pub caller: String,
    /// Is this an external call?
    pub is_external: bool,
    /// Source location (if available)
    pub location: Option<SourceLocation>,
}

/// Source code location
#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
}

/// Data layout information extracted from IR
#[derive(Debug, Clone)]
pub struct DataLayout {
    /// Target triple (e.g., "x86_64-apple-darwin")
    pub target_triple: Option<String>,
    /// Data layout string (e.g., "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128")
    pub data_layout: Option<String>,
    /// Pointer size in bits
    pub pointer_size: Option<u32>,
    /// Endianness (true = little, false = big)
    pub little_endian: Option<bool>,
}

/// Calling convention information
#[derive(Debug, Clone)]
pub struct CallingConvention {
    /// Convention name (e.g., "ccc", "fastcc", "webkit_jscc")
    pub name: String,
    /// Platform-specific convention
    pub platform_specific: bool,
}

/// Parsed LLVM IR module
#[derive(Debug, Clone)]
pub struct IRModule {
    /// Functions defined in this module
    pub functions: HashMap<String, Function>,
    /// External declarations
    pub declarations: HashMap<String, Function>,
    /// Call instructions
    pub calls: Vec<CallInstruction>,
    /// Data layout information
    pub data_layout: DataLayout,
    /// Calling conventions used in this module
    pub calling_conventions: Vec<CallingConvention>,
}

impl IRModule {
    /// Creates a new empty module
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            declarations: HashMap::new(),
            calls: Vec::new(),
            data_layout: DataLayout {
                target_triple: None,
                data_layout: None,
                pointer_size: None,
                little_endian: None,
            },
            calling_conventions: Vec::new(),
        }
    }

    /// Parse LLVM IR from text
    pub fn parse_from_text(content: &str) -> Self {
        let mut module = Self::new();
        let mut current_function = String::new();

        for line in content.lines() {
            let line = line.trim();

            // Parse module-level metadata
            if line.starts_with("target triple") {
                module.data_layout.target_triple = extract_target_triple(line);
            } else if line.starts_with("target datalayout") {
                module.data_layout.data_layout = extract_datalayout(line);
                module.parse_datalayout_info();
            }

            // Parse function declarations: declare ... @name(...)
            if line.starts_with("declare") {
                if let Some(func) = parse_declaration(line) {
                    module.declarations.insert(func.name.clone(), func);
                }
            }
            // Parse function definitions: define ... @name(...) {
            else if line.starts_with("define") {
                if let Some(func) = parse_definition(line) {
                    current_function = func.name.clone();
                    module.functions.insert(func.name.clone(), func);

                    // Extract calling convention
                    if let Some(conv_name) = extract_calling_convention(line) {
                        module.calling_conventions.push(CallingConvention {
                            name: conv_name,
                            platform_specific: true,
                        });
                    }
                }
            }
            // End of function
            else if line == "}" {
                current_function.clear();
            }
            // Parse call instructions: call ... @name(...)
            else if line.contains("call") {
                if let Some(call) = parse_call(line, &current_function) {
                    module.calls.push(call);
                }
            }
        }

        // Mark external calls
        for call in &mut module.calls {
            call.is_external = module.declarations.contains_key(&call.callee);
        }

        module
    }

    /// Load and parse from file (.ll or .bc)
    pub fn load_from_file(path: &Path) -> std::io::Result<Self> {
        tracing::info!("Loading IR from {:?}", path);
        let content = if path.extension().is_some_and(|ext| ext == "bc") {
            tracing::debug!("Converting .bc to .ll via llvm-dis");
            Self::convert_bc_to_ll(path)?
        } else {
            std::fs::read_to_string(path)?
        };
        let module = Self::parse_from_text(&content);
        tracing::info!(
            "IR loaded: {} functions, {} declarations, {} calls",
            module.functions.len(),
            module.declarations.len(),
            module.calls.len()
        );
        Ok(module)
    }

    /// Parse datalayout information to extract pointer size and endianness
    fn parse_datalayout_info(&mut self) {
        if let Some(ref layout) = self.data_layout.data_layout {
            // Parse endianness (first character: 'e' = little, 'E' = big)
            if let Some(first_char) = layout.chars().next() {
                self.data_layout.little_endian = Some(first_char == 'e');
            }

            // Parse pointer size (format: p:64:64 or p0:64:64)
            for part in layout.split('-') {
                if part.starts_with('p') {
                    // Extract pointer size from format like "p:64:64" or "p0:64:64"
                    let parts: Vec<&str> = part.split(':').collect();
                    if parts.len() >= 2 {
                        if let Ok(size) = parts[1].parse::<u32>() {
                            self.data_layout.pointer_size = Some(size);
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Convert .bc file to .ll text using llvm-dis
    fn convert_bc_to_ll(path: &Path) -> std::io::Result<String> {
        use std::process::Command;

        // Try multiple llvm-dis versions (newest first for best bitcode compat)
        let llvm_dis_candidates = [
            "/opt/homebrew/opt/llvm@22/bin/llvm-dis",
            "/opt/homebrew/opt/llvm@21/bin/llvm-dis",
            "/opt/homebrew/opt/llvm@20/bin/llvm-dis",
            "/opt/homebrew/opt/llvm@19/bin/llvm-dis",
            "/opt/homebrew/opt/llvm@18/bin/llvm-dis",
            "/opt/homebrew/opt/llvm@17/bin/llvm-dis",
            "llvm-dis", // fallback to PATH
        ];

        for llvm_dis in &llvm_dis_candidates {
            let output = Command::new(llvm_dis)
                .arg(path)
                .arg("-o")
                .arg("-") // Output to stdout
                .output();

            match output {
                Ok(output) if output.status.success() && !output.stdout.is_empty() => {
                    return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
                }
                _ => continue,
            }
        }

        // Fallback: try to read .ll file if it exists
        let ll_path = path.with_extension("ll");
        if ll_path.exists() {
            std::fs::read_to_string(&ll_path)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "Cannot convert {:?} to text IR. No compatible llvm-dis found.",
                    path
                ),
            ))
        }
    }

    /// Returns FFI boundaries (calls to external functions)
    pub fn ffi_boundaries(&self) -> Vec<&CallInstruction> {
        self.calls.iter().filter(|call| call.is_external).collect()
    }
}

impl Default for IRModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a function declaration
fn parse_declaration(line: &str) -> Option<Function> {
    // Format: declare ... @name(...)
    if !line.starts_with("declare") {
        return None;
    }

    // Extract function name
    if let Some(start) = line.find('@') {
        let rest = &line[start + 1..];
        if let Some(end) = rest.find('(') {
            let name = rest[..end].to_string();
            return Some(Function {
                name,
                is_declaration: true,
                params: Vec::new(),
                return_type: "unknown".to_string(),
            });
        }
    }

    None
}

/// Parse a function definition
fn parse_definition(line: &str) -> Option<Function> {
    // Format: define ... @name(...) {
    if !line.starts_with("define") {
        return None;
    }

    // Extract function name
    if let Some(start) = line.find('@') {
        let rest = &line[start + 1..];
        if let Some(end) = rest.find('(') {
            let name = rest[..end].to_string();
            return Some(Function {
                name,
                is_declaration: false,
                params: Vec::new(),
                return_type: "unknown".to_string(),
            });
        }
    }

    None
}

/// Parse a call instruction
fn parse_call(line: &str, current_function: &str) -> Option<CallInstruction> {
    // Format: ... call ... @name(...)
    if !line.contains("call") {
        return None;
    }

    // Find the call keyword
    let call_pos = line.find("call")?;
    let after_call = &line[call_pos..];

    // Extract callee name
    if let Some(start) = after_call.find('@') {
        let rest = &after_call[start + 1..];
        if let Some(end) = rest.find('(') {
            let callee = rest[..end].to_string();

            // Extract source location if present (!dbg !123)
            let location = extract_location(line);

            return Some(CallInstruction {
                callee,
                caller: current_function.to_string(),
                is_external: false,
                location,
            });
        }
    }

    None
}

/// Extract source location from metadata
fn extract_location(line: &str) -> Option<SourceLocation> {
    // Look for !dbg !N pattern
    if let Some(dbg_pos) = line.rfind("!dbg") {
        // In real implementation, we'd look up the metadata
        // For now, return None
        let _ = dbg_pos;
    }
    None
}

/// Extract target triple from IR line.
///
/// Format: target triple = "x86_64-apple-darwin"
fn extract_target_triple(line: &str) -> Option<String> {
    // Find the opening quote
    if let Some(start) = line.find('"') {
        // Find the closing quote
        if let Some(end) = line[start + 1..].find('"') {
            return Some(line[start + 1..start + 1 + end].to_string());
        }
    }
    None
}

/// Extract datalayout from IR line.
///
/// Format: target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
fn extract_datalayout(line: &str) -> Option<String> {
    // Find the opening quote
    if let Some(start) = line.find('"') {
        // Find the closing quote
        if let Some(end) = line[start + 1..].find('"') {
            return Some(line[start + 1..start + 1 + end].to_string());
        }
    }
    None
}

/// Extract calling convention from function definition.
///
/// Examples:
/// - "define void @foo()" -> None (default ccc)
/// - "define fastcc void @foo()" -> Some("fastcc")
/// - "define webkit_jscc void @foo()" -> Some("webkit_jscc")
fn extract_calling_convention(line: &str) -> Option<String> {
    // Common calling conventions
    let conventions = [
        "fastcc",
        "coldcc",
        "webkit_jscc",
        "anyregcc",
        "preserve_mostcc",
        "preserve_allcc",
        "swiftcc",
        "aarch64_sve_vector_pcs",
        "aarch64_vector_pcs",
        "amdgpu_kernel",
        "spir_kernel",
    ];

    for conv in &conventions {
        if line.contains(conv) {
            return Some(conv.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_declaration() {
        let line = "declare i32 @external_func(i32, i32)";
        let func = parse_declaration(line).unwrap();
        assert_eq!(func.name, "external_func");
        assert!(func.is_declaration);
    }

    #[test]
    fn test_parse_definition() {
        let line = "define i32 @my_func(i32 %x) {";
        let func = parse_definition(line).unwrap();
        assert_eq!(func.name, "my_func");
        assert!(!func.is_declaration);
    }

    #[test]
    fn test_parse_module() {
        let ir = r#"
            declare i32 @external_func(i32)
            
            define i32 @my_func(i32 %x) {
                %result = call i32 @external_func(i32 %x)
                ret i32 %result
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        assert_eq!(module.declarations.len(), 1);
        assert_eq!(module.functions.len(), 1);
        assert_eq!(module.calls.len(), 1);
    }
}
