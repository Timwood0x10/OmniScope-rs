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
}

impl IRModule {
    /// Creates a new empty module
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            declarations: HashMap::new(),
            calls: Vec::new(),
        }
    }

    /// Parse LLVM IR from text
    pub fn parse_from_text(content: &str) -> Self {
        let mut module = Self::new();

        for line in content.lines() {
            let line = line.trim();

            // Parse function declarations: declare ... @name(...)
            if line.starts_with("declare") {
                if let Some(func) = parse_declaration(line) {
                    module.declarations.insert(func.name.clone(), func);
                }
            }

            // Parse function definitions: define ... @name(...) {
            else if line.starts_with("define") {
                if let Some(func) = parse_definition(line) {
                    module.functions.insert(func.name.clone(), func);
                }
            }

            // Parse call instructions: call ... @name(...)
            else if line.contains("call") {
                if let Some(call) = parse_call(line, &module.functions) {
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

    /// Load and parse from file
    pub fn load_from_file(path: &Path) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::parse_from_text(&content))
    }

    /// Returns FFI boundaries (calls to external functions)
    pub fn ffi_boundaries(&self) -> Vec<&CallInstruction> {
        self.calls
            .iter()
            .filter(|call| call.is_external)
            .collect()
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
fn parse_call(line: &str, _functions: &HashMap<String, Function>) -> Option<CallInstruction> {
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

            // Note: We don't know the caller here, would need context
            return Some(CallInstruction {
                callee,
                caller: "unknown".to_string(),
                is_external: false,
            });
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
