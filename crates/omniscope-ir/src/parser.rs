//! LLVM IR text format parser
//!
//! Simple parser for LLVM IR textual representation (.ll files).
//! This module handles module-level parsing (declarations, definitions,
//! data layout) and delegates instruction-level parsing to the
//! [`instruction_parser`] submodule.

use std::collections::HashMap;
use std::path::Path;

// Re-export instruction-level types so that external consumers can still
// access them via `omniscope_ir::IRInstructionKind` etc.
pub use crate::instruction_parser::{IRInstruction, IRInstructionKind};
use crate::location::SourceLocation;

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
}

/// Function body with extracted instruction stream.
///
/// Represents the body of a defined function (not a declaration) with
/// all instructions parsed into structured form. This is the foundation
/// for semantic derivation: we analyze instruction sequences to derive
/// behavior patterns without relying on function names.
#[derive(Debug, Clone)]
pub struct FunctionBody {
    /// Function name
    pub name: String,
    /// Instructions in program order (across all basic blocks)
    pub instructions: Vec<IRInstruction>,
}

impl FunctionBody {
    /// Returns the number of instructions of a given kind.
    pub fn count_kind(&self, kind: IRInstructionKind) -> usize {
        self.instructions.iter().filter(|i| i.kind == kind).count()
    }

    /// Returns all instructions of a given kind.
    pub fn instructions_of_kind(&self, kind: IRInstructionKind) -> Vec<&IRInstruction> {
        self.instructions
            .iter()
            .filter(|i| i.kind == kind)
            .collect()
    }

    /// Returns the return instruction, if any.
    pub fn ret_instruction(&self) -> Option<&IRInstruction> {
        self.instructions
            .iter()
            .find(|i| i.kind == IRInstructionKind::Ret)
    }

    /// Returns all call instructions in this function body (both direct and indirect).
    pub fn call_instructions(&self) -> Vec<&IRInstruction> {
        self.instructions
            .iter()
            .filter(|i| {
                i.kind == IRInstructionKind::Call || i.kind == IRInstructionKind::IndirectCall
            })
            .collect()
    }

    /// Returns all atomicrmw instructions with a specific operation.
    pub fn atomic_rmw_with_op(&self, op: &str) -> Vec<&IRInstruction> {
        self.instructions
            .iter()
            .filter(|i| {
                i.kind == IRInstructionKind::AtomicRmw && i.atomic_op.as_deref() == Some(op)
            })
            .collect()
    }
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
    /// Function bodies with instruction-level detail (for defined functions)
    pub function_bodies: HashMap<String, FunctionBody>,
    /// Data layout information
    pub data_layout: DataLayout,
    /// Calling conventions used in this module
    pub calling_conventions: Vec<CallingConvention>,
    /// Debug metadata: maps metadata ID (e.g., "123" from !123) to source location.
    pub debug_metadata: HashMap<String, SourceLocation>,
}

impl IRModule {
    /// Creates a new empty module
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            declarations: HashMap::new(),
            calls: Vec::new(),
            function_bodies: HashMap::new(),
            data_layout: DataLayout {
                target_triple: None,
                data_layout: None,
                pointer_size: None,
                little_endian: None,
            },
            calling_conventions: Vec::new(),
            debug_metadata: HashMap::new(),
        }
    }

    /// Parse LLVM IR from text
    pub fn parse_from_text(content: &str) -> Self {
        let mut module = Self::new();
        let mut current_function = String::new();
        let mut current_instructions: Vec<IRInstruction> = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Parse module-level metadata
            if line.starts_with("target triple") {
                module.data_layout.target_triple = extract_target_triple(line);
            } else if line.starts_with("target datalayout") {
                module.data_layout.data_layout = extract_datalayout(line);
                module.parse_datalayout_info();
            }

            // Collect debug metadata definitions: !N = !DILocation(...)
            if line.starts_with('!') {
                if let Some((id, loc)) = parse_debug_metadata(line) {
                    module.debug_metadata.insert(id, loc);
                }
                // Skip other metadata lines inside function bodies
                if !current_function.is_empty() {
                    continue;
                }
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
                    // Save previous function's body if any
                    if !current_function.is_empty() && !current_instructions.is_empty() {
                        let body = FunctionBody {
                            name: current_function.clone(),
                            instructions: std::mem::take(&mut current_instructions),
                        };
                        module
                            .function_bodies
                            .insert(current_function.clone(), body);
                    }
                    current_function = func.name.clone();
                    current_instructions.clear();
                    module.functions.insert(func.name.clone(), func);

                    // Extract calling convention
                    if let Some(conv_name) = extract_calling_convention(line) {
                        module
                            .calling_conventions
                            .push(CallingConvention { name: conv_name });
                    }
                }
            }
            // End of function
            else if line == "}" {
                if !current_function.is_empty() && !current_instructions.is_empty() {
                    let body = FunctionBody {
                        name: current_function.clone(),
                        instructions: std::mem::take(&mut current_instructions),
                    };
                    module
                        .function_bodies
                        .insert(current_function.clone(), body);
                }
                current_function.clear();
                current_instructions.clear();
            }
            // Parse instructions inside function body
            else if !current_function.is_empty() && !line.is_empty() {
                // Skip labels (including labels with trailing metadata like "entry: !dbg !123"),
                // and comments. Metadata lines (!) are handled above.
                if line.starts_with(';') || is_label_line(line) {
                    continue;
                }

                // Parse instruction-level detail
                if let Some(inst) = crate::instruction_parser::parse_instruction(line) {
                    // Extract call instructions for backward compatibility
                    // Both direct and indirect calls are recorded to module.calls.
                    match inst.kind {
                        IRInstructionKind::Call => {
                            if let Some(call) =
                                parse_call(line, &current_function, &module.debug_metadata)
                            {
                                module.calls.push(call);
                            }
                        }
                        IRInstructionKind::IndirectCall => {
                            // Indirect calls: use callee register name or "indirect"
                            // as the callee identifier so downstream analysis can
                            // discover them.
                            let callee_name = inst
                                .callee
                                .clone()
                                .unwrap_or_else(|| "indirect".to_string());
                            module.calls.push(CallInstruction {
                                callee: callee_name,
                                caller: current_function.clone(),
                                is_external: false,
                                location: extract_location(line, &module.debug_metadata),
                            });
                        }
                        _ => {}
                    }
                    current_instructions.push(inst);
                }
            }
            // Top-level call (outside any function body — malformed/truncated IR)
            // Record with a sentinel caller name so downstream analysis can
            // discover these calls rather than silently dropping them.
            else if line.contains("call") && current_function.is_empty() {
                let caller_tag = "<top-level>";
                if let Some(call) = parse_call(line, caller_tag, &module.debug_metadata) {
                    module.calls.push(call);
                }
            }
        }

        // Flush any remaining function body when file is truncated (no closing '}')
        if !current_function.is_empty() && !current_instructions.is_empty() {
            let body = FunctionBody {
                name: current_function.clone(),
                instructions: std::mem::take(&mut current_instructions),
            };
            module.function_bodies.insert(current_function, body);
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

    /// Parse datalayout information to extract pointer size and endianness.
    ///
    /// This is also called from [`crate::ir_model`] during model-to-module
    /// conversion so that pointer size and endianness are derived from the
    /// data layout string populated by the C++ pass.
    pub(crate) fn parse_datalayout_info(&mut self) {
        if let Some(ref layout) = self.data_layout.data_layout {
            // Parse endianness (first character: 'e' = little, 'E' = big)
            if let Some(first_char) = layout.chars().next() {
                self.data_layout.little_endian = Some(first_char == 'e');
            }

            // Parse pointer size for the default address space (0).
            // Format: "p:64:64", "p0:64:64", or "p270:32:32" (address-space-specific).
            // Only the generic pointer (no address space or `p0:`) sets pointer_size.
            for part in layout.split('-') {
                if let Some(rest) = part.strip_prefix('p') {
                    // Generic pointer: "p:64:64" (no address space number)
                    if rest.starts_with(':') {
                        let parts: Vec<&str> = rest.split(':').collect();
                        if parts.len() >= 2 {
                            if let Ok(size) = parts[1].parse::<u32>() {
                                self.data_layout.pointer_size = Some(size);
                                break;
                            }
                        }
                    }
                    // Address space 0: "p0:64:64"
                    if let Some(as_rest) = rest.strip_prefix("0:") {
                        let parts: Vec<&str> = as_rest.split(':').collect();
                        if !parts.is_empty() {
                            if let Ok(size) = parts[0].parse::<u32>() {
                                self.data_layout.pointer_size = Some(size);
                                break;
                            }
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

/// Check if a line is a label (basic block entry point).
///
/// In LLVM IR, a label line has a first token ending with ':'.
/// Trailing metadata like `!dbg !123` should not prevent label detection.
/// Examples: "entry:", "loop_header:", "bb1: !dbg !123"
fn is_label_line(line: &str) -> bool {
    // Get the first token (before any whitespace)
    let first_token = line.split_whitespace().next().unwrap_or("");
    first_token.ends_with(':') && !first_token.starts_with(';') && !first_token.starts_with('!')
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
            let name = rest.get(..end).unwrap_or("").to_string();
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
            let name = rest.get(..end).unwrap_or("").to_string();
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
fn parse_call(
    line: &str,
    current_function: &str,
    metadata: &HashMap<String, SourceLocation>,
) -> Option<CallInstruction> {
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
            let callee = rest.get(..end).unwrap_or("").to_string();

            // Extract source location if present (!dbg !123)
            let location = extract_location(line, metadata);

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
///
/// Looks for `!dbg !N` in the instruction line, then resolves the metadata
/// ID `N` against the provided debug metadata table (populated from
/// `!N = !DILocation(line: ..., column: ..., ...)` entries).
fn extract_location(
    line: &str,
    metadata: &HashMap<String, SourceLocation>,
) -> Option<SourceLocation> {
    // Look for !dbg !N pattern
    let dbg_pos = line.rfind("!dbg")?;
    let after_dbg = &line[dbg_pos + 4..].trim_start();

    // Extract the metadata ID number (e.g., "123" from "!123")
    if after_dbg.starts_with('!') {
        let num_start = 1;
        let num_str: String = after_dbg[num_start..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if !num_str.is_empty() {
            if let Some(loc) = metadata.get(&num_str) {
                return Some(loc.clone());
            }
            // Metadata not yet parsed (forward reference) — return a
            // placeholder SourceLocation with the metadata ID as file name
            // so downstream code knows a debug location was present.
            return Some(SourceLocation::new(
                std::path::PathBuf::from(format!("!{}", num_str)),
                0,
            ));
        }
    }
    None
}

/// Parse a debug metadata definition line.
///
/// Format: `!N = !DILocation(line: 42, column: 5, scope: !1, file: !2)`
/// Returns (metadata_id, SourceLocation) if the line is a DILocation.
fn parse_debug_metadata(line: &str) -> Option<(String, SourceLocation)> {
    // Match: !N = !DILocation(...)
    let eq_pos = line.find(" = ")?;
    let id_part = &line[..eq_pos];
    if !id_part.starts_with('!') {
        return None;
    }
    let id_num: String = id_part[1..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if id_num.is_empty() {
        return None;
    }

    let def_part = &line[eq_pos + 3..];
    if !def_part.starts_with("!DILocation") {
        return None;
    }

    // Extract line number: "line: N"
    let mut src_line: u32 = 0;
    let mut src_column: Option<u32> = None;
    if let Some(line_start) = def_part.find("line:") {
        let after = &def_part[line_start + 5..];
        let num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !num.is_empty() {
            if let Ok(v) = num.parse() {
                src_line = v;
            }
        }
    }

    // Extract column number: "column: N"
    if let Some(col_start) = def_part.find("column:") {
        let after = &def_part[col_start + 7..];
        let num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !num.is_empty() {
            if let Ok(v) = num.parse() {
                src_column = Some(v);
            }
        }
    }

    let mut loc = SourceLocation::new(std::path::PathBuf::new(), src_line);
    loc.column = src_column;
    Some((id_num, loc))
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
/// Calling conventions appear between `define` and the return type:
/// - "define void @foo()"        → None (default ccc)
/// - "define fastcc void @foo()" → Some("fastcc")
/// - "define webkit_jscc void @foo()" → Some("webkit_jscc")
///
/// We only check tokens between `define` and the return type / `@` to avoid
/// false positives from function names containing convention substrings
/// (e.g., `@fastcc_helper` would be missed without positional validation).
fn extract_calling_convention(line: &str) -> Option<String> {
    // Must be a define line
    if !line.starts_with("define") {
        return None;
    }

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

    // Extract the region between "define" and "@" — this is where calling
    // conventions legally appear. Avoids matching inside function names.
    let after_define = &line["define".len()..];
    let region = if let Some(at_pos) = after_define.find('@') {
        &after_define[..at_pos]
    } else {
        // No function name found — nothing to extract
        return None;
    };

    // Check each convention as a whole word within the valid region
    for conv in &conventions {
        // Use word-boundary check: the convention must appear as a standalone
        // token, not as a substring of another word.
        for token in region.split_whitespace() {
            if token == *conv {
                return Some(conv.to_string());
            }
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

    #[test]
    fn test_function_body_extraction() {
        let ir = r#"
            declare i32 @strlen(ptr)

            define i64 @my_strlen(ptr %s) {
            entry:
                %len = call i32 @strlen(ptr %s)
                %result = zext i32 %len to i64
                ret i64 %result
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        assert!(module.function_bodies.contains_key("my_strlen"));

        let body = &module.function_bodies["my_strlen"];
        assert_eq!(body.instructions.len(), 3); // call + zext + ret
        assert_eq!(body.count_kind(IRInstructionKind::Call), 1);
        assert_eq!(body.count_kind(IRInstructionKind::Ret), 1);
    }

    /// Objective: Verify that parsing an empty string produces a valid empty module.
    /// Invariants: All collections (functions, declarations, calls, bodies) must be empty.
    #[test]
    fn test_parse_empty_string() {
        let module = IRModule::parse_from_text("");
        assert!(
            module.functions.is_empty(),
            "Empty input should produce no functions"
        );
        assert!(
            module.declarations.is_empty(),
            "Empty input should produce no declarations"
        );
        assert!(
            module.calls.is_empty(),
            "Empty input should produce no calls"
        );
        assert!(
            module.function_bodies.is_empty(),
            "Empty input should produce no function bodies"
        );
    }

    /// Objective: Verify that parsing whitespace-only input produces a valid empty module.
    /// Invariants: Whitespace lines are trimmed to empty and must not trigger any parsing logic.
    #[test]
    fn test_parse_whitespace_only() {
        let module = IRModule::parse_from_text("   \n  \n  ");
        assert!(
            module.functions.is_empty(),
            "Whitespace input should produce no functions"
        );
        assert!(
            module.declarations.is_empty(),
            "Whitespace input should produce no declarations"
        );
        assert!(
            module.calls.is_empty(),
            "Whitespace input should produce no calls"
        );
        assert!(
            module.function_bodies.is_empty(),
            "Whitespace input should produce no function bodies"
        );
    }

    /// Objective: Verify that an incomplete "declare" keyword without a function signature
    ///            is handled gracefully without adding any declaration.
    /// Invariants: parse_declaration requires '@' and '(' to extract a name;
    ///            missing both means no declaration is inserted.
    #[test]
    fn test_parse_incomplete_declaration() {
        let module = IRModule::parse_from_text("declare");
        assert!(
            module.declarations.is_empty(),
            "Incomplete declare should not produce a declaration"
        );
        assert!(
            module.functions.is_empty(),
            "Incomplete declare should not produce a function definition"
        );
    }

    /// Objective: Verify that a define line without a function body (no braces)
    ///            registers the function but produces no function body.
    /// Invariants: The function is added to `functions` (definition header parsed),
    ///            but without '{' and '}' no instructions are captured in `function_bodies`.
    #[test]
    fn test_parse_definition_without_body() {
        let module = IRModule::parse_from_text("define void @foo()");
        assert_eq!(
            module.functions.len(),
            1,
            "Definition header should register function 'foo'"
        );
        assert!(
            module.functions.contains_key("foo"),
            "Function 'foo' should be present in functions map"
        );
        assert!(
            module.function_bodies.is_empty(),
            "Definition without body braces should produce no function body"
        );
    }

    /// Objective: Verify that arbitrary non-LLVM IR text does not cause panics
    ///            and produces an empty module.
    /// Invariants: None of the parser branches match random text,
    ///            so all collections remain empty.
    #[test]
    fn test_parse_garbage_text() {
        let module = IRModule::parse_from_text("random garbage text");
        assert!(
            module.functions.is_empty(),
            "Garbage text should produce no functions"
        );
        assert!(
            module.declarations.is_empty(),
            "Garbage text should produce no declarations"
        );
        assert!(
            module.calls.is_empty(),
            "Garbage text should produce no calls"
        );
        assert!(
            module.function_bodies.is_empty(),
            "Garbage text should produce no function bodies"
        );
    }

    /// Objective: Verify that a function definition with an unclosed body
    ///            registers the function and saves the partial body (truncated file).
    /// Invariants: Instructions parsed inside the unclosed body are saved
    ///            because we flush remaining function body after the loop ends.
    #[test]
    fn test_parse_unclosed_function_body() {
        let module = IRModule::parse_from_text("define void @foo() {\n  ret void");
        assert_eq!(
            module.functions.len(),
            1,
            "Unclosed body should still register function 'foo'"
        );
        assert!(
            module.functions.contains_key("foo"),
            "Function 'foo' should be present in functions map"
        );
        assert!(
            module.function_bodies.contains_key("foo"),
            "Unclosed function body should be flushed to function_bodies on truncation"
        );
        let body = &module.function_bodies["foo"];
        assert_eq!(
            body.instructions.len(),
            1,
            "Unclosed body should contain the parsed instruction"
        );
    }

    #[test]
    fn test_conditional_release_pattern() {
        let ir = r#"
            define void @release_string(ptr %s) {
            entry:
                %22 = atomicrmw sub ptr %s, i32 2 monotonic
                %23 = icmp eq i32 %22, 2
                br i1 %23, label %destroy, label %exit
            destroy:
                tail call void @Bun__WTFStringImpl__destroy(ptr %s)
                ret void
            exit:
                ret void
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let body = &module.function_bodies["release_string"];

        // Verify the ConditionalRelease pattern is detectable
        assert_eq!(body.count_kind(IRInstructionKind::AtomicRmw), 1);
        assert_eq!(body.count_kind(IRInstructionKind::Icmp), 1);
        assert_eq!(body.count_kind(IRInstructionKind::Branch), 1);
        assert_eq!(body.count_kind(IRInstructionKind::Call), 1);

        // Verify atomicrmw sub
        let atomic_insts = body.atomic_rmw_with_op("sub");
        assert_eq!(atomic_insts.len(), 1);

        // Verify icmp eq
        let icmp_insts = body.instructions_of_kind(IRInstructionKind::Icmp);
        assert_eq!(icmp_insts.len(), 1);
        assert_eq!(icmp_insts[0].icmp_pred.as_deref(), Some("eq"));
    }
}
