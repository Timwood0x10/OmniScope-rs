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

// ──────────────────────────────────────────────────────────────────────────
// IR Instruction-level types for semantic derivation
// ──────────────────────────────────────────────────────────────────────────

/// Kind of an LLVM IR instruction.
///
/// This enum covers the instructions relevant to semantic derivation:
/// - Memory operations (alloca, load, store, atomicrmw)
/// - Pointer arithmetic (getelementptr)
/// - Control flow (icmp, branch, ret, phi)
/// - Computation (binary ops, call)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IRInstructionKind {
    /// `alloca` — stack allocation (pointer originates from stack)
    Alloca,
    /// `load` / `load atomic` — read from memory
    Load,
    /// `store` / `store atomic` — write to memory
    Store,
    /// `atomicrmw add/sub/xchg` — atomic read-modify-write (refcount pattern)
    AtomicRmw,
    /// `getelementptr` — pointer offset into struct/array
    GetElementPtr,
    /// `icmp eq/ne/...` — integer comparison (condition for branch)
    Icmp,
    /// `br i1` / `br label` — conditional or unconditional branch
    Branch,
    /// `call @func(...)` — function call
    Call,
    /// `ret` — return from function
    Ret,
    /// `phi` — SSA phi node
    Phi,
    /// `add`/`sub`/`mul`/`and`/`or`/`xor`/`shl`/`lshr`/`ashr` — binary arithmetic
    BinaryOp,
    /// `bitcast`/`inttoptr`/`ptrtoint`/`zext`/`sext`/`trunc` — type conversion
    Conversion,
    /// `select` — conditional select
    Select,
    /// Any instruction not in the above categories
    Other,
}

/// A single LLVM IR instruction with extracted metadata.
///
/// This is a simplified representation that captures enough information
/// for semantic derivation without attempting a full IR parser.
///
/// Example IR line and its parsed result:
/// ```llvm
/// %22 = atomicrmw sub ptr %string_impl, i32 2 monotonic
/// ```
/// → `IRInstruction { kind: AtomicRmw, dest: Some("%22"), atomic_op: Some("sub"), ... }`
#[derive(Debug, Clone)]
pub struct IRInstruction {
    /// Instruction kind
    pub kind: IRInstructionKind,
    /// Destination register (e.g., `%3`, `%result`), if any
    pub dest: Option<String>,
    /// Operands as raw strings (registers, constants, types)
    pub operands: Vec<String>,
    /// For Call: the callee function name (without @)
    pub callee: Option<String>,
    /// For AtomicRmw: the operation (add, sub, xchg, etc.)
    pub atomic_op: Option<String>,
    /// For Icmp: the comparison predicate (eq, ne, slt, etc.)
    pub icmp_pred: Option<String>,
    /// Raw text of the instruction line (for evidence/debugging)
    pub raw_text: String,
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

    /// Returns all call instructions in this function body.
    pub fn call_instructions(&self) -> Vec<&IRInstruction> {
        self.instructions_of_kind(IRInstructionKind::Call)
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
                        module.calling_conventions.push(CallingConvention {
                            name: conv_name,
                            platform_specific: true,
                        });
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
                // Skip labels, comments, and metadata-only lines
                if line.starts_with(';') || line.starts_with('!') || line.ends_with(':') {
                    continue;
                }

                // Parse instruction-level detail
                if let Some(inst) = parse_instruction(line) {
                    // Also extract call instruction for backward compatibility
                    if inst.kind == IRInstructionKind::Call {
                        if let Some(call) = parse_call(line, &current_function) {
                            module.calls.push(call);
                        }
                    }
                    current_instructions.push(inst);
                }
            }
            // Top-level call (shouldn't happen in valid IR, but handle gracefully)
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

// ──────────────────────────────────────────────────────────────────────────
// Instruction-level parsing for semantic derivation
// ──────────────────────────────────────────────────────────────────────────

/// Parse a single IR instruction line into structured form.
///
/// This is a best-effort parser — it extracts the instruction kind,
/// destination register, and key operands. It does NOT attempt to be
/// a full LLVM IR parser; instead, it captures enough information for
/// semantic derivation (pattern detection on instruction sequences).
///
/// Examples of parsed lines:
/// ```llvm
/// %3 = alloca i64                          → Alloca
/// %5 = load i64, ptr %3                    → Load
/// store i64 %5, ptr %1                     → Store
/// %22 = atomicrmw sub ptr %s, i32 2 mon    → AtomicRmw
/// %4 = getelementptr i8, ptr %1, i64 0     → GetElementPtr
/// %23 = icmp eq i32 %22, 2                 → Icmp
/// br i1 %23, label %bb5, label %exit       → Branch
/// tail call void @destroy(ptr %1)          → Call
/// ret i32 %result                          → Ret
/// %x = add i32 %a, %b                      → BinaryOp
/// ```
fn parse_instruction(line: &str) -> Option<IRInstruction> {
    let line = line.trim();
    if line.is_empty() || line.starts_with(';') || line.starts_with('!') {
        return None;
    }

    // Extract destination register: `%name = ...`
    let (dest, rest) = if let Some(eq_pos) = line.find(" = ") {
        let dest_part = line[..eq_pos].trim();
        let rest_part = line[eq_pos + 3..].trim();
        // Validate it looks like a register (%something)
        if dest_part.starts_with('%') {
            (Some(dest_part.to_string()), rest_part)
        } else {
            (None, line)
        }
    } else {
        (None, line)
    };

    // Classify instruction kind from the start of the (rest) line
    let raw_text = line.to_string();

    // Strip leading keywords: "tail", "musttail", "notail", "nuw", "nsw", etc.
    let stripped = strip_calling_prefixes(rest);

    // alloca
    if stripped.starts_with("alloca") {
        return Some(IRInstruction {
            kind: IRInstructionKind::Alloca,
            dest,
            operands: extract_operands(stripped, "alloca"),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // load (including "load atomic")
    if stripped.starts_with("load") {
        return Some(IRInstruction {
            kind: IRInstructionKind::Load,
            dest,
            operands: extract_operands(stripped, "load"),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // store (including "store atomic")
    if stripped.starts_with("store") {
        return Some(IRInstruction {
            kind: IRInstructionKind::Store,
            dest,
            operands: extract_operands(stripped, "store"),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // atomicrmw
    if stripped.starts_with("atomicrmw") {
        let atomic_op = extract_atomicrmw_op(stripped);
        return Some(IRInstruction {
            kind: IRInstructionKind::AtomicRmw,
            dest,
            operands: extract_operands(stripped, "atomicrmw"),
            callee: None,
            atomic_op,
            icmp_pred: None,
            raw_text,
        });
    }

    // cmpxchg
    if stripped.starts_with("cmpxchg") {
        return Some(IRInstruction {
            kind: IRInstructionKind::AtomicRmw, // Treat as atomic op
            dest,
            operands: extract_operands(stripped, "cmpxchg"),
            callee: None,
            atomic_op: Some("cmpxchg".to_string()),
            icmp_pred: None,
            raw_text,
        });
    }

    // getelementptr
    if stripped.starts_with("getelementptr") {
        return Some(IRInstruction {
            kind: IRInstructionKind::GetElementPtr,
            dest,
            operands: extract_operands(stripped, "getelementptr"),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // icmp
    if stripped.starts_with("icmp") {
        let icmp_pred = extract_icmp_pred(stripped);
        return Some(IRInstruction {
            kind: IRInstructionKind::Icmp,
            dest,
            operands: extract_operands(stripped, "icmp"),
            callee: None,
            atomic_op: None,
            icmp_pred,
            raw_text,
        });
    }

    // fcmp
    if stripped.starts_with("fcmp") {
        let icmp_pred = extract_icmp_pred(stripped);
        return Some(IRInstruction {
            kind: IRInstructionKind::Icmp, // Treat similarly
            dest,
            operands: extract_operands(stripped, "fcmp"),
            callee: None,
            atomic_op: None,
            icmp_pred,
            raw_text,
        });
    }

    // br
    if stripped.starts_with("br") {
        return Some(IRInstruction {
            kind: IRInstructionKind::Branch,
            dest,
            operands: extract_operands(stripped, "br"),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // call (including "tail call", "musttail call")
    if stripped.starts_with("call") {
        let callee = extract_call_callee(stripped);
        return Some(IRInstruction {
            kind: IRInstructionKind::Call,
            dest,
            operands: Vec::new(), // operands not needed for call; callee is sufficient
            callee,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // ret
    if stripped.starts_with("ret") {
        return Some(IRInstruction {
            kind: IRInstructionKind::Ret,
            dest,
            operands: extract_operands(stripped, "ret"),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // phi
    if stripped.starts_with("phi") {
        return Some(IRInstruction {
            kind: IRInstructionKind::Phi,
            dest,
            operands: extract_operands(stripped, "phi"),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // select
    if stripped.starts_with("select") {
        return Some(IRInstruction {
            kind: IRInstructionKind::Select,
            dest,
            operands: Vec::new(),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // Binary operations
    let binary_ops = [
        "add", "sub", "mul", "udiv", "sdiv", "urem", "srem", "and", "or", "xor", "shl", "lshr",
        "ashr",
    ];
    for op in &binary_ops {
        if stripped.starts_with(op) {
            // Make sure it's not a longer word (e.g., "sub" vs "subroutine")
            let after_op = stripped.get(op.len()..).unwrap_or("");
            if after_op.is_empty()
                || !after_op
                    .chars()
                    .next()
                    .map(|c| c.is_alphanumeric())
                    .unwrap_or(false)
            {
                return Some(IRInstruction {
                    kind: IRInstructionKind::BinaryOp,
                    dest,
                    operands: extract_operands(stripped, op),
                    callee: None,
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text,
                });
            }
        }
    }

    // Conversion operations
    let conv_ops = [
        "bitcast", "inttoptr", "ptrtoint", "zext", "sext", "trunc", "fptoui", "fptosi", "uitofp",
        "sitofp", "fpext", "fptrunc",
    ];
    for op in &conv_ops {
        if stripped.starts_with(op) {
            return Some(IRInstruction {
                kind: IRInstructionKind::Conversion,
                dest,
                operands: Vec::new(),
                callee: None,
                atomic_op: None,
                icmp_pred: None,
                raw_text,
            });
        }
    }

    // switch / invoke / resume / landingpad / indirectbr / extractvalue / insertvalue
    // → classify as Other
    Some(IRInstruction {
        kind: IRInstructionKind::Other,
        dest,
        operands: Vec::new(),
        callee: None,
        atomic_op: None,
        icmp_pred: None,
        raw_text,
    })
}

/// Strip call-prefix keywords: "tail", "musttail", "notail"
fn strip_calling_prefixes(s: &str) -> &str {
    let mut rest = s;
    loop {
        if rest.starts_with("tail ") {
            rest = &rest[5..];
        } else if rest.starts_with("musttail ") {
            rest = &rest[9..];
        } else if rest.starts_with("notail ") {
            rest = &rest[7..];
        } else {
            break;
        }
    }
    rest
}

/// Extract the atomicrmw operation name (add, sub, xchg, etc.)
fn extract_atomicrmw_op(s: &str) -> Option<String> {
    // Format: "atomicrmw <op> <type> <ptr>, <value> <ordering>"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() >= 2 && parts[0] == "atomicrmw" {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Extract the icmp predicate (eq, ne, slt, sgt, ult, ugt, sle, sge, ule, uge)
fn extract_icmp_pred(s: &str) -> Option<String> {
    // Format: "icmp <pred> <type> <op1>, <op2>"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Extract the callee function name from a call instruction.
fn extract_call_callee(s: &str) -> Option<String> {
    // Format: "call [fastcc] <ret_type> @<name>(<args>)"
    // Find @name( pattern
    if let Some(at_pos) = s.find('@') {
        let after_at = &s[at_pos + 1..];
        if let Some(paren_pos) = after_at.find('(') {
            let name = after_at[..paren_pos].to_string();
            // Filter out LLVM intrinsics
            if !name.starts_with("llvm.") {
                return Some(name);
            }
        }
    }
    None
}

/// Extract operands from an instruction line after stripping the opcode.
///
/// This is a simplified operand extractor that captures register names
/// (%-prefixed) and constants from the instruction text. It does NOT
/// attempt full type-aware parsing.
fn extract_operands(s: &str, opcode: &str) -> Vec<String> {
    let after_opcode = if let Some(pos) = s.find(opcode) {
        &s[pos + opcode.len()..]
    } else {
        s
    };

    let mut operands = Vec::new();

    // Extract %-prefixed registers
    for part in after_opcode.split(|c: char| c.is_whitespace() || c == ',') {
        let part = part.trim();
        if part.starts_with('%') {
            operands.push(part.to_string());
        }
    }

    operands
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

    // ── Instruction-level parsing tests ──

    #[test]
    fn test_parse_alloca() {
        let inst = parse_instruction("  %3 = alloca i64").unwrap();
        assert_eq!(inst.kind, IRInstructionKind::Alloca);
        assert_eq!(inst.dest.as_deref(), Some("%3"));
    }

    #[test]
    fn test_parse_load() {
        let inst = parse_instruction("  %5 = load i64, ptr %3").unwrap();
        assert_eq!(inst.kind, IRInstructionKind::Load);
        assert_eq!(inst.dest.as_deref(), Some("%5"));
    }

    #[test]
    fn test_parse_store() {
        let inst = parse_instruction("  store i64 %5, ptr %1").unwrap();
        assert_eq!(inst.kind, IRInstructionKind::Store);
        assert!(inst.dest.is_none());
    }

    #[test]
    fn test_parse_atomicrmw_sub() {
        let inst =
            parse_instruction("  %22 = atomicrmw sub ptr %string_impl, i32 2 monotonic").unwrap();
        assert_eq!(inst.kind, IRInstructionKind::AtomicRmw);
        assert_eq!(inst.dest.as_deref(), Some("%22"));
        assert_eq!(inst.atomic_op.as_deref(), Some("sub"));
    }

    #[test]
    fn test_parse_atomicrmw_add() {
        let inst = parse_instruction("  %10 = atomicrmw add ptr %refcount, i32 1 acquire").unwrap();
        assert_eq!(inst.kind, IRInstructionKind::AtomicRmw);
        assert_eq!(inst.atomic_op.as_deref(), Some("add"));
    }

    #[test]
    fn test_parse_getelementptr() {
        let inst = parse_instruction("  %4 = getelementptr i8, ptr %1, i64 0").unwrap();
        assert_eq!(inst.kind, IRInstructionKind::GetElementPtr);
        assert_eq!(inst.dest.as_deref(), Some("%4"));
    }

    #[test]
    fn test_parse_icmp_eq() {
        let inst = parse_instruction("  %23 = icmp eq i32 %22, 2").unwrap();
        assert_eq!(inst.kind, IRInstructionKind::Icmp);
        assert_eq!(inst.icmp_pred.as_deref(), Some("eq"));
    }

    #[test]
    fn test_parse_branch_conditional() {
        let inst = parse_instruction("  br i1 %23, label %bb5, label %exit").unwrap();
        assert_eq!(inst.kind, IRInstructionKind::Branch);
    }

    #[test]
    fn test_parse_call() {
        let inst =
            parse_instruction("  tail call void @Bun__WTFStringImpl__destroy(ptr %1)").unwrap();
        assert_eq!(inst.kind, IRInstructionKind::Call);
        assert_eq!(inst.callee.as_deref(), Some("Bun__WTFStringImpl__destroy"));
    }

    #[test]
    fn test_parse_ret() {
        let inst = parse_instruction("  ret i32 %result").unwrap();
        assert_eq!(inst.kind, IRInstructionKind::Ret);
    }

    #[test]
    fn test_parse_binary_op_add() {
        let inst = parse_instruction("  %x = add i32 %a, %b").unwrap();
        assert_eq!(inst.kind, IRInstructionKind::BinaryOp);
    }

    #[test]
    fn test_parse_bitcast() {
        let inst = parse_instruction("  %2 = bitcast ptr %1 to ptr").unwrap();
        assert_eq!(inst.kind, IRInstructionKind::Conversion);
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
