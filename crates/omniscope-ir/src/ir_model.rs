//! Rich IR model with full type information, CFG edges, and metadata.
//!
//! This module defines the intermediate representation consumed by both:
//! - **Plan A**: C++ LLVM Pass that exports JSON, deserialized here via serde.
//! - **Plan C**: `llvm-sys` C API that populates these structs directly.
//!
//! The [`IRModuleModel`] carries richer type information than the legacy
//! [`crate::parser::IRModule`], including per-instruction result types,
//! operand types, basic-block successor edges, and global variable metadata.
//!
//! Conversion into the legacy format is provided by [`IRModuleModel::to_ir_module`]
//! so that all existing analysis passes continue to work unchanged.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::instruction_parser::{IRInstruction, IRInstructionKind};
use crate::parser::{
    CallInstruction, CallingConvention, DataLayout, Function, FunctionBody, IRModule,
};

// ---------------------------------------------------------------------------
// Top-level model
// ---------------------------------------------------------------------------

/// Top-level IR module representation produced by the C++ SafetyExportPass
/// or populated directly via the llvm-sys C API.
///
/// All fields except `functions` and `declarations` have sensible defaults
/// so that partial JSON from the C++ pass can be deserialized without errors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IRModuleModel {
    /// Target triple (e.g. `"x86_64-apple-darwin"`).
    pub target_triple: Option<String>,
    /// Data layout string.
    pub data_layout: Option<String>,
    /// Function definitions (with body).
    #[serde(default)]
    pub functions: Vec<IRFunction>,
    /// External function declarations (no body).
    #[serde(default)]
    pub declarations: Vec<IRDeclaration>,
    /// Named struct type definitions: struct name -> field type strings.
    #[serde(default)]
    pub named_struct_types: HashMap<String, Vec<String>>,
    /// Global variable definitions.
    #[serde(default)]
    pub global_variables: Vec<IRGlobalVariable>,
}

impl IRModuleModel {
    /// Deserialize an [`IRModuleModel`] from a JSON string produced by
    /// the C++ pass.
    ///
    /// This is the primary entry point for Plan A (C++ LLVM Pass -> JSON).
    pub fn from_json_str(json: &str) -> anyhow::Result<Self> {
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("JSON parse error: {}", e))
    }
}

// ---------------------------------------------------------------------------
// Function-level types
// ---------------------------------------------------------------------------

/// A function definition (with body).
///
/// Each function contains zero or more [`IRBasicBlock`]s which in turn hold
/// the instructions.  The calling convention defaults to `"ccc"` (C calling
/// convention) when not specified in the JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRFunction {
    /// Function name (without the leading `@`).
    pub name: String,
    /// Demangled C++ name (e.g. `"foo(int)"` from `"_Z3fooi"`).
    #[serde(default)]
    pub demangled: Option<String>,
    /// LLVM IR return type string (e.g. `"i32"`, `"void"`, `"ptr"`).
    #[serde(default)]
    pub return_type: String,
    /// Parameter type strings in declaration order.
    #[serde(default)]
    pub param_types: Vec<String>,
    /// Calling convention (e.g. `"ccc"`, `"fastcc"`). Defaults to `"ccc"`.
    #[serde(default = "default_calling_convention")]
    pub calling_convention: String,
    /// Basic blocks in layout order.
    #[serde(default)]
    pub blocks: Vec<IRBasicBlock>,
    /// Linkage type (e.g. `"internal"`, `"external"`).
    pub linkage: Option<String>,
}

/// Default calling convention for serde when the field is absent.
fn default_calling_convention() -> String {
    "ccc".to_string()
}

impl Default for IRFunction {
    fn default() -> Self {
        Self {
            name: String::new(),
            demangled: None,
            return_type: "void".to_string(),
            param_types: Vec::new(),
            calling_convention: default_calling_convention(),
            blocks: Vec::new(),
            linkage: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Basic block
// ---------------------------------------------------------------------------

/// A basic block within a function.
///
/// The `successors` field carries the CFG edge information: it lists the
/// labels of blocks that can be reached from the end of this block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IRBasicBlock {
    /// Block label (without trailing colon), e.g. `"entry"`, `"loop.header"`.
    pub label: String,
    /// Instructions in program order.
    #[serde(default)]
    pub instructions: Vec<IRInstructionModel>,
    /// Labels of successor blocks (for CFG construction).
    #[serde(default)]
    pub successors: Vec<String>,
}

// ---------------------------------------------------------------------------
// GEP deconstruction types
// ---------------------------------------------------------------------------

/// Deconstructed GEP instruction details for struct field access analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IRGepDetails {
    /// Source element type being indexed into.
    #[serde(default)]
    pub source_type: String,
    /// Whether the GEP is in-bounds.
    #[serde(default)]
    pub in_bounds: bool,
    /// Per-index details: value and the composite type at that level.
    #[serde(default)]
    pub indices: Vec<IRGepIndex>,
}

/// A single GEP index with its value and the field type at that level.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IRGepIndex {
    /// The index value (register or constant).
    #[serde(default)]
    pub value: String,
    /// The composite type that this index is selecting within.
    #[serde(default)]
    pub field_type: String,
}

// ---------------------------------------------------------------------------
// Instruction model
// ---------------------------------------------------------------------------

/// A single instruction with full type information.
///
/// This is the rich counterpart of [`IRInstruction`] which only carries
/// a best-effort classification.  Here we additionally record the result
/// type, per-operand types, and source location.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IRInstructionModel {
    /// Instruction index within its basic block.
    #[serde(default)]
    pub id: Option<u64>,
    /// Opcode string (e.g. `"add"`, `"load"`, `"call"`, `"br"`).
    pub opcode: String,
    /// Result type of the instruction (e.g. `"i64"`, `"ptr"`).
    /// `None` for void instructions (store, br, ret void).
    pub result_type: Option<String>,
    /// Type of each operand, parallel to [`operands`].
    #[serde(default)]
    pub operand_types: Vec<String>,
    /// Operand strings (registers, constants, globals).
    #[serde(default)]
    pub operands: Vec<String>,
    /// For call instructions: the callee function name (without `@`).
    pub callee: Option<String>,
    /// Whether this is an indirect call (function pointer).
    #[serde(default)]
    pub is_indirect: bool,
    /// Debug location as a string (e.g. `"/src/main.c:42:5"`).
    pub debug_loc: Option<String>,
    /// Raw LLVM IR text of the instruction.
    #[serde(default)]
    pub raw: String,
    /// For bitcast/inttoptr/ptrtoint: the original source type after tracing
    /// through chains of casts. Critical for FFI type recovery.
    pub source_type: Option<String>,
    /// For GEP instructions: deconstructed index and field-type information.
    pub gep_details: Option<IRGepDetails>,
}

// ---------------------------------------------------------------------------
// Declarations and globals
// ---------------------------------------------------------------------------

/// External function declaration (no body).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRDeclaration {
    /// Function name (without `@`).
    pub name: String,
    /// Demangled C++ name.
    #[serde(default)]
    pub demangled: Option<String>,
    /// LLVM IR return type string.
    #[serde(default)]
    pub return_type: String,
    /// Parameter type strings.
    #[serde(default)]
    pub param_types: Vec<String>,
}

impl Default for IRDeclaration {
    fn default() -> Self {
        Self {
            name: String::new(),
            demangled: None,
            return_type: "void".to_string(),
            param_types: Vec::new(),
        }
    }
}

/// Global variable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IRGlobalVariable {
    /// Variable name (without `@`).
    pub name: String,
    /// LLVM IR type string. C++ pass outputs `"type"`.
    #[serde(rename = "type")]
    pub ty: String,
    /// Whether the global is constant (`const`).
    #[serde(default)]
    pub is_constant: bool,
}

// ---------------------------------------------------------------------------
// Conversion: IRModuleModel -> IRModule (legacy)
// ---------------------------------------------------------------------------

impl IRModuleModel {
    /// Convert this rich model into the legacy [`IRModule`] format used by
    /// existing analysis passes.
    ///
    /// The conversion is lossless in the following sense: every field in
    /// [`IRModule`] that **can** be populated from the model **will** be
    /// populated.  Fields that have no counterpart in the model (e.g.
    /// `pointer_size`) are derived where possible or left at their defaults.
    pub fn to_ir_module(&self) -> IRModule {
        let mut module = IRModule::new();

        // -- Data layout -------------------------------------------------------
        module.data_layout = DataLayout {
            target_triple: self.target_triple.clone(),
            data_layout: self.data_layout.clone(),
            pointer_size: None,
            little_endian: None,
        };
        // Derive pointer_size / little_endian from the data layout string.
        module.parse_datalayout_info();

        // -- Declarations ------------------------------------------------------
        for decl in &self.declarations {
            let func = Function {
                name: decl.name.clone(),
                is_declaration: true,
                params: decl.param_types.clone(),
                return_type: decl.return_type.clone(),
            };
            module.declarations.insert(decl.name.clone(), func);
        }

        // -- Functions ---------------------------------------------------------
        for ir_func in &self.functions {
            // Collect all instructions across blocks into a flat stream.
            let mut all_instructions: Vec<IRInstruction> = Vec::new();
            let mut call_instructions: Vec<(IRInstruction, String)> = Vec::new();

            for block in &ir_func.blocks {
                for inst_model in &block.instructions {
                    let ir_inst = inst_model.to_ir_instruction();
                    // Collect calls for the module-level call list.
                    if ir_inst.kind == IRInstructionKind::Call
                        || ir_inst.kind == IRInstructionKind::IndirectCall
                    {
                        call_instructions.push((ir_inst.clone(), ir_func.name.clone()));
                    }
                    all_instructions.push(ir_inst);
                }
            }

            // Build legacy Function entry.
            let function = Function {
                name: ir_func.name.clone(),
                is_declaration: false,
                params: ir_func.param_types.clone(),
                return_type: ir_func.return_type.clone(),
            };
            module.functions.insert(ir_func.name.clone(), function);

            // Build legacy FunctionBody entry.
            let body = FunctionBody {
                name: ir_func.name.clone(),
                instructions: all_instructions,
            };
            module.function_bodies.insert(ir_func.name.clone(), body);

            // Record calling convention (skip default "ccc").
            if ir_func.calling_convention != "ccc" {
                module.calling_conventions.push(CallingConvention {
                    name: ir_func.calling_convention.clone(),
                });
            }

            // Populate module-level call list.
            for (inst, caller_name) in call_instructions {
                let callee_name = inst
                    .callee
                    .clone()
                    .unwrap_or_else(|| "indirect".to_string());
                let is_external = module.declarations.contains_key(&callee_name);
                module.calls.push(CallInstruction {
                    callee: callee_name,
                    caller: caller_name,
                    is_external,
                    location: None,
                });
            }
        }

        module
    }
}

// ---------------------------------------------------------------------------
// Conversion: IRInstructionModel -> IRInstruction (legacy)
// ---------------------------------------------------------------------------

impl IRInstructionModel {
    /// Convert this rich instruction into the legacy [`IRInstruction`]
    /// format.  The opcode string is mapped to the closest
    /// [`IRInstructionKind`] variant.
    pub fn to_ir_instruction(&self) -> IRInstruction {
        let kind = classify_opcode(&self.opcode);

        // Extract destination register from the raw text pattern "%name = ...".
        let dest = if self.result_type.is_some() {
            extract_dest_from_raw(&self.raw)
        } else {
            None
        };

        // Derive atomic_op for AtomicRmw / cmpxchg.
        let atomic_op = if kind == IRInstructionKind::AtomicRmw {
            extract_atomicrmw_op_from_raw(&self.raw)
        } else {
            None
        };

        // Derive icmp_pred for Icmp / fcmp.
        let icmp_pred = if kind == IRInstructionKind::Icmp {
            extract_icmp_pred_from_raw(&self.raw)
        } else {
            None
        };

        // Derive element_type from source_type (bitcast chains) or gep_details.
        let element_type = self
            .source_type
            .clone()
            .or_else(|| self.gep_details.as_ref().map(|g| g.source_type.clone()));

        IRInstruction {
            kind,
            dest,
            operands: self.operands.clone(),
            callee: self.callee.clone(),
            atomic_op,
            icmp_pred,
            raw_text: self.raw.clone(),
            result_type: self.result_type.clone(),
            element_type,
            function_signature: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Opcode classification helper
// ---------------------------------------------------------------------------

/// Map an opcode string to the legacy [`IRInstructionKind`].
///
/// This covers all variants that the legacy parser recognises.  Unknown
/// opcodes map to [`IRInstructionKind::Other`].
fn classify_opcode(opcode: &str) -> IRInstructionKind {
    match opcode {
        "alloca" => IRInstructionKind::Alloca,
        "load" => IRInstructionKind::Load,
        "store" => IRInstructionKind::Store,
        "atomicrmw" | "cmpxchg" => IRInstructionKind::AtomicRmw,
        "getelementptr" => IRInstructionKind::GetElementPtr,
        "icmp" | "fcmp" => IRInstructionKind::Icmp,
        "br" => IRInstructionKind::Branch,
        "call" | "invoke" => IRInstructionKind::Call,
        "ret" => IRInstructionKind::Ret,
        "phi" => IRInstructionKind::Phi,
        "select" => IRInstructionKind::Select,
        // Binary arithmetic ops
        "add" | "sub" | "mul" | "udiv" | "sdiv" | "urem" | "srem" | "and" | "or" | "xor"
        | "shl" | "lshr" | "ashr" => IRInstructionKind::BinaryOp,
        // Type conversions
        "bitcast" | "inttoptr" | "ptrtoint" | "zext" | "sext" | "trunc" | "fptoui" | "fptosi"
        | "uitofp" | "sitofp" | "fpext" | "fptrunc" => IRInstructionKind::Conversion,
        _ => IRInstructionKind::Other,
    }
}

/// Extract the destination register from a raw instruction line.
///
/// Looks for the pattern `%name = ...` at the start of the trimmed line.
fn extract_dest_from_raw(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if let Some(eq_pos) = trimmed.find(" = ") {
        let dest_part = trimmed[..eq_pos].trim();
        if dest_part.starts_with('%') {
            return Some(dest_part.to_string());
        }
    }
    None
}

/// Extract the atomicrmw operation from the raw text.
///
/// Handles both `atomicrmw sub ...` and `%dest = atomicrmw sub ...` patterns.
fn extract_atomicrmw_op_from_raw(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    // Skip "%dest = " prefix if present.
    let after_eq = if let Some(eq_pos) = trimmed.find(" = ") {
        trimmed[eq_pos + 3..].trim()
    } else {
        trimmed
    };
    let parts: Vec<&str> = after_eq.split_whitespace().collect();
    if parts.len() >= 2 && parts[0] == "atomicrmw" {
        return Some(parts[1].to_string());
    }
    None
}

/// Extract the icmp predicate from the raw text.
///
/// Handles both `icmp eq ...` and `%dest = icmp eq ...` patterns.
fn extract_icmp_pred_from_raw(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let after_eq = if let Some(eq_pos) = trimmed.find(" = ") {
        trimmed[eq_pos + 3..].trim()
    } else {
        trimmed
    };
    let parts: Vec<&str> = after_eq.split_whitespace().collect();
    if parts.len() >= 2 && (parts[0] == "icmp" || parts[0] == "fcmp") {
        return Some(parts[1].to_string());
    }
    None
}

// ---------------------------------------------------------------------------
// JSON loading helpers
// ---------------------------------------------------------------------------

/// Load an IR module from a JSON file produced by the C++ SafetyExportPass.
///
/// # Errors
/// Returns an error if the file cannot be read or the JSON is malformed.
pub fn load_from_json(path: &std::path::Path) -> anyhow::Result<IRModule> {
    let content = std::fs::read_to_string(path)?;
    parse_from_json(&content)
}

/// Load an IR module from a JSON string.
///
/// # Errors
/// Returns an error if the JSON is malformed.
pub fn parse_from_json(json: &str) -> anyhow::Result<IRModule> {
    let model: IRModuleModel = serde_json::from_str(json)?;
    Ok(model.to_ir_module())
}

// ===========================================================================
// Tests (extracted to ir_model_tests.rs to stay under the 1000-line limit)
// ===========================================================================

#[cfg(test)]
#[path = "ir_model_tests.rs"]
mod tests;
