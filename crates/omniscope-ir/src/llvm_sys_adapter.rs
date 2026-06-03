//! llvm-sys C API adapter (Plan C)
//!
//! This module uses the `llvm-sys` crate to parse `.bc` and `.ll` files
//! directly, producing an [`IRModule`] with full type information, metadata,
//! and module-level attributes that the text parser discards.
//!
//! The implementation uses LLVM's C API through `llvm-sys` to walk modules,
//! functions, basic blocks, and instructions, populating [`IRModule`] with
//! complete type and CFG data.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;

use anyhow::{Context, Result};
use llvm_sys::core::*;
use llvm_sys::ir_reader::LLVMParseIRInContext2;
use llvm_sys::prelude::*;
use llvm_sys::LLVMOpcode;
use tracing::debug;

use crate::instruction_parser::{IRInstruction, IRInstructionKind};
use crate::parser::{CallingConvention, Function, FunctionBody, IRModule};

// ──────────────────────────────────────────────────────────────────────────
// RAII Guards
// ──────────────────────────────────────────────────────────────────────────

/// RAII guard for an LLVM context. Disposes the context on drop.
struct ContextGuard(LLVMContextRef);

impl Drop for ContextGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was created by `LLVMContextCreate` and has not
            // been disposed yet. We are the sole owner.
            unsafe { LLVMContextDispose(self.0) };
        }
        self.0 = ptr::null_mut();
    }
}

/// RAII guard for an LLVM module. Disposes the module on drop.
struct ModuleGuard(LLVMModuleRef);

impl Drop for ModuleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was created by `LLVMParseIRInContext` and has
            // not been disposed yet. We are the sole owner.
            unsafe { LLVMDisposeModule(self.0) };
        }
        self.0 = ptr::null_mut();
    }
}

/// RAII guard for an LLVM memory buffer. Disposes the buffer on drop.
struct MemoryBufferGuard(LLVMMemoryBufferRef);

impl Drop for MemoryBufferGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was created by LLVM and has not been disposed yet.
            unsafe { LLVMDisposeMemoryBuffer(self.0) };
        }
        self.0 = ptr::null_mut();
    }
}

/// Returns `true` if the llvm-sys backend is available at runtime.
///
/// Probes by attempting to create and immediately dispose an LLVM context.
/// If the LLVM library is linked and functional, this returns `true`.
pub fn is_available() -> bool {
    // SAFETY: `LLVMContextCreate` allocates a fresh context.
    // `LLVMContextDispose` releases it immediately. No other references
    // to the context exist.
    unsafe {
        let ctx = LLVMContextCreate();
        if ctx.is_null() {
            return false;
        }
        LLVMContextDispose(ctx);
    }
    true
}

/// Parse an LLVM IR file using the llvm-sys C API.
///
/// This is the highest-fidelity backend: it preserves full type information,
/// metadata, and module-level attributes that the text parser discards.
///
/// # Errors
///
/// Returns an error if:
/// - LLVM libraries are not installed or not found.
/// - The file cannot be parsed (corrupt bitcode, unsupported IR version, etc.).
pub fn parse_with_llvm_sys(path: &Path) -> Result<IRModule> {
    debug!(path = %path.display(), "Parsing via llvm-sys");

    let path_str = path
        .to_str()
        .context("Path contains non-UTF-8 characters")?;
    let c_path = CString::new(path_str).context("Path contains null byte")?;

    // SAFETY: `LLVMContextCreate` returns a fresh context. The `ContextGuard`
    // ensures it is disposed when we return, even on error paths.
    let ctx_guard = ContextGuard(unsafe { LLVMContextCreate() });
    if ctx_guard.0.is_null() {
        anyhow::bail!("LLVMContextCreate returned null");
    }

    // Create a memory buffer from the file.
    let mut msg_ptr: *mut c_char = ptr::null_mut();
    let mut mem_buf: LLVMMemoryBufferRef = ptr::null_mut();

    // SAFETY: `LLVMCreateMemoryBufferWithContentsOfFile` reads the file and
    // creates a memory buffer. On failure it returns non-zero and sets msg_ptr.
    let buf_ok = unsafe {
        LLVMCreateMemoryBufferWithContentsOfFile(c_path.as_ptr(), &mut mem_buf, &mut msg_ptr)
    };

    if buf_ok != 0 {
        let err_msg = if !msg_ptr.is_null() {
            let msg = unsafe { CStr::from_ptr(msg_ptr) }
                .to_string_lossy()
                .into_owned();
            unsafe { LLVMDisposeMessage(msg_ptr) };
            msg
        } else {
            "failed to read file".to_string()
        };
        anyhow::bail!("LLVM could not read {}: {}", path_str, err_msg);
    }

    let _buf_guard = MemoryBufferGuard(mem_buf);

    // Parse the IR from the memory buffer.
    let mut module_ptr: LLVMModuleRef = ptr::null_mut();
    let mut parse_msg: *mut c_char = ptr::null_mut();

    // SAFETY: `LLVMParseIRInContext2` parses the memory buffer into an LLVM
    // module. Returns 0 on success. On failure, `parse_msg` receives the error.
    let parse_ok =
        unsafe { LLVMParseIRInContext2(ctx_guard.0, mem_buf, &mut module_ptr, &mut parse_msg) };

    if parse_ok != 0 {
        let err_msg = if !parse_msg.is_null() {
            let msg = unsafe { CStr::from_ptr(parse_msg) }
                .to_string_lossy()
                .into_owned();
            unsafe { LLVMDisposeMessage(parse_msg) };
            msg
        } else {
            "unknown parse error".to_string()
        };
        anyhow::bail!("LLVM IR parse failed for {}: {}", path_str, err_msg);
    }

    // Clean up any parse message (should be null on success).
    if !parse_msg.is_null() {
        unsafe { LLVMDisposeMessage(parse_msg) };
    }

    let _module_guard = ModuleGuard(module_ptr);

    // Walk the module and populate IRModule
    let mut module = IRModule::new();

    // Extract target triple and data layout
    extract_module_metadata(module_ptr, &mut module);

    // Walk functions (declarations and definitions)
    walk_module_functions(module_ptr, &mut module)?;

    Ok(module)
}

// ──────────────────────────────────────────────────────────────────────────
// Module metadata extraction
// ──────────────────────────────────────────────────────────────────────────

/// Extract target triple, data layout, pointer size, and endianness.
fn extract_module_metadata(module_ref: LLVMModuleRef, module: &mut IRModule) {
    // SAFETY: `LLVMGetTarget` returns a pointer to an internal LLVM string.
    // We copy it into a Rust `String` before any further LLVM calls.
    let triple_c = unsafe { LLVMGetTarget(module_ref) };
    if !triple_c.is_null() {
        let triple = unsafe { CStr::from_ptr(triple_c) }
            .to_string_lossy()
            .into_owned();
        module.data_layout.target_triple = Some(triple);
    }

    // SAFETY: `LLVMGetDataLayoutStr` returns a pointer to an internal string.
    let layout_c = unsafe { LLVMGetDataLayoutStr(module_ref) };
    if !layout_c.is_null() {
        let layout = unsafe { CStr::from_ptr(layout_c) }
            .to_string_lossy()
            .into_owned();
        module.data_layout.data_layout = Some(layout);
        module.parse_datalayout_info();
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Function walking
// ──────────────────────────────────────────────────────────────────────────

/// Walk all functions in the module, separating declarations from definitions.
fn walk_module_functions(module_ref: LLVMModuleRef, module: &mut IRModule) -> Result<()> {
    // SAFETY: `LLVMGetFirstFunction` returns the first function in the
    // module's function list, or null if the module has no functions.
    let mut func = unsafe { LLVMGetFirstFunction(module_ref) };

    while !func.is_null() {
        let name = get_value_name(func);

        // SAFETY: `LLVMIsDeclaration` checks if the function has no body.
        let is_decl = unsafe { LLVMIsDeclaration(func) } != 0;

        // Extract return type via `LLVMGlobalGetValueType` which returns the
        // FunctionType directly (works correctly with opaque pointers).
        // SAFETY: `LLVMGlobalGetValueType` returns the type of a global value,
        // which for functions is the FunctionType itself.
        let func_ty_ref = unsafe { LLVMGlobalGetValueType(func) };
        let return_type = if !func_ty_ref.is_null() {
            // SAFETY: `LLVMGetReturnType` extracts the return type from a
            // FunctionType.
            let ret_ty = unsafe { LLVMGetReturnType(func_ty_ref) };
            type_to_string(ret_ty)
        } else {
            "unknown".to_string()
        };

        // Extract parameters
        let params = extract_function_params(func);

        let function = Function {
            name: name.clone(),
            is_declaration: is_decl,
            params,
            return_type,
        };

        if is_decl {
            module.declarations.insert(name, function);
        } else {
            module.functions.insert(name.clone(), function);

            // Walk function body
            let body = walk_function_body(func, &name);

            // Extract call instructions for the module-level calls list.
            for inst in &body.instructions {
                if inst.kind == IRInstructionKind::Call
                    || inst.kind == IRInstructionKind::IndirectCall
                {
                    let callee_name = inst
                        .callee
                        .clone()
                        .unwrap_or_else(|| "indirect".to_string());
                    let is_external = module.declarations.contains_key(&callee_name);
                    module.calls.push(crate::parser::CallInstruction {
                        callee: callee_name,
                        caller: name.clone(),
                        is_external,
                        location: None,
                    });
                }
            }

            module.function_bodies.insert(name, body);

            // Extract calling convention
            // SAFETY: `LLVMGetFunctionCallConv` returns the calling convention
            // as an integer. We map known conventions to names.
            let cc_id = unsafe { LLVMGetFunctionCallConv(func) };
            if let Some(cc_name) = calling_convention_name(cc_id) {
                module
                    .calling_conventions
                    .push(CallingConvention { name: cc_name });
            }
        }

        // SAFETY: `LLVMGetNextFunction` advances to the next function in the
        // module's function list, or returns null at the end.
        func = unsafe { LLVMGetNextFunction(func) };
    }

    // Walk global variables
    walk_global_variables(module_ref, module);

    Ok(())
}

/// Extract parameter names and types for a function.
fn extract_function_params(func: LLVMValueRef) -> Vec<String> {
    let mut params = Vec::new();
    // SAFETY: `LLVMCountParams` returns the number of parameters.
    let count = unsafe { LLVMCountParams(func) } as usize;

    for i in 0..count {
        // SAFETY: `LLVMGetParam` returns the i-th parameter of the function.
        let param = unsafe { LLVMGetParam(func, i as u32) };
        let name = get_value_name(param);
        if !name.is_empty() {
            params.push(name);
        } else {
            params.push(format!("%{}", i));
        }
    }

    params
}

/// Walk global variables in the module.
fn walk_global_variables(module_ref: LLVMModuleRef, module: &mut IRModule) {
    // SAFETY: `LLVMGetFirstGlobal` returns the first global variable.
    let mut global = unsafe { LLVMGetFirstGlobal(module_ref) };

    while !global.is_null() {
        let name = get_value_name(global);

        // SAFETY: `LLVMIsGlobalConstant` checks if the global is constant.
        let is_constant = unsafe { LLVMIsGlobalConstant(global) } != 0;

        // Record every global variable so downstream passes can query
        // whether a symbol is a global (e.g. HeapProvenancePass,
        // BorrowEscapePass) instead of relying on name heuristics.
        module.global_variables.insert(name, is_constant);

        // SAFETY: `LLVMGetNextGlobal` advances to the next global variable.
        global = unsafe { LLVMGetNextGlobal(global) };
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Function body walking
// ──────────────────────────────────────────────────────────────────────────

/// Walk the basic blocks and instructions of a function definition.
fn walk_function_body(func: LLVMValueRef, func_name: &str) -> FunctionBody {
    let mut instructions = Vec::new();

    // SAFETY: `LLVMGetFirstBasicBlock` returns the first basic block, or
    // null if the function has no body (declaration).
    let mut bb = unsafe { LLVMGetFirstBasicBlock(func) };

    while !bb.is_null() {
        // SAFETY: `LLVMGetFirstInstruction` returns the first instruction
        // in the basic block.
        let mut inst = unsafe { LLVMGetFirstInstruction(bb) };

        while !inst.is_null() {
            if let Some(ir_inst) = convert_instruction(inst, func_name) {
                instructions.push(ir_inst);

                // Record call instructions in the module-level calls list
                // (done at the caller level for the module, not here)
            }

            // SAFETY: `LLVMGetNextInstruction` advances to the next
            // instruction in the basic block.
            inst = unsafe { LLVMGetNextInstruction(inst) };
        }

        // SAFETY: `LLVMGetNextBasicBlock` advances to the next basic block.
        bb = unsafe { LLVMGetNextBasicBlock(bb) };
    }

    FunctionBody {
        name: func_name.to_string(),
        instructions,
    }
}

/// Convert an LLVM instruction C-API handle to an `IRInstruction`.
fn convert_instruction(inst: LLVMValueRef, _func_name: &str) -> Option<IRInstruction> {
    // SAFETY: `LLVMGetInstructionOpcode` returns the opcode enum value
    // for the instruction.
    let opcode = unsafe { LLVMGetInstructionOpcode(inst) };

    let kind = map_opcode(opcode)?;
    let dest = get_dest_name(inst);
    let raw_text = get_instruction_debug_string(inst);

    // Extract type information
    // SAFETY: `LLVMTypeOf` returns the type of the instruction's result.
    // For void-typed instructions (like store/branch), this returns the
    // void type.
    let ty_ref = unsafe { LLVMTypeOf(inst) };
    let result_type = if !ty_ref.is_null() {
        Some(type_to_string(ty_ref))
    } else {
        None
    };

    // Extract callee for call instructions
    let (callee, function_signature, element_type) = match opcode {
        LLVMOpcode::LLVMCall => {
            let callee_name = extract_call_callee_from_llvm(inst);
            let sig = extract_call_signature(inst);
            (callee_name, sig, None)
        }
        LLVMOpcode::LLVMLoad => {
            // For load instructions, the result type IS the element type
            // (the type of the value loaded from memory). With opaque
            // pointers, we cannot derive it from the pointer operand,
            // so we reuse the result_type.
            (None, None, result_type.clone())
        }
        LLVMOpcode::LLVMStore => {
            // For store, element type is the type of the value being stored
            // SAFETY: `LLVMGetOperand(inst, 0)` is the value being stored.
            let val_op = unsafe { LLVMGetOperand(inst, 0) };
            let et = if !val_op.is_null() {
                let val_ty = unsafe { LLVMTypeOf(val_op) };
                if !val_ty.is_null() {
                    Some(type_to_string(val_ty))
                } else {
                    None
                }
            } else {
                None
            };
            (None, None, et)
        }
        LLVMOpcode::LLVMGetElementPtr => {
            // SAFETY: `LLVMGetGEPSourceElementType` is not available in all
            // llvm-sys versions. Use the first type argument from the
            // instruction's type metadata or extract from operand 0's type.
            let et = extract_gep_element_type(inst);
            (None, None, et)
        }
        _ => (None, None, None),
    };

    // Extract atomic op for atomicrmw
    let atomic_op = if opcode == LLVMOpcode::LLVMAtomicRMW {
        extract_atomicrmw_op_name(inst)
    } else {
        None
    };

    // Extract icmp predicate
    let icmp_pred = if opcode == LLVMOpcode::LLVMICmp {
        extract_icmp_predicate(inst)
    } else {
        None
    };

    Some(IRInstruction {
        kind,
        dest,
        operands: Vec::new(), // Operands populated by text parser; llvm-sys uses typed access
        callee,
        atomic_op,
        icmp_pred,
        raw_text,
        result_type,
        element_type,
        function_signature,
        conversion_opcode: None, // Will be populated by caller if needed
        binary_opcode: None,     // Will be populated by caller if needed
    })
}

/// Map an LLVM opcode to our `IRInstructionKind`.
fn map_opcode(opcode: LLVMOpcode) -> Option<IRInstructionKind> {
    match opcode {
        LLVMOpcode::LLVMAlloca => Some(IRInstructionKind::Alloca),
        LLVMOpcode::LLVMLoad => Some(IRInstructionKind::Load),
        LLVMOpcode::LLVMStore => Some(IRInstructionKind::Store),
        LLVMOpcode::LLVMAtomicRMW => Some(IRInstructionKind::AtomicRmw),
        LLVMOpcode::LLVMGetElementPtr => Some(IRInstructionKind::GetElementPtr),
        LLVMOpcode::LLVMICmp => Some(IRInstructionKind::Icmp),
        LLVMOpcode::LLVMFCmp => Some(IRInstructionKind::Fcmp),
        LLVMOpcode::LLVMBr => Some(IRInstructionKind::Branch),
        LLVMOpcode::LLVMIndirectBr => Some(IRInstructionKind::Branch),
        LLVMOpcode::LLVMCall => Some(IRInstructionKind::Call),
        LLVMOpcode::LLVMInvoke => Some(IRInstructionKind::Call),
        LLVMOpcode::LLVMRet => Some(IRInstructionKind::Ret),
        LLVMOpcode::LLVMPHI => Some(IRInstructionKind::Phi),
        LLVMOpcode::LLVMSelect => Some(IRInstructionKind::Select),
        // Binary operations
        LLVMOpcode::LLVMAdd
        | LLVMOpcode::LLVMFAdd
        | LLVMOpcode::LLVMSub
        | LLVMOpcode::LLVMFSub
        | LLVMOpcode::LLVMMul
        | LLVMOpcode::LLVMFMul
        | LLVMOpcode::LLVMUDiv
        | LLVMOpcode::LLVMSDiv
        | LLVMOpcode::LLVMFDiv
        | LLVMOpcode::LLVMURem
        | LLVMOpcode::LLVMSRem
        | LLVMOpcode::LLVMFRem
        | LLVMOpcode::LLVMAnd
        | LLVMOpcode::LLVMOr
        | LLVMOpcode::LLVMXor
        | LLVMOpcode::LLVMShl
        | LLVMOpcode::LLVMLShr
        | LLVMOpcode::LLVMAShr => Some(IRInstructionKind::BinaryOp),
        // Conversion operations
        LLVMOpcode::LLVMTrunc
        | LLVMOpcode::LLVMZExt
        | LLVMOpcode::LLVMSExt
        | LLVMOpcode::LLVMFPToUI
        | LLVMOpcode::LLVMFPToSI
        | LLVMOpcode::LLVMUIToFP
        | LLVMOpcode::LLVMSIToFP
        | LLVMOpcode::LLVMFPTrunc
        | LLVMOpcode::LLVMFPExt
        | LLVMOpcode::LLVMPtrToInt
        | LLVMOpcode::LLVMIntToPtr
        | LLVMOpcode::LLVMBitCast
        | LLVMOpcode::LLVMAddrSpaceCast => Some(IRInstructionKind::Conversion),
        // Catch-all for unhandled opcodes
        _ => Some(IRInstructionKind::Other),
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Helper: type to string
// ──────────────────────────────────────────────────────────────────────────

/// Convert an LLVM type to a human-readable string.
fn type_to_string(ty_ref: LLVMTypeRef) -> String {
    // SAFETY: `LLVMPrintTypeToString` allocates a C string with the type's
    // textual representation. We must free it with `LLVMDisposeMessage`.
    let c_str = unsafe { LLVMPrintTypeToString(ty_ref) };
    if c_str.is_null() {
        return "<unknown>".to_string();
    }
    let result = unsafe { CStr::from_ptr(c_str) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: `c_str` was allocated by LLVM's `LLVMPrintTypeToString` and
    // must be freed with `LLVMDisposeMessage`.
    unsafe { LLVMDisposeMessage(c_str) };
    result
}

/// Get the name of an LLVM value (function, parameter, instruction result).
fn get_value_name(val: LLVMValueRef) -> String {
    // SAFETY: `LLVMGetValueName` returns a pointer to an internal string.
    // We copy it into a Rust String.
    let mut length: usize = 0;
    let c_str = unsafe { LLVMGetValueName2(val, &mut length) };
    if c_str.is_null() || length == 0 {
        return String::new();
    }
    // SAFETY: `c_str` points to `length` valid bytes of a UTF-8-ish name.
    unsafe { CStr::from_ptr(c_str).to_string_lossy().into_owned() }
}

/// Get the destination register name for an instruction, if it produces a value.
fn get_dest_name(inst: LLVMValueRef) -> Option<String> {
    // SAFETY: `LLVMGetTypeKind` on the result type tells us if it's void
    // (instructions returning void have no destination name).
    let ty = unsafe { LLVMTypeOf(inst) };
    if ty.is_null() {
        return None;
    }
    // SAFETY: `LLVMGetTypeKind` returns the kind of the type.
    let kind = unsafe { LLVMGetTypeKind(ty) };
    if kind == llvm_sys::LLVMTypeKind::LLVMVoidTypeKind {
        return None;
    }

    let name = get_value_name(inst);
    if name.is_empty() {
        // Instruction has no explicit name — LLVM assigns a numeric ID.
        // We construct a synthetic register name.
        // SAFETY: `LLVMGetValueName2` returned empty, so we use the pointer
        // address as a unique fallback identifier.
        Some(format!("%__inst_{:p}", inst))
    } else if name.starts_with('%') {
        Some(name)
    } else {
        Some(format!("%{}", name))
    }
}

/// Get a debug string representation of the instruction.
fn get_instruction_debug_string(inst: LLVMValueRef) -> String {
    // SAFETY: `LLVMPrintValueToString` allocates a C string with the value's
    // textual LLVM IR representation. We must free it.
    let c_str = unsafe { LLVMPrintValueToString(inst) };
    if c_str.is_null() {
        return "<unknown>".to_string();
    }
    let result = unsafe { CStr::from_ptr(c_str) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: `c_str` was allocated by LLVM and must be freed.
    unsafe { LLVMDisposeMessage(c_str) };
    result
}

// ──────────────────────────────────────────────────────────────────────────
// Call instruction helpers
// ──────────────────────────────────────────────────────────────────────────

/// Extract the callee function name from a call instruction.
fn extract_call_callee_from_llvm(inst: LLVMValueRef) -> Option<String> {
    // SAFETY: For call instructions, the called function is the last operand
    // if it's a direct call (LLVM stores callee as the last operand).
    // `LLVMGetCalledValue` returns the callee value.
    let callee_val = unsafe { LLVMGetCalledValue(inst) };
    if callee_val.is_null() {
        return None;
    }

    // Check if it's a direct call (function, not a function pointer)
    // SAFETY: `LLVMIsAFunction` returns non-null if the value is a Function.
    let is_func = unsafe { LLVMIsAFunction(callee_val) };
    if !is_func.is_null() {
        let name = get_value_name(callee_val);
        // Filter LLVM intrinsics
        if name.starts_with("llvm.") {
            return None;
        }
        return Some(name);
    }

    // Indirect call — callee is a register/pointer
    let name = get_value_name(callee_val);
    if name.is_empty() {
        Some("<indirect>".to_string())
    } else {
        Some(name)
    }
}

/// Extract the call signature as a string (e.g., "i32 (ptr, i32)").
fn extract_call_signature(inst: LLVMValueRef) -> Option<String> {
    // SAFETY: `LLVMGetCalledFunctionType` returns the function type of the
    // callee (LLVM 14+). If unavailable, we fall back to type_of.
    let func_ty = unsafe { LLVMGetCalledFunctionType(inst) };
    if func_ty.is_null() {
        return None;
    }
    Some(type_to_string(func_ty))
}

// ──────────────────────────────────────────────────────────────────────────
// Atomic RMW helpers
// ──────────────────────────────────────────────────────────────────────────

/// Extract the atomicrmw operation name from an LLVM atomicrmw instruction.
fn extract_atomicrmw_op_name(inst: LLVMValueRef) -> Option<String> {
    // SAFETY: `LLVMGetAtomicRMWBinOp` returns the binary operation enum
    // for the atomicrmw instruction.
    let binop = unsafe { LLVMGetAtomicRMWBinOp(inst) };
    let name = match binop {
        llvm_sys::LLVMAtomicRMWBinOp::LLVMAtomicRMWBinOpXchg => "xchg",
        llvm_sys::LLVMAtomicRMWBinOp::LLVMAtomicRMWBinOpAdd => "add",
        llvm_sys::LLVMAtomicRMWBinOp::LLVMAtomicRMWBinOpSub => "sub",
        llvm_sys::LLVMAtomicRMWBinOp::LLVMAtomicRMWBinOpAnd => "and",
        llvm_sys::LLVMAtomicRMWBinOp::LLVMAtomicRMWBinOpNand => "nand",
        llvm_sys::LLVMAtomicRMWBinOp::LLVMAtomicRMWBinOpOr => "or",
        llvm_sys::LLVMAtomicRMWBinOp::LLVMAtomicRMWBinOpXor => "xor",
        llvm_sys::LLVMAtomicRMWBinOp::LLVMAtomicRMWBinOpMax => "max",
        llvm_sys::LLVMAtomicRMWBinOp::LLVMAtomicRMWBinOpMin => "min",
        llvm_sys::LLVMAtomicRMWBinOp::LLVMAtomicRMWBinOpUMax => "umax",
        llvm_sys::LLVMAtomicRMWBinOp::LLVMAtomicRMWBinOpUMin => "umin",
        llvm_sys::LLVMAtomicRMWBinOp::LLVMAtomicRMWBinOpFAdd => "fadd",
        llvm_sys::LLVMAtomicRMWBinOp::LLVMAtomicRMWBinOpFSub => "fsub",
        _ => return None,
    };
    Some(name.to_string())
}

// ──────────────────────────────────────────────────────────────────────────
// ICMP predicate helpers
// ──────────────────────────────────────────────────────────────────────────

/// Extract the icmp predicate from an LLVM icmp instruction.
fn extract_icmp_predicate(inst: LLVMValueRef) -> Option<String> {
    // SAFETY: `LLVMGetICmpPredicate` returns the predicate enum for icmp.
    let pred = unsafe { LLVMGetICmpPredicate(inst) };
    let name = match pred {
        llvm_sys::LLVMIntPredicate::LLVMIntEQ => "eq",
        llvm_sys::LLVMIntPredicate::LLVMIntNE => "ne",
        llvm_sys::LLVMIntPredicate::LLVMIntUGT => "ugt",
        llvm_sys::LLVMIntPredicate::LLVMIntUGE => "uge",
        llvm_sys::LLVMIntPredicate::LLVMIntULT => "ult",
        llvm_sys::LLVMIntPredicate::LLVMIntULE => "ule",
        llvm_sys::LLVMIntPredicate::LLVMIntSGT => "sgt",
        llvm_sys::LLVMIntPredicate::LLVMIntSGE => "sge",
        llvm_sys::LLVMIntPredicate::LLVMIntSLT => "slt",
        llvm_sys::LLVMIntPredicate::LLVMIntSLE => "sle",
    };
    Some(name.to_string())
}

// ──────────────────────────────────────────────────────────────────────────
// GEP element type extraction
// ──────────────────────────────────────────────────────────────────────────

/// Extract the element type from a GEP instruction.
fn extract_gep_element_type(inst: LLVMValueRef) -> Option<String> {
    // SAFETY: `LLVMGetGEPSourceElementType` returns the source element type
    // of a GEP instruction directly from the instruction's metadata. This
    // works correctly with opaque pointers (LLVM 15+).
    let elem_ty = unsafe { LLVMGetGEPSourceElementType(inst) };
    if !elem_ty.is_null() {
        Some(type_to_string(elem_ty))
    } else {
        None
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Calling convention mapping
// ──────────────────────────────────────────────────────────────────────────

/// Map a numeric calling convention ID to a human-readable name.
fn calling_convention_name(cc_id: u32) -> Option<String> {
    match cc_id {
        0 => None, // C calling convention (default, don't record)
        8 => Some("fastcc".to_string()),
        9 => Some("coldcc".to_string()),
        10 => Some("webkit_jscc".to_string()),
        11 => Some("anyregcc".to_string()),
        14 => Some("preserve_mostcc".to_string()),
        15 => Some("preserve_allcc".to_string()),
        16 => Some("swiftcc".to_string()),
        // Unknown convention — still record with numeric ID
        n => Some(format!("cc_{}", n)),
    }
}
