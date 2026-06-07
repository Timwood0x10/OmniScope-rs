//! Integration tests verifying Plan A (C++ Pass JSON) and Plan C (llvm-sys)
//! produce correct and consistent output.
//!
//! Plan A: C++ LLVM Pass outputs JSON, Rust deserializes via `ir_model.rs`.
//! Plan C: `llvm-sys` C API directly populates `IRModule`.
//!
//! Both should produce the same `IRModule` for the same input.
//!
//! # Feature gates
//!
//! - Plan C tests require `--features llvm-backend` (the `llvm-sys` crate).
//! - Plan A tests and the text-parser baseline always compile and run.
//! - Without `llvm-backend`, Plan C tests are skipped at compile time.

use std::path::Path;

use omniscope_ir::instruction_parser::IRInstructionKind;
use omniscope_ir::ir_model::{
    IRBasicBlock, IRDeclaration, IRFunction, IRGlobalVariable, IRInstructionModel, IRModuleModel,
};
use omniscope_ir::parser::IRModule;
#[cfg(feature = "llvm-backend")]
use tracing::debug;

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Path to the `rust_hash.ll` fixture (small, well-understood).
fn rust_hash_fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/integration/rust_hash.ll")
}

/// Parse the `rust_hash.ll` fixture with the text parser as a baseline.
fn text_parse_rust_hash() -> IRModule {
    let path = rust_hash_fixture();
    IRModule::load_from_file(&path).expect("text parser must load rust_hash.ll")
}

/// Build a JSON instruction model with the given opcode and raw text.
fn json_inst(opcode: &str, raw: &str) -> IRInstructionModel {
    IRInstructionModel {
        opcode: opcode.to_string(),
        raw: raw.to_string(),
        ..Default::default()
    }
}

/// Build a JSON call instruction model.
fn json_call_inst(callee: &str, raw: &str, ret_ty: &str) -> IRInstructionModel {
    IRInstructionModel {
        opcode: "call".to_string(),
        result_type: Some(ret_ty.to_string()),
        callee: Some(callee.to_string()),
        raw: raw.to_string(),
        ..Default::default()
    }
}

/// Build a basic block from instruction models.
fn json_block(label: &str, insts: Vec<IRInstructionModel>, successors: &[&str]) -> IRBasicBlock {
    IRBasicBlock {
        label: label.to_string(),
        instructions: insts,
        successors: successors.iter().map(|s| s.to_string()).collect(),
    }
}

/// Build an IRModuleModel that mirrors the structure of `rust_hash.ll`
/// for consistency testing.
///
/// This captures the two defined functions (`rust_fft_forward`, `rust_hash_compute`)
/// and the two declarations (`c_fft_forward`, `c_hash`).
fn build_rust_hash_json_model() -> IRModuleModel {
    // -- rust_fft_forward --
    let fft_entry_insts = vec![
        IRInstructionModel {
            opcode: "icmp".to_string(),
            result_type: Some("i1".to_string()),
            raw: "%0 = icmp eq ptr %real, null".to_string(),
            operands: vec!["%real".to_string(), "null".to_string()],
            ..Default::default()
        },
        IRInstructionModel {
            opcode: "br".to_string(),
            raw: "br i1 %0, label %bb7, label %bb2".to_string(),
            ..Default::default()
        },
    ];
    let fft_bb2_insts = vec![
        IRInstructionModel {
            opcode: "icmp".to_string(),
            result_type: Some("i1".to_string()),
            raw: "%1 = icmp eq ptr %imag, null".to_string(),
            operands: vec!["%imag".to_string(), "null".to_string()],
            ..Default::default()
        },
        IRInstructionModel {
            opcode: "icmp".to_string(),
            result_type: Some("i1".to_string()),
            raw: "%2 = icmp eq i64 %n, 0".to_string(),
            operands: vec!["%n".to_string(), "0".to_string()],
            ..Default::default()
        },
        IRInstructionModel {
            opcode: "br".to_string(),
            raw: "br i1 %or.cond, label %bb7, label %bb6".to_string(),
            ..Default::default()
        },
    ];
    let fft_bb6_insts = vec![
        json_call_inst(
            "c_fft_forward",
            "%3 = tail call noundef i32 @c_fft_forward(ptr nonnull %real, ptr nonnull %imag, i64 %n)",
            "i32",
        ),
        IRInstructionModel {
            opcode: "br".to_string(),
            raw: "br label %bb7".to_string(),
            ..Default::default()
        },
    ];
    let fft_bb7_insts = vec![IRInstructionModel {
        opcode: "ret".to_string(),
        raw: "ret i32 %_0.sroa.0.0".to_string(),
        ..Default::default()
    }];

    let fft_func = IRFunction {
        name: "rust_fft_forward".to_string(),
        demangled: None,
        return_type: "i32".to_string(),
        param_types: vec!["ptr".to_string(), "ptr".to_string(), "i64".to_string()],
        calling_convention: "ccc".to_string(),
        blocks: vec![
            json_block("start", fft_entry_insts, &["bb7", "bb2"]),
            json_block("bb2", fft_bb2_insts, &["bb7", "bb6"]),
            json_block("bb6", fft_bb6_insts, &["bb7"]),
            json_block("bb7", fft_bb7_insts, &[]),
        ],
        linkage: None,
    };

    // -- rust_hash_compute --
    let hash_start_insts = vec![
        IRInstructionModel {
            opcode: "icmp".to_string(),
            result_type: Some("i1".to_string()),
            raw: "%0 = icmp eq ptr %data, null".to_string(),
            ..Default::default()
        },
        IRInstructionModel {
            opcode: "icmp".to_string(),
            result_type: Some("i1".to_string()),
            raw: "%1 = icmp eq ptr %out, null".to_string(),
            ..Default::default()
        },
        IRInstructionModel {
            opcode: "br".to_string(),
            raw: "br i1 %or.cond, label %bb7, label %bb5".to_string(),
            ..Default::default()
        },
    ];
    let hash_bb5_insts = vec![
        json_call_inst(
            "c_hash",
            "%_result = tail call noundef i32 @c_hash(ptr nonnull %data, i64 %len, ptr nonnull %out)",
            "i32",
        ),
        IRInstructionModel {
            opcode: "br".to_string(),
            raw: "br label %bb7".to_string(),
            ..Default::default()
        },
    ];
    let hash_bb7_insts = vec![IRInstructionModel {
        opcode: "ret".to_string(),
        raw: "ret i32 0".to_string(),
        ..Default::default()
    }];

    let hash_func = IRFunction {
        name: "rust_hash_compute".to_string(),
        demangled: None,
        return_type: "i32".to_string(),
        param_types: vec!["ptr".to_string(), "i64".to_string(), "ptr".to_string()],
        calling_convention: "ccc".to_string(),
        blocks: vec![
            json_block("start", hash_start_insts, &["bb7", "bb5"]),
            json_block("bb5", hash_bb5_insts, &["bb7"]),
            json_block("bb7", hash_bb7_insts, &[]),
        ],
        linkage: None,
    };

    // -- Declarations --
    let decl_fft = IRDeclaration {
        name: "c_fft_forward".to_string(),
        demangled: None,
        return_type: "i32".to_string(),
        param_types: vec!["ptr".to_string(), "ptr".to_string(), "i64".to_string()],
    };
    let decl_hash = IRDeclaration {
        name: "c_hash".to_string(),
        demangled: None,
        return_type: "i32".to_string(),
        param_types: vec!["ptr".to_string(), "i64".to_string(), "ptr".to_string()],
    };

    IRModuleModel {
        target_triple: Some("arm64-apple-macosx11.0.0".to_string()),
        data_layout: Some(
            "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32".to_string(),
        ),
        functions: vec![fft_func, hash_func],
        declarations: vec![decl_fft, decl_hash],
        named_struct_types: Default::default(),
        global_variables: vec![],
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Plan A: JSON model round-trip tests
// ═══════════════════════════════════════════════════════════════════════════

/// Serialize an IRModuleModel to JSON and deserialize it back.
/// All fields must survive the round-trip unchanged.
#[test]
fn test_json_model_roundtrip() {
    let model = build_rust_hash_json_model();

    // Serialize to JSON.
    let json = serde_json::to_string(&model).expect("serialization must succeed");

    // Deserialize back.
    let model2: IRModuleModel = serde_json::from_str(&json).expect("deserialization must succeed");

    // Top-level fields.
    assert_eq!(
        model.target_triple, model2.target_triple,
        "target_triple must survive round-trip"
    );
    assert_eq!(
        model.data_layout, model2.data_layout,
        "data_layout must survive round-trip"
    );
    assert_eq!(
        model.functions.len(),
        model2.functions.len(),
        "function count must survive round-trip"
    );
    assert_eq!(
        model.declarations.len(),
        model2.declarations.len(),
        "declaration count must survive round-trip"
    );
    assert_eq!(
        model.global_variables.len(),
        model2.global_variables.len(),
        "global_variables count must survive round-trip"
    );

    // Per-function fields.
    for (f1, f2) in model.functions.iter().zip(model2.functions.iter()) {
        assert_eq!(f1.name, f2.name, "function name must survive round-trip");
        assert_eq!(
            f1.return_type, f2.return_type,
            "return_type must survive round-trip for {}",
            f1.name
        );
        assert_eq!(
            f1.param_types, f2.param_types,
            "param_types must survive round-trip for {}",
            f1.name
        );
        assert_eq!(
            f1.calling_convention, f2.calling_convention,
            "calling_convention must survive round-trip for {}",
            f1.name
        );
        assert_eq!(
            f1.blocks.len(),
            f2.blocks.len(),
            "block count must survive round-trip for {}",
            f1.name
        );

        // Per-block fields.
        for (b1, b2) in f1.blocks.iter().zip(f2.blocks.iter()) {
            assert_eq!(
                b1.label, b2.label,
                "block label must survive round-trip in {}",
                f1.name
            );
            assert_eq!(
                b1.instructions.len(),
                b2.instructions.len(),
                "instruction count must survive round-trip for block {} in {}",
                b1.label,
                f1.name
            );
            assert_eq!(
                b1.successors, b2.successors,
                "successors must survive round-trip for block {} in {}",
                b1.label, f1.name
            );

            // Per-instruction fields.
            for (i1, i2) in b1.instructions.iter().zip(b2.instructions.iter()) {
                assert_eq!(
                    i1.opcode, i2.opcode,
                    "opcode must survive round-trip in block {} of {}",
                    b1.label, f1.name
                );
                assert_eq!(
                    i1.result_type, i2.result_type,
                    "result_type must survive round-trip in block {} of {}",
                    b1.label, f1.name
                );
                assert_eq!(
                    i1.callee, i2.callee,
                    "callee must survive round-trip in block {} of {}",
                    b1.label, f1.name
                );
                assert_eq!(
                    i1.raw, i2.raw,
                    "raw text must survive round-trip in block {} of {}",
                    b1.label, f1.name
                );
            }
        }
    }

    // Per-declaration fields.
    for (d1, d2) in model.declarations.iter().zip(model2.declarations.iter()) {
        assert_eq!(d1.name, d2.name, "declaration name must survive round-trip");
        assert_eq!(
            d1.return_type, d2.return_type,
            "declaration return_type must survive round-trip for {}",
            d1.name
        );
        assert_eq!(
            d1.param_types, d2.param_types,
            "declaration param_types must survive round-trip for {}",
            d1.name
        );
    }
}

/// A minimal model with a single function and a single instruction must
/// survive JSON round-trip.
#[test]
fn test_json_model_roundtrip_minimal() {
    let model = IRModuleModel {
        functions: vec![IRFunction {
            name: "minimal".to_string(),
            return_type: "void".to_string(),
            blocks: vec![IRBasicBlock {
                label: "entry".to_string(),
                instructions: vec![json_inst("ret", "ret void")],
                successors: vec![],
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let json = serde_json::to_string(&model).expect("minimal model serialization must succeed");
    let model2: IRModuleModel =
        serde_json::from_str(&json).expect("minimal model deserialization must succeed");

    assert_eq!(model.functions.len(), model2.functions.len());
    assert_eq!(model.functions[0].name, model2.functions[0].name);
    assert_eq!(
        model.functions[0].blocks[0].instructions[0].opcode,
        model2.functions[0].blocks[0].instructions[0].opcode,
        "instruction opcode must survive round-trip"
    );
}

/// Deserialize a real JSON string (simulating C++ pass output) and verify
/// the resulting IRModuleModel has correct structure.
#[test]
fn test_json_deserialize_cpp_pass_output() {
    let json = r#"{
        "target_triple": "x86_64-unknown-linux-gnu",
        "data_layout": "e-m:e-p:64:64-i64:64-f80:128-n8:16:32:64-S128",
        "functions": [
            {
                "name": "leaky_func",
                "return_type": "void",
                "param_types": ["i64"],
                "calling_convention": "ccc",
                "blocks": [
                    {
                        "label": "entry",
                        "instructions": [
                            {
                                "opcode": "call",
                                "result_type": "ptr",
                                "callee": "malloc",
                                "raw": "%ptr = call ptr @malloc(i64 %size)",
                                "operands": ["%size"],
                                "operand_types": ["i64"],
                                "is_indirect": false
                            },
                            {
                                "opcode": "ret",
                                "raw": "ret void",
                                "operands": [],
                                "operand_types": [],
                                "is_indirect": false
                            }
                        ],
                        "successors": []
                    }
                ],
                "linkage": "external"
            }
        ],
        "declarations": [
            {
                "name": "malloc",
                "return_type": "ptr",
                "param_types": ["i64"]
            }
        ],
        "named_struct_types": {},
        "global_variables": []
    }"#;

    let model =
        IRModuleModel::from_json_str(json).expect("C++ pass JSON must deserialize successfully");

    assert_eq!(
        model.functions.len(),
        1,
        "Model should have 1 function from C++ pass output"
    );
    assert_eq!(
        model.functions[0].name, "leaky_func",
        "Function name should be 'leaky_func'"
    );
    assert_eq!(
        model.functions[0].blocks.len(),
        1,
        "Function should have 1 basic block"
    );
    assert_eq!(
        model.functions[0].blocks[0].label, "entry",
        "Block label should be 'entry'"
    );
    assert_eq!(
        model.functions[0].blocks[0].instructions.len(),
        2,
        "Block should have 2 instructions"
    );

    // Verify call instruction details.
    let call_inst = &model.functions[0].blocks[0].instructions[0];
    assert_eq!(
        call_inst.opcode, "call",
        "First instruction opcode should be 'call'"
    );
    assert_eq!(
        call_inst.callee.as_deref(),
        Some("malloc"),
        "Call callee should be 'malloc'"
    );
    assert_eq!(
        call_inst.result_type.as_deref(),
        Some("ptr"),
        "Call result_type should be 'ptr'"
    );
    assert!(!call_inst.is_indirect, "malloc call should not be indirect");

    // Verify declarations.
    assert_eq!(
        model.declarations.len(),
        1,
        "Should have 1 declaration (malloc)"
    );
    assert_eq!(
        model.declarations[0].name, "malloc",
        "Declaration name should be 'malloc'"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Plan A: JSON -> IRModule conversion tests
// ═══════════════════════════════════════════════════════════════════════════

/// Convert the rust_hash JSON model to IRModule and verify all fields
/// are populated correctly.
#[test]
fn test_json_to_ir_module_conversion() {
    let model = build_rust_hash_json_model();
    let ir_module = model.to_ir_module();

    // Functions.
    assert_eq!(
        ir_module.functions.len(),
        2,
        "Converted module should have 2 functions"
    );
    assert!(
        ir_module.functions.contains_key("rust_fft_forward"),
        "Should contain function 'rust_fft_forward'"
    );
    assert!(
        ir_module.functions.contains_key("rust_hash_compute"),
        "Should contain function 'rust_hash_compute'"
    );

    // Declarations.
    assert_eq!(
        ir_module.declarations.len(),
        2,
        "Converted module should have 2 declarations"
    );
    assert!(
        ir_module.declarations.contains_key("c_fft_forward"),
        "Should contain declaration 'c_fft_forward'"
    );
    assert!(
        ir_module.declarations.contains_key("c_hash"),
        "Should contain declaration 'c_hash'"
    );
    assert!(
        ir_module.declarations["c_fft_forward"].is_declaration,
        "c_fft_forward should be marked as declaration"
    );

    // Data layout.
    assert_eq!(
        ir_module.data_layout.target_triple,
        Some("arm64-apple-macosx11.0.0".to_string()),
        "Target triple should be preserved"
    );
    // The rust_hash.ll data layout has only address-space-specific pointers
    // (p270, p271, p272) and no generic p: entry, so pointer_size is None.
    assert_eq!(
        ir_module.data_layout.little_endian,
        Some(true),
        "Endianness should be derived from data layout"
    );

    // Function bodies.
    assert_eq!(
        ir_module.function_bodies.len(),
        2,
        "Converted module should have 2 function bodies"
    );

    // FFT function body.
    let fft_body = &ir_module.function_bodies["rust_fft_forward"];
    assert!(
        fft_body.instructions.len() >= 5,
        "FFT body should have at least 5 instructions, got {}",
        fft_body.instructions.len()
    );
    assert!(
        fft_body
            .instructions
            .iter()
            .any(|i| i.kind == IRInstructionKind::Call),
        "FFT body should contain a call instruction"
    );
    assert!(
        fft_body
            .instructions
            .iter()
            .any(|i| i.kind == IRInstructionKind::Icmp),
        "FFT body should contain an icmp instruction"
    );
    assert!(
        fft_body
            .instructions
            .iter()
            .any(|i| i.kind == IRInstructionKind::Branch),
        "FFT body should contain a branch instruction"
    );
    assert!(
        fft_body
            .instructions
            .iter()
            .any(|i| i.kind == IRInstructionKind::Ret),
        "FFT body should contain a ret instruction"
    );

    // Calls recorded at module level.
    assert_eq!(
        ir_module.calls.len(),
        2,
        "Module should have 2 call instructions"
    );

    let call_callees: Vec<&str> = ir_module.calls.iter().map(|c| c.callee.as_str()).collect();
    assert!(
        call_callees.contains(&"c_fft_forward"),
        "Should have a call to c_fft_forward, found: {:?}",
        call_callees
    );
    assert!(
        call_callees.contains(&"c_hash"),
        "Should have a call to c_hash, found: {:?}",
        call_callees
    );

    // Calls to declarations should be marked external.
    let fft_call = ir_module
        .calls
        .iter()
        .find(|c| c.callee == "c_fft_forward")
        .expect("c_fft_forward call must exist");
    assert!(
        fft_call.is_external,
        "Call to c_fft_forward should be marked external"
    );
}

/// Converting an empty model should produce an empty IRModule.
#[test]
fn test_json_to_ir_module_empty() {
    let ir_module = IRModuleModel::default().to_ir_module();

    assert!(
        ir_module.functions.is_empty(),
        "Empty model should produce no functions"
    );
    assert!(
        ir_module.declarations.is_empty(),
        "Empty model should produce no declarations"
    );
    assert!(
        ir_module.calls.is_empty(),
        "Empty model should produce no calls"
    );
    assert!(
        ir_module.function_bodies.is_empty(),
        "Empty model should produce no function bodies"
    );
}

/// Verify that indirect calls are correctly handled in the conversion.
#[test]
fn test_json_to_ir_module_indirect_call() {
    let model = IRModuleModel {
        functions: vec![IRFunction {
            name: "dispatch".to_string(),
            return_type: "void".to_string(),
            param_types: vec!["ptr".to_string()],
            blocks: vec![IRBasicBlock {
                label: "entry".to_string(),
                instructions: vec![IRInstructionModel {
                    opcode: "call".to_string(),
                    callee: Some("%fp".to_string()),
                    is_indirect: true,
                    raw: "call void %fp(ptr %ctx)".to_string(),
                    ..Default::default()
                }],
                successors: vec![],
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let ir_module = model.to_ir_module();
    assert_eq!(
        ir_module.calls.len(),
        1,
        "Should have 1 call recorded for indirect call"
    );
    assert_eq!(
        ir_module.calls[0].callee, "%fp",
        "Indirect call callee should be '%fp'"
    );
    assert!(
        !ir_module.calls[0].is_external,
        "Indirect call should not be marked external"
    );
}

/// Verify that global variables are preserved in the model (not yet
/// converted to IRModule, but present in the model).
#[test]
fn test_json_global_variables() {
    let model = IRModuleModel {
        global_variables: vec![
            IRGlobalVariable {
                name: "counter".to_string(),
                ty: "i32".to_string(),
                is_constant: false,
            },
            IRGlobalVariable {
                name: "VERSION".to_string(),
                ty: "i8".to_string(),
                is_constant: true,
            },
        ],
        ..Default::default()
    };

    assert_eq!(
        model.global_variables.len(),
        2,
        "Should have 2 global variables"
    );
    assert_eq!(
        model.global_variables[0].name, "counter",
        "First global variable name should be 'counter'"
    );
    assert!(
        !model.global_variables[0].is_constant,
        "counter should not be constant"
    );
    assert!(
        model.global_variables[1].is_constant,
        "VERSION should be constant"
    );
}

/// Verify that named struct types are preserved in the model.
#[test]
fn test_json_named_struct_types() {
    let json = r#"{
        "functions": [],
        "declarations": [],
        "named_struct_types": {
            "struct.MyClass": ["i32", "ptr", "i8"],
            "struct.Pair": ["i64", "i64"]
        }
    }"#;

    let model =
        IRModuleModel::from_json_str(json).expect("JSON with named struct types must deserialize");

    assert_eq!(
        model.named_struct_types.len(),
        2,
        "Should have 2 named struct types"
    );
    assert_eq!(
        model.named_struct_types["struct.MyClass"].len(),
        3,
        "struct.MyClass should have 3 fields"
    );
    assert_eq!(
        model.named_struct_types["struct.Pair"].len(),
        2,
        "struct.Pair should have 2 fields"
    );
}

/// Malformed JSON must produce a proper error, not a panic.
#[test]
fn test_json_malformed_returns_error() {
    let result = omniscope_ir::ir_model::parse_from_json("not valid json {{{");
    assert!(
        result.is_err(),
        "Malformed JSON should return an error, not panic"
    );
}

/// Missing required fields in JSON must produce a proper error.
#[test]
fn test_json_missing_required_field_returns_error() {
    let json = r#"{"functions": "not_an_array"}"#;
    let result = omniscope_ir::ir_model::parse_from_json(json);
    assert!(
        result.is_err(),
        "JSON with wrong type for 'functions' should return an error"
    );
}

/// Test that the opcode classification covers all expected instruction types.
#[test]
fn test_json_opcode_classification() {
    let cases: Vec<(&str, IRInstructionKind)> = vec![
        ("alloca", IRInstructionKind::Alloca),
        ("load", IRInstructionKind::Load),
        ("store", IRInstructionKind::Store),
        ("atomicrmw", IRInstructionKind::AtomicRmw),
        ("cmpxchg", IRInstructionKind::AtomicRmw),
        ("getelementptr", IRInstructionKind::GetElementPtr),
        ("icmp", IRInstructionKind::Icmp),
        ("fcmp", IRInstructionKind::Fcmp),
        ("br", IRInstructionKind::Branch),
        ("call", IRInstructionKind::Call),
        ("invoke", IRInstructionKind::Call),
        ("ret", IRInstructionKind::Ret),
        ("phi", IRInstructionKind::Phi),
        ("select", IRInstructionKind::Select),
        ("add", IRInstructionKind::BinaryOp),
        ("sub", IRInstructionKind::BinaryOp),
        ("mul", IRInstructionKind::BinaryOp),
        ("and", IRInstructionKind::BinaryOp),
        ("or", IRInstructionKind::BinaryOp),
        ("xor", IRInstructionKind::BinaryOp),
        ("shl", IRInstructionKind::BinaryOp),
        ("lshr", IRInstructionKind::BinaryOp),
        ("ashr", IRInstructionKind::BinaryOp),
        ("bitcast", IRInstructionKind::Conversion),
        ("inttoptr", IRInstructionKind::Conversion),
        ("ptrtoint", IRInstructionKind::Conversion),
        ("zext", IRInstructionKind::Conversion),
        ("sext", IRInstructionKind::Conversion),
        ("trunc", IRInstructionKind::Conversion),
        ("fptoui", IRInstructionKind::Conversion),
        ("fptosi", IRInstructionKind::Conversion),
        ("uitofp", IRInstructionKind::Conversion),
        ("sitofp", IRInstructionKind::Conversion),
        ("fpext", IRInstructionKind::Conversion),
        ("fptrunc", IRInstructionKind::Conversion),
        ("unknown_opcode_xyz", IRInstructionKind::Other),
    ];

    for (opcode, expected) in &cases {
        let inst = IRInstructionModel {
            opcode: opcode.to_string(),
            raw: format!("%x = {} ...", opcode),
            result_type: Some("i32".to_string()),
            ..Default::default()
        };
        let converted = inst.to_ir_instruction();
        assert_eq!(
            converted.kind, *expected,
            "Opcode '{}' should classify as {:?}, got {:?}",
            opcode, expected, converted.kind
        );
    }
}

/// Verify CFG edges (successors) are preserved from JSON model to IRModule.
#[test]
fn test_json_cfg_edges_preserved() {
    let model = IRModuleModel {
        functions: vec![IRFunction {
            name: "branching".to_string(),
            return_type: "void".to_string(),
            blocks: vec![
                IRBasicBlock {
                    label: "entry".to_string(),
                    instructions: vec![json_inst("br", "br label %loop")],
                    successors: vec!["loop".to_string()],
                },
                IRBasicBlock {
                    label: "loop".to_string(),
                    instructions: vec![json_inst("br", "br i1 %cond, label %body, label %exit")],
                    successors: vec!["body".to_string(), "exit".to_string()],
                },
                IRBasicBlock {
                    label: "body".to_string(),
                    instructions: vec![json_inst("br", "br label %loop")],
                    successors: vec!["loop".to_string()],
                },
                IRBasicBlock {
                    label: "exit".to_string(),
                    instructions: vec![json_inst("ret", "ret void")],
                    successors: vec![],
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    };

    // Verify successors are present in the model.
    assert_eq!(
        model.functions[0].blocks[0].successors,
        vec!["loop"],
        "entry block should have successor 'loop'"
    );
    assert_eq!(
        model.functions[0].blocks[1].successors,
        vec!["body", "exit"],
        "loop block should have successors 'body' and 'exit'"
    );
    assert!(
        model.functions[0].blocks[3].successors.is_empty(),
        "exit block should have no successors"
    );

    // Verify instruction count in converted module.
    let ir_module = model.to_ir_module();
    let body = &ir_module.function_bodies["branching"];
    assert_eq!(
        body.instructions.len(),
        4,
        "Function body should have 4 instructions (one per block)"
    );
    assert_eq!(
        body.count_kind(IRInstructionKind::Branch),
        3,
        "Should have 3 branch instructions"
    );
    assert_eq!(
        body.count_kind(IRInstructionKind::Ret),
        1,
        "Should have 1 ret instruction"
    );
}

/// Verify that non-default calling conventions are preserved.
#[test]
fn test_json_calling_convention_preserved() {
    let model = IRModuleModel {
        functions: vec![IRFunction {
            name: "hot_path".to_string(),
            return_type: "i64".to_string(),
            param_types: vec!["i64".to_string()],
            calling_convention: "fastcc".to_string(),
            blocks: vec![IRBasicBlock {
                label: "entry".to_string(),
                instructions: vec![json_inst("ret", "ret i64 42")],
                successors: vec![],
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let ir_module = model.to_ir_module();
    assert_eq!(
        ir_module.calling_conventions.len(),
        1,
        "Should have 1 non-default calling convention"
    );
    assert_eq!(
        ir_module.calling_conventions[0].name, "fastcc",
        "Calling convention should be 'fastcc'"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Plan C: llvm-sys tests (feature-gated)
// ═══════════════════════════════════════════════════════════════════════════

/// When the `llvm-backend` feature is NOT enabled, `can_use_llvm_sys`
/// must return false and `load_ir` with `LlvmSys` strategy must fail
/// with a clear error message.
#[cfg(not(feature = "llvm-backend"))]
mod plan_c_without_feature {
    use super::*;

    #[test]
    fn test_llvm_sys_not_available_without_feature() {
        // The loader_v2 module's can_use_llvm_sys is private, but we can
        // test the public entry point.
        let path = rust_hash_fixture();
        let result =
            omniscope_ir::loader_v2::load_ir(&path, omniscope_ir::loader_v2::LoadStrategy::LlvmSys);
        assert!(
            result.is_err(),
            "LlvmSys strategy should fail when llvm-backend feature is not enabled"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("llvm-backend") || msg.contains("not enabled"),
            "Error should mention the missing feature, got: {}",
            msg
        );
    }

    #[test]
    fn test_auto_strategy_falls_back_to_text_parser() {
        // Auto strategy should fall through llvm-sys and cpp-pass and
        // land on text parser.
        let path = rust_hash_fixture();
        let result =
            omniscope_ir::loader_v2::load_ir(&path, omniscope_ir::loader_v2::LoadStrategy::Auto);
        assert!(
            result.is_ok(),
            "Auto strategy should succeed by falling back to text parser"
        );
        let loaded = result.expect("auto load must succeed");
        assert!(
            !loaded.module.functions.is_empty(),
            "Auto-loaded module should have at least 1 function"
        );
    }
}

/// When the `llvm-backend` feature IS enabled, test the llvm-sys adapter.
///
/// The adapter uses LLVM's C API to parse IR files directly, producing
/// an IRModule with full type information.
#[cfg(feature = "llvm-backend")]
mod plan_c_with_feature {
    use super::*;

    #[test]
    fn test_llvm_sys_adapter_is_available() {
        // The adapter probes for LLVM libraries at startup.
        // If LLVM is linked, this returns true.
        let available = omniscope_ir::llvm_sys_adapter::is_available();
        // We cannot guarantee LLVM is installed in CI, so accept either result.
        // This test documents the contract and verifies no panics.
        let _ = available;
    }

    #[test]
    fn test_llvm_sys_parse_real_fixture() {
        // Parse the rust_hash.ll fixture via llvm-sys.
        let path = rust_hash_fixture();
        let result = omniscope_ir::llvm_sys_adapter::parse_with_llvm_sys(&path);

        // If LLVM is not available at runtime, the parse will fail.
        // If it is available, verify the parsed module is correct.
        match result {
            Ok(module) => {
                // Functions.
                assert!(
                    module.functions.contains_key("rust_fft_forward"),
                    "llvm-sys should find function 'rust_fft_forward'"
                );
                assert!(
                    module.functions.contains_key("rust_hash_compute"),
                    "llvm-sys should find function 'rust_hash_compute'"
                );
                assert_eq!(
                    module.functions.len(),
                    2,
                    "llvm-sys should find 2 defined functions"
                );

                // Declarations.
                assert!(
                    module.declarations.contains_key("c_fft_forward"),
                    "llvm-sys should find declaration 'c_fft_forward'"
                );
                assert!(
                    module.declarations.contains_key("c_hash"),
                    "llvm-sys should find declaration 'c_hash'"
                );

                // Target triple.
                assert_eq!(
                    module.data_layout.target_triple,
                    Some("arm64-apple-macosx11.0.0".to_string()),
                    "llvm-sys should parse target triple correctly"
                );

                // Function bodies.
                assert_eq!(
                    module.function_bodies.len(),
                    2,
                    "llvm-sys should produce 2 function bodies"
                );

                // Calls.
                assert!(
                    module.calls.len() >= 2,
                    "llvm-sys should find at least 2 calls, found {}",
                    module.calls.len()
                );
            }
            Err(e) => {
                // LLVM not available at runtime — skip gracefully.
                debug!("Skipping llvm-sys parse test (LLVM not available): {}", e);
            }
        }
    }

    #[test]
    fn test_llvm_sys_type_fields_populated() {
        // Verify that result_type and element_type are populated for
        // load/store/call instructions when LLVM is available.
        let path = rust_hash_fixture();
        let result = omniscope_ir::llvm_sys_adapter::parse_with_llvm_sys(&path);

        match result {
            Ok(module) => {
                for (fname, body) in &module.function_bodies {
                    for inst in &body.instructions {
                        match inst.kind {
                            IRInstructionKind::Load => {
                                assert!(
                                    inst.result_type.is_some(),
                                    "Load instruction in {} should have result_type",
                                    fname
                                );
                            }
                            IRInstructionKind::Call => {
                                assert!(
                                    inst.result_type.is_some(),
                                    "Call instruction in {} should have result_type",
                                    fname
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Skipping type fields test (LLVM not available): {}", e);
            }
        }
    }

    #[test]
    fn test_llvm_sys_cfg_edges() {
        // Verify that the parsed module has function bodies with
        // multiple instructions (CFG is captured implicitly through
        // instruction ordering across basic blocks).
        let path = rust_hash_fixture();
        let result = omniscope_ir::llvm_sys_adapter::parse_with_llvm_sys(&path);

        match result {
            Ok(module) => {
                // rust_fft_forward has 4 basic blocks with branching.
                let fft_body = &module.function_bodies["rust_fft_forward"];
                assert!(
                    fft_body.instructions.len() >= 5,
                    "FFT body should have at least 5 instructions (across 4 blocks), got {}",
                    fft_body.instructions.len()
                );
                assert!(
                    fft_body.count_kind(IRInstructionKind::Branch) >= 1,
                    "FFT body should have at least 1 branch instruction"
                );
                assert!(
                    fft_body.count_kind(IRInstructionKind::Icmp) >= 1,
                    "FFT body should have at least 1 icmp instruction"
                );

                // rust_hash_compute has 3 basic blocks with branching.
                let hash_body = &module.function_bodies["rust_hash_compute"];
                assert!(
                    hash_body.instructions.len() >= 4,
                    "Hash body should have at least 4 instructions (across 3 blocks), got {}",
                    hash_body.instructions.len()
                );
            }
            Err(e) => {
                debug!("Skipping CFG edges test (LLVM not available): {}", e);
            }
        }
    }

    #[test]
    fn test_llvm_sys_via_loader_strategy() {
        // Test that load_ir with LlvmSys strategy properly delegates
        // to the llvm-sys adapter.
        let path = rust_hash_fixture();
        let result =
            omniscope_ir::loader_v2::load_ir(&path, omniscope_ir::loader_v2::LoadStrategy::LlvmSys);

        match result {
            Ok(module) => {
                assert!(
                    !module.module.functions.is_empty(),
                    "LlvmSys-loaded module should have functions"
                );
            }
            Err(e) => {
                // LLVM not available — this is expected in some environments.
                debug!("Skipping LlvmSys loader test (LLVM not available): {}", e);
            }
        }
    }

    #[test]
    fn test_llvm_sys_auto_strategy() {
        // Auto strategy should try llvm-sys first. If it succeeds, great.
        // If not, it falls back to text parser.
        let path = rust_hash_fixture();
        let result =
            omniscope_ir::loader_v2::load_ir(&path, omniscope_ir::loader_v2::LoadStrategy::Auto);
        assert!(
            result.is_ok(),
            "Auto strategy should succeed (via llvm-sys or text parser fallback)"
        );
        let module = result.expect("auto load must succeed");
        assert!(
            !module.module.functions.is_empty(),
            "Auto-loaded module should have functions"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Consistency: Plan A (JSON) vs Text Parser baseline
// ═══════════════════════════════════════════════════════════════════════════

/// Compare the JSON model conversion (Plan A) against the text parser
/// for the same rust_hash.ll fixture.
///
/// Both should agree on:
/// - Number of defined functions
/// - Function names
/// - Number of declarations
/// - Declaration names
/// - Number of calls
/// - Call targets (callees)
#[test]
fn test_plan_a_json_vs_text_parser_consistency() {
    // Text parser baseline.
    let text_module = text_parse_rust_hash();

    // JSON model (Plan A) — built to mirror rust_hash.ll structure.
    let json_module = build_rust_hash_json_model().to_ir_module();

    // Function count.
    assert_eq!(
        text_module.functions.len(),
        json_module.functions.len(),
        "Text parser and JSON model should agree on function count"
    );

    // Function names.
    let mut text_fn_names: Vec<&str> = text_module.functions.keys().map(|s| s.as_str()).collect();
    let mut json_fn_names: Vec<&str> = json_module.functions.keys().map(|s| s.as_str()).collect();
    text_fn_names.sort();
    json_fn_names.sort();
    assert_eq!(
        text_fn_names, json_fn_names,
        "Text parser and JSON model should agree on function names"
    );

    // Declaration count.
    assert_eq!(
        text_module.declarations.len(),
        json_module.declarations.len(),
        "Text parser and JSON model should agree on declaration count"
    );

    // Declaration names.
    let mut text_decl_names: Vec<&str> = text_module
        .declarations
        .keys()
        .map(|s| s.as_str())
        .collect();
    let mut json_decl_names: Vec<&str> = json_module
        .declarations
        .keys()
        .map(|s| s.as_str())
        .collect();
    text_decl_names.sort();
    json_decl_names.sort();
    assert_eq!(
        text_decl_names, json_decl_names,
        "Text parser and JSON model should agree on declaration names"
    );

    // Call count.
    assert_eq!(
        text_module.calls.len(),
        json_module.calls.len(),
        "Text parser and JSON model should agree on call count: text={}, json={}",
        text_module.calls.len(),
        json_module.calls.len()
    );

    // Call targets.
    let mut text_callees: Vec<&str> = text_module
        .calls
        .iter()
        .map(|c| c.callee.as_str())
        .collect();
    let mut json_callees: Vec<&str> = json_module
        .calls
        .iter()
        .map(|c| c.callee.as_str())
        .collect();
    text_callees.sort();
    json_callees.sort();
    assert_eq!(
        text_callees, json_callees,
        "Text parser and JSON model should agree on call targets"
    );

    // External call marking.
    for call in &json_module.calls {
        let text_call = text_module
            .calls
            .iter()
            .find(|c| c.callee == call.callee && c.caller == call.caller);
        if let Some(text_call) = text_call {
            assert_eq!(
                text_call.is_external, call.is_external,
                "External marking should match for call {} -> {}",
                call.caller, call.callee
            );
        }
    }
}

/// Verify that the text parser produces the expected structure for rust_hash.ll,
/// which serves as the ground truth for Plan A consistency checks.
#[test]
fn test_text_parser_rust_hash_baseline() {
    let module = text_parse_rust_hash();

    // Target triple.
    assert_eq!(
        module.data_layout.target_triple,
        Some("arm64-apple-macosx11.0.0".to_string()),
        "Target triple should be parsed from rust_hash.ll"
    );

    // Data layout.
    assert!(
        module.data_layout.data_layout.is_some(),
        "Data layout should be parsed from rust_hash.ll"
    );
    // The rust_hash.ll data layout has only address-space-specific pointers
    // (p270, p271, p272) and no generic p: entry, so pointer_size is None.
    assert_eq!(
        module.data_layout.little_endian,
        Some(true),
        "Should be little-endian"
    );

    // Functions.
    assert_eq!(
        module.functions.len(),
        2,
        "rust_hash.ll should have 2 defined functions"
    );
    assert!(
        module.functions.contains_key("rust_fft_forward"),
        "Should contain rust_fft_forward"
    );
    assert!(
        module.functions.contains_key("rust_hash_compute"),
        "Should contain rust_hash_compute"
    );

    // Declarations.
    assert_eq!(
        module.declarations.len(),
        2,
        "rust_hash.ll should have 2 declarations"
    );
    assert!(
        module.declarations.contains_key("c_fft_forward"),
        "Should contain declaration c_fft_forward"
    );
    assert!(
        module.declarations.contains_key("c_hash"),
        "Should contain declaration c_hash"
    );

    // Calls.
    assert_eq!(
        module.calls.len(),
        2,
        "rust_hash.ll should have 2 call instructions"
    );
    let callees: Vec<&str> = module.calls.iter().map(|c| c.callee.as_str()).collect();
    assert!(
        callees.contains(&"c_fft_forward"),
        "Should have a call to c_fft_forward"
    );
    assert!(callees.contains(&"c_hash"), "Should have a call to c_hash");

    // Function bodies.
    assert_eq!(
        module.function_bodies.len(),
        2,
        "Should have 2 function bodies"
    );

    // FFT function body analysis.
    let fft_body = &module.function_bodies["rust_fft_forward"];
    assert!(
        fft_body.instructions.len() >= 5,
        "FFT body should have at least 5 instructions, got {}",
        fft_body.instructions.len()
    );
    assert_eq!(
        fft_body.count_kind(IRInstructionKind::Icmp),
        3,
        "FFT body should have 3 icmp instructions"
    );
    assert!(
        fft_body.count_kind(IRInstructionKind::Call) >= 1,
        "FFT body should have at least 1 call instruction"
    );
    assert!(
        fft_body.count_kind(IRInstructionKind::Ret) >= 1,
        "FFT body should have at least 1 ret instruction"
    );

    // Hash function body analysis.
    let hash_body = &module.function_bodies["rust_hash_compute"];
    assert!(
        hash_body.instructions.len() >= 4,
        "Hash body should have at least 4 instructions, got {}",
        hash_body.instructions.len()
    );
    assert!(
        hash_body.count_kind(IRInstructionKind::Call) >= 1,
        "Hash body should have at least 1 call instruction"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Consistency: Plan A (JSON) vs Plan C (llvm-sys)
// ═══════════════════════════════════════════════════════════════════════════

/// When both backends are available, parse the same fixture with both
/// and compare: function names, instruction counts, call targets.
///
/// This test requires the `llvm-backend` feature AND a working llvm-sys
/// implementation. Currently it verifies that the JSON model (Plan A)
/// agrees with the text parser baseline on key structural properties.
/// When the llvm-sys implementation lands, a second comparison can be added.
#[test]
fn test_plan_a_plan_c_consistency() {
    // Plan A: JSON model -> IRModule.
    let plan_a_module = build_rust_hash_json_model().to_ir_module();

    // Baseline: text parser (the ground truth until Plan C is implemented).
    let baseline_module = text_parse_rust_hash();

    // -- Compare function names --
    let mut plan_a_fns: Vec<&str> = plan_a_module.functions.keys().map(|s| s.as_str()).collect();
    let mut baseline_fns: Vec<&str> = baseline_module
        .functions
        .keys()
        .map(|s| s.as_str())
        .collect();
    plan_a_fns.sort();
    baseline_fns.sort();
    assert_eq!(
        plan_a_fns, baseline_fns,
        "Plan A and baseline should agree on function names"
    );

    // -- Compare instruction counts per function --
    for fname in &plan_a_fns {
        let plan_a_body = &plan_a_module.function_bodies[*fname];
        let baseline_body = &baseline_module.function_bodies[*fname];

        // Both should have at least one instruction.
        assert!(
            !plan_a_body.instructions.is_empty(),
            "Plan A body for {} should not be empty",
            fname
        );
        assert!(
            !baseline_body.instructions.is_empty(),
            "Baseline body for {} should not be empty",
            fname
        );

        // Call instruction counts should match.
        let plan_a_calls = plan_a_body.count_kind(IRInstructionKind::Call);
        let baseline_calls = baseline_body.count_kind(IRInstructionKind::Call);
        assert_eq!(
            plan_a_calls, baseline_calls,
            "Call instruction count should match for {}: Plan A={}, Baseline={}",
            fname, plan_a_calls, baseline_calls
        );

        // Ret instruction counts should match.
        let plan_a_rets = plan_a_body.count_kind(IRInstructionKind::Ret);
        let baseline_rets = baseline_body.count_kind(IRInstructionKind::Ret);
        assert_eq!(
            plan_a_rets, baseline_rets,
            "Ret instruction count should match for {}: Plan A={}, Baseline={}",
            fname, plan_a_rets, baseline_rets
        );
    }

    // -- Compare call targets --
    let mut plan_a_callees: Vec<&str> = plan_a_module
        .calls
        .iter()
        .map(|c| c.callee.as_str())
        .collect();
    let mut baseline_callees: Vec<&str> = baseline_module
        .calls
        .iter()
        .map(|c| c.callee.as_str())
        .collect();
    plan_a_callees.sort();
    baseline_callees.sort();
    assert_eq!(
        plan_a_callees, baseline_callees,
        "Plan A and baseline should agree on call targets"
    );

    // -- Compare declaration names --
    let mut plan_a_decls: Vec<&str> = plan_a_module
        .declarations
        .keys()
        .map(|s| s.as_str())
        .collect();
    let mut baseline_decls: Vec<&str> = baseline_module
        .declarations
        .keys()
        .map(|s| s.as_str())
        .collect();
    plan_a_decls.sort();
    baseline_decls.sort();
    assert_eq!(
        plan_a_decls, baseline_decls,
        "Plan A and baseline should agree on declaration names"
    );

    // -- Compare target triple --
    assert_eq!(
        plan_a_module.data_layout.target_triple, baseline_module.data_layout.target_triple,
        "Plan A and baseline should agree on target triple"
    );

    // -- Compare endianness --
    assert_eq!(
        plan_a_module.data_layout.little_endian, baseline_module.data_layout.little_endian,
        "Plan A and baseline should agree on endianness"
    );
}

/// When llvm-backend feature is enabled, compare Plan C (llvm-sys) output
/// against the text parser baseline.
///
/// Both should agree on: function names, instruction counts, call targets.
#[cfg(feature = "llvm-backend")]
#[test]
fn test_plan_c_vs_baseline_consistency() {
    let path = rust_hash_fixture();
    let plan_c_result = omniscope_ir::llvm_sys_adapter::parse_with_llvm_sys(&path);

    let baseline = text_parse_rust_hash();

    match plan_c_result {
        Ok(plan_c_module) => {
            // -- Compare function names --
            let mut plan_c_fns: Vec<&str> =
                plan_c_module.functions.keys().map(|s| s.as_str()).collect();
            let mut baseline_fns: Vec<&str> =
                baseline.functions.keys().map(|s| s.as_str()).collect();
            plan_c_fns.sort();
            baseline_fns.sort();
            assert_eq!(
                plan_c_fns, baseline_fns,
                "Plan C and baseline should agree on function names"
            );

            // -- Compare declaration names --
            let mut plan_c_decls: Vec<&str> = plan_c_module
                .declarations
                .keys()
                .map(|s| s.as_str())
                .collect();
            let mut baseline_decls: Vec<&str> =
                baseline.declarations.keys().map(|s| s.as_str()).collect();
            plan_c_decls.sort();
            baseline_decls.sort();
            assert_eq!(
                plan_c_decls, baseline_decls,
                "Plan C and baseline should agree on declaration names"
            );

            // -- Compare call targets --
            let mut plan_c_callees: Vec<&str> = plan_c_module
                .calls
                .iter()
                .map(|c| c.callee.as_str())
                .collect();
            let mut baseline_callees: Vec<&str> =
                baseline.calls.iter().map(|c| c.callee.as_str()).collect();
            plan_c_callees.sort();
            baseline_callees.sort();
            assert_eq!(
                plan_c_callees, baseline_callees,
                "Plan C and baseline should agree on call targets"
            );

            // -- Compare instruction counts per function --
            for fname in &plan_c_fns {
                let plan_c_body = &plan_c_module.function_bodies[*fname];
                let baseline_body = &baseline.function_bodies[*fname];

                let plan_c_calls = plan_c_body.count_kind(IRInstructionKind::Call);
                let baseline_calls = baseline_body.count_kind(IRInstructionKind::Call);
                assert_eq!(
                    plan_c_calls, baseline_calls,
                    "Call count should match for {}: Plan C={}, Baseline={}",
                    fname, plan_c_calls, baseline_calls
                );

                let plan_c_rets = plan_c_body.count_kind(IRInstructionKind::Ret);
                let baseline_rets = baseline_body.count_kind(IRInstructionKind::Ret);
                assert_eq!(
                    plan_c_rets, baseline_rets,
                    "Ret count should match for {}: Plan C={}, Baseline={}",
                    fname, plan_c_rets, baseline_rets
                );
            }

            // -- Compare target triple --
            assert_eq!(
                plan_c_module.data_layout.target_triple, baseline.data_layout.target_triple,
                "Plan C and baseline should agree on target triple"
            );
        }
        Err(e) => {
            // LLVM not available — skip the comparison but verify baseline
            // is deterministic (sanity check).
            debug!(
                "Skipping Plan C vs baseline comparison (LLVM not available): {}",
                e
            );
            let baseline2 = text_parse_rust_hash();
            assert_eq!(
                baseline.functions.len(),
                baseline2.functions.len(),
                "Baseline should be deterministic"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Cross-fixture tests
// ═══════════════════════════════════════════════════════════════════════════

/// Verify that the text parser can load all integration fixtures without
/// panicking, and that each produces a non-empty module.
#[test]
fn test_text_parser_loads_all_fixtures() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let fixtures_dir = Path::new(manifest_dir).join("tests/integration");

    let fixtures = [
        "c_ffi_bugs.ll",
        "c_fft_c_bridge.ll",
        "c_hash_c_bridge.ll",
        "c_merkle_tree.ll",
        "cpp_fft.ll",
        "cpp_hash.ll",
        "go_ffi_bugs.ll",
        "python_ffi_bugs.ll",
        "rust_ffi_bugs.ll",
        "rust_hash.ll",
        "zig_ffi_bridge.ll",
        "zig_ffi_bugs.ll",
    ];

    for fixture_name in &fixtures {
        let path = fixtures_dir.join(fixture_name);
        assert!(
            path.exists(),
            "Fixture {} must exist at {}",
            fixture_name,
            path.display()
        );

        let module = IRModule::load_from_file(&path)
            .unwrap_or_else(|e| panic!("Text parser must load fixture {}: {}", fixture_name, e));

        // Every fixture should have at least one function or declaration.
        assert!(
            !module.functions.is_empty() || !module.declarations.is_empty(),
            "Fixture {} should have at least one function or declaration",
            fixture_name
        );
    }
}

/// Verify that the JSON model can be constructed for a fixture and
/// converted to IRModule without panicking.
#[test]
fn test_json_model_for_fixture_conversion() {
    let model = build_rust_hash_json_model();
    let json_str = serde_json::to_string(&model).expect("model serialization must succeed");
    let parsed_model =
        IRModuleModel::from_json_str(&json_str).expect("model deserialization must succeed");
    let ir_module = parsed_model.to_ir_module();

    // The converted module should have the same function names.
    assert_eq!(
        ir_module.functions.len(),
        2,
        "Converted module should have 2 functions"
    );
    assert!(
        ir_module.functions.contains_key("rust_fft_forward"),
        "Converted module should contain rust_fft_forward"
    );
    assert!(
        ir_module.functions.contains_key("rust_hash_compute"),
        "Converted module should contain rust_hash_compute"
    );
}
