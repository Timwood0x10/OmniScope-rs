// ===========================================================================
// Tests for ir_model.rs
// ===========================================================================
//
// Extracted from ir_model.rs to keep the main module under the 1000-line
// project limit.  All helpers and test cases are unchanged.

use super::*;

/// Build a compact JSON instruction object.
fn inst_json(opcode: &str, raw: &str) -> String {
    format!(
        r#"{{"opcode":"{}","raw":"{}","operands":[],"operand_types":[],"is_indirect":false}}"#,
        opcode, raw
    )
}

/// Build a JSON instruction with callee (for call instructions).
fn call_inst_json(callee: &str, raw: &str, ret_ty: &str) -> String {
    format!(
        r#"{{"opcode":"call","result_type":"{}","callee":"{}","raw":"{}","operands":[],"operand_types":[],"is_indirect":false}}"#,
        ret_ty, callee, raw
    )
}

/// Build a JSON basic block from instruction JSON strings.
fn block_json(label: &str, insts: &[String], successors: &[&str]) -> String {
    let succs: Vec<String> = successors.iter().map(|s| format!("\"{}\"", s)).collect();
    format!(
        r#"{{"label":"{}","instructions":[{}],"successors":[{}]}}"#,
        label,
        insts.join(","),
        succs.join(",")
    )
}

/// Build a full module JSON with given functions and declarations JSON.
fn module_json(functions: &str, decls: &str) -> String {
    format!(r#"{{"functions":{},"declarations":{}}}"#, functions, decls)
}

/// Minimal valid JSON with target triple and data layout.
fn minimal_json() -> String {
    let ret_inst = inst_json("ret", "ret i32 0");
    let block = block_json("entry", &[ret_inst], &[]);
    format!(
        r#"{{"target_triple":"x86_64-apple-darwin","data_layout":"e-m:e-p:64:64-i64:64-f80:128-n8:16:32:64-S128","functions":[{{"name":"main","return_type":"i32","param_types":[],"calling_convention":"ccc","blocks":[{}],"linkage":"external"}}],"declarations":[],"named_struct_types":{{}},"global_variables":[]}}"#,
        block
    )
}

#[test]
fn test_deserialize_minimal_json() {
    let model: IRModuleModel =
        serde_json::from_str(&minimal_json()).expect("JSON must deserialize");
    assert_eq!(model.functions.len(), 1, "Model should contain 1 function");
    assert_eq!(
        model.functions[0].name, "main",
        "Function name should be 'main'"
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
        1,
        "Block should have 1 instruction"
    );
}

#[test]
fn test_round_trip_json() {
    let model: IRModuleModel =
        serde_json::from_str(&minimal_json()).expect("Deserialization must succeed");
    let json_out = serde_json::to_string(&model).expect("Serialization must succeed");
    let model2: IRModuleModel =
        serde_json::from_str(&json_out).expect("Re-deserialization must succeed");
    assert_eq!(
        model.functions.len(),
        model2.functions.len(),
        "Round-trip should preserve function count"
    );
    assert_eq!(
        model.functions[0].name, model2.functions[0].name,
        "Round-trip should preserve function name"
    );
}

#[test]
fn test_to_ir_module_basic() {
    let model: IRModuleModel =
        serde_json::from_str(&minimal_json()).expect("Deserialization must succeed");
    let ir_module = model.to_ir_module();

    assert_eq!(
        ir_module.functions.len(),
        1,
        "Legacy module should have 1 function"
    );
    assert!(
        ir_module.functions.contains_key("main"),
        "Legacy module should contain function 'main'"
    );
    assert!(
        ir_module.declarations.is_empty(),
        "Legacy module should have no declarations"
    );
    assert!(
        ir_module.calls.is_empty(),
        "Legacy module should have no calls (ret only)"
    );
    assert!(
        ir_module.function_bodies.contains_key("main"),
        "Legacy module should have a body for 'main'"
    );

    // Data layout should be populated.
    assert_eq!(
        ir_module.data_layout.target_triple,
        Some("x86_64-apple-darwin".to_string()),
        "Target triple should be preserved"
    );
    assert_eq!(
        ir_module.data_layout.pointer_size,
        Some(64),
        "Pointer size should be derived from data layout"
    );
    assert_eq!(
        ir_module.data_layout.little_endian,
        Some(true),
        "Endianness should be derived from data layout"
    );
}

#[test]
fn test_to_ir_module_with_call() {
    let call = call_inst_json("callee_fn", "%r = call i32 @callee_fn(i32 42)", "i32");
    let ret = inst_json("ret", "ret void");
    let block = block_json("entry", &[call, ret], &[]);
    let func = format!(
        r#"{{"name":"caller","return_type":"void","param_types":["i32"],"calling_convention":"ccc","blocks":[{}]}}"#,
        block
    );
    let decl = r#"{"name":"callee_fn","return_type":"i32","param_types":["i32"]}"#;
    let json = module_json(&format!("[{}]", func), &format!("[{}]", decl));

    let model: IRModuleModel = serde_json::from_str(&json).expect("JSON must deserialize");
    let ir_module = model.to_ir_module();

    assert_eq!(
        ir_module.calls.len(),
        1,
        "Should have 1 call instruction recorded"
    );
    assert_eq!(
        ir_module.calls[0].callee, "callee_fn",
        "Call callee should be 'callee_fn'"
    );
    assert_eq!(
        ir_module.calls[0].caller, "caller",
        "Call caller should be 'caller'"
    );
    assert!(
        ir_module.calls[0].is_external,
        "Call to declared function should be marked external"
    );

    let body = &ir_module.function_bodies["caller"];
    assert_eq!(
        body.instructions.len(),
        2,
        "Body should have 2 instructions"
    );
    assert_eq!(
        body.instructions[0].kind,
        IRInstructionKind::Call,
        "First instruction should be Call"
    );
    assert_eq!(
        body.instructions[1].kind,
        IRInstructionKind::Ret,
        "Second instruction should be Ret"
    );
}

#[test]
fn test_to_ir_module_with_atomicrmw() {
    let atomic = IRInstructionModel {
        opcode: "atomicrmw".into(),
        result_type: Some("i32".into()),
        operands: vec!["%s".into(), "2".into()],
        operand_types: vec!["ptr".into(), "i32".into()],
        raw: "%22 = atomicrmw sub ptr %s, i32 2 monotonic".into(),
        ..Default::default()
    };
    let icmp = IRInstructionModel {
        opcode: "icmp".into(),
        result_type: Some("i1".into()),
        operands: vec!["%22".into(), "2".into()],
        operand_types: vec!["i32".into(), "i32".into()],
        raw: "%23 = icmp eq i32 %22, 2".into(),
        ..Default::default()
    };
    let br = IRInstructionModel {
        opcode: "br".into(),
        raw: "br i1 %23, label %destroy, label %exit".into(),
        ..Default::default()
    };
    let ret = IRInstructionModel {
        opcode: "ret".into(),
        raw: "ret void".into(),
        ..Default::default()
    };

    let model = IRModuleModel {
        functions: vec![IRFunction {
            name: "release".into(),
            return_type: "void".into(),
            param_types: vec!["ptr".into()],
            blocks: vec![
                IRBasicBlock {
                    label: "entry".into(),
                    instructions: vec![atomic, icmp, br],
                    successors: vec!["destroy".into(), "exit".into()],
                },
                IRBasicBlock {
                    label: "destroy".into(),
                    instructions: vec![ret.clone()],
                    successors: vec![],
                },
                IRBasicBlock {
                    label: "exit".into(),
                    instructions: vec![ret],
                    successors: vec![],
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    };
    let ir_module = model.to_ir_module();

    let body = &ir_module.function_bodies["release"];
    assert_eq!(
        body.count_kind(IRInstructionKind::AtomicRmw),
        1,
        "Should have 1 atomicrmw instruction"
    );
    assert_eq!(
        body.count_kind(IRInstructionKind::Icmp),
        1,
        "Should have 1 icmp instruction"
    );
    assert_eq!(
        body.count_kind(IRInstructionKind::Branch),
        1,
        "Should have 1 branch instruction"
    );

    let atomic_insts = body.atomic_rmw_with_op("sub");
    assert_eq!(atomic_insts.len(), 1, "Should find atomicrmw sub");

    let icmp_insts = body.instructions_of_kind(IRInstructionKind::Icmp);
    assert_eq!(
        icmp_insts[0].icmp_pred.as_deref(),
        Some("eq"),
        "icmp predicate should be 'eq'"
    );
}

#[test]
fn test_load_from_json_string() {
    let ir_module = parse_from_json(&minimal_json()).expect("parse_from_json must succeed");
    assert!(
        ir_module.functions.contains_key("main"),
        "Parsed module should contain function 'main'"
    );
}

#[test]
fn test_from_json_str_method() {
    let model = IRModuleModel::from_json_str(&minimal_json()).expect("from_json_str must succeed");
    assert_eq!(model.functions.len(), 1, "Model should have 1 function");
}

#[test]
fn test_default_traits() {
    let model = IRModuleModel::default();
    assert!(
        model.functions.is_empty(),
        "Default model should have no functions"
    );

    let func = IRFunction::default();
    assert_eq!(func.name, "", "Default function name should be empty");
    assert_eq!(
        func.calling_convention, "ccc",
        "Default calling convention should be 'ccc'"
    );

    let block = IRBasicBlock::default();
    assert_eq!(block.label, "", "Default block label should be empty");
    assert!(
        block.successors.is_empty(),
        "Default block should have no successors"
    );

    let inst = IRInstructionModel::default();
    assert_eq!(
        inst.opcode, "",
        "Default instruction opcode should be empty"
    );
    assert!(
        !inst.is_indirect,
        "Default instruction should not be indirect"
    );

    let decl = IRDeclaration::default();
    assert_eq!(decl.name, "", "Default declaration name should be empty");

    let gv = IRGlobalVariable::default();
    assert_eq!(gv.name, "", "Default global variable name should be empty");
    assert!(
        !gv.is_constant,
        "Default global variable should not be constant"
    );
}

#[test]
fn test_empty_model_conversion() {
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

#[test]
fn test_missing_optional_fields() {
    let json =
        r#"{"functions":[{"name":"test","return_type":"void","blocks":[]}],"declarations":[]}"#;
    let model: IRModuleModel = serde_json::from_str(json).expect("Minimal JSON must deserialize");
    assert_eq!(
        model.functions[0].calling_convention, "ccc",
        "Missing calling_convention should default to 'ccc'"
    );
    assert!(
        model.functions[0].param_types.is_empty(),
        "Missing param_types should default to empty vec"
    );
    assert!(
        model.functions[0].linkage.is_none(),
        "Missing linkage should default to None"
    );
    assert!(
        model.named_struct_types.is_empty(),
        "Missing named_struct_types should default to empty map"
    );
    assert!(
        model.global_variables.is_empty(),
        "Missing global_variables should default to empty vec"
    );
}

#[test]
fn test_declarations_conversion() {
    let json = r#"{"functions":[],"declarations":[{"name":"malloc","return_type":"ptr","param_types":["i64"]},{"name":"free","return_type":"void","param_types":["ptr"]}]}"#;
    let model: IRModuleModel = serde_json::from_str(json).expect("JSON must deserialize");
    let ir_module = model.to_ir_module();

    assert_eq!(
        ir_module.declarations.len(),
        2,
        "Should have 2 declarations"
    );
    assert!(
        ir_module.declarations.contains_key("malloc"),
        "Should contain 'malloc' declaration"
    );
    assert!(
        ir_module.declarations.contains_key("free"),
        "Should contain 'free' declaration"
    );
    assert!(
        ir_module.declarations["malloc"].is_declaration,
        "malloc should be marked as declaration"
    );
}

#[test]
fn test_global_variables_parsed() {
    let json = r#"{"functions":[],"declarations":[],"global_variables":[{"name":"my_global","type":"i32","is_constant":true}]}"#;
    let model: IRModuleModel = serde_json::from_str(json).expect("JSON must deserialize");
    assert_eq!(
        model.global_variables.len(),
        1,
        "Should have 1 global variable"
    );
    assert_eq!(
        model.global_variables[0].name, "my_global",
        "Global variable name should be 'my_global'"
    );
    assert!(
        model.global_variables[0].is_constant,
        "Global variable should be constant"
    );
}

#[test]
fn test_malformed_json_returns_error() {
    let result = parse_from_json("not valid json {{{");
    assert!(result.is_err(), "Malformed JSON should return an error");
}

#[test]
fn test_multiple_blocks_with_successors() {
    let br1 = inst_json("br", "br label %loop");
    let br2 = inst_json("br", "br label %exit");
    let ret = inst_json("ret", "ret void");
    let b1 = block_json("entry", &[br1], &["loop"]);
    let b2 = block_json("loop", &[br2], &["exit"]);
    let b3 = block_json("exit", &[ret], &[]);
    let func = format!(
        r#"{{"name":"branching","return_type":"void","param_types":[],"calling_convention":"ccc","blocks":[{},{},{}],"linkage":null}}"#,
        b1, b2, b3
    );
    let json = module_json(&format!("[{}]", func), "[]");

    let model: IRModuleModel = serde_json::from_str(&json).expect("JSON must deserialize");
    let ir_module = model.to_ir_module();

    let body = &ir_module.function_bodies["branching"];
    assert_eq!(
        body.instructions.len(),
        3,
        "Body should have 3 instructions across 3 blocks"
    );
    assert_eq!(
        body.count_kind(IRInstructionKind::Branch),
        2,
        "Should have 2 branch instructions"
    );
}

#[test]
fn test_fastcc_calling_convention() {
    let ret = inst_json("ret", "ret i64 42");
    let block = block_json("entry", &[ret], &[]);
    let func = format!(
        r#"{{"name":"hot_path","return_type":"i64","param_types":["i64"],"calling_convention":"fastcc","blocks":[{}]}}"#,
        block
    );
    let json = module_json(&format!("[{}]", func), "[]");

    let model: IRModuleModel = serde_json::from_str(&json).expect("JSON must deserialize");
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

#[test]
fn test_named_struct_types() {
    let json = r#"{"functions":[],"declarations":[],"named_struct_types":{"struct.MyClass":["i32","ptr","i8"]}}"#;
    let model: IRModuleModel = serde_json::from_str(json).expect("JSON must deserialize");
    assert_eq!(
        model.named_struct_types.len(),
        1,
        "Should have 1 named struct type"
    );
    assert!(
        model.named_struct_types.contains_key("struct.MyClass"),
        "Should contain 'struct.MyClass'"
    );
    assert_eq!(
        model.named_struct_types["struct.MyClass"].len(),
        3,
        "struct.MyClass should have 3 fields"
    );
}

#[test]
fn test_indirect_call_conversion() {
    let call = IRInstructionModel {
        opcode: "call".into(),
        callee: Some("%fp".into()),
        is_indirect: true,
        raw: "call void %fp(ptr %ctx)".into(),
        ..Default::default()
    };
    let model = IRModuleModel {
        functions: vec![IRFunction {
            name: "dispatch".into(),
            return_type: "void".into(),
            param_types: vec!["ptr".into()],
            blocks: vec![IRBasicBlock {
                label: "entry".into(),
                instructions: vec![call],
                successors: vec![],
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let ir_module = model.to_ir_module();

    assert_eq!(ir_module.calls.len(), 1, "Should have 1 call recorded");
    assert_eq!(
        ir_module.calls[0].callee, "%fp",
        "Indirect call callee should be '%fp'"
    );
    assert!(
        !ir_module.calls[0].is_external,
        "Indirect call to register should not be marked external"
    );
}

#[test]
fn test_conversion_classify_all_opcodes() {
    let cases = vec![
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
        ("ret", IRInstructionKind::Ret),
        ("phi", IRInstructionKind::Phi),
        ("select", IRInstructionKind::Select),
        ("add", IRInstructionKind::BinaryOp),
        ("sub", IRInstructionKind::BinaryOp),
        ("bitcast", IRInstructionKind::Conversion),
        ("zext", IRInstructionKind::Conversion),
        ("unknown_opcode_xyz", IRInstructionKind::Other),
    ];
    for (opcode, expected) in cases {
        assert_eq!(
            classify_opcode(opcode),
            expected,
            "Opcode '{}' should map to {:?}",
            opcode,
            expected
        );
    }
}
