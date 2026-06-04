//! Boundary inference demo example.
//!
//! This example demonstrates how to use the automatic boundary inference
//! feature when no explicit --cross configuration is provided.

use omniscope_ir::IRModule;
use omniscope_pass::infer_boundaries;

fn main() {
    // 创建一个示例 IR 模块
    let mut module = IRModule::new();

    // 添加一些 C++ mangled 函数调用
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "_Z3fooi".to_string(),
        caller: "c_main".to_string(),
        is_external: true,
        location: None,
        args: Vec::new(),
        result: None,
    });

    module.calls.push(omniscope_ir::CallInstruction {
        callee: "_Z3barv".to_string(),
        caller: "c_main".to_string(),
        is_external: true,
        location: None,
        args: Vec::new(),
        result: None,
    });

    // 添加一些语言特定的函数
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "PyObject_GetAttr".to_string(),
        caller: "c_main".to_string(),
        is_external: true,
        location: None,
        args: Vec::new(),
        result: None,
    });

    module.calls.push(omniscope_ir::CallInstruction {
        callee: "_Cfunc_malloc".to_string(),
        caller: "c_main".to_string(),
        is_external: true,
        location: None,
        args: Vec::new(),
        result: None,
    });

    // 自动推断边界
    let boundary_ctx = infer_boundaries(&module);

    // 输出结果
    println!("=== Boundary Inference Demo ===");
    println!(
        "Total boundaries detected: {}",
        boundary_ctx.boundary_count()
    );
    println!("Is empty: {}", boundary_ctx.is_empty());

    // 显示所有边界函数
    println!("\nDetected boundary functions:");
    for (func, (from, to)) in boundary_ctx.function_boundaries() {
        println!("  {} -> {} ({})", from, to, func);
    }

    // 检查特定函数
    println!("\nChecking specific functions:");
    let test_functions = ["_Z3fooi", "malloc", "PyObject_GetAttr", "_Cfunc_malloc"];
    for func in &test_functions {
        match boundary_ctx.is_declared_boundary(func) {
            Some((from, to)) => println!("  {}: {} -> {} (boundary)", func, from, to),
            None => println!("  {}: not a boundary", func),
        }
    }
}
