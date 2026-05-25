要求：
必须遵守： 在没有我的允许下禁止删除项目任何文件，禁止执行任何的`rm` 命令，其次，每个模块重构完成之后，必须对比之前模块，功能上不能打任何折扣，否则我会立刻马上把你从我的电脑上删除！！！！！

***

1. 单个文件的代码行数不能超过 1000 行。（包括注释和test case）,超出的可以设计成一个模块。
2. 验收标准，make check 0 errors
3. 每次修改完之后，确保make fmt 
4. make check 显示的warning，可以先不管
5. 修复warning 时，禁止用#\[allow(dead\_code)] 
6. 禁止使用任何git 命令。
7. 编写测试的时候，应该以检测代码隐形bug为先，而不是很敷衍的进行assert! 这是不负责任的。禁止滥竽充数，而是编写符合模块功能的测试用例。
8. 逐模块测试，一个做完，进行下一个。
9. 禁止执行覆盖率测试（因为浪费时间和资源）

<br />

# 🧪 MemScope-rs: Tier-1 Testing Rigor & Standards

## I. Core Testing Philosophy

- **Proof, Not Prayer**: 测试不是为了证明代码能跑，而是为了证明代码在极端情况下不会崩。
- **Deterministic Safety**: 所有的 `unsafe` 代码路径必须实现 $100\\%$ 的覆盖。
- **Zero-Cost Verification**: 测试本身不应污染生产代码（使用 `#[cfg(test)]`）。

***

## II. Strict Test Case Requirements

### 1. The "Golden Trio" of Coverage

每一组核心逻辑（特别是涉及内存分配、原子计数、双生命周期结构）必须包含：

- **Positive Tests (Happy Path)**: 验证标准输入下的预期行为。
- **Negative Tests (Edge Cases)**: 必须验证 `null` 指针、`0` 长度分配、容量溢出、以及无效的内存对齐。
- **Stress/Concurrency Tests**: 涉及 `Atomic` 或 `Lock-free` 的逻辑，必须通过 `loom` 或至少 50 线程并发压测。

### 2. Implementation Rules (Mandatory)

- **No** **`println!`**: 测试输出必须使用 `tracing` 的 `test_subscriber`。
- **Expect meaningful context**: 所有的断言 `assert!` 必须带有具体的错误消息。

  Rust
  ```
  // ✅ GOOD
  assert_eq!(tracker.count(), 1, "Tracker should record exactly one allocation after push");
  // ❌ BAD
  assert_eq!(tracker.count(), 1);

  ```
- **Panic Testing**: 对于逻辑上应该触发 `Result::Err` 的地方，必须验证其返回的错误类型；对于契约违规，使用 `#[should_panic]`。

***

## III. Advanced Verification Standards

### 1. Memory Leak Detection (The "Miriri" Rule)

对于所有涉及 `Raw Pointer` 或手动内存管理的模块，必须通过 `Miri` 检查。

- **Requirement**: 执行 `cargo miri test` 必须 0 报错。
- **Focus**: 检查数据竞争（Data Race）、无效指针解引用、以及内存泄漏。

### 2. Concurrency Invariant Testing (Loom)

由于你追求无锁（Lock-free），必须使用 `loom` 库来模拟线程调度的所有排列组合。

Rust

```
#[test]
fn test_concurrent_allocation_logic() {
    loom::model(|| {
        let tracker = Tracker::new();
        let t1 = thread::spawn(move || tracker.track(0x1, 100));
        let t2 = thread::spawn(move || tracker.track(0x2, 200));
        t1.join().unwrap();
        t2.join().unwrap();
        // 验证原子性一致性
    });
}

```

### 3. Fuzzing (AFL++ / libFuzzer)

对于解析内存元数据的函数，必须包含模糊测试（Fuzz Testing）。

- **Goal**: 证明随机输入流不会导致内存越界或系统崩溃。

***

## IV. Documentation of Test Cases

### 1. The 7:3 Ratio in Tests

即使是测试代码，也必须遵循你的规范：**70% 代码，30% 注释**。每一条测试用例前必须明确标注：

- **Objective**: 这个测试要验证什么？
- **Invariants**: 运行此测试前后的状态约束。

Rust

```
/// Objective: Verify that the tracker correctly handles rapid allocation/deallocation
/// Invariants: Total tracked bytes must return to zero after all blocks are freed.
#[test]
fn test_balance_invariants() {
    // ... code ...
}

```

***

## V. Quality Gates (Pre-merge)

在提升覆盖率的过程中，任何 PR 必须满足以下硬性指标：

1. **Line Coverage**: $> 90\\%$。
2. **Unsafe Block Coverage**: **必须 $100\\%$**。
3. **Property-Based Testing**: 使用 `proptest` 验证至少 1000 组随机生成的内存地址和大小。
4. **Static Check**: `cargo clippy --tests` 必须全绿通过。

***

<br />

<br />

## 🦀 Rust 标准编码规范指南

### 1. 命名规范 (Naming Conventions)

Rust 遵循严格的命名约定，违反这些约定通常会触发 `rustc` 的警告。

| 项目                              | 格式                        | 范例               |
| :------------------------------ | :------------------------ | :--------------- |
| **Crates / Modules**            | `snake_case`              | `data_processor` |
| **Types (Struct, Enum, Trait)** | `UpperCamelCase`          | `UserRecord`     |
| **Functions / Methods**         | `snake_case`              | `get_user_id()`  |
| **Variables / Parameters**      | `snake_case`              | `total_count`    |
| **Constants / Statics**         | `SCREAMING_SNAKE_CASE`    | `MAX_TIMEOUT`    |
| **Type Parameters**             | `UpperCamelCase` (通常为单字母) | `T`, `U`, `Item` |

***

### 2. 注释规范 (Commenting)

良好的注释不仅仅是解释“做了什么”，更要解释“为什么这么做”。

- **普通代码注释**：使用 `//` 进行行内说明。
- **文档注释 (Outer)**：使用 `///` 为其后的项（函数、结构体等）生成文档。
- **文档注释 (Inner)**：使用 `//!` 为当前项（通常是 `lib.rs` 或 `mod.rs` 顶部）编写模块级文档。
- 代码和注释的比例为7:3，注释必须为英文

#### 文档注释的最佳实践：

````rust
//! # 模块标题
//! 这里描述整个 crate 或模块的功能。

/// 对函数进行简短描述（首字母大写，句号结尾）。
///
/// # Examples
///
/// ```
/// let result = my_crate::add(1, 2);
/// assert_eq!(result, 3);
/// ```
///
/// # Errors
///
/// 列出该函数可能返回 `Err` 的情况。
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}
````

***

### 3. 文档化 (Documentation)

- **Markdown 支持**：Rustdoc 原生支持 Markdown。使用反引号 \` 包围代码，使用标题进行分类。
- **常用章节**：
  - `# Examples`: 必填。既是文档，也是**文档测试**。
  - `# Panics`: 如果函数在特定条件下会崩溃，必须注明。
  - `# Safety`: 如果是 `unsafe fn`，必须说明调用者需遵守的契约。
- **隐藏代码**：在文档测试中，可以使用 `#` 隐藏辅助性的设置代码，只展示核心逻辑。

***

### 4. 测试规范 (Testing)

Rust 的测试分为单元测试和集成测试。

#### 4.1 单元测试 (Unit Tests)

- **位置**：放在源文件的末尾，使用 `mod tests`。
- **标注**：使用 `#[cfg(test)]` 属性，确保只有在 `cargo test` 时才进行编译。

```rust
#[cfg(test)]
mod tests {
    use super::*; // 导入父模块的项

    #[test]
    fn test_add_function() {
        assert_eq!(add(2, 2), 4);
    }

    #[test]
    #[should_panic(expected = "division by zero")]
    fn test_divide_by_zero() {
        // 测试会导致崩溃的情况
    }
}
```

#### 4.2 集成测试 (Integration Tests)

- **位置**：放在项目根目录下的 `tests/` 文件夹中。
- **作用**：像外部用户一样调用你的公共 API。

#### 4.3 文档测试 (Doc Tests)

- 写在 `///` 里的代码块会自动运行。这是确保文档示例永不过时的最佳手段。

***

### 5. 代码风格与工具

- **格式化**：始终使用 `cargo fmt` 进行代码自动对齐。
- **静态分析**：始终运行 `cargo clippy`。它不仅检查错误，还会给出“更具 Rust 风味”的代码建议。
- **错误处理**：
  - 优先使用memscope-rs 内置的错误。
  - 使用 `?` 运算符传播错误。
  - 禁止库代码中使用 `unwrap()`，除非你能证明它永远不会失败（并加上注释说明理由）。

***

### 6. 核心设计原则

- **所有权优先**：在设计 API 时，考虑参数是应该转移所有权 (`T`)，还是借用 (`&T`)，亦或是可变借用 (`&mut T`)。
- **组合优于继承**：利用 `Trait` 来实现多态。
- **零成本抽象**：不要为了代码简洁而牺牲性能，除非该开销是必须的。

***

## 进阶编码规范与最佳实践

### 1. 变量与类型处理 (Variable & Type Handling)

- **变量遮蔽 (Shadowing)**：
  鼓励使用变量遮蔽来改变变量的类型或可变性，而不是创建类似 `data_str` 和 `data_int` 这样的冗余名称。
  ```rust
  let data = " 42 ";
  let data: i32 = data.trim().parse()?; // 优雅地转换类型
  ```
- **临时变量的可变性**：
  尽量保持变量不可变（默认 `let`）。只有在确实需要原地修改时才使用 `mut`。
- **使用** **`new()`** **和** **`Default`**：
  - 结构体的构造函数应命名为 `new`。
  - 如果结构体所有字段都有默认值，务必实现 `Default` trait，这样用户可以使用 `..Default::default()` 语法。

***

### 2. 函数签名与参数 (Function Signatures)

- **强制转换引用 (Deref Coercions)**：
  函数参数应优先使用切片（Slice）而非集合容器。
  - **Bad**: `fn process(s: &String)` 或 `fn process(v: &Vec<u32>)`
  - **Good**: `fn process(s: &str)` 或 `fn process(v: &[u32])`
  - *原因*：`&String` 只能接受 String，而 `&str` 可以接受 String 和字符串字面量。
- **避免过度使用** **`Clone`**：
  在函数内部调用 `.clone()` 前，先考虑是否可以通过借用 (`&T`) 解决。如果必须拥有所有权，请让调用者决定是否克隆。
- **返回** **`impl Trait`**：
  当返回闭包或复杂的迭代器时，使用 `fn iter_elements(&self) -> impl Iterator<Item = &u32>`，隐藏复杂的内部类型。

***

### 3. 错误处理 (Error Handling) - 深度规范

- **库 (Library) vs 应用 (Binary)**：
  - **库代码**：定义自己的 `Error` 枚举，并为之实现 `std::fmt::Display` 和 `std::error::Error`（推荐使用 `thiserror` crate）。
  - **应用代码**：使用 `anyhow` crate 来处理各种来源的错误，它支持错误上下文注入。
- **不可恢复错误的界限**：
  - 仅在以下情况使用 `panic!` / `unwrap()`：
    1. 逻辑上的“绝对不可能”发生（如写死的核心配置加载失败）。
    2. 测试代码中。
    3. 示例代码中（为了简洁）。
  - 其他情况一律返回 `Result`。

***

### 4. 控制流优化 (Control Flow)

- **if let vs match**：
  - 如果只关心一种模式，用 `if let`。
  - 如果有多个分支或需要穷举，必用 `match`。
- **提前返回 (Early Return)**：
  减少嵌套深度。优先处理错误分支并返回。
  ```rust
  // 推荐做法
  let Some(user) = get_user() else { return Err(Error::NotFound) };
  ```
- **迭代器胜过循环**：
  优先使用 `.map()`, `.filter()`, `.collect()` 等迭代器方法，而不是显式的 `for` 循环。它们不仅更简洁，通常还能触发编译器优化（如边界检查消除）。

***

### 5. Trait 设计规范

- **Orphan Rule (孤儿规则)**：
  记住：你要么拥有该 Trait，要么拥有该类型，否则不能为该类型实现该 Trait。
- **关联类型 vs 泛型**：
  - 如果一个类型对一个 Trait 只能有一种实现（如 `Add` 后的结果），使用**关联类型**。
  - 如果需要多种实现（如 `From<T>` 可以有多个 T），使用**泛型**。
- **密封 Trait (Sealed Traits)**：
  如果不希望外部用户实现你的 Trait，可以使用私有模块模式：
  ```rust
  mod private {
      pub trait Sealed {}
  }
  pub trait MyPublicTrait: private::Sealed { ... }
  ```

***

### 6. 并发与内存安全 (Concurrency)

- **Send & Sync**：
  理解这两个标记 Trait。大多数类型默认是 `Send` + `Sync`，但 `Rc`, `Cell`, `RefCell` 不是。
- **锁的粒度**：
  尽量缩小 `Mutex` 锁定的范围。使用花括号 `{}` 明确控制锁的生命周期，防止死锁并提高并发。
- **原子操作**：
  对于简单的计数器，优先使用 `std::sync::atomic` 而不是 `Mutex<i32>`。

***

### 7. Cargo.toml 与项目结构

- **显式声明版本**：始终在 `Cargo.toml` 中固定依赖的主版本号。
- **Feature Gates**：
  如果你开发的库功能较多，使用 `[features]` 将非核心功能设为可选，以优化下游用户的编译速度和二进制体积。
- **层级结构**：
  ```text
  src/
    lib.rs       # 导出公共 API
    error.rs     # 统一错误定义
    models/      # 数据结构
      mod.rs
      user.rs
  ```

***

### 8. 性能微调技巧

- **预分配空间**：
  如果你知道集合的大小，使用 `Vec::with_capacity(n)`。
- **避免频繁分配**：
  在循环内部尽量复用 `String` 或 `Vec` 的缓冲区，使用 `.clear()` 而不是重新创建。

***

**建议工具链：**

1. **`cargo clippy`**: 它的建议几乎就是“标准答案”。
2. **`cargo deny`**: 用于检查依赖许可证和漏洞。
3. **`cargo bloat`**: 查看是谁占据了二进制文件的空间。
4. make check  确保0 errors

