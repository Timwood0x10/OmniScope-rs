define dso_local noundef i32 @square(int)(i32 noundef %0) #0 !dbg !8 {
  %2 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !14, metadata !DIExpression()), !dbg !15
  %3 = load i32, ptr %2, align 4, !dbg !16
  %4 = load i32, ptr %2, align 4, !dbg !17
  %5 = mul nsw i32 %3, %4, !dbg !18
  ret i32 %5, !dbg !19
}

declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

attributes #0 = { mustprogress noinline nounwind optnone uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }


---

define dso_local noundef i32 @square(int)(i32 noundef %num) #0 !dbg !10 {
entry:
  %num.addr = alloca i32, align 4
  store i32 %num, ptr %num.addr, align 4
    #dbg_declare(ptr %num.addr, !16, !DIExpression(), !17)
  %0 = load i32, ptr %num.addr, align 4, !dbg !18
  %1 = load i32, ptr %num.addr, align 4, !dbg !19
  %mul = mul nsw i32 %0, %1, !dbg !20
  ret i32 %mul, !dbg !21
}

attributes #0 = { mustprogress noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

----


# License: MSVC Proprietary
# The use of this compiler is only permitted for internal evaluation purposes and is otherwise governed by the MSVC License Agreement.
# See https://visualstudio.microsoft.com/license-terms/vs2022-ga-community/
_num$ = 8                                         ; size = 4
int square(int) PROC                                    ; square
        push    ebp
        mov     ebp, esp
        mov     eax, DWORD PTR _num$[ebp]
        imul    eax, DWORD PTR _num$[ebp]
        pop     ebp
        ret     0
int square(int) ENDP                                    ; square

---



### 对比总结表

| 项目 | MinGW Clang (Windows GNU) | 另一个 Clang (可能是 Linux) | MSVC (Windows) |
|------|---------------------------|-----------------------------|---------------|
| **Target Triple** | `x86_64-w64-windows-gnu` | `x86_64-unknown-linux-gnu` | `x86_64-pc-windows-msvc` |
| **函数定义** | `define dso_local noundef i32 @square(int)(i32 noundef %0)` | `define dso_local noundef i32 @square(int)(i32 noundef %num)` | 不生成 IR，直接生成汇编 |
| **dso_local** | 有 | 有 | -（MSVC 风格不同） |
| **Calling Convention** | Microsoft x64 + GNU 混合 | System V AMD64 | Microsoft x64 |
| **frame-pointer** | 默认无（或 all） | `"frame-pointer"="all"` | 使用 ebp（传统） |
| **Debug Info** | `llvm.dbg.declare` | `#dbg_declare` | 无（汇编里无） |
| **target-features** | `+cx8,+fxsr,+mmx,+sse,+sse2,+x87` | `+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87` | - |
| **栈处理** | alloca + store | alloca + store | 直接用 ebp 寻址 |
| **函数名** | `@square(int)`（带括号，clang 特色） | `@square(int)` | `_square`（MSVC 修饰） |

---

### 关键平台特定信息解释

1. **dso_local**
   - Windows（尤其是 MinGW 和 MSVC）上非常常见，表示这个符号是当前模块（DSO）本地的。
   - Linux 上通常也会有，但语义略有不同。

2. **target datalayout 和 triple**（你之前 macOS 的例子 vs 这里）
   - macOS ARM64：`arm64-apple-macosx15.0.0` + `m:o`
   - Linux x86_64：`x86_64-unknown-linux-gnu` + `m:e`
   - Windows MinGW：`x86_64-w64-windows-gnu` + `m:w`（Windows 风格）
   - Windows MSVC：`x86_64-pc-windows-msvc`

3. **frame-pointer**
   - Linux 版本常默认开启 `"frame-pointer"="all"`
   - Windows MinGW 经常关闭（性能考虑）
   - 这会影响栈帧结构和调试信息。

4. **Debug Information**
   - Clang 在不同平台生成的 debug intrinsic 写法略有不同（`llvm.dbg.declare` vs `#dbg_declare`）。

5. **MSVC 的特殊性**
   - MSVC 不太爱生成 LLVM IR（Godbolt 上显示的是直接汇编）。
   - 使用传统 ebp 栈帧，而不是 rsp。
   - 函数名可能带下划线 `_square`。

---

**对于 OmniScope 的意义：**

这些差异正是你需要适配的重点：
- **target triple** → 判断当前运行环境
- **datalayout** → 决定指针大小、对齐规则、结构体布局
- **attributes**（frame-pointer、target-features、uwtable 等）→ 影响 lifetime、stack、exception handling 的分析
- **dso_local / dllimport / dllexport** → Windows 特有，需要单独处理
- Calling convention 差异会影响参数传递和 ownership 追踪

---

**下一步建议：**

1. 你可以再生成**纯 Linux** 和 **Windows MSVC** 的完整 IR（前 30 行就够），贴过来我继续对比。
2. 或者告诉我你现在最关心哪一块差异（比如结构体对齐？函数调用？Debug 信息？还是 Windows DLL 相关？）

要我帮你写一个**Godbolt 最佳配置**（一次性出三个平台的 IR）吗？直接复制就能用。