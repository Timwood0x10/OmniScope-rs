; C++ Hidden FFI Bug Corpus
; ═══════════════════════════════════════════════════════════════════════
; Subtle C++ ownership bugs visible at the IR level.
;
;   BUG-CPP1  new[] + scalar delete — array/objector mismatch
;   BUG-CPP2  malloc + operator delete — cross-family within C/C++ boundary
;   BUG-CPP3  new + _ZdaPv (array delete on scalar) — inverted mismatch
;   BUG-CPP4  Hidden leak in exception path: new in try, no delete in catch
;   BUG-CPP5  mimalloc mi_malloc + free — family mismatch (MIMALLOC vs C_HEAP)
;   NOISE-N1  operator new + operator delete — proper scalar pairing
;   NOISE-N2  new[] + delete[] — proper array pairing

target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"

; ── BUG-CPP1: new[] + scalar delete ────────────────────────────────
; _Znam is operator new[], _ZdlPv is operator delete (scalar).
; Array allocation freed with scalar deallocator — undefined behavior.
define void @array_new_scalar_delete(i64 %n) {
entry:
  %arr = call ptr @_Znam(i64 %n)
  ; BUG: should be _ZdaPv (array delete), not _ZdlPv (scalar delete)
  call void @_ZdlPv(ptr %arr)
  ret void
}

; ── BUG-CPP2: malloc + operator delete ─────────────────────────────
; C allocation freed with C++ deallocator. Technically works on some
; platforms but is undefined behavior per the standard.
define void @malloc_then_delete(i64 %size) {
entry:
  %buf = call ptr @malloc(i64 %size)
  ; BUG: malloc'd memory freed with operator delete — family mismatch
  call void @_ZdlPv(ptr %buf)
  ret void
}

; ── BUG-CPP3: new + array delete (inverted) ────────────────────────
; _Znwm is operator new (scalar), _ZdaPv is operator delete[] (array).
; Scalar allocation freed with array deallocator.
define void @scalar_new_array_delete(i64 %size) {
entry:
  %obj = call ptr @_Znwm(i64 %size)
  ; BUG: should be _ZdlPv (scalar delete), not _ZdaPv (array delete)
  call void @_ZdaPv(ptr %obj)
  ret void
}

; ── BUG-CPP4: Leak in "exception" path ─────────────────────────────
; Simulates a C++ exception: new is called, then a branch simulates
; throwing (error path) where delete is never reached.
define i32 @exception_path_leak(i64 %size) {
entry:
  %obj = call ptr @_Znwm(i64 %size)
  %ok = call i32 @may_throw()
  %failed = icmp slt i32 %ok, 0
  br i1 %failed, label %catch_block, label %normal
normal:
  call void @_ZdlPv(ptr %obj)
  ret i32 0
catch_block:
  ; BUG: obj was new'd but catch block forgot to delete it
  ret i32 -1
}

; ── BUG-CPP5: mimalloc + free family mismatch ──────────────────────
; mi_malloc returns MIMALLOC-family memory; free expects C_HEAP.
; This compiles and even works with some allocators but violates
; the resource family contract.
define void @mimalloc_then_free(i64 %size) {
entry:
  %ptr = call ptr @mi_malloc(i64 %size)
  ; BUG: MIMALLOC allocation freed with C free — family mismatch
  call void @free(ptr %ptr)
  ret void
}

; ── NOISE-N1: Proper scalar new + delete ───────────────────────────
define void @new_delete_clean(i64 %size) {
entry:
  %obj = call ptr @_Znwm(i64 %size)
  call void @_ZdlPv(ptr %obj)
  ret void
}

; ── NOISE-N2: Proper array new[] + delete[] ────────────────────────
define void @array_new_delete_clean(i64 %n) {
entry:
  %arr = call ptr @_Znam(i64 %n)
  call void @_ZdaPv(ptr %arr)
  ret void
}

; ── Declarations ───────────────────────────────────────────────────
declare ptr @malloc(i64)
declare void @free(ptr)
declare ptr @_Znwm(i64)
declare void @_ZdlPv(ptr)
declare ptr @_Znam(i64)
declare void @_ZdaPv(ptr)
declare ptr @mi_malloc(i64)
declare void @mi_free(ptr)
declare i32 @may_throw()