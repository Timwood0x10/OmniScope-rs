; Rust Hidden FFI Bug Corpus
; ═══════════════════════════════════════════════════════════════════════
; Subtle Rust ownership bugs visible at IR level.
;
;   BUG-R1  __rust_alloc without __rust_dealloc — leaked global allocator memory
;   BUG-R2  Box::into_raw without Box::from_raw — escaped ownership never reclaimed
;   BUG-R3  into_raw + double from_raw — reclaimed twice (double reclaim / use-after-free)
;   BUG-R4  __rust_alloc + free — cross-family (RUST_GLOBAL freed by C_HEAP)
;   BUG-R5  CString::into_raw leak — raw pointer returned to C, Rust forgets to reclaim
;   NOISE-N1  __rust_alloc + __rust_dealloc — properly paired
;   NOISE-N2  __rust_alloc_zeroed + __rust_dealloc — zeroed alloc variant paired

target triple = "aarch64-apple-darwin"
target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128"

; ── BUG-R1: __rust_alloc leak ──────────────────────────────────────
; The global allocator is called but the pointer is returned to
; the caller without a matching __rust_dealloc. The caller (C code)
; will try to free it with free() → cross-family, or never free it → leak.
define ptr @rust_alloc_leak(i64 %size, i64 %align) {
entry:
  %ptr = call ptr @__rust_alloc(i64 %size, i64 %align)
  ; BUG: no __rust_dealloc — ownership leaks
  ret ptr %ptr
}

; ── BUG-R2: Box::into_raw escape without reclaim ───────────────────
; into_raw transfers ownership to raw pointer territory.
; The pointer is handed to C code, but no from_raw is ever called.
; This is the most common Rust FFI leak pattern.
define ptr @box_into_raw_leak(i64 %size, i64 %align) {
entry:
  %boxed = call ptr @__rust_alloc(i64 %size, i64 %align)
  ; Escape: ownership leaves Rust's type system
  call void @Box::into_raw(ptr %boxed)
  ; BUG: no Box::from_raw — escaped ownership never reclaimed
  ret ptr %boxed
}

; ── BUG-R3: Double reclaim ────────────────────────────────────────
; from_raw is called twice on the same raw pointer — this creates
; two Box instances pointing to the same allocation. When both
; Boxes are dropped, the memory is freed twice → double-free.
define void @double_from_raw(ptr %raw) {
entry:
  ; First reclaim — valid
  %b1 = call ptr @Box::from_raw(ptr %raw)
  ; Second reclaim on the SAME pointer — BUG: double reclaim
  %b2 = call ptr @Box::from_raw(ptr %raw)
  ; Both Boxes will be dropped → double-free
  call void @__rust_dealloc(ptr %b1, i64 8, i64 8)
  call void @__rust_dealloc(ptr %b2, i64 8, i64 8)
  ret void
}

; ── BUG-R4: __rust_alloc + free — cross-family ─────────────────────
; Rust's global allocator allocated the memory, but C's free()
; is used to release it. This is undefined behavior because the
; allocators may be different (e.g., jemalloc vs system malloc).
define void @rust_alloc_then_c_free(i64 %size, i64 %align) {
entry:
  %ptr = call ptr @__rust_alloc(i64 %size, i64 %align)
  ; BUG: RUST_GLOBAL memory freed with C_HEAP free — cross-family
  call void @free(ptr %ptr)
  ret void
}

; ── BUG-R5: CString::into_raw leak ─────────────────────────────────
; CString::into_raw returns a *char to C. C code will use the
; string but never calls CString::from_raw to reclaim it.
; The CString allocation leaks.
define ptr @cstring_into_raw_leak(ptr %rust_str, i64 %len) {
entry:
  %cstr = call ptr @__rust_alloc(i64 %len, i64 1)
  call void @CString::into_raw(ptr %cstr)
  ; BUG: raw pointer given to C, no CString::from_raw ever called
  ret ptr %cstr
}

; ── NOISE-N1: __rust_alloc + __rust_dealloc ────────────────────────
define void @rust_alloc_dealloc_clean(i64 %size, i64 %align) {
entry:
  %ptr = call ptr @__rust_alloc(i64 %size, i64 %align)
  call void @__rust_dealloc(ptr %ptr, i64 %size, i64 %align)
  ret void
}

; ── NOISE-N2: __rust_alloc_zeroed + __rust_dealloc ────────────────
define void @rust_alloc_zeroed_clean(i64 %size, i64 %align) {
entry:
  %ptr = call ptr @__rust_alloc_zeroed(i64 %size, i64 %align)
  call void @__rust_dealloc(ptr %ptr, i64 %size, i64 %align)
  ret void
}

; ── Declarations ───────────────────────────────────────────────────
declare ptr @__rust_alloc(i64, i64)
declare ptr @__rust_alloc_zeroed(i64, i64)
declare void @__rust_dealloc(ptr, i64, i64)
declare void @Box::into_raw(ptr)
declare ptr @Box::from_raw(ptr)
declare void @CString::into_raw(ptr)
declare ptr @CString::from_raw(ptr)
declare void @free(ptr)