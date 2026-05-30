; Zig Hidden FFI Bug Corpus
; ═══════════════════════════════════════════════════════════════════════
; Subtle Zig FFI memory management bugs using pipeline-recognized symbols.
;
;   BUG-Z1  zig_allocator_allocImpl leak — no zig_allocator_freeImpl
;   BUG-Z2  malloc + zig_allocator_freeImpl — C_HEAP/ZIG_ALLOCATOR cross-family
;   BUG-Z3  Double zig_allocator_freeImpl — stale pointer double-free
;   BUG-Z4  zig_allocator_allocImpl + free — ZIG_ALLOCATOR/C_HEAP cross-family
;   BUG-Z5  zig_allocator_allocImpl + __rust_dealloc — Zig/Rust cross-family
;   NOISE-N1  zig_allocator_allocImpl + zig_allocator_freeImpl — proper Zig pairing
;   NOISE-N2  malloc + free — proper C pairing

target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-f80:128-n8:16:32:64-S128"

; ── BUG-Z1: Zig allocator leak ─────────────────────────────────────
define ptr @zig_alloc_leak(i64 %n) {
entry:
  %mem = call ptr @zig_allocator_allocImpl(i64 %n)
  ; BUG: no zig_allocator_freeImpl — allocator detects leak at deinit
  ret ptr %mem
}

; ── BUG-Z2: C malloc + Zig free — cross-family ─────────────────────
define void @zig_cross_family_free() {
entry:
  %c_mem = call ptr @malloc(i64 256)
  ; BUG: C_HEAP memory freed with ZIG_ALLOCATOR — cross-family
  call void @zig_allocator_freeImpl(ptr %c_mem)
  ret void
}

; ── BUG-Z3: Double-free via stale pointer ──────────────────────────
define void @zig_double_free(ptr %p) {
entry:
  call void @zig_allocator_freeImpl(ptr %p)
  ; BUG: freeing already-freed pointer — double free
  call void @zig_allocator_freeImpl(ptr %p)
  ret void
}

; ── BUG-Z4: Zig alloc + C free — cross-family ─────────────────────
define void @zig_alloc_c_free(i64 %n) {
entry:
  %mem = call ptr @zig_allocator_allocImpl(i64 %n)
  ; BUG: ZIG_ALLOCATOR memory freed with C free — cross-family
  call void @free(ptr %mem)
  ret void
}

; ── BUG-Z5: Zig alloc + Rust dealloc — cross-family ───────────────
define void @zig_alloc_rust_free(i64 %n) {
entry:
  %mem = call ptr @zig_allocator_allocImpl(i64 %n)
  ; BUG: ZIG_ALLOCATOR memory freed with Rust dealloc — cross-family
  call void @__rust_dealloc(ptr %mem, i64 %n, i64 8)
  ret void
}

; ── NOISE-N1: Zig alloc + Zig free ────────────────────────────────
define void @zig_alloc_free_clean(i64 %n) {
entry:
  %mem = call ptr @zig_allocator_allocImpl(i64 %n)
  call void @zig_allocator_freeImpl(ptr %mem)
  ret void
}

; ── NOISE-N2: C malloc + C free ───────────────────────────────────
define void @zig_c_malloc_free_clean(i64 %n) {
entry:
  %p = call ptr @malloc(i64 %n)
  call void @free(ptr %p)
  ret void
}

; ── Declarations ───────────────────────────────────────────────────
declare ptr @zig_allocator_allocImpl(i64)
declare void @zig_allocator_freeImpl(ptr)
declare ptr @malloc(i64)
declare void @free(ptr)
declare void @__rust_dealloc(ptr, i64, i64)