; Go/cgo Hidden FFI Bug Corpus
; ═══════════════════════════════════════════════════════════════════════
; Subtle cgo memory management bugs using pipeline-recognized symbols.
;
;   BUG-GO1  _Cfunc_GoMalloc leak — no _Cfunc_GoFree (cgo C alloc leak)
;   BUG-GO2  _cgo_allocate + free — cross-family (GO_CGO vs C_HEAP)
;   BUG-GO3  runtime.mallocgc + _cgo_free — GC vs cgo cross-family
;   BUG-GO4  Double _cgo_free — cleanup path double-free
;   BUG-GO5  _Cfunc_GoMalloc + __rust_dealloc — Go/Rust cross-family
;   NOISE-N1  _Cfunc_GoMalloc + _Cfunc_GoFree — proper cgo pairing
;   NOISE-N2  runtime.mallocgc only — GC-managed, no leak

target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-f80:128-n8:16:32:64-S128"

; ── BUG-GO1: _Cfunc_GoMalloc leak ──────────────────────────────────
; cgo C allocation that is never freed. The Go GC does NOT manage
; C memory allocated through cgo.
define ptr @cgo_malloc_leak(i64 %size) {
entry:
  %p = call ptr @_Cfunc_GoMalloc(i64 %size)
  ; BUG: no _Cfunc_GoFree — C memory allocated via cgo leaks
  ret ptr %p
}

; ── BUG-GO2: _cgo_allocate + free — cross-family ───────────────────
; cgo-allocated memory freed with C free(). This is a cross-family
; mismatch: GO_CGO memory freed by C_HEAP free.
define void @cgo_cross_family_free(i64 %size) {
entry:
  %p = call ptr @_cgo_allocate(i64 %size)
  ; BUG: GO_CGO memory freed with C free — cross-family
  call void @free(ptr %p)
  ret void
}

; ── BUG-GO3: runtime.mallocgc + _cgo_free ──────────────────────────
; GC-managed memory freed via cgo free. This is a cross-family
; mismatch: GO_GC memory freed by GO_CGO release.
define void @cgo_gc_vs_cgo_mismatch(i64 %size) {
entry:
  %p = call ptr @runtime.mallocgc(i64 %size)
  ; BUG: GO_GC memory freed via cgo — cross-family
  call void @_cgo_free(ptr %p)
  ret void
}

; ── BUG-GO4: Double _cgo_free ──────────────────────────────────────
; Two cleanup paths both free the same cgo memory. This is the cgo
; equivalent of double-free, extremely common in error handling.
define void @cgo_double_free(ptr %p, i1 %err) {
entry:
  call void @_cgo_free(ptr %p)
  br i1 %err, label %error, label %ok

error:
  ; BUG: second _cgo_free on same pointer — double free
  call void @_cgo_free(ptr %p)
  ret void

ok:
  ret void
}

; ── BUG-GO5: _Cfunc_GoMalloc + __rust_dealloc ─────────────────────
; Go cgo allocation freed with Rust deallocator — cross-family
; between GO_CGO and RUST_GLOBAL.
define void @cgo_rust_cross_free(i64 %size) {
entry:
  %p = call ptr @_Cfunc_GoMalloc(i64 %size)
  ; BUG: GO_CGO memory freed with Rust dealloc — cross-family
  call void @__rust_dealloc(ptr %p, i64 %size, i64 8)
  ret void
}

; ── NOISE-N1: _Cfunc_GoMalloc + _Cfunc_GoFree ─────────────────────
define void @cgo_malloc_free_clean(i64 %size) {
entry:
  %p = call ptr @_Cfunc_GoMalloc(i64 %size)
  call void @_Cfunc_GoFree(ptr %p)
  ret void
}

; ── NOISE-N2: runtime.mallocgc only — GC-managed ──────────────────
define ptr @cgo_gc_alloc_only(i64 %size) {
entry:
  %p = call ptr @runtime.mallocgc(i64 %size)
  ; GC-managed, no explicit free needed
  ret ptr %p
}

; ── Declarations ───────────────────────────────────────────────────
declare ptr @_Cfunc_GoMalloc(i64)
declare void @_Cfunc_GoFree(ptr)
declare ptr @_cgo_allocate(i64)
declare void @_cgo_free(ptr)
declare ptr @runtime.mallocgc(i64)
declare void @free(ptr)
declare void @__rust_dealloc(ptr, i64, i64)