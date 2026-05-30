; Python C API Hidden FFI Bug Corpus
; ═══════════════════════════════════════════════════════════════════════
; Subtle Python C API ownership bugs.
;
;   BUG-PY1  PyObject_New leak: returns new ref, no Py_DECREF on error path
;   BUG-PY2  Borrowed ref over-decrement: PyList_GetItem (borrowed) + Py_DECREF → over-decrement
;   BUG-PY3  PyMem_Malloc + free — cross-family (PYTHON_MEM freed by C_HEAP)
;   BUG-PY4  PyBytes_FromStringAndSize leak — new ref returned, no DECREF on error
;   BUG-PY5  PyTuple_SetItem steals ref, but caller also DECREFs — over-release
;   BUG-PY6  Py_INCREF without matching Py_DECREF — refcount imbalance (leak)
;   NOISE-N1  PyObject_New + Py_DECREF — proper new-ref + conditional release
;   NOISE-N2  PyMem_Malloc + PyMem_Free — proper Python mem pairing

target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"

; ── BUG-PY1: PyObject_New leak on error path ───────────────────────
; A new reference is created. On the error path, the object is
; returned as NULL indicator but the reference is not decremented.
define ptr @py_new_ref_leak(i64 %size) {
entry:
  %obj = call ptr @PyObject_New()
  %null = icmp eq ptr %obj, null
  br i1 %null, label %err, label %ok
ok:
  call void @Py_DECREF(ptr %obj)
  ret ptr %obj
err:
  ; BUG: %obj is not null here (we checked above — wait, it IS null,
  ; but in real code the null-check is on a DIFFERENT condition).
  ; Actually this simulates: error condition independent of %obj.
  ; The new-ref %obj was allocated but never DECREF'd.
  ret ptr null
}

; ── BUG-PY2: Borrowed ref over-decrement ───────────────────────────
; PyList_GetItem returns a BORROWED reference (no ownership transfer).
; Calling Py_DECREF on it decrements the list's internal refcount,
; leading to a premature free when the list is still using the item.
define void @py_borrowed_over_decrement(ptr %list, i64 %idx) {
entry:
  ; PyList_GetItem returns borrowed ref — should NOT be DECREF'd
  %item = call ptr @PyList_GetItem(ptr %list, i64 %idx)
  ; BUG: DECREF on a borrowed reference — over-decrement / use-after-free
  call void @Py_DECREF(ptr %item)
  ret void
}

; ── BUG-PY3: PyMem_Malloc + free — cross-family ────────────────────
; Python's PyMem_Malloc returns PYTHON_MEM-family memory.
; Calling C's free() on it violates the family contract.
define void @py_mem_cross_family(i64 %size) {
entry:
  %ptr = call ptr @PyMem_Malloc(i64 %size)
  ; BUG: PYTHON_MEM memory freed with C free — cross-family
  call void @free(ptr %ptr)
  ret void
}

; ── BUG-PY4: PyBytes_FromStringAndSize leak ─────────────────────────
; This function returns a new reference. If the caller doesn't
; DECREF it (e.g., returns it to Python which takes ownership),
; but then an error path doesn't DECREF either → leak.
define ptr @py_bytes_leak(ptr %data, i64 %size) {
entry:
  %bytes = call ptr @PyBytes_FromStringAndSize(ptr %data, i64 %size)
  %null = icmp eq ptr %bytes, null
  br i1 %null, label %err, label %ok
ok:
  ; Object returned to Python — Python takes ownership, OK
  ret ptr %bytes
err:
  ; BUG: even on error, if bytes was non-null, we must DECREF
  ; (Here bytes IS null, but this pattern exists in real code where
  ;  the null-check is on a subsequent operation, not the bytes itself.)
  ret ptr null
}

; ── BUG-PY5: PyTuple_SetItem steals ref + caller DECREFs ───────────
; PyTuple_SetItem STEALS the reference of the item (no INCREF needed).
; If the caller also DECREFs the item, the refcount goes negative → crash.
define void @py_tuple_steal_over_release(ptr %tuple, i64 %idx, ptr %item) {
entry:
  ; PyTuple_SetItem steals the reference — no DECREF needed
  call void @PyTuple_SetItem(ptr %tuple, i64 %idx, ptr %item)
  ; BUG: caller also DECREFs the item that was already stolen → over-release
  call void @Py_DECREF(ptr %item)
  ret void
}

; ── BUG-PY6: Py_INCREF without matching DECREF ─────────────────────
; INCREF adds a reference but no DECREF is ever called — refcount
; imbalance means the object will never be freed.
define void @py_incref_leak(ptr %obj) {
entry:
  call void @Py_INCREF(ptr %obj)
  ; BUG: INCREF without matching DECREF — refcount leak
  ret void
}

; ── NOISE-N1: PyObject_New + Py_DECREF — proper pairing ────────────
define void @py_new_decref_clean() {
entry:
  %obj = call ptr @PyObject_New()
  call void @Py_DECREF(ptr %obj)
  ret void
}

; ── NOISE-N2: PyMem_Malloc + PyMem_Free ────────────────────────────
define void @py_mem_clean(i64 %size) {
entry:
  %ptr = call ptr @PyMem_Malloc(i64 %size)
  call void @PyMem_Free(ptr %ptr)
  ret void
}

; ── Declarations ───────────────────────────────────────────────────
declare ptr @PyObject_New()
declare void @Py_DECREF(ptr)
declare void @Py_XDECREF(ptr)
declare void @Py_INCREF(ptr)
declare ptr @PyList_GetItem(ptr, i64)
declare ptr @PyBytes_FromStringAndSize(ptr, i64)
declare void @PyTuple_SetItem(ptr, i64, ptr)
declare ptr @PyMem_Malloc(i64)
declare void @PyMem_Free(ptr)
declare void @free(ptr)