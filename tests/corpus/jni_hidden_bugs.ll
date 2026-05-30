; Java/JNI Hidden FFI Bug Corpus
; ═══════════════════════════════════════════════════════════════════════
; Subtle JNI reference management bugs.
;
;   BUG-JNI1  GetStringUTFChars leak — no ReleaseStringUTFChars
;   BUG-JNI2  NewGlobalRef leak — no DeleteGlobalRef (common in native libs)
;   BUG-JNI3  NewLocalRef + DeleteGlobalRef — local/global ref mismatch
;   BUG-JNI4  GetByteArrayElements without ReleaseByteArrayElements — pin leak
;   BUG-JNI5  NewStringUTF leak — created but never released
;   NOISE-N1  NewLocalRef + DeleteLocalRef — proper local ref pairing
;   NOISE-N2  GetStringUTFChars + ReleaseStringUTFChars — proper borrow pairing

target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"

; ── BUG-JNI1: GetStringUTFChars leak ───────────────────────────────
; GetStringUTFChars returns a pinned UTF-8 string that MUST be
; released with ReleaseStringUTFChars. Forgetting to release pins
; the Java string in memory, preventing GC.
define ptr @jni_string_leak(ptr %jstr) {
entry:
  %chars = call ptr @GetStringUTFChars(ptr %jstr, ptr null)
  ; BUG: no ReleaseStringUTFChars — pinned string leaks
  ret ptr %chars
}

; ── BUG-JNI2: NewGlobalRef leak ────────────────────────────────────
; Global references must be explicitly deleted. A common bug in
; native libraries: creating a global ref for a callback but
; never deleting it when the callback is unregistered.
define ptr @jni_global_ref_leak(ptr %obj) {
entry:
  %gref = call ptr @NewGlobalRef(ptr %obj)
  ; BUG: no DeleteGlobalRef — global ref leaks
  ret ptr %gref
}

; ── BUG-JNI3: Local/global ref mismatch ────────────────────────────
; A local reference is created but a global reference deletion
; function is called. This is a type confusion in JNI ref management.
define void @jni_local_global_mismatch(ptr %obj) {
entry:
  %ref = call ptr @NewLocalRef(ptr %obj)
  ; BUG: local ref deleted with DeleteGlobalRef — ref type mismatch
  call void @DeleteGlobalRef(ptr %ref)
  ret void
}

; ── BUG-JNI4: GetByteArrayElements pin leak ────────────────────────
; GetByteArrayElements may pin the array or copy it. Without
; ReleaseByteArrayElements, the array remains pinned and the
; JVM cannot compact the heap.
define ptr @jni_array_pin_leak(ptr %array) {
entry:
  %elems = call ptr @GetByteArrayElements(ptr %array, ptr null)
  ; BUG: no ReleaseByteArrayElements — array remains pinned
  ret ptr %elems
}

; ── BUG-JNI5: NewStringUTF leak ────────────────────────────────────
; NewStringUTF creates a new Java string (global ref family).
; The returned jstring must eventually be managed, but if the
; native code returns it AND keeps a reference, it leaks.
define ptr @jni_newstring_leak(ptr %utf_chars) {
entry:
  %jstr = call ptr @NewStringUTF(ptr %utf_chars)
  ; BUG: NewStringUTF creates a reference that's never released
  ret ptr %jstr
}

; ── NOISE-N1: NewLocalRef + DeleteLocalRef ────────────────────────
define void @jni_local_ref_clean(ptr %obj) {
entry:
  %ref = call ptr @NewLocalRef(ptr %obj)
  call void @DeleteLocalRef(ptr %ref)
  ret void
}

; ── NOISE-N2: GetStringUTFChars + ReleaseStringUTFChars ───────────
define void @jni_string_clean(ptr %jstr) {
entry:
  %chars = call ptr @GetStringUTFChars(ptr %jstr, ptr null)
  call void @ReleaseStringUTFChars(ptr %jstr, ptr %chars)
  ret void
}

; ── Declarations ───────────────────────────────────────────────────
declare ptr @NewLocalRef(ptr)
declare void @DeleteLocalRef(ptr)
declare ptr @NewGlobalRef(ptr)
declare void @DeleteGlobalRef(ptr)
declare ptr @GetStringUTFChars(ptr, ptr)
declare void @ReleaseStringUTFChars(ptr, ptr)
declare ptr @GetByteArrayElements(ptr, ptr)
declare void @ReleaseByteArrayElements(ptr, ptr, i32)
declare ptr @NewStringUTF(ptr)