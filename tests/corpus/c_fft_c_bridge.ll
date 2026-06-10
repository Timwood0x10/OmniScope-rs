; C FFT Bridge FFI Corpus
; ═══════════════════════════════════════════════════════════════════════
; Simulates an FFT library bridge where fft_result is freed via different
; paths depending on error handling. Each path frees exactly once — this
; is NOT a double-free.
;
; Patterns:
;   FFT-1  Error-path vs cleanup-path free: mutually exclusive → not DoubleFree
;   FFT-2  Normal return with proper free: clean code, no issues expected

target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"

; ── FFT-1: Mutually-exclusive error/cleanup free ─────────────────
; In an FFT bridge, the result buffer may be freed on either the error
; path (allocation failed downstream) or the normal cleanup path, but
; never both. This is a common FFI pattern that triggers FP DoubleFree.
define void @fft_bridge_cleanup(ptr %result, i1 %has_error) {
entry:
  br i1 %has_error, label %error_free, label %normal_cleanup
error_free:
  ; Free on error path — only one of these two executes
  call void @free(ptr %result)
  br label %end
normal_cleanup:
  ; Free on normal path — mutually exclusive with error_free
  call void @free(ptr %result)
  br label %end
end:
  ret void
}

; ── FFT-2: Clean single-allocation single-free ───────────────────
; Standard correct usage: malloc + unconditional free. No issues expected.
define void @fft_bridge_clean(i64 %size) {
entry:
  %buf = call ptr @malloc(i64 %size)
  ; ... use buf for FFT operations ...
  call void @free(ptr %buf)
  ret void
}

; ── Declarations ───────────────────────────────────────────────────
declare ptr @malloc(i64)
declare void @free(ptr)
