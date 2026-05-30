; C Hidden FFI Bug Corpus
; ═══════════════════════════════════════════════════════════════════════
; Every function in this file contains a SUBTLE ownership / FFI bug.
; The pipeline should detect these; they are NOT obvious false positives.
;
; Bug categories:
;   BUG-C1  Early-return leak: malloc on success path, early return skips free
;   BUG-C2  Conditional double-free: free + realloc on error recovery path
;   BUG-C3  Cross-allocator: posix_memalign + free (wrong alignment contract)
;   BUG-C4  Realloc-orphan: realloc returns new ptr, old ptr still used then freed
;   BUG-C5  Library family mismatch: malloc + sqlite3_free (C_HEAP vs SQLITE_RESOURCE)
;   BUG-C6  Hidden leak via fdopen: malloc + fdopen, fclose frees FILE but not buffer
;   BUG-C7  OpenSSL partial cleanup: EVP_CIPHER_CTX_new + BIO_new, only BIO_free
;   NOISE-N1  realloc(NULL, size) is equivalent to malloc — properly freed
;   NOISE-N2  calloc + free — standard pairing

target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"

; ── BUG-C1: Early-return leak ──────────────────────────────────────
; The malloc happens unconditionally, but the null-check on `out`
; causes an early return that skips free. This is a classic
; path-sensitive leak — the "happy path" frees, the error path doesn't.
define i32 @early_return_leak(i64 %size, ptr %out) {
entry:
  %buf = call ptr @malloc(i64 %size)
  %null = icmp eq ptr %buf, null
  br i1 %null, label %err_nomem, label %check_out
check_out:
  %out_null = icmp eq ptr %out, null
  br i1 %out_null, label %err_noout, label %ok
ok:
  call void @memcpy(ptr %buf, ptr %out, i64 %size)
  call void @free(ptr %buf)
  ret i32 0
err_noout:
  ; BUG: buf was malloc'd but never freed on this path
  ret i32 -2
err_nomem:
  ret i32 -1
}

; ── BUG-C2: Conditional double-free ────────────────────────────────
; free is called unconditionally, then on the error path free is
; called again on the same pointer. This is a classic double-free
; pattern that often appears in cleanup/error-handling code.
define void @conditional_double_free(ptr %p, i1 %err) {
entry:
  call void @free(ptr %p)
  br i1 %err, label %error, label %ok
error:
  ; BUG: second free on same pointer — double-free
  call void @free(ptr %p)
  ret void
ok:
  ret void
}

; ── BUG-C3: Cross-allocator ────────────────────────────────────────
; posix_memalign requires the pointer to be freed with free(), but
; this function returns the aligned pointer to a C++ caller that
; will call operator delete on it — a cross-family free.
; The bug is invisible in the C code; it only manifests at the FFI boundary.
define ptr @cross_allocator(i64 %size, i64 %align) {
entry:
  %memptr = alloca ptr
  %rc = call i32 @posix_memalign(ptr %memptr, i64 %align, i64 %size)
  %failed = icmp ne i32 %rc, 0
  br i1 %failed, label %err, label %ok
ok:
  %ptr = load ptr, ptr %memptr
  ; Returned to C++ which will call _ZdlPv on it — cross-family!
  ret ptr %ptr
err:
  ret ptr null
}

; ── BUG-C4: Realloc-orphan ─────────────────────────────────────────
; realloc may return a NEW pointer; the old pointer is invalid.
; But this code stores the old pointer separately and frees it
; AFTER realloc — use-after-free + double-free.
define ptr @realloc_orphan(ptr %old, i64 %new_size) {
entry:
  %saved_old = alloca ptr
  store ptr %old, ptr %saved_old
  %new = call ptr @realloc(ptr %old, i64 %new_size)
  %is_null = icmp eq ptr %new, null
  br i1 %is_null, label %err, label %ok
ok:
  ; BUG: freeing the old pointer that realloc already invalidated
  %old_val = load ptr, ptr %saved_old
  call void @free(ptr %old_val)
  ret ptr %new
err:
  ret ptr null
}

; ── BUG-C5: Library family mismatch ────────────────────────────────
; malloc returns C_HEAP memory, but sqlite3_free expects SQLITE_RESOURCE.
; This compiles fine but violates the resource family contract.
define void @library_family_mismatch(ptr %data, i64 %len) {
entry:
  %buf = call ptr @malloc(i64 %len)
  ; BUG: sqlite3_free on a malloc'd pointer — family mismatch
  call void @sqlite3_free(ptr %buf)
  ret void
}

; ── BUG-C6: Hidden leak via fdopen ─────────────────────────────────
; malloc creates a buffer that gets wrapped by fdopen. fclose()
; closes the FILE* but does NOT free the original malloc'd buffer
; (fdopen does not take ownership of user-provided buffers in all
; implementations). The buffer leaks.
define void @hidden_leak_fdopen(i32 %fd, i64 %bufsize) {
entry:
  %buf = call ptr @malloc(i64 %bufsize)
  %fp = call ptr @fdopen(i32 %fd, ptr %buf)
  ; fclose frees the FILE but the original %buf leaks
  call void @fclose(ptr %fp)
  ret void
}

; ── BUG-C7: OpenSSL partial cleanup ────────────────────────────────
; Two resources allocated: EVP_CIPHER_CTX and BIO.
; Only BIO is freed — EVP_CIPHER_CTX leaks.
; This is a common pattern in error-handling shortcuts.
define ptr @openssl_partial_cleanup() {
entry:
  %ctx = call ptr @EVP_CIPHER_CTX_new()
  %bio = call ptr @BIO_new()
  %bio_null = icmp eq ptr %bio, null
  br i1 %bio_null, label %err, label %ok
ok:
  call void @BIO_free(ptr %bio)
  ; BUG: %ctx is never freed — EVP_CIPHER_CTX leak
  ret ptr %ctx
err:
  call void @BIO_free(ptr %bio)
  ret ptr null
}

; ── NOISE-N1: realloc(NULL, size) ≡ malloc, properly freed ─────────
define void @realloc_null_clean(i64 %size) {
entry:
  %ptr = call ptr @realloc(ptr null, i64 %size)
  call void @free(ptr %ptr)
  ret void
}

; ── NOISE-N2: calloc + free — standard pairing ─────────────────────
define void @calloc_free_clean(i64 %n, i64 %elem) {
entry:
  %ptr = call ptr @calloc(i64 %n, i64 %elem)
  call void @free(ptr %ptr)
  ret void
}

; ── Declarations ───────────────────────────────────────────────────
declare ptr @malloc(i64)
declare void @free(ptr)
declare ptr @calloc(i64, i64)
declare ptr @realloc(ptr, i64)
declare i32 @posix_memalign(ptr, i64, i64)
declare void @memcpy(ptr, ptr, i64)
declare ptr @fdopen(i32, ptr)
declare void @fclose(ptr)
declare void @sqlite3_free(ptr)
declare ptr @EVP_CIPHER_CTX_new()
declare void @EVP_CIPHER_CTX_free(ptr)
declare ptr @BIO_new()
declare void @BIO_free(ptr)