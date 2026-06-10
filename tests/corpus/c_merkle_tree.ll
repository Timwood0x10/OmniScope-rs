; C Merkle Tree FFI Corpus
; ═══════════════════════════════════════════════════════════════════════
; Simulates a Merkle tree FFI binding where node memory is freed through
; different traversal paths. Each leaf/internal node free is on a
; mutually exclusive path.
;
; Patterns:
;   MK-1  Leaf vs internal node free: different types, mutually exclusive
;   MK-2  Clean tree teardown: correct sequential free, no DoubleFree

target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"

; ── MK-1: Mutually-exclusive node type free ──────────────────────
; In a Merkle tree FFI, nodes may be freed as either leaf nodes or
; internal nodes depending on runtime type. The free is mutually exclusive.
define void @merkle_free_node(ptr %node, i1 %is_leaf) {
entry:
  br i1 %is_leaf, label %leaf_free, label %internal_free
leaf_free:
  ; Free as leaf node — only one path executes
  call void @free(ptr %node)
  br label %done
internal_free:
  ; Free as internal node — mutually exclusive with leaf_free
  call void @free(ptr %node)
  br label %done
done:
  ret void
}

; ── MK-2: Clean allocation + single free ─────────────────────────
; Correct Merkle node lifecycle: allocate, use, free once.
define void @merkle_node_clean(i64 %node_size) {
entry:
  %node = call ptr @malloc(i64 %node_size)
  ; ... initialize and use node ...
  call void @free(ptr %node)
  ret void
}

; ── Declarations ───────────────────────────────────────────────────
declare ptr @malloc(i64)
declare void @free(ptr)
