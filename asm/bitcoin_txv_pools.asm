; ============================================================================
; bitcoin_txv_pools.asm -- the tx_verify allocation arenas, 100% AI-generated
; x86-64 assembly (NASM, ELF64). Phase 2 slice 5 / "phase 3 boundary" of the
; C->asm conversion (2026-08-24): the seams the earlier slices deliberately
; left in C (txv_witpool_reserve behind txv_parse_asm/txvb_parse_tx_asm,
; txv_bytepool_alloc behind txvb_classify_asm) get asm twins here, so the
; already-shipped twins can lose their last C callbacks at swap time.
; Differential: tests/test_txv_pools_diff.c.
;
;   u64   txv_witpool_reserve_asm(witpool_t* wp, u64 n)      -> off / ~0
;   u64   txv_bytepool_reserve_asm(bytepool_t* pool, u64 n)  -> off / ~0
;   u64   txv_bytepool_alloc_asm(bytepool_t* pool, const u8* src, u64 n)
;   void* txv_grow_arena_asm(void** buf, u64* cap, u64 need) -> ptr / 0
;
; Growth stays libc realloc -- the daemon links libc and the asm calls it
; like any other extern; "no-libc" is bitcoin_store.asm's discipline for
; the storage layer, not a project-wide rule (bitcoin_undo.asm documents
; the same distinction from the other side).
;
; FIDELITY: txv_witpool_reserve's twin reproduces the C's quirk exactly --
; on doubling it reallocs the ptr array THEN the len array, commits
; whichever succeeded (`if (np) wp->ptr = np; if (nl) wp->len = nl;`), and
; only then fails if either was null. A half-grown pool after OOM is
; observable state; the twin leaves the same state behind.
;
; struct offsets (offsetof-pinned): witpool_t ptr@0 len@8 cap@16 used@24;
; bytepool_t buf@0 cap@8 used@16.
; ============================================================================

BITS 64
DEFAULT REL

extern realloc

%define WP_PTR   0
%define WP_LEN   8
%define WP_CAP   16
%define WP_USED  24

%define BP_BUF   0
%define BP_CAP   8
%define BP_USED  16

section .text

; ----------------------------------------------------------------------------
; txv_witpool_reserve_asm(wp=rdi, n=rsi) -> rax off / ~0
; Frame: push rbp + 3 pushes, sub rsp,0x18 -> 0 mod 16 at the realloc calls.
; rbx = wp, r12 = n, r13 = newcap; np parked at [rbp-0x28].
; ----------------------------------------------------------------------------
global txv_witpool_reserve_asm
txv_witpool_reserve_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    sub  rsp, 0x18
    mov  rbx, rdi
    mov  r12, rsi
    ; if (used + n > cap) grow
    mov  rax, [rbx+WP_USED]
    add  rax, r12                        ; used + n (wraps like the C's u64)
    cmp  rax, [rbx+WP_CAP]
    jbe  .fit
    ; newcap = cap ? cap : 4096; while (newcap < used+n) newcap *= 2
    mov  r13, [rbx+WP_CAP]
    test r13, r13
    jnz  .dbl
    mov  r13, 4096
.dbl:
    mov  rax, [rbx+WP_USED]
    add  rax, r12
    cmp  r13, rax
    jae  .grown_size
    shl  r13, 1
    jmp  .dbl
.grown_size:
    ; np = realloc(wp->ptr, newcap * 8)
    mov  rdi, [rbx+WP_PTR]
    lea  rsi, [r13*8]
    call realloc
    mov  [rbp-0x28], rax                 ; np
    ; nl = realloc(wp->len, newcap * 4)
    mov  rdi, [rbx+WP_LEN]
    lea  rsi, [r13*4]
    call realloc
    ; commit whichever succeeded, THEN check both -- the C's exact order
    mov  rcx, [rbp-0x28]
    test rcx, rcx
    jz   .skip_ptr
    mov  [rbx+WP_PTR], rcx
.skip_ptr:
    test rax, rax
    jz   .skip_len
    mov  [rbx+WP_LEN], rax
.skip_len:
    test rcx, rcx
    jz   .oom
    test rax, rax
    jz   .oom
    mov  [rbx+WP_CAP], r13
.fit:
    mov  rax, [rbx+WP_USED]              ; off = used; used += n
    lea  rcx, [rax+r12]
    mov  [rbx+WP_USED], rcx
    jmp  .out
.oom:
    mov  rax, -1
.out:
    add  rsp, 0x18
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; txv_bytepool_reserve_asm(pool=rdi, n=rsi) -> rax off / ~0
; Doubling from 65536. Frame: push rbp + 3 pushes, sub rsp,0x18.
; rbx = pool, r12 = n, r13 = newcap.
; ----------------------------------------------------------------------------
global txv_bytepool_reserve_asm
txv_bytepool_reserve_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    sub  rsp, 0x18
    mov  rbx, rdi
    mov  r12, rsi
    mov  rax, [rbx+BP_USED]
    add  rax, r12
    cmp  rax, [rbx+BP_CAP]
    jbe  .fit
    mov  r13, [rbx+BP_CAP]
    test r13, r13
    jnz  .dbl
    mov  r13, 65536
.dbl:
    mov  rax, [rbx+BP_USED]
    add  rax, r12
    cmp  r13, rax
    jae  .grown
    shl  r13, 1
    jmp  .dbl
.grown:
    mov  rdi, [rbx+BP_BUF]
    mov  rsi, r13
    call realloc
    test rax, rax
    jz   .oom
    mov  [rbx+BP_BUF], rax
    mov  [rbx+BP_CAP], r13
.fit:
    mov  rax, [rbx+BP_USED]
    lea  rcx, [rax+r12]
    mov  [rbx+BP_USED], rcx
    jmp  .out
.oom:
    mov  rax, -1
.out:
    add  rsp, 0x18
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; txv_bytepool_alloc_asm(pool=rdi, src=rsi, n=rdx) -> rax off / ~0
; reserve + copy-in (rep movsb -- no libc memcpy needed for a bump copy).
; Frame: push rbp + 3 pushes, sub rsp,0x18.
; rbx = pool, r12 = src, r13 = n.
; ----------------------------------------------------------------------------
global txv_bytepool_alloc_asm
txv_bytepool_alloc_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    sub  rsp, 0x18
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  rsi, rdx                        ; n
    call txv_bytepool_reserve_asm        ; rdi = pool already
    cmp  rax, -1
    je   .out
    ; memcpy(pool->buf + off, src, n)
    mov  rdi, [rbx+BP_BUF]
    add  rdi, rax
    mov  rsi, r12
    mov  rcx, r13
    push rax                             ; off survives the copy
    rep  movsb
    pop  rax
.out:
    add  rsp, 0x18
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; txv_grow_arena_asm(buf=rdi(void**), cap=rsi(u64*), need=rdx) -> ptr / 0
; Exact grow_arena: realloc only when need > cap, cap set to need (not
; doubled -- the callers pass their own computed totals), 0 on OOM with
; *buf/*cap untouched.
; Frame: push rbp + 3 pushes, sub rsp,0x18.
; ----------------------------------------------------------------------------
global txv_grow_arena_asm
txv_grow_arena_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    sub  rsp, 0x18
    mov  rbx, rdi                        ; &buf
    mov  r12, rsi                        ; &cap
    mov  r13, rdx                        ; need
    cmp  rdx, [rsi]
    jbe  .have
    mov  rdi, [rbx]
    mov  rsi, r13
    call realloc
    test rax, rax
    jz   .out                            ; 0: *buf/*cap untouched
    mov  [rbx], rax
    mov  [r12], r13
    jmp  .out
.have:
    mov  rax, [rbx]
.out:
    add  rsp, 0x18
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
