; ============================================================================
; bitcoin_chainwork.asm -- Stage A reorg/fork-choice primitive #1: chainwork
;   tracking. 100% AI-authored x86-64 assembly, System V AMD64 ABI.
;
;   STANDALONE / ADDITIVE: nothing in the live daemon calls anything in this
;   file yet. It is exercised only by tests/test_chainwork.c. Wiring
;   chainwork tracking into the real block-accept path is a later, separately
;   reviewed stage.
;
;   Per-header "work" (the standard formula: work = 2^256 / (target+1),
;   computed via Bitcoin Core's GetBlockProof identity
;     work = floor((2^256-1-target) / (target+1)) + 1
;   which sidesteps representing the otherwise-unrepresentable 2^256 dividend
;   directly -- (2^256-1-target) is exactly bitwise-NOT(target) and always
;   fits in 256 bits) is computed exactly via a general 256-bit/256-bit
;   unsigned integer division (u256_div, below).
;
;   CHAINWORK PRECISION: the *accumulated* running total is kept as a plain
;   128-bit (two u64 limbs, low:high) unsigned integer with a simple
;   add/adc chain -- the simplification this stage's spec explicitly invites
;   ("simplicity favored over cleverness"). 128 bits is enormous headroom:
;   real Bitcoin mainnet's per-block work has stayed under 2^90 throughout
;   its entire history (see tests/test_chainwork.c's hand-checked vectors),
;   and the cumulative total across the whole chain is nowhere near 2^128.
;   A per-header work value is computed via the EXACT 256-bit division above
;   (not a truncated/approximate one) and then only its low 128 bits are
;   kept -- for any realistic Bitcoin nBits this is exact, not an
;   approximation, because the true work value never approaches 2^128.
;
;   Exports:
;     void u256_div(u8 q_out[32], const u8 a[32], const u8 b[32])
;         q_out = floor(a / b), unsigned 256-bit little-endian 4-limb ints.
;         b must be nonzero (guaranteed by block_work's caller-side check).
;     void block_work(u8 work[16], u32 bits)
;         work = 2^256/(target(bits)+1), truncated to its low 128 bits (LE).
;         target==0 (degenerate/invalid nBits, mirrors Core's GetBlockProof)
;         -> work=0.
;     void chainwork_add(u8 out[16], const u8 a[16], const u8 b[16])
;         out = a+b, 128-bit unsigned add/adc (any overflow past bit 127 is
;         silently dropped -- unreachable for real chainwork totals).
;
;   Persistence (store_buf integration -- see bitcoin_store.asm's own header
;   comment for the base struct layout up to +48/prune_height):
;     +56..+71  (16 bytes) cur_chainwork  -- cumulative chainwork of the
;                                            in-memory tip, 128-bit LE.
;     +72..+79  (8 bytes)  chainwork_fd   -- open fd of chainwork.dat, or -1.
;   chainwork.dat holds one 16-byte little-endian cumulative-chainwork
;   record per stored height (positional, mirroring index.dat's own
;   height-indexed layout: record for height h at byte offset h*16).
;
;     int  store_chainwork_init(void* st)  -> 1 ok / -1
;         Opens/creates chainwork.dat, zeroes the +56 cache. Mirrors
;         store_init's shape; call once after store_init.
;     int  store_chainwork_append(void* st, long height, const u8 work[16])
;         -> 1 ok / -1 err
;         cumulative(height) = cumulative(height-1) [0 if height==0] + work;
;         written to chainwork.dat at height*16 and cached at st+56.
;     int  store_chainwork_get_at(void* st, long height, u8 out[16])
;         -> 1 ok / -1 (no such record)
;     int  store_chainwork_get_tip(void* st, u8 out[16]) -> 1 (always;
;         copies the st+56 cache verbatim -- 0 for a fresh/never-appended
;         store, matching an empty chain's zero cumulative work).
; ============================================================================

default rel
section .text

; ============================================================================
; compact_to_target_le(out_le[32], bits32)  -- INTERNAL (not exported).
;   out = mantissa * 256^(exponent-3), written as a 256-bit LITTLE-ENDIAN
;   4-limb integer (out[0..7] = the low 64 bits, ... out[24..31] = the high
;   64 bits). Same compact-format formula as bitcoin_hash.asm's diff_target
;   (mirrors it deliberately for identical semantics on the mantissa's
;   high-bit / "negative" edge case: we do NOT special-case it either, same
;   as diff_target's own documented behaviour), but self-contained here (no
;   cross-file dependency, no big-endian intermediate/reversal) and
;   additionally bounds-checks the mantissa's byte offset against the
;   32-byte buffer so an extreme exponent clamps to target=0 instead of
;   writing out of bounds (diff_target does not bounds-check that side;
;   real Bitcoin nBits exponents never approach it either way).
;   In: rdi=out_le, esi=bits. Clobbers rax,rcx,rdx,r8.
; ============================================================================
compact_to_target_le:
    xor  eax, eax
    mov  [rdi+0], rax
    mov  [rdi+8], rax
    mov  [rdi+16], rax
    mov  [rdi+24], rax
    mov  eax, esi
    mov  edx, esi
    shr  eax, 24              ; exponent
    and  edx, 0x00ffffff       ; mantissa
    cmp  eax, 3
    jl   .done                  ; exponent<3 -> target=0 (matches diff_target's scope)
    mov  ecx, eax
    sub  ecx, 3                  ; byte offset of the mantissa's LSB in out[]
    cmp  ecx, 29
    jg   .done                    ; would need a 3rd mantissa byte past out[31]
    mov  byte [rdi+rcx], dl
    cmp  ecx, 31
    jae  .done
    mov  r8d, edx
    shr  r8d, 8
    mov  byte [rdi+rcx+1], r8b
    cmp  ecx, 30
    jae  .done
    mov  r8d, edx
    shr  r8d, 16
    mov  byte [rdi+rcx+2], r8b
.done:
    ret

; ============================================================================
; u256_div(q_out[32], a[32], b[32]) -> q_out = floor(a/b)
;   Unsigned 256-bit / 256-bit division, both operands and the result are
;   little-endian 4x-u64-limb integers. b MUST be nonzero.
;
;   Standard bit-serial (MSB-first) restoring division: 256 iterations, one
;   dividend bit consumed per step. Not performance-critical (called at most
;   once per header) -- clarity over speed, matching this stage's stated
;   "simplicity favored over cleverness" preference. All working state lives
;   in stack memory rather than registers.
;
;   Per-iteration invariant: remainder r < divisor b BEFORE the step. After
;   shifting r left by 1 and mixing in the next dividend bit, r' = 2r+bit <
;   2b, so r' can need one bit more than b's own 256 -- that extra bit is
;   tracked via the carry flag through an rcl chain (COUT below) rather than
;   a 5th limb. Whenever COUT=1, r (the low 256 bits alone) is PROVABLY < b
;   (otherwise r'=2^256+r would be >= 2b, contradicting r'<2b) -- so the
;   plain 4-limb "r - b" (mod 2^256, via sub/sbb) always equals the true
;   r'-b in that case too, with no separate 257-bit subtract required. This
;   makes "always speculatively subtract, then decide whether to keep it by
;   COUT-OR-no-borrow" branch-free and correct in both cases.
;
;   Makes no subroutine calls -> free to use every caller-saved scratch reg;
;   only rdi (q_out) is kept live across the whole function.
; ============================================================================
global u256_div
u256_div:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0xC0
    ; ---- copy a[32] (rsi) -> A block @ rbp-0x20 ; b[32] (rdx) -> B @ rbp-0x40 ----
    mov  rax, [rsi+0]
    mov  [rbp-0x20], rax
    mov  rax, [rsi+8]
    mov  [rbp-0x18], rax
    mov  rax, [rsi+16]
    mov  [rbp-0x10], rax
    mov  rax, [rsi+24]
    mov  [rbp-0x08], rax
    mov  rax, [rdx+0]
    mov  [rbp-0x40], rax
    mov  rax, [rdx+8]
    mov  [rbp-0x38], rax
    mov  rax, [rdx+16]
    mov  [rbp-0x30], rax
    mov  rax, [rdx+24]
    mov  [rbp-0x28], rax
    ; ---- zero Q @ rbp-0x60, R @ rbp-0x80 ----
    xor  eax, eax
    mov  [rbp-0x60], rax
    mov  [rbp-0x58], rax
    mov  [rbp-0x50], rax
    mov  [rbp-0x48], rax
    mov  [rbp-0x80], rax
    mov  [rbp-0x78], rax
    mov  [rbp-0x70], rax
    mov  [rbp-0x68], rax
    ; i = 255 (loop index, authoritative copy kept in memory @ rbp-0xA8)
    mov  qword [rbp-0xA8], 255
.loop:
    ; ---- extract dividend bit i: bit = (A[i>>6] >> (i&63)) & 1 ----
    mov  rcx, [rbp-0xA8]
    mov  rax, rcx
    shr  rax, 6                 ; limb index 0..3
    mov  r8, rcx
    and  r8, 63                  ; bit position within limb
    mov  r9, [rbp+rax*8-0x20]      ; A[limb]
    mov  rcx, r8
    shr  r9, cl
    and  r9, 1                     ; r9 = bit (0/1)

    ; ---- shift R left 1 (4 limbs), capture the 257th "overflow" bit COUT ----
    clc
    mov  rax, [rbp-0x80]
    rcl  rax, 1
    mov  [rbp-0x80], rax
    mov  rax, [rbp-0x78]
    rcl  rax, 1
    mov  [rbp-0x78], rax
    mov  rax, [rbp-0x70]
    rcl  rax, 1
    mov  [rbp-0x70], rax
    mov  rax, [rbp-0x68]
    rcl  rax, 1
    mov  [rbp-0x68], rax
    setc r10b                       ; COUT (captured before anything clobbers CF)
    movzx r10, r10b

    ; ---- inject the dividend bit into R0's LSB (guaranteed 0 post-shift) ----
    or   qword [rbp-0x80], r9

    ; ---- speculative S = R - B (4 limbs); capture the borrow ----
    mov  rax, [rbp-0x80]
    sub  rax, [rbp-0x40]
    mov  [rbp-0xA0], rax
    mov  rax, [rbp-0x78]
    sbb  rax, [rbp-0x38]
    mov  [rbp-0x98], rax
    mov  rax, [rbp-0x70]
    sbb  rax, [rbp-0x30]
    mov  [rbp-0x90], rax
    mov  rax, [rbp-0x68]
    sbb  rax, [rbp-0x28]
    mov  [rbp-0x88], rax
    setc r11b                        ; CF_sub (1 = borrow, i.e. R<B)
    movzx r11, r11b

    ; ---- do_commit = COUT | !CF_sub ----
    mov  eax, r11d
    xor  eax, 1
    or   eax, r10d
    test eax, eax
    jz   .no_commit

    ; commit: R := S ; set quotient bit i
    mov  rax, [rbp-0xA0]
    mov  [rbp-0x80], rax
    mov  rax, [rbp-0x98]
    mov  [rbp-0x78], rax
    mov  rax, [rbp-0x90]
    mov  [rbp-0x70], rax
    mov  rax, [rbp-0x88]
    mov  [rbp-0x68], rax

    mov  rcx, [rbp-0xA8]
    mov  rax, rcx
    shr  rax, 6
    mov  r8, rcx
    and  r8, 63
    mov  rcx, r8
    mov  r9, 1
    shl  r9, cl
    or   qword [rbp+rax*8-0x60], r9
.no_commit:
    ; i-- ; stop after processing i==0
    mov  rax, [rbp-0xA8]
    test rax, rax
    jz   .done
    dec  rax
    mov  [rbp-0xA8], rax
    jmp  .loop
.done:
    mov  rax, [rbp-0x60]
    mov  [rdi+0], rax
    mov  rax, [rbp-0x58]
    mov  [rdi+8], rax
    mov  rax, [rbp-0x50]
    mov  [rdi+16], rax
    mov  rax, [rbp-0x48]
    mov  [rdi+24], rax
    add  rsp, 0xC0
    pop  rbp
    ret

; ============================================================================
; block_work(work[16], bits32) -> work = 2^256/(target(bits)+1), low 128 bits
;   (LE). See file header for the exact identity used and why 128 bits is
;   exact (not merely "enough") for every realistic Bitcoin difficulty.
; ============================================================================
; Frame: 2 pushes (rbp,rbx) -> sub amount must be ~=8 mod16 to keep call
; sites aligned; 0x148 (328 = 20*16+8) satisfies that with ample margin over
; the 128 bytes of locals actually used (target_le/notA/divB/q, 32B each).
;
; SAVE-AREA CLEARANCE (found the hard way -- see LOG note below): with only
; `push rbx` after `push rbp`, the saved rbx lives at [rbp-8, rbp). A local
; buffer must start at rbp-8-size or deeper to avoid writing into that slot;
; starting a 32-byte buffer at rbp-0x20 is WRONG (it reaches [rbp-0x20,
; rbp), i.e. all the way up through the saved-rbx byte) even though -0x20
; "looks" comfortably negative. All four local buffers below therefore
; start 8 bytes deeper than the naive rbp-0x20/-0x40/-0x60/-0x80 scheme.
; CONFIRMED BUG (pre-fix): the naive layout silently overwrote the saved
; rbx via compact_to_target_le's `mov [rdi+24], rax` (target_le's 4th
; qword, at rdi+24 = rbp-0x20+24 = rbp-8) -- block_work's own epilogue then
; `pop`ed that clobbered value back into rbx, corrupting the CALLER's rbx
; the moment block_work returned. It only reproduced under -O2 (where GCC
; happened to keep a live value in rbx across the call) and was invisible
; at -O0 and in trivial single-call smoke tests -- caught via a
; minimal-repro bisection (tests/test_chainwork.c crashing at -O2 but not
; -O0) down to a 2-consecutive-calls reproduction, then a stack watchpoint
; that caught `pop rbx` reading back a value nothing legitimate had written.
global block_work
block_work:
    push rbp
    mov  rbp, rsp
    push rbx
    sub  rsp, 0x148
    mov  rbx, rdi              ; work[16] out (kept live across both calls)
    lea  rdi, [rbp-0x28]        ; target_le[32] (see save-area note above)
    call compact_to_target_le
    ; target==0 -> work=0 (degenerate/invalid nBits; matches Core's
    ; GetBlockProof returning 0 for a zero/negative/overflowing target)
    mov  rax, [rbp-0x28]
    or   rax, [rbp-0x20]
    or   rax, [rbp-0x18]
    or   rax, [rbp-0x10]
    jnz  .nonzero
    xor  eax, eax
    mov  [rbx+0], rax
    mov  [rbx+8], rax
    jmp  .ret
.nonzero:
    ; notA[32] @ rbp-0x48 = ~target_le  (bitwise NOT, always fits in 256 bits)
    mov  rax, [rbp-0x28]
    not  rax
    mov  [rbp-0x48], rax
    mov  rax, [rbp-0x20]
    not  rax
    mov  [rbp-0x40], rax
    mov  rax, [rbp-0x18]
    not  rax
    mov  [rbp-0x38], rax
    mov  rax, [rbp-0x10]
    not  rax
    mov  [rbp-0x30], rax
    ; divB[32] @ rbp-0x68 = target_le + 1  (256-bit increment, add-with-carry)
    mov  rax, [rbp-0x28]
    add  rax, 1
    mov  [rbp-0x68], rax
    mov  rax, [rbp-0x20]
    adc  rax, 0
    mov  [rbp-0x60], rax
    mov  rax, [rbp-0x18]
    adc  rax, 0
    mov  [rbp-0x58], rax
    mov  rax, [rbp-0x10]
    adc  rax, 0
    mov  [rbp-0x50], rax
    jc   .overflow               ; target was 2^256-1 -> +1 wraps to 2^256
    ; q[32] @ rbp-0x88 = u256_div(notA, divB)
    lea  rdi, [rbp-0x88]
    lea  rsi, [rbp-0x48]
    lea  rdx, [rbp-0x68]
    call u256_div
    ; work = q + 1 ; keep only the low 128 bits (2 limbs)
    mov  rax, [rbp-0x88]
    add  rax, 1
    mov  [rbx+0], rax
    mov  rax, [rbp-0x80]
    adc  rax, 0
    mov  [rbx+8], rax
    jmp  .ret
.overflow:
    ; target+1 == 2^256 (target was all-ones) -> work = 2^256/2^256 = 1.
    ; Unreachable for any real compact nBits (would need mantissa=0xFFFFFF
    ; at an exponent that fills all 32 bytes) -- handled defensively only.
    mov  qword [rbx+0], 1
    mov  qword [rbx+8], 0
.ret:
    add  rsp, 0x148
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; chainwork_add(out[16], a[16], b[16]) -> out = a+b, 128-bit unsigned.
;   Plain add/adc chain (no stack frame needed -- leaf, no calls, touches no
;   callee-saved registers).
; ============================================================================
global chainwork_add
chainwork_add:
    mov  rax, [rsi+0]
    add  rax, [rdx+0]
    mov  [rdi+0], rax
    mov  rax, [rsi+8]
    adc  rax, [rdx+8]
    mov  [rdi+8], rax
    ret

; ============================================================================
; store_chainwork_init(st) -> 1 ok / -1 err
;   Opens/creates chainwork.dat and zeroes the st+56 cumulative-chainwork
;   cache. Call once, analogous to (and typically right after) store_init.
; ============================================================================
global store_chainwork_init
store_chainwork_init:
    push rbp
    mov  rbp, rsp
    push rbx
    mov  rbx, rdi
    lea  rdi, [rel cwname]
    mov  esi, 2 | 0x40        ; O_RDWR | O_CREAT
    mov  edx, 0o644
    mov  eax, 2                ; open
    syscall
    test rax, rax
    jl   .fail
    mov  [rbx+72], rax          ; chainwork_fd
    xor  eax, eax
    mov  [rbx+56], rax
    mov  [rbx+64], rax
    mov  rax, 1
    jmp  .ret
.fail:
    mov  rax, -1
.ret:
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; store_chainwork_append(st, height, work[16]) -> 1 ok / -1 err
;   cumulative(height) = cumulative(height-1) [0 if height==0] + work;
;   written to chainwork.dat at height*16 and cached at st+56. height MUST
;   be appended in order (0,1,2,...) -- same positional-append discipline
;   store_append itself relies on for index.dat.
; ============================================================================
; Frame: 4 pushes (rbp,r12,r13,r14) -> save area is [rbp-0x18, rbp) (24
; bytes: r12,r13,r14); locals must start at rbp-0x18-size or deeper (see
; block_work's save-area-clearance note -- the same class of bug was caught
; and fixed here too on re-audit: prev_cum at a naive rbp-0x20 would reach
; up into r14's saved slot). prev_cum@-0x40, new_cum@-0x60 (each 16 bytes,
; 0x20 apart, both comfortably below -0x18). sub amount must be ~=8 mod16;
; 0x68 (104 = 6*16+8) covers the deepest local (-0x60..-0x50) with margin.
global store_chainwork_append
store_chainwork_append:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    sub  rsp, 0x68
    mov  r12, rdi              ; st
    mov  r13, rsi               ; height
    mov  r14, rdx                ; work[16]
    test r13, r13
    jnz  .have_prev
    xor  eax, eax
    mov  [rbp-0x40], rax
    mov  [rbp-0x38], rax
    jmp  .prevdone
.have_prev:
    mov  rax, r13
    dec  rax
    imul rax, 16
    mov  rdi, [r12+72]           ; chainwork_fd
    lea  rsi, [rbp-0x40]           ; prev_cum[16]
    mov  edx, 16
    mov  r10, rax
    mov  eax, 17                     ; pread64
    syscall
    cmp  rax, 16
    jne  .err
.prevdone:
    lea  rdi, [rbp-0x60]             ; new_cum[16]
    lea  rsi, [rbp-0x40]              ; prev_cum
    mov  rdx, r14                      ; work
    call chainwork_add
    mov  rax, r13
    imul rax, 16
    mov  rdi, [r12+72]
    lea  rsi, [rbp-0x60]
    mov  edx, 16
    mov  r10, rax
    mov  eax, 18                        ; pwrite64
    syscall
    cmp  rax, 16
    jne  .err
    mov  rax, [rbp-0x60]
    mov  [r12+56], rax
    mov  rax, [rbp-0x58]
    mov  [r12+64], rax
    mov  rax, 1
    jmp  .ret
.err:
    mov  rax, -1
.ret:
    add  rsp, 0x68
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

; ============================================================================
; store_chainwork_get_at(st, height, out[16]) -> 1 ok / -1 (no such record)
; ============================================================================
global store_chainwork_get_at
store_chainwork_get_at:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rdx               ; out
    mov  rax, rsi                ; height
    imul rax, 16
    mov  r10, rax
    mov  rdi, [rbx+72]             ; chainwork_fd
    mov  rsi, r12
    mov  edx, 16
    mov  eax, 17                     ; pread64
    syscall
    cmp  rax, 16
    jne  .fail
    mov  rax, 1
    jmp  .ret
.fail:
    mov  rax, -1
.ret:
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; store_chainwork_get_tip(st, out[16]) -> 1 (always; copies the st+56 cache)
; ============================================================================
global store_chainwork_get_tip
store_chainwork_get_tip:
    mov  rax, [rdi+56]
    mov  [rsi+0], rax
    mov  rax, [rdi+64]
    mov  [rsi+8], rax
    mov  eax, 1
    ret

section .rodata
cwname: db "chainwork.dat", 0

section .note.GNU-stack noalloc noexec nowrite progbits
