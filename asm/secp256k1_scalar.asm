; ============================================================================
; secp256k1_scalar.asm -- scalar arithmetic mod the secp256k1 curve order n.
;   100% AI-authored x86-64 assembly (built from first principles, validated
;   against a self-written Python big-int oracle -- NOT derived from any
;   existing Bitcoin implementation).
;
; Scalars are 256-bit values reduced mod n, stored as 4 little-endian u64
; limbs (same convention as secp256k1_fe.asm / secp256k1_point.asm).
;
;   n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
;
; Exported API:
;   sc_add(r[4], a[4], b[4]) : r = (a+b) mod n
;   sc_sub(r[4], a[4], b[4]) : r = (a-b) mod n
;   sc_mul(r[4], a[4], b[4]) : r = (a*b) mod n
;   sc_sqr(r[4], a[4])       : r = (a*a) mod n
;   sc_inv(r[4], a[4])       : r = a^(n-2) mod n  (Fermat)
;
; DESIGN NOTE: sc_mul was originally a correctness-first MSB->LSB
; double-and-add over sc_add. It was replaced (2026-08-16, see commits
; 5e39cc5/71985ca) with a constant-time native schoolbook multiply +
; bounded-fold reduction (see sc_mul's own header comment below for the
; current design) once ECDSA verification became a real hot path -- this
; note previously described the abandoned slow version and was stale.
; sc_inv uses MSB->LSB square-and-multiply over the Fermat exponent n-2,
; so its cost is dominated by ~255 sc_mul calls; see sc_mul's own comment
; for that function's current cost profile.
;
;   System V AMD64 ABI: args rdi,rsi,rdx; preserve rbx/r12-r15. sc_mul/sc_inv
;   call sc_add/sc_sub, so they keep their own long-lived state in callee-saved
;   registers.
; ============================================================================

default rel

section .rodata

align 16
N_LIMBS:
    dq 0xBFD25E8CD0364141   ; limb0 of n
    dq 0xBAAEDCE6AF48A03B   ; limb1
    dq 0xFFFFFFFFFFFFFFFE   ; limb2
    dq 0xFFFFFFFFFFFFFFFF   ; limb3

; DELTA = 2^256 - n, 4 little-endian limbs. Folds an adc carry in sc_add
; (because 2^256 == DELTA mod n).
align 16
DELTA:
    dq 0x402DA1732FC9BEBF
    dq 0x4551231950B75FC4
    dq 0x0000000000000001
    dq 0x0000000000000000

; n - 2, the Fermat inverse exponent, as 32 little-endian bytes (sc_inv).
align 16
N_EXP:
    db 0x3f,0x41,0x36,0xd0,0x8c,0x5e,0xd2,0xbf
    db 0x3b,0xa0,0x48,0xaf,0xe6,0xdc,0xae,0xba
    db 0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    db 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
N_EXP_END:

section .text

; sc_mul is now DEFINED natively in this file (see sc_mul below).

; ----------------------------------------------------------------------------
; sc_add(r,a,b) = (a+b) mod n
;   s = a+b (adc chain). Sum in [0,2n) < 2^257, has at most one 257th bit.
;   If set (>=2^256): fold by adding DELTA (2^256 == DELTA mod n). This may
;   set a top bit again (DELTA ~2^128) once; fold again. Then one conditional
;   subtract of n canonicalizes.
; ----------------------------------------------------------------------------
global sc_add
sc_add:
    push rbx
    push r12
    push r13
    push r14

    mov rax, [rsi+0]
    add rax, [rdx+0]
    mov r8, rax
    mov rax, [rsi+8]
    adc rax, [rdx+8]
    mov r9, rax
    mov rax, [rsi+16]
    adc rax, [rdx+16]
    mov r10, rax
    mov rax, [rsi+24]
    adc rax, [rdx+24]
    mov r11, rax          ; CF = carry (257th bit)

    ; --- constant-time DELTA fold (replaces the branchy jnc folds below) ---
    ; a,b are reduced (< n), so s = a+b < 2n < 2^257 with at most one 257th
    ; carry bit (CF). Fold 2^256 == DELTA (mod n) by adding DELTA iff CF is
    ; set, using a mask instead of a branch so the instruction count -- and
    ; therefore the execution time -- is independent of the operand values.
    ;   w = s + (c ? DELTA : 0), computed add/mask over 4 limbs.
    ; Proof that w fits 4 limbs (no carry-out) and w < 2n (single cond-sub):
    ;   c=0: w = a+b < 2n, no 257-bit carry by definition.
    ;   c=1: t = s - 2^256 < n (since a+b < 2n => t < n); w = t+DELTA; and
    ;        n + DELTA = 2^256  =>  w <= n-1+DELTA = 2^256-1  (no carry-out).
    ;        w < n + DELTA < 2n, so one conditional subtract of n suffices.
    mov  rbx, 0
    adc  rbx, 0           ; rbx = c (0 or 1); reads CF with no branch
    neg  rbx              ; rbx = -c  =>  0, or -1 (all-ones mask)
    ; Pre-mask the four DELTA limbs into scratch regs FIRST. This keeps the
    ; and/mask ops out of the add/adc chain below -- an `and` between an `add`
    ; and an `adc` would clobber the carry flag (CF) and corrupt propagation.
    mov  rax, [DELTA+0]
    and  rax, rbx
    mov  rcx, [DELTA+8]
    and  rcx, rbx
    mov  r12, [DELTA+16]
    and  r12, rbx
    mov  r13, [DELTA+24]
    and  r13, rbx
    ; constant-time fold: w = s + (c ? DELTA : 0) over 4 limbs. No interleaved
    ; flag-clobbering instructions, so the adc chain propagates carries
    ; correctly and the instruction count is independent of c.
    add  r8, rax
    adc  r9, rcx
    adc  r10, r12
    adc  r11, r13

.folded:
    mov rax, r8
    sub rax, [N_LIMBS+0]
    mov rcx, rax
    mov rax, r9
    sbb rax, [N_LIMBS+8]
    mov rbx, rax
    mov rax, r10
    sbb rax, [N_LIMBS+16]
    mov r12, rax
    mov rax, r11
    sbb rax, [N_LIMBS+24]
    mov r13, rax
    cmovnc r8, rcx
    cmovnc r9, rbx
    cmovnc r10, r12
    cmovnc r11, r13

    mov [rdi+0], r8
    mov [rdi+8], r9
    mov [rdi+16], r10
    mov [rdi+24], r11

    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; sc_sub(r,a,b) = (a-b) mod n  : d = a-b; if borrow add n back.
; ----------------------------------------------------------------------------
global sc_sub
sc_sub:
    push rbx
    push r12
    push r13

    mov rax, [rsi+0]
    sub rax, [rdx+0]
    mov r8, rax
    mov rax, [rsi+8]
    sbb rax, [rdx+8]
    mov r9, rax
    mov rax, [rsi+16]
    sbb rax, [rdx+16]
    mov r10, rax
    mov rax, [rsi+24]
    sbb rax, [rdx+24]
    mov r11, rax
    ; CF = borrow (0 iff a >= b). Add n back iff borrow, branch-free.
    ; mask = -borrow  (all-ones if borrow, else 0), via sbb rax,rax.
    sbb rax, rax          ; rax = -CF  = 0 or -1 (mask)
    ; Pre-mask n limbs so the add/adc chain has no interleaved flag-clobber.
    mov rbx, [N_LIMBS+0]
    and rbx, rax
    mov r12, [N_LIMBS+8]
    and r12, rax
    mov r13, [N_LIMBS+16]
    and r13, rax
    mov rcx, [N_LIMBS+24]
    and rcx, rax
    add r8, rbx
    adc r9, r12
    adc r10, r13
    adc r11, rcx

    mov [rdi+0], r8
    mov [rdi+8], r9
    mov [rdi+16], r10
    mov [rdi+24], r11

    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; sc_mul(r,a,b) = (a*b) mod n  : CONSTANT-TIME 256x256 schoolbook multiply +
;   bounded-fold reduction (8 rounds, DELTA=2^256-n) + 3 constant-time
;   n-subtractions.  ABI: rdi=out[4], rsi=a[4], rdx=b[4].
;   Fast-method port of secp256k1_scalar_c.c sc_mul (NOT the abandoned slow
;   double-and-add). Validated bit-exact against the C reference by
;   tests/test_scalar (which is the oracle for this conversion).
;   Frame (rbp-based, NON-overlapping):
;     cur[0..9]  rbp-80  .. rbp-8
;     tmp[0..9]  rbp-160 .. rbp-88
;     a[0..3]    rbp-192 .. rbp-168
;     b[0..3]    rbp-224 .. rbp-200
;     out        rbp-232
;   Uses r8,r9,r10,r11,rbx,r12-r15 as scratch (callee-saved restored).
; ----------------------------------------------------------------------------
global sc_mul
sc_mul:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 232

    ; save a, b, out
    mov  rax, [rsi+0]
    mov  [rbp-192], rax
    mov  rax, [rsi+8]
    mov  [rbp-184], rax
    mov  rax, [rsi+16]
    mov  [rbp-176], rax
    mov  rax, [rsi+24]
    mov  [rbp-168], rax
    mov  rax, [rdx+0]
    mov  [rbp-224], rax
    mov  rax, [rdx+8]
    mov  [rbp-216], rax
    mov  rax, [rdx+16]
    mov  [rbp-208], rax
    mov  rax, [rdx+24]
    mov  [rbp-200], rax
    mov  [rbp-232], rdi        ; out

    ; zero cur[0..9]
    xor  eax, eax
    lea  rdi, [rbp-80]
    mov  rcx, 10
.zero_cur:
    mov  [rdi], rax
    add  rdi, 8
    dec  rcx
    jnz  .zero_cur

    ; ================= PHASE 1: schoolbook product cur = a*b ================
    ; 16 products. For (i,j) with k=i+j: cur[k]+=lo(a[i]*b[j]),
    ;   cur[k+1]+=hi (with the carry from cur[k]+lo), cur[k+2]+=carry.
%macro MULACC 2
    mov    rax, [rbp-192 + (8*%1)]
    mul    qword [rbp-224 + (8*%2)]
    mov    r8,  [rbp-80 + 8*(%1+%2)]
    add    r8,  rax
    mov    [rbp-80 + 8*(%1+%2)], r8
    mov    r8,  [rbp-80 + 8*(%1+%2+1)]
    adc    r8,  rdx
    mov    [rbp-80 + 8*(%1+%2+1)], r8
    mov    r8,  [rbp-80 + 8*(%1+%2+2)]
    adc    r8,  0
    mov    [rbp-80 + 8*(%1+%2+2)], r8
%endmacro
    MULACC 0,0
    MULACC 0,1
    MULACC 0,2
    MULACC 0,3
    MULACC 1,0
    MULACC 1,1
    MULACC 1,2
    MULACC 1,3
    MULACC 2,0
    MULACC 2,1
    MULACC 2,2
    MULACC 2,3
    MULACC 3,0
    MULACC 3,1
    MULACC 3,2
    MULACC 3,3

    ; PHASE 1 DONE. Raw 512-bit product is in cur[0..9].

    ; ==== PHASE 2: bounded-fold reduction (8 rounds) ====
    ; Round: hi=cur[4..8] (5 limbs); tmp = hi*DELTA (5x4 products into tmp[0..9]);
    ;   cur = tmp + cur[0..3] with carry, all 10 limbs copied.
%macro FOLD 0
    ; zero tmp[0..9] (rbp-160..-88)
    xor    eax, eax
    lea    rdi, [rbp-160]
    mov    rcx, 10
%%zt:
    mov    [rdi], rax
    add    rdi, 8
    dec    rcx
    jnz    %%zt
    ; tmp += hi * DELTA ; hi=cur[4+hh], DELTA[dj]
%assign hh 0
%rep 5
%assign dj 0
%rep 4
    mov    rax, [rbp-80 + 8*(4+hh)]
    mul    qword [DELTA + 8*dj]
    mov    r8,  [rbp-160 + 8*(hh+dj)]
    add    r8,  rax
    mov    [rbp-160 + 8*(hh+dj)], r8
    mov    r8,  [rbp-160 + 8*(hh+dj+1)]
    adc    r8,  rdx
    mov    [rbp-160 + 8*(hh+dj+1)], r8
    mov    r8,  [rbp-160 + 8*(hh+dj+2)]
    adc    r8,  0
    mov    [rbp-160 + 8*(hh+dj+2)], r8
%assign dj dj+1
%endrep
%assign hh hh+1
%endrep
    ; cur = tmp + cur[0..3] (carry into high), all 10 limbs
    mov    r8,  [rbp-160+0]
    add    r8,  [rbp-80+0]
    mov    [rbp-80+0], r8
    mov    r8,  [rbp-160+8]
    adc    r8,  [rbp-80+8]
    mov    [rbp-80+8], r8
    mov    r8,  [rbp-160+16]
    adc    r8,  [rbp-80+16]
    mov    [rbp-80+16], r8
    mov    r8,  [rbp-160+24]
    adc    r8,  [rbp-80+24]
    mov    [rbp-80+24], r8
    mov    r8,  [rbp-160+32]
    adc    r8,  0
    mov    [rbp-80+32], r8
    mov    r8,  [rbp-160+40]
    adc    r8,  0
    mov    [rbp-80+40], r8
    mov    r8,  [rbp-160+48]
    adc    r8,  0
    mov    [rbp-80+48], r8
    mov    r8,  [rbp-160+56]
    adc    r8,  0
    mov    [rbp-80+56], r8
    mov    r8,  [rbp-160+64]
    adc    r8,  0
    mov    [rbp-80+64], r8
    mov    r8,  [rbp-160+72]
    adc    r8,  0
    mov    [rbp-80+72], r8
%endmacro
    FOLD
    FOLD
    FOLD
    FOLD
    FOLD
    FOLD
    FOLD
    FOLD

    ; ==== PHASE 3: 3 constant-time conditional n-subtractions ====
%macro CONDS 0
    mov    r8,  [rbp-80+0]
    sub    r8,  [N_LIMBS+0]
    mov    r9,  [rbp-80+8]
    sbb    r9,  [N_LIMBS+8]
    mov    r10, [rbp-80+16]
    sbb    r10, [N_LIMBS+16]
    mov    r11, [rbp-80+24]
    sbb    r11, [N_LIMBS+24]
    sbb    rax, rax
    not    rax                 ; mask = -1 iff no-borrow (>=n => subtract), else 0
    ; constant-time select via XOR-fold: (r & mask) | (cur & ~mask)
    ;   = cur ^ (cur&mask) ^ (r&mask)  [since mask is 0 or -1]
    mov    rcx, [rbp-80+0]
    mov    rdx, rcx
    and    rdx, rax
    xor    rcx, rdx
    and    r8,  rax
    xor    r8,  rcx
    mov    [rbp-80+0], r8
    mov    rcx, [rbp-80+8]
    mov    rdx, rcx
    and    rdx, rax
    xor    rcx, rdx
    and    r9,  rax
    xor    r9,  rcx
    mov    [rbp-80+8], r9
    mov    rcx, [rbp-80+16]
    mov    rdx, rcx
    and    rdx, rax
    xor    rcx, rdx
    and    r10, rax
    xor    r10, rcx
    mov    [rbp-80+16], r10
    mov    rcx, [rbp-80+24]
    mov    rdx, rcx
    and    rdx, rax
    xor    rcx, rdx
    and    r11, rax
    xor    r11, rcx
    mov    [rbp-80+24], r11
%endmacro
    CONDS
    CONDS
    CONDS

    ; ---- store result ----
    mov    rdi, [rbp-232]
    mov    rax, [rbp-80+0]
    mov    [rdi+0], rax
    mov    rax, [rbp-80+8]
    mov    [rdi+8], rax
    mov    rax, [rbp-80+16]
    mov    [rdi+16], rax
    mov    rax, [rbp-80+24]
    mov    [rdi+24], rax
    add  rsp, 232
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
; ----------------------------------------------------------------------------

; ----------------------------------------------------------------------------
; sc_sqr(r,a) = (a*a) mod n
; ----------------------------------------------------------------------------
global sc_sqr
sc_sqr:
    ; tail-jump into sc_mul with b = a : sc_mul(r, a, a)
    mov rdx, rsi
    jmp sc_mul

; ----------------------------------------------------------------------------
; sc_inv(r,a) = a^(n-2) mod n, MSB->LSB square-and-multiply over N_EXP bytes.
;   long-lived: r12 = &resultR, r13 = &baseA, r14 = iterator index (254..0),
;               rbx = final output pointer.
; ----------------------------------------------------------------------------
global sc_inv
sc_inv:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0xa8

    mov rbx, rdi           ; output
    ; R = A local at -0x50 ; A base at -0x78
    ; copy a (rsi) -> [-0x78..-0x90] and R = a -> [-0x50..-0x68]
    mov rax, [rsi+0]
    mov [rbp-0x78], rax
    mov [rbp-0x50], rax
    mov rax, [rsi+8]
    mov [rbp-0x70], rax
    mov [rbp-0x48], rax
    mov rax, [rsi+16]
    mov [rbp-0x68], rax
    mov [rbp-0x40], rax
    mov rax, [rsi+24]
    mov [rbp-0x60], rax
    mov [rbp-0x38], rax
    lea r13, [rbp-0x78]    ; A
    lea r12, [rbp-0x50]    ; R
    lea r14, [N_EXP]       ; base pointer to the Fermat exponent bytes (load
                           ; once; index with a register is PIC-safe, whereas
                           ; a 32-bit absolute of rodata is not)

    ; iterate bits 254..0
    mov r15, 254
.inv_loop:
    ; R = R*R
    mov rdi, r12
    mov rsi, r12
    mov rdx, r12
    call sc_mul
    ; test bit r15 of N_EXP
    mov rcx, r15
    shr rcx, 3
    mov rdx, r15
    and rdx, 7
    movzx eax, byte [r14 + rcx]
    bt rax, rdx
    jnc .inv_next
    ; R = R * A
    mov rdi, r12
    mov rsi, r12
    mov rdx, r13
    call sc_mul
.inv_next:
    dec r15
    jns .inv_loop

    ; copy R (r12) -> output (rbx)
    mov rax, [r12+0]
    mov [rbx+0], rax
    mov rax, [r12+8]
    mov [rbx+8], rax
    mov rax, [r12+16]
    mov [rbx+16], rax
    mov rax, [r12+24]
    mov [rbx+24], rax

    add rsp, 0xa8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits

