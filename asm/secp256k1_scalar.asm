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
;   sc_inv(r[4], a[4])       : r = a^(n-2) mod n  (Fermat, constant-time;
;                              secret-scalar paths: signing k^{-1})
;   sc_inv_var(r[4], a[4])   : r = a^{-1} mod n   (binary xgcd, VARIABLE-TIME;
;                              public-scalar path only: ecdsa_verify s^{-1})
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

; n in 5 signed 62-bit limbs (sc_inv_var's safegcd representation), and
; n^{-1} mod 2^62. Both checked by tests/test_ecdsa_inverse (campaign 1) and
; derivable in a line: limbs = n >> 62k & (2^62-1); inverse by Newton,
; x <- x*(2 - n*x) from x = n, six rounds.
align 16
N62_LIMBS:
    dq 0x3FD25E8CD0364141
    dq 0x2ABB739ABD2280EE
    dq 0x3FFFFFFFFFFFFFEB
    dq 0x3FFFFFFFFFFFFFFF
    dq 0x00000000000000FF
NINV62:
    dq 0x34F20099AA774EC1

; ---- GLV endomorphism constants (PERF_SCOPE.md 4.3), 4 LE limbs each.
; Transcribed from libsecp256k1 (scalar_impl.h:83 lambda, :144-159 the
; lattice constants) and re-verified in validation/glv_split_oracle.py:
; lambda^3 == 1 (mod n), lambda^2 + lambda + 1 == 0, g1/g2 are
; round(2^384 * b2 / n) and round(2^384 * -b1 / n) for Core's basis
; (a1,b1),(a2,b2) with a1*b2 - b1*a2 == n, minus_b1/minus_b2 are -b1/-b2
; mod n. Public curve parameters, not derived secrets. ----
align 16
LAMBDA_LIMBS:
    dq 0xDF02967C1B23BD72, 0x122E22EA20816678, 0xA5261C028812645A, 0x5363AD4CC05C30E0
align 16
MINUS_B1_LIMBS:
    dq 0x6F547FA90ABFE4C3, 0xE4437ED6010E8828, 0x0000000000000000, 0x0000000000000000
align 16
MINUS_B2_LIMBS:
    dq 0xD765CDA83DB1562C, 0x8A280AC50774346D, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF
align 16
G1_LIMBS:
    dq 0xE893209A45DBB031, 0x3DAA8A1471E8CA7F, 0xE86C90E49284EB15, 0x3086D221A7D46BCD
align 16
G2_LIMBS:
    dq 0x1571B4AE8AC47F71, 0x221208AC9DF506C6, 0x6F547FA90ABFE4C4, 0xE4437ED6010E8828

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
; CARRY PROPAGATION (bug fixed 2026-08-21): the original macro stopped the
; carry chain at limb k+2 (`adc r8, 0` once). When cur[k+2] was exactly
; 0xFFFFFFFFFFFFFFFF at that moment the carry out of it was DROPPED -- a lost
; 2^(64*(k+3)), i.e. for k+3 == 4 a lost 2^256 == DELTA (mod n), giving a
; result off by exactly DELTA. Random operands hit it with probability ~2^-64
; per product, but structured values hit it deterministically: sc_inv(6),
; sc_inv(n-2) and every sc_inv(n-k) for small k were wrong (found by the
; PERF_SCOPE 4.2 sc_inv_var differential, reproduced by emulating this
; exact carry truncation in Python). The chain now carries to the END of the
; 10-limb accumulator: same instruction count on every input (still
; constant-time), never a lost carry.
%macro MULACC 2
    mov    rax, [rbp-192 + (8*%1)]
    mul    qword [rbp-224 + (8*%2)]
    mov    r8,  [rbp-80 + 8*(%1+%2)]
    add    r8,  rax
    mov    [rbp-80 + 8*(%1+%2)], r8
    mov    r8,  [rbp-80 + 8*(%1+%2+1)]
    adc    r8,  rdx
    mov    [rbp-80 + 8*(%1+%2+1)], r8
%assign mcl (%1+%2+2)
%rep (10 - (%1+%2+2))
    mov    r8,  [rbp-80 + 8*mcl]
    adc    r8,  0
    mov    [rbp-80 + 8*mcl], r8
%assign mcl mcl+1
%endrep
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
    ; full carry propagation to the end of tmp (same fix as MULACC above)
%assign mcl (hh+dj+2)
%rep (10 - (hh+dj+2))
    mov    r8,  [rbp-160 + 8*mcl]
    adc    r8,  0
    mov    [rbp-160 + 8*mcl], r8
%assign mcl mcl+1
%endrep
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

; ----------------------------------------------------------------------------
; int sc_inv_var(r[4], a[4]) : r = a^-1 mod n  --  VARIABLE-TIME.
;   Bernstein-Yang "safegcd" (Fast constant-time gcd computation and modular
;   inversion, 2019), in its variable-time form: divsteps are batched 62 at a
;   time on the low 64 bits of f and g, and the resulting 2x2 transition
;   matrix is then applied to the full-width f, g and to the cofactors d, e.
;   Replaced the binary extended GCD (Stein) on 2026-09-27: that one stripped
;   one bit per step over 4-limb values and cost 3.6 us per call on this box,
;   16% of an ecdsa_verify (tests/bench_sc_inv; libsecp256k1's
;   scalar_inverse_var is 0.68 us on the same core).
;
;   Used on the ONE call site whose operand is public: ecdsa_verify's
;   w = s^{-1}. Everything that inverts a secret (signing k^{-1} in
;   wallet_core.c / wallet_msgsign.c) keeps calling sc_inv; never route a
;   secret through this function. Policy (secp256k1_point_ct.asm header):
;   variable time "is FINE and FAST for verification, where the scalar is
;   public ... It is FATAL for signing, where the scalar is the secret nonce k".
;
;   REPRESENTATION. f, g, d, e are 5 signed 62-bit limbs: value =
;   sum limb[k] * 2^(62k). Limbs 0..3 are in [0, 2^62) and limb 4 carries the
;   sign (the updates below always leave them that way). f and g shrink, so
;   they have a live length LEN (5 down to 1); a top limb that is 0 or -1 in
;   both is folded into the one below.
;
;   ONE OUTER ITERATION.
;   1. divsteps (on f0 = f mod 2^64, g0 = g mod 2^64, eta), 62 of them:
;        z = ctz(g0), capped at the steps left: g0 >>= z, u,v <<= z,
;        eta -= z. If eta < 0: eta = -eta, (f0,g0) = (g0,-f0),
;        (u,v,q,r) = (q,r,-u,-v). Then clear up to min(eta+1, steps left, 6)
;        low bits of g0 in one step: g0 += w*f0 with w = -g0/f0 mod 2^limit,
;        using f0*(f0*f0-2) == -f0^{-1} (mod 64) for odd f0; q += w*u,
;        r += w*v. Invariant: 2^62 * (f',g') = [u v; q r] (f,g).
;   2. d, e = [u v; q r] (d, e) / 2^62 mod n. The division is exact after
;        adding md*n (resp. me*n), md = -(u*d0+v*e0) * n^{-1} mod 2^62, with
;        n added up front for each negative input. Keeps d, e in (-2n, n).
;   3. f, g = [u v; q r] (f, g) / 2^62 (exact: the divsteps cleared 62 bits).
;   4. g == 0 -> done: f == +-1 and a^{-1} == d * f (mod n).
;   Start: f = n, g = a, d = 0, e = 1, eta = -1. At most 10 outer
;   iterations were seen over 1e6 random inputs (the prototype this was
;   transcribed from, validated against sc_inv before a line of asm).
;
;   Every accumulation is a signed 128-bit rdx:rax sum of products of a
;   matrix entry (|x| <= 2^62) and a limb (< 2^62 in magnitude), at most
;   three plus a carry, so it cannot overflow.
;
;   Returns eax=1 and writes r on success. Returns eax=0 and leaves r
;   untouched if a == 0 (no inverse). The caller (ecdsa_verify) already
;   rejects s == 0 and s >= n before calling; a >= n is not supported.
;   ABI: rdi=out, rsi=a. Leaf. Preserves rbx, rbp, r12-r15.
;   Frame (rsp-relative, 5-limb blocks): F @0, G @40, D @80, E @120,
;                                        ETA @160, LEN @168, OUT @176.
; ----------------------------------------------------------------------------
%define SIV_F    0
%define SIV_G    40
%define SIV_D    80
%define SIV_E    120
%define SIV_ETA  160
%define SIV_LEN  168
%define SIV_OUT  176
%define SIV_FRAME 192           ; 5 pushes + ret = 48; 48 + 192 keeps rsp 16-aligned

; x &= 2^62 - 1
%macro MASK62 1
    shl  %1, 2
    shr  %1, 2
%endmacro
; (hi:lo) >>= 62, arithmetic
%macro SAR62 2
    shrd %1, %2, 62
    sar  %2, 62
%endmacro
; (hi:lo) += reg * [mem], signed 64x64 -> 128. Clobbers rax, rdx.
%macro SMACC 4
    mov  rax, %3
    imul qword %4
    add  %1, rax
    adc  %2, rdx
%endmacro

global sc_inv_var
sc_inv_var:
    ; a == 0 -> fail, before touching anything
    mov  rax, [rsi+0]
    or   rax, [rsi+8]
    or   rax, [rsi+16]
    or   rax, [rsi+24]
    jz   .fail_early

    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, SIV_FRAME
    mov  [rsp+SIV_OUT], rdi

    ; f = n
    mov  rax, [N62_LIMBS+0]
    mov  [rsp+SIV_F+0], rax
    mov  rax, [N62_LIMBS+8]
    mov  [rsp+SIV_F+8], rax
    mov  rax, [N62_LIMBS+16]
    mov  [rsp+SIV_F+16], rax
    mov  rax, [N62_LIMBS+24]
    mov  [rsp+SIV_F+24], rax
    mov  rax, [N62_LIMBS+32]
    mov  [rsp+SIV_F+32], rax

    ; g = a, 4x64 -> 5x62
    mov  r8,  [rsi+0]
    mov  r9,  [rsi+8]
    mov  r10, [rsi+16]
    mov  r11, [rsi+24]
    mov  rax, r8
    MASK62 rax
    mov  [rsp+SIV_G+0], rax
    mov  rax, r9
    shld rax, r8, 2             ; a1<<2 | a0>>62
    MASK62 rax
    mov  [rsp+SIV_G+8], rax
    mov  rax, r10
    shld rax, r9, 4             ; a2<<4 | a1>>60
    MASK62 rax
    mov  [rsp+SIV_G+16], rax
    mov  rax, r11
    shld rax, r10, 6            ; a3<<6 | a2>>58
    MASK62 rax
    mov  [rsp+SIV_G+24], rax
    mov  rax, r11
    shr  rax, 56
    mov  [rsp+SIV_G+32], rax

    ; d = 0, e = 1, eta = -1, len = 5
    xor  eax, eax
    mov  [rsp+SIV_D+0], rax
    mov  [rsp+SIV_D+8], rax
    mov  [rsp+SIV_D+16], rax
    mov  [rsp+SIV_D+24], rax
    mov  [rsp+SIV_D+32], rax
    mov  [rsp+SIV_E+8], rax
    mov  [rsp+SIV_E+16], rax
    mov  [rsp+SIV_E+24], rax
    mov  [rsp+SIV_E+32], rax
    mov  qword [rsp+SIV_E+0], 1
    mov  qword [rsp+SIV_ETA], -1
    mov  qword [rsp+SIV_LEN], 5

.outer:
    ; ---- 1. 62 divsteps on the low words. rdi=f0 rsi=g0 r12=eta r14=steps
    ;         left, (u,v,q,r) = (r8,r9,r10,r11).
    mov  rdi, [rsp+SIV_F]
    mov  rsi, [rsp+SIV_G]
    mov  r12, [rsp+SIV_ETA]
    mov  r8d, 1
    xor  r9d, r9d
    xor  r10d, r10d
    mov  r11d, 1
    mov  r14d, 62
.ds_loop:
    mov  rax, -1
    mov  ecx, r14d
    shl  rax, cl                ; bits >= steps-left set: caps the count
    or   rax, rsi
    bsf  rcx, rax               ; z (rax != 0)
    shr  rsi, cl
    shl  r8, cl
    shl  r9, cl
    sub  r12, rcx
    sub  r14, rcx
    jz   .ds_done
    test r12, r12
    jns  .ds_noswap
    neg  r12                    ; eta = -eta
    mov  rax, rdi               ; (f,g) = (g,-f)
    mov  rdi, rsi
    neg  rax
    mov  rsi, rax
    mov  rax, r8                ; (u,v,q,r) = (q,r,-u,-v)
    mov  r8, r10
    neg  rax
    mov  r10, rax
    mov  rax, r9
    mov  r9, r11
    neg  rax
    mov  r11, rax
.ds_noswap:
    lea  rcx, [r12+1]           ; limit = min(eta+1, steps left); eta >= 0 here
    cmp  rcx, r14
    cmova rcx, r14
    neg  rcx
    add  rcx, 64                ; cl = 64 - limit
    mov  rdx, -1
    shr  rdx, cl
    and  edx, 63                ; m = 2^min(limit,6) - 1
    mov  rax, rdi
    imul rax, rdi
    sub  rax, 2
    imul rax, rdi               ; f*(f*f-2) == -1/f mod 64
    imul rax, rsi
    and  rax, rdx               ; w
    mov  rcx, rdi
    imul rcx, rax
    add  rsi, rcx               ; g += w*f
    mov  rcx, r8
    imul rcx, rax
    add  r10, rcx               ; q += w*u
    mov  rcx, r9
    imul rcx, rax
    add  r11, rcx               ; r += w*v
    jmp  .ds_loop
.ds_done:
    mov  [rsp+SIV_ETA], r12

    ; ---- 2. (d,e) = [u v; q r](d,e) / 2^62 mod n.
    ;         md=r12 me=r13, cd=r15:r14, ce=rcx:rbx.
    mov  rax, [rsp+SIV_D+32]
    sar  rax, 63                ; sd
    mov  rdx, [rsp+SIV_E+32]
    sar  rdx, 63                ; se
    mov  r12, r8
    and  r12, rax
    mov  rsi, r9
    and  rsi, rdx
    add  r12, rsi               ; md = (u & sd) + (v & se)
    mov  r13, r10
    and  r13, rax
    mov  rsi, r11
    and  rsi, rdx
    add  r13, rsi               ; me = (q & sd) + (r & se)
    xor  r14d, r14d
    xor  r15d, r15d
    xor  ebx, ebx
    xor  ecx, ecx
    SMACC r14, r15, r8,  [rsp+SIV_D]
    SMACC r14, r15, r9,  [rsp+SIV_E]
    SMACC rbx, rcx, r10, [rsp+SIV_D]
    SMACC rbx, rcx, r11, [rsp+SIV_E]
    mov  rax, [NINV62]
    imul rax, r14
    add  rax, r12
    MASK62 rax
    sub  r12, rax               ; md -= (ninv*cd + md) mod 2^62
    mov  rax, [NINV62]
    imul rax, rbx
    add  rax, r13
    MASK62 rax
    sub  r13, rax               ; me -= (ninv*ce + me) mod 2^62
    SMACC r14, r15, r12, [N62_LIMBS+0]
    SMACC rbx, rcx, r13, [N62_LIMBS+0]
    SAR62 r14, r15              ; low 62 bits are zero by construction
    SAR62 rbx, rcx
%assign k 1
%rep 4
    SMACC r14, r15, r8,  [rsp+SIV_D+8*k]
    SMACC r14, r15, r9,  [rsp+SIV_E+8*k]
    SMACC r14, r15, r12, [N62_LIMBS+8*k]
    SMACC rbx, rcx, r10, [rsp+SIV_D+8*k]
    SMACC rbx, rcx, r11, [rsp+SIV_E+8*k]
    SMACC rbx, rcx, r13, [N62_LIMBS+8*k]
    mov  rax, r14
    MASK62 rax
    mov  [rsp+SIV_D+8*(k-1)], rax
    mov  rax, rbx
    MASK62 rax
    mov  [rsp+SIV_E+8*(k-1)], rax
    SAR62 r14, r15
    SAR62 rbx, rcx
%assign k k+1
%endrep
    mov  [rsp+SIV_D+32], r14
    mov  [rsp+SIV_E+32], rbx

    ; ---- 3. (f,g) = [u v; q r](f,g) / 2^62 over the live length.
    ;         cf=r15:r14, cg=rcx:rbx, rsi=k, rdi=len.
    xor  r14d, r14d
    xor  r15d, r15d
    xor  ebx, ebx
    xor  ecx, ecx
    SMACC r14, r15, r8,  [rsp+SIV_F]
    SMACC r14, r15, r9,  [rsp+SIV_G]
    SMACC rbx, rcx, r10, [rsp+SIV_F]
    SMACC rbx, rcx, r11, [rsp+SIV_G]
    SAR62 r14, r15
    SAR62 rbx, rcx
    mov  rdi, [rsp+SIV_LEN]
    mov  esi, 1
.fg_loop:
    cmp  rsi, rdi
    jae  .fg_end
    SMACC r14, r15, r8,  [rsp+SIV_F+rsi*8]
    SMACC r14, r15, r9,  [rsp+SIV_G+rsi*8]
    SMACC rbx, rcx, r10, [rsp+SIV_F+rsi*8]
    SMACC rbx, rcx, r11, [rsp+SIV_G+rsi*8]
    mov  rax, r14
    MASK62 rax
    mov  [rsp+SIV_F-8+rsi*8], rax
    mov  rax, rbx
    MASK62 rax
    mov  [rsp+SIV_G-8+rsi*8], rax
    SAR62 r14, r15
    SAR62 rbx, rcx
    inc  rsi
    jmp  .fg_loop
.fg_end:
    mov  [rsp+SIV_F-8+rdi*8], r14
    mov  [rsp+SIV_G-8+rdi*8], rbx

    ; ---- 4. g == 0 -> done; else fold a 0/-1 top limb pair and go again.
    mov  rax, [rsp+SIV_G]
    test rax, rax
    jnz  .shrink
    mov  esi, 1
.or_loop:
    cmp  rsi, rdi
    jae  .or_end
    or   rax, [rsp+SIV_G+rsi*8]
    inc  rsi
    jmp  .or_loop
.or_end:
    test rax, rax
    jz   .done
.shrink:
    cmp  rdi, 2
    jb   .outer
    mov  rax, [rsp+SIV_F-8+rdi*8]   ; fn
    mov  rdx, [rsp+SIV_G-8+rdi*8]   ; gn
    mov  rsi, rax
    sar  rsi, 63
    xor  rsi, rax
    mov  rcx, rdx
    sar  rcx, 63
    xor  rcx, rdx
    or   rsi, rcx
    jnz  .outer
    shl  rax, 62
    or   [rsp+SIV_F-16+rdi*8], rax
    shl  rdx, 62
    or   [rsp+SIV_G-16+rdi*8], rdx
    dec  rdi
    mov  [rsp+SIV_LEN], rdi
    jmp  .outer

.done:
    ; ---- result = d * sign(f), reduced into [0, n). d as 320-bit two's
    ;      complement in r12:r11:r10:r9:r8 (limbs 0..3 are in [0,2^62)).
    mov  rax, [rsp+SIV_D+8]
    mov  r8, rax
    shl  r8, 62
    or   r8, [rsp+SIV_D+0]          ; w0 = l0 | l1<<62
    shr  rax, 2
    mov  r9, [rsp+SIV_D+16]
    mov  rdx, r9
    shl  r9, 60
    or   r9, rax                    ; w1 = l1>>2 | l2<<60
    shr  rdx, 4
    mov  r10, [rsp+SIV_D+24]
    mov  rax, r10
    shl  r10, 58
    or   r10, rdx                   ; w2 = l2>>4 | l3<<58
    shr  rax, 6
    mov  r12, [rsp+SIV_D+32]
    mov  r11, r12
    shl  r11, 56
    or   r11, rax                   ; w3 = l3>>6 | l4<<56
    sar  r12, 8                     ; w4 = l4 >> 8, sign-extended
    mov  rax, [rsp+SIV_F-8+rdi*8]   ; f's top live limb carries its sign
    test rax, rax
    jns  .addn
    not  r8                         ; d = -d
    not  r9
    not  r10
    not  r11
    not  r12
    add  r8, 1
    adc  r9, 0
    adc  r10, 0
    adc  r11, 0
    adc  r12, 0
.addn:
    test r12, r12
    jns  .subn
    add  r8,  [N_LIMBS+0]
    adc  r9,  [N_LIMBS+8]
    adc  r10, [N_LIMBS+16]
    adc  r11, [N_LIMBS+24]
    adc  r12, 0
    jmp  .addn
.subn:
    mov  rax, r8                    ; t = x - n; keep it while t >= 0
    sub  rax, [N_LIMBS+0]
    mov  rcx, r9
    sbb  rcx, [N_LIMBS+8]
    mov  rdx, r10
    sbb  rdx, [N_LIMBS+16]
    mov  rsi, r11
    sbb  rsi, [N_LIMBS+24]
    mov  rdi, r12
    sbb  rdi, 0
    js   .store
    mov  r8, rax
    mov  r9, rcx
    mov  r10, rdx
    mov  r11, rsi
    mov  r12, rdi
    jmp  .subn
.store:
    mov  rax, [rsp+SIV_OUT]
    mov  [rax+0],  r8
    mov  [rax+8],  r9
    mov  [rax+16], r10
    mov  [rax+24], r11
    add  rsp, SIV_FRAME
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.fail_early:
    xor  eax, eax
    ret

; ----------------------------------------------------------------------------
; void sc_mul_512(r[8], a[4], b[4]) : r = a*b, the full 512-bit product, NO
;   reduction. This is sc_mul's Phase 1 (16 schoolbook products with full
;   carry chains) exposed as a callable: the GLV split (PERF_SCOPE.md 4.3)
;   needs the raw product's limbs 5..7, which the reduced sc_mul discards.
;   Same frame layout as sc_mul so the MULACC macro is reused verbatim:
;   a @ rbp-192, b @ rbp-224, out @ rbp-232, cur[0..9] @ rbp-80.
;   ABI: rdi=out, rsi=a, rdx=b. Preserves rbx, r12-r15, rbp.
; ----------------------------------------------------------------------------
global sc_mul_512
sc_mul_512:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 232

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
    mov  [rbp-232], rdi

    xor  eax, eax
    lea  rdi, [rbp-80]
    mov  rcx, 10
.zero_cur:
    mov  [rdi], rax
    add  rdi, 8
    dec  rcx
    jnz  .zero_cur

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

    mov    rdi, [rbp-232]
%assign li 0
%rep 8
    mov    rax, [rbp-80 + 8*li]
    mov    [rdi + 8*li], rax
%assign li li+1
%endrep
    add  rsp, 232
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ----------------------------------------------------------------------------
; int sc_split_lambda(r1[4], r2[4], k[4]) -- GLV decomposition, PERF_SCOPE 4.3
;   k == r1 + LAMBDA*r2 (mod n), with each of r1, r2 either < 2^128 or its
;   negation mod n < 2^128 (so a 129-slot wNAF covers it; the sign rule is
;   "bit 255 set => negative", valid because n > 2^255). Exactly
;   libsecp256k1's secp256k1_scalar_split_lambda (scalar_impl.h:142-178):
;     c1 = round((k*G1) >> 384)       ; round = + bit 383 of the product
;     c2 = round((k*G2) >> 384)
;     c1 = c1*MINUS_B1 ; c2 = c2*MINUS_B2 ; r2 = c1 + c2   (all mod n)
;     r1 = k - r2*LAMBDA
;   Then the identity check libsecp runs only in VERIFY builds is run
;   ALWAYS (1 sc_mul + 1 sc_add, ~0.1 us): LAMBDA*r2 + r1 must equal k.
;   Returns eax=1 on success, eax=0 if that check fails -- the caller
;   (point_scalar_mul_glv) then falls back to the plain multiply; a verify
;   path degrades to slow-and-correct, it never aborts.
;   Requires k < n (every caller passes a reduced scalar; sc_sub needs it).
;   ABI: rdi=r1, rsi=r2, rdx=k (r1, r2 must not alias k). Preserves
;   rbx, r12-r15, rbp. Calls sc_mul_512, sc_mul, sc_add, sc_sub.
;   Frame: t @ rbp-0x50, c1 @ rbp-0x70, c2 @ rbp-0x90, prod[8] @ rbp-0xd0.
;   5 pushes (0x28) + 0xa8 = 0xd0 -> rsp = rbp-0xd0, 16-byte aligned.
; ----------------------------------------------------------------------------
global sc_split_lambda
sc_split_lambda:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0xa8
    mov  r12, rdi            ; r1
    mov  r13, rsi            ; r2
    mov  r14, rdx            ; k

    ; ---- c1 = round((k * G1) >> 384) ----
    lea  rdi, [rbp-0xd0]
    mov  rsi, r14
    lea  rdx, [G1_LIMBS]
    call sc_mul_512
    mov  rax, [rbp-0xd0+40]  ; prod[5]
    shr  rax, 63             ; rounding bit 383
    add  rax, [rbp-0xd0+48]  ; + prod[6]
    mov  [rbp-0x70], rax
    mov  rax, [rbp-0xd0+56]  ; prod[7]
    adc  rax, 0
    mov  [rbp-0x70+8], rax
    mov  eax, 0              ; mov keeps CF
    adc  rax, 0              ; 2^128 itself is reachable
    mov  [rbp-0x70+16], rax
    mov  qword [rbp-0x70+24], 0

    ; ---- c2 = round((k * G2) >> 384) ----
    lea  rdi, [rbp-0xd0]
    mov  rsi, r14
    lea  rdx, [G2_LIMBS]
    call sc_mul_512
    mov  rax, [rbp-0xd0+40]
    shr  rax, 63
    add  rax, [rbp-0xd0+48]
    mov  [rbp-0x90], rax
    mov  rax, [rbp-0xd0+56]
    adc  rax, 0
    mov  [rbp-0x90+8], rax
    mov  eax, 0
    adc  rax, 0
    mov  [rbp-0x90+16], rax
    mov  qword [rbp-0x90+24], 0

    ; ---- c1 *= MINUS_B1 ; c2 *= MINUS_B2  (mod n; sc_mul copies inputs
    ;      to its own frame first, so in-place is fine) ----
    lea  rdi, [rbp-0x70]
    lea  rsi, [rbp-0x70]
    lea  rdx, [MINUS_B1_LIMBS]
    call sc_mul
    lea  rdi, [rbp-0x90]
    lea  rsi, [rbp-0x90]
    lea  rdx, [MINUS_B2_LIMBS]
    call sc_mul

    ; ---- r2 = c1 + c2 ----
    mov  rdi, r13
    lea  rsi, [rbp-0x70]
    lea  rdx, [rbp-0x90]
    call sc_add

    ; ---- t = r2 * LAMBDA ; r1 = k - t ----
    lea  rdi, [rbp-0x50]
    mov  rsi, r13
    lea  rdx, [LAMBDA_LIMBS]
    call sc_mul
    mov  rdi, r12
    mov  rsi, r14
    lea  rdx, [rbp-0x50]
    call sc_sub

    ; ---- permanent identity check: LAMBDA*r2 + r1 == k ----
    lea  rdi, [rbp-0x50]
    lea  rsi, [LAMBDA_LIMBS]
    mov  rdx, r13
    call sc_mul
    lea  rdi, [rbp-0x50]
    lea  rsi, [rbp-0x50]
    mov  rdx, r12
    call sc_add
    mov  rax, [rbp-0x50+0]
    cmp  rax, [r14+0]
    jne  .bad
    mov  rax, [rbp-0x50+8]
    cmp  rax, [r14+8]
    jne  .bad
    mov  rax, [rbp-0x50+16]
    cmp  rax, [r14+16]
    jne  .bad
    mov  rax, [rbp-0x50+24]
    cmp  rax, [r14+24]
    jne  .bad
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    add  rsp, 0xa8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits

