; ============================================================================
; secp256k1_point_ct.asm -- CONSTANT-TIME scalar multiplication (FINDING 1).
;
; WHY THIS FILE EXISTS
;   secp256k1_point.asm's point_scalar_mul is a w=4 windowed ladder that is
;   deliberately VARIABLE-TIME: its loop bound comes from bsr on the scalar
;   (leaking bit-length), it skips zero window digits with `jz .wskip`
;   (leaking per-window digit zero-ness), it indexes TAB[digit] with a
;   secret-derived address (leaking digit via cache), and the point_add /
;   point_add_mixed it calls branch on equal / opposite / infinity.
;
;   That is FINE and FAST for verification, where the scalar is public
;   (ecdsa_verify u2*Q, schnorr_verify s*G and e*P, taproot tweak t*G).
;   It is FATAL for signing, where the scalar is the secret nonce k: a timing
;   attacker recovers k, and from k the private key d. This file provides the
;   constant-time counterpart used ONLY on secret-scalar paths.
;   point_scalar_mul is left untouched so its existing differential proof
;   (tests/run_pointmul_diff.py) still guards it byte-for-byte.
;
; APPROACH -- COMPLETE FORMULAS, NOT PATCHED JACOBIAN
;   Making the Jacobian add "infinity-safe" by cmov-ing around its special
;   cases is possible but fragile: you must enumerate and neutralise Z1=0,
;   Z2=0, P=Q and P=-Q, and each patch is a place to be subtly wrong.
;   Instead this file uses the Renes-Costello-Batina COMPLETE addition
;   formulas for prime-order short Weierstrass curves with a=0
;   (eprint 2015/1060, Alg. 7 for addition and Alg. 9 for doubling).
;   They are exception-free BY CONSTRUCTION: one straight-line sequence is
;   correct for every input pair including the identity, P=Q and P=-Q.
;   There is nothing to special-case, hence nothing to branch on.
;
;   These formulas use HOMOGENEOUS projective coordinates (X:Y:Z) meaning
;   affine (X/Z, Y/Z), identity = (0:1:0) -- NOT the Jacobian (X/Z^2, Y/Z^3)
;   convention of secp256k1_point.asm. The conversion back to Jacobian
;   happens once, at the end of point_scalar_mul_ct, so the exported ABI and
;   the 12-limb Jacobian output format are unchanged:
;       Jacobian (X*Z, Y*Z^2, Z)  <->  homogeneous (X:Y:Z)
;   Both send Z=0 to Z=0, so infinity round-trips.
;
;   Curve constant: b = 7, so b3 = 3b = 21.
;
; CONSTANT-TIME PROPERTIES (the whole point of the file)
;   * Exactly 256 loop iterations regardless of k -- no bsr, no bit-length.
;   * Every iteration performs exactly one complete double and one complete
;     add -- double-and-add-always. The add result is committed or discarded
;     by cmov, never by a jump.
;   * No memory address anywhere depends on a bit of k -- there is no
;     precomputed table, so no secret-indexed load and no cache leak.
;   * The underlying fe_mul / fe_sqr, and the inlined add/sub macros, are all
;     branch-free (they reduce with an sbb mask and cmov; there is no jump in
;     any of them).
;   Cost: 256 doublings + 256 additions, ~4x the variable-time windowed
;   version. Signing is not a hot path; block validation, which is, keeps
;   using the fast variable-time routine.
;   (2026-09-28: point_scalar_mul_gen_ct and point_scalar_mul_win_ct at the
;   end of this file keep the same properties at 64 adds / 256 doubles + 64
;   adds -- 9 us and 33 us against the ladder's 52 -- by scanning a table
;   with cmov instead of indexing it; see their header.)
;
; ABI (System V AMD64), matching secp256k1_point.asm:
;   void point_scalar_mul_ct(u64 r[12], const u64 xy[8], const u64 k[4])
;       r  = k * affine(xy), returned in JACOBIAN form (X,Y,Z), 12 limbs.
;       k == 0 (mod n) yields canonical Jacobian infinity (1,1,0).
;   Helpers (exported for the test harness; homogeneous coordinates):
;   void pointh_add(u64 r[12], const u64 p[12], const u64 q[12])
;   void pointh_double(u64 r[12], const u64 p[12])
;
;   Callee-saved rbx/r12-r15 are preserved, as the fe_* primitives require.
;
; STACK-FRAME CONVENTION (same shape as secp256k1_point.asm)
;   push rbp; mov rbp,rsp; push rbx,r12,r13,r14,r15  => save area [rbp-8..-40].
;   Scratch slots are 32 bytes each and start at rbp-0x50, strictly below the
;   save area. Every `sub rsp, N` below uses N == 8 (mod 16) so that RSP is
;   16-byte aligned at each nested call, as the ABI requires.
; ============================================================================

BITS 64

; ----------------------------------------------------------------------------
; INLINED FIELD ADD / SUB (2026-08-22, PERF_SCOPE.md 12) -- the same macros
; secp256k1_point.asm uses. The Renes-Costello-Batina formulas are
; addition-heavy by design (19a in the add, 9a in the double), so the call
; boundary costs proportionally MORE here than on the verification path.
;
; CONSTANT-TIME: every macro is straight-line -- adc/sbb/cmov only, no branch,
; no data-dependent memory address, no variable shift. It is exactly the
; instruction sequence fe_add/fe_sub already executed, minus the call. The
; property this file exists to guarantee is unchanged.
; ----------------------------------------------------------------------------
%include "secp256k1_fe_inline.inc"

extern fe_mul
extern fe_sqr

section .rodata
align 16
; b3 = 3*b = 21 as a field element (4 little-endian limbs).
B3_LIMBS:
    dq 21
    dq 0
    dq 0
    dq 0

section .text

; ----------------------------------------------------------------------------
; pointh_add(r[12], p[12], q[12]) -- complete addition, homogeneous, a=0.
; Renes-Costello-Batina Algorithm 7. 12M + 2*m_b3 + 19a.
; Correct for ALL inputs: p or q the identity, p == q, p == -q. No branches.
;
; Aliasing: p and q are only read in steps 1-15; r is only written in the
; final copy-out, so r may alias p and/or q safely.
;
; Slots: t0=-0x50 t1=-0x70 t2=-0x90 t3=-0xb0 t4=-0xd0
;        X3=-0xf0 Y3=-0x110 Z3=-0x130
; ----------------------------------------------------------------------------
global pointh_add
pointh_add:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x148

    mov r12, rdi           ; out
    mov r13, rsi           ; p
    mov r14, rdx           ; q
    FE_C_INIT              ; rbx = C for the inlined add/sub

    ; 1. t0 = X1*X2
    lea rdi, [rbp-0x50]
    lea rsi, [r13+0]
    lea rdx, [r14+0]
    call fe_mul
    ; 2. t1 = Y1*Y2
    lea rdi, [rbp-0x70]
    lea rsi, [r13+32]
    lea rdx, [r14+32]
    call fe_mul
    ; 3. t2 = Z1*Z2
    lea rdi, [rbp-0x90]
    lea rsi, [r13+64]
    lea rdx, [r14+64]
    call fe_mul
    ; 4. t3 = X1+Y1
    FE_LD   r13+0
    FE_ADDM r13+32
    FE_ST   rbp-0xb0
    ; 5. t4 = X2+Y2
    FE_LD   r14+0
    FE_ADDM r14+32
    FE_ST   rbp-0xd0
    ; 6. t3 = t3*t4
    lea rdi, [rbp-0xb0]
    lea rsi, [rbp-0xb0]
    lea rdx, [rbp-0xd0]
    call fe_mul
    ; 7+8. t3 = t3 - (t0+t1), as t3 - t0 - t1.  The reference materialised
    ;      t4 = t0+t1 and immediately consumed it; step 9 overwrites t4, so
    ;      nothing else ever reads it. Same reduction count, one slot round
    ;      trip fewer, and t4 never has to be written here at all.
    FE_LD   rbp-0xb0
    FE_SUBM rbp-0x50
    FE_SUBM rbp-0x70
    FE_ST   rbp-0xb0
    ; 9. t4 = Y1+Z1
    FE_LD   r13+32
    FE_ADDM r13+64
    FE_ST   rbp-0xd0
    ; 10. X3 = Y2+Z2
    FE_LD   r14+32
    FE_ADDM r14+64
    FE_ST   rbp-0xf0
    ; 11. t4 = t4*X3
    lea rdi, [rbp-0xd0]
    lea rsi, [rbp-0xd0]
    lea rdx, [rbp-0xf0]
    call fe_mul
    ; 12+13. t4 = t4 - (t1+t2), as t4 - t1 - t2 (X3 is rewritten at step 14)
    FE_LD   rbp-0xd0
    FE_SUBM rbp-0x70
    FE_SUBM rbp-0x90
    FE_ST   rbp-0xd0
    ; 14. X3 = X1+Z1
    FE_LD   r13+0
    FE_ADDM r13+64
    FE_ST   rbp-0xf0
    ; 15. Y3 = X2+Z2
    FE_LD   r14+0
    FE_ADDM r14+64
    FE_ST   rbp-0x110
    ; 16. X3 = X3*Y3
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0xf0]
    lea rdx, [rbp-0x110]
    call fe_mul
    ; 17+18. Y3 = X3 - (t0+t2), as X3 - t0 - t2
    FE_LD   rbp-0xf0
    FE_SUBM rbp-0x50
    FE_SUBM rbp-0x90
    FE_ST   rbp-0x110
    ; 19+20. t0 = 3*t0.  The reference parked 2*t0 in X3; X3 is rewritten at
    ;        step 25 and not read before it, so the intermediate stays in
    ;        registers and the slot store disappears.
    FE_LD   rbp-0x50
    FE_DBL
    FE_ADDM rbp-0x50
    FE_ST   rbp-0x50
    ; 21. t2 = b3*t2
    lea rdi, [rbp-0x90]
    mov rsi, B3_LIMBS
    lea rdx, [rbp-0x90]
    call fe_mul
    ; 22. Z3 = t1+t2
    FE_LD   rbp-0x70
    FE_ADDM rbp-0x90
    FE_ST   rbp-0x130
    ; 23. t1 = t1-t2  (t1 must be reloaded: the accumulator is one field
    ;     element wide and step 22 consumed it)
    FE_LD   rbp-0x70
    FE_SUBM rbp-0x90
    FE_ST   rbp-0x70
    ; 24. Y3 = b3*Y3
    lea rdi, [rbp-0x110]
    mov rsi, B3_LIMBS
    lea rdx, [rbp-0x110]
    call fe_mul
    ; 25. X3 = t4*Y3
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0xd0]
    lea rdx, [rbp-0x110]
    call fe_mul
    ; 26. t2 = t3*t1
    lea rdi, [rbp-0x90]
    lea rsi, [rbp-0xb0]
    lea rdx, [rbp-0x70]
    call fe_mul
    ; 27. X3 = t2-X3
    FE_LD   rbp-0x90
    FE_SUBM rbp-0xf0
    FE_ST   rbp-0xf0
    ; 28. Y3 = Y3*t0
    lea rdi, [rbp-0x110]
    lea rsi, [rbp-0x110]
    lea rdx, [rbp-0x50]
    call fe_mul
    ; 29. t1 = t1*Z3
    lea rdi, [rbp-0x70]
    lea rsi, [rbp-0x70]
    lea rdx, [rbp-0x130]
    call fe_mul
    ; 30. Y3 = t1+Y3
    FE_LD   rbp-0x70
    FE_ADDM rbp-0x110
    FE_ST   rbp-0x110
    ; 31. t0 = t0*t3
    lea rdi, [rbp-0x50]
    lea rsi, [rbp-0x50]
    lea rdx, [rbp-0xb0]
    call fe_mul
    ; 32. Z3 = Z3*t4
    lea rdi, [rbp-0x130]
    lea rsi, [rbp-0x130]
    lea rdx, [rbp-0xd0]
    call fe_mul
    ; 33. Z3 = Z3+t0
    FE_LD   rbp-0x130
    FE_ADDM rbp-0x50
    FE_ST   rbp-0x130

    ; copy-out: r = (X3, Y3, Z3)
    lea rsi, [rbp-0xf0]
    lea rdi, [r12+0]
    mov rcx, 4
    rep movsq
    lea rsi, [rbp-0x110]
    lea rdi, [r12+32]
    mov rcx, 4
    rep movsq
    lea rsi, [rbp-0x130]
    lea rdi, [r12+64]
    mov rcx, 4
    rep movsq

    add rsp, 0x148
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; ----------------------------------------------------------------------------
; pointh_double(r[12], p[12]) -- complete doubling, homogeneous, a=0.
; Renes-Costello-Batina Algorithm 9. 6M + 2S + 1*m_b3 + 9a.
; Correct including p == identity. No branches.
;
; Aliasing: p is read in steps 1, 5, 6, 16; r is written only in the final
; copy-out, so r may alias p.
;
; Slots: t0=-0x50 t1=-0x70 t2=-0x90 X3=-0xb0 Y3=-0xd0 Z3=-0xf0
; ----------------------------------------------------------------------------
global pointh_double
pointh_double:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x148

    mov r12, rdi           ; out
    mov r13, rsi           ; p
    FE_C_INIT              ; rbx = C for the inlined add/sub

    ; 1. t0 = Y*Y
    lea rdi, [rbp-0x50]
    lea rsi, [r13+32]
    call fe_sqr
    ; 2-4. Z3 = 8*t0 : three doublings, all three in registers
    FE_LD   rbp-0x50
    FE_DBL
    FE_DBL
    FE_DBL
    FE_ST   rbp-0xf0
    ; 5. t1 = Y*Z
    lea rdi, [rbp-0x70]
    lea rsi, [r13+32]
    lea rdx, [r13+64]
    call fe_mul
    ; 6. t2 = Z*Z
    lea rdi, [rbp-0x90]
    lea rsi, [r13+64]
    call fe_sqr
    ; 7. t2 = b3*t2
    lea rdi, [rbp-0x90]
    mov rsi, B3_LIMBS
    lea rdx, [rbp-0x90]
    call fe_mul
    ; 8. X3 = t2*Z3
    lea rdi, [rbp-0xb0]
    lea rsi, [rbp-0x90]
    lea rdx, [rbp-0xf0]
    call fe_mul
    ; 9. Y3 = t0+t2
    FE_LD   rbp-0x50
    FE_ADDM rbp-0x90
    FE_ST   rbp-0xd0
    ; 10. Z3 = t1*Z3
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0x70]
    lea rdx, [rbp-0xf0]
    call fe_mul
    ; 11+12. t2 = 3*t2.  The reference parked 2*t2 in t1; t1 is rewritten at
    ;        step 16 and not read before it, so it stays in registers.
    FE_LD   rbp-0x90
    FE_DBL
    FE_ADDM rbp-0x90
    FE_ST   rbp-0x90
    ; 13. t0 = t0-t2
    FE_LD   rbp-0x50
    FE_SUBM rbp-0x90
    FE_ST   rbp-0x50
    ; 14. Y3 = t0*Y3
    lea rdi, [rbp-0xd0]
    lea rsi, [rbp-0x50]
    lea rdx, [rbp-0xd0]
    call fe_mul
    ; 15. Y3 = X3+Y3
    FE_LD   rbp-0xb0
    FE_ADDM rbp-0xd0
    FE_ST   rbp-0xd0
    ; 16. t1 = X*Y
    lea rdi, [rbp-0x70]
    lea rsi, [r13+0]
    lea rdx, [r13+32]
    call fe_mul
    ; 17. X3 = t0*t1
    lea rdi, [rbp-0xb0]
    lea rsi, [rbp-0x50]
    lea rdx, [rbp-0x70]
    call fe_mul
    ; 18. X3 = X3+X3
    FE_LD   rbp-0xb0
    FE_DBL
    FE_ST   rbp-0xb0

    ; copy-out: r = (X3, Y3, Z3)
    lea rsi, [rbp-0xb0]
    lea rdi, [r12+0]
    mov rcx, 4
    rep movsq
    lea rsi, [rbp-0xd0]
    lea rdi, [r12+32]
    mov rcx, 4
    rep movsq
    lea rsi, [rbp-0xf0]
    lea rdi, [r12+64]
    mov rcx, 4
    rep movsq

    add rsp, 0x148
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; ----------------------------------------------------------------------------
; point_scalar_mul_ct(r[12], xy[8], k[4]) : r = k*affine(xy), CONSTANT TIME.
;
;   Pb = (x : y : 1)            homogeneous base
;   R  = (0 : 1 : 0)            identity
;   for i = 255 downto 0:       FIXED 256 iterations, independent of k
;       R = 2*R                 complete double
;       T = R + Pb              complete add (always performed)
;       R = cmov(bit_i(k), T, R)
;   return Jacobian(R) = (X*Z, Y*Z^2, Z)
;
; The add is always executed and its result selected by cmov, so the
; instruction trace and the memory access pattern are identical for every
; scalar. No secret value ever reaches an address computation or a branch.
;
; Slots: R @ rbp-0x100 (96 B), T @ rbp-0x160 (96 B), Pb @ rbp-0x1c0 (96 B),
;        kbuf @ rbp-0x1e0 (32 B).
; sub rsp, 0x1e8 (== 8 mod 16) keeps RSP aligned at nested calls.
; ----------------------------------------------------------------------------
global point_scalar_mul_ct
point_scalar_mul_ct:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x1e8

    mov r12, rdi           ; out
    mov r13, rsi           ; affine xy
    mov r14, rdx           ; k

    ; ---- kbuf = k[0..3] ----
    mov rax, [r14+0]
    mov [rbp-0x1e0+0], rax
    mov rax, [r14+8]
    mov [rbp-0x1e0+8], rax
    mov rax, [r14+16]
    mov [rbp-0x1e0+16], rax
    mov rax, [r14+24]
    mov [rbp-0x1e0+24], rax

    ; ---- Pb = (x : y : 1) ----
    lea rdi, [rbp-0x1c0]
    mov rsi, r13
    mov rcx, 8
    rep movsq              ; X, Y from affine
    mov qword [rbp-0x1c0+64], 1
    mov qword [rbp-0x1c0+72], 0
    mov qword [rbp-0x1c0+80], 0
    mov qword [rbp-0x1c0+88], 0

    ; ---- R = identity (0 : 1 : 0) ----
    xor eax, eax
    mov [rbp-0x100+0],  rax
    mov [rbp-0x100+8],  rax
    mov [rbp-0x100+16], rax
    mov [rbp-0x100+24], rax
    mov qword [rbp-0x100+32], 1
    mov [rbp-0x100+40], rax
    mov [rbp-0x100+48], rax
    mov [rbp-0x100+56], rax
    mov [rbp-0x100+64], rax
    mov [rbp-0x100+72], rax
    mov [rbp-0x100+80], rax
    mov [rbp-0x100+88], rax

    ; ---- ladder: i = 255 downto 0 (exactly 256 iterations) ----
    mov r15, 255
.loop:
    ; R = 2*R
    lea rdi, [rbp-0x100]
    lea rsi, [rbp-0x100]
    call pointh_double
    ; T = R + Pb   (always)
    lea rdi, [rbp-0x160]
    lea rsi, [rbp-0x100]
    lea rdx, [rbp-0x1c0]
    call pointh_add

    ; bit = (k >> i) & 1 ; ZF = (bit == 0)
    mov rcx, r15
    mov rdx, rcx
    shr rdx, 6                     ; limb index = i/64
    and rcx, 63                    ; bit index within limb
    lea rax, [rbp-0x1e0]
    mov rax, [rax + rdx*8]
    shr rax, cl
    and rax, 1                     ; sets ZF; no jump follows

    ; R = bit ? T : R -- 12 cmovs. `lea` and `mov r,m` do not touch flags,
    ; so ZF set by the `and` above stays valid across the whole block.
    lea rsi, [rbp-0x160]           ; T
    lea rdi, [rbp-0x100]           ; R
%assign off 0
%rep 12
    mov r8, [rsi + off]
    mov r9, [rdi + off]
    cmovz r8, r9                   ; bit == 0 -> keep R, discard T
    mov [rdi + off], r8
%assign off off+8
%endrep

    dec r15
    jns .loop

    ; ---- homogeneous (X:Y:Z) -> Jacobian (X*Z, Y*Z^2, Z) ----
    ; T is free again; use T slot as scratch for Z^2.
    lea rdi, [rbp-0x160]
    lea rsi, [rbp-0x100+64]
    call fe_sqr                    ; T[0..3] = Z^2
    lea rdi, [rbp-0x160+32]
    lea rsi, [rbp-0x100+32]
    lea rdx, [rbp-0x160]
    call fe_mul                    ; T[4..7] = Y*Z^2  (Jacobian Y)
    lea rdi, [rbp-0x160+64]
    lea rsi, [rbp-0x100+0]
    lea rdx, [rbp-0x100+64]
    call fe_mul                    ; T[8..11] = X*Z   (Jacobian X)

    ; ---- canonicalise infinity, branch-free ----
    ; If Z == 0 the point is at infinity; emit (1,1,0) to match the
    ; convention used by secp256k1_point.asm. Selected with cmov, so the
    ; timing does not reveal whether k reduced to zero.
    ; NOTE: r10/r11 are loaded BEFORE the or-chain -- `xor` writes flags and
    ; would otherwise clobber the ZF the cmovs below depend on.
    mov r10, 1
    xor r11d, r11d
    mov rax, [rbp-0x100+64]
    or  rax, [rbp-0x100+72]
    or  rax, [rbp-0x100+80]
    or  rax, [rbp-0x100+88]
    ; ZF = 1 <=> Z == 0

    ; X: limb0 = Z==0 ? 1 : (X*Z).limb0 ; limbs 1..3 = Z==0 ? 0 : ...
    mov r8, [rbp-0x160+64]
    cmovz r8, r10
    mov [r12+0], r8
    mov r8, [rbp-0x160+72]
    cmovz r8, r11
    mov [r12+8], r8
    mov r8, [rbp-0x160+80]
    cmovz r8, r11
    mov [r12+16], r8
    mov r8, [rbp-0x160+88]
    cmovz r8, r11
    mov [r12+24], r8
    ; Y
    mov r8, [rbp-0x160+32]
    cmovz r8, r10
    mov [r12+32], r8
    mov r8, [rbp-0x160+40]
    cmovz r8, r11
    mov [r12+40], r8
    mov r8, [rbp-0x160+48]
    cmovz r8, r11
    mov [r12+48], r8
    mov r8, [rbp-0x160+56]
    cmovz r8, r11
    mov [r12+56], r8
    ; Z (already 0 in the infinity case, copied verbatim)
    mov r8, [rbp-0x100+64]
    mov [r12+64], r8
    mov r8, [rbp-0x100+72]
    mov [r12+72], r8
    mov r8, [rbp-0x100+80]
    mov [r12+80], r8
    mov r8, [rbp-0x100+88]
    mov [r12+88], r8

    add rsp, 0x1e8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret


; ============================================================================
; TWO MORE CONSTANT-TIME MULTIPLIES (2026-09-28), for the BIP324 handshake.
;
;   The ladder above costs 256 complete doubles + 256 complete adds (52 us):
;   it was written for signing, which is not a hot path. ElligatorSwift is
;   not one either -- once per connection -- but it was 6.6x/3.2x behind
;   libsecp256k1 (docs/devlog/BENCHMARKS.md, 2026-09-27), and the ladder was
;   the whole gap. Both routines below keep every property listed in the
;   header (fixed iteration counts, no secret-dependent branch, no
;   secret-indexed load) and gain by shape, not by weakening anything:
;
;   point_scalar_mul_gen_ct(out[12], k[4])      out = k*G,   64 complete adds
;   point_scalar_mul_win_ct(out[12], xy[8], k[4]) out = k*P, 256 doubles + 64 adds
;
;   HOW A TABLE IS READ WITHOUT LEAKING THE DIGIT. A precomputed table indexed
;   by a secret digit leaks it through the cache line touched. Both routines
;   instead read EVERY entry of the column, in order, and keep the wanted one
;   with cmov: the digit only ever reaches a `cmp`, never an address, and the
;   loads are the same for every scalar. (libsecp256k1's ecmult_gen /
;   ecmult_const do the same scan.)
;
;   The fixed-base routine uses the w=4 comb table G_COMB_TABLE from
;   secp256k1_point.asm (T[j][i] = i * 2^(4j) * G, affine, i = 1..15): the
;   digit-0 case selects nothing and adds the identity (0:1:0), which the
;   complete formula handles like any other input. That table is what
;   point_scalar_mul_fixed indexes DIRECTLY with the digit -- fine for the
;   public u1 of ecdsa_verify, and the reason that routine must never see a
;   private key.
;
;   The variable-base routine builds its own 16-entry table (identity, P,
;   2P .. 15P) with 14 complete adds, then walks the 64 nibbles of k from the
;   top: 4 complete doubles, a full scan of the table, one complete add.
;
;   Both end in pointh_to_jac (below): the same homogeneous -> Jacobian
;   conversion and branch-free infinity canonicalisation as the ladder's
;   tail, as a function so it is written once.
;
;   Proof: tests/test_pointmul_ct_variants (against the ladder and the
;   variable-time multiplies on random and edge scalars, random base points).
; ============================================================================

extern G_COMB_TABLE            ; secp256k1_point.asm, .rodata

; ----------------------------------------------------------------------------
; pointh_to_jac(out[12], R[12]) -- homogeneous (X:Y:Z) -> Jacobian
;   (X*Z, Y*Z^2, Z); Z == 0 yields the canonical infinity (1,1,0), selected
;   with cmov so the timing does not say whether k reduced to zero.
;   Scratch T @ rbp-0x90 (96 B); sub rsp, 0x88 (== 8 mod 16).
; ----------------------------------------------------------------------------
pointh_to_jac:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x88
    mov  r12, rdi                  ; out
    mov  r13, rsi                  ; R

    lea  rdi, [rbp-0x90]
    lea  rsi, [r13+64]
    call fe_sqr                    ; T[0..3]  = Z^2
    lea  rdi, [rbp-0x90+32]
    lea  rsi, [r13+32]
    lea  rdx, [rbp-0x90]
    call fe_mul                    ; T[4..7]  = Y*Z^2   (Jacobian Y)
    lea  rdi, [rbp-0x90+64]
    mov  rsi, r13
    lea  rdx, [r13+64]
    call fe_mul                    ; T[8..11] = X*Z     (Jacobian X)

    ; r10/r11 loaded BEFORE the or-chain: xor writes flags.
    mov  r10, 1
    xor  r11d, r11d
    mov  rax, [r13+64]
    or   rax, [r13+72]
    or   rax, [r13+80]
    or   rax, [r13+88]             ; ZF = 1 <=> Z == 0
    ; X
    mov  r8, [rbp-0x90+64]
    cmovz r8, r10
    mov  [r12+0], r8
    mov  r8, [rbp-0x90+72]
    cmovz r8, r11
    mov  [r12+8], r8
    mov  r8, [rbp-0x90+80]
    cmovz r8, r11
    mov  [r12+16], r8
    mov  r8, [rbp-0x90+88]
    cmovz r8, r11
    mov  [r12+24], r8
    ; Y
    mov  r8, [rbp-0x90+32]
    cmovz r8, r10
    mov  [r12+32], r8
    mov  r8, [rbp-0x90+40]
    cmovz r8, r11
    mov  [r12+40], r8
    mov  r8, [rbp-0x90+48]
    cmovz r8, r11
    mov  [r12+48], r8
    mov  r8, [rbp-0x90+56]
    cmovz r8, r11
    mov  [r12+56], r8
    ; Z (already 0 in the infinity case, copied verbatim)
    mov  r8, [r13+64]
    mov  [r12+64], r8
    mov  r8, [r13+72]
    mov  [r12+72], r8
    mov  r8, [r13+80]
    mov  [r12+80], r8
    mov  r8, [r13+88]
    mov  [r12+88], r8

    add  rsp, 0x88
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; sets the 12 limbs at [base] to the identity (0 : 1 : 0); clobbers rax
%macro POINTH_SET_IDENTITY 1
    xor  eax, eax
    mov  [%1+0],  rax
    mov  [%1+8],  rax
    mov  [%1+16], rax
    mov  [%1+24], rax
    mov  qword [%1+32], 1
    mov  [%1+40], rax
    mov  [%1+48], rax
    mov  [%1+56], rax
    mov  [%1+64], rax
    mov  [%1+72], rax
    mov  [%1+80], rax
    mov  [%1+88], rax
%endmacro

; ebx = nibble j (in r14) of the scalar at [kbuf]: (k >> 4j) & 15.
; The shift count depends on j only, never on k.
%macro NIBBLE_OF_K 1
    mov  rcx, r14
    and  ecx, 15
    shl  ecx, 2                    ; bit offset within the limb
    mov  rax, r14
    shr  rax, 4                    ; limb index
    mov  rax, [%1 + rax*8]
    shr  rax, cl
    and  eax, 15
    mov  ebx, eax
%endmacro

; ----------------------------------------------------------------------------
; point_scalar_mul_gen_ct(out[12], k[4]) : out = k*G, CONSTANT TIME.
;   R = identity; for j = 0..63: T = cmov-scan of column j for digit_j (the
;   identity when the digit is 0); R = R + T (complete). 64 adds, no doubling.
;   k is the 256-bit integer as given (k >= n wraps like the ladder does).
;   Slots: R @ rbp-0xa0 (96), T @ rbp-0x100 (96), kbuf @ rbp-0x120 (32).
;   sub rsp, 0xf8 (== 8 mod 16).
; ----------------------------------------------------------------------------
global point_scalar_mul_gen_ct
point_scalar_mul_gen_ct:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0xf8
    mov  r12, rdi                  ; out
    mov  rax, [rsi+0]
    mov  [rbp-0x120+0], rax
    mov  rax, [rsi+8]
    mov  [rbp-0x120+8], rax
    mov  rax, [rsi+16]
    mov  [rbp-0x120+16], rax
    mov  rax, [rsi+24]
    mov  [rbp-0x120+24], rax

    POINTH_SET_IDENTITY rbp-0xa0
    xor  r14d, r14d                ; j = 0
.col:
    NIBBLE_OF_K rbp-0x120          ; ebx = digit
    POINTH_SET_IDENTITY rbp-0x100  ; T = identity: what digit 0 selects
    imul r15, r14, 960             ; column j = 15 entries * 64 bytes
    lea  r15, [G_COMB_TABLE + r15]
    mov  r10, 1
    mov  ecx, 1                    ; i = 1..15
.scan:
    cmp  ecx, ebx                  ; ZF = (i == digit); no flag writes below until add
%assign off 0
%rep 8
    mov  r8, [r15 + off]
    mov  r9, [rbp-0x100 + off]
    cmovz r9, r8
    mov  [rbp-0x100 + off], r9
%assign off off+8
%endrep
    mov  r9, [rbp-0x100+64]
    cmovz r9, r10                  ; Z = 1 for a selected affine entry
    mov  [rbp-0x100+64], r9
    add  r15, 64
    inc  ecx
    cmp  ecx, 16
    jb   .scan                     ; counter only
    lea  rdi, [rbp-0xa0]
    lea  rsi, [rbp-0xa0]
    lea  rdx, [rbp-0x100]
    call pointh_add                ; R = R + T, always
    inc  r14
    cmp  r14, 64
    jb   .col                      ; counter only

    mov  rdi, r12
    lea  rsi, [rbp-0xa0]
    call pointh_to_jac
    add  rsp, 0xf8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; point_scalar_mul_win_ct(out[12], xy[8], k[4]) : out = k*affine(xy), CONSTANT
;   TIME, fixed window w=4 over the complete formulas.
;   TB[0] = identity, TB[1] = (x:y:1), TB[i] = TB[i-1] + TB[1] (14 adds);
;   R = identity; for j = 63 downto 0: R = 16R (4 doubles); T = cmov-scan of
;   TB for digit_j; R = R + T. 256 doubles + 64 adds, all complete.
;   Slots: R @ rbp-0xa0 (96), T @ rbp-0x100 (96), kbuf @ rbp-0x120 (32),
;   TB @ rbp-0x720 (16 * 96 = 0x600). sub rsp, 0x6f8 (== 8 mod 16).
; ----------------------------------------------------------------------------
global point_scalar_mul_win_ct
point_scalar_mul_win_ct:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x6f8
    mov  r12, rdi                  ; out
    mov  r13, rsi                  ; affine xy
    mov  rax, [rdx+0]
    mov  [rbp-0x120+0], rax
    mov  rax, [rdx+8]
    mov  [rbp-0x120+8], rax
    mov  rax, [rdx+16]
    mov  [rbp-0x120+16], rax
    mov  rax, [rdx+24]
    mov  [rbp-0x120+24], rax

    ; TB[0] = identity, TB[1] = (x : y : 1)
    POINTH_SET_IDENTITY rbp-0x720
    lea  rdi, [rbp-0x720+96]
    mov  rsi, r13
    mov  rcx, 8
    rep movsq
    mov  qword [rbp-0x720+96+64], 1
    mov  qword [rbp-0x720+96+72], 0
    mov  qword [rbp-0x720+96+80], 0
    mov  qword [rbp-0x720+96+88], 0
    ; TB[i] = TB[i-1] + TB[1], i = 2..15
    mov  ebx, 2
.tab:
    imul rax, rbx, 96
    lea  rdi, [rbp-0x720]
    add  rdi, rax                  ; TB[i]
    lea  rsi, [rdi-96]             ; TB[i-1]
    lea  rdx, [rbp-0x720+96]       ; TB[1]
    call pointh_add
    inc  ebx
    cmp  ebx, 16
    jb   .tab                      ; counter only

    POINTH_SET_IDENTITY rbp-0xa0
    mov  r14, 63                   ; j = 63 downto 0
.win:
%rep 4
    lea  rdi, [rbp-0xa0]
    lea  rsi, [rbp-0xa0]
    call pointh_double
%endrep
    NIBBLE_OF_K rbp-0x120          ; ebx = digit
    lea  r15, [rbp-0x720]          ; TB[0]
    xor  ecx, ecx                  ; i = 0..15: exactly one entry matches
.scan:
    cmp  ecx, ebx                  ; ZF = (i == digit)
%assign off 0
%rep 12
    mov  r8, [r15 + off]
    mov  r9, [rbp-0x100 + off]
    cmovz r9, r8
    mov  [rbp-0x100 + off], r9
%assign off off+8
%endrep
    add  r15, 96
    inc  ecx
    cmp  ecx, 16
    jb   .scan                     ; counter only
    lea  rdi, [rbp-0xa0]
    lea  rsi, [rbp-0xa0]
    lea  rdx, [rbp-0x100]
    call pointh_add                ; R = R + T, always
    dec  r14
    jns  .win                      ; counter only

    mov  rdi, r12
    lea  rsi, [rbp-0xa0]
    call pointh_to_jac
    add  rsp, 0x6f8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret


; ----------------------------------------------------------------------------
; The table scan with AVX2 (2026-09-28). The cmov scan reads 16 entries x 12
; limbs one qword at a time (~100 ns); with AVX2 each entry is three 32-byte
; loads blended into three accumulators under a lane mask that is all-ones
; when the entry index equals the digit (~25 ns). Same property: every entry
; is read, the digit only ever meets a compare. The probe runs once and is
; cached; the choice depends on the CPU, never on the scalar.
;   point_ct_force_scan(edi): 0 re-probe, 1 AVX2, 2 cmov (tests run both).
; ----------------------------------------------------------------------------
section .data
ct_scan_path: db 0
section .rodata
align 32
CT_ONE_DD: dd 1,1,1,1,1,1,1,1
section .text
global point_ct_force_scan
point_ct_force_scan:
    mov  byte [rel ct_scan_path], dil
    ret
ct_scan_probe:                     ; eax = 1 if AVX2 usable (leaf 7 ebx.5, OSXSAVE, XCR0[2:1])
    push rbx
    xor  eax, eax
    cpuid
    cmp  eax, 7
    jb   .no
    mov  eax, 1
    xor  ecx, ecx
    cpuid
    bt   ecx, 27
    jnc  .no
    mov  eax, 7
    xor  ecx, ecx
    cpuid
    bt   ebx, 5
    jnc  .no
    xor  ecx, ecx
    xgetbv
    and  eax, 6
    cmp  eax, 6
    jne  .no
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret
; sets al = 1 (AVX2) or 2 (cmov) into [rbp-0x1f8] for this call; clobbers rax, rcx, rdx, rbx? no: cpuid inside the probe saves rbx
%macro CT_SCAN_SELECT 0
    movzx eax, byte [rel ct_scan_path]
    test eax, eax
    jnz  %%have
    call ct_scan_probe
    mov  ecx, 2
    test eax, eax
    mov  eax, 1
    cmovz eax, ecx
    mov  byte [rel ct_scan_path], al
%%have:
    mov  byte [rbp-0x1f8], al
%endmacro
; T (rbp-0x100) = entry ebx of the 16-entry, 96-byte-entry table at rbp-%1
%macro GLV_SCAN_AVX2 1
    vmovd   xmm15, ebx
    vpbroadcastd ymm15, xmm15          ; the digit in every lane
    vpxor   ymm14, ymm14, ymm14        ; the running index
    vmovdqu ymm13, [rel CT_ONE_DD]      ; unaligned: this .rodata is 16-aligned
    vpxor   ymm0, ymm0, ymm0
    vpxor   ymm1, ymm1, ymm1
    vpxor   ymm2, ymm2, ymm2
    lea  r15, [rbp-%1]
    mov  ecx, 16
%%scan:
    vpcmpeqd ymm3, ymm14, ymm15        ; all-ones lanes when index == digit
    vpblendvb ymm0, ymm0, [r15+0],  ymm3
    vpblendvb ymm1, ymm1, [r15+32], ymm3
    vpblendvb ymm2, ymm2, [r15+64], ymm3
    vpaddd  ymm14, ymm14, ymm13
    add  r15, 96
    dec  ecx
    jnz  %%scan
    vmovdqu [rbp-0x100+0],  ymm0
    vmovdqu [rbp-0x100+32], ymm1
    vmovdqu [rbp-0x100+64], ymm2
%endmacro
; either scan, by the per-call selection at [rbp-0x1f8]
%macro GLV_SCAN_ANY 1
    cmp  byte [rbp-0x1f8], 1
    jne  %%cmov
    GLV_SCAN_AVX2 %1
    jmp  %%done
%%cmov:
    GLV_SCAN %1
%%done:
%endmacro

; ============================================================================
; point_scalar_mul_glv_ct(out[12], xy[8], k[4]) : out = k*P, CONSTANT TIME,
;   the GLV endomorphism halving the doublings (2026-09-28, for the BIP324
;   ECDH: the w=4 window above was 33 of its 40 us against libsecp256k1's
;   GLV-split ecmult_const).
;
;   k = r1 + lambda*r2 (mod n) by sc_split_lambda (secp256k1_scalar.asm --
;   libsecp256k1's constant-time split: its only branch is the identity
;   check that fails only on a bug, and the scalar primitives it calls have
;   none). Each of r1, r2 is either < 2^128 or has a negation mod n that is;
;   the sign is folded into the POINT (y -> p - y, selected with cmov) so
;   both scalars are non-negative 128-bit values, and the second base is
;   lambda*P = (beta*x, y). Then 33 nibble windows (132 bits, the slack the
;   split's bound leaves) of: four complete doubles, a cmov scan of P's
;   16-entry table, one complete add, a cmov scan of lambda*P's table, one
;   complete add. 132 doubles + 66 adds, all complete; no secret reaches an
;   address or a branch (the digits reach `cmp` only).
;
;   Requires k < n (every caller passes a range-checked secret key). If the
;   split's identity check ever failed the routine falls back to the window
;   above, which is correct for any k; that branch is taken on a defect,
;   never on a value.
;
;   Slots (rbp-relative): R @ -0xa0, T @ -0x100, r1 @ -0x120, r2 @ -0x140,
;   P1 @ -0x180 (affine, 64), P2 @ -0x1c0 (64), t @ -0x1e0 (32),
;   kptr @ -0x1e8, mask @ -0x1f0, scan selection @ -0x1f8, TB1 @ -0x800
;   (0x600, up to -0x201), TB2 @ -0xe00 (0x600). sub rsp, 0xdd8 (== 8 mod 16).
; ============================================================================
extern sc_split_lambda
extern sc_sub
extern fe_sub
section .rodata
align 16
CT_ORDER_N: dq 0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF
CT_BETA:    dq 0xC1396C28719501EE, 0x9CF0497512F58995, 0x6E64479EAC3434E9, 0x7AE96A2B657C0710
CT_ZERO:    dq 0, 0, 0, 0
section .text

; fold the sign of the scalar at %1 into the affine point built at %2 from
; x = [r13], y = [r13+32]; %3 = the x to use (address). Clobbers rax, rcx,
; r8, r9, rdi, rsi, rdx.
%macro GLV_SIGN_FOLD 3
    ; t = n - r (branch-free); mask = -(r[3] >> 63); r = mask ? t : r
    lea  rdi, [rbp-0x1e0]
    lea  rsi, [rel CT_ORDER_N]
    lea  rdx, [%1]
    call sc_sub
    mov  rcx, [%1+24]
    sar  rcx, 63                   ; 0 or -1: the "negative" representation
%assign off 0
%rep 4
    mov  r8, [%1+off]
    mov  r9, [rbp-0x1e0+off]
    test rcx, rcx
    cmovnz r8, r9
    mov  [%1+off], r8
%assign off off+8
%endrep
    ; x
    mov  rax, [%3+0]
    mov  [%2+0], rax
    mov  rax, [%3+8]
    mov  [%2+8], rax
    mov  rax, [%3+16]
    mov  [%2+16], rax
    mov  rax, [%3+24]
    mov  [%2+24], rax
    ; y or p - y
    lea  rdi, [rbp-0x1e0]
    lea  rsi, [rel CT_ZERO]
    lea  rdx, [r13+32]
    call fe_sub                    ; t = -y
    mov  rcx, [%1+24]              ; (the sign was consumed above; recompute the mask from the saved copy)
    mov  rcx, [rbp-0x1f0]
%assign off 0
%rep 4
    mov  r8, [r13+32+off]
    mov  r9, [rbp-0x1e0+off]
    test rcx, rcx
    cmovnz r8, r9
    mov  [%2+32+off], r8
%assign off off+8
%endrep
%endmacro

; TB at %1 (rbp-relative offset) from the affine point at %2
%macro GLV_TABLE 2
    POINTH_SET_IDENTITY rbp-%1
    lea  rdi, [rbp-%1+96]
    lea  rsi, [%2]
    mov  rcx, 8
    rep movsq
    mov  qword [rbp-%1+96+64], 1
    mov  qword [rbp-%1+96+72], 0
    mov  qword [rbp-%1+96+80], 0
    mov  qword [rbp-%1+96+88], 0
    mov  ebx, 2
%%tab:
    imul rax, rbx, 96
    lea  rdi, [rbp-%1]
    add  rdi, rax
    lea  rsi, [rdi-96]
    lea  rdx, [rbp-%1+96]
    call pointh_add
    inc  ebx
    cmp  ebx, 16
    jb   %%tab
%endmacro

; T = cmov scan of the table at %1 for the digit in ebx
%macro GLV_SCAN 1
    lea  r15, [rbp-%1]
    xor  ecx, ecx
%%scan:
    cmp  ecx, ebx
%assign off 0
%rep 12
    mov  r8, [r15 + off]
    mov  r9, [rbp-0x100 + off]
    cmovz r9, r8
    mov  [rbp-0x100 + off], r9
%assign off off+8
%endrep
    add  r15, 96
    inc  ecx
    cmp  ecx, 16
    jb   %%scan
%endmacro

global point_scalar_mul_glv_ct
point_scalar_mul_glv_ct:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0xdd8
    mov  r12, rdi                  ; out
    mov  r13, rsi                  ; affine xy
    mov  [rbp-0x1e8], rdx          ; k
    CT_SCAN_SELECT                 ; the probe's cpuid clobbers rcx/rdx
    lea  rdi, [rbp-0x120]
    lea  rsi, [rbp-0x140]
    mov  rdx, [rbp-0x1e8]          ; k, reloaded after the selection
    call sc_split_lambda
    test eax, eax
    jz   .fallback

    ; the sign masks are needed twice (scalar fix, then y): save them
    mov  rcx, [rbp-0x120+24]
    sar  rcx, 63
    mov  [rbp-0x1f0], rcx
    GLV_SIGN_FOLD rbp-0x120, rbp-0x180, r13          ; P1 = +-P
    mov  rcx, [rbp-0x140+24]
    sar  rcx, 63
    mov  [rbp-0x1f0], rcx
    ; x2 = beta * x
    lea  rdi, [rbp-0x1e0]
    lea  rsi, [rel CT_BETA]
    mov  rdx, r13
    call fe_mul
    mov  rax, [rbp-0x1e0+0]
    mov  [rbp-0x1c0+0], rax
    mov  rax, [rbp-0x1e0+8]
    mov  [rbp-0x1c0+8], rax
    mov  rax, [rbp-0x1e0+16]
    mov  [rbp-0x1c0+16], rax
    mov  rax, [rbp-0x1e0+24]
    mov  [rbp-0x1c0+24], rax
    GLV_SIGN_FOLD rbp-0x140, rbp-0x1c0, rbp-0x1c0    ; P2 = +-lambda*P (x already in place)

    GLV_TABLE 0x800, rbp-0x180
    GLV_TABLE 0xe00, rbp-0x1c0

    POINTH_SET_IDENTITY rbp-0xa0
    mov  r14, 32                   ; nibble 32 downto 0
.win:
%rep 4
    lea  rdi, [rbp-0xa0]
    lea  rsi, [rbp-0xa0]
    call pointh_double
%endrep
    NIBBLE_OF_K rbp-0x120
    GLV_SCAN_ANY 0x800
    lea  rdi, [rbp-0xa0]
    lea  rsi, [rbp-0xa0]
    lea  rdx, [rbp-0x100]
    call pointh_add
    NIBBLE_OF_K rbp-0x140
    GLV_SCAN_ANY 0xe00
    lea  rdi, [rbp-0xa0]
    lea  rsi, [rbp-0xa0]
    lea  rdx, [rbp-0x100]
    call pointh_add
    dec  r14
    jns  .win
    vzeroupper

    mov  rdi, r12
    lea  rsi, [rbp-0xa0]
    call pointh_to_jac
    jmp  .done
.fallback:
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, [rbp-0x1e8]
    call point_scalar_mul_win_ct
.done:
    ; scalars and tables held secrets: clear what the caller does not own
    xor  eax, eax
%assign off 0
%rep 8
    mov  [rbp-0x140+off], rax
%assign off off+8
%endrep
    add  rsp, 0xdd8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
