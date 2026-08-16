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
;   * The underlying fe_add / fe_sub / fe_mul / fe_sqr are already branch-free
;     (they reduce with sbb-mask + cmovnc; the only jump in fe_mul is a
;     fixed-count 8-iteration memset).
;   Cost: 256 doublings + 256 additions, ~4x the variable-time windowed
;   version. Signing is not a hot path; block validation, which is, keeps
;   using the fast variable-time routine.
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

extern fe_add
extern fe_sub
extern fe_mul

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
    lea rdi, [rbp-0xb0]
    lea rsi, [r13+0]
    lea rdx, [r13+32]
    call fe_add
    ; 5. t4 = X2+Y2
    lea rdi, [rbp-0xd0]
    lea rsi, [r14+0]
    lea rdx, [r14+32]
    call fe_add
    ; 6. t3 = t3*t4
    lea rdi, [rbp-0xb0]
    lea rsi, [rbp-0xb0]
    lea rdx, [rbp-0xd0]
    call fe_mul
    ; 7. t4 = t0+t1
    lea rdi, [rbp-0xd0]
    lea rsi, [rbp-0x50]
    lea rdx, [rbp-0x70]
    call fe_add
    ; 8. t3 = t3-t4
    lea rdi, [rbp-0xb0]
    lea rsi, [rbp-0xb0]
    lea rdx, [rbp-0xd0]
    call fe_sub
    ; 9. t4 = Y1+Z1
    lea rdi, [rbp-0xd0]
    lea rsi, [r13+32]
    lea rdx, [r13+64]
    call fe_add
    ; 10. X3 = Y2+Z2
    lea rdi, [rbp-0xf0]
    lea rsi, [r14+32]
    lea rdx, [r14+64]
    call fe_add
    ; 11. t4 = t4*X3
    lea rdi, [rbp-0xd0]
    lea rsi, [rbp-0xd0]
    lea rdx, [rbp-0xf0]
    call fe_mul
    ; 12. X3 = t1+t2
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0x70]
    lea rdx, [rbp-0x90]
    call fe_add
    ; 13. t4 = t4-X3
    lea rdi, [rbp-0xd0]
    lea rsi, [rbp-0xd0]
    lea rdx, [rbp-0xf0]
    call fe_sub
    ; 14. X3 = X1+Z1
    lea rdi, [rbp-0xf0]
    lea rsi, [r13+0]
    lea rdx, [r13+64]
    call fe_add
    ; 15. Y3 = X2+Z2
    lea rdi, [rbp-0x110]
    lea rsi, [r14+0]
    lea rdx, [r14+64]
    call fe_add
    ; 16. X3 = X3*Y3
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0xf0]
    lea rdx, [rbp-0x110]
    call fe_mul
    ; 17. Y3 = t0+t2
    lea rdi, [rbp-0x110]
    lea rsi, [rbp-0x50]
    lea rdx, [rbp-0x90]
    call fe_add
    ; 18. Y3 = X3-Y3
    lea rdi, [rbp-0x110]
    lea rsi, [rbp-0xf0]
    lea rdx, [rbp-0x110]
    call fe_sub
    ; 19. X3 = t0+t0
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0x50]
    lea rdx, [rbp-0x50]
    call fe_add
    ; 20. t0 = X3+t0
    lea rdi, [rbp-0x50]
    lea rsi, [rbp-0xf0]
    lea rdx, [rbp-0x50]
    call fe_add
    ; 21. t2 = b3*t2
    lea rdi, [rbp-0x90]
    mov rsi, B3_LIMBS
    lea rdx, [rbp-0x90]
    call fe_mul
    ; 22. Z3 = t1+t2
    lea rdi, [rbp-0x130]
    lea rsi, [rbp-0x70]
    lea rdx, [rbp-0x90]
    call fe_add
    ; 23. t1 = t1-t2
    lea rdi, [rbp-0x70]
    lea rsi, [rbp-0x70]
    lea rdx, [rbp-0x90]
    call fe_sub
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
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0x90]
    lea rdx, [rbp-0xf0]
    call fe_sub
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
    lea rdi, [rbp-0x110]
    lea rsi, [rbp-0x70]
    lea rdx, [rbp-0x110]
    call fe_add
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
    lea rdi, [rbp-0x130]
    lea rsi, [rbp-0x130]
    lea rdx, [rbp-0x50]
    call fe_add

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

    ; 1. t0 = Y*Y
    lea rdi, [rbp-0x50]
    lea rsi, [r13+32]
    mov rdx, rsi
    call fe_mul
    ; 2. Z3 = t0+t0
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0x50]
    mov rdx, rsi
    call fe_add
    ; 3. Z3 = Z3+Z3
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0xf0]
    mov rdx, rsi
    call fe_add
    ; 4. Z3 = Z3+Z3
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0xf0]
    mov rdx, rsi
    call fe_add
    ; 5. t1 = Y*Z
    lea rdi, [rbp-0x70]
    lea rsi, [r13+32]
    lea rdx, [r13+64]
    call fe_mul
    ; 6. t2 = Z*Z
    lea rdi, [rbp-0x90]
    lea rsi, [r13+64]
    mov rdx, rsi
    call fe_mul
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
    lea rdi, [rbp-0xd0]
    lea rsi, [rbp-0x50]
    lea rdx, [rbp-0x90]
    call fe_add
    ; 10. Z3 = t1*Z3
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0x70]
    lea rdx, [rbp-0xf0]
    call fe_mul
    ; 11. t1 = t2+t2
    lea rdi, [rbp-0x70]
    lea rsi, [rbp-0x90]
    mov rdx, rsi
    call fe_add
    ; 12. t2 = t1+t2
    lea rdi, [rbp-0x90]
    lea rsi, [rbp-0x70]
    lea rdx, [rbp-0x90]
    call fe_add
    ; 13. t0 = t0-t2
    lea rdi, [rbp-0x50]
    lea rsi, [rbp-0x50]
    lea rdx, [rbp-0x90]
    call fe_sub
    ; 14. Y3 = t0*Y3
    lea rdi, [rbp-0xd0]
    lea rsi, [rbp-0x50]
    lea rdx, [rbp-0xd0]
    call fe_mul
    ; 15. Y3 = X3+Y3
    lea rdi, [rbp-0xd0]
    lea rsi, [rbp-0xb0]
    lea rdx, [rbp-0xd0]
    call fe_add
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
    lea rdi, [rbp-0xb0]
    lea rsi, [rbp-0xb0]
    mov rdx, rsi
    call fe_add

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
    mov rdx, rsi
    call fe_mul                    ; T[0..3] = Z^2
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

section .note.GNU-stack noalloc noexec nowrite progbits
