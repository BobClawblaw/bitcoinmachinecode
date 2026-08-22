; ============================================================================
; tests/point_ref.asm -- FROZEN copy of asm/secp256k1_point.asm as of main
; @ 91b7c9d, every exported symbol suffixed _ref.
;
; DO NOT EDIT. It exists so tests/test_point_repr can prove, limb for limb,
; that the current EC layer computes exactly what the implementation that
; replayed the chain computed. It is the point-layer analogue of
; tests/fe_ref.asm and tests/ecdsa_verify_ref.asm, and was added with the
; 2026-08-22 change that (a) routed the 20 fe_mul(a,a) call sites through
; fe_sqr and (b) deleted a dead fe_mul+fe_sub from point_double.
;
; It links against the LIVE fe_add/fe_sub/fe_mul/fe_sqr on purpose: the field
; layer is unchanged by that commit and already has its own frozen reference,
; so any difference this file reports is a difference in the POINT layer.
; Not linked into any daemon or tool.
; ============================================================================
; ============================================================================
; secp256k1_point.asm -- Jacobian point arithmetic over secp256k1 (100% AI).
;
; Curve: y^2 = x^3 + 7   (a = 0). Jacobian coordinates (X, Y, Z) represent
; affine (x, y) = (X/Z^2, Y/Z^3). Each coordinate is a secp256k1 field element
; stored as 4 little-endian u64 limbs (same convention as secp256k1_fe.asm).
;
; A Jacobian point is 3 field elements = 12 consecutive u64 limbs:
;   [0..3] = X, [4..7] = Y, [8..11] = Z.
; An AFFINE point is 8 consecutive limbs: [0..3] = x, [4..7] = y.
;
; All sub-functions call the verified field primitives (fe_add, fe_sub,
; fe_mul, fe_sqr) which follow the SysV AMD64 ABI and preserve rbx/r12-r15.
; This file makes no other external calls.
;
; API exported:
;   point_double_ref(r[12], p[12])            : r = 2*p   (both Jacobian)
;   point_add_ref(    r[12], p[12], q[12])     : r = p+q   (both Jacobian)
;   point_add_mixed_ref(r[12], p[12], xy[8])   : r = p + affine(xy)
;   point_scalar_mul_ref(r[12], xy[8], k[4])   : r = k * affine(xy) (double-and-add)
;
; ----------------------------------------------------------------------------
; WINDOW / STACK-FRAME CONVENTION (shared by every point_* function)
;
; Prologue:  push rbp; mov rbp,rsp; push rbx,r12,r13,r14,r15; sub rsp,0x148
;   => the 5 pushes occupy [rbp-8 .. rbp-40]  (SAVE area - never overwrite)
;   => rsp = rbp-0x148 ; scratch slots live in [rsp, rbp-0x48] exclusively.
;   Slot base offsets (all BELOW the save area; 32 bytes each = one field elt):
;     S0 = rbp-0x50, S1 = rbp-0x70, S2 = rbp-0x90, S3 = rbp-0xb0,
;     S4 = rbp-0xd0, S5 = rbp-0xf0, S6 = rbp-0x110, S7 = rbp-0x130.
;   sub rsp,0x148 (328 == 8 mod 16) keeps RSP 16-byte aligned at each nested
;   fe_* call (ABI), and reserves room for S7 at rbp-0x130 (= rsp+0x18).
; ----------------------------------------------------------------------------
; (Offsets used below as plain constants for clarity + auditability.)
; ----------------------------------------------------------------------------

; Fixed-base G comb table (w=4): T[j][i] = i * 2^(4j) * G, affine, for the
; fixed-base scalar multiply point_scalar_mul_fixed_ref (see end of file). Entry
; offset = ((j*15)+(i-1)) * 64 bytes. Auto-generated + validated offline.
section .rodata
%include "g_comb_table_ref.inc"

; ---- GLV (PERF_SCOPE.md 4.3): beta, the cube root of unity mod p with
; lambda*(x, y) == (beta*x, y) for the matching lambda in
; secp256k1_scalar.asm. libsecp256k1 field.h:69-72; verified together with
; lambda by validation/glv_split_oracle.py's derivation and by the
; lambda*G == (beta*Gx, Gy) check in tests/test_glv_pointmul.c. ----
align 16
BETA_LIMBS_ref:
    dq 0xC1396C28719501EE, 0x9CF0497512F58995, 0x6E64479EAC3434E9, 0x7AE96A2B657C0710
align 16
FE_ZERO_ref:
    dq 0, 0, 0, 0
section .text

extern fe_add
extern fe_sub
extern fe_mul
extern fe_sqr
extern sc_split_lambda        ; secp256k1_scalar.asm
extern glv_wnaf               ; secp256k1_glv_c.c

; ----------------------------------------------------------------------------
; point_double_ref(r[12], p[12])  -- Jacobian doubling, a=0 curve.
;   A = X1^2 ; B = Y1^2 ; C = B^2
;   D = 2*((X1+B)^2 - A - C) ; E = 3*A ; F = E^2
;   X3 = F - 2*D
;   Y3 = E*(D - X3) - 8*C
;   Z3 = 2*Y1*Z1
; Slot map: S0=A  S1=B  S2=C  S3=(X1+B)^2 then D  S4=E  S5=F  S6=work  S7=work2
; ----------------------------------------------------------------------------
global point_double_ref
point_double_ref:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x148        ; see WINDOW convention above

    mov r12, rdi           ; r12 = output r
    mov r13, rsi           ; r13 = input  p

    ; A = X1*X1            -> S0
    lea rdi, [rbp-0x50]
    lea rsi, [r13+0]
    mov rdx, rsi
    call fe_mul

    ; B = Y1*Y1            -> S1
    lea rdi, [rbp-0x70]
    lea rsi, [r13+32]
    mov rdx, rsi
    call fe_mul

    ; C = B*B              -> S2
    lea rdi, [rbp-0x90]
    lea rsi, [rbp-0x70]
    mov rdx, rsi
    call fe_mul

    ; T = X1 + B           -> S3
    lea rdi, [rbp-0xb0]
    lea rsi, [r13+0]
    lea rdx, [rbp-0x70]
    call fe_add
    ; T = T^2              -> S3
    lea rdi, [rbp-0xb0]
    lea rsi, [rbp-0xb0]
    mov rdx, rsi
    call fe_mul
    ; T = T - A            -> S3
    lea rdi, [rbp-0xb0]
    lea rsi, [rbp-0xb0]
    lea rdx, [rbp-0x50]
    call fe_sub
    ; T = T - C            -> S3  (T = (X1+B)^2 - A - C)
    lea rdi, [rbp-0xb0]
    lea rsi, [rbp-0xb0]
    lea rdx, [rbp-0x90]
    call fe_sub

    ; D = T + T            -> S3  (D = 2*((X1+B)^2-A-C))
    lea rdi, [rbp-0xb0]
    lea rsi, [rbp-0xb0]
    mov rdx, rsi
    call fe_add

    ; E = A + A            -> S4
    lea rdi, [rbp-0xd0]
    lea rsi, [rbp-0x50]
    mov rdx, rsi
    call fe_add
    ; E = E + A            -> S4  (E = 3*A)
    lea rdi, [rbp-0xd0]
    lea rsi, [rbp-0xd0]
    lea rdx, [rbp-0x50]
    call fe_add

    ; F = E*E              -> S5
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0xd0]
    mov rdx, rsi
    call fe_mul

    ; S6 = D + D  (= 2*D) ; X3 = F - S6 -> r12+0
    lea rdi, [rbp-0x110]
    lea rsi, [rbp-0xb0]
    mov rdx, rsi
    call fe_add
    lea rdi, [r12+0]
    lea rsi, [rbp-0xf0]
    lea rdx, [rbp-0x110]
    call fe_sub

    ; S6 = D - X3
    lea rdi, [rbp-0x110]
    lea rsi, [rbp-0xb0]
    lea rdx, [r12+0]
    call fe_sub
    ; S6 = E * (D-X3)
    lea rdi, [rbp-0x110]
    lea rsi, [rbp-0xd0]
    lea rdx, [rbp-0x110]
    call fe_mul

    ; S7 = 8*C : C+C ; + ; +
    lea rdi, [rbp-0x130]
    lea rsi, [rbp-0x90]
    mov rdx, rsi
    call fe_add
    lea rdi, [rbp-0x130]
    lea rsi, [rbp-0x130]
    mov rdx, rsi
    call fe_add
    lea rdi, [rbp-0x130]
    lea rsi, [rbp-0x130]
    mov rdx, rsi
    call fe_add

    ; Y3 = S6 - S7        -> r12+32
    ; BUT first capture Z3's operands (Y1,Z1) while the input is still intact,
    ; because writing r12+32 may overwrite Y1 when r == p (in-place callers).
    lea rdi, [rbp-0x110]   ; S6 = Y1*Z1  (S6 was holding R*(V-X3); no longer needed)
    lea rsi, [r13+32]
    lea rdx, [r13+64]
    call fe_mul
    ; Y3 = R*(V-X3) - 8*C  -> the (R*(V-X3)) was clobbered by S6 above; recompute:
    ;   S7(reused as t) = D - X3 ; S6' = ... simpler: recompute Y3 below.
    ;   Y3 = E*(D-X3) - 8*C ; we still have E=S4, D=S3, X3=r12+0, C=S2.
    ;   t = D - X3 -> S6  (overwrites the Y1*Z1 we just stashed -> stash it in OUT Z3 zone first)
    ;   Z3 part: write Z3 = S6(old Y1Z1)+S6(old Y1Z1) into r12+64 (safe: r13+64 no longer needed)
    lea rdi, [r12+64]
    lea rsi, [rbp-0x110]
    mov rdx, rsi
    call fe_add          ; r12+64 = 2*Y1*Z1 = Z3
    ; now recompute Y3 using slots (D, X3, E, C still in slots/out)
    ;   t = D - X3 -> S6
    lea rdi, [rbp-0x110]
    lea rsi, [rbp-0xb0]
    lea rdx, [r12+0]
    call fe_sub
    ;   t = E * t -> S6
    lea rdi, [rbp-0x110]
    lea rsi, [rbp-0xd0]
    lea rdx, [rbp-0x110]
    call fe_mul
    ;   8C in S7 still = 8*C ; Y3 = S6 - S7 -> r12+32
    lea rdi, [r12+32]
    lea rsi, [rbp-0x110]
    lea rdx, [rbp-0x130]
    call fe_sub

    add rsp, 0x148
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; ----------------------------------------------------------------------------
; point_add_mixed_ref(r[12], p[12], xy[8])  -- r = p + affine(xy), Jacobian.
;   Z1Z1 = Z1^2
;   U2   = X2*Z1Z1 ; S2 = Y2*Z1*Z1Z1
;   if U2 == X1: if S2==Y1 -> point_double_ref(p) ; else -> infinity
;   H = U2 - X1 ; R = S2 - Y1 ; HH = H^2 ; HHH = H*HH ; V = X1*HH
;   X3 = R^2 - HHH - 2V ; Y3 = R*(V-X3) - Y1*HHH ; Z3 = Z1*H
;   Slot window (add sub 0x188 : save area [rbp-8..-40], slots below):
;     S0=-0x50 Z1Z1, S1=-0x70 U2, S2=-0x90 V(also t), S3=-0xb0 S2(y), S4=-0xd0 H,
;     S5=-0xf0 R, S6=-0x110 HH, S7=-0x130 HHH, S8=-0x150 work, S9=-0x170 work2
; ----------------------------------------------------------------------------
; point_add_mixed_zr_ref(r[12], p[12], xy[8], zr[4]) -- identical, plus
;   zr = Z3/Z1 = H, the z-ratio libsecp256k1's secp256k1_gej_add_ge_var
;   returns through rzr. The GLV odd-multiples table build needs it to
;   bring all entries to one Z (secp256k1_ge_table_set_globalz). On the
;   degenerate branches -- unreachable from that build, which adds distinct
;   odd multiples of one point on a prime-order curve -- it stores what the
;   ratio would be: 2*Y1 for the doubling case (our Z3 = 2*Y1*Z1), 0 for
;   opposite points (result infinity), 1 for p == infinity.
;   Shares point_add_mixed_ref's body via r15 (= zr pointer, NULL for the plain
;   entry); r15 is callee-saved and otherwise unused in that body.
global point_add_mixed_zr_ref
point_add_mixed_zr_ref:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x188
    mov r12, rdi           ; OUT
    mov r13, rsi           ; p
    mov r14, rdx           ; affine xy
    mov r15, rcx           ; zr out
    jmp point_add_mixed_ref.body

global point_add_mixed_ref
point_add_mixed_ref:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x188

    mov r12, rdi           ; OUT
    mov r13, rsi           ; p
    mov r14, rdx           ; affine xy
    xor r15d, r15d         ; no z-ratio requested
.body:

    ; ---- Z1 == 0 (p is infinity) -> r = (xy, Z=1).  (2026-08-22)
    ; Without this, Z1=0 gives U2=0, S2=0, H=-X1, Z3=Z1*H=0: the result is
    ; "infinity" instead of xy. Unreachable from point_scalar_mul_ref (it seeds
    ; R from the top digit) but reachable from any ladder that starts at
    ; infinity, e.g. the GLV dual-stream one. Mirrors Core's
    ; secp256k1_gej_add_ge_var "if (a->infinity)" arm (group_impl.h). ----
    mov rax, [r13+64]
    or  rax, [r13+72]
    or  rax, [r13+80]
    or  rax, [r13+88]
    jnz .p_finite
    mov rdi, r12
    mov rsi, r14
    mov rcx, 8
    rep movsq              ; X,Y = xy (clobbers rdi/rsi/rcx only)
    mov qword [r12+64], 1
    mov qword [r12+72], 0
    mov qword [r12+80], 0
    mov qword [r12+88], 0
    test r15, r15
    jz  .done
    mov qword [r15+0], 1   ; zr := 1 (Core asserts rzr == NULL here)
    mov qword [r15+8], 0
    mov qword [r15+16], 0
    mov qword [r15+24], 0
    jmp .done
.p_finite:

    ; S0 = Z1*Z1        (Z1Z1)
    lea rdi, [rbp-0x50]
    lea rsi, [r13+64]
    mov rdx, rsi
    call fe_mul

    ; S1 = X2*Z1Z1      (U2)
    lea rdi, [rbp-0x70]
    lea rsi, [r14+0]
    lea rdx, [rbp-0x50]
    call fe_mul

    ; S8 = Z1*Z1Z1
    lea rdi, [rbp-0x150]
    lea rsi, [r13+64]
    lea rdx, [rbp-0x50]
    call fe_mul
    ; S3 = Y2 * S8      (S2)
    lea rdi, [rbp-0xb0]
    lea rsi, [r14+32]
    lea rdx, [rbp-0x150]
    call fe_mul

    ; if U2 == X1  -> equal-x case
    ; compare U2 (S1) against X1 (p[0]) limb by limb
    mov rax, [rbp-0x70+0]
    cmp rax, [r13+0]
    jne .distinct
    mov rax, [rbp-0x70+8]
    cmp rax, [r13+8]
    jne .distinct
    mov rax, [rbp-0x70+16]
    cmp rax, [r13+16]
    jne .distinct
    mov rax, [rbp-0x70+24]
    cmp rax, [r13+24]
    jne .distinct
    ; equal X: compare S2 (S3) vs Y1 (p[4])
    mov rax, [rbp-0xb0+0]
    cmp rax, [r13+32+0]
    jne .inf
    mov rax, [rbp-0xb0+8]
    cmp rax, [r13+32+8]
    jne .inf
    mov rax, [rbp-0xb0+16]
    cmp rax, [r13+32+16]
    jne .inf
    mov rax, [rbp-0xb0+24]
    cmp rax, [r13+32+24]
    jne .inf
    ; same point -> double. r = 2*p   (zr = 2*Y1, captured before Y1 can be
    ; overwritten by an in-place double)
    test r15, r15
    jz  .dbl
    mov rdi, r15
    lea rsi, [r13+32]
    mov rdx, rsi
    call fe_add
.dbl:
    mov rdi, r12
    mov rsi, r13
    call point_double_ref
    jmp .done
.inf:
    ; opposite point -> infinity. Set Z3 = 0 (X3=1, Y3=1 canonical inf)
    mov qword [r12+0], 1
    mov qword [r12+8], 0
    mov qword [r12+16], 0
    mov qword [r12+24], 0
    mov qword [r12+32], 1
    mov qword [r12+40], 0
    mov qword [r12+48], 0
    mov qword [r12+56], 0
    mov qword [r12+64], 0
    mov qword [r12+72], 0
    mov qword [r12+80], 0
    mov qword [r12+88], 0
    test r15, r15
    jz  .done
    mov qword [r15+0], 0   ; zr := 0
    mov qword [r15+8], 0
    mov qword [r15+16], 0
    mov qword [r15+24], 0
    jmp .done

.distinct:
    ; H = U2 - X1      -> S4
    lea rdi, [rbp-0xd0]
    lea rsi, [rbp-0x70]
    lea rdx, [r13+0]
    call fe_sub
    ; R = S2 - Y1      -> S5
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0xb0]
    lea rdx, [r13+32]
    call fe_sub
    ; HH = H^2         -> S6
    lea rdi, [rbp-0x110]
    lea rsi, [rbp-0xd0]
    mov rdx, rsi
    call fe_mul
    ; HHH = H*HH       -> S7
    lea rdi, [rbp-0x130]
    lea rsi, [rbp-0xd0]
    lea rdx, [rbp-0x110]
    call fe_mul
    ; V = X1*HH        -> S2 (reuse)
    lea rdi, [rbp-0x90]
    lea rsi, [r13+0]
    lea rdx, [rbp-0x110]
    call fe_mul
    ; X3 = R^2 - HHH - 2V
    ;   S8 = R^2 ; S9 = 2V
    lea rdi, [rbp-0x150]
    lea rsi, [rbp-0xf0]
    mov rdx, rsi
    call fe_mul
    lea rdi, [rbp-0x170]
    lea rsi, [rbp-0x90]
    mov rdx, rsi
    call fe_add          ; 2V
    lea rdi, [r12+0]
    lea rsi, [rbp-0x150]
    lea rdx, [rbp-0x170]
    call fe_sub          ; X3 = R^2 - 2V
    lea rdi, [r12+0]
    lea rsi, [r12+0]
    lea rdx, [rbp-0x130]
    call fe_sub          ; X3 = X3 - HHH
    ; Y3 = R*(V-X3) - Y1*HHH
    ;   S8 = V - X3
    lea rdi, [rbp-0x150]
    lea rsi, [rbp-0x90]
    lea rdx, [r12+0]
    call fe_sub          ; V - X3
    ;   S8 = R * (V-X3)
    lea rdi, [rbp-0x150]
    lea rsi, [rbp-0xf0]
    lea rdx, [rbp-0x150]
    call fe_mul
    ;   S9 = Y1 * HHH
    lea rdi, [rbp-0x170]
    lea rsi, [r13+32]
    lea rdx, [rbp-0x130]
    call fe_mul
    ;   Y3 = S8 - S9  -> out+32
    lea rdi, [r12+32]
    lea rsi, [rbp-0x150]
    lea rdx, [rbp-0x170]
    call fe_sub
    ; Z3 = Z1 * H -> out+64
    lea rdi, [r12+64]
    lea rsi, [r13+64]
    lea rdx, [rbp-0xd0]
    call fe_mul
    ; zr = H (S4 is not touched after it is computed)
    test r15, r15
    jz  .done
    mov rax, [rbp-0xd0+0]
    mov [r15+0], rax
    mov rax, [rbp-0xd0+8]
    mov [r15+8], rax
    mov rax, [rbp-0xd0+16]
    mov [r15+16], rax
    mov rax, [rbp-0xd0+24]
    mov [r15+24], rax

.done:
    add rsp, 0x188
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; ----------------------------------------------------------------------------
; point_scalar_mul_ref(r[12], xy[8], k[4]) -- r = k * affine(xy), Jacobian,
;   MSB->LSB double-and-add. Registers kept across nested point_* calls
;   (which preserve rbx/r12-r15):
;     r12 = R (working accumulator = output)
;     r13 = base affine xy
;     r14 = k limb buffer (4 limbs copied to stack)
;     r15 = current bit index (msb-1 ... 0)
;   Init: R = base (Z=1). Loop i from msb-1 downto 0:
;     point_double_ref(R,R); if k bit i set: point_add_mixed_ref(R,R,base).
;   k==0 -> return Jacobian infinity (Z=0).
; ----------------------------------------------------------------------------
; point_scalar_mul_ref(r[12], xy[8], k[4]) -- r = k*affine(xy), Jacobian, w=4
; windowed, VARIABLE-TIME (verification-safe). Replaces the former MSB->LSB
; double-and-add with a fixed 4-bit window:
;   * Build a 15-entry Jacobian table TAB[1..15] = i*base (TAB[i]=TAB[i-1]+base
;     via point_add_mixed_ref). ~14 adds, done per-call (base is NOT precomputed
;     here; see FINDING-1/option-1 notes for fixed-base G to drop this).
;   * Process the scalar from the MSB nibble down: 4 point_double_ref per window,
;     plus one conditional point_add_ref of TAB[digit] when the window digit != 0.
;   * ~252 doublings (unchanged -- windowing cannot cut doublings) but only
;     ~(nonzero lower nibbles) window-adds vs the naive ~128 addmixeds,
;     i.e. adds roughly halved. Variable-time is fine: the OLD double-and-add
;     (branchy `jnc` skip) was already variable-time, so this does NOT regress
;     the (pending, FINDING-1) constant-time signing ladder which is a separate
;     routine. Verified bit-exact (affine) vs the prior version and vs Core by
;     tests/run_pointmul_diff.py and the full suite.
;
; Register discipline (all callee-saved, preserved by point_* callees):
;   rbx = TAB base            r12 = R (working accumulator = output)
;   r13 = base affine xy      r14 = k limb buffer (4 u64, limb0 first)
;   r15 = window index / temp
; ----------------------------------------------------------------------------
global point_scalar_mul_ref
point_scalar_mul_ref:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x808          ; 0x808 == 8 mod16 -> rsp 0 mod16 at nested calls.
                             ; TAB[1..15] @ rbp-0x600 (15*96 = 1440 B), k buffer
                             ; @ rbp-0x58, top-window idx @ rbp-0x48.

    mov r12, rdi           ; R (out)
    mov r13, rsi           ; base affine xy

    ; ---- copy k[0..3] (rdx) to persistent ascending-limb buffer ----
    mov rax, [rdx+0]
    mov [rbp-0x58], rax
    mov rax, [rdx+8]
    mov [rbp-0x50], rax
    mov rax, [rdx+16]
    mov [rbp-0x48], rax
    mov rax, [rdx+24]
    mov [rbp-0x40], rax
    lea r14, [rbp-0x58]    ; r14 = k buffer (limb0 at +0, limb3 at +24)

    ; ---- k == 0 -> Jacobian infinity ----
    mov rax, [r14+0]
    or  rax, [r14+8]
    or  rax, [r14+16]
    or  rax, [r14+24]
    jz  .zero

    ; ---- find msb index (0..255) -> keep top-win idx at [r14? no] ----
    ; Use r15 as working msb first.
    mov r15, -1
    mov rax, [r14+24]
    test rax, rax
    jz  .l2
    bsr rcx, rax
    mov r15, 192
    add r15, rcx
    jmp .gotmsb
.l2:
    mov rax, [r14+16]
    test rax, rax
    jz  .l1
    bsr rcx, rax
    mov r15, 128
    add r15, rcx
    jmp .gotmsb
.l1:
    mov rax, [r14+8]
    test rax, rax
    jz  .l0
    bsr rcx, rax
    mov r15, 64
    add r15, rcx
    jmp .gotmsb
.l0:
    mov rax, [r14+0]
    bsr rcx, rax
    mov r15, rcx
.gotmsb:
    ; top_win = msb>>2 ; stash at [rbp-0x38]
    mov rax, r15
    shr rax, 2
    mov [rbp-0x38], rax

    ; ================= BUILD TABLE TAB[1..15] =================
    lea rbx, [rbp-0x600]       ; TAB base
    ; TAB[1] = base : copy xy[0..7] -> TAB[0..55], Z=1
    mov rax, [r13+0]
    mov [rbx+0], rax
    mov rax, [r13+8]
    mov [rbx+8], rax
    mov rax, [r13+16]
    mov [rbx+16], rax
    mov rax, [r13+24]
    mov [rbx+24], rax
    mov rax, [r13+32]
    mov [rbx+32], rax
    mov rax, [r13+40]
    mov [rbx+40], rax
    mov rax, [r13+48]
    mov [rbx+48], rax
    mov rax, [r13+56]
    mov [rbx+56], rax
    mov qword [rbx+64], 1
    mov qword [rbx+72], 0
    mov qword [rbx+80], 0
    mov qword [rbx+88], 0
    ; for i=2..15 (ASCENDING: TAB[i] depends on TAB[i-1]): TAB[i]=TAB[i-1]+base
    ; Entry m lives at offset (m-1)*96. out = TAB[i] @ (i-1)*96,
    ; p = TAB[i-1] @ (i-2)*96 = out - 96. point_add_mixed_ref clobbers rdi/rsi,
    ; so recompute addresses from preserved rbx each iteration.
    mov r15, 2                 ; i=2..15 ascending
.mktab:
    mov rax, r15
    dec rax                    ; i-1
    imul rax, rax, 96
    lea rdi, [rbx + rax]       ; out = TAB[i]
    lea rsi, [rdi - 96]        ; p   = TAB[i-1]
    mov rdx, r13               ; base affine
    call point_add_mixed_ref       ; TAB[i] = TAB[i-1] + base
    inc r15
    cmp r15, 15
    jle .mktab

    ; ================= TOP WINDOW =================
    ; R = TAB[digit_top] ; digit_top = (k >> (top_win*4)) & 0xF  (>=1 by def)
    mov rcx, [rbp-0x38]        ; top_win
    shl rcx, 2                 ; bit offset
    mov rdx, rcx
    shr rdx, 6
    lea rdx, [r14 + rdx*8]     ; k limb
    and rcx, 63
    mov rax, [rdx]
    shr rax, cl
    and rax, 15
    dec rax
    imul rax, rax, 96
    lea rsi, [rbx + rax]       ; -> TAB[digit]
    mov rdi, r12
    mov rcx, 12
    rep movsq                  ; copy 96 B : R = TAB[digit] (clobbers rcx/rsi/rdi)

    ; ================= REMAINING WINDOWS (top_win-1 .. 0) =================
    mov r15, [rbp-0x38]
    dec r15
    js  .done                  ; only one window total
.wnext:
    ; R = 16*R : four doublings
    mov rdi, r12
    mov rsi, r12
    call point_double_ref
    mov rdi, r12
    mov rsi, r12
    call point_double_ref
    mov rdi, r12
    mov rsi, r12
    call point_double_ref
    mov rdi, r12
    mov rsi, r12
    call point_double_ref
    ; digit for window r15
    mov rcx, r15
    shl rcx, 2
    mov rdx, rcx
    shr rdx, 6
    lea rdx, [r14 + rdx*8]
    and rcx, 63
    mov rax, [rdx]
    shr rax, cl
    and rax, 15
    jz  .wskip
    dec rax
    imul rax, rax, 96
    lea rcx, [rbx + rax]       ; TAB[digit]
    mov rdi, r12
    mov rsi, r12
    mov rdx, rcx
    call point_add_ref             ; R = R + TAB[digit]
.wskip:
    dec r15
    jns .wnext
    jmp .done

.zero:
    ; k == 0 : return Jacobian infinity (X=1,Y=1,Z=0)
    mov qword [r12+0], 1
    mov qword [r12+8], 0
    mov qword [r12+16], 0
    mov qword [r12+24], 0
    mov qword [r12+32], 1
    mov qword [r12+40], 0
    mov qword [r12+48], 0
    mov qword [r12+56], 0
    mov qword [r12+64], 0
    mov qword [r12+72], 0
    mov qword [r12+80], 0
    mov qword [r12+88], 0

.done:
    add rsp, 0x808
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
global point_add_ref
point_add_ref:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x1c8

    mov r12, rdi           ; out
    mov r13, rsi           ; p
    mov r14, rdx           ; q

    ; ---- infinity operands (2026-08-22): p inf -> r = q ; q inf -> r = p.
    ; Without this a Z=0 operand falls into the generic formulas and
    ; Z3 = Z1*Z2*H = 0 -- "infinity" instead of the other point. rep movsq
    ; with rdi == rsi (in-place caller) is a harmless self-copy. ----
    mov rax, [r13+64]
    or  rax, [r13+72]
    or  rax, [r13+80]
    or  rax, [r13+88]
    jnz .p_finite
    mov rdi, r12
    mov rsi, r14
    mov rcx, 12
    rep movsq
    jmp .done
.p_finite:
    mov rax, [r14+64]
    or  rax, [r14+72]
    or  rax, [r14+80]
    or  rax, [r14+88]
    jnz .q_finite
    mov rdi, r12
    mov rsi, r13
    mov rcx, 12
    rep movsq
    jmp .done
.q_finite:

    ; Z1Z1 = Z1*Z1 -> S0
    lea rdi, [rbp-0x50]
    lea rsi, [r13+64]
    mov rdx, rsi
    call fe_mul
    ; Z22 = Z2*Z2 -> (store in S5, free)
    lea rdi, [rbp-0xf0]
    lea rsi, [r14+64]
    mov rdx, rsi
    call fe_mul
    ; U1 = X1*Z22 -> S2
    lea rdi, [rbp-0x90]
    lea rsi, [r13+0]
    lea rdx, [rbp-0xf0]
    call fe_mul
    ; U2 = X2*Z1Z1 -> S3
    lea rdi, [rbp-0xb0]
    lea rsi, [r14+0]
    lea rdx, [rbp-0x50]
    call fe_mul
    ; w = Z2*Z22 -> S11 ; S1 = Y1*w -> S1
    lea rdi, [rbp-0x1b0]
    lea rsi, [r14+64]
    lea rdx, [rbp-0xf0]
    call fe_mul
    lea rdi, [rbp-0x70]
    lea rsi, [r13+32]
    lea rdx, [rbp-0x1b0]
    call fe_mul
    ; w = Z1*Z1Z1 -> S11 ; S2proj = Y2*w -> S4
    lea rdi, [rbp-0x1b0]
    lea rsi, [r13+64]
    lea rdx, [rbp-0x50]
    call fe_mul
    lea rdi, [rbp-0xd0]
    lea rsi, [r14+32]
    lea rdx, [rbp-0x1b0]
    call fe_mul

    ; if U1==U2 : (U1=S2/-0x90 vs U2=S3/-0xb0). NOTE: one instruction per line
    ; because in NASM ';' starts a comment (NOT a statement separator) -- joining
    ; instructions with ';' silently drops everything after the first one.
    mov rax, [rbp-0x90+0]
    cmp rax, [rbp-0xb0+0]
    jne .distinct
    mov rax, [rbp-0x90+8]
    cmp rax, [rbp-0xb0+8]
    jne .distinct
    mov rax, [rbp-0x90+16]
    cmp rax, [rbp-0xb0+16]
    jne .distinct
    mov rax, [rbp-0x90+24]
    cmp rax, [rbp-0xb0+24]
    jne .distinct
    ; equal X: if S1 != S2proj -> infinity else double
    mov rax, [rbp-0x70+0]
    cmp rax, [rbp-0xd0+0]
    jne .inf
    mov rax, [rbp-0x70+8]
    cmp rax, [rbp-0xd0+8]
    jne .inf
    mov rax, [rbp-0x70+16]
    cmp rax, [rbp-0xd0+16]
    jne .inf
    mov rax, [rbp-0x70+24]
    cmp rax, [rbp-0xd0+24]
    jne .inf
    ; same point -> double
    mov rdi, r12
    mov rsi, r13
    call point_double_ref
    jmp .done
.inf:
    ; opposite/infinity: Z3=0, canonical (1,1,0)
    mov qword [r12+0], 1
    mov qword [r12+8], 0
    mov qword [r12+16], 0
    mov qword [r12+24], 0
    mov qword [r12+32], 1
    mov qword [r12+40], 0
    mov qword [r12+48], 0
    mov qword [r12+56], 0
    mov qword [r12+64], 0
    mov qword [r12+72], 0
    mov qword [r12+80], 0
    mov qword [r12+88], 0
    jmp .done

.distinct:
    ; H = U2 - U1 -> S6
    lea rdi, [rbp-0x110]
    lea rsi, [rbp-0xb0]
    lea rdx, [rbp-0x90]
    call fe_sub
    ; R = S2proj - S1 -> S7
    lea rdi, [rbp-0x130]
    lea rsi, [rbp-0xd0]
    lea rdx, [rbp-0x70]
    call fe_sub
    ; HH = H*H -> S8
    lea rdi, [rbp-0x150]
    lea rsi, [rbp-0x110]
    mov rdx, rsi
    call fe_mul
    ; HHH = H*HH -> S9
    lea rdi, [rbp-0x170]
    lea rsi, [rbp-0x110]
    lea rdx, [rbp-0x150]
    call fe_mul
    ; V = U1*HH -> S10
    lea rdi, [rbp-0x190]
    lea rsi, [rbp-0x90]
    lea rdx, [rbp-0x150]
    call fe_mul
    ; X3 = R^2 - HHH - 2V -> out+0
    ;   S5 = R*R
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0x130]
    mov rdx, rsi
    call fe_mul
    ;   S11 = 2V
    lea rdi, [rbp-0x1b0]
    lea rsi, [rbp-0x190]
    mov rdx, rsi
    call fe_add
    ;   out = S5 - S11 - S9
    lea rdi, [r12+0]
    lea rsi, [rbp-0xf0]
    lea rdx, [rbp-0x1b0]
    call fe_sub
    lea rdi, [r12+0]
    lea rsi, [r12+0]
    lea rdx, [rbp-0x170]
    call fe_sub

    ; Y3 = R*(V-X3) - S1*HHH -> out+32
    ;   S5 = V - X3
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0x190]
    lea rdx, [r12+0]
    call fe_sub
    ;   S5 = R * (V-X3)
    lea rdi, [rbp-0xf0]
    lea rsi, [rbp-0x130]
    lea rdx, [rbp-0xf0]
    call fe_mul
    ;   S11 = S1 * HHH
    lea rdi, [rbp-0x1b0]
    lea rsi, [rbp-0x70]
    lea rdx, [rbp-0x170]
    call fe_mul
    ;   Y3 = S5 - S11 -> out+32
    lea rdi, [r12+32]
    lea rsi, [rbp-0xf0]
    lea rdx, [rbp-0x1b0]
    call fe_sub

    ; Z3 = Z1*Z2*H -> out+64
    ;   S11 = Z1*Z2
    lea rdi, [rbp-0x1b0]
    lea rsi, [r13+64]
    lea rdx, [r14+64]
    call fe_mul
    ;   out+64 = S11 * H
    lea rdi, [r12+64]
    lea rsi, [rbp-0x1b0]
    lea rdx, [rbp-0x110]
    call fe_mul

.done:
    add rsp, 0x1c8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; ----------------------------------------------------------------------------
; point_scalar_mul_fixed_ref(out[12], k[4]) : out = k*G  (FIXED-BASE G comb, w=4)
;   G is a compile-time constant, so the full w=4 comb table T[j][i]=i*2^(4j)*G
;   (affine) is precomputed in .rodata (g_comb_table.inc, auto-generated and
;   validated offline vs the oracle).  k*G = sum_j T[j][digit_j], so the multiply
;   needs ZERO doublings -- only up to 64 point_add_mixed_ref Jacobian+affine adds.
;   Used by ecdsa_verify for the u1*G term (variable-base Q still uses
;   point_scalar_mul_ref).
;   ABI: point_scalar_mul_fixed_ref(rdi=out[12], rsi=k[4]); preserves rbx,r12-r15.
;   k==0 -> Jacobian infinity.  Constant-time: fixed loop over 64 columns.
;   Stack (rbp-relative): R @ -0x98 (12), Rcopy @ -0x140 (12), k @ -0x168 (4).
;   sub rsp 0x178 (==8 mod16) -> rsp 0 mod16 at nested point_add_mixed_ref calls.
; ----------------------------------------------------------------------------
global point_scalar_mul_fixed_ref
point_scalar_mul_fixed_ref:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x178
    mov  r12, rdi            ; out
    ; copy k (rsi) ascending into rbp-0x168
    mov  rax, [rsi+0]
    mov  [rbp-0x168], rax
    mov  rax, [rsi+8]
    mov  [rbp-0x160], rax
    mov  rax, [rsi+16]
    mov  [rbp-0x158], rax
    mov  rax, [rsi+24]
    mov  [rbp-0x150], rax
    ; k == 0 -> infinity
    mov  rax, [rbp-0x168]
    or   rax, [rbp-0x160]
    or   rax, [rbp-0x158]
    or   rax, [rbp-0x150]
    jz   .zero
    xor  r15, r15            ; j = 0..63
.find:
    mov  rcx, r15
    shl  rcx, 2
    mov  rdx, rcx
    shr  rdx, 6
    lea  rdx, [rbp-0x168 + rdx*8]
    and  rcx, 63
    mov  rax, [rdx]
    shr  rax, cl
    and  rax, 15
    jnz  .init
    inc  r15
    cmp  r15, 64
    jb   .find
    jmp  .zero
.init:
    dec  rax                ; d-1
    mov  r14, r15
    imul r14, r14, 15
    add  r14, rax           ; (j*15)+(d-1)
    imul r14, r14, 64
    lea  r14, [G_COMB_TABLE_ref + r14]
    lea  rdi, [rbp-0x98]    ; R
    mov  rsi, r14
    mov  rcx, 8
    rep  movsq              ; R[0..7] = affine x,y
    mov  qword [rbp-0x98+64], 1
    mov  qword [rbp-0x98+72], 0
    mov  qword [rbp-0x98+80], 0
    mov  qword [rbp-0x98+88], 0
    inc  r15
    cmp  r15, 64
    jae  .store
.acc:
    mov  rcx, r15
    shl  rcx, 2
    mov  rdx, rcx
    shr  rdx, 6
    lea  rdx, [rbp-0x168 + rdx*8]
    and  rcx, 63
    mov  rax, [rdx]
    shr  rax, cl
    and  rax, 15
    jz   .accskip
    dec  rax                ; d-1
    mov  r14, r15
    imul r14, r14, 15
    add  r14, rax
    imul r14, r14, 64
    lea  r14, [G_COMB_TABLE_ref + r14]
    ; Rcopy = R
    lea  rdi, [rbp-0x140]
    lea  rsi, [rbp-0x98]
    mov  rcx, 12
    rep  movsq
    ; R = Rcopy + affine(table)  (distinct p -> no aliasing)
    lea  rdi, [rbp-0x98]
    lea  rsi, [rbp-0x140]
    mov  rdx, r14
    call point_add_mixed_ref
.accskip:
    inc  r15
    cmp  r15, 64
    jb   .acc
    jmp  .store
.zero:
    mov  qword [rbp-0x98+0], 1
    mov  qword [rbp-0x98+8], 0
    mov  qword [rbp-0x98+16], 0
    mov  qword [rbp-0x98+24], 0
    mov  qword [rbp-0x98+32], 1
    mov  qword [rbp-0x98+40], 0
    mov  qword [rbp-0x98+48], 0
    mov  qword [rbp-0x98+56], 0
    mov  qword [rbp-0x98+64], 0
    mov  qword [rbp-0x98+72], 0
    mov  qword [rbp-0x98+80], 0
    mov  qword [rbp-0x98+88], 0
.store:
    mov  rax, [rbp-0x98+0]
    mov  [r12+0], rax
    mov  rax, [rbp-0x98+8]
    mov  [r12+8], rax
    mov  rax, [rbp-0x98+16]
    mov  [r12+16], rax
    mov  rax, [rbp-0x98+24]
    mov  [r12+24], rax
    mov  rax, [rbp-0x98+32]
    mov  [r12+32], rax
    mov  rax, [rbp-0x98+40]
    mov  [r12+40], rax
    mov  rax, [rbp-0x98+48]
    mov  [r12+48], rax
    mov  rax, [rbp-0x98+56]
    mov  [r12+56], rax
    mov  rax, [rbp-0x98+64]
    mov  [r12+64], rax
    mov  rax, [rbp-0x98+72]
    mov  [r12+72], rax
    mov  rax, [rbp-0x98+80]
    mov  [r12+80], rax
    mov  rax, [rbp-0x98+88]
    mov  [r12+88], rax
    add  rsp, 0x178
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; point_scalar_mul_glv_ref(out[12], xy[8], k[4]) -- out = k * affine(xy), Jacobian,
;   VARIABLE-TIME (verification only). PERF_SCOPE.md 4.3: the shape of
;   libsecp256k1's secp256k1_ecmult_strauss_wnaf for a single point
;   (ecmult_impl.h), GLV endomorphism + width-5 wNAF:
;     1. k = r1 + lambda*r2 (mod n), both halves < 2^128 up to sign
;        (sc_split_lambda, with its permanent identity check).
;     2. wNAF of each half, 129 digit slots (glv_wnaf).
;     3. Odd-multiples table TAB[i] = (2i+1)*Q, i = 0..7, built on the
;        isomorphic curve with C := z(2Q) so every step is a mixed add
;        (secp256k1_ecmult_odd_multiples_table), then brought to one common
;        Z via the captured z-ratios (secp256k1_ge_table_set_globalz) -- no
;        inversion anywhere. AUXX[i] = TAB[i].x * beta is the lambda-table:
;        lambda*(x, y) == (beta*x, y), and a shared Z keeps that true.
;     4. One ladder over both digit streams: ~128 doublings instead of 252,
;        one mixed add per non-zero digit (TAB[idx] for stream 1, (AUXX[idx],
;        TAB[idx].y) for stream 2, y negated for a negative digit).
;     5. R.z *= Z to leave the isomorphic curve.
;   Falls back to point_scalar_mul_ref (kept intact) if the split's identity
;   check or the wNAF encoder signals a problem -- slow-and-correct, never
;   an abort. k == 0 -> Jacobian infinity.
;   The accumulator starts at infinity, so the Z=0-operand guards in
;   point_add_ref / point_add_mixed_ref (2026-08-22) are load-bearing here.
;
; Frame (rbp-relative; save area rbp-8..-0x28):
;   K -0x50  R1 -0x70  R2 -0x90  W1 -0x120 (129 B)  W2 -0x1b0 (129 B)
;   ZG -0x1d0  ZS -0x1f0  D -0x250 (96; its X,Y are the affine d_ge)
;   AI -0x2b0 (96)  TAB -0x4b0 (8 x 64: x @+0, y @+32)  AUXX -0x5b0 (8 x 32)
;   ZR -0x6b0 (8 x 32)  TMP -0x6f0 (64, affine scratch)  BITS -0x6f8
;   sub rsp, 0x6f8 -> rsp = rbp-0x720, 16-byte aligned at every call.
; Registers (callee-saved across every callee): r12 = out (= R), r13 = xy,
;   r14 = loop index, r15 = stream, rbx = digit.
; ----------------------------------------------------------------------------
global point_scalar_mul_glv_ref
point_scalar_mul_glv_ref:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x6f8
    ; Force 16-byte alignment regardless of the CALLER's alignment: the
    ; all-asm interpreter -> sv_checksig -> ecdsa_verify chain can arrive
    ; here with rsp == 8 (mod 16) on the CHECKMULTISIG path, and glv_wnaf is
    ; gcc-compiled C whose SSE spills (movaps to the stack) fault on a
    ; misaligned frame -- found by tests/test_scriptverify_parity with
    ; BMC_ECDSA_GLV=1 (the direct-call harnesses were aligned by luck).
    ; Every local is rbp-relative, so rounding rsp down is safe; the
    ; epilogue restores rsp from rbp instead of adding the constant back.
    and  rsp, -16
    mov  r12, rdi
    mov  r13, rsi
    mov  rax, [rdx+0]
    mov  [rbp-0x50], rax
    mov  rax, [rdx+8]
    mov  [rbp-0x48], rax
    mov  rax, [rdx+16]
    mov  [rbp-0x40], rax
    mov  rax, [rdx+24]
    mov  [rbp-0x38], rax
    mov  rax, [rbp-0x50]
    or   rax, [rbp-0x48]
    or   rax, [rbp-0x40]
    or   rax, [rbp-0x38]
    jz   .zero

    ; ---- 1. split ----
    lea  rdi, [rbp-0x70]
    lea  rsi, [rbp-0x90]
    lea  rdx, [rbp-0x50]
    call sc_split_lambda
    test eax, eax
    jz   .fallback

    ; ---- 2. wNAF both halves; BITS = max ----
    lea  rdi, [rbp-0x120]
    lea  rsi, [rbp-0x70]
    call glv_wnaf
    test eax, eax
    js   .fallback
    movsxd rax, eax
    mov  [rbp-0x6f8], rax
    lea  rdi, [rbp-0x1b0]
    lea  rsi, [rbp-0x90]
    call glv_wnaf
    test eax, eax
    js   .fallback
    movsxd rax, eax
    cmp  rax, [rbp-0x6f8]
    jle  .bits_ok
    mov  [rbp-0x6f8], rax
.bits_ok:
    cmp  qword [rbp-0x6f8], 0
    je   .zero                     ; both halves zero <=> k == 0 (already excluded)

    ; ---- 3a. table on the isomorphic curve ----
    ; AI := (Qx, Qy, 1) ; D := 2*AI ; C := D.z
    lea  rdi, [rbp-0x2b0]
    mov  rsi, r13
    mov  rcx, 8
    rep  movsq
    mov  qword [rbp-0x2b0+64], 1
    mov  qword [rbp-0x2b0+72], 0
    mov  qword [rbp-0x2b0+80], 0
    mov  qword [rbp-0x2b0+88], 0
    lea  rdi, [rbp-0x250]
    lea  rsi, [rbp-0x2b0]
    call point_double_ref
    ; TAB[0] = (Qx*C^2, Qy*C^3)   (ZS scratch = C^2 then C^3)
    lea  rdi, [rbp-0x1f0]
    lea  rsi, [rbp-0x250+64]
    mov  rdx, rsi
    call fe_mul
    lea  rdi, [rbp-0x4b0]
    mov  rsi, r13
    lea  rdx, [rbp-0x1f0]
    call fe_mul
    lea  rdi, [rbp-0x1f0]
    lea  rsi, [rbp-0x1f0]
    lea  rdx, [rbp-0x250+64]
    call fe_mul
    lea  rdi, [rbp-0x4b0+32]
    lea  rsi, [r13+32]
    lea  rdx, [rbp-0x1f0]
    call fe_mul
    ; AI := (TAB[0].x, TAB[0].y, 1)  -- phi(Q) with z = 1
    lea  rdi, [rbp-0x2b0]
    lea  rsi, [rbp-0x4b0]
    mov  rcx, 8
    rep  movsq
    ; ZR[0] := C
    lea  rdi, [rbp-0x6b0]
    lea  rsi, [rbp-0x250+64]
    mov  rcx, 4
    rep  movsq
    ; TAB[i] = AI += d_ge  (i = 1..7), ZR[i] = the z-ratio of that add
    mov  r14, 1
.tab_loop:
    lea  rdi, [rbp-0x2b0]
    mov  rsi, rdi
    lea  rdx, [rbp-0x250]          ; d_ge = (D.x, D.y)
    mov  rcx, r14
    shl  rcx, 5
    lea  rcx, [rbp-0x6b0 + rcx]    ; &ZR[i]
    call point_add_mixed_zr_ref
    mov  rax, r14
    shl  rax, 6
    lea  rdi, [rbp-0x4b0 + rax]    ; &TAB[i]
    lea  rsi, [rbp-0x2b0]
    mov  rcx, 8
    rep  movsq
    inc  r14
    cmp  r14, 8
    jb   .tab_loop
    ; ZG := AI.z * C  (the table's common Z once globalz has run)
    lea  rdi, [rbp-0x1d0]
    lea  rsi, [rbp-0x2b0+64]
    lea  rdx, [rbp-0x250+64]
    call fe_mul

    ; ---- 3b. globalz: scale TAB[j] (j = 6..0) by zs = ZR[j+1]*...*ZR[7] ----
    lea  rdi, [rbp-0x1f0]          ; ZS := ZR[7]
    lea  rsi, [rbp-0x6b0 + 7*32]
    mov  rcx, 4
    rep  movsq
    mov  r14, 6
.gz_loop:
    cmp  r14, 6
    je   .gz_scale
    lea  rax, [r14+1]
    shl  rax, 5
    lea  rdi, [rbp-0x1f0]          ; ZS *= ZR[j+1]
    mov  rsi, rdi
    lea  rdx, [rbp-0x6b0 + rax]
    call fe_mul
.gz_scale:
    lea  rdi, [rbp-0x6f0]          ; TMP := ZS^2
    lea  rsi, [rbp-0x1f0]
    mov  rdx, rsi
    call fe_mul
    mov  rax, r14
    shl  rax, 6
    lea  rdi, [rbp-0x4b0 + rax]    ; TAB[j].x *= ZS^2
    mov  rsi, rdi
    lea  rdx, [rbp-0x6f0]
    call fe_mul
    lea  rdi, [rbp-0x6f0]          ; TMP := ZS^3
    mov  rsi, rdi
    lea  rdx, [rbp-0x1f0]
    call fe_mul
    mov  rax, r14
    shl  rax, 6
    lea  rdi, [rbp-0x4b0+32 + rax] ; TAB[j].y *= ZS^3
    mov  rsi, rdi
    lea  rdx, [rbp-0x6f0]
    call fe_mul
    dec  r14
    jns  .gz_loop

    ; ---- 3c. lambda-table: AUXX[i] = TAB[i].x * beta ----
    xor  r14d, r14d
.aux_loop:
    mov  rax, r14
    shl  rax, 5
    lea  rdi, [rbp-0x5b0 + rax]
    mov  rax, r14
    shl  rax, 6
    lea  rsi, [rbp-0x4b0 + rax]
    lea  rdx, [rel BETA_LIMBS_ref]
    call fe_mul
    inc  r14
    cmp  r14, 8
    jb   .aux_loop

    ; ---- 4. ladder: R = inf; for i = BITS-1..0: R = 2R (+ digit adds) ----
    mov  qword [r12+0], 1
    mov  qword [r12+8], 0
    mov  qword [r12+16], 0
    mov  qword [r12+24], 0
    mov  qword [r12+32], 1
    mov  qword [r12+40], 0
    mov  qword [r12+48], 0
    mov  qword [r12+56], 0
    mov  qword [r12+64], 0
    mov  qword [r12+72], 0
    mov  qword [r12+80], 0
    mov  qword [r12+88], 0
    mov  r14, [rbp-0x6f8]
.ladder:
    dec  r14
    js   .finish
    mov  rdi, r12
    mov  rsi, r12
    call point_double_ref
    xor  r15d, r15d                ; stream 0 = W1/TAB.x, stream 1 = W2/AUXX
.stream:
    mov  rax, r15
    imul rax, rax, 0x90            ; W2 sits 0x90 below W1
    lea  rcx, [rbp-0x120]
    sub  rcx, rax
    movsx rbx, byte [rcx + r14]    ; digit
    test rbx, rbx
    jz   .next_stream
    mov  rax, rbx
    mov  rcx, rbx
    sar  rcx, 63
    xor  rax, rcx
    sub  rax, rcx                  ; |d|
    dec  rax
    shr  rax, 1                    ; idx = (|d|-1)/2
    mov  rdx, rax
    shl  rdx, 6
    lea  rsi, [rbp-0x4b0 + rdx]    ; &TAB[idx].x
    test r15, r15
    jz   .xsrc_ok
    mov  rdx, rax
    shl  rdx, 5
    lea  rsi, [rbp-0x5b0 + rdx]    ; &AUXX[idx]
.xsrc_ok:
    lea  rdi, [rbp-0x6f0]          ; TMP.x
    mov  rcx, 4
    rep  movsq
    mov  rdx, rax
    shl  rdx, 6
    lea  rsi, [rbp-0x4b0+32 + rdx] ; &TAB[idx].y
    test rbx, rbx
    js   .negy
    lea  rdi, [rbp-0x6f0+32]       ; TMP.y = y
    mov  rcx, 4
    rep  movsq
    jmp  .addit
.negy:
    lea  rdi, [rbp-0x6f0+32]       ; TMP.y = 0 - y
    mov  rdx, rsi
    lea  rsi, [rel FE_ZERO_ref]
    call fe_sub
.addit:
    mov  rdi, r12
    mov  rsi, r12
    lea  rdx, [rbp-0x6f0]
    call point_add_mixed_ref           ; R += TMP (R == inf handled by its guard)
.next_stream:
    inc  r15
    cmp  r15, 2
    jb   .stream
    jmp  .ladder

.finish:
    ; ---- 5. leave the isomorphic curve: R.z *= ZG (Z == 0 stays 0) ----
    lea  rdi, [r12+64]
    mov  rsi, rdi
    lea  rdx, [rbp-0x1d0]
    call fe_mul
    jmp  .done

.fallback:
    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rbp-0x50]
    call point_scalar_mul_ref
    jmp  .done

.zero:
    mov  qword [r12+0], 1
    mov  qword [r12+8], 0
    mov  qword [r12+16], 0
    mov  qword [r12+24], 0
    mov  qword [r12+32], 1
    mov  qword [r12+40], 0
    mov  qword [r12+48], 0
    mov  qword [r12+56], 0
    mov  qword [r12+64], 0
    mov  qword [r12+72], 0
    mov  qword [r12+80], 0
    mov  qword [r12+88], 0

.done:
    lea  rsp, [rbp-0x28]           ; == rsp after the 5 pushes (rsp was and-ed)
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
