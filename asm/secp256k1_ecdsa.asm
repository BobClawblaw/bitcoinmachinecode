; ============================================================================
; secp256k1_ecdsa.asm -- ECDSA signature verification (verify-only) for the
;   secp256k1 curve, hand-written 100% AI x86-64 assembly.
;
;   Derived from first principles + my own Python oracle (asm/validation/);
;   NOT derived from Bitcoin Core or any existing signature library.
;
;   public API:
;     int ecdsa_verify(const u64 z[4], const u64 r[4], const u64 s[4],
;                      const u64 Qx[4], const u64 Qy[4])
;     returns 1 if (r,s) is a valid ECDSA signature of message-hash z under
;     public key Q=(Qx,Qy); else 0.
;
;     int ecdsa_x_eq_mod_n(const u64 r[4], const u64 X[4], const u64 Z[4])
;     test-visible helper (see below): 1 iff x(P) == r (mod n) for the
;     Jacobian point with X-coordinate X and Z-coordinate Z (Z != 0).
;
;   System V ABI: rdi=z, rsi=r, rdx=s, rcx=Qx, r8=Qy. Preserve rbx/r12-r15.
;   Nested calls need rsp 16-aligned.
;
;   Algorithm (standard ECDSA, verify is over PUBLIC inputs -> variable time):
;     if !(1<=r<n and 1<=s<n): return 0
;     w  = s^{-1} mod n            [sc_inv_var: variable-time binary xgcd]
;     u1 = z*w mod n ; u2 = r*w mod n
;     P  = u1*G + u2*Q             (Jacobian X:Y:Z)
;     if P infinity: return 0
;     return x(P) == r (mod n)     [ecdsa_x_eq_mod_n: NO field inversion]
;
;   PERF_SCOPE.md 4.2 (2026-08-21): the two inversions that used to sit on
;   this path -- Fermat sc_inv for w (450 sc_mul, 45% of a verify) and
;   fe_inv for the affine x (503 fe_mul, 5.4%) -- are gone:
;     A. x(P) == r (mod n) is decided in projective form exactly as
;        libsecp256k1's secp256k1_ecdsa_sig_verify does (ecdsa_impl.h:238-270):
;          x(P) = X / Z^2 mod p, and since 2n > p,
;          x(P) == r (mod n)  <=>  r*Z^2 == X (mod p)
;                             or  (r + n < p  and  (r+n)*Z^2 == X (mod p)).
;        Pure algebra; identical verdict on every input.
;     B. w = s^{-1} uses sc_inv_var (secp256k1_scalar.asm), a variable-time
;        binary extended GCD. s is PUBLIC (it is in the signature), so the
;        variable-time policy that already covers point_scalar_mul applies
;        (see secp256k1_point_ct.asm header). Secret-scalar paths (signing,
;        wallet) keep the constant-time Fermat sc_inv.
;
;   CENTRAL CONVENTION (the hard-won lesson): every multi-limb buffer is a
;   CONTIGUOUS ASCENDING array: limb0 at base+0 .. limb3 at base+24.  ALL
;   helpers (sc_inv_var, sc_mul, point_scalar_mul, point_add, fe_mul) read
;   operands and write results exactly this way from their base pointer.
;
;   Frame (all blocks ASCENDING from their base, disjoint; base = lowest addr):
;     s: -0x50   w: -0x90   u1: -0xc0   u2: -0xf0   Q: -0x150 (8)
;     P1: -0x1c0 (12)   P2: -0x220 (12)   P: -0x280 (12)
;   frame = sub rsp, 0x2c8
; ============================================================================

default rel

extern sc_inv_var
extern sc_mul
extern point_scalar_mul
extern point_scalar_mul_glv       ; PERF_SCOPE.md 4.3 (GLV + wNAF), secp256k1_point.asm
extern bmc_ecdsa_glv_enabled      ; BMC_ECDSA_GLV kill switch, secp256k1_glv_c.c
extern point_scalar_mul_fixed
extern point_add
extern fe_mul

section .rodata

align 16
; Generator G affine: two 4-limb field elements, limbs little-endian ascending.
G_AFF:
    dq 0x59F2815B16F81798,0x029BFCDB2DCE28D9,0x55A06295CE870B07,0x79BE667EF9DCBBAC
    dq 0x9C47D08FFB10D4B8,0xFD17B448A6855419,0x5DA4FBFC0E1108A8,0x483ADA7726A3C465

align 16
N_LIMBS:
    dq 0xBFD25E8CD0364141,0xBAAEDCE6AF48A03B,0xFFFFFFFFFFFFFFFE,0xFFFFFFFFFFFFFFFF

; p - n = 0x14551231950b75fc4402da1722fc9baee (libsecp256k1's
; secp256k1_ecdsa_const_p_minus_order, ecdsa_impl.h:32), 4 LE limbs.
; r + n < p  <=>  r < p - n.
align 16
PMN_LIMBS:
    dq 0x402DA1722FC9BAEE,0x4551231950B75FC4,0x0000000000000001,0x0000000000000000

section .text

; ---- local helper: x (rsi -> 4 ascending limbs) strictly in (0,n) ? ----
; eax=1 if yes, eax=0 if no. Clobbers rax; preserves rsi,rdi,rbx,r12-r15.
ecdsa_in_range:
    mov rax, [rsi+0]
    or  rax, [rsi+8]
    or  rax, [rsi+16]
    or  rax, [rsi+24]
    jz  .no
    mov rax, [rsi+24]
    cmp rax, [N_LIMBS+24]
    jb  .yes
    ja  .no
    mov rax, [rsi+16]
    cmp rax, [N_LIMBS+16]
    jb  .yes
    ja  .no
    mov rax, [rsi+8]
    cmp rax, [N_LIMBS+8]
    jb  .yes
    ja  .no
    mov rax, [rsi+0]
    cmp rax, [N_LIMBS+0]
    jb  .yes
    ja  .no
    jmp .no
.yes:
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; ----------------------------------------------------------------------------
; int ecdsa_x_eq_mod_n(const u64 r[4], const u64 X[4], const u64 Z[4])
;   1 iff X / Z^2 == r (mod n), decided without inverting Z:
;     t = r * Z^2 (mod p);            if t == X  -> 1
;     if r >= p - n                   -> 0   (r + n >= p: no second candidate)
;     t = (r + n) * Z^2 (mod p);      if t == X  -> 1 else 0
;   Preconditions: 0 < r < n (so r, r+n are canonical field elements when
;   r < p - n), X and Z canonical in [0,p), Z != 0 (caller checks infinity).
;   fe_mul output is canonical, so limb equality is field equality.
;   Exported (not static) ONLY so tests/test_ecdsa_inverse.c can drive the
;   r + n branch directly: a real signature reaches it with probability
;   ~2^-127, so no signature vector can.
;   rdi=r, rsi=X, rdx=Z. Preserves rbx, r12-r15.
;   Frame: z2 @ rbp-0x40, t @ rbp-0x60, rn @ rbp-0x80 (ascending, 4 limbs).
; ----------------------------------------------------------------------------
global ecdsa_x_eq_mod_n
ecdsa_x_eq_mod_n:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 0x60          ; entry rsp==8 mod 16; +5 pushes -> 0; -0x60 -> 0
    mov  r12, rdi           ; r
    mov  r13, rsi           ; X
    mov  r14, rdx           ; Z

    ; z2 = Z*Z
    lea  rdi, [rbp-0x40]
    mov  rsi, r14
    mov  rdx, r14
    call fe_mul
    ; t = r * z2
    lea  rdi, [rbp-0x60]
    mov  rsi, r12
    lea  rdx, [rbp-0x40]
    call fe_mul
    ; t == X ?
    mov  rax, [rbp-0x60+0]
    cmp  rax, [r13+0]
    jne  .second
    mov  rax, [rbp-0x60+8]
    cmp  rax, [r13+8]
    jne  .second
    mov  rax, [rbp-0x60+16]
    cmp  rax, [r13+16]
    jne  .second
    mov  rax, [rbp-0x60+24]
    cmp  rax, [r13+24]
    jne  .second
    jmp  .yes

.second:
    ; r < p - n ?  (strict: r == p-n means r+n == p, not a field element)
    mov  rax, [r12+24]
    cmp  rax, [PMN_LIMBS+24]
    jb   .lt
    ja   .no
    mov  rax, [r12+16]
    cmp  rax, [PMN_LIMBS+16]
    jb   .lt
    ja   .no
    mov  rax, [r12+8]
    cmp  rax, [PMN_LIMBS+8]
    jb   .lt
    ja   .no
    mov  rax, [r12+0]
    cmp  rax, [PMN_LIMBS+0]
    jae  .no
.lt:
    ; rn = r + n  (< p < 2^256: no carry out)
    mov  rax, [r12+0]
    add  rax, [N_LIMBS+0]
    mov  [rbp-0x80+0], rax
    mov  rax, [r12+8]
    adc  rax, [N_LIMBS+8]
    mov  [rbp-0x80+8], rax
    mov  rax, [r12+16]
    adc  rax, [N_LIMBS+16]
    mov  [rbp-0x80+16], rax
    mov  rax, [r12+24]
    adc  rax, [N_LIMBS+24]
    mov  [rbp-0x80+24], rax
    ; t = rn * z2
    lea  rdi, [rbp-0x60]
    lea  rsi, [rbp-0x80]
    lea  rdx, [rbp-0x40]
    call fe_mul
    mov  rax, [rbp-0x60+0]
    cmp  rax, [r13+0]
    jne  .no
    mov  rax, [rbp-0x60+8]
    cmp  rax, [r13+8]
    jne  .no
    mov  rax, [rbp-0x60+16]
    cmp  rax, [r13+16]
    jne  .no
    mov  rax, [rbp-0x60+24]
    cmp  rax, [r13+24]
    jne  .no
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    add  rsp, 0x60
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
global ecdsa_verify
ecdsa_verify:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x2c8         ; below save area [rbp-8..-0x28]; 0x2c8==8 mod16
                            ; -> rsp 0 mod16 at nested calls. Covers -0x280.
    and  rsp, -16           ; ...only if the caller was aligned, which the
                            ; interpreter -> sv_checksig chain does not
                            ; guarantee. This function now calls C
                            ; (bmc_ecdsa_glv_enabled), so align here; every
                            ; local is rbp-relative and .done restores from rbp.

    ; arg pointers in callee-saved regs (helpers preserve them):
    ;   r12=Qx  r13=Qy  r14=r  r15=z
    mov r12, rcx
    mov r13, r8
    mov r14, rsi
    mov r15, rdi

    ; ---- copy s into ASCENDING local (s_base -0x50) ----
    mov rax, [rdx+0]
    mov [rbp-0x50], rax
    mov rax, [rdx+8]
    mov [rbp-0x48], rax
    mov rax, [rdx+16]
    mov [rbp-0x40], rax
    mov rax, [rdx+24]
    mov [rbp-0x38], rax

    ; s in (0,n) ?
    lea rsi, [rbp-0x50]
    call ecdsa_in_range
    test eax, eax
    jz  .invalid
    ; r in (0,n) ?
    mov rsi, r14
    call ecdsa_in_range
    test eax, eax
    jz  .invalid

    ; ---- w = s^{-1} mod n : w_base -0x90  (variable-time; s is public and
    ;      ecdsa_in_range above already guaranteed 0 < s < n) ----
    lea rdi, [rbp-0x90]
    lea rsi, [rbp-0x50]
    call sc_inv_var
    test eax, eax           ; 0 only for s == 0, which cannot reach here;
    jz  .invalid            ; kept as a belt-and-braces reject, never accept

    ; ---- u1 = z*w mod n : u1_base -0xc0 ----
    lea rdi, [rbp-0xc0]
    mov rsi, r15            ; z
    lea rdx, [rbp-0x90]     ; w
    call sc_mul

    ; ---- build Q affine ASCENDING: Q_base -0x150 (8 limbs: x then y) ----
    ; x@[-0x150,-0x148,-0x140,-0x138] ; y@[-0x130,-0x128,-0x120,-0x118]
    mov rax, [r12+0]
    mov [rbp-0x150], rax
    mov rax, [r12+8]
    mov [rbp-0x148], rax
    mov rax, [r12+16]
    mov [rbp-0x140], rax
    mov rax, [r12+24]
    mov [rbp-0x138], rax
    mov rax, [r13+0]
    mov [rbp-0x130], rax
    mov rax, [r13+8]
    mov [rbp-0x128], rax
    mov rax, [r13+16]
    mov [rbp-0x120], rax
    mov rax, [r13+24]
    mov [rbp-0x118], rax

    ; ---- u2 = r*w mod n : u2_base -0xf0 ----
    lea rdi, [rbp-0xf0]
    mov rsi, r14            ; r
    lea rdx, [rbp-0x90]     ; w
    call sc_mul

    ; ---- P1 = u1*G : P1_base -0x1c0 (12)  [fixed-base G comb] ----
    lea rdi, [rbp-0x1c0]
    lea rsi, [rbp-0xc0]     ; u1
    call point_scalar_mul_fixed

    ; ---- P2 = u2*Q : P2_base -0x220 (12) ----
    ; GLV endomorphism + wNAF ladder (PERF_SCOPE.md 4.3) unless the
    ; BMC_ECDSA_GLV=0 kill switch is set; point_scalar_mul_glv itself falls
    ; back to point_scalar_mul if the split's identity check fails. u2 is
    ; public, so a variable-time multiply is within policy
    ; (secp256k1_point_ct.asm header). The C call clobbers only
    ; caller-saved registers; every operand below is re-derived from rbp.
    call bmc_ecdsa_glv_enabled
    test eax, eax
    jz  .p2_plain
    lea rdi, [rbp-0x220]
    lea rsi, [rbp-0x150]    ; Q
    lea rdx, [rbp-0xf0]     ; u2
    call point_scalar_mul_glv
    jmp .p2_done
.p2_plain:
    lea rdi, [rbp-0x220]
    lea rsi, [rbp-0x150]    ; Q
    lea rdx, [rbp-0xf0]     ; u2
    call point_scalar_mul
.p2_done:

    ; ---- P = P1 + P2 : P_base -0x280 (12) ----
    lea rdi, [rbp-0x280]
    lea rsi, [rbp-0x1c0]    ; P1
    lea rdx, [rbp-0x220]    ; P2
    call point_add

    ; ---- P infinite? (Z = P[8..11] = base+64 .. +88, all zero) ----
    mov rax, [rbp-0x280+64]
    or  rax, [rbp-0x280+72]
    or  rax, [rbp-0x280+80]
    or  rax, [rbp-0x280+88]
    jz  .invalid

    ; ---- x(P) == r (mod n), projective (no fe_inv) ----
    mov rdi, r14            ; r
    lea rsi, [rbp-0x280]    ; X = P[0..3]
    lea rdx, [rbp-0x280+64] ; Z = P[8..11]
    call ecdsa_x_eq_mod_n
    test eax, eax
    jz  .invalid
    mov eax, 1
    jmp .done
.invalid:
    xor eax, eax
.done:
    lea rsp, [rbp-0x28]     ; == rsp after the 5 pushes (rsp was and-ed)
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
