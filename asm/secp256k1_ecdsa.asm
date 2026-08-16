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
;   System V ABI: rdi=z, rsi=r, rdx=s, rcx=Qx, r8=Qy. Preserve rbx/r12-r15.
;   Nested calls need rsp 16-aligned.
;
;   Algorithm (standard low-S ECDSA):
;     if !(1<=r<n and 1<=s<n): return 0
;     w  = s^{-1} mod n ; u1 = z*w mod n ; u2 = r*w mod n
;     P  = u1*G + u2*Q            (Jacobian)
;     if P infinity: return 0
;     px = P.x * (1/P.z^2) mod p   (affine x)
;     return ( (px mod n) == r ) ? 1 : 0
;
;   CENTRAL CONVENTION (the hard-won lesson): every multi-limb buffer is a
;   CONTIGUOUS ASCENDING array: limb0 at base+0 .. limb3 at base+24.  ALL
;   helpers (sc_inv, sc_mul, point_scalar_mul, point_add, fe_mul/fe_inv) read
;   operands and write results exactly this way from their base pointer. Storing
;   a buffer descending or scattered silently scrambles it.
;
;   Frame (all blocks ASCENDING from their base, disjoint; base = lowest addr):
;     s: -0x50   w: -0x90   u1: -0xc0   u2: -0xf0   Q: -0x150 (8)
;     P1: -0x1c0 (12)   P2: -0x220 (12)   P: -0x280 (12)
;     scratch z2/px: -0x50 ; zi: -0x90   (reused after point step)
;   frame = sub rsp, 0x2c8
; ============================================================================

default rel

extern sc_inv
extern sc_mul
extern point_scalar_mul
extern point_scalar_mul_fixed
extern point_add
extern fe_mul
extern fe_inv

section .rodata

align 16
; Generator G affine: two 4-limb field elements, limbs little-endian ascending.
G_AFF:
    dq 0x59F2815B16F81798,0x029BFCDB2DCE28D9,0x55A06295CE870B07,0x79BE667EF9DCBBAC
    dq 0x9C47D08FFB10D4B8,0xFD17B448A6855419,0x5DA4FBFC0E1108A8,0x483ADA7726A3C465

align 16
N_LIMBS:
    dq 0xBFD25E8CD0364141,0xBAAEDCE6AF48A03B,0xFFFFFFFFFFFFFFFE,0xFFFFFFFFFFFFFFFF

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

    ; ---- w = s^{-1} mod n : w_base -0x90 ----
    lea rdi, [rbp-0x90]
    lea rsi, [rbp-0x50]
    call sc_inv

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
    lea rdi, [rbp-0x220]
    lea rsi, [rbp-0x150]    ; Q
    lea rdx, [rbp-0xf0]     ; u2
    call point_scalar_mul

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

    ; ---- affine x = X * (1/Z^2) mod p. scratch ascending: z2@-0x50, zi@-0x90 ----
    ; z2 = Z*Z   (Z = P[8..11] at -0x280+64)
    lea rdi, [rbp-0x50]
    lea rsi, [rbp-0x280+64]
    mov rdx, rsi
    call fe_mul
    ; zi = z2^{-1}
    lea rdi, [rbp-0x90]
    lea rsi, [rbp-0x50]
    call fe_inv
    ; px = X * zi  (X = P[0..3] at -0x280)
    lea rdi, [rbp-0x50]
    lea rsi, [rbp-0x280]
    lea rdx, [rbp-0x90]
    call fe_mul
    ; px now lives at -0x50

    ; ---- px mod n -> pxmod at -0xf0 (one conditional subtract; px < p < 2n) ----
    mov rax, [rbp-0x50+0]
    sub rax, [N_LIMBS+0]
    mov rbx, rax
    mov rax, [rbp-0x50+8]
    sbb rax, [N_LIMBS+8]
    mov r11, rax
    mov rax, [rbp-0x50+16]
    sbb rax, [N_LIMBS+16]
    mov r10, rax
    mov rax, [rbp-0x50+24]
    sbb rax, [N_LIMBS+24]
    mov r9, rax
    jc  .px_lt
    mov [rbp-0xf0+0], rbx
    mov [rbp-0xf0+8], r11
    mov [rbp-0xf0+16], r10
    mov [rbp-0xf0+24], r9
    jmp .compare
.px_lt:
    mov rax, [rbp-0x50+0]
    mov [rbp-0xf0+0], rax
    mov rax, [rbp-0x50+8]
    mov [rbp-0xf0+8], rax
    mov rax, [rbp-0x50+16]
    mov [rbp-0xf0+16], rax
    mov rax, [rbp-0x50+24]
    mov [rbp-0xf0+24], rax
.compare:
    ; compare pxmod (base -0xf0) vs r (r14)
    mov rax, [rbp-0xf0+0]
    cmp rax, [r14+0]
    jne .invalid
    mov rax, [rbp-0xf0+8]
    cmp rax, [r14+8]
    jne .invalid
    mov rax, [rbp-0xf0+16]
    cmp rax, [r14+16]
    jne .invalid
    mov rax, [rbp-0xf0+24]
    cmp rax, [r14+24]
    jne .invalid
    mov eax, 1
    jmp .done
.invalid:
    xor eax, eax
.done:
    add rsp, 0x2c8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
