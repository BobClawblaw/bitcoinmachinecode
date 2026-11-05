/* ============================================================================
 * secp256k1_ecdsa.S -- ECDSA verification in AArch64 assembly (Apple
 * silicon), the counterpart of asm/secp256k1_ecdsa.asm. Replaces
 * ecdsa_twin.c on the Mac (2026-09-26); the twin stays in port/osx/
 * test_support as the differential oracle.
 *
 *   int ecdsa_verify(const u64 z[4], const u64 r[4], const u64 s[4],
 *                    const u64 Qx[4], const u64 Qy[4]);          1 valid / 0
 *   int ecdsa_x_eq_mod_n(const u64 r[4], const u64 X[4], const u64 Z[4]);
 *
 * verify: r, s in (0, n); w = s^-1 (sc_inv_var); u1 = z*w, u2 = r*w;
 * P = u1*G (fixed comb) + u2*Q (GLV unless BMC_ECDSA_GLV=0); P at infinity
 * is invalid; otherwise x(P) == r (mod n), tested projectively.
 *
 * x_eq_mod_n: r*Z^2 == X (mod p), or -- only when r < p - n, so r + n < p --
 * (r+n)*Z^2 == X. The bound check walks the limbs from the top and falls
 * through to the next limb on EQUALITY, as the x86 chain does (jb/ja/fall):
 * the first Mac port returned on equality in limb 3, where p - n is 0, which
 * made the r+n branch dead code and rejected valid signatures whose R.x lies
 * in [n, p) -- testnet4 block 126,683 tx 93 (fixed 2026-09-11 in the twin;
 * the same walk here). Variable-time: verification only, all inputs public.
 *
 * The twin's BMC_ECDSADBG stderr dump (diagnostics only, not in the x86
 * module) is not carried over.
 * ========================================================================== */
    .text

/* w0 = 1 iff the 4-limb value at x0 is in (0, n) ; clobbers x9..x15 */
    .p2align 2
Lin_range:
    ldp   x9, x10, [x0]
    ldp   x11, x12, [x0, #16]
    orr   x13, x9, x10
    orr   x14, x11, x12
    orr   x13, x13, x14
    cbz   x13, 9f                         /* zero */
    adrp  x15, Ln@PAGE
    add   x15, x15, Ln@PAGEOFF
    ldp   x13, x14, [x15, #16]            /* n2, n3 */
    cmp   x12, x14
    b.ne  8f
    cmp   x11, x13
    b.ne  8f
    ldp   x13, x14, [x15]                 /* n0, n1 */
    cmp   x10, x14
    b.ne  8f
    cmp   x9, x13                         /* last limb: x0 < n0 */
8:  cset  w0, lo                          /* the first differing limb decides: x < n */
    ret
9:  mov   w0, #0
    ret

/* ============================================================================
 * ecdsa_x_eq_mod_n(r=x0, X=x1, Z=x2)
 * frame: t 0, lhs 32, cand 64 (96) ; r x19, X x20
 * ========================================================================== */
    .p2align 2
    .globl _ecdsa_x_eq_mod_n
_ecdsa_x_eq_mod_n:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #96
    mov   x19, x0
    mov   x20, x1
    mov   x0, sp                          /* t = Z^2 */
    mov   x1, x2
    bl    _fe_sqr
    add   x0, sp, #32                     /* lhs = r*Z^2 */
    mov   x1, x19
    mov   x2, sp
    bl    _fe_mul
    add   x0, sp, #32
    bl    Leq_x
    cbnz  w0, Lxm_yes
    /* r < p - n ?  top limb first; equality falls through to the next limb */
    adrp  x15, Lpmn@PAGE
    add   x15, x15, Lpmn@PAGEOFF
    ldr   x9,  [x19, #24]
    ldr   x10, [x15, #24]
    cmp   x9, x10
    b.lo  Lxm_lt
    b.hi  Lxm_no
    ldr   x9,  [x19, #16]
    ldr   x10, [x15, #16]
    cmp   x9, x10
    b.lo  Lxm_lt
    b.hi  Lxm_no
    ldr   x9,  [x19, #8]
    ldr   x10, [x15, #8]
    cmp   x9, x10
    b.lo  Lxm_lt
    b.hi  Lxm_no
    ldr   x9,  [x19]
    ldr   x10, [x15]
    cmp   x9, x10
    b.hs  Lxm_no
Lxm_lt:
    /* cand = r + n (mod 2^256) */
    adrp  x15, Ln@PAGE
    add   x15, x15, Ln@PAGEOFF
    ldp   x9, x10, [x19]
    ldp   x11, x12, [x19, #16]
    ldp   x13, x14, [x15]
    adds  x9, x9, x13
    adcs  x10, x10, x14
    ldp   x13, x14, [x15, #16]
    adcs  x11, x11, x13
    adc   x12, x12, x14
    stp   x9, x10, [sp, #64]
    stp   x11, x12, [sp, #80]
    add   x0, sp, #32                     /* lhs = (r+n)*Z^2 */
    add   x1, sp, #64
    mov   x2, sp
    bl    _fe_mul
    add   x0, sp, #32
    bl    Leq_x
    b     Lxm_ret
Lxm_yes:
    mov   w0, #1
    b     Lxm_ret
Lxm_no:
    mov   w0, #0
Lxm_ret:
    add   sp, sp, #96
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* w0 = 1 iff the element at x0 equals the element at x20 (X) ; leaf */
Leq_x:
    ldp   x9, x10, [x0]
    ldp   x11, x12, [x0, #16]
    ldp   x13, x14, [x20]
    ldp   x15, x16, [x20, #16]
    eor   x9, x9, x13
    eor   x10, x10, x14
    eor   x11, x11, x15
    eor   x12, x12, x16
    orr   x9, x9, x10
    orr   x11, x11, x12
    orr   x9, x9, x11
    cmp   x9, #0
    cset  w0, eq
    ret

/* ============================================================================
 * ecdsa_verify(z=x0, r=x1, s=x2, Qx=x3, Qy=x4)
 * frame: sbuf 0, w 32, u1 64, u2 96, Q 128 (64), P1 192 (96), P2 288 (96),
 *        P 384 (96) -> 480 ; z x19, r x20
 * ========================================================================== */
    .p2align 2
    .globl _ecdsa_verify
_ecdsa_verify:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #480
    mov   x19, x0
    mov   x20, x1
    ldp   x9, x10, [x2]                   /* sbuf = s */
    ldp   x11, x12, [x2, #16]
    stp   x9, x10, [sp]
    stp   x11, x12, [sp, #16]
    ldp   x9, x10, [x3]                   /* Q = (Qx, Qy) */
    ldp   x11, x12, [x3, #16]
    stp   x9, x10, [sp, #128]
    stp   x11, x12, [sp, #144]
    ldp   x9, x10, [x4]
    ldp   x11, x12, [x4, #16]
    stp   x9, x10, [sp, #160]
    stp   x11, x12, [sp, #176]
    mov   x0, sp
    bl    Lin_range
    cbz   w0, Lv_no
    mov   x0, x20
    bl    Lin_range
    cbz   w0, Lv_no
    add   x0, sp, #32                     /* w = s^-1 mod n */
    mov   x1, sp
    bl    _sc_inv_var
    cbz   w0, Lv_no
    add   x0, sp, #64                     /* u1 = z*w */
    mov   x1, x19
    add   x2, sp, #32
    bl    _sc_mul
    add   x0, sp, #96                     /* u2 = r*w */
    mov   x1, x20
    add   x2, sp, #32
    bl    _sc_mul
    add   x0, sp, #192                    /* P1 = u1*G */
    add   x1, sp, #64
    bl    _point_scalar_mul_fixed
    bl    _bmc_ecdsa_glv_enabled
    add   x1, sp, #128                    /* Q */
    add   x2, sp, #96                     /* u2 */
    cbz   w0, 1f
    add   x0, sp, #288
    bl    _point_scalar_mul_glv           /* P2 = u2*Q (GLV) */
    b     2f
1:  add   x0, sp, #288
    bl    _point_scalar_mul               /* P2 = u2*Q (window) */
2:  add   x0, sp, #384                    /* P = P1 + P2 */
    add   x1, sp, #192
    add   x2, sp, #288
    bl    _point_add
    ldp   x9, x10, [sp, #448]             /* P.Z == 0: infinity */
    ldp   x11, x12, [sp, #464]
    orr   x9, x9, x10
    orr   x11, x11, x12
    orr   x9, x9, x11
    cbz   x9, Lv_no
    mov   x0, x20                         /* x(P) == r (mod n) */
    add   x1, sp, #384
    add   x2, sp, #448
    bl    _ecdsa_x_eq_mod_n
    b     Lv_ret
Lv_no:
    mov   w0, #0
Lv_ret:
    add   sp, sp, #480
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

    .section __TEXT,__const
    .p2align 4
Ln:     /* n, the group order */
    .quad 0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF
Lpmn:   /* p - n */
    .quad 0x402DA1722FC9BAEE, 0x4551231950B75FC4, 0x0000000000000001, 0x0000000000000000
