/* ============================================================================
 * secp256k1_fe.S -- the secp256k1 prime field, p = 2^256 - 2^32 - 977, in
 * AArch64 assembly (Apple silicon), the counterpart of asm/secp256k1_fe.asm.
 * Replaces the C twin (fe_twin.c, now the test oracle in port/osx/
 * test_support) on the Mac, 2026-09-26.
 *
 * Elements are 4 little-endian u64 limbs. ABI as the x86 module:
 *   void fe_add(u64 r[4], const u64 a[4], const u64 b[4])
 *   void fe_sub(u64 r[4], const u64 a[4], const u64 b[4])
 *   void fe_mul(u64 r[4], const u64 a[4], const u64 b[4])
 *   void fe_sqr(u64 r[4], const u64 a[4])
 *   void fe_inv(u64 r[4], const u64 a[4])        a^(p-2); fe_inv(0) = 0
 * r may alias a and/or b: every routine loads all its inputs first.
 *
 * WHAT MUST MATCH, AND HOW
 *   fe_add / fe_sub are BIT-IDENTICAL to the frozen x86 reference on every
 *   pair of 256-bit inputs, in range or not (tests/test_fe_repr check 4),
 *   so they transcribe its steps exactly:
 *     add: s = a + b; if bit 256 is set, s += C (mod 2^256, C = 2^32 + 977
 *          = 2^256 - p); then s -= p if s >= p, i.e. w = s + C and take w
 *          when that addition carries out.
 *     sub: d = a - b; if it borrowed, d -= C (mod 2^256) -- the same as
 *          adding p.
 *   fe_mul / fe_sqr / fe_inv return the unique canonical value for ANY
 *   256-bit input, so only correctness is required of their method.
 *
 * fe_mul: a 4x4 schoolbook product into t0..t7 (per row, the low halves and
 * the high halves of a_i*b_j each go through their own adds/adcs chain), then
 *   t = L + H*2^256 == L + H*C (mod p)          H*C < 2^290: 5 limbs
 *   v = L + (H*C mod 2^256), over = (H*C >> 256) + carry      over < 2^35
 *   v += over*C (< 2^68), top = carry out            top <= 1
 *   v += top*C   -- the carry out of the second fold. Dropping it is the bug
 *                  x86's fold 2 had until 2026-08-21 and the Mac C twin had
 *                  until 2026-09-25: ((p-2^31)^2 came out 2^62 - C). After a
 *                  wrap v < 2^68 + 2^33, so this cannot carry again.
 *   r = v >= p ? v - p : v      (w = v + C; take w when it carries out)
 * Every select is csel or a mask: no branch or address depends on the data.
 *
 * fe_inv: the addition chain of asm/secp256k1_fe.asm (x_k = a^(2^k - 1);
 * 255 squarings, 15 multiplies; its exponent was checked equal to p-2 over
 * the integers before this was written).
 *
 * Registers: x18 is never touched (Apple reserves it); x19..x25 are saved
 * where used (AAPCS64 callee-saved; the port's ABI audit checks them).
 * ========================================================================== */
    .text

/* C = 2^32 + 977 = 0x1000003D1 into \reg */
.macro LOADC reg
    movz  \reg, #0x03D1
    movk  \reg, #0x0001, lsl #32
.endm

/* ---------------------------------------------------------------------------
 * fe_add(r=x0, a=x1, b=x2)
 * ------------------------------------------------------------------------- */
    .p2align 2
    .globl _fe_add
_fe_add:
    ldp   x3, x4, [x1]
    ldp   x5, x6, [x1, #16]
    ldp   x7, x8, [x2]
    ldp   x9, x10, [x2, #16]
    adds  x3, x3, x7
    adcs  x4, x4, x8
    adcs  x5, x5, x9
    adcs  x6, x6, x10
    cset  x11, cs                   /* bit 256 */
    LOADC x12
    neg   x11, x11                  /* all-ones when set */
    and   x13, x12, x11
    adds  x3, x3, x13               /* s += C when bit 256 was set; final carry dropped */
    adcs  x4, x4, xzr
    adcs  x5, x5, xzr
    adc   x6, x6, xzr
    adds  x7, x3, x12               /* w = s + C: carries out iff s >= p */
    adcs  x8, x4, xzr
    adcs  x9, x5, xzr
    adcs  x10, x6, xzr
    csel  x3, x7, x3, cs
    csel  x4, x8, x4, cs
    csel  x5, x9, x5, cs
    csel  x6, x10, x6, cs
    stp   x3, x4, [x0]
    stp   x5, x6, [x0, #16]
    ret

/* ---------------------------------------------------------------------------
 * fe_sub(r=x0, a=x1, b=x2)
 * ------------------------------------------------------------------------- */
    .p2align 2
    .globl _fe_sub
_fe_sub:
    ldp   x3, x4, [x1]
    ldp   x5, x6, [x1, #16]
    ldp   x7, x8, [x2]
    ldp   x9, x10, [x2, #16]
    subs  x3, x3, x7
    sbcs  x4, x4, x8
    sbcs  x5, x5, x9
    sbcs  x6, x6, x10
    cset  x11, cc                   /* borrowed (AArch64: carry clear) */
    LOADC x12
    neg   x11, x11
    and   x13, x12, x11
    subs  x3, x3, x13               /* d -= C when it borrowed; final borrow dropped */
    sbcs  x4, x4, xzr
    sbcs  x5, x5, xzr
    sbc   x6, x6, xzr
    stp   x3, x4, [x0]
    stp   x5, x6, [x0, #16]
    ret

/* ---------------------------------------------------------------------------
 * fe_sqr(r=x0, a=x1) = fe_mul(r, a, a)
 * ------------------------------------------------------------------------- */
    .p2align 2
    .globl _fe_sqr
_fe_sqr:
    mov   x2, x1
    /* fall through */

/* ---------------------------------------------------------------------------
 * fe_mul(r=x0, a=x1, b=x2)
 *   a: x3..x6   b: x7..x10   t0..t7: x11..x17, x19
 *   row temporaries lo0..lo3: x1, x2, x20, x21   hi0..hi3: x22..x25
 * ------------------------------------------------------------------------- */
    .globl _fe_mul
_fe_mul:
    stp   x19, x20, [sp, #-48]!
    stp   x21, x22, [sp, #16]
    stp   x23, x24, [sp, #32]
    str   x25, [sp, #-16]!
    ldp   x3, x4, [x1]
    ldp   x5, x6, [x1, #16]
    ldp   x7, x8, [x2]
    ldp   x9, x10, [x2, #16]

    /* row 0: t0..t4 = a0 * b */
    mul   x11, x3, x7
    umulh x1,  x3, x7
    mul   x2,  x3, x8
    umulh x20, x3, x8
    mul   x21, x3, x9
    umulh x22, x3, x9
    mul   x23, x3, x10
    umulh x15, x3, x10
    adds  x12, x1, x2
    adcs  x13, x20, x21
    adcs  x14, x22, x23
    adc   x15, x15, xzr

    /* row 1: t1..t5 += a1 * b */
    mul   x1,  x4, x7
    mul   x2,  x4, x8
    mul   x20, x4, x9
    mul   x21, x4, x10
    umulh x22, x4, x7
    umulh x23, x4, x8
    umulh x24, x4, x9
    umulh x25, x4, x10
    adds  x12, x12, x1
    adcs  x13, x13, x2
    adcs  x14, x14, x20
    adcs  x15, x15, x21
    adc   x16, xzr, xzr
    adds  x13, x13, x22
    adcs  x14, x14, x23
    adcs  x15, x15, x24
    adc   x16, x16, x25

    /* row 2: t2..t6 += a2 * b */
    mul   x1,  x5, x7
    mul   x2,  x5, x8
    mul   x20, x5, x9
    mul   x21, x5, x10
    umulh x22, x5, x7
    umulh x23, x5, x8
    umulh x24, x5, x9
    umulh x25, x5, x10
    adds  x13, x13, x1
    adcs  x14, x14, x2
    adcs  x15, x15, x20
    adcs  x16, x16, x21
    adc   x17, xzr, xzr
    adds  x14, x14, x22
    adcs  x15, x15, x23
    adcs  x16, x16, x24
    adc   x17, x17, x25

    /* row 3: t3..t7 += a3 * b */
    mul   x1,  x6, x7
    mul   x2,  x6, x8
    mul   x20, x6, x9
    mul   x21, x6, x10
    umulh x22, x6, x7
    umulh x23, x6, x8
    umulh x24, x6, x9
    umulh x25, x6, x10
    adds  x14, x14, x1
    adcs  x15, x15, x2
    adcs  x16, x16, x20
    adcs  x17, x17, x21
    adc   x19, xzr, xzr
    adds  x15, x15, x22
    adcs  x16, x16, x23
    adcs  x17, x17, x24
    adc   x19, x19, x25

    /* ---- reduce: L = x11..x14, H = x15, x16, x17, x19 ---- */
    LOADC x3
    /* acc = H * C  (acc0..acc4 in x4, x5, x6, x7, x8) */
    mul   x4,  x15, x3
    umulh x9,  x15, x3
    mul   x1,  x16, x3
    umulh x10, x16, x3
    mul   x2,  x17, x3
    umulh x20, x17, x3
    mul   x21, x19, x3
    umulh x8,  x19, x3
    adds  x5, x9, x1
    adcs  x6, x10, x2
    adcs  x7, x20, x21
    adc   x8, x8, xzr
    /* v = L + acc[0..3]; over = acc4 + carry */
    adds  x11, x11, x4
    adcs  x12, x12, x5
    adcs  x13, x13, x6
    adcs  x14, x14, x7
    adc   x8, x8, xzr
    /* v += over * C; top = carry out */
    mul   x1, x8, x3
    umulh x2, x8, x3
    adds  x11, x11, x1
    adcs  x12, x12, x2
    adcs  x13, x13, xzr
    adcs  x14, x14, xzr
    cset  x9, cs
    /* v += top * C (cannot carry again) */
    mul   x9, x9, x3
    adds  x11, x11, x9
    adcs  x12, x12, xzr
    adcs  x13, x13, xzr
    adc   x14, x14, xzr
    /* r = v >= p ? v - p : v */
    adds  x4, x11, x3
    adcs  x5, x12, xzr
    adcs  x6, x13, xzr
    adcs  x7, x14, xzr
    csel  x11, x4, x11, cs
    csel  x12, x5, x12, cs
    csel  x13, x6, x13, cs
    csel  x14, x7, x14, cs
    stp   x11, x12, [x0]
    stp   x13, x14, [x0, #16]

    ldr   x25, [sp], #16
    ldp   x23, x24, [sp, #32]
    ldp   x21, x22, [sp, #16]
    ldp   x19, x20, [sp], #48
    ret

/* ---------------------------------------------------------------------------
 * fe_inv(r=x0, a=x1): the addition chain (see the header)
 * frame: x19/x20 at sp+0, then A X2 X3 X11 X22 X44 T U (32 bytes each) from
 * sp+16, r at sp+272, the frame record at sp+288
 * ------------------------------------------------------------------------- */
#define F_A   16
#define F_X2  48
#define F_X3  80
#define F_X11 112
#define F_X22 144
#define F_X44 176
#define F_T   208
#define F_U   240

/* dst = src (32 bytes), both sp-relative offsets */
.macro CP dst, src
    ldp   x9, x10, [sp, #\src]
    ldp   x11, x12, [sp, #\src + 16]
    stp   x9, x10, [sp, #\dst]
    stp   x11, x12, [sp, #\dst + 16]
.endm
/* [dst] = [a] * [b] */
.macro MUL3 dst, a, b
    add   x0, sp, #\dst
    add   x1, sp, #\a
    add   x2, sp, #\b
    bl    _fe_mul
.endm
/* [x] = [x]^(2^n) */
.macro SQRN x, n
    add   x19, sp, #\x
    mov   x20, #\n
1:  mov   x0, x19
    mov   x1, x19
    bl    _fe_sqr
    subs  x20, x20, #1
    b.ne  1b
.endm

    .p2align 2
    .globl _fe_inv
_fe_inv:
    sub   sp, sp, #304
    stp   x29, x30, [sp, #288]
    add   x29, sp, #288
    stp   x19, x20, [sp, #0]
    str   x0, [sp, #272]                /* r (the frame keeps a's copy: r may alias a) */
    ldp   x9, x10, [x1]
    ldp   x11, x12, [x1, #16]
    stp   x9, x10, [sp, #F_A]
    stp   x11, x12, [sp, #F_A + 16]

    CP    F_X2, F_A
    SQRN  F_X2, 1
    MUL3  F_X2, F_X2, F_A               /* x2  */
    CP    F_X3, F_X2
    SQRN  F_X3, 1
    MUL3  F_X3, F_X3, F_A               /* x3  */
    CP    F_T, F_X3
    SQRN  F_T, 3
    MUL3  F_T, F_T, F_X3                /* x6  */
    SQRN  F_T, 3
    MUL3  F_T, F_T, F_X3                /* x9  */
    SQRN  F_T, 2
    MUL3  F_X11, F_T, F_X2              /* x11 */
    CP    F_T, F_X11
    SQRN  F_T, 11
    MUL3  F_X22, F_T, F_X11             /* x22 */
    CP    F_T, F_X22
    SQRN  F_T, 22
    MUL3  F_X44, F_T, F_X22             /* x44 */
    CP    F_T, F_X44
    SQRN  F_T, 44
    MUL3  F_T, F_T, F_X44               /* x88 */
    CP    F_U, F_T
    SQRN  F_U, 88
    MUL3  F_U, F_U, F_T                 /* x176 */
    SQRN  F_U, 44
    MUL3  F_U, F_U, F_X44               /* x220 */
    SQRN  F_U, 3
    MUL3  F_U, F_U, F_X3                /* x223 */
    SQRN  F_U, 23
    MUL3  F_U, F_U, F_X22
    SQRN  F_U, 5
    MUL3  F_U, F_U, F_A
    SQRN  F_U, 3
    MUL3  F_U, F_U, F_X2
    SQRN  F_U, 2
    ldr   x0, [sp, #272]                /* r = t * a */
    add   x1, sp, #F_U
    add   x2, sp, #F_A
    bl    _fe_mul

    ldp   x19, x20, [sp, #0]
    ldp   x29, x30, [sp, #288]
    add   sp, sp, #304
    ret
