/* ============================================================================
 * safegcd_var.h -- variable-time modular inverse by Bernstein-Yang "safegcd"
 * in AArch64 assembly: the counterpart of asm/safegcd_var.inc, as one
 * assembler macro instantiated per modulus. An assembly include (the .S
 * files #include it; the .h suffix is what build_daemon.sh's staleness rule
 * watches).
 *
 *   SAFEGCD_INV_VAR name, M62, MINV62, M4
 *     int name(u64 r[4], const u64 a[4]) : r = a^-1 mod m
 *     M62    : label of m as 5 signed 62-bit limbs
 *     MINV62 : label of one u64, m^{-1} mod 2^62
 *     M4     : label of m as 4 little-endian u64 limbs
 *   m odd and in (2^255, 2^256), so one subtraction reduces any 256-bit
 *   input. Users: n (secp256k1_scalar.S: sc_inv_var, ecdsa_verify's s^{-1})
 *   and p (secp256k1_fe.S: fe_inv_var, schnorr_verify's Z^{-1} for the
 *   even-Y test, secp256k1_taproot.S's affine conversions).
 *
 *   VARIABLE TIME: public inputs only. Secrets go through the constant-time
 *   Fermat sc_inv / fe_inv (policy in secp256k1_point_ct.S's header).
 *
 *   The algorithm, step for step as the x86 macro (its header has the full
 *   derivation; a C prototype of exactly these steps was checked against
 *   fe_inv / sc_inv on 4e5 inputs before this was written, 2026-09-27):
 *   f, g, d, e are 5 signed 62-bit limbs, limbs 0..3 in [0, 2^62), limb 4
 *   carries the sign; f, g have a live length LEN (5 down to 1).
 *   Per outer iteration: (1) 62 divsteps on f0 = f mod 2^64, g0 = g mod 2^64
 *   and eta, accumulating the transition matrix [u v; q r] (the ctz-and-
 *   clear-up-to-6-bits form, w = -g0/f0 mod 2^limit via f0*(f0*f0-2) ==
 *   -f0^{-1} mod 64); (2) d, e = [u v; q r](d, e) / 2^62 mod m, the division
 *   exact after adding md*m, me*m; (3) f, g = [u v; q r](f, g) / 2^62 over
 *   the live length; (4) g == 0 -> done (f == +-1, a^{-1} = d * f mod m),
 *   else fold a 0/-1 top limb pair and repeat. Start f = m, g = a, d = 0,
 *   e = 1, eta = -1. Every accumulation is a signed 128-bit sum of at most
 *   three products |x| <= 2^62 times a limb < 2^62 plus a carry: no overflow.
 *
 *   Returns w0 = 1 and writes r; w0 = 0 with r untouched when a == 0 (mod m).
 *   Leaf; x19..x28 saved. Frame (sp-relative, 5-limb blocks): F @0, G @40,
 *   D @80, E @120. Registers across the outer loop: x19 out, x20 eta,
 *   x21 len, x22..x25 = u v q r, x26 &M62, x27 &M4, x28 m^{-1} mod 2^62.
 * ========================================================================== */
#ifndef SAFEGCD_VAR_H
#define SAFEGCD_VAR_H
#ifdef __ASSEMBLER__   /* assembler macros: a C parser (an editor's) sees nothing */

#define SGV_F   0
#define SGV_G   40
#define SGV_D   80
#define SGV_E   120
#define SGV_FRAME 160
#define SGV_M62 0x3FFFFFFFFFFFFFFF

/* (hi:lo) += reg * [sp, #off]  signed 64x64 -> 128. Clobbers x12, x13, x14. */
.macro SMACC_SP lo, hi, reg, off
    ldr   x12, [sp, #\off]
    mul   x13, \reg, x12
    smulh x14, \reg, x12
    adds  \lo, \lo, x13
    adc   \hi, \hi, x14
.endm
/* (hi:lo) += reg * [base, #off] */
.macro SMACC_B lo, hi, reg, base, off
    ldr   x12, [\base, #\off]
    mul   x13, \reg, x12
    smulh x14, \reg, x12
    adds  \lo, \lo, x13
    adc   \hi, \hi, x14
.endm
/* (hi:lo) >>= 62, arithmetic */
.macro SAR62 lo, hi
    extr  \lo, \hi, \lo, #62
    asr   \hi, \hi, #62
.endm

.macro SAFEGCD_INV_VAR name, m62, minv62, m4
    .p2align 2
    .globl _\name
_\name:
    /* a >= m -> a - m (m > 2^255, so once is enough); then a == 0 -> fail,
     * before anything is saved or written */
    adrp  x10, \m4@PAGE
    add   x10, x10, \m4@PAGEOFF
    ldp   x2, x3, [x1]
    ldp   x4, x5, [x1, #16]
    ldp   x11, x12, [x10]
    ldp   x13, x14, [x10, #16]
    subs  x6, x2, x11
    sbcs  x7, x3, x12
    sbcs  x8, x4, x13
    sbcs  x9, x5, x14
    csel  x2, x6, x2, cs                /* no borrow: a >= m, take a - m */
    csel  x3, x7, x3, cs
    csel  x4, x8, x4, cs
    csel  x5, x9, x5, cs
    orr   x6, x2, x3
    orr   x7, x4, x5
    orr   x6, x6, x7
    cbz   x6, Lsgv_\name\()_fail

    stp   x19, x20, [sp, #-80]!
    stp   x21, x22, [sp, #16]
    stp   x23, x24, [sp, #32]
    stp   x25, x26, [sp, #48]
    stp   x27, x28, [sp, #64]
    sub   sp, sp, #SGV_FRAME
    mov   x19, x0
    mov   x27, x10
    adrp  x26, \m62@PAGE
    add   x26, x26, \m62@PAGEOFF
    adrp  x28, \minv62@PAGE
    add   x28, x28, \minv62@PAGEOFF
    ldr   x28, [x28]

    /* f = m */
    ldp   x6, x7, [x26]
    ldp   x8, x9, [x26, #16]
    ldr   x10, [x26, #32]
    stp   x6, x7, [sp, #SGV_F]
    stp   x8, x9, [sp, #SGV_F + 16]
    str   x10, [sp, #SGV_F + 32]
    /* g = a (reduced, in x2..x5), 4x64 -> 5x62 */
    and   x6, x2, #SGV_M62
    extr  x7, x3, x2, #62               /* a1<<2 | a0>>62 */
    and   x7, x7, #SGV_M62
    extr  x8, x4, x3, #60
    and   x8, x8, #SGV_M62
    extr  x9, x5, x4, #58
    and   x9, x9, #SGV_M62
    lsr   x10, x5, #56
    stp   x6, x7, [sp, #SGV_G]
    stp   x8, x9, [sp, #SGV_G + 16]
    str   x10, [sp, #SGV_G + 32]
    /* d = 0, e = 1, eta = -1, len = 5 */
    stp   xzr, xzr, [sp, #SGV_D]
    stp   xzr, xzr, [sp, #SGV_D + 16]
    str   xzr, [sp, #SGV_D + 32]
    mov   x6, #1
    stp   x6, xzr, [sp, #SGV_E]
    stp   xzr, xzr, [sp, #SGV_E + 16]
    str   xzr, [sp, #SGV_E + 32]
    mov   x20, #-1
    mov   x21, #5

Lsgv_\name\()_outer:
    /* ---- 1. 62 divsteps on the low words. x0=f0 x1=g0 x20=eta x2=steps
     *         left, (u,v,q,r) = (x22,x23,x24,x25). */
    ldr   x0, [sp, #SGV_F]
    ldr   x1, [sp, #SGV_G]
    mov   x2, #62
    mov   x22, #1
    mov   x23, #0
    mov   x24, #0
    mov   x25, #1
Lsgv_\name\()_ds:
    mov   x3, #-1
    lsl   x3, x3, x2                    /* bits >= steps-left set: caps the count */
    orr   x3, x3, x1
    rbit  x4, x3
    clz   x4, x4                        /* z (x3 != 0) */
    lsr   x1, x1, x4
    lsl   x22, x22, x4
    lsl   x23, x23, x4
    sub   x20, x20, x4
    subs  x2, x2, x4
    b.eq  Lsgv_\name\()_ds_done
    tbz   x20, #63, 1f
    neg   x20, x20                      /* eta = -eta */
    mov   x3, x0                        /* (f,g) = (g,-f) */
    mov   x0, x1
    neg   x1, x3
    mov   x3, x22                       /* (u,v,q,r) = (q,r,-u,-v) */
    mov   x22, x24
    neg   x24, x3
    mov   x3, x23
    mov   x23, x25
    neg   x25, x3
1:  add   x3, x20, #1                   /* limit = min(eta+1, steps left); eta >= 0 here */
    cmp   x3, x2
    csel  x3, x2, x3, hi
    neg   x3, x3
    add   x3, x3, #64                   /* 64 - limit */
    mov   x4, #-1
    lsr   x4, x4, x3
    and   x4, x4, #63                   /* mask = 2^min(limit,6) - 1 */
    mul   x5, x0, x0
    sub   x5, x5, #2
    mul   x5, x5, x0                    /* f*(f*f-2) == -1/f mod 64 */
    mul   x5, x5, x1
    and   x5, x5, x4                    /* w */
    madd  x1, x5, x0, x1                /* g += w*f */
    madd  x24, x5, x22, x24             /* q += w*u */
    madd  x25, x5, x23, x25             /* r += w*v */
    b     Lsgv_\name\()_ds
Lsgv_\name\()_ds_done:

    /* ---- 2. (d,e) = [u v; q r](d,e) / 2^62 mod m.
     *         md=x6 me=x7, cd=x9:x8, ce=x11:x10. */
    ldr   x3, [sp, #SGV_D + 32]
    asr   x3, x3, #63                   /* sd */
    ldr   x4, [sp, #SGV_E + 32]
    asr   x4, x4, #63                   /* se */
    and   x6, x22, x3
    and   x5, x23, x4
    add   x6, x6, x5                    /* md = (u & sd) + (v & se) */
    and   x7, x24, x3
    and   x5, x25, x4
    add   x7, x7, x5                    /* me = (q & sd) + (r & se) */
    mov   x8, #0
    mov   x9, #0
    mov   x10, #0
    mov   x11, #0
    SMACC_SP x8, x9, x22, SGV_D
    SMACC_SP x8, x9, x23, SGV_E
    SMACC_SP x10, x11, x24, SGV_D
    SMACC_SP x10, x11, x25, SGV_E
    madd  x3, x28, x8, x6
    and   x3, x3, #SGV_M62
    sub   x6, x6, x3                    /* md -= (minv*cd + md) mod 2^62 */
    madd  x3, x28, x10, x7
    and   x3, x3, #SGV_M62
    sub   x7, x7, x3                    /* me -= (minv*ce + me) mod 2^62 */
    SMACC_B x8, x9, x6, x26, 0
    SMACC_B x10, x11, x7, x26, 0
    SAR62 x8, x9                        /* low 62 bits are zero by construction */
    SAR62 x10, x11
.irp k, 1, 2, 3, 4
    SMACC_SP x8, x9, x22, SGV_D + 8*\k
    SMACC_SP x8, x9, x23, SGV_E + 8*\k
    SMACC_B  x8, x9, x6, x26, 8*\k
    SMACC_SP x10, x11, x24, SGV_D + 8*\k
    SMACC_SP x10, x11, x25, SGV_E + 8*\k
    SMACC_B  x10, x11, x7, x26, 8*\k
    and   x3, x8, #SGV_M62
    str   x3, [sp, #SGV_D + 8*(\k - 1)]
    and   x3, x10, #SGV_M62
    str   x3, [sp, #SGV_E + 8*(\k - 1)]
    SAR62 x8, x9
    SAR62 x10, x11
.endr
    str   x8, [sp, #SGV_D + 32]
    str   x10, [sp, #SGV_E + 32]

    /* ---- 3. (f,g) = [u v; q r](f,g) / 2^62 over the live length.
     *         cf=x9:x8, cg=x11:x10, x15=k, x16=&limb k. */
    mov   x8, #0
    mov   x9, #0
    mov   x10, #0
    mov   x11, #0
    SMACC_SP x8, x9, x22, SGV_F
    SMACC_SP x8, x9, x23, SGV_G
    SMACC_SP x10, x11, x24, SGV_F
    SMACC_SP x10, x11, x25, SGV_G
    SAR62 x8, x9
    SAR62 x10, x11
    mov   x15, #1
Lsgv_\name\()_fg:
    cmp   x15, x21
    b.hs  Lsgv_\name\()_fg_end
    add   x16, sp, x15, lsl #3
    SMACC_B x8, x9, x22, x16, SGV_F
    SMACC_B x8, x9, x23, x16, SGV_G
    SMACC_B x10, x11, x24, x16, SGV_F
    SMACC_B x10, x11, x25, x16, SGV_G
    and   x3, x8, #SGV_M62
    str   x3, [x16, #SGV_F - 8]
    and   x3, x10, #SGV_M62
    str   x3, [x16, #SGV_G - 8]
    SAR62 x8, x9
    SAR62 x10, x11
    add   x15, x15, #1
    b     Lsgv_\name\()_fg
Lsgv_\name\()_fg_end:
    add   x16, sp, x21, lsl #3          /* &limb len */
    str   x8, [x16, #SGV_F - 8]
    str   x10, [x16, #SGV_G - 8]

    /* ---- 4. g == 0 -> done; else fold a 0/-1 top limb pair and go again. */
    ldr   x3, [sp, #SGV_G]
    mov   x15, #1
Lsgv_\name\()_or:
    cmp   x15, x21
    b.hs  Lsgv_\name\()_or_end
    add   x16, sp, x15, lsl #3
    ldr   x4, [x16, #SGV_G]
    orr   x3, x3, x4
    add   x15, x15, #1
    b     Lsgv_\name\()_or
Lsgv_\name\()_or_end:
    cbz   x3, Lsgv_\name\()_done
    cmp   x21, #2
    b.lo  Lsgv_\name\()_outer
    add   x16, sp, x21, lsl #3
    ldr   x3, [x16, #SGV_F - 8]         /* fn */
    ldr   x4, [x16, #SGV_G - 8]         /* gn */
    eor   x5, x3, x3, asr #63           /* 0 iff fn is 0 or -1 */
    eor   x6, x4, x4, asr #63
    orr   x5, x5, x6
    cbnz  x5, Lsgv_\name\()_outer
    ldr   x5, [x16, #SGV_F - 16]
    orr   x5, x5, x3, lsl #62
    str   x5, [x16, #SGV_F - 16]
    ldr   x5, [x16, #SGV_G - 16]
    orr   x5, x5, x4, lsl #62
    str   x5, [x16, #SGV_G - 16]
    sub   x21, x21, #1
    b     Lsgv_\name\()_outer

Lsgv_\name\()_done:
    /* ---- result = d * sign(f), reduced into [0, m). d as 320-bit two's
     *      complement in x6:x5:x4:x3:x2 (limbs 0..3 are in [0, 2^62)). */
    ldp   x2, x3, [sp, #SGV_D]
    ldp   x4, x5, [sp, #SGV_D + 16]
    ldr   x6, [sp, #SGV_D + 32]
    orr   x2, x2, x3, lsl #62           /* w0 = l0 | l1<<62 */
    lsr   x3, x3, #2
    orr   x3, x3, x4, lsl #60           /* w1 = l1>>2 | l2<<60 */
    lsr   x4, x4, #4
    orr   x4, x4, x5, lsl #58           /* w2 = l2>>4 | l3<<58 */
    lsr   x5, x5, #6
    orr   x5, x5, x6, lsl #56           /* w3 = l3>>6 | l4<<56 */
    asr   x6, x6, #8                    /* w4 = l4 >> 8, sign-extended */
    add   x16, sp, x21, lsl #3
    ldr   x7, [x16, #SGV_F - 8]         /* f's top live limb carries its sign */
    tbz   x7, #63, Lsgv_\name\()_addm
    mvn   x2, x2                        /* d = -d */
    mvn   x3, x3
    mvn   x4, x4
    mvn   x5, x5
    mvn   x6, x6
    adds  x2, x2, #1
    adcs  x3, x3, xzr
    adcs  x4, x4, xzr
    adcs  x5, x5, xzr
    adc   x6, x6, xzr
Lsgv_\name\()_addm:
    ldp   x11, x12, [x27]
    ldp   x13, x14, [x27, #16]
1:  tbz   x6, #63, Lsgv_\name\()_subm
    adds  x2, x2, x11
    adcs  x3, x3, x12
    adcs  x4, x4, x13
    adcs  x5, x5, x14
    adc   x6, x6, xzr
    b     1b
Lsgv_\name\()_subm:
    subs  x7, x2, x11                   /* t = x - m; keep it while t >= 0 */
    sbcs  x8, x3, x12
    sbcs  x9, x4, x13
    sbcs  x10, x5, x14
    sbcs  x15, x6, xzr
    tbnz  x15, #63, Lsgv_\name\()_store
    mov   x2, x7
    mov   x3, x8
    mov   x4, x9
    mov   x5, x10
    mov   x6, x15
    b     Lsgv_\name\()_subm
Lsgv_\name\()_store:
    stp   x2, x3, [x19]
    stp   x4, x5, [x19, #16]
    add   sp, sp, #SGV_FRAME
    ldp   x27, x28, [sp, #64]
    ldp   x25, x26, [sp, #48]
    ldp   x23, x24, [sp, #32]
    ldp   x21, x22, [sp, #16]
    ldp   x19, x20, [sp], #80
    mov   w0, #1
    ret
Lsgv_\name\()_fail:
    mov   w0, #0
    ret
.endm

#endif /* __ASSEMBLER__ */
#endif /* SAFEGCD_VAR_H */
