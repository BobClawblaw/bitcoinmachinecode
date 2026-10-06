/* secp256k1_fe_inline.h -- fe_add / fe_sub as in-line macros for the point
 * formulas (secp256k1_point.S, secp256k1_point_ct.S), the Mac's counterpart
 * of x86's asm/secp256k1_fe_inline.inc (main 5501c764, 2026: point_double
 * 1.22x). The bodies are secp256k1_fe.S's _fe_add / _fe_sub instruction for
 * instruction, on the same x0 = r, x1 = a, x2 = b, so the results stay
 * bit-identical to the functions (tests/test_fe_repr pins those) and r may
 * alias a and/or b (all inputs are loaded first). They clobber x3..x13 only
 * -- a subset of what the call clobbered -- and leave x30 alone.
 *
 * Measured before (2026-10-06): a dependent fe_add / fe_sub call costs a
 * memory round trip plus the call; the Jacobian point_double, 5S + 2M + 13
 * add/sub calls, took 106 ns, more than the complete-formula double's 91. */
#ifndef BMC_SECP256K1_FE_INLINE_H
#define BMC_SECP256K1_FE_INLINE_H

.macro FE_ADD_INLINE
    ldp   x3, x4, [x1]
    ldp   x5, x6, [x1, #16]
    ldp   x7, x8, [x2]
    ldp   x9, x10, [x2, #16]
    adds  x3, x3, x7
    adcs  x4, x4, x8
    adcs  x5, x5, x9
    adcs  x6, x6, x10
    cset  x11, cs                   /* bit 256 */
    movz  x12, #0x03D1
    movk  x12, #0x0001, lsl #32     /* C = 2^256 - p */
    neg   x11, x11
    and   x13, x12, x11
    adds  x3, x3, x13               /* s += C when bit 256 was set */
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
.endm

.macro FE_SUB_INLINE
    ldp   x3, x4, [x1]
    ldp   x5, x6, [x1, #16]
    ldp   x7, x8, [x2]
    ldp   x9, x10, [x2, #16]
    subs  x3, x3, x7
    sbcs  x4, x4, x8
    sbcs  x5, x5, x9
    sbcs  x6, x6, x10
    cset  x11, cc                   /* borrowed */
    movz  x12, #0x03D1
    movk  x12, #0x0001, lsl #32
    neg   x11, x11
    and   x13, x12, x11
    subs  x3, x3, x13               /* d -= C when it borrowed */
    sbcs  x4, x4, xzr
    sbcs  x5, x5, xzr
    sbc   x6, x6, xzr
    stp   x3, x4, [x0]
    stp   x5, x6, [x0, #16]
.endm

#endif
