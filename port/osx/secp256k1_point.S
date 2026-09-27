/* ============================================================================
 * secp256k1_point.S -- secp256k1 Jacobian point arithmetic in AArch64
 * assembly (Apple silicon), the counterpart of asm/secp256k1_point.asm.
 * Replaces point_twin.c on the Mac (2026-09-26); the twin stays in
 * port/osx/test_support as the differential oracle.
 *
 * Curve y^2 = x^3 + 7. A Jacobian point is 12 limbs: X [0..3], Y [4..7],
 * Z [8..11]; affine (x, y) = (X/Z^2, Y/Z^3); infinity is Z = 0 with X = Y = 1.
 * An affine point is 8 limbs. Field ops: secp256k1_fe.S.
 *
 *   void point_double(u64 r[12], const u64 p[12]);
 *   void point_add_mixed_zr(u64 r[12], const u64 p[12], const u64 xy[8], u64 zr[4]);
 *   void point_add_mixed(u64 r[12], const u64 p[12], const u64 xy[8]);
 *   void point_add(u64 r[12], const u64 p[12], const u64 q[12]);
 *   void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
 *   void point_scalar_mul_fixed(u64 r[12], const u64 k[4]);
 *   void point_scalar_mul_glv(u64 r[12], const u64 xy[8], const u64 k[4]);
 *
 * THE CONTRACT: tests/test_point_repr requires these to agree limb for limb
 * with the frozen x86 EC layer on arbitrary (off-curve) operands, in place
 * (r == p) and out of place. So every routine is the twin's exact sequence
 * of field calls -- the same operands, the same slot or output limb, the same
 * moment each output limb is written relative to the reads of the input --
 * not merely an algebraically equivalent formula. Squarings are fe_sqr where
 * the twin has fe_sqr; doublings are fe_add(x, x, x) (fe_add loads both
 * operands before it stores, so that is the twin's temp-and-copy).
 *
 * point_scalar_mul (w = 4 window) and point_scalar_mul_glv (GLV + wNAF,
 * isomorphic-curve table with captured z-ratios, fallback to the window on
 * any split/wNAF signal) are VARIABLE-TIME, for verification only, as on x86.
 *
 * Registers: x18 untouched; x19..x28 saved where used.
 * ========================================================================== */
    .text

/* ---- operand helpers: each field operand is (base register, byte offset) ---- */
.macro FE3 fn, b0, o0, b1, o1, b2, o2
    add   x0, \b0, #\o0
    add   x1, \b1, #\o1
    add   x2, \b2, #\o2
    bl    _\fn
.endm
.macro FE2 fn, b0, o0, b1, o1
    add   x0, \b0, #\o0
    add   x1, \b1, #\o1
    bl    _\fn
.endm
/* dst = src, 32 / 64 / 96 bytes. Addresses are formed in x13/x14 first: an
 * ldp/stp immediate reaches only +-504 bytes and the GLV frame is 1.8 KB. */
.macro CP32 db, do, sb, so
    add   x13, \sb, #\so
    add   x14, \db, #\do
    ldp   x11, x12, [x13]           /* data in x11/x12/x15/x16, never a base: */
    ldp   x15, x16, [x13, #16]      /* call sites pass x9/x10 as bases, and a */
    stp   x11, x12, [x14]           /* CP64/CP96 reuses its base after the    */
    stp   x15, x16, [x14, #16]      /* first 32 bytes                         */
.endm
.macro CP64 db, do, sb, so
    CP32  \db, \do, \sb, \so
    CP32  \db, \do + 32, \sb, \so + 32
.endm
.macro CP96 db, do, sb, so
    CP64  \db, \do, \sb, \so
    CP32  \db, \do + 64, \sb, \so + 64
.endm
/* Z flag <- (the element at base+off is zero) */
.macro ISZERO b, o
    add   x13, \b, #\o
    ldp   x9, x10, [x13]
    ldp   x11, x12, [x13, #16]
    orr   x9, x9, x10
    orr   x11, x11, x12
    orr   x9, x9, x11
    cmp   x9, #0
.endm
/* Z flag <- (the two elements are equal) */
.macro FEEQ ab, ao, bb, bo
    add   x13, \ab, #\ao
    add   x14, \bb, #\bo
    ldp   x9, x10, [x13]
    ldp   x11, x12, [x13, #16]
    ldp   x15, x16, [x14]
    ldp   x13, x14, [x14, #16]
    eor   x9, x9, x15
    eor   x10, x10, x16
    eor   x11, x11, x13
    eor   x12, x12, x14
    orr   x9, x9, x10
    orr   x11, x11, x12
    orr   x9, x9, x11
    cmp   x9, #0
.endm
/* the 12 limbs at base+off := canonical infinity (1, 1, 0) */
.macro SETINF b, o
    add   x13, \b, #\o
    mov   x9, #1
    stp   x9, xzr, [x13]
    stp   xzr, xzr, [x13, #16]
    stp   x9, xzr, [x13, #32]
    stp   xzr, xzr, [x13, #48]
    stp   xzr, xzr, [x13, #64]
    stp   xzr, xzr, [x13, #80]
.endm
/* the 4 limbs at base+off := 1 */
.macro SETONE b, o
    add   x13, \b, #\o
    mov   x9, #1
    stp   x9, xzr, [x13]
    stp   xzr, xzr, [x13, #16]
.endm
/* w4 := the 4-bit window \n (a register holding the window index) of the
 * 4-limb scalar at sp+\k ; clobbers x9, x10 */
.macro NIBBLE dst, n, k
    lsl   x9, \n, #2                  /* bit */
    lsr   x10, x9, #6                 /* limb */
    add   x10, sp, x10, lsl #3
    ldr   x10, [x10, #\k]
    and   x9, x9, #63
    lsr   x10, x10, x9
    and   \dst, x10, #15
.endm

/* ============================================================================
 * point_double(r=x0, p=x1)
 * slots: A 0, B 32, C 64, D 96, E 128, F 160, t 192, yz 224, c8 256, edt 288,
 *        dx 320, y3 352   (frame 384 + saves)
 * ========================================================================== */
    .p2align 2
    .globl _point_double
_point_double:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #384
    mov   x19, x0                     /* r */
    mov   x20, x1                     /* p */
    FE2   fe_sqr, sp, 0,   x20, 0        /* A = X1^2 */
    FE2   fe_sqr, sp, 32,  x20, 32       /* B = Y1^2 */
    FE2   fe_sqr, sp, 64,  sp, 32        /* C = B^2 */
    FE3   fe_add, sp, 192, x20, 0, sp, 32   /* t = X1 + B */
    FE2   fe_sqr, sp, 96,  sp, 192       /* D = t^2 */
    FE3   fe_sub, sp, 96,  sp, 96, sp, 0    /* - A */
    FE3   fe_sub, sp, 96,  sp, 96, sp, 64   /* - C */
    FE3   fe_add, sp, 96,  sp, 96, sp, 96   /* D = 2*(t^2 - A - C) */
    FE3   fe_add, sp, 128, sp, 0,  sp, 0    /* E = 2A */
    FE3   fe_add, sp, 128, sp, 128, sp, 0   /* E = 3A */
    FE2   fe_sqr, sp, 160, sp, 128       /* F = E^2 */
    FE3   fe_sub, sp, 192, sp, 160, sp, 96  /* t = F - D */
    FE3   fe_sub, sp, 192, sp, 192, sp, 96  /* X3 = F - 2D */
    FE3   fe_mul, sp, 224, x20, 32, x20, 64 /* yz = Y1*Z1 (before r is written) */
    FE3   fe_add, x19, 64, sp, 224, sp, 224 /* Z3 = 2*Y1*Z1 */
    FE3   fe_sub, sp, 320, sp, 96, sp, 192  /* dx = D - X3 */
    FE3   fe_mul, sp, 288, sp, 128, sp, 320 /* edt = E*(D - X3) */
    FE3   fe_add, sp, 256, sp, 64, sp, 64
    FE3   fe_add, sp, 256, sp, 256, sp, 256
    FE3   fe_add, sp, 256, sp, 256, sp, 256 /* 8C */
    FE3   fe_sub, sp, 352, sp, 288, sp, 256 /* Y3 = E*(D - X3) - 8C */
    CP32  x19, 0,  sp, 192               /* X3 */
    CP32  x19, 32, sp, 352               /* Y3 */
    add   sp, sp, #384
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* ============================================================================
 * point_add_mixed(r=x0, p=x1, xy=x2) / point_add_mixed_zr(..., zr=x3)
 * slots: Z1Z1 0, U2 32, S2 64, V 96, H 128, Rr 160, HH 192, HHH 224, w 256,
 *        t 288, y1hhh 320   (frame 352)
 * r x19, p x20, xy x21, zr x22 (0 = none)
 * ========================================================================== */
    .p2align 2
    .globl _point_add_mixed
_point_add_mixed:
    mov   x3, #0
    /* fall through */
    .globl _point_add_mixed_zr
_point_add_mixed_zr:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #352
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   x22, x3
    ISZERO x20, 64
    b.ne  Lam_finite
    CP64  x19, 0, x21, 0                  /* p infinite: r = (xy, 1) */
    SETONE x19, 64
    cbz   x22, Lam_done
    SETONE x22, 0                         /* zr = 1 */
    b     Lam_done
Lam_finite:
    FE2   fe_sqr, sp, 0,   x20, 64        /* Z1Z1 */
    FE3   fe_mul, sp, 32,  x21, 0,  sp, 0     /* U2 = X2*Z1Z1 */
    FE3   fe_mul, sp, 256, x20, 64, sp, 0     /* w = Z1*Z1Z1 */
    FE3   fe_mul, sp, 64,  x21, 32, sp, 256   /* S2 = Y2*w */
    FEEQ  sp, 32, x20, 0
    b.ne  Lam_distinct
    FEEQ  sp, 64, x20, 32
    b.ne  Lam_opposite
    cbz   x22, 1f
    FE3   fe_add, x22, 0, x20, 32, x20, 32    /* zr = 2*Y1, before the double */
1:  mov   x0, x19
    mov   x1, x20
    bl    _point_double
    b     Lam_done
Lam_opposite:
    SETINF x19, 0
    cbz   x22, Lam_done
    stp   xzr, xzr, [x22]
    stp   xzr, xzr, [x22, #16]            /* zr = 0 */
    b     Lam_done
Lam_distinct:
    FE3   fe_sub, sp, 128, sp, 32, x20, 0     /* H = U2 - X1 */
    FE3   fe_sub, sp, 160, sp, 64, x20, 32    /* Rr = S2 - Y1 */
    FE2   fe_sqr, sp, 192, sp, 128            /* HH */
    FE3   fe_mul, sp, 224, sp, 128, sp, 192   /* HHH = H*HH */
    FE3   fe_mul, sp, 96,  x20, 0,  sp, 192   /* V = X1*HH */
    FE2   fe_sqr, sp, 288, sp, 160            /* t = Rr^2 */
    FE3   fe_sub, sp, 288, sp, 288, sp, 96
    FE3   fe_sub, sp, 288, sp, 288, sp, 96
    FE3   fe_sub, sp, 288, sp, 288, sp, 224   /* X3 = Rr^2 - 2V - HHH */
    CP32  x19, 0, sp, 288                     /* X3 out (before the Y3 reads) */
    FE3   fe_sub, sp, 288, sp, 96,  x19, 0    /* t = V - X3 */
    FE3   fe_mul, sp, 288, sp, 160, sp, 288   /* t = Rr*(V - X3) */
    FE3   fe_mul, sp, 320, x20, 32, sp, 224   /* Y1*HHH */
    FE3   fe_sub, sp, 288, sp, 288, sp, 320   /* Y3 */
    CP32  x19, 32, sp, 288
    FE3   fe_mul, x19, 64, x20, 64, sp, 128   /* Z3 = Z1*H */
    cbz   x22, Lam_done
    CP32  x22, 0, sp, 128                     /* zr = H */
Lam_done:
    add   sp, sp, #352
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* ============================================================================
 * point_add(r=x0, p=x1, q=x2)
 * slots: Z1Z1 0, Z22 32, U1 64, U2 96, S1 128, S2 160, H 192, Rr 224, HH 256,
 *        HHH 288, V 320, w 352, t 384, y3 416, x3 448, s1hhh 480  (frame 512)
 * r x19, p x20, q x21
 * ========================================================================== */
    .p2align 2
    .globl _point_add
_point_add:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #512
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    ISZERO x20, 64
    b.ne  1f
    CP96  x19, 0, x21, 0                  /* p infinite: r = q */
    b     Lpa_done
1:  ISZERO x21, 64
    b.ne  2f
    CP96  x19, 0, x20, 0                  /* q infinite: r = p */
    b     Lpa_done
2:  FE2   fe_sqr, sp, 0,   x20, 64        /* Z1Z1 */
    FE2   fe_sqr, sp, 32,  x21, 64        /* Z22 */
    FE3   fe_mul, sp, 64,  x20, 0,  sp, 32    /* U1 = X1*Z22 */
    FE3   fe_mul, sp, 96,  x21, 0,  sp, 0     /* U2 = X2*Z1Z1 */
    FE3   fe_mul, sp, 352, x21, 64, sp, 32    /* w = Z2*Z22 */
    FE3   fe_mul, sp, 128, x20, 32, sp, 352   /* S1 = Y1*w */
    FE3   fe_mul, sp, 352, x20, 64, sp, 0     /* w = Z1*Z1Z1 */
    FE3   fe_mul, sp, 160, x21, 32, sp, 352   /* S2 = Y2*w */
    FEEQ  sp, 64, sp, 96
    b.ne  Lpa_distinct
    FEEQ  sp, 128, sp, 160
    b.ne  Lpa_inf
    mov   x0, x19
    mov   x1, x20
    bl    _point_double
    b     Lpa_done
Lpa_inf:
    SETINF x19, 0
    b     Lpa_done
Lpa_distinct:
    FE3   fe_sub, sp, 192, sp, 96,  sp, 64    /* H = U2 - U1 */
    FE3   fe_sub, sp, 224, sp, 160, sp, 128   /* Rr = S2 - S1 */
    FE2   fe_sqr, sp, 256, sp, 192            /* HH */
    FE3   fe_mul, sp, 288, sp, 192, sp, 256   /* HHH */
    FE3   fe_mul, sp, 320, sp, 64,  sp, 256   /* V = U1*HH */
    FE2   fe_sqr, sp, 384, sp, 224            /* t = Rr^2 */
    FE3   fe_sub, sp, 384, sp, 384, sp, 320
    FE3   fe_sub, sp, 384, sp, 384, sp, 320
    FE3   fe_sub, sp, 384, sp, 384, sp, 288
    CP32  sp, 448, sp, 384                    /* x3 */
    FE3   fe_sub, sp, 384, sp, 320, sp, 448   /* t = V - X3 */
    FE3   fe_mul, sp, 384, sp, 224, sp, 384   /* t = Rr*t */
    FE3   fe_mul, sp, 480, sp, 128, sp, 288   /* S1*HHH */
    FE3   fe_sub, sp, 416, sp, 384, sp, 480   /* y3 */
    FE3   fe_mul, sp, 352, x20, 64, x21, 64   /* w = Z1*Z2 */
    FE3   fe_mul, x19, 64, sp, 352, sp, 192   /* Z3 = w*H */
    CP32  x19, 0,  sp, 448
    CP32  x19, 32, sp, 416
Lpa_done:
    add   sp, sp, #512
    ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* ============================================================================
 * point_scalar_mul(r=x0, xy=x1, k=x2): w = 4 window, variable-time
 * frame: kb 0 (32), TAB 32 (15 x 96 = 1440)  -> 1472
 * r x19, xy x20, window index x21, digit x22
 * ========================================================================== */
#define PSM_KB  0
#define PSM_TAB 32
    .p2align 2
    .globl _point_scalar_mul
_point_scalar_mul:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #1472
    mov   x19, x0
    mov   x20, x1
    CP32  sp, PSM_KB, x2, 0
    ISZERO sp, PSM_KB
    b.ne  1f
    SETINF x19, 0
    b     Lpsm_done
1:  /* msb of kb: the highest non-zero limb, 63 - clz */
    mov   x21, #3
2:  ldr   x9, [sp, x21, lsl #3]
    cbnz  x9, 3f
    sub   x21, x21, #1
    b     2b
3:  clz   x9, x9
    mov   x10, #63
    sub   x9, x10, x9
    add   x21, x9, x21, lsl #6        /* msb */
    lsr   x21, x21, #2                /* top window */
    /* TAB[1] = (xy, Z = 1) */
    CP64  sp, PSM_TAB, x20, 0
    SETONE sp, PSM_TAB + 64
    /* TAB[i] = TAB[i-1] + xy, i = 2..15 */
    mov   x22, #1
4:  mov   x9, #96
    mul   x9, x22, x9
    add   x0, sp, #PSM_TAB
    add   x0, x0, x9                  /* &TAB[i] (index i-1 = x22) */
    sub   x1, x0, #96                 /* &TAB[i-1] */
    mov   x2, x20
    bl    _point_add_mixed
    add   x22, x22, #1
    cmp   x22, #15
    b.lo  4b
    /* R = TAB[top digit] */
    NIBBLE x22, x21, PSM_KB
    sub   x22, x22, #1
    mov   x9, #96
    mul   x9, x22, x9
    add   x10, sp, #PSM_TAB
    add   x10, x10, x9
    CP96  x19, 0, x10, 0
    /* remaining windows */
5:  subs  x21, x21, #1
    b.mi  Lpsm_done
    mov   x0, x19
    mov   x1, x19
    bl    _point_double
    mov   x0, x19
    mov   x1, x19
    bl    _point_double
    mov   x0, x19
    mov   x1, x19
    bl    _point_double
    mov   x0, x19
    mov   x1, x19
    bl    _point_double
    NIBBLE x22, x21, PSM_KB
    cbz   x22, 5b
    sub   x22, x22, #1
    mov   x9, #96
    mul   x9, x22, x9
    add   x2, sp, #PSM_TAB
    add   x2, x2, x9
    mov   x0, x19
    mov   x1, x19
    bl    _point_add
    b     5b
Lpsm_done:
    add   sp, sp, #1472
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* ============================================================================
 * point_scalar_mul_fixed(r=x0, k=x1): k*G over the w = 4 comb table
 * frame: kb 0 (32), R 32 (96)  -> 128
 * r x19, j x20, started x21, table base x22
 * ========================================================================== */
    .p2align 2
    .globl _point_scalar_mul_fixed
_point_scalar_mul_fixed:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #128
    mov   x19, x0
    CP32  sp, 0, x1, 0
    SETINF sp, 32
    mov   x21, #0
    adrp  x22, _g_comb_table_data@PAGE
    add   x22, x22, _g_comb_table_data@PAGEOFF
    mov   x20, #0
1:  NIBBLE x9, x20, 0
    cbz   x9, 3f
    /* entry = table + ((j*15) + (d-1)) * 64 */
    sub   x9, x9, #1
    mov   x10, #15
    madd  x9, x20, x10, x9
    add   x1, x22, x9, lsl #6
    cbnz  x21, 2f
    CP64  sp, 32, x1, 0                   /* first digit: R = (entry, 1) */
    SETONE sp, 96
    mov   x21, #1
    b     3f
2:  mov   x2, x1
    add   x0, sp, #32
    add   x1, sp, #32
    bl    _point_add_mixed
3:  add   x20, x20, #1
    cmp   x20, #64
    b.lo  1b
    cbnz  x21, 4f
    SETINF sp, 32
4:  CP96  x19, 0, sp, 32
    add   sp, sp, #128
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* ============================================================================
 * point_scalar_mul_glv(r=x0, xy=x1, k=x2): GLV + width-5 wNAF, variable-time
 * frame (sp-relative):
 *   K 0, R1 32, R2 64, W1 96 (144), W2 240 (144), AI 384 (96), D 480 (96),
 *   TABX 576 (256), TABY 832 (256), AUX 1088 (256), ZR 1344 (256),
 *   ZS 1600, TMP 1632, ZG 1664, AFF 1696 (64), T 1760, Z 1792   -> 1824
 * r x19, xy x20, bits/i x21, stream x22, j x23, d x24
 * ========================================================================== */
#define G_K    0
#define G_R1   32
#define G_R2   64
#define G_W1   96
#define G_W2   240
#define G_AI   384
#define G_D    480
#define G_TX   576
#define G_TY   832
#define G_AUX  1088
#define G_ZR   1344
#define G_ZS   1600
#define G_TMP  1632
#define G_ZG   1664
#define G_AFF  1696
#define G_T    1760
#define G_Z    1792
#define G_SIZE 1824
    .p2align 2
    .globl _point_scalar_mul_glv
_point_scalar_mul_glv:
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    mov   x29, sp
    sub   sp, sp, #G_SIZE
    mov   x19, x0
    mov   x20, x1
    CP32  sp, G_K, x2, 0
    ISZERO sp, G_K
    b.ne  1f
    SETINF x19, 0
    b     Lglv_done
1:  add   x0, sp, #G_R1
    add   x1, sp, #G_R2
    add   x2, sp, #G_K
    bl    _sc_split_lambda
    cbz   w0, Lglv_fallback
    add   x0, sp, #G_W1
    add   x1, sp, #G_R1
    bl    _glv_wnaf
    tbnz  w0, #31, Lglv_fallback
    sxtw  x21, w0                         /* b1 */
    add   x0, sp, #G_W2
    add   x1, sp, #G_R2
    bl    _glv_wnaf
    tbnz  w0, #31, Lglv_fallback
    sxtw  x9, w0                          /* b2 */
    cmp   x9, x21
    csel  x21, x9, x21, gt                /* bits = max(b1, b2) */
    cbnz  x21, 2f
    SETINF x19, 0
    b     Lglv_done

    /* ---- 3a. odd-multiples table on the isomorphic curve ---- */
2:  CP64  sp, G_AI, x20, 0
    SETONE sp, G_AI + 64
    add   x0, sp, #G_D
    add   x1, sp, #G_AI
    bl    _point_double                   /* D = 2Q */
    FE2   fe_sqr, sp, G_ZS, sp, G_D + 64          /* C^2 */
    FE3   fe_mul, sp, G_TX, x20, 0, sp, G_ZS      /* TABX[0] = Qx*C^2 */
    FE3   fe_mul, sp, G_TMP, sp, G_ZS, sp, G_D + 64   /* C^3 */
    FE3   fe_mul, sp, G_TY, x20, 32, sp, G_TMP    /* TABY[0] = Qy*C^3 */
    CP32  sp, G_AI, sp, G_TX
    CP32  sp, G_AI + 32, sp, G_TY
    SETONE sp, G_AI + 64
    CP32  sp, G_ZR, sp, G_D + 64                  /* ZR[0] = C */
    mov   x23, #1
3:  add   x0, sp, #G_AI
    add   x1, sp, #G_AI
    add   x2, sp, #G_D
    add   x3, sp, #G_ZR
    add   x3, x3, x23, lsl #5                     /* &ZR[i] */
    bl    _point_add_mixed_zr                     /* AI += 2Q */
    add   x9, sp, #G_TX
    add   x9, x9, x23, lsl #5
    CP32  x9, 0, sp, G_AI
    add   x9, sp, #G_TY
    add   x9, x9, x23, lsl #5
    CP32  x9, 0, sp, G_AI + 32
    add   x23, x23, #1
    cmp   x23, #8
    b.lo  3b
    FE3   fe_mul, sp, G_ZG, sp, G_AI + 64, sp, G_D + 64   /* ZG = AI.z * C */

    /* ---- 3b. globalz: TAB[j] *= zs^(2,3), zs = ZR[j+1]*...*ZR[7], j = 6..0 ---- */
    CP32  sp, G_ZS, sp, G_ZR + 7*32
    mov   x23, #6
4:  cmp   x23, #6
    b.eq  5f
    add   x2, sp, #G_ZR
    add   x2, x2, x23, lsl #5
    add   x2, x2, #32                             /* &ZR[j+1] */
    add   x0, sp, #G_T
    add   x1, sp, #G_ZS
    bl    _fe_mul
    CP32  sp, G_ZS, sp, G_T
5:  FE2   fe_sqr, sp, G_TMP, sp, G_ZS             /* zs^2 */
    add   x0, sp, #G_TX
    add   x0, x0, x23, lsl #5
    mov   x1, x0
    add   x2, sp, #G_TMP
    bl    _fe_mul                                 /* x *= zs^2 */
    FE3   fe_mul, sp, G_TMP, sp, G_TMP, sp, G_ZS  /* zs^3 */
    add   x0, sp, #G_TY
    add   x0, x0, x23, lsl #5
    mov   x1, x0
    add   x2, sp, #G_TMP
    bl    _fe_mul                                 /* y *= zs^3 */
    subs  x23, x23, #1
    b.pl  4b

    /* ---- 3c. AUX[i] = TABX[i] * beta ---- */
    mov   x23, #0
6:  add   x0, sp, #G_AUX
    add   x0, x0, x23, lsl #5
    add   x1, sp, #G_TX
    add   x1, x1, x23, lsl #5
    adrp  x2, Lbeta@PAGE
    add   x2, x2, Lbeta@PAGEOFF
    bl    _fe_mul
    add   x23, x23, #1
    cmp   x23, #8
    b.lo  6b

    /* ---- 4. ladder ---- */
    SETINF x19, 0
7:  subs  x21, x21, #1
    b.mi  Lglv_finish
    mov   x0, x19
    mov   x1, x19
    bl    _point_double
    mov   x22, #0                                 /* stream */
8:  add   x9, sp, #G_W1
    mov   x10, #(G_W2 - G_W1)
    madd  x9, x22, x10, x9
    ldrsb x24, [x9, x21]                          /* d */
    cbz   x24, 10f
    cmp   x24, #0
    cneg  x9, x24, lt                             /* |d| */
    sub   x9, x9, #1
    lsr   x9, x9, #1                              /* idx */
    lsl   x9, x9, #5
    add   x10, sp, #G_TX
    add   x11, sp, #G_AUX
    cmp   x22, #0
    csel  x10, x10, x11, eq
    add   x10, x10, x9
    CP32  sp, G_AFF, x10, 0                       /* x: TABX or AUX */
    add   x10, sp, #G_TY
    add   x10, x10, x9
    tbnz  x24, #63, 9f
    CP32  sp, G_AFF + 32, x10, 0                  /* y */
    b     11f
9:  add   x0, sp, #G_AFF + 32
    adrp  x1, Lfezero@PAGE
    add   x1, x1, Lfezero@PAGEOFF
    mov   x2, x10
    bl    _fe_sub                                 /* y = 0 - y */
11: mov   x0, x19
    mov   x1, x19
    add   x2, sp, #G_AFF
    bl    _point_add_mixed
10: add   x22, x22, #1
    cmp   x22, #2
    b.lo  8b
    b     7b

Lglv_finish:                                      /* 5. leave the isomorphic curve */
    FE3   fe_mul, sp, G_Z, x19, 64, sp, G_ZG
    CP32  x19, 64, sp, G_Z
    b     Lglv_done
Lglv_fallback:
    mov   x0, x19
    mov   x1, x20
    add   x2, sp, #G_K
    bl    _point_scalar_mul
Lglv_done:
    add   sp, sp, #G_SIZE
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

    .section __TEXT,__const
    .p2align 4
Lbeta:
    .quad 0xC1396C28719501EE, 0x9CF0497512F58995, 0x6E64479EAC3434E9, 0x7AE96A2B657C0710
Lfezero:
    .quad 0, 0, 0, 0
