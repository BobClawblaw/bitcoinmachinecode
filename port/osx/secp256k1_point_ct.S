/* ============================================================================
 * secp256k1_point_ct.S -- CONSTANT-TIME scalar multiplication for the secret
 * scalar paths (signing), in AArch64 assembly: the counterpart of
 * asm/secp256k1_point_ct.asm. Replaces point_ct_twin.c on the Mac
 * (2026-09-26); the twin stays in port/osx/test_support as the oracle.
 *
 *   void pointh_add(u64 r[12], const u64 p[12], const u64 q[12]);
 *   void pointh_double(u64 r[12], const u64 p[12]);
 *   void point_scalar_mul_ct(u64 r[12], const u64 xy[8], const u64 k[4]);
 *
 * pointh_* are the Renes-Costello-Batina complete formulas (eprint 2015/1060,
 * Alg. 7 and 9) in HOMOGENEOUS coordinates, a = 0, b3 = 21: exception-free by
 * construction, so nothing to branch on. They read their inputs completely
 * before the final copy-out, so r may alias p and/or q.
 *
 * point_scalar_mul_ct: exactly 256 iterations of double-and-add-always,
 * the add committed or discarded by csel on every limb -- no branch and no
 * address depends on a bit of k. The field ops are branch-free. The result
 * is converted to Jacobian (X*Z, Y*Z^2, Z), infinity canonicalised to
 * (1, 1, 0) by csel. The ladder starts from (0 : 1 : 0), as the x86 does.
 *
 * Every step is point_ct_twin.c's field call, in its order (tests/
 * test_point_repr diffs pointh_add, pointh_double and the ladder limb for
 * limb against the frozen x86 copy).
 * ========================================================================== */
    .text

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
/* fe_mul(dst, B3, src) */
.macro MULB3 db, do, sb, so
    add   x0, \db, #\do
    adrp  x1, Lb3@PAGE
    add   x1, x1, Lb3@PAGEOFF
    add   x2, \sb, #\so
    bl    _fe_mul
.endm
.macro CP32 db, do, sb, so
    add   x13, \sb, #\so
    add   x14, \db, #\do
    ldp   x11, x12, [x13]
    ldp   x15, x16, [x13, #16]
    stp   x11, x12, [x14]
    stp   x15, x16, [x14, #16]
.endm

/* ============================================================================
 * pointh_add(r=x0, p=x1, q=x2)
 * slots: t0 0, t1 32, t2 64, t3 96, t4 128, X3 160, Y3 192, Z3 224, tt 256
 * ========================================================================== */
    .p2align 2
    .globl _pointh_add
_pointh_add:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #288
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    FE3   fe_mul, sp, 0,   x20, 0,  x21, 0      /* 1.  t0 = X1*X2 */
    FE3   fe_mul, sp, 32,  x20, 32, x21, 32     /* 2.  t1 = Y1*Y2 */
    FE3   fe_mul, sp, 64,  x20, 64, x21, 64     /* 3.  t2 = Z1*Z2 */
    FE3   fe_add, sp, 96,  x20, 0,  x20, 32     /* 4.  t3 = X1+Y1 */
    FE3   fe_add, sp, 128, x21, 0,  x21, 32     /* 5.  t4 = X2+Y2 */
    FE3   fe_mul, sp, 96,  sp, 96,  sp, 128     /* 6.  t3 = t3*t4 */
    FE3   fe_sub, sp, 96,  sp, 96,  sp, 0       /* 7.  t3 -= t0 */
    FE3   fe_sub, sp, 96,  sp, 96,  sp, 32      /* 8.  t3 -= t1 */
    FE3   fe_add, sp, 128, x20, 32, x20, 64     /* 9.  t4 = Y1+Z1 */
    FE3   fe_add, sp, 160, x21, 32, x21, 64     /* 10. X3 = Y2+Z2 */
    FE3   fe_mul, sp, 128, sp, 128, sp, 160     /* 11. t4 = t4*X3 */
    FE3   fe_sub, sp, 128, sp, 128, sp, 32      /* 12. t4 -= t1 */
    FE3   fe_sub, sp, 128, sp, 128, sp, 64      /* 13. t4 -= t2 */
    FE3   fe_add, sp, 160, x20, 0,  x20, 64     /* 14. X3 = X1+Z1 */
    FE3   fe_add, sp, 192, x21, 0,  x21, 64     /* 15. Y3 = X2+Z2 */
    FE3   fe_mul, sp, 160, sp, 160, sp, 192     /* 16. X3 = X3*Y3 */
    FE3   fe_sub, sp, 192, sp, 160, sp, 0       /* 17+18. Y3slot = X3 - t0 - t2 */
    FE3   fe_sub, sp, 192, sp, 192, sp, 64
    FE3   fe_add, sp, 256, sp, 0,   sp, 0       /* 19+20. t0 = 3*t0 */
    FE3   fe_add, sp, 0,   sp, 256, sp, 0
    MULB3 sp, 64,  sp, 64                       /* 21. t2 = b3*t2 */
    FE3   fe_add, sp, 224, sp, 32,  sp, 64      /* 22. Z3 = t1+t2 */
    FE3   fe_sub, sp, 32,  sp, 32,  sp, 64      /* 23. t1 = t1-t2 */
    MULB3 sp, 192, sp, 192                      /* 24. Y3 = b3*Y3slot */
    FE3   fe_mul, sp, 160, sp, 128, sp, 192     /* 25. X3 = t4*Y3 */
    FE3   fe_mul, sp, 64,  sp, 96,  sp, 32      /* 26. t2 = t3*t1 */
    FE3   fe_sub, sp, 160, sp, 64,  sp, 160     /* 27. X3 = t2-X3 */
    FE3   fe_mul, sp, 192, sp, 192, sp, 0       /* 28. Y3 = Y3*t0 */
    FE3   fe_mul, sp, 32,  sp, 32,  sp, 224     /* 29. t1 = t1*Z3 */
    FE3   fe_add, sp, 192, sp, 32,  sp, 192     /* 30. Y3 = t1+Y3 */
    FE3   fe_mul, sp, 0,   sp, 0,   sp, 96      /* 31. t0 = t0*t3 */
    FE3   fe_mul, sp, 224, sp, 224, sp, 128     /* 32. Z3 = Z3*t4 */
    FE3   fe_add, sp, 224, sp, 224, sp, 0       /* 33. Z3 = Z3+t0 */
    CP32  x19, 0,  sp, 160
    CP32  x19, 32, sp, 192
    CP32  x19, 64, sp, 224
    add   sp, sp, #288
    ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* ============================================================================
 * pointh_double(r=x0, p=x1)
 * slots: t0 0, t1 32, t2 64, X3 96, Y3 128, Z3 160, tt 192
 * ========================================================================== */
    .p2align 2
    .globl _pointh_double
_pointh_double:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #224
    mov   x19, x0
    mov   x20, x1
    FE2   fe_sqr, sp, 0,   x20, 32              /* 1.  t0 = Y1^2 */
    FE3   fe_add, sp, 160, sp, 0,   sp, 0       /* 2-4. Z3 = 8*t0 */
    FE3   fe_add, sp, 160, sp, 160, sp, 160
    FE3   fe_add, sp, 160, sp, 160, sp, 160
    FE3   fe_mul, sp, 32,  x20, 32, x20, 64     /* 5.  t1 = Y1*Z1 */
    FE2   fe_sqr, sp, 64,  x20, 64              /* 6.  t2 = Z1^2 */
    MULB3 sp, 64,  sp, 64                       /* 7.  t2 = b3*t2 */
    FE3   fe_mul, sp, 96,  sp, 64,  sp, 160     /* 8.  X3 = t2*Z3 */
    FE3   fe_add, sp, 128, sp, 0,   sp, 64      /* 9.  Y3 = t0+t2 */
    FE3   fe_mul, sp, 160, sp, 32,  sp, 160     /* 10. Z3 = t1*Z3 */
    FE3   fe_add, sp, 192, sp, 64,  sp, 64      /* 11+12. t2 = 3*t2 */
    FE3   fe_add, sp, 64,  sp, 192, sp, 64
    FE3   fe_sub, sp, 0,   sp, 0,   sp, 64      /* 13. t0 = t0-t2 */
    FE3   fe_mul, sp, 128, sp, 0,   sp, 128     /* 14. Y3 = t0*Y3 */
    FE3   fe_add, sp, 128, sp, 96,  sp, 128     /* 15. Y3 = X3+Y3 */
    FE3   fe_mul, sp, 32,  x20, 0,  x20, 32     /* 16. t1 = X*Y */
    FE3   fe_mul, sp, 96,  sp, 0,   sp, 32      /* 17. X3 = t0*t1 */
    FE3   fe_add, sp, 96,  sp, 96,  sp, 96      /* 18. X3 = 2*X3 */
    CP32  x19, 0,  sp, 96
    CP32  x19, 32, sp, 128
    CP32  x19, 64, sp, 160
    add   sp, sp, #224
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* ============================================================================
 * point_scalar_mul_ct(r=x0, xy=x1, k=x2)
 * frame: kb 0, base 32 (96), R 128 (96), T 224 (96), Z2 320, yz2 352, xz 384
 * r x19, bit index x20
 * ========================================================================== */
    .p2align 2
    .globl _point_scalar_mul_ct
_point_scalar_mul_ct:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #416
    mov   x19, x0
    CP32  sp, 0,  x2, 0                   /* kb */
    CP32  sp, 32, x1, 0                   /* base = (xy, 1) */
    CP32  sp, 64, x1, 32
    mov   x9, #1
    stp   x9, xzr, [sp, #96]
    stp   xzr, xzr, [sp, #112]
    stp   xzr, xzr, [sp, #128]            /* R = (0 : 1 : 0) */
    stp   xzr, xzr, [sp, #144]
    stp   x9, xzr, [sp, #160]
    stp   xzr, xzr, [sp, #176]
    stp   xzr, xzr, [sp, #192]
    stp   xzr, xzr, [sp, #208]
    mov   x20, #255
1:  add   x0, sp, #128
    add   x1, sp, #128
    bl    _pointh_double                  /* R = 2R */
    add   x0, sp, #224
    add   x1, sp, #128
    add   x2, sp, #32
    bl    _pointh_add                     /* T = R + base (always) */
    lsr   x9, x20, #6
    ldr   x9, [sp, x9, lsl #3]            /* kb[i >> 6]: the address depends on i only */
    and   x10, x20, #63
    lsr   x9, x9, x10
    tst   x9, #1                          /* Z = (bit == 0) */
    add   x13, sp, #224                   /* T */
    add   x14, sp, #128                   /* R */
    mov   x15, #0
2:  ldr   x11, [x13, x15]
    ldr   x12, [x14, x15]
    csel  x11, x12, x11, eq               /* bit 0: keep R; bit 1: take T */
    str   x11, [x14, x15]
    add   x15, x15, #8
    cmp   x15, #96                        /* (resets flags: re-test the bit) */
    b.eq  3f
    tst   x9, #1
    b     2b
3:  subs  x20, x20, #1
    b.pl  1b
    /* homogeneous (X : Y : Z) -> Jacobian (X*Z, Y*Z^2, Z) */
    FE2   fe_sqr, sp, 320, sp, 192               /* Z^2 */
    FE3   fe_mul, sp, 352, sp, 160, sp, 320      /* Y*Z^2 */
    FE3   fe_mul, sp, 384, sp, 128, sp, 192      /* X*Z */
    ldp   x9, x10, [sp, #192]
    ldp   x11, x12, [sp, #208]
    orr   x9, x9, x10
    orr   x11, x11, x12
    orr   x9, x9, x11
    cmp   x9, #0                          /* Z = (Z == 0): infinity */
    mov   x13, #1
    ldp   x9, x10, [sp, #384]
    ldp   x11, x12, [sp, #400]
    csel  x9, x13, x9, eq
    csel  x10, xzr, x10, eq
    csel  x11, xzr, x11, eq
    csel  x12, xzr, x12, eq
    stp   x9, x10, [x19]
    stp   x11, x12, [x19, #16]
    ldp   x9, x10, [sp, #352]
    ldp   x11, x12, [sp, #368]
    csel  x9, x13, x9, eq
    csel  x10, xzr, x10, eq
    csel  x11, xzr, x11, eq
    csel  x12, xzr, x12, eq
    stp   x9, x10, [x19, #32]
    stp   x11, x12, [x19, #48]
    CP32  x19, 64, sp, 192
    add   sp, sp, #416
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

    .section __TEXT,__const
    .p2align 4
Lb3:
    .quad 21, 0, 0, 0
