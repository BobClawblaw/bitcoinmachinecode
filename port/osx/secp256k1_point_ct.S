/* ============================================================================
 * secp256k1_point_ct.S -- CONSTANT-TIME scalar multiplication for the secret
 * scalar paths (signing), in AArch64 assembly: the counterpart of
 * asm/secp256k1_point_ct.asm. Replaces point_ct_twin.c on the Mac
 * (2026-09-26); the twin stays in port/osx/test_support as the oracle.
 *
 *   void pointh_add(u64 r[12], const u64 p[12], const u64 q[12]);
 *   void pointh_double(u64 r[12], const u64 p[12]);
 *   void point_scalar_mul_ct(u64 r[12], const u64 xy[8], const u64 k[4]);
 *   void point_scalar_mul_gen_ct(u64 r[12], const u64 k[4]);              k*G
 *   void point_scalar_mul_win_ct(u64 r[12], const u64 xy[8], const u64 k[4]);
 *   void point_scalar_mul_glv_ct(u64 r[12], const u64 xy[8], const u64 k[4]);  k < n
 *   void point_ct_force_scan(int p);        x86's AVX2/cmov scan knob: a no-op
 *
 * The three routines after the ladder are x86 main #330/#334's (2026-09-28),
 * ported the same day: the ladder costs 256 complete doubles + 256 complete
 * adds; the comb reads a column of G_COMB_TABLE per nibble of k with every
 * entry loaded and the wanted one kept by csel (64 adds, no doubling); the
 * window builds a 16-entry table of P and walks the 64 nibbles from the top
 * (256 doubles + 64 adds); the GLV routine splits k = r1 + lambda*r2 by
 * sc_split_lambda, folds each sign into its point (y -> p - y by csel), and
 * walks 33 nibbles over two tables (132 doubles + 66 adds). In all three
 * the digit only ever reaches a cmp, never an address; the loads are the
 * same for every scalar. x86 has an AVX2 blend scan beside the cmov scan;
 * the Mac has the one csel scan, and point_ct_force_scan accepts the knob.
 * Proof: tests/test_pointmul_ct_variants (main's), against the ladder and
 * point_scalar_mul; the ladder itself is unchanged.
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

/* ============================================================================
 * The 2026-09-28 routines. Shared pieces first.
 * ========================================================================== */
/* [b+o] = the identity (0 : 1 : 0) */
.macro SETID b, o
    add   x13, \b, #\o
    mov   x9, #1
    stp   xzr, xzr, [x13]
    stp   xzr, xzr, [x13, #16]
    stp   x9, xzr, [x13, #32]
    stp   xzr, xzr, [x13, #48]
    stp   xzr, xzr, [x13, #64]
    stp   xzr, xzr, [x13, #80]
.endm
/* dst = nibble n of the scalar at [sp + k]: the address depends on n only */
.macro NIBBLE dst, n, k
    lsl   x9, \n, #2
    lsr   x10, x9, #6
    add   x10, sp, x10, lsl #3
    ldr   x10, [x10, #\k]
    and   x9, x9, #63
    lsr   x10, x10, x9
    and   \dst, x10, #15
.endm
/* T at [sp + t] = entry \dig (a register) of the 16-entry, 96-byte table at
 * [sp + tb]: every entry is read; the digit meets only the cmp. x23, x24 */
.macro SCAN96 t, tb, dig
    add   x24, sp, #\tb
    mov   x23, #0
6:  cmp   x23, \dig
    .irp off, 0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88
    ldr   x9, [x24, #\off]
    ldr   x10, [sp, #\t + \off]
    csel  x10, x9, x10, eq
    str   x10, [sp, #\t + \off]
    .endr
    add   x24, x24, #96
    add   x23, x23, #1
    cmp   x23, #16
    b.lo  6b
.endm
/* the 16-entry table at [sp + tb] from the affine point at [sp + aff]:
 * TB[0] = identity, TB[1] = (x : y : 1), TB[i] = TB[i-1] + TB[1]. x23 */
.macro TABLE16 tb, aff
    SETID sp, \tb
    CP64  sp, \tb + 96, sp, \aff
    SETONE sp, \tb + 160
    mov   x23, #2
5:  mov   x9, #96
    mul   x9, x23, x9
    add   x0, sp, #\tb
    add   x0, x0, x9                      /* TB[i] */
    sub   x1, x0, #96                     /* TB[i-1] */
    add   x2, sp, #\tb + 96               /* TB[1] */
    bl    _pointh_add
    add   x23, x23, #1
    cmp   x23, #16
    b.lo  5b
.endm
.macro CP64 db, do, sb, so
    CP32  \db, \do, \sb, \so
    CP32  \db, \do + 32, \sb, \so + 32
.endm
.macro SETONE b, o
    add   x13, \b, #\o
    mov   x9, #1
    stp   x9, xzr, [x13]
    stp   xzr, xzr, [x13, #16]
.endm

/* ---------------------------------------------------------------------------
 * pointh_to_jac(out=x0, R=x1): homogeneous (X:Y:Z) -> Jacobian (X*Z, Y*Z^2, Z);
 * Z == 0 yields the canonical infinity (1, 1, 0) by csel. The ladder's tail
 * as a function. frame: T 0 (96)
 * ------------------------------------------------------------------------- */
    .p2align 2
    .globl _pointh_to_jac
_pointh_to_jac:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #96
    mov   x19, x0
    mov   x20, x1
    FE2   fe_sqr, sp, 0, x20, 64                 /* Z^2 */
    FE3   fe_mul, sp, 32, x20, 32, sp, 0         /* Y*Z^2 */
    FE3   fe_mul, sp, 64, x20, 0, x20, 64        /* X*Z */
    ldp   x9, x10, [x20, #64]
    ldp   x11, x12, [x20, #80]
    orr   x9, x9, x10
    orr   x11, x11, x12
    orr   x9, x9, x11
    cmp   x9, #0                          /* Z = (Z == 0): infinity */
    mov   x13, #1
    ldp   x9, x10, [sp, #64]
    ldp   x11, x12, [sp, #80]
    csel  x9, x13, x9, eq
    csel  x10, xzr, x10, eq
    csel  x11, xzr, x11, eq
    csel  x12, xzr, x12, eq
    stp   x9, x10, [x19]
    stp   x11, x12, [x19, #16]
    ldp   x9, x10, [sp, #32]
    ldp   x11, x12, [sp, #48]
    csel  x9, x13, x9, eq
    csel  x10, xzr, x10, eq
    csel  x11, xzr, x11, eq
    csel  x12, xzr, x12, eq
    stp   x9, x10, [x19, #32]
    stp   x11, x12, [x19, #48]
    CP32  x19, 64, x20, 64
    add   sp, sp, #96
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* ---------------------------------------------------------------------------
 * point_scalar_mul_gen_ct(out=x0, k=x1): k*G by the w=4 comb table
 * (g_comb_table_data: T[j][i] = i * 2^(4j) * G, affine, 64-byte entries,
 * column j at j*960). R = identity; for j = 0..63: T = the column's entry for
 * digit j (the identity for 0: what nothing selects); R = R + T. k as given
 * (k >= n wraps like the ladder).
 * frame: kb 0 (32), R 32 (96), T 128 (96) -> 224. x19 out, x20 j, x21 entry,
 * x22 digit, x23 i
 * ------------------------------------------------------------------------- */
    .p2align 2
    .globl _point_scalar_mul_gen_ct
_point_scalar_mul_gen_ct:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    str   x23, [sp, #-16]!
    mov   x29, sp
    sub   sp, sp, #224
    mov   x19, x0
    CP32  sp, 0, x1, 0
    SETID sp, 32
    mov   x20, #0
1:  NIBBLE x22, x20, 0
    SETID sp, 128
    adrp  x21, _g_comb_table_data@PAGE
    add   x21, x21, _g_comb_table_data@PAGEOFF
    mov   x9, #960
    madd  x21, x20, x9, x21               /* column j */
    mov   x23, #1
2:  cmp   x23, x22                        /* eq: this entry is the digit's */
    .irp off, 0, 8, 16, 24, 32, 40, 48, 56
    ldr   x9, [x21, #\off]
    ldr   x10, [sp, #128 + \off]
    csel  x10, x9, x10, eq
    str   x10, [sp, #128 + \off]
    .endr
    ldr   x10, [sp, #192]
    mov   x11, #1
    csel  x10, x11, x10, eq               /* Z = 1 for a selected affine entry */
    str   x10, [sp, #192]
    add   x21, x21, #64
    add   x23, x23, #1
    cmp   x23, #16
    b.lo  2b
    add   x0, sp, #32
    add   x1, sp, #32
    add   x2, sp, #128
    bl    _pointh_add                     /* R = R + T, always */
    add   x20, x20, #1
    cmp   x20, #64
    b.lo  1b
    mov   x0, x19
    add   x1, sp, #32
    bl    _pointh_to_jac
    add   sp, sp, #224
    ldr   x23, [sp], #16
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* ---------------------------------------------------------------------------
 * point_scalar_mul_win_ct(out=x0, xy=x1, k=x2): k*P, fixed window w=4.
 * frame: kb 0 (32), aff 32 (64), R 96 (96), T 192 (96), TB 288 (1536)
 * -> 1824. x19 out, x20 j, x22 digit, x23/x24 the scan
 * ------------------------------------------------------------------------- */
    .p2align 2
    .globl _point_scalar_mul_win_ct
_point_scalar_mul_win_ct:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #-16]!
    mov   x29, sp
    sub   sp, sp, #1824
    mov   x19, x0
    CP32  sp, 0, x2, 0
    CP64  sp, 32, x1, 0
    TABLE16 288, 32
    SETID sp, 96
    mov   x20, #63
1:  .rept 4
    add   x0, sp, #96
    add   x1, sp, #96
    bl    _pointh_double
    .endr
    NIBBLE x22, x20, 0
    SCAN96 192, 288, x22
    add   x0, sp, #96
    add   x1, sp, #96
    add   x2, sp, #192
    bl    _pointh_add                     /* R = R + T, always */
    subs  x20, x20, #1
    b.pl  1b
    mov   x0, x19
    add   x1, sp, #96
    bl    _pointh_to_jac
    add   sp, sp, #1824
    ldp   x23, x24, [sp], #16
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* ---------------------------------------------------------------------------
 * point_scalar_mul_glv_ct(out=x0, xy=x1, k=x2): k*P, k < n (every caller
 * range-checks its secret key), the GLV endomorphism halving the doublings.
 * k = r1 + lambda*r2 by sc_split_lambda; a scalar whose bit 255 is set is a
 * negation mod n: it is replaced by n - r and the sign goes into its point
 * (y -> p - y), both by csel. Base 2 is lambda*P = (beta*x, y). Then 33
 * nibbles: 4 doubles, scan TB1, add, scan TB2, add. If the split's identity
 * check ever failed (a defect, never a value) the window above answers.
 * frame: r1 0 (32), r2 32 (32), R 64 (96), T 160 (96), P1 256 (64),
 * P2 320 (64), t 384 (32), TB1 416 (1536), TB2 1952 (1536) -> 3488.
 * x19 out, x20 xy, x21 k, x22 digit / j, x25 the sign mask, x26 j
 * ------------------------------------------------------------------------- */
/* r at [sp + r] := mask ? [sp + t] : r ; the point's y at [sp + py] :=
 * mask ? [sp + t2] : y (x25 = the mask, 0 or -1) */
.macro SEL32 dst, a, b
    cmp   x25, #0
    .irp off, 0, 8, 16, 24
    ldr   x9, [sp, #\a + \off]
    ldr   x10, [sp, #\b + \off]
    csel  x9, x10, x9, ne
    str   x9, [sp, #\dst + \off]
    .endr
.endm
    .p2align 2
    .globl _point_scalar_mul_glv_ct
_point_scalar_mul_glv_ct:
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #-16]!
    mov   x29, sp
    sub   sp, sp, #3488
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    add   x0, sp, #0
    add   x1, sp, #32
    mov   x2, x21
    bl    _sc_split_lambda
    cbz   w0, 9f
    /* r1 and P1 */
    ldr   x25, [sp, #24]
    asr   x25, x25, #63                   /* the sign of r1 */
    add   x0, sp, #384
    adrp  x1, Lct_n@PAGE
    add   x1, x1, Lct_n@PAGEOFF
    add   x2, sp, #0
    bl    _sc_sub                         /* t = n - r1 */
    SEL32 0, 0, 384                       /* r1 = mask ? n - r1 : r1 */
    CP32  sp, 256, x20, 0                 /* P1.x = x */
    add   x0, sp, #384
    adrp  x1, Lct_zero@PAGE
    add   x1, x1, Lct_zero@PAGEOFF
    add   x2, x20, #32
    bl    _fe_sub                         /* t = -y */
    CP32  sp, 288, x20, 32                /* P1.y = y ... */
    SEL32 288, 288, 384                   /* ... or -y */
    /* r2 and P2 = +-lambda*P */
    ldr   x25, [sp, #56]
    asr   x25, x25, #63
    add   x0, sp, #384
    adrp  x1, Lct_n@PAGE
    add   x1, x1, Lct_n@PAGEOFF
    add   x2, sp, #32
    bl    _sc_sub
    SEL32 32, 32, 384
    add   x0, sp, #320
    adrp  x1, Lct_beta@PAGE
    add   x1, x1, Lct_beta@PAGEOFF
    mov   x2, x20
    bl    _fe_mul                         /* P2.x = beta * x */
    add   x0, sp, #384
    adrp  x1, Lct_zero@PAGE
    add   x1, x1, Lct_zero@PAGEOFF
    add   x2, x20, #32
    bl    _fe_sub
    CP32  sp, 352, x20, 32
    SEL32 352, 352, 384
    TABLE16 416, 256
    TABLE16 1952, 320
    SETID sp, 64
    mov   x26, #32                        /* nibble 32 downto 0 */
1:  .rept 4
    add   x0, sp, #64
    add   x1, sp, #64
    bl    _pointh_double
    .endr
    NIBBLE x22, x26, 0
    SCAN96 160, 416, x22
    add   x0, sp, #64
    add   x1, sp, #64
    add   x2, sp, #160
    bl    _pointh_add
    NIBBLE x22, x26, 32
    SCAN96 160, 1952, x22
    add   x0, sp, #64
    add   x1, sp, #64
    add   x2, sp, #160
    bl    _pointh_add
    subs  x26, x26, #1
    b.pl  1b
    mov   x0, x19
    add   x1, sp, #64
    bl    _pointh_to_jac
    b     8f
9:  mov   x0, x19                         /* the split failed its identity check */
    mov   x1, x20
    mov   x2, x21
    bl    _point_scalar_mul_win_ct
8:  stp   xzr, xzr, [sp, #0]              /* the split scalars held a secret */
    stp   xzr, xzr, [sp, #16]
    stp   xzr, xzr, [sp, #32]
    stp   xzr, xzr, [sp, #48]
    add   sp, sp, #3488
    ldp   x25, x26, [sp], #16
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

/* point_ct_force_scan(p): x86's AVX2-or-cmov scan selection; the Mac has one
 * scan, so the knob is accepted and ignored. */
    .p2align 2
    .globl _point_ct_force_scan
_point_ct_force_scan:
    ret

    .section __TEXT,__const
    .p2align 4
Lb3:
    .quad 21, 0, 0, 0
Lct_n:
    .quad 0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF
Lct_beta:
    .quad 0xC1396C28719501EE, 0x9CF0497512F58995, 0x6E64479EAC3434E9, 0x7AE96A2B657C0710
Lct_zero:
    .quad 0, 0, 0, 0
