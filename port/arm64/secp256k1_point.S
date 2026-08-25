/* ============================================================================
 * secp256k1_point.S -- AArch64 (ARMv8-A) port of asm/secp256k1_point.asm
 *
 * Jacobian point arithmetic over secp256k1 (a = 0, curve y^2 = x^3 + 7).
 * Jacobian point = 12 little-endian u64 limbs [X(4) Y(4) Z(4)]; AFFINE point =
 * 8 limbs [x(4) y(4)]. Same conventions as asm/secp256k1_point.asm and the
 * ported secp256k1_fe.S.
 *
 * AAPCS64 (SysV x64 -> AArch64): args x0,x1,x2,x3.
 *   void point_double(u64 r[12], const u64 p[12])          : r = 2*p
 *   void point_add(u64 r[12], const u64 p[12], const u64 q[12]) : r = p+q
 *   void point_add_mixed(u64 r[12], const u64 p[12], const u64 xy[8])
 *                                                          : r = p + affine(xy)
 *   void point_add_mixed_zr(..., u64 zr[4])                : + z-ratio zr = H
 *   void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4])
 *                                                          : r = k*affine(xy)
 *
 * Unlike the x86 original (which inlines field add/sub via FE_* macros for
 * speed), this port CALLS the verified fe_add / fe_sub / fe_mul / fe_sqr
 * primitives of secp256k1_fe.S. All four are AAPCS64 leaves that touch only
 * x0-x18 (never x19+), so every pointer/loop-counter held in x19..x28 here is
 * preserved across a bl. Correctness over speed (PERF_SCOPE can revisit the
 * macro inlining later -- the formulas are the same).
 *
 * Formula sources (matched to the x86 original, which uses the standard
 * add-2007-bl / dbl-2009-l for a=0):
 *   point_double : A=X1^2 B=Y1^2 C=B^2 D=2((X1+B)^2-A-C) E=3A F=E^2
 *                  X3=F-2D Y3=E(D-X3)-8C Z3=2Y1Z1
 *   point_add_mixed (+zr): Z1Z1=Z1^2 U2=X2*Z1Z1 S2=Y2*Z1*Z1Z1 H=U2-X1 R=S2-Y1
 *                  HH=H^2 HHH=H*HH V=X1*HH X3=R^2-HHH-2V Y3=R(V-X3)-Y1*HHH
 *                  Z3=Z1*H ; zr=H
 *   point_add    : full Jacobian-Jacobian analogue (Z1Z1,Z22,U1,U2,S1,S2proj,
 *                  H=R etc.) from secp256k1_gej_add_var; z3=Z1Z2H
 *   point_scalar_mul : w=4 windowed double-and-add (16 R=16R doublings per
 *                  window, table TAB[1..15] = i*base built by point_add_mixed)
 * ========================================================================== */

	.text

	/* \rd = sp + 32*n  (n in 0..11 -> imm up to 384, within 12-bit add) */
	.macro SLOT rd, n
	add  \rd, sp, #(32*(\n))
	.endm

/* ============================================================================
 * point_double(r=x0, p=x1)
 * slots: S0=A S1=B S2=C S3=(X1+B)^2->D S4=E S5=F S6=work S7=8C
 * ========================================================================== */
	.global point_double
	.type   point_double, %function
point_double:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	sub  sp, sp, #256            /* slots S0..S7 */
	mov  x19, x0                 /* r */
	mov  x20, x1                 /* p */

	/* S0 = X1^2 */
	SLOT x0, 0
	mov  x1, x20
	bl   fe_sqr
	/* S1 = Y1^2 */
	SLOT x0, 1
	add  x1, x20, #32
	bl   fe_sqr
	/* S2 = B^2 = C */
	SLOT x0, 2
	SLOT x1, 1
	bl   fe_sqr
	/* S3 = (X1+B) then ^2 */
	SLOT x0, 3
	mov  x1, x20
	SLOT x2, 1
	bl   fe_add
	SLOT x0, 3
	SLOT x1, 3
	bl   fe_sqr
	/* D = 2*((X1+B)^2 - A - C) -> S3 */
	SLOT x0, 3
	SLOT x1, 3
	SLOT x2, 0
	bl   fe_sub                 /* - A */
	SLOT x0, 3
	SLOT x1, 3
	SLOT x2, 2
	bl   fe_sub                 /* - C */
	SLOT x0, 3
	SLOT x1, 3
	SLOT x2, 3
	bl   fe_add                 /* *2 */
	/* E = 3*A -> S4 */
	SLOT x0, 4
	SLOT x1, 0
	SLOT x2, 0
	bl   fe_add                 /* A+A */
	SLOT x0, 4
	SLOT x1, 4
	SLOT x2, 0
	bl   fe_add                 /* 2A+A */
	/* F = E^2 -> S5 */
	SLOT x0, 5
	SLOT x1, 4
	bl   fe_sqr
	/* X3 = F - D - D -> r+0 */
	SLOT x0, 5
	SLOT x1, 5
	SLOT x2, 3
	bl   fe_sub
	SLOT x0, 5
	SLOT x1, 5
	SLOT x2, 3
	bl   fe_sub
	mov  x0, x19
	SLOT x1, 5
	ldp  x2, x3,  [x1]
	ldp  x4, x5,  [x1, #16]
	stp  x2, x3,  [x0]
	stp  x4, x5,  [x0, #16]
	/* S7 = 8*C -> S7 */
	SLOT x0, 7
	SLOT x1, 2
	SLOT x2, 2
	bl   fe_add
	SLOT x0, 7
	SLOT x1, 7
	SLOT x2, 7
	bl   fe_add
	SLOT x0, 7
	SLOT x1, 7
	SLOT x2, 7
	bl   fe_add
	/* S6 = Y1*Z1 -> S6  (reads Y1,Z1 before r+64 write aliases Z1) */
	SLOT x0, 6
	add  x1, x20, #32
	add  x2, x20, #64
	bl   fe_mul
	/* Z3 = 2*S6 -> r+64 */
	SLOT x0, 6
	SLOT x1, 6
	SLOT x2, 6
	bl   fe_add
	mov  x0, x19
	add  x0, x0, #64
	SLOT x1, 6
	ldp  x2, x3,  [x1]
	ldp  x4, x5,  [x1, #16]
	stp  x2, x3,  [x0]
	stp  x4, x5,  [x0, #16]
	/* t = D - X3 -> S6 */
	SLOT x0, 6
	SLOT x1, 3
	mov  x2, x19
	bl   fe_sub
	/* S6 = E * t */
	SLOT x0, 6
	SLOT x1, 4
	SLOT x2, 6
	bl   fe_mul
	/* Y3 = S6 - S7 -> r+32 */
	SLOT x0, 6
	SLOT x1, 6
	SLOT x2, 7
	bl   fe_sub
	mov  x0, x19
	add  x0, x0, #32
	SLOT x1, 6
	ldp  x2, x3,  [x1]
	ldp  x4, x5,  [x1, #16]
	stp  x2, x3,  [x0]
	stp  x4, x5,  [x0, #16]

	add  sp, sp, #256
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size point_double, .-point_double

/* ============================================================================
 * point_add_mixed / point_add_mixed_zr (b shares zr body with x3==0)
 * slots: S0=Z1Z1 S1=U2 S2=V S3=S2y S4=H S5=R S6=HH S7=HHH S8=work S9=Y1*HHH
 * ========================================================================== */
	.global point_add_mixed
	.type   point_add_mixed, %function
point_add_mixed:
	mov  x3, xzr                 /* no z-ratio requested */
	b    point_add_mixed_zr

	.global point_add_mixed_zr
	.type   point_add_mixed_zr, %function
point_add_mixed_zr:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	sub  sp, sp, #320            /* slots S0..S9 */
	mov  x19, x0                 /* r */
	mov  x20, x1                 /* p  (Jacobian) */
	mov  x21, x2                 /* xy (affine)   */
	mov  x22, x3                 /* zr (u64[4] or NULL) */

	/* ---- p == infinity (Z1==0) -> r = (xy, Z=1), zr=1 ---- */
	ldr  x4,  [x20, #64]
	ldr  x5,  [x20, #72]
	orr  x4, x4, x5
	ldr  x5,  [x20, #80]
	orr  x4, x4, x5
	ldr  x5,  [x20, #88]
	orr  x4, x4, x5
	cbnz x4, 2f
	mov  x0, x19
	mov  x1, x21
	ldp  x2, x3,  [x1]
	ldp  x4, x5,  [x1, #16]
	ldp  x6, x7,  [x1, #32]
	ldp  x8, x9,  [x1, #48]
	stp  x2, x3,  [x0]
	stp  x4, x5,  [x0, #16]
	stp  x6, x7,  [x0, #32]
	stp  x8, x9,  [x0, #48]
	mov  x10, #1
	str  x10, [x19, #64]
	str  xzr, [x19, #72]
	str  xzr, [x19, #80]
	str  xzr, [x19, #88]
	cbz  x22, 9f
	mov  x10, #1
	str  x10, [x22, #0]
	str  xzr, [x22, #8]
	str  xzr, [x22, #16]
	str  xzr, [x22, #24]
	b    9f
2:
	/* S0 = Z1^2 (Z1Z1) */
	SLOT x0, 0
	add  x1, x20, #64
	bl   fe_sqr
	/* S1 = X2 * Z1Z1 (U2) */
	SLOT x0, 1
	mov  x1, x21
	SLOT x2, 0
	bl   fe_mul
	/* S8 = Z1 * Z1Z1 */
	SLOT x0, 8
	add  x1, x20, #64
	SLOT x2, 0
	bl   fe_mul
	/* S3 = Y2 * S8 (S2y) */
	SLOT x0, 3
	add  x1, x21, #32
	SLOT x2, 8
	bl   fe_mul

	/* ---- if U2 == X1 (equal-x case) ---- */
	SLOT x4, 1
	ldr  x5, [x4, #0]
	ldr  x6, [x20, #0]
	cmp  x5, x6
	b.ne 3f
	ldr  x5, [x4, #8]
	ldr  x6, [x20, #8]
	cmp  x5, x6
	b.ne 3f
	ldr  x5, [x4, #16]
	ldr  x6, [x20, #16]
	cmp  x5, x6
	b.ne 3f
	ldr  x5, [x4, #24]
	ldr  x6, [x20, #24]
	cmp  x5, x6
	b.ne 3f
	/* equal X: compare S2y(S3) vs Y1 */
	SLOT x4, 3
	ldr  x5, [x4, #0]
	ldr  x6, [x20, #32]
	cmp  x5, x6
	b.ne 4f
	ldr  x5, [x4, #8]
	ldr  x6, [x20, #40]
	cmp  x5, x6
	b.ne 4f
	ldr  x5, [x4, #16]
	ldr  x6, [x20, #48]
	cmp  x5, x6
	b.ne 4f
	ldr  x5, [x4, #24]
	ldr  x6, [x20, #56]
	cmp  x5, x6
	b.ne 4f
	/* same point -> double ; zr = 2*Y1 captured first */
	cbz  x22, 5f
	SLOT x0, 9
	add  x1, x20, #32
	add  x2, x20, #32
	bl   fe_add
	mov  x0, x22
	SLOT x1, 9
	ldp  x2, x3,  [x1]
	ldp  x4, x5,  [x1, #16]
	stp  x2, x3,  [x0]
	stp  x4, x5,  [x0, #16]
5:	mov  x0, x19
	mov  x1, x20
	bl   point_double
	b    9f
4:	/* opposite point -> infinity, zr=0 */
	mov  x6, #1
	str  x6,  [x19, #0]
	str  xzr, [x19, #8]
	str  xzr, [x19, #16]
	str  xzr, [x19, #24]
	str  x6,  [x19, #32]
	str  xzr, [x19, #40]
	str  xzr, [x19, #48]
	str  xzr, [x19, #56]
	str  xzr, [x19, #64]
	str  xzr, [x19, #72]
	str  xzr, [x19, #80]
	str  xzr, [x19, #88]
	cbz  x22, 9f
	str  xzr, [x22, #0]
	str  xzr, [x22, #8]
	str  xzr, [x22, #16]
	str  xzr, [x22, #24]
	b    9f

3:	/* ---- distinct: H=U2-X1 -> S4 ; R=S2y-Y1 -> S5 ---- */
	SLOT x0, 4
	SLOT x1, 1
	mov  x2, x20
	bl   fe_sub                  /* H */
	SLOT x0, 5
	SLOT x1, 3
	add  x2, x20, #32
	bl   fe_sub                  /* R */
	/* HH = H^2 -> S6 ; HHH = H*HH -> S7 ; V = X1*HH -> S2 */
	SLOT x0, 6
	SLOT x1, 4
	bl   fe_sqr
	SLOT x0, 7
	SLOT x1, 4
	SLOT x2, 6
	bl   fe_mul
	SLOT x0, 2
	mov  x1, x20
	SLOT x2, 6
	bl   fe_mul
	/* X3 = R^2 - HHH - 2V -> r+0 */
	SLOT x0, 8
	SLOT x1, 5
	bl   fe_sqr                 /* S8 = R^2 */
	SLOT x0, 8
	SLOT x1, 8
	SLOT x2, 2
	bl   fe_sub                 /* - V */
	SLOT x0, 8
	SLOT x1, 8
	SLOT x2, 2
	bl   fe_sub                 /* - V */
	SLOT x0, 8
	SLOT x1, 8
	SLOT x2, 7
	bl   fe_sub                 /* - HHH */
	mov  x0, x19
	SLOT x1, 8
	ldp  x2, x3,  [x1]
	ldp  x4, x5,  [x1, #16]
	stp  x2, x3,  [x0]
	stp  x4, x5,  [x0, #16]
	/* Y3 = R*(V-X3) - Y1*HHH -> r+32 */
	SLOT x0, 8
	SLOT x1, 2
	mov  x2, x19
	bl   fe_sub                 /* S8 = V - X3 */
	SLOT x0, 8
	SLOT x1, 5
	SLOT x2, 8
	bl   fe_mul                 /* S8 = R*(V-X3) */
	SLOT x0, 9
	add  x1, x20, #32
	SLOT x2, 7
	bl   fe_mul                 /* S9 = Y1*HHH */
	SLOT x0, 8
	SLOT x1, 8
	SLOT x2, 9
	bl   fe_sub                 /* Y3 = S8 - S9 */
	mov  x0, x19
	add  x0, x0, #32
	SLOT x1, 8
	ldp  x2, x3,  [x1]
	ldp  x4, x5,  [x1, #16]
	stp  x2, x3,  [x0]
	stp  x4, x5,  [x0, #16]
	/* Z3 = Z1 * H -> r+64 */
	SLOT x0, 9
	add  x1, x20, #64
	SLOT x2, 4
	bl   fe_mul
	mov  x0, x19
	add  x0, x0, #64
	SLOT x1, 9
	ldp  x2, x3,  [x1]
	ldp  x4, x5,  [x1, #16]
	stp  x2, x3,  [x0]
	stp  x4, x5,  [x0, #16]
	/* zr = H (S4) */
	cbz  x22, 9f
	mov  x0, x22
	SLOT x1, 4
	ldp  x2, x3,  [x1]
	ldp  x4, x5,  [x1, #16]
	stp  x2, x3,  [x0]
	stp  x4, x5,  [x0, #16]
9:
	add  sp, sp, #320
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size point_add_mixed_zr, .-point_add_mixed_zr
	.size point_add_mixed, .-point_add_mixed

/* ============================================================================
 * point_add(r=x0, p=x1, q=x2)  -- full Jacobian-Jacobian
 * slots: S0=Z1Z1 S1=Y1w S2=U1 S3=U2 S4=S2proj S5=Z22 S6=H S7=R S8=HH S9=HHH
 *        S10=V S11=w/Z1Z2
 * ========================================================================== */
	.global point_add
	.type   point_add, %function
point_add:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	sub  sp, sp, #384            /* slots S0..S11 */
	mov  x19, x0                 /* r */
	mov  x20, x1                 /* p */
	mov  x21, x2                 /* q */

	/* ---- p inf -> r = q ; q inf -> r = p ---- */
	ldr  x4,  [x20, #64]
	ldr  x5,  [x20, #72]
	orr  x4, x4, x5
	ldr  x5,  [x20, #80]
	orr  x4, x4, x5
	ldr  x5,  [x20, #88]
	orr  x4, x4, x5
	cbnz x4, 2f
	mov  x0, x19
	mov  x1, x21
	ldp  x2, x3,  [x1]
	ldp  x4, x5,  [x1, #16]
	ldp  x6, x7,  [x1, #32]
	ldp  x8, x9,  [x1, #48]
	stp  x2, x3,  [x0]
	stp  x4, x5,  [x0, #16]
	stp  x6, x7,  [x0, #32]
	stp  x8, x9,  [x0, #48]
	ldp  x2, x3,  [x1, #64]
	ldp  x4, x5,  [x1, #80]
	stp  x2, x3,  [x0, #64]
	stp  x4, x5,  [x0, #80]
	b    9f
2:
	ldr  x4,  [x21, #64]
	ldr  x5,  [x21, #72]
	orr  x4, x4, x5
	ldr  x5,  [x21, #80]
	orr  x4, x4, x5
	ldr  x5,  [x21, #88]
	orr  x4, x4, x5
	cbnz x4, 3f
	mov  x0, x19
	mov  x1, x20
	ldp  x2, x3,  [x1]
	ldp  x4, x5,  [x1, #16]
	ldp  x6, x7,  [x1, #32]
	ldp  x8, x9,  [x1, #48]
	stp  x2, x3,  [x0]
	stp  x4, x5,  [x0, #16]
	stp  x6, x7,  [x0, #32]
	stp  x8, x9,  [x0, #48]
	ldp  x2, x3,  [x1, #64]
	ldp  x4, x5,  [x1, #80]
	stp  x2, x3,  [x0, #64]
	stp  x4, x5,  [x0, #80]
	b    9f
3:
	/* S0 = Z1Z1 ; S5 = Z22 */
	SLOT x0, 0
	add  x1, x20, #64
	bl   fe_sqr
	SLOT x0, 5
	add  x1, x21, #64
	bl   fe_sqr
	/* S2 = U1 = X1*Z22 */
	SLOT x0, 2
	mov  x1, x20
	SLOT x2, 5
	bl   fe_mul
	/* S3 = U2 = X2*Z1Z1 */
	SLOT x0, 3
	mov  x1, x21
	SLOT x2, 0
	bl   fe_mul
	/* S11 = w = Z2*Z22 ; S1 = Y1*w */
	SLOT x0, 11
	add  x1, x21, #64
	SLOT x2, 5
	bl   fe_mul
	SLOT x0, 1
	add  x1, x20, #32
	SLOT x2, 11
	bl   fe_mul
	/* S11 = w = Z1*Z1Z1 ; S4 = S2proj = Y2*w */
	SLOT x0, 11
	add  x1, x20, #64
	SLOT x2, 0
	bl   fe_mul
	SLOT x0, 4
	add  x1, x21, #32
	SLOT x2, 11
	bl   fe_mul

	/* ---- if U1 == U2 (S2 vs S3) ---- */
	SLOT x4, 2
	SLOT x5, 3
	ldr  x6, [x4, #0]
	ldr  x7, [x5, #0]
	cmp  x6, x7
	b.ne 6f
	ldr  x6, [x4, #8]
	ldr  x7, [x5, #8]
	cmp  x6, x7
	b.ne 6f
	ldr  x6, [x4, #16]
	ldr  x7, [x5, #16]
	cmp  x6, x7
	b.ne 6f
	ldr  x6, [x4, #24]
	ldr  x7, [x5, #24]
	cmp  x6, x7
	b.ne 6f
	/* equal X: compare S1(Y1w) vs S4(S2proj) */
	SLOT x4, 1
	SLOT x5, 4
	ldr  x6, [x4, #0]
	ldr  x7, [x5, #0]
	cmp  x6, x7
	b.ne 5f
	ldr  x6, [x4, #8]
	ldr  x7, [x5, #8]
	cmp  x6, x7
	b.ne 5f
	ldr  x6, [x4, #16]
	ldr  x7, [x5, #16]
	cmp  x6, x7
	b.ne 5f
	ldr  x6, [x4, #24]
	ldr  x7, [x5, #24]
	cmp  x6, x7
	b.ne 5f
	/* same point -> double(p) */
	mov  x0, x19
	mov  x1, x20
	bl   point_double
	b    9f
5:	/* opposite -> infinity */
	mov  x6, #1
	str  x6,  [x19, #0]
	str  xzr, [x19, #8]
	str  xzr, [x19, #16]
	str  xzr, [x19, #24]
	str  x6,  [x19, #32]
	str  xzr, [x19, #40]
	str  xzr, [x19, #48]
	str  xzr, [x19, #56]
	str  xzr, [x19, #64]
	str  xzr, [x19, #72]
	str  xzr, [x19, #80]
	str  xzr, [x19, #88]
	b    9f
6:
	/* H = U2-U1 -> S6 ; R = S2proj - S1 -> S7 */
	SLOT x0, 6
	SLOT x1, 3
	SLOT x2, 2
	bl   fe_sub
	SLOT x0, 7
	SLOT x1, 4
	SLOT x2, 1
	bl   fe_sub
	/* HH=H^2->S8 ; HHH=H*HH->S9 ; V=U1*HH->S10 */
	SLOT x0, 8
	SLOT x1, 6
	bl   fe_sqr
	SLOT x0, 9
	SLOT x1, 6
	SLOT x2, 8
	bl   fe_mul
	SLOT x0, 10
	SLOT x1, 2
	SLOT x2, 8
	bl   fe_mul
	/* X3 = R^2 - HHH - 2V -> r+0 */
	SLOT x0, 5
	SLOT x1, 7
	bl   fe_sqr                 /* S5 = R^2 */
	SLOT x0, 5
	SLOT x1, 5
	SLOT x2, 10
	bl   fe_sub                 /* - V */
	SLOT x0, 5
	SLOT x1, 5
	SLOT x2, 10
	bl   fe_sub                 /* - V */
	SLOT x0, 5
	SLOT x1, 5
	SLOT x2, 9
	bl   fe_sub                 /* - HHH */
	mov  x0, x19
	SLOT x1, 5
	ldp  x2, x3,  [x1]
	ldp  x4, x5,  [x1, #16]
	stp  x2, x3,  [x0]
	stp  x4, x5,  [x0, #16]
	/* Y3 = R*(V-X3) - S1*HHH -> r+32 */
	SLOT x0, 5
	SLOT x1, 10
	mov  x2, x19
	bl   fe_sub                 /* S5 = V - X3 */
	SLOT x0, 5
	SLOT x1, 7
	SLOT x2, 5
	bl   fe_mul                 /* S5 = R*(V-X3) */
	SLOT x0, 11
	SLOT x1, 1
	SLOT x2, 9
	bl   fe_mul                 /* S11 = S1*HHH */
	SLOT x0, 5
	SLOT x1, 5
	SLOT x2, 11
	bl   fe_sub                 /* Y3 */
	mov  x0, x19
	add  x0, x0, #32
	SLOT x1, 5
	ldp  x2, x3,  [x1]
	ldp  x4, x5,  [x1, #16]
	stp  x2, x3,  [x0]
	stp  x4, x5,  [x0, #16]
	/* Z3 = Z1*Z2*H -> r+64 */
	SLOT x0, 11
	add  x1, x20, #64
	add  x2, x21, #64
	bl   fe_mul                 /* S11 = Z1*Z2 */
	SLOT x0, 11
	SLOT x1, 11
	SLOT x2, 6
	bl   fe_mul                 /* S11 = Z1Z2*H */
	mov  x0, x19
	add  x0, x0, #64
	SLOT x1, 11
	ldp  x2, x3,  [x1]
	ldp  x4, x5,  [x1, #16]
	stp  x2, x3,  [x0]
	stp  x4, x5,  [x0, #16]
9:
	add  sp, sp, #384
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size point_add, .-point_add

/* ============================================================================
 * point_scalar_mul(r=x0, xy=x1, k=x2) -- w=4 windowed double-and-add
 * Frame: TAB[1..15] @ sp+0 (1440B), kbuf @ sp+1440 (32B); total 1472B.
 * Persistent regs are x23..x28 ONLY: the leaf point_* / fe_* callees never
 * touch them (they clobber x19..x22 and x0..x18). Holding loop state in
 * x19/x20/x21/x22 here is FATAL because point_add/add_mixed/double overwrite
 * those with their own r/p/q/zr pointers.
 *   x23=r  x24=base affine  x25=kbuf  x26=TAB base
 *   x27=top_win             x28=counter (table i / window w)
 * ========================================================================== */
	.global point_scalar_mul
	.type   point_scalar_mul, %function
point_scalar_mul:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x27, x28, [sp, #-16]!
	sub  sp, sp, #1472
	mov  x23, x0                 /* r */
	mov  x24, x1                 /* base affine xy */

	/* copy k[0..3] -> kbuf(sp+1440) */
	add  x25, sp, #1440
	ldr  x4,  [x2, #0]
	ldr  x5,  [x2, #8]
	ldr  x6,  [x2, #16]
	ldr  x7,  [x2, #24]
	str  x4,  [x25, #0]
	str  x5,  [x25, #8]
	str  x6,  [x25, #16]
	str  x7,  [x25, #24]

	/* k == 0 -> infinity */
	ldr  x4,  [x25, #0]
	ldr  x5,  [x25, #8]
	orr  x4, x4, x5
	ldr  x5,  [x25, #16]
	orr  x4, x4, x5
	ldr  x5,  [x25, #24]
	orr  x4, x4, x5
	cbz  x4, 10f                /* k == 0 -> infinity */

	/* ---- find msb bit index -> x27 = top_win = msb>>2 ---- */
	ldr  x8,  [x25, #24]
	cbnz x8, 4f
	ldr  x8,  [x25, #16]
	cbnz x8, 3f
	ldr  x8,  [x25, #8]
	cbnz x8, 2f
	mov  x10, #0
	ldr  x8,  [x25, #0]
	b    5f
2:	mov  x10, #1
	ldr  x8,  [x25, #8]
	b    5f
3:	mov  x10, #2
	ldr  x8,  [x25, #16]
	b    5f
4:	mov  x10, #3
	ldr  x8,  [x25, #24]
5:	clz  x9, x8                 /* leading zeros in limb */
	mov  x11, #63
	sub  x11, x11, x9           /* bit within limb */
	mov  x9, x10
	lsl  x9, x9, #6             /* limb*64 */
	add  x11, x11, x9           /* msb index 0..255 */
	lsr  x11, x11, #2           /* top_win */
	mov  x27, x11

	/* ---- build TAB[1..15] = i*base ---- */
	mov  x26, sp                 /* TAB base */
	mov  x9, x26
	ldp  x2, x3,  [x24]
	ldp  x4, x5,  [x24, #16]
	ldp  x6, x7,  [x24, #32]
	ldp  x8, x10, [x24, #48]
	stp  x2, x3,  [x9]
	stp  x4, x5,  [x9, #16]
	stp  x6, x7,  [x9, #32]
	stp  x8, x10, [x9, #48]
	mov  x11, #1
	str  x11, [x9, #64]
	str  xzr, [x9, #72]
	str  xzr, [x9, #80]
	str  xzr, [x9, #88]
	mov  x28, #2                 /* i = 2..15 */
6:	mov  x0, x28
	sub  x0, x0, #1
	mov  x1, #96
	mul  x0, x0, x1              /* (i-1)*96 */
	add  x0, x0, x26             /* out = TAB[i] */
	sub  x1, x0, #96             /* p   = TAB[i-1] */
	mov  x2, x24                 /* affine base */
	bl   point_add_mixed
	add  x28, x28, #1
	cmp  x28, #15
	b.le 6b

	/* ---- R = TAB[digit_top] ---- */
	mov  x9, x27
	lsl  x9, x9, #2              /* bit = top_win*4 */
	mov  x10, x9
	lsr  x10, x10, #6            /* limb idx */
	and  x9, x9, #63
	ldr  x8, [x25, x10, lsl #3]
	lsrv x8, x8, x9
	and  x8, x8, #15             /* digit_top (>=1) */
	sub  x9, x8, #1
	mov  x10, #96
	mul  x9, x9, x10
	add  x9, x9, x26             /* -> TAB[digit] */
	mov  x0, x23
	ldp  x2, x3,  [x9]
	ldp  x4, x5,  [x9, #16]
	ldp  x6, x7,  [x9, #32]
	ldp  x8, x10, [x9, #48]
	stp  x2, x3,  [x0]
	stp  x4, x5,  [x0, #16]
	stp  x6, x7,  [x0, #32]
	stp  x8, x10, [x0, #48]
	ldp  x2, x3,  [x9, #64]
	ldp  x4, x5,  [x9, #80]
	stp  x2, x3,  [x0, #64]
	stp  x4, x5,  [x0, #80]

	/* ---- remaining windows w = top_win-1 .. 0 ---- */
	mov  x28, x27
	subs x28, x28, #1
	b.mi 9f                      /* only top window exists */
7:	/* R = 16*R */
	mov  x0, x23
	mov  x1, x23
	bl   point_double
	mov  x0, x23
	mov  x1, x23
	bl   point_double
	mov  x0, x23
	mov  x1, x23
	bl   point_double
	mov  x0, x23
	mov  x1, x23
	bl   point_double
	/* digit for window w(x28) */
	mov  x9, x28
	lsl  x9, x9, #2
	mov  x10, x9
	lsr  x10, x10, #6
	and  x9, x9, #63
	ldr  x8, [x25, x10, lsl #3]
	lsrv x8, x8, x9
	and  x8, x8, #15
	cbz  x8, 8f
	sub  x9, x8, #1
	mov  x10, #96
	mul  x9, x9, x10
	add  x9, x9, x26             /* TAB[digit] */
	mov  x2, x9
	mov  x0, x23
	mov  x1, x23
	bl   point_add                /* R = R + TAB[digit] */
8:	subs x28, x28, #1
	b.pl 7b
	b    9f

	/* ---- zero scalar: Jacobian infinity (1,1,0) ---- */
10:	mov  x6, #1
	str  x6,  [x23, #0]
	str  xzr, [x23, #8]
	str  xzr, [x23, #16]
	str  xzr, [x23, #24]
	str  x6,  [x23, #32]
	str  xzr, [x23, #40]
	str  xzr, [x23, #48]
	str  xzr, [x23, #56]
	str  xzr, [x23, #64]
	str  xzr, [x23, #72]
	str  xzr, [x23, #80]
	str  xzr, [x23, #88]
9:
	add  sp, sp, #1472
	ldp  x27, x28, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size point_scalar_mul, .-point_scalar_mul

	.section .note.GNU-stack,"",%progbits

