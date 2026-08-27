/* ============================================================================
 * secp256k1_point_ct.S -- AArch64 (ARMv8-A) port of asm/secp256k1_point_ct.asm
 *
 * CONSTANT-TIME secp256k1 scalar multiplication / homogeneous point ops for the
 * SIGNING path only. Faithful port of the x86 constant-time module.
 *
 * The x86 original inlines the field add/sub via FE_* macros; like the rest of
 * this repo's port (see secp256k1_point.S), this port CALLS the verified
 * fe_add / fe_sub / fe_mul / fe_sqr primitives of secp256k1_fe.S instead.
 * That is CONSTANT-TIME SAFE: all four primitives are branch-free straight-line
 * code (csel/cset only, no jumps, no secret-indexed memory), so the property
 * this file exists to guarantee is preserved.
 *
 * Formulas: Renes-Costello-Batina COMPLETE addition (Algorithm 7) / doubling
 * (Algorithm 9) in HOMOGENEOUS projective coordinates (X:Y:Z) -- exception-free
 * by construction for every input including the identity, P=Q and P=-Q.
 * Curve a=0, b=7 -> b3 = 3b = 21.
 *
 * ABI (AAPCS64, SysV x64 registers -> x0,x1,x2 when unconstrained):
 *   void pointh_add(u64 r[12], const u64 p[12], const u64 q[12])
 *   void pointh_double(u64 r[12], const u64 p[12])
 *   void point_scalar_mul_ct(u64 r[12], const u64 xy[8], const u64 k[4])
 *       r = k * affine(xy), returned in JACOBIAN form (X,Y,Z), 12 limbs.
 *       k == 0 (mod n) yields canonical Jacobian infinity (1,1,0).
 * pointh_* use homogeneous coords; point_scalar_mul_ct converts back to
 * Jacobian (X*Z, Y*Z^2, Z) at the end so the exported ABI is unchanged.
 *
 * CONSTANT-TIME STRUCTURE (mirrors the x86 source exactly):
 *   * exactly 256 ladder iterations regardless of k -- no bsr / bit-length.
 *   * every iteration does one complete double + one complete add
 *     (double-and-add-always); the add result is committed or discarded by
 *     CSEL, never by a branch (no cbz/cbnz on a secret bit).
 *   * no memory address depends on a bit of k -- no precomputed table, no
 *     secret-indexed load (the only indexed load is the fixed kbuf limb lookup
 *     whose index is the non-secret loop counter's i/64).
 *   * the infinity canonicalisation is CSEL-driven, so its timing does not
 *     reveal whether k reduced to zero.
 * ========================================================================== */
	.text

	/* b3 = 3*b = 21 as a 4-limb field element (little-endian) */
	.section .rodata
	.balign 16
B3_LIMBS:
	.quad 21
	.quad 0
	.quad 0
	.quad 0
	.text

/* ============================================================================
 * pointh_add(r=x0, p=x1, q=x2) -- complete addition, homogeneous, a=0.
 * RCB Algorithm 7. Correct for ALL inputs (identity, P==Q, P==-Q). No branches.
 *
 * Slots (sp-relative, 32B each):
 *   t0=0 t1=32 t2=64 t3=96 t4=128 X3=160 Y3=192 Z3=224   (frame 256B)
 * Persistent (callee) regs x19=out x20=p x21=q (preserved for us by fe_*,
 * which touch only x0..x18).
 * Note: X3@160 is used as the 2*t0 scratch for step 19/20 (its value from
 * step 16's product is already consumed at steps 17/18; it is rewritten at
 * step 25) -- exactly the x86 "intermediate stays in a dead slot" trick.
 * ========================================================================== */
	.global pointh_add
	.type   pointh_add, %function
pointh_add:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	sub  sp, sp, #256
	mov  x19, x0                 /* out */
	mov  x20, x1                 /* p   */
	mov  x21, x2                 /* q   */

	/* 1. t0 = X1*X2 */
	add  x0, sp, #0
	mov  x1, x20
	mov  x2, x21
	bl   fe_mul
	/* 2. t1 = Y1*Y2 */
	add  x0, sp, #32
	add  x1, x20, #32
	add  x2, x21, #32
	bl   fe_mul
	/* 3. t2 = Z1*Z2 */
	add  x0, sp, #64
	add  x1, x20, #64
	add  x2, x21, #64
	bl   fe_mul
	/* 4. t3 = X1+Y1 */
	add  x0, sp, #96
	mov  x1, x20
	add  x2, x20, #32
	bl   fe_add
	/* 5. t4 = X2+Y2 */
	add  x0, sp, #128
	mov  x1, x21
	add  x2, x21, #32
	bl   fe_add
	/* 6. t3 = t3*t4 */
	add  x0, sp, #96
	add  x1, sp, #96
	add  x2, sp, #128
	bl   fe_mul
	/* 7+8. t3 = t3 - t0 - t1 */
	add  x0, sp, #96
	add  x1, sp, #96
	mov  x2, sp
	bl   fe_sub
	add  x0, sp, #96
	add  x1, sp, #96
	add  x2, sp, #32
	bl   fe_sub
	/* 9. t4 = Y1+Z1 */
	add  x0, sp, #128
	add  x1, x20, #32
	add  x2, x20, #64
	bl   fe_add
	/* 10. X3 = Y2+Z2 */
	add  x0, sp, #160
	add  x1, x21, #32
	add  x2, x21, #64
	bl   fe_add
	/* 11. t4 = t4*X3 */
	add  x0, sp, #128
	add  x1, sp, #128
	add  x2, sp, #160
	bl   fe_mul
	/* 12+13. t4 = t4 - t1 - t2 */
	add  x0, sp, #128
	add  x1, sp, #128
	add  x2, sp, #32
	bl   fe_sub
	add  x0, sp, #128
	add  x1, sp, #128
	add  x2, sp, #64
	bl   fe_sub
	/* 14. X3 = X1+Z1 */
	add  x0, sp, #160
	mov  x1, x20
	add  x2, x20, #64
	bl   fe_add
	/* 15. Y3 = X2+Z2 */
	add  x0, sp, #192
	mov  x1, x21
	add  x2, x21, #64
	bl   fe_add
	/* 16. X3 = X3*Y3 */
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #192
	bl   fe_mul
	/* 17+18. Y3 = X3 - t0 - t2 */
	add  x0, sp, #192
	add  x1, sp, #160
	mov  x2, sp
	bl   fe_sub
	add  x0, sp, #192
	add  x1, sp, #192
	add  x2, sp, #64
	bl   fe_sub
	/* 19+20. t0 = 3*t0 : first 2*t0 into X3(dead), then add the original t0 */
	add  x0, sp, #160
	mov  x1, sp
	mov  x2, sp
	bl   fe_add                  /* X3 = 2*t0 */
	mov  x0, sp
	add  x1, sp, #160
	mov  x2, sp
	bl   fe_add                  /* t0 = 2t0 + t0 = 3t0 */
	/* 21. t2 = b3*t2 */
	add  x0, sp, #64
	adrp x1, B3_LIMBS
	add  x1, x1, :lo12:B3_LIMBS
	add  x2, sp, #64
	bl   fe_mul
	/* 22. Z3 = t1+t2 */
	add  x0, sp, #224
	add  x1, sp, #32
	add  x2, sp, #64
	bl   fe_add
	/* 23. t1 = t1-t2 */
	add  x0, sp, #32
	add  x1, sp, #32
	add  x2, sp, #64
	bl   fe_sub
	/* 24. Y3 = b3*Y3 */
	add  x0, sp, #192
	adrp x1, B3_LIMBS
	add  x1, x1, :lo12:B3_LIMBS
	add  x2, sp, #192
	bl   fe_mul
	/* 25. X3 = t4*Y3 */
	add  x0, sp, #160
	add  x1, sp, #128
	add  x2, sp, #192
	bl   fe_mul
	/* 26. t2 = t3*t1 */
	add  x0, sp, #64
	add  x1, sp, #96
	add  x2, sp, #32
	bl   fe_mul
	/* 27. X3 = t2 - X3 */
	add  x0, sp, #160
	add  x1, sp, #64
	add  x2, sp, #160
	bl   fe_sub
	/* 28. Y3 = Y3*t0 */
	add  x0, sp, #192
	add  x1, sp, #192
	mov  x2, sp
	bl   fe_mul
	/* 29. t1 = t1*Z3 */
	add  x0, sp, #32
	add  x1, sp, #32
	add  x2, sp, #224
	bl   fe_mul
	/* 30. Y3 = t1+Y3 */
	add  x0, sp, #192
	add  x1, sp, #32
	add  x2, sp, #192
	bl   fe_add
	/* 31. t0 = t0*t3 */
	mov  x0, sp
	mov  x1, sp
	add  x2, sp, #96
	bl   fe_mul
	/* 32. Z3 = Z3*t4 */
	add  x0, sp, #224
	add  x1, sp, #224
	add  x2, sp, #128
	bl   fe_mul
	/* 33. Z3 = Z3+t0 */
	add  x0, sp, #224
	add  x1, sp, #224
	mov  x2, sp
	bl   fe_add

	/* copy-out: r = (X3, Y3, Z3) */
	add  x4, sp, #160
	ldp  x5, x6,  [x4, #0]
	stp  x5, x6,  [x19, #0]
	ldp  x5, x6,  [x4, #16]
	stp  x5, x6,  [x19, #16]
	add  x4, sp, #192
	ldp  x5, x6,  [x4, #0]
	stp  x5, x6,  [x19, #32]
	ldp  x5, x6,  [x4, #16]
	stp  x5, x6,  [x19, #48]
	add  x4, sp, #224
	ldp  x5, x6,  [x4, #0]
	stp  x5, x6,  [x19, #64]
	ldp  x5, x6,  [x4, #16]
	stp  x5, x6,  [x19, #80]

	add  sp, sp, #256
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size pointh_add, .-pointh_add

/* ============================================================================
 * pointh_double(r=x0, p=x1) -- complete doubling, homogeneous, a=0.
 * RCB Algorithm 9. Correct including p == identity. No branches.
 *
 * Slots (32B each): t0=0 t1=32 t2=64 X3=96 Y3=128 Z3=160 ws=192 (frame 224B)
 * ws@192 is a private scratch holding 2*t2 for step 11/12 (3*t2); it is never
 * a formula slot, so it cannot collide. x19=out x20=p.
 * ========================================================================== */
	.global pointh_double
	.type   pointh_double, %function
pointh_double:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	sub  sp, sp, #224
	mov  x19, x0                 /* out */
	mov  x20, x1                 /* p   */

	/* 1. t0 = Y*Y */
	add  x0, sp, #0
	add  x1, x20, #32
	bl   fe_sqr
	/* 2-4. Z3 = 8*t0 : three doublings */
	add  x0, sp, #160
	mov  x1, sp
	mov  x2, sp
	bl   fe_add                  /* Z3 = 2*t0 */
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #160
	bl   fe_add                  /* Z3 = 4*t0 */
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #160
	bl   fe_add                  /* Z3 = 8*t0 */
	/* 5. t1 = Y*Z */
	add  x0, sp, #32
	add  x1, x20, #32
	add  x2, x20, #64
	bl   fe_mul
	/* 6. t2 = Z*Z */
	add  x0, sp, #64
	add  x1, x20, #64
	bl   fe_sqr
	/* 7. t2 = b3*t2 */
	add  x0, sp, #64
	adrp x1, B3_LIMBS
	add  x1, x1, :lo12:B3_LIMBS
	add  x2, sp, #64
	bl   fe_mul
	/* 8. X3 = t2*Z3 */
	add  x0, sp, #96
	add  x1, sp, #64
	add  x2, sp, #160
	bl   fe_mul
	/* 9. Y3 = t0+t2 */
	add  x0, sp, #128
	mov  x1, sp
	add  x2, sp, #64
	bl   fe_add
	/* 10. Z3 = t1*Z3 */
	add  x0, sp, #160
	add  x1, sp, #32
	add  x2, sp, #160
	bl   fe_mul
	/* 11+12. t2 = 3*t2 (2*t2 into ws, then add original t2) */
	add  x0, sp, #192
	add  x1, sp, #64
	add  x2, sp, #64
	bl   fe_add                  /* ws = 2*t2 */
	add  x0, sp, #64
	add  x1, sp, #192
	add  x2, sp, #64
	bl   fe_add                  /* t2 = 3*t2 */
	/* 13. t0 = t0-t2 */
	mov  x0, sp
	mov  x1, sp
	add  x2, sp, #64
	bl   fe_sub
	/* 14. Y3 = t0*Y3 */
	add  x0, sp, #128
	mov  x1, sp
	add  x2, sp, #128
	bl   fe_mul
	/* 15. Y3 = X3+Y3 */
	add  x0, sp, #128
	add  x1, sp, #96
	add  x2, sp, #128
	bl   fe_add
	/* 16. t1 = X*Y */
	add  x0, sp, #32
	mov  x1, x20
	add  x2, x20, #32
	bl   fe_mul
	/* 17. X3 = t0*t1 */
	add  x0, sp, #96
	mov  x1, sp
	add  x2, sp, #32
	bl   fe_mul
	/* 18. X3 = X3+X3 */
	add  x0, sp, #96
	add  x1, sp, #96
	add  x2, sp, #96
	bl   fe_add

	/* copy-out: r = (X3, Y3, Z3) */
	add  x4, sp, #96
	ldp  x5, x6,  [x4, #0]
	stp  x5, x6,  [x19, #0]
	ldp  x5, x6,  [x4, #16]
	stp  x5, x6,  [x19, #16]
	add  x4, sp, #128
	ldp  x5, x6,  [x4, #0]
	stp  x5, x6,  [x19, #32]
	ldp  x5, x6,  [x4, #16]
	stp  x5, x6,  [x19, #48]
	add  x4, sp, #160
	ldp  x5, x6,  [x4, #0]
	stp  x5, x6,  [x19, #64]
	ldp  x5, x6,  [x4, #16]
	stp  x5, x6,  [x19, #80]

	add  sp, sp, #224
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size pointh_double, .-pointh_double

/* ============================================================================
 * point_scalar_mul_ct(r=x0, xy=x1, k=x2) : r = k*affine(xy), CONSTANT TIME.
 *   Pb=(x:y:1) homogeneous base ; R=(0:1:0) identity.
 *   for i = 255 downto 0 (FIXED 256 iterations, independent of k):
 *       R = 2*R          complete double
 *       T = R + Pb       complete add (always performed)
 *       R = csel(bit_i(k), T, R)   -- committed/discarded by CSEL, no branch
 *   return Jacobian(R) = (X*Z, Y*Z^2, Z), infinity canonicalised to (1,1,0).
 *
 * Slots (sp-relative): R@0(96B) T@96(96B) Pb@192(96B) kbuf@288(32B)..320.
 * Persistent callee regs (untouched by fe_* which use only x0..x18; and
 * restored by pointh_add/pointh_double which save/restore x19..x22):
 *   x19=out  x20=xy  x21=k  x22=ladder counter i (255..0).
 * The bit is extracted from kbuf with the NON-secret counter index (i/64,
 * i%64) and tested with `cmp` + CSEL -- never cbz/cbnz -- so the trace is
 * identical for every scalar.
 * ========================================================================== */
	.global point_scalar_mul_ct
	.type   point_scalar_mul_ct, %function
point_scalar_mul_ct:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	sub  sp, sp, #320
	mov  x19, x0                 /* out */
	mov  x20, x1                 /* affine xy */
	mov  x21, x2                 /* k */

	/* ---- kbuf = k[0..3] (sp+288) ---- */
	add  x4, sp, #288
	ldr  x5, [x21, #0]
	str  x5, [x4, #0]
	ldr  x5, [x21, #8]
	str  x5, [x4, #8]
	ldr  x5, [x21, #16]
	str  x5, [x4, #16]
	ldr  x5, [x21, #24]
	str  x5, [x4, #24]

	/* ---- Pb = (x : y : 1) @ sp+192 ---- */
	add  x4, sp, #192
	ldp  x5, x6,  [x20, #0]
	stp  x5, x6,  [x4, #0]
	ldp  x5, x6,  [x20, #16]
	stp  x5, x6,  [x4, #16]
	ldp  x5, x6,  [x20, #32]
	stp  x5, x6,  [x4, #32]
	ldp  x5, x6,  [x20, #48]
	stp  x5, x6,  [x4, #48]
	mov  x5, #1
	str  x5, [x4, #64]
	str  xzr, [x4, #72]
	str  xzr, [x4, #80]
	str  xzr, [x4, #88]

	/* ---- R = identity (0 : 1 : 0) @ sp+0 ---- */
	str  xzr, [sp, #0]
	str  xzr, [sp, #8]
	str  xzr, [sp, #16]
	str  xzr, [sp, #24]
	mov  x5, #1
	str  x5, [sp, #32]
	str  xzr, [sp, #40]
	str  xzr, [sp, #48]
	str  xzr, [sp, #56]
	str  xzr, [sp, #64]
	str  xzr, [sp, #72]
	str  xzr, [sp, #80]
	str  xzr, [sp, #88]

	/* ---- ladder: i = 255 downto 0 (exactly 256 iterations) ---- */
	mov  x22, #255
.Lpcm_loop:
	/* R = 2*R */
	mov  x0, sp
	mov  x1, sp
	bl   pointh_double
	/* T = R + Pb (always) */
	add  x0, sp, #96
	mov  x1, sp
	add  x2, sp, #192
	bl   pointh_add

	/* bit = (k >> i) & 1 ; no jump follows -- selected with CSEL */
	mov  x9, x22
	mov  x10, x9
	lsr  x10, x10, #6            /* limb index = i/64 */
	and  x9, x9, #63             /* bit index within limb */
	add  x11, sp, #288           /* kbuf */
	ldr  x8, [x11, x10, lsl #3]
	lsrv x8, x8, x9
	and  x8, x8, #1              /* bit, 0 or 1 */
	cmp  x8, xzr                 /* set ZF; ZF set <=> bit==0 (flags survive) */

	/* R = bit ? T : R -- 12 CSEL selects (never a branch on the secret bit) */
	add  x11, sp, #0             /* R */
	add  x12, sp, #96            /* T */
	ldr  x13, [x11, #0]
	ldr  x14, [x12, #0]
	csel x13, x14, x13, ne
	str  x13, [x11, #0]
	ldr  x13, [x11, #8]
	ldr  x14, [x12, #8]
	csel x13, x14, x13, ne
	str  x13, [x11, #8]
	ldr  x13, [x11, #16]
	ldr  x14, [x12, #16]
	csel x13, x14, x13, ne
	str  x13, [x11, #16]
	ldr  x13, [x11, #24]
	ldr  x14, [x12, #24]
	csel x13, x14, x13, ne
	str  x13, [x11, #24]
	ldr  x13, [x11, #32]
	ldr  x14, [x12, #32]
	csel x13, x14, x13, ne
	str  x13, [x11, #32]
	ldr  x13, [x11, #40]
	ldr  x14, [x12, #40]
	csel x13, x14, x13, ne
	str  x13, [x11, #40]
	ldr  x13, [x11, #48]
	ldr  x14, [x12, #48]
	csel x13, x14, x13, ne
	str  x13, [x11, #48]
	ldr  x13, [x11, #56]
	ldr  x14, [x12, #56]
	csel x13, x14, x13, ne
	str  x13, [x11, #56]
	ldr  x13, [x11, #64]
	ldr  x14, [x12, #64]
	csel x13, x14, x13, ne
	str  x13, [x11, #64]
	ldr  x13, [x11, #72]
	ldr  x14, [x12, #72]
	csel x13, x14, x13, ne
	str  x13, [x11, #72]
	ldr  x13, [x11, #80]
	ldr  x14, [x12, #80]
	csel x13, x14, x13, ne
	str  x13, [x11, #80]
	ldr  x13, [x11, #88]
	ldr  x14, [x12, #88]
	csel x13, x14, x13, ne
	str  x13, [x11, #88]

	subs x22, x22, #1
	b.pl .Lpcm_loop

	/* ---- homogeneous (X:Y:Z) -> Jacobian (X*Z, Y*Z^2, Z) ----
	 * T slot is free; use it as scratch: Z^2@96, Y*Z^2@128, X*Z@160. */
	add  x0, sp, #96
	add  x1, sp, #64
	bl   fe_sqr                  /* T[0..3]  = Z^2 */
	add  x0, sp, #128
	add  x1, sp, #32
	add  x2, sp, #96
	bl   fe_mul                  /* T[4..7]  = Y*Z^2 (Jacobian Y) */
	add  x0, sp, #160
	mov  x1, sp
	add  x2, sp, #64
	bl   fe_mul                  /* T[8..11] = X*Z  (Jacobian X) */

	/* ---- canonicalise infinity, branch-free (CSEL) ----
	 * R[64..95] = homogeneous Z. If Z == 0 the point is at infinity; emit
	 * (1,1,0) to match secp256k1_point.asm's convention. The `cmp` below sets
	 * ZF (== 0 <=> infinity) once; the following ldr/mov/str/csel do not touch
	 * flags, so all 12 CSELs share it. */
	add  x4, sp, #64
	ldr  x5, [x4, #0]
	ldr  x6, [x4, #8]
	orr  x5, x5, x6
	ldr  x6, [x4, #16]
	orr  x5, x5, x6
	ldr  x6, [x4, #24]
	orr  x5, x5, x6
	cmp  x5, xzr                 /* ZF = 1 <=> Z == 0 (infinity) */

	/* X: limb0 = Z==0 ? 1 : X*Z.limb0 ; limbs1..3 = Z==0 ? 0 : ... */
	mov  x9, #1
	ldr  x8, [sp, #160]
	csel x8, x9, x8, eq
	str  x8, [x19, #0]
	mov  x9, xzr
	ldr  x8, [sp, #168]
	csel x8, x9, x8, eq
	str  x8, [x19, #8]
	ldr  x8, [sp, #176]
	csel x8, x9, x8, eq
	str  x8, [x19, #16]
	ldr  x8, [sp, #184]
	csel x8, x9, x8, eq
	str  x8, [x19, #24]
	/* Y */
	mov  x9, #1
	ldr  x8, [sp, #128]
	csel x8, x9, x8, eq
	str  x8, [x19, #32]
	mov  x9, xzr
	ldr  x8, [sp, #136]
	csel x8, x9, x8, eq
	str  x8, [x19, #40]
	ldr  x8, [sp, #144]
	csel x8, x9, x8, eq
	str  x8, [x19, #48]
	ldr  x8, [sp, #152]
	csel x8, x9, x8, eq
	str  x8, [x19, #56]
	/* Z (already 0 in the infinity case, copied verbatim from R@64..95) */
	ldr  x8, [x4, #0]
	str  x8, [x19, #64]
	ldr  x8, [x4, #8]
	str  x8, [x19, #72]
	ldr  x8, [x4, #16]
	str  x8, [x19, #80]
	ldr  x8, [x4, #24]
	str  x8, [x19, #88]

	add  sp, sp, #320
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size point_scalar_mul_ct, .-point_scalar_mul_ct

	.section .note.GNU-stack,"",@progbits
