/* ============================================================================
 * ecdsa_verify_ref.S -- FROZEN pre-PERF_SCOPE-4.2 verifier, AArch64 port of
 *   asm/tests/ecdsa_verify_ref.asm (itself a frozen copy of
 *   secp256k1_ecdsa.asm at main @ 0fc5d06, symbol renamed ecdsa_verify_ref).
 *   Test-only differential reference: affine x via fe_inv + Fermat sc_inv --
 *   the current ecdsa_verify is inversion-free (projective x-compare) with a
 *   variable-time s^-1; this file proves the verdicts stay byte-identical.
 *   DO NOT EDIT / DO NOT "fix" anything here -- a verdict-changing edit
 *   defeats its purpose. Not linked into any daemon or tool.
 *
 *   int ecdsa_verify_ref(const u64 z[4], const u64 r[4], const u64 s[4],
 *                        const u64 Qx[4], const u64 Qy[4])
 *   returns 1 iff (r,s) is a valid ECDSA signature of hash z under Q.
 *
 *   Algorithm (the frozen pre-4.2 shape; point_scalar_mul for u2*Q, NO GLV --
 *   it predates point_scalar_mul_glv):
 *     if !(1<=r<n and 1<=s<n): return 0
 *     w  = sc_inv(s) (Fermat);  u1 = z*w;  u2 = r*w  (mod n)
 *     P  = u1*G (fixed-base comb) + u2*Q (plain variable-base)   (Jacobian)
 *     if P infinity: return 0
 *     px = P.x * (1/P.z^2) mod p  (fe_inv)
 *     px mod n (one conditional subtract; px < p < 2n)
 *     return pxmod == r limb-wise
 *
 *   CENTRAL CONVENTION (kept from the x86): every multi-limb buffer is a
 *   CONTIGUOUS ASCENDING array, limb0 at base+0 .. limb3 at base+24; all
 *   callees read/write operands exactly this way.
 *
 *   AAPCS64: x0=z x1=r x2=s x3=Qx x4=Qy. Persistent x19=z x20=r x21=Qx
 *   x22=Qy -- preserved by every callee (see secp256k1_glv_mul.S's
 *   transitive-closure derivation: point_scalar_mul[_fixed]/point_add save
 *   what they write, sc_inv/sc_mul save x19-x22, fe_* never touch x19-x28).
 *   Frame (sp-relative, blocks ascending; the x86 reuses the s/w/u2 blocks
 *   as z2+px / zi / pxmod scratch AFTER the point step -- kept identical):
 *     s@+0 w@+32 u1@+64 u2@+96 Q@+128(8) P1@+192(12) P2@+288(12) P@+384(12)
 *     sub 480; epilogue pops the frame then the save pairs.
 *   Calls: sc_inv, sc_mul (scalar.S), point_scalar_mul,
 *     point_scalar_mul_fixed, point_add (point.S), fe_mul, fe_inv (fe.S).
 * ========================================================================== */

	.text

/* ---- local helper: 4 ascending limbs at x0 strictly in (0, n)? ----
 * w0 = 1 if yes, 0 if no. Clobbers x1, x4-x15 only (all caller-saved). */
	.type   ecdsa_in_range, %function
ecdsa_in_range:
	ldp  x4, x5,  [x0, #0]
	ldp  x6, x7,  [x0, #16]
	orr  x8, x4, x5
	orr  x8, x8, x6
	orr  x8, x8, x7
	cbz  x8, .Lr_no               /* == 0 */
	adrp x1, N_LIMBS
	add  x1, x1, :lo12:N_LIMBS
	ldp  x8, x9,  [x1, #0]
	ldp  x10, x11,[x1, #16]
	subs x12, x4, x8
	sbcs x13, x5, x9
	sbcs x14, x6, x10
	sbcs x15, x7, x11
	b.cs .Lr_no                   /* carry set = no borrow = value >= n */
	mov  w0, #1
	ret
.Lr_no:
	mov  w0, #0
	ret
	.size ecdsa_in_range, .-ecdsa_in_range

/* ============================================================================
 * int ecdsa_verify_ref(x0=z, x1=r, x2=s, x3=Qx, x4=Qy)
 * ========================================================================== */
	.global ecdsa_verify_ref
	.type   ecdsa_verify_ref, %function
ecdsa_verify_ref:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	sub  sp, sp, #480
	mov  x19, x0                 /* z */
	mov  x20, x1                 /* r */
	mov  x21, x3                 /* Qx */
	mov  x22, x4                 /* Qy */

	/* ---- copy s(x2) -> sp+0 ---- */
	ldr  x4, [x2, #0]
	ldr  x5, [x2, #8]
	ldr  x6, [x2, #16]
	ldr  x7, [x2, #24]
	str  x4, [sp, #0]
	str  x5, [sp, #8]
	str  x6, [sp, #16]
	str  x7, [sp, #24]
	/* s in (0,n)? */
	mov  x0, sp
	bl   ecdsa_in_range
	cbz  w0, .Lvr_inv
	/* r in (0,n)? */
	mov  x0, x20
	bl   ecdsa_in_range
	cbz  w0, .Lvr_inv

	/* ---- w = s^{-1} mod n : sp+32 (Fermat sc_inv, the pre-4.2 inverse) ---- */
	add  x0, sp, #32
	mov  x1, sp
	bl   sc_inv

	/* ---- u1 = z*w mod n : sp+64 ---- */
	add  x0, sp, #64
	mov  x1, x19                 /* z */
	add  x2, sp, #32             /* w */
	bl   sc_mul

	/* ---- build Q affine ascending: Qx -> sp+128, Qy -> sp+160 ---- */
	ldr  x4, [x21, #0]
	ldr  x5, [x21, #8]
	ldr  x6, [x21, #16]
	ldr  x7, [x21, #24]
	str  x4, [sp, #128]
	str  x5, [sp, #136]
	str  x6, [sp, #144]
	str  x7, [sp, #152]
	ldr  x4, [x22, #0]
	ldr  x5, [x22, #8]
	ldr  x6, [x22, #16]
	ldr  x7, [x22, #24]
	str  x4, [sp, #160]
	str  x5, [sp, #168]
	str  x6, [sp, #176]
	str  x7, [sp, #184]

	/* ---- u2 = r*w mod n : sp+96 ---- */
	add  x0, sp, #96
	mov  x1, x20                 /* r */
	add  x2, sp, #32             /* w */
	bl   sc_mul

	/* ---- P1 = u1*G : sp+192 (fixed-base G comb) ---- */
	add  x0, sp, #192
	add  x1, sp, #64             /* u1 */
	bl   point_scalar_mul_fixed

	/* ---- P2 = u2*Q : sp+288 (plain; the frozen verifier has no GLV) ---- */
	add  x0, sp, #288
	add  x1, sp, #128            /* Q */
	add  x2, sp, #96             /* u2 */
	bl   point_scalar_mul

	/* ---- P = P1 + P2 : sp+384 ---- */
	add  x0, sp, #384
	add  x1, sp, #192            /* P1 */
	add  x2, sp, #288            /* P2 */
	bl   point_add

	/* ---- P infinite? (Z @ sp+448..472 all zero) -> invalid ---- */
	ldr  x4, [sp, #448]
	ldr  x5, [sp, #456]
	orr  x4, x4, x5
	ldr  x5, [sp, #464]
	orr  x4, x4, x5
	ldr  x5, [sp, #472]
	orr  x4, x4, x5
	cbz  x4, .Lvr_inv

	/* ---- affine x = X * (1/Z^2) mod p; scratch: z2@sp+0, zi@sp+32 ---- */
	/* z2 = Z*Z   (Z = P[8..11] @ sp+448) */
	add  x0, sp, #0
	add  x1, sp, #448
	mov  x2, x1
	bl   fe_mul
	/* zi = z2^{-1} */
	add  x0, sp, #32
	add  x1, sp, #0
	bl   fe_inv
	/* px = X * zi  (X = P[0..3] @ sp+384); px reuses the z2 block @ sp+0 */
	add  x0, sp, #0
	add  x1, sp, #384
	add  x2, sp, #32
	bl   fe_mul

	/* ---- px mod n -> sp+96 (one conditional subtract; px < p < 2n) ----
	 * subs/sbcs leave C set when there was NO borrow, i.e. px >= n. */
	adrp x1, N_LIMBS
	add  x1, x1, :lo12:N_LIMBS
	ldp  x8, x9,  [x1, #0]
	ldp  x10, x11,[x1, #16]
	ldp  x4, x5,  [sp, #0]
	ldp  x6, x7,  [sp, #16]
	subs x12, x4, x8
	sbcs x13, x5, x9
	sbcs x14, x6, x10
	sbcs x15, x7, x11
	b.cc .Lpx_lt                 /* borrow: px < n, keep px */
	stp  x12, x13, [sp, #96]
	stp  x14, x15, [sp, #112]
	b    .Lpx_cmp
.Lpx_lt:
	ldp  x12, x13, [sp, #0]
	ldp  x14, x15, [sp, #16]
	stp  x12, x13, [sp, #96]
	stp  x14, x15, [sp, #112]
.Lpx_cmp:
	/* compare pxmod (sp+96) vs r (x20) limb-wise */
	ldp  x4, x5,  [sp, #96]
	ldp  x6, x7,  [sp, #112]
	ldp  x8, x9,  [x20, #0]
	ldp  x10, x11,[x20, #16]
	eor  x4, x4, x8
	eor  x5, x5, x9
	eor  x6, x6, x10
	eor  x7, x7, x11
	orr  x4, x4, x5
	orr  x6, x6, x7
	orr  x4, x4, x6
	cbnz x4, .Lvr_inv
	mov  w0, #1
	b    .Lvr_done
.Lvr_inv:
	mov  w0, #0
.Lvr_done:
	add  sp, sp, #480
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size ecdsa_verify_ref, .-ecdsa_verify_ref

	.section .rodata
	.balign 16
/* (the frozen x86 file also carries an unused G_AFF here -- dropped; this
 * verifier's only rodata need is n. point_scalar_mul_fixed owns its own
 * generator table.) */
N_LIMBS:
	.quad 0xBFD25E8CD0364141
	.quad 0xBAAEDCE6AF48A03B
	.quad 0xFFFFFFFFFFFFFFFE
	.quad 0xFFFFFFFFFFFFFFFF

	.section .note.GNU-stack,"",%progbits
