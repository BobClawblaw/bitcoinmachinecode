/* ============================================================================
 * secp256k1_schnorr.S -- AArch64 (ARMv8-A) port of asm/secp256k1_schnorr.asm
 *
 * BIP340 Schnorr VERIFICATION (verify-only), same exported symbols:
 *   int schnorr_x_eq_r(const u64 r[4], const u64 X[4], const u64 Z[4])
 *       1 iff X/Z^2 == r mod p (projectively, no inversion). r<=p prechecked.
 *   int schnorr_verify(const u8 sig[64], const u8 pub_xonly[32],
 *                      const u8 *msg, int msglen)
 *       sig = r(32)||s(32) BE ; pub = x-only(32) ; msg arbitrary length.
 *       P=lift_x(pk); r<p; s<n; e=tagged_hash("BIP0340/challenge",r||Px||m) mod n;
 *       R = s*G - e*P ; fail if y(R) odd or x(R)!=r.
 *
 * GLV DEVIATION (same as ecdsa_verify): the x86 dispatches e*P through
 * bmc_ecdsa_glv_enabled/point_scalar_mul_glv; this port uses the VERIFIED
 * point_scalar_mul directly (the documented kill-switch fallback). GLV is a
 * pure perf path. Semantically identical.
 *
 * AAPCS64: schnorr_x_eq_r(x0,x1,x2); schnorr_verify(x0=sig,x1=pk,x2=msg,x3=len).
 * Chained callees preserve x19+.
 * Frame (sp-relative): sSL0 rSL32 e64 Paff96 sG160 eP256 R352 z3 448 zi480
 * yr512 tagh544 digest576 keyscr608 preimg640; sub 960.
 * ========================================================================== */
	.text
	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm

	.set S_SL,  0
	.set R_SL,  32
	.set E_SL,  64
	.set P_AFF, 96
	.set SG,    160
	.set EP,    256
	.set RPT,   352
	.set Z3S,   448
	.set ZI,    480
	.set YR,    512
	.set TAGH,  544
	.set DIG,   576
	.set KEYSCR,608
	.set PREIMG,640
	.set MSG_CAP, 192     /* PREIMG_CAP(320) - 128 */

	.section .rodata
	.balign 16
P_LIMBS:
	.quad 0xFFFFFFFEFFFFFC2F
	.quad 0xFFFFFFFFFFFFFFFF
	.quad 0xFFFFFFFFFFFFFFFF
	.quad 0xFFFFFFFFFFFFFFFF
	.balign 16
N_LIMBS:
	.quad 0xBFD25E8CD0364141
	.quad 0xBAAEDCE6AF48A03B
	.quad 0xFFFFFFFFFFFFFFFE
	.quad 0xFFFFFFFFFFFFFFFF
CHALLENGE_TAG:
	.ascii "BIP0340/challenge"
	.text

/* ---- schnorr_x_eq_r(x0=r, x1=X, x2=Z) ---- */
	.global schnorr_x_eq_r
	.type   schnorr_x_eq_r, %function
schnorr_x_eq_r:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	sub  sp, sp, #96          /* z2@0 t@32 */
	mov  x19, x0              /* r */
	mov  x20, x1              /* X */
	/* z2 = Z^2 @0 */
	mov  x0, sp
	mov  x1, x2
	bl   fe_sqr
	/* t = r*z2 @32 */
	add  x0, sp, #32
	mov  x1, x19
	mov  x2, sp
	bl   fe_mul
	/* t == X ? */
	add  x3, sp, #32
	ldr  x4, [x3, #0]
	ldr  x5, [x20, #0]
	cmp  x4, x5
	b.ne 1f
	ldr  x4, [x3, #8]
	ldr  x5, [x20, #8]
	cmp  x4, x5
	b.ne 1f
	ldr  x4, [x3, #16]
	ldr  x5, [x20, #16]
	cmp  x4, x5
	b.ne 1f
	ldr  x4, [x3, #24]
	ldr  x5, [x20, #24]
	cmp  x4, x5
	b.ne 1f
	mov  w0, #1
	b    2f
1:	mov  w0, #0
2:	add  sp, sp, #96
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size schnorr_x_eq_r, .-schnorr_x_eq_r

/* ---- schnorr_verify(x0=sig, x1=pk, x2=msg, x3=msglen) ---- */
	.global schnorr_verify
	.type   schnorr_verify, %function
schnorr_verify:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	sub  sp, sp, #960
	mov  x19, x0              /* sig */
	mov  x20, x1              /* pub_xonly */
	mov  x21, x2              /* msg */
	sxtw x22, w3              /* msglen (sign-extended) */

	/* msglen bound */
	cmp  x22, #0
	b.lt .Lsv_inv
	cmp  x22, #MSG_CAP
	b.gt .Lsv_inv

	/* ---- P = lift_x(pk) : pubkey_parse([0x02||pk],33,P_AFF,P_AFF+32) ---- */
	mov  w4, #0x02
	strb w4, [sp, #(KEYSCR)]
	/* copy 32 pk bytes -> keyscratch+1 using ldrb/strb loop */
	add  x6, sp, #(KEYSCR+1)
	mov  x7, x20
	mov  x8, #0
1:	ldrb w9, [x7, x8]
	strb w9, [x6, x8]
	add  x8, x8, #1
	cmp  x8, #32
	b.lo 1b
	add  x0, sp, #(KEYSCR)
	mov  x1, #33
	add  x2, sp, #(P_AFF)
	add  x3, sp, #(P_AFF+32)
	bl   pubkey_parse
	cbz  w0, .Lsv_inv

	/* ---- r limbs from sig[0:32] : limb[j]=rev(load sig[24-8j]) -> R_SL ; r<p */
	add  x8, x19, #24
	ldr  x4, [x8, #0]
	rev  x4, x4
	str  x4, [sp, #(R_SL+0)]
	add  x8, x19, #16
	ldr  x4, [x8, #0]
	rev  x4, x4
	str  x4, [sp, #(R_SL+8)]
	add  x8, x19, #8
	ldr  x4, [x8, #0]
	rev  x4, x4
	str  x4, [sp, #(R_SL+16)]
	add  x8, x19, #0
	ldr  x4, [x8, #0]
	rev  x4, x4
	str  x4, [sp, #(R_SL+24)]
	/* check r < p */
	LAddr x9, P_LIMBS
	ldr  x4, [sp, #(R_SL+24)]
	ldr  x6, [x9, #24]
	cmp  x4, x6
	b.hi .Lsv_inv
	b.lo 1f
	ldr  x4, [sp, #(R_SL+16)]
	ldr  x6, [x9, #16]
	cmp  x4, x6
	b.hi .Lsv_inv
	b.lo 1f
	ldr  x4, [sp, #(R_SL+8)]
	ldr  x6, [x9, #8]
	cmp  x4, x6
	b.hi .Lsv_inv
	b.lo 1f
	ldr  x4, [sp, #(R_SL+0)]
	ldr  x6, [x9, #0]
	cmp  x4, x6
	b.hs .Lsv_inv
1:	/* s limbs from sig[32:64] : limb0=rev(load sig[32+24]) -> S_SL ; s<n */
	add  x8, x19, #32
	add  x8, x8, #24
	ldr  x4, [x8, #0]
	rev  x4, x4
	str  x4, [sp, #(S_SL+0)]
	add  x8, x19, #32
	ldr  x4, [x8, #16]
	rev  x4, x4
	str  x4, [sp, #(S_SL+8)]
	add  x8, x19, #32
	ldr  x4, [x8, #8]
	rev  x4, x4
	str  x4, [sp, #(S_SL+16)]
	add  x8, x19, #32
	ldr  x4, [x8, #0]
	rev  x4, x4
	str  x4, [sp, #(S_SL+24)]
	LAddr x9, N_LIMBS
	ldr  x4, [sp, #(S_SL+24)]
	ldr  x6, [x9, #24]
	cmp  x4, x6
	b.hi .Lsv_inv
	b.lo 2f
	ldr  x4, [sp, #(S_SL+16)]
	ldr  x6, [x9, #16]
	cmp  x4, x6
	b.hi .Lsv_inv
	b.lo 2f
	ldr  x4, [sp, #(S_SL+8)]
	ldr  x6, [x9, #8]
	cmp  x4, x6
	b.hi .Lsv_inv
	b.lo 2f
	ldr  x4, [sp, #(S_SL+0)]
	ldr  x6, [x9, #0]
	cmp  x4, x6
	b.hs .Lsv_inv
2:	/* ---- e = tagged_hash(BIP0340/challenge, r||pk||m) mod n ----
	 * tagh=sha256(CHALLENGE_TAG) ; preimg=tagh||tagh||r_BE||pk||msg ;
	 * digest=sha256(preimg) ; e=digest mod n */
	add  x0, sp, #(TAGH)
	LAddr x1, CHALLENGE_TAG
	mov  x2, #17
	bl   sha256_full
	/* preimg[0:32]=tagh ; [32:64]=tagh */
	mov  x6, sp
	add  x6, x6, #(TAGH)
	mov  x7, sp
	add  x7, x7, #(PREIMG)
	ldp  x2, x3,  [x6]
	ldp  x4, x5,  [x6, #16]
	stp  x2, x3,  [x7]
	stp  x4, x5,  [x7, #16]
	ldp  x2, x3,  [x6]
	ldp  x4, x5,  [x6, #16]
	stp  x2, x3,  [x7, #32]
	stp  x4, x5,  [x7, #48]
	/* preimg[64:96]=sig[0:32] (r BE) */
	mov  x7, sp
	add  x7, x7, #(PREIMG+64)
	mov  x8, x19
	ldp  x2, x3,  [x8]
	ldp  x4, x5,  [x8, #16]
	stp  x2, x3,  [x7]
	stp  x4, x5,  [x7, #16]
	/* preimg[96:128]=pk */
	mov  x7, sp
	add  x7, x7, #(PREIMG+96)
	mov  x8, x20
	ldp  x2, x3,  [x8]
	ldp  x4, x5,  [x8, #16]
	stp  x2, x3,  [x7]
	stp  x4, x5,  [x7, #16]
	/* preimg[128:]=msg (x22 bytes) */
	mov  x7, sp
	add  x7, x7, #(PREIMG+128)
	mov  x8, x21
	mov  x9, x22
3:	cbz  x9, 4f
	ldrb w10, [x8]
	strb w10, [x7]
	add  x8, x8, #1
	add  x7, x7, #1
	sub  x9, x9, #1
	b    3b
4:	/* digest = sha256(preimg, 128+msglen) */
	add  x0, sp, #(DIG)
	add  x1, sp, #(PREIMG)
	add  x2, x22, #128
	bl   sha256_full
	/* e limbs = rev digest words -> E_SL ; then e %= n (single subtract) */
	add  x8, sp, #(DIG)
	ldr  x4, [x8, #24]
	rev  x4, x4
	str  x4, [sp, #(E_SL+0)]
	ldr  x4, [x8, #16]
	rev  x4, x4
	str  x4, [sp, #(E_SL+8)]
	ldr  x4, [x8, #8]
	rev  x4, x4
	str  x4, [sp, #(E_SL+16)]
	ldr  x4, [x8, #0]
	rev  x4, x4
	str  x4, [sp, #(E_SL+24)]
	/* compare e vs n top-down; if >= n subtract n */
	LAddr x9, N_LIMBS
	ldr  x4, [sp, #(E_SL+24)]
	ldr  x6, [x9, #24]
	cmp  x4, x6
	b.lo 5f
	b.hi .Le_sub
	ldr  x4, [sp, #(E_SL+16)]
	ldr  x6, [x9, #16]
	cmp  x4, x6
	b.lo 5f
	b.hi .Le_sub
	ldr  x4, [sp, #(E_SL+8)]
	ldr  x6, [x9, #8]
	cmp  x4, x6
	b.lo 5f
	b.hi .Le_sub
	ldr  x4, [sp, #(E_SL+0)]
	ldr  x6, [x9, #0]
	cmp  x4, x6
	b.lo 5f
.Le_sub:
	ldr  x4, [x9, #0]
	ldr  x5, [x9, #8]
	ldr  x6, [x9, #16]
	ldr  x7, [x9, #24]
	ldr  x8, [sp, #(E_SL+0)]
	subs x8, x8, x4
	str  x8, [sp, #(E_SL+0)]
	ldr  x8, [sp, #(E_SL+8)]
	sbcs x8, x8, x5
	str  x8, [sp, #(E_SL+8)]
	ldr  x8, [sp, #(E_SL+16)]
	sbcs x8, x8, x6
	str  x8, [sp, #(E_SL+16)]
	ldr  x8, [sp, #(E_SL+24)]
	sbcs x8, x8, x7
	str  x8, [sp, #(E_SL+24)]
5:	/* ---- sG = s*G (fixed comb) ---- */
	add  x0, sp, #(SG)
	add  x1, sp, #(S_SL)
	bl   point_scalar_mul_fixed
	/* ---- eP = e*P (variable, plain; GLV deferred) ---- */
	add  x0, sp, #(EP)
	add  x1, sp, #(P_AFF)
	add  x2, sp, #(E_SL)
	bl   point_scalar_mul
	/* ---- negate eP.Y (Jacobian) : Y = p - Y ---- */
	ldr  x4, [sp, #(EP+32)]
	ldr  x5, [sp, #(EP+40)]
	orr  x4, x4, x5
	ldr  x5, [sp, #(EP+48)]
	orr  x4, x4, x5
	ldr  x5, [sp, #(EP+56)]
	orr  x4, x4, x5
	cbz  x4, 6f
	LAddr x9, P_LIMBS
	ldr  x4, [x9, #0]
	ldr  x5, [sp, #(EP+32)]
	subs x4, x4, x5
	str  x4, [sp, #(EP+32)]
	ldr  x4, [x9, #8]
	ldr  x5, [sp, #(EP+40)]
	sbcs x4, x4, x5
	str  x4, [sp, #(EP+40)]
	ldr  x4, [x9, #16]
	ldr  x5, [sp, #(EP+48)]
	sbcs x4, x4, x5
	str  x4, [sp, #(EP+48)]
	ldr  x4, [x9, #24]
	ldr  x5, [sp, #(EP+56)]
	sbcs x4, x4, x5
	str  x4, [sp, #(EP+56)]
6:	/* ---- R = sG + eP (point_add already handles -eP) ---- */
	add  x0, sp, #(RPT)
	add  x1, sp, #(SG)
	add  x2, sp, #(EP)
	bl   point_add
	/* ---- R infinite? (Z @ RPT+64 all zero) ---- */
	ldr  x4, [sp, #(RPT+64)]
	ldr  x5, [sp, #(RPT+72)]
	orr  x4, x4, x5
	ldr  x5, [sp, #(RPT+80)]
	orr  x4, x4, x5
	ldr  x5, [sp, #(RPT+88)]
	orr  x4, x4, x5
	cbz  x4, .Lsv_inv
	/* ---- x(R)==r projectively ---- */
	add  x0, sp, #(R_SL)
	add  x1, sp, #(RPT)
	add  x2, sp, #(RPT+64)
	bl   schnorr_x_eq_r
	cbz  w0, .Lsv_inv
	/* ---- y(R) even ?  zi=Z^-1 ; z3=zi^3 ; yr=Y*z3 ; test yr&1 ---- */
	mov  x0, x29
	/* z3/zi/yr pointers are sp-relative; compute */
	add  x0, sp, #(ZI)
	add  x1, sp, #(RPT+64)
	bl   fe_inv
	add  x0, sp, #(Z3S)
	add  x1, sp, #(ZI)
	bl   fe_sqr
	add  x0, sp, #(Z3S)
	add  x1, sp, #(Z3S)
	add  x2, sp, #(ZI)
	bl   fe_mul
	add  x0, sp, #(YR)
	add  x1, sp, #(RPT+32)
	add  x2, sp, #(Z3S)
	bl   fe_mul
	ldr  x4, [sp, #(YR)]
	tbnz x4, #0, .Lsv_inv
	mov  w0, #1
	b    .Lsv_done
.Lsv_inv:
	mov  w0, #0
.Lsv_done:
	add  sp, sp, #960
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size schnorr_verify, .-schnorr_verify

	.section .note.GNU-stack,"",%progbits
