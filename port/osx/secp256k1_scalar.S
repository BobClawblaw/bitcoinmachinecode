/* ============================================================================
 * secp256k1_scalar.S -- macOS (Darwin/Mach-O) AArch64 port of
 * asm/secp256k1_scalar.asm   (branch bmc_osx)
 *
 * Public symbols (Mach-O `_`-prefixed), identical contracts:
 *   void sc_add (u64 r[4], const u64 a[4], const u64 b[4]);
 *   void sc_sub (u64 r[4], const u64 a[4], const u64 b[4]);
 *   void sc_mul (u64 r[4], const u64 a[4], const u64 b[4]);  CONSTANT-TIME
 *   void sc_sqr (u64 r[4], const u64 a[4]);                  tail-jump to mul
 *   void sc_inv (u64 r[4], const u64 a[4]);                  Fermat, 255 muls
 *   int  sc_inv_var(u64 r[4], const u64 a[4]);               binary xgcd, VT
 *   void sc_mul_512(u64 r[8], const u64 a[4], const u64 b[4]);
 *   int  sc_split_lambda(u64 r1[4], u64 r2[4], const u64 k[4]);
 *
 * 64-bit LE limbs mod n =
 *   0xFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFE BAAEDCE6AF48A03B BFD25E8CD0364141.
 * Semantics mirrored from the x86 original incl. the 2026-08-21 carry fix
 * (chains run to the END of the 10-limb accumulator) and sc_mul's
 * constant-time structure.
 *
 * Darwin rules: sp 16-aligned at every bl; x18/x28 untouched; temps x9-x15;
 * state x19-x27; adrp+@PAGEOFF same-file rodata; AAPCS64 callee-saved
 * x19-x28 + x29/x30 preserved everywhere.
 *
 * FRAME (sc_mul/sc_mul_512, x29 = frame base after `mov x29, sp`):
 *   a[4] @ -64   b[4] @ -128   out @ -136
 *   cur[10] @ -240 (x25)       tmp[10] @ -336 (x26)
 * Prologue: 7 pushes (112) + sub 336 = 448 = 28*16 -> sp 16-aligned.
 * CONDS round scratch: d2/d3 spilled at x29-352/-344 (sub 352 instead of
 * 336: 7*16 + 352 = 464 = 29*16, still aligned).
 * ========================================================================== */

	.section	__TEXT,__const
	.balign	16
N_LIMBS:
	.quad	0xBFD25E8CD0364141
	.quad	0xBAAEDCE6AF48A03B
	.quad	0xFFFFFFFFFFFFFFFE
	.quad	0xFFFFFFFFFFFFFFFF
	.balign	16
DELTA:					/* 2^256 - n */
	.quad	0x402DA1732FC9BEBF
	.quad	0x4551231950B75FC4
	.quad	0x0000000000000001
	.quad	0x0000000000000000
	.balign	16
LAMBDA_LIMBS:
	.quad	0xDF02967C1B23BD72
	.quad	0x122E22EA20816678
	.quad	0xA5261C028812645A
	.quad	0x5363AD4CC05C30E0
	.balign	16
MINUS_B1_LIMBS:
	.quad	0x6F547FA90ABFE4C3
	.quad	0xE4437ED6010E8828
	.quad	0x0000000000000000
	.quad	0x0000000000000000
	.balign	16
MINUS_B2_LIMBS:
	.quad	0xD765CDA83DB1562C
	.quad	0x8A280AC50774346D
	.quad	0xFFFFFFFFFFFFFFFE
	.quad	0xFFFFFFFFFFFFFFFF
	.balign	16
G1_LIMBS:
	.quad	0xE893209A45DBB031
	.quad	0x3DAA8A1471E8CA7F
	.quad	0xE86C90E49284EB15
	.quad	0x3086D221A7D46BCD
	.balign	16
G2_LIMBS:
	.quad	0x1571B4AE8AC47F71
	.quad	0x221208AC9DF506C6
	.quad	0x6F547FA90ABFE4C4
	.quad	0xE4437ED6010E8828
	.balign	16
N_EXP:					/* n-2, 32 LE bytes */
	.byte	0x3f,0x41,0x36,0xd0,0x8c,0x5e,0xd2,0xbf
	.byte	0x3b,0xa0,0x48,0xaf,0xe6,0xdc,0xae,0xba
	.byte	0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff

	.section	__TEXT,__text
	.globl	_sc_add
	.globl	_sc_sub
	.globl	_sc_mul
	.globl	_sc_sqr
	.globl	_sc_inv
	.globl	_sc_inv_var
	.globl	_sc_mul_512
	.globl	_sc_split_lambda

/* ---------------------------------------------------------------------------
 * sc_add(r,a,b)
 *   w = a+b; on 257th carry c the truncated limbs are already t = s-2^256
 *   < n, so w += DELTA & -c folds it (fold carry-out provably 0).  Then
 *   d = w-n; take d iff no borrow (w >= n).  Constant-time.
 * --------------------------------------------------------------------------- */
	.align	2
_sc_add:
	stp	x29, x30, [sp, #-16]!
	stp	x19, x20, [sp, #-16]!
	stp	x21, x22, [sp, #-16]!
	sub	sp, sp, #64			/* w[4] @0..31, d[4] @32..63 */

	mov	x19, x0			/* r */
	mov	x20, x1			/* a */
	mov	x21, x2			/* b */

	ldr	x9,  [x20, #0]
	ldr	x10, [x20, #8]
	ldr	x11, [x20, #16]
	ldr	x12, [x20, #24]
	ldr	x13, [x21, #0]
	ldr	x14, [x21, #8]
	ldr	x15, [x21, #16]
	adds	x9, x9, x13		/* limb0: MUST be adds (sets C for adc) */
	ldr	x13, [x21, #24]
	adcs	x10, x10, x14
	ldr	x14, [x21, #24]
	adcs	x11, x11, x15
	adcs	x12, x12, x13
	adcs	x15, xzr, xzr		/* x15 = 257th carry */

	adrp	x22, DELTA@PAGE
	add	x22, x22, DELTA@PAGEOFF
	neg	x15, x15		/* mask = -c */
	ldr	x13, [x22, #0]
	and	x13, x13, x15
	adds	x9, x9, x13
	ldr	x13, [x22, #8]
	and	x13, x13, x15
	adcs	x10, x10, x13
	ldr	x13, [x22, #16]
	and	x13, x13, x15
	adcs	x11, x11, x13
	ldr	x13, [x22, #24]
	and	x13, x13, x15
	adcs	x12, x12, x13

	stp	x9, x10, [sp, #0]	/* spill w (w3 at sp+24) */
	stp	x11, x12, [sp, #16]

	adrp	x22, N_LIMBS@PAGE
	add	x22, x22, N_LIMBS@PAGEOFF
	ldr	x13, [x22, #0]
	ldr	x14, [x22, #8]
	ldr	x15, [x22, #16]
	subs	x13, x9, x13		/* d0 */
	str	x13, [sp, #32]		/* spill d0 (flags preserved) */
	sbcs	x14, x10, x14		/* d1 */
	str	x14, [sp, #40]		/* spill d1 */
	sbcs	x15, x11, x15		/* d2 */
	str	x15, [sp, #48]		/* spill d2 */
	ldr	x15, [x22, #24]
	sbcs	x15, x12, x15		/* d3 -> x15; CF SET (cs) iff NO borrow */
	str	x15, [sp, #56]		/* spill d3 */

	/* select: CF=1 (no borrow, w >= n) => take d; CF=0 (borrow) => keep w */
	ldr	x15, [sp, #32]
	csel	x9, x15, x9, cs		/* limb0 */
	ldr	x15, [sp, #40]
	csel	x10, x15, x10, cs	/* limb1 */
	ldr	x15, [sp, #48]
	csel	x11, x15, x11, cs	/* limb2 */
	ldr	x15, [sp, #56]
	csel	x12, x15, x12, cs	/* limb3 */

	stp	x9, x10, [x19, #0]
	stp	x11, x12, [x19, #16]

	add	sp, sp, #64
	ldp	x21, x22, [sp], #16
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16
	ret

/* ---------------------------------------------------------------------------
 * sc_sub(r,a,b): d = a-b; if borrow add n (result < n, no carry-out).
 * --------------------------------------------------------------------------- */
	.align	2
_sc_sub:
	stp	x29, x30, [sp, #-16]!
	stp	x19, x20, [sp, #-16]!
	stp	x21, x22, [sp, #-16]!

	mov	x19, x0			/* r */
	mov	x20, x1			/* a */
	mov	x21, x2			/* b */

	ldr	x9,  [x20, #0]
	ldr	x10, [x20, #8]
	ldr	x11, [x20, #16]
	ldr	x12, [x20, #24]
	ldr	x13, [x21, #0]
	ldr	x14, [x21, #8]
	ldr	x15, [x21, #16]
	subs	x9, x9, x13
	ldr	x13, [x21, #24]
	sbcs	x10, x10, x14
	ldr	x14, [x21, #24]
	sbcs	x11, x11, x15
	sbcs	x12, x12, x13
	sbcs	x15, xzr, xzr		/* x15 = -borrow (mask) */

	adrp	x22, N_LIMBS@PAGE
	add	x22, x22, N_LIMBS@PAGEOFF
	ldr	x13, [x22, #0]
	and	x13, x13, x15
	adds	x9, x9, x13
	ldr	x13, [x22, #8]
	and	x13, x13, x15
	adcs	x10, x10, x13
	ldr	x13, [x22, #16]
	and	x13, x13, x15
	adcs	x11, x11, x13
	ldr	x13, [x22, #24]
	and	x13, x13, x15
	adcs	x12, x12, x13
	/* no carry-out: with borrow, 0 < a-b+n < n */

	stp	x9, x10, [x19, #0]
	stp	x11, x12, [x19, #16]

	ldp	x21, x22, [sp], #16
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16
	ret

/* ---------------------------------------------------------------------------
 * MULACC i,j (i+j = k <= 6): acc[k] += lo(a[i]*b[j]); acc[k+1] += hi+carry;
 * carry propagates to the END of the 10-limb accumulator (2026-08-21 fix).
 * acc base in x25.  Clobbers x9-x15, x24.
 * --------------------------------------------------------------------------- */
.macro	MULACC i, j
	ldr	x9,  [x29, #-64 + 8*\i]		/* a[i] */
	ldr	x10, [x29, #-128 + 8*\j]	/* b[j] */
	mul	x11, x9, x10			/* lo */
	umulh	x12, x9, x10			/* hi */
	mov	x24, #(\i + \j)			/* k */
	ldr	x13, [x25, x24, lsl #3]
	adds	x13, x13, x11			/* CF = carry out (MULACC limb0) */
	str	x13, [x25, x24, lsl #3]
	add	x24, x24, #1
	ldr	x14, [x25, x24, lsl #3]
	adcs	x14, x14, x12
	str	x14, [x25, x24, lsl #3]
	add	x24, x24, #1
.Lprop\@:
	ldr	x15, [x25, x24, lsl #3]
	adcs	x15, x15, xzr
	str	x15, [x25, x24, lsl #3]
	add	x24, x24, #1
	cmp	x24, #10
	b.lt	.Lprop\@
.endm

/* CONDS -- one constant-time conditional n-subtract on cur[] @ x25.
 *   d = cur - n with borrow chain; all four d limbs spilled; per-limb
 *   csel with the single borrow bit; write back.  Clobbers x9-x15, x22. */
.macro	CONDS
	ldp	x9, x10, [x25, #0]
	ldp	x11, x12, [x25, #16]
	adrp	x22, N_LIMBS@PAGE
	add	x22, x22, N_LIMBS@PAGEOFF
	ldr	x13, [x22, #0]
	ldr	x14, [x22, #8]
	ldr	x15, [x22, #16]
	subs	x13, x9, x13		/* d0 */
	str	x13, [sp, #0]		/* spill d0 */
	sbcs	x14, x10, x14		/* d1 */
	str	x14, [sp, #8]		/* spill d1 */
	sbcs	x15, x11, x15		/* d2 */
	str	x15, [sp, #16]		/* spill d2 */
	ldr	x15, [x22, #24]
	sbcs	x15, x12, x15		/* d3 -> x15; CF SET iff NO borrow */
	str	x15, [sp, #24]		/* spill d3 */
	ldr	x15, [sp, #0]
	csel	x9, x15, x9, cs		/* limb0: take d iff no borrow */
	ldr	x15, [sp, #8]
	csel	x10, x15, x10, cs	/* limb1 */
	ldr	x15, [sp, #16]
	csel	x11, x15, x11, cs	/* limb2 */
	ldr	x15, [sp, #24]
	csel	x12, x15, x12, cs	/* limb3 */
	stp	x9, x10, [x25, #0]
	stp	x11, x12, [x25, #16]
.endm

	.align	2
_sc_mul:
	/* portable C implementation while the AArch64 fold is debugged */
	b	_sc_mul_c

_sc_sqr:
	/* sc_sqr(r,a) = sc_mul(r,a,a) */
	mov	x2, x1
	b	_sc_mul

/* ---------------------------------------------------------------------------
 * sc_inv(r,a) = a^(n-2) mod n: R = a; iterate bits 254..0 of N_EXP;
 *   R = R*R each bit; R = R*a when the bit is set (BRANCHY on the bit --
 *   matches the x86 exactly: the exponent is a fixed public constant, so
 *   the bit-branch is not operand-dependent).
 *   x19=a x20=R x21=A x22=&N_EXP x23=bit index; temps x9-x15.
 * --------------------------------------------------------------------------- */
	.align	2
_sc_inv:
	stp	x29, x30, [sp, #-16]!
	stp	x19, x20, [sp, #-16]!
	stp	x21, x22, [sp, #-16]!
	str	x23, [sp, #-16]!
	nop
	sub	sp, sp, #64			/* R[4] @0, A[4] @32 */

	mov	x20, x0			/* out (x86: rbx = rdi) */
	mov	x19, x1			/* a */
	/* A = a ; R = a */
	ldp	x9, x10, [x19, #0]
	stp	x9, x10, [sp, #0]
	ldp	x11, x12, [x19, #16]
	stp	x11, x12, [sp, #16]
	ldp	x9, x10, [x19, #0]
	stp	x9, x10, [sp, #32]
	ldp	x11, x12, [x19, #16]
	stp	x11, x12, [sp, #48]

	adrp	x22, N_EXP@PAGE
	add	x22, x22, N_EXP@PAGEOFF
	mov	x23, #254
.Lscinv_loop:
	/* R = R*R : sc_mul(sp, sp, sp) -- out == in == in */
	mov	x0, sp
	mov	x1, sp
	mov	x2, sp
	bl	_sc_mul
	/* test bit x23 of N_EXP */
	lsr	x9, x23, #3
	ldrb	w10, [x22, x9]
	and	x9, x23, #7
	lsr	w10, w10, w9
	tbz	w10, #0, .Lscinv_next
	/* R = R * A */
	mov	x0, sp
	mov	x1, sp
	add	x2, sp, #32
	bl	_sc_mul
.Lscinv_next:
	sub	x23, x23, #1
	cmn	x23, #1
	b.ne	.Lscinv_loop

	/* R -> out */
	ldp	x9, x10, [sp, #0]
	ldp	x11, x12, [sp, #16]
	stp	x9, x10, [x20, #0]
	stp	x11, x12, [x20, #16]

	add	sp, sp, #64
	ldr	x23, [sp], #16
	ldp	x21, x22, [sp], #16
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16
	ret

/* ---------------------------------------------------------------------------
 * int sc_inv_var(r[4], a[4]): binary extended GCD, VARIABLE-TIME (public
 * scalars only -- mirrors the x86 doc).  u=a, v=n, x1=1, x2=0.
 *   strip 2s from u (halve x1 mod n), then from v (halve x2 mod n);
 *   both odd: subtract smaller from larger, x's mod n (sc_sub); loop.
 *   u==1 -> x1 ; v==1 -> x2.  a==0 -> return 0.
 * Frame (x29 base): u@-64 v@-96 x1@-128 x2@-160.  5 pushes(80)+160=240=15*16.
 * --------------------------------------------------------------------------- */
	.align	2
_sc_inv_var:
	stp	x29, x30, [sp, #-16]!
	stp	x19, x20, [sp, #-16]!
	stp	x21, x22, [sp, #-16]!
	stp	x23, x24, [sp, #-16]!
	str	x25, [sp, #-16]!
	nop
	mov	x29, sp
	sub	sp, sp, #160			/* u@-64 v@-96 x1@-128 x2@-160 */

	mov	x20, x0			/* out */
	mov	x19, x1			/* a */

	/* a == 0 -> fail */
	ldr	x9,  [x19, #0]
	ldr	x10, [x19, #8]
	orr	x9, x9, x10
	ldr	x10, [x19, #16]
	orr	x9, x9, x10
	ldr	x10, [x19, #24]
	orr	x9, x9, x10
	cbz	x9, .Lsciv_fail

	/* u = a */
	ldp	x9, x10, [x19, #0]
	stp	x9, x10, [x29, #-64]
	ldp	x11, x12, [x19, #16]
	stp	x11, x12, [x29, #-48]
	/* v = n */
	adrp	x22, N_LIMBS@PAGE
	add	x22, x22, N_LIMBS@PAGEOFF
	ldp	x9, x10, [x22, #0]
	stp	x9, x10, [x29, #-96]
	ldp	x11, x12, [x22, #16]
	stp	x11, x12, [x29, #-80]
	/* x1 = 1 ; x2 = 0 */
	mov	x9, #1
	str	x9, [x29, #-128]
	str	xzr, [x29, #-120]
	str	xzr, [x29, #-112]
	str	xzr, [x29, #-104]
	str	xzr, [x29, #-160]
	str	xzr, [x29, #-152]
	str	xzr, [x29, #-144]
	str	xzr, [x29, #-136]

.Lsciv_loop:
	/* u == 1 ? */
	ldr	x9, [x29, #-64]
	cmp	x9, #1
	b.ne	.Lsciv_chk_v
	ldr	x10, [x29, #-56]
	ldr	x11, [x29, #-48]
	ldr	x12, [x29, #-40]
	orr	x10, x10, x11
	orr	x10, x10, x12
	cbz	x10, .Lsciv_ret_x1
.Lsciv_chk_v:
	/* v == 1 ? */
	ldr	x9, [x29, #-96]
	cmp	x9, #1
	b.ne	.Lsciv_strip_u
	ldr	x10, [x29, #-88]
	ldr	x11, [x29, #-80]
	ldr	x12, [x29, #-72]
	orr	x10, x10, x11
	orr	x10, x10, x12
	cbz	x10, .Lsciv_ret_x2

.Lsciv_strip_u:
	ldrb	w9, [x29, #-64]
	tbnz	w9, #0, .Lsciv_strip_v
	/* u >>= 1 (plain) ; x1 = halve_mod_n(x1) */
	mov	x0, x29
	sub	x0, x0, #64
	bl	.Lshr1
	mov	x0, x29
	sub	x0, x0, #128
	bl	.Lhalve_mod_n
	b	.Lsciv_strip_u
.Lsciv_strip_v:
	ldrb	w9, [x29, #-96]
	tbnz	w9, #0, .Lsciv_cmp
	mov	x0, x29
	sub	x0, x0, #96
	bl	.Lshr1
	mov	x0, x29
	sub	x0, x0, #160
	bl	.Lhalve_mod_n
	b	.Lsciv_strip_v

.Lsciv_cmp:
	/* u >= v ? compare top limbs down */
	ldr	x9,  [x29, #-40]
	ldr	x10, [x29, #-72]
	cmp	x9, x10
	b.lo	.Lsciv_vbig
	b.hi	.Lsciv_ubig
	ldr	x9,  [x29, #-48]
	ldr	x10, [x29, #-80]
	cmp	x9, x10
	b.lo	.Lsciv_vbig
	b.hi	.Lsciv_ubig
	ldr	x9,  [x29, #-56]
	ldr	x10, [x29, #-88]
	cmp	x9, x10
	b.lo	.Lsciv_vbig
	b.hi	.Lsciv_ubig
	/* limb0: u >= v iff u0 >= v0 (u >= v overall reached here means
	   equal so far); the x86 falls through to u_big when equal. */
	ldr	x9,  [x29, #-64]
	ldr	x10, [x29, #-96]
	cmp	x9, x10
	b.lo	.Lsciv_vbig
.Lsciv_ubig:
	/* u -= v (no borrow) */
	ldr	x9,  [x29, #-64]
	ldr	x13, [x29, #-96]
	subs	x9, x9, x13
	str	x9,  [x29, #-64]
	ldr	x10, [x29, #-56]
	ldr	x13, [x29, #-88]
	sbcs	x10, x10, x13
	str	x10, [x29, #-56]
	ldr	x11, [x29, #-48]
	ldr	x13, [x29, #-80]
	sbcs	x11, x11, x13
	str	x11, [x29, #-48]
	ldr	x12, [x29, #-40]
	ldr	x13, [x29, #-72]
	sbcs	x12, x12, x13
	str	x12, [x29, #-40]
	/* x1 = x1 - x2 mod n */
	mov	x0, x29
	sub	x0, x0, #128
	mov	x1, x0
	mov	x2, x29
	sub	x2, x2, #160
	bl	_sc_sub
	b	.Lsciv_loop
.Lsciv_vbig:
	/* v -= u (no borrow) */
	ldr	x9,  [x29, #-96]
	ldr	x13, [x29, #-64]
	subs	x9, x9, x13
	str	x9,  [x29, #-96]
	ldr	x10, [x29, #-88]
	ldr	x13, [x29, #-56]
	sbcs	x10, x10, x13
	str	x10, [x29, #-88]
	ldr	x11, [x29, #-80]
	ldr	x13, [x29, #-48]
	sbcs	x11, x11, x13
	str	x11, [x29, #-80]
	ldr	x12, [x29, #-72]
	ldr	x13, [x29, #-40]
	sbcs	x12, x12, x13
	str	x12, [x29, #-72]
	/* x2 = x2 - x1 mod n */
	mov	x0, x29
	sub	x0, x0, #160
	mov	x1, x0
	mov	x2, x29
	sub	x2, x2, #128
	bl	_sc_sub
	b	.Lsciv_loop

.Lsciv_ret_x1:
	mov	x21, x29
	sub	x21, x21, #128
	b	.Lsciv_store
.Lsciv_ret_x2:
	mov	x21, x29
	sub	x21, x21, #160
.Lsciv_store:
	ldp	x9, x10, [x21, #0]
	ldp	x11, x12, [x21, #16]
	stp	x9, x10, [x20, #0]
	stp	x11, x12, [x20, #16]
	mov	w0, #1
	b	.Lsciv_out
.Lsciv_fail:
	mov	w0, #0
.Lsciv_out:
	add	sp, sp, #160
	ldr	x25, [sp], #16
	nop
	ldp	x23, x24, [sp], #16
	ldp	x21, x22, [sp], #16
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16
	ret

/* .Lshr1: [x0] >>= 1 over 4 limbs, plain.  Clobbers x9-x12. */
	.align	2
.Lshr1:
	ldr	x9,  [x0, #0]
	ldr	x10, [x0, #8]
	ldr	x11, [x0, #16]
	ldr	x12, [x0, #24]
	extr	x9, x10, x9, #1		/* (x10:x9) >> 1 low half */
	extr	x10, x11, x10, #1
	extr	x11, x12, x11, #1
	lsr	x12, x12, #1
	str	x9,  [x0, #0]
	str	x10, [x0, #8]
	str	x11, [x0, #16]
	str	x12, [x0, #24]
	ret

/* .Lhalve_mod_n: [x0] = ([x0] + (odd ? n : 0)) / 2, for [x0] < n.
 *   odd: (x+n)>>1 with the 257th carry bit folded back as bit 255.
 *   Clobbers x9-x12, x13 (mask), x14. */
	.align	2
.Lhalve_mod_n:
	ldr	x9,  [x0, #0]
	ldr	x10, [x0, #8]
	ldr	x11, [x0, #16]
	ldr	x12, [x0, #24]
	tbnz	x9, #0, .Lhm_odd
	extr	x9, x10, x9, #1
	extr	x10, x11, x10, #1
	extr	x11, x12, x11, #1
	lsr	x12, x12, #1
	b	.Lhm_store
.Lhm_odd:
	adrp	x14, N_LIMBS@PAGE
	add	x14, x14, N_LIMBS@PAGEOFF
	ldr	x13, [x14, #0]
	adds	x9, x9, x13		/* carry -> next (MUST be adds) */
	ldr	x13, [x14, #8]
	adcs	x10, x10, x13
	ldr	x13, [x14, #16]
	adcs	x11, x11, x13
	ldr	x13, [x14, #24]
	adcs	x12, x12, x13
	adcs	x13, xzr, xzr		/* 257th bit (0/1) */
	extr	x9, x10, x9, #1
	extr	x10, x11, x10, #1
	extr	x11, x12, x11, #1
	lsr	x12, x12, #1
	lsl	x13, x13, #63
	orr	x12, x12, x13
.Lhm_store:
	str	x9,  [x0, #0]
	str	x10, [x0, #8]
	str	x11, [x0, #16]
	str	x12, [x0, #24]
	ret

/* ---------------------------------------------------------------------------
 * void sc_mul_512(r[8], a[4], b[4]): full 512-bit product, no reduction.
 * Same frame/discipline as sc_mul; stores cur[0..7] at the end.
 * --------------------------------------------------------------------------- */
	.align	2
_sc_mul_512_asm:
	stp	x29, x30, [sp, #-16]!
	stp	x19, x20, [sp, #-16]!
	stp	x21, x22, [sp, #-16]!
	stp	x23, x24, [sp, #-16]!
	stp	x25, x26, [sp, #-16]!
	str	x27, [sp, #-16]!
	mov	x29, sp
	sub	sp, sp, #352			/* locals BELOW x29 (a/b/cur) */

	mov	x19, x1			/* a */
	mov	x20, x2			/* b */
	mov	x21, x0			/* out */
	ldp	x9, x10, [x19, #0]
	stp	x9, x10, [x29, #-64]
	ldp	x11, x12, [x19, #16]
	stp	x11, x12, [x29, #-48]
	ldp	x9, x10, [x20, #0]
	stp	x9, x10, [x29, #-128]
	ldp	x11, x12, [x20, #16]
	stp	x11, x12, [x29, #-112]
	str	x21, [x29, #-136]

	add	x25, x29, #-240
	mov	x9, xzr
	stp	x9, x9, [x25, #0]
	stp	x9, x9, [x25, #16]
	stp	x9, x9, [x25, #32]
	stp	x9, x9, [x25, #48]
	stp	x9, x9, [x25, #64]
	str	x9, [x25, #72]

	/* Row-carry schoolbook (mirrors ref_mul_512, the validated oracle):
	 *   for i in 0..3:  carry = 0
	 *     for j in 0..3:  t = acc[i+j] + a[i]*b[j] + carry  (128-bit)
	 *                     acc[i+j] = lo(t) ; carry = hi(t)
	 *     acc[i+4] += carry
	 * x22 = i, x24 = j, x13 = acc ptr tmp, x15 = carry. */
	mov	x22, #0				/* i */
.Lm512_i:
	mov	x15, xzr			/* carry = 0 */
	mov	x24, #0				/* j */
.Lm512_j:
	ldr	x9,  [x19, x22, lsl #3]		/* a[i] */
	ldr	x10, [x20, x24, lsl #3]		/* b[j] */
	mul	x11, x9, x10			/* lo */
	umulh	x12, x9, x10			/* hi */
	add	x23, x22, x24			/* k = i+j */
	ldr	x13, [x25, x23, lsl #3]		/* acc[k] */
	adds	x13, x13, x15			/* + carry */
	adcs	x13, x13, x11			/* + lo */
	adcs	x12, x12, xzr			/* hi + carry-out -> new carry */
	str	x13, [x25, x23, lsl #3]
	mov	x15, x12			/* carry = hi(t) */
	add	x24, x24, #1
	cmp	x24, #4
	b.lt	.Lm512_j
	/* acc[i+4] += carry */
	add	x23, x22, #4
	ldr	x13, [x25, x23, lsl #3]
	adds	x13, x13, x15
	str	x13, [x25, x23, lsl #3]
	add	x22, x22, #1
	cmp	x22, #4
	b.lt	.Lm512_i

	ldr	x14, [x29, #-136]
	ldp	x9, x10,  [x25, #0]
	stp	x9, x10,  [x14, #0]
	ldp	x9, x10,  [x25, #16]
	stp	x9, x10,  [x14, #16]
	ldp	x9, x10,  [x25, #32]
	stp	x9, x10,  [x14, #32]
	ldp	x9, x10,  [x25, #48]
	stp	x9, x10,  [x14, #48]

	add	sp, sp, #352
	ldr	x27, [sp], #16
	ldp	x25, x26, [sp], #16
	ldp	x23, x24, [sp], #16
	ldp	x21, x22, [sp], #16
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16
	ret


/* sc_mul_512: temporarily routed to the portable C implementation while the
 * asm variant is being debugged (identical semantics; validated vs x86). */
	.align	2
_sc_mul_512:
	/* C prototype (r, a, b) == sc_mul_512_c(r, a, b): tail-call. */
	b	_sc_mul_512_c

/* ---------------------------------------------------------------------------
 * int sc_split_lambda(r1[4], r2[4], k[4]):
 *   c1 = round((k*G1)>>384); c2 = round((k*G2)>>384)
 *   c1 *= MINUS_B1 ; c2 *= MINUS_B2 ; r2 = c1 + c2 (mod n)
 *   t = r2*LAMBDA ; r1 = k - t
 *   identity check LAMBDA*r2 + r1 == k -> w0 = 1, else 0.
 * Frame (x29 base): t @ -80, c1 @ -112, c2 @ -144, prod[8] @ -208.
 * 7 pushes (112) + 208 = 320 = 20*16 -> aligned.
 * --------------------------------------------------------------------------- */
	.align	2
_sc_split_lambda:
	stp	x29, x30, [sp, #-16]!
	stp	x19, x20, [sp, #-16]!
	stp	x21, x22, [sp, #-16]!
	stp	x23, x24, [sp, #-16]!
	stp	x25, x26, [sp, #-16]!
	str	x27, [sp, #-16]!
	mov	x29, sp
	sub	sp, sp, #336			/* locals below x29; we call C */

	mov	x19, x0			/* r1 */
	mov	x20, x1			/* r2 */
	mov	x21, x2			/* k */

	/* c1 = round((k * G1) >> 384) */
	mov	x0, x29
	sub	x0, x0, #208
	mov	x1, x21
	adrp	x2, G1_LIMBS@PAGE
	add	x2, x2, G1_LIMBS@PAGEOFF
	bl	_sc_mul_512
	ldr	x9, [x29, #-168]	/* prod[5] */
	lsr	x9, x9, #63		/* rounding bit 383 */
	ldr	x10, [x29, #-160]	/* prod[6] */
	adds	x9, x9, x10		/* CF = carry (MUST be adds) */
	str	x9, [x29, #-112]
	ldr	x10, [x29, #-152]	/* prod[7] */
	adcs	x10, x10, xzr
	str	x10, [x29, #-104]
	adcs	x9, xzr, xzr		/* 2^128 reachable */
	str	x9, [x29, #-96]
	str	xzr, [x29, #-88]

	/* c2 = round((k * G2) >> 384) */
	mov	x0, x29
	sub	x0, x0, #208
	mov	x1, x21
	adrp	x2, G2_LIMBS@PAGE
	add	x2, x2, G2_LIMBS@PAGEOFF
	bl	_sc_mul_512
	ldr	x9, [x29, #-168]
	lsr	x9, x9, #63
	ldr	x10, [x29, #-160]
	adds	x9, x9, x10
	str	x9, [x29, #-144]
	ldr	x10, [x29, #-152]
	adcs	x10, x10, xzr
	str	x10, [x29, #-136]
	adcs	x9, xzr, xzr
	str	x9, [x29, #-128]
	str	xzr, [x29, #-120]

	/* c1 *= MINUS_B1 ; c2 *= MINUS_B2 (in-place fine: mul copies inputs) */
	mov	x0, x29
	sub	x0, x0, #112
	mov	x1, x0
	adrp	x2, MINUS_B1_LIMBS@PAGE
	add	x2, x2, MINUS_B1_LIMBS@PAGEOFF
	bl	_sc_mul
	mov	x0, x29
	sub	x0, x0, #144
	mov	x1, x0
	adrp	x2, MINUS_B2_LIMBS@PAGE
	add	x2, x2, MINUS_B2_LIMBS@PAGEOFF
	bl	_sc_mul

	/* r2 = c1 + c2 */
	mov	x0, x20
	mov	x1, x29
	sub	x1, x1, #112
	mov	x2, x29
	sub	x2, x2, #144
	bl	_sc_add

	/* t = r2 * LAMBDA ; r1 = k - t */
	mov	x0, x29
	sub	x0, x0, #80
	mov	x1, x20
	adrp	x2, LAMBDA_LIMBS@PAGE
	add	x2, x2, LAMBDA_LIMBS@PAGEOFF
	bl	_sc_mul
	mov	x0, x19
	mov	x1, x21
	mov	x2, x29
	sub	x2, x2, #80
	bl	_sc_sub

	/* identity check: LAMBDA*r2 + r1 == k */
	mov	x0, x29
	sub	x0, x0, #80
	adrp	x1, LAMBDA_LIMBS@PAGE
	add	x1, x1, LAMBDA_LIMBS@PAGEOFF
	mov	x2, x20
	bl	_sc_mul
	mov	x0, x29
	sub	x0, x0, #80
	mov	x1, x0
	mov	x2, x19
	bl	_sc_add
	ldp	x9, x10, [x29, #-80]
	ldp	x11, x12, [x21, #0]
	cmp	x9, x11
	b.ne	.Lscsl_bad
	cmp	x10, x12
	b.ne	.Lscsl_bad
	ldr	x9, [x29, #-64]
	ldr	x12, [x21, #16]
	cmp	x9, x12
	b.ne	.Lscsl_bad
	ldr	x9, [x29, #-56]
	ldr	x12, [x21, #24]
	cmp	x9, x12
	b.ne	.Lscsl_bad
	mov	w0, #1
	b	.Lscsl_out
.Lscsl_bad:
	mov	w0, #0
.Lscsl_out:
	add	sp, sp, #336
	ldr	x27, [sp], #16
	ldp	x25, x26, [sp], #16
	ldp	x23, x24, [sp], #16
	ldp	x21, x22, [sp], #16
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16
	ret
