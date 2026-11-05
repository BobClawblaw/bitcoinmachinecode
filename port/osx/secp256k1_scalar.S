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
 *   int  sc_inv_var(u64 r[4], const u64 a[4]);               safegcd, VT
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
/* n in 5 signed 62-bit limbs (sc_inv_var's safegcd representation) and
 * n^{-1} mod 2^62, as asm/secp256k1_scalar.asm: limbs = n >> 62k & (2^62-1),
 * the inverse by Newton. Re-derived in Python for this port (2026-09-27). */
	.balign	16
N62_LIMBS:
	.quad	0x3FD25E8CD0364141
	.quad	0x2ABB739ABD2280EE
	.quad	0x3FFFFFFFFFFFFFEB
	.quad	0x3FFFFFFFFFFFFFFF
	.quad	0x00000000000000FF
NINV62:
	.quad	0x34F20099AA774EC1
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

/* sc_mul, sc_mul_512 and their product helper: see the block at the end of
 * this file (2026-09-26: assembly; they tail-called sc_mul_c.c / sc_mul_512_c.c) */

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
 * int sc_inv_var(r[4], a[4]) : r = a^-1 mod n  --  VARIABLE-TIME.
 *   Bernstein-Yang safegcd (safegcd_var.h, the same body as fe_inv_var,
 *   instantiated for n). PUBLIC scalars only: ecdsa_verify's s^{-1}. sc_inv
 *   above stays the constant-time path for everything a signer computes.
 *   2026-09-27: replaces the binary extended GCD (u=a, v=n, halve-mod-n),
 *   which took 1.4 us here and looped forever on a >= n; this is 0.9 us
 *   and reduces a >= n first (a == n -> 0, as a == 0).
 *   Returns w0 = 1 and writes r; w0 = 0 with r untouched when a == 0 (mod n).
 * --------------------------------------------------------------------------- */
#include "safegcd_var.h"
SAFEGCD_INV_VAR sc_inv_var, N62_LIMBS, NINV62, N_LIMBS

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

/* ===========================================================================
 * sc_mul / sc_sqr's multiply and sc_mul_512, in assembly (2026-09-26). They
 * tail-called the portable C (sc_mul_c.c, sc_mul_512_c.c -- now the oracles in
 * test_support) "while the AArch64 fold is debugged"; the unused
 * _sc_mul_512_asm beside them carried the bug: its first add's carry went back
 * in at bit 0 instead of bit 64. sc_mul is CONSTANT-TIME (fixed folds, a csel
 * subtract), as the x86's; the C was not. Both give the canonical a*b mod n,
 * so the answers are the same (5M cases vs the C, edge operands, aliasing).
 * ========================================================================= */
	.text
/* Lsc_prod(a=x1, b=x2) -> p0..p7 in x3..x10 ; leaf, uses x11..x17 */
    .p2align 2
Lsc_prod:
    ldp   x11, x12, [x1]                  /* a0 a1 */
    ldp   x13, x14, [x1, #16]             /* a2 a3 */
    ldp   x15, x16, [x2]                  /* b0 b1 */
    ldp   x1, x2, [x2, #16]               /* b2 b3 (a, b pointers spent) */
    /* column accumulation: (x17:acc_hi2) -- use x3.. as outputs */
    /* col 0 */
    mul   x3, x11, x15
    umulh x4, x11, x15
    mov   x5, xzr
    mov   x6, xzr
    /* col 1: a0b1 + a1b0 */
.macro MAC lo, hi, top, ra, rb
    mul   x17, \ra, \rb
    adds  \lo, \lo, x17
    umulh x17, \ra, \rb
    adcs  \hi, \hi, x17
    adc   \top, \top, xzr
.endm
    MAC   x4, x5, x6, x11, x16
    MAC   x4, x5, x6, x12, x15
    /* col 2: a0b2 a1b1 a2b0 */
    mov   x7, xzr
    MAC   x5, x6, x7, x11, x1
    MAC   x5, x6, x7, x12, x16
    MAC   x5, x6, x7, x13, x15
    /* col 3: a0b3 a1b2 a2b1 a3b0 */
    mov   x8, xzr
    MAC   x6, x7, x8, x11, x2
    MAC   x6, x7, x8, x12, x1
    MAC   x6, x7, x8, x13, x16
    MAC   x6, x7, x8, x14, x15
    /* col 4: a1b3 a2b2 a3b1 */
    mov   x9, xzr
    MAC   x7, x8, x9, x12, x2
    MAC   x7, x8, x9, x13, x1
    MAC   x7, x8, x9, x14, x16
    /* col 5: a2b3 a3b2 */
    mov   x10, xzr
    MAC   x8, x9, x10, x13, x2
    MAC   x8, x9, x10, x14, x1
    /* col 6: a3b3 */
    mul   x17, x14, x2
    adds  x9, x9, x17
    umulh x17, x14, x2
    adc   x10, x10, x17
    ret

/* void sc_mul_512(r[8], a[4], b[4]): the full product, no reduction */
    .p2align 2
    .globl _sc_mul_512
_sc_mul_512:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    str   x0, [sp, #-16]!
    bl    Lsc_prod
    ldr   x0, [sp], #16
    stp   x3, x4, [x0]
    stp   x5, x6, [x0, #16]
    stp   x7, x8, [x0, #32]
    stp   x9, x10, [x0, #48]
    ldp   x29, x30, [sp], #16
    ret

/* ---------------------------------------------------------------------------
 * void sc_mul(r[4], a[4], b[4]) = a*b mod n, CONSTANT-TIME, canonical.
 * The 512-bit product L + H*2^256, then four folds of 2^256 = DELTA (mod n),
 * DELTA = 2^256 - n = d0 + d1*2^64 + 2^128 (129 bits):
 *   fold 1: H (256 bits) -> L + H*DELTA        <= 386 bits (7 limbs)
 *   fold 2: bits 256.. (<= 130) -> ...          <= 260 bits (5 limbs)
 *   fold 3: bits 256.. (<= 4)   -> ...          <= 257 bits
 *   fold 4: bit 256 (0 / 1)     -> ...          <  2^256 (cannot carry: when
 *           that bit is set the low 256 bits are tiny)
 * then one csel subtract of n (the value is < 2^256 < 2n). No branch or
 * address depends on the operands. Every fold is always performed.
 * ------------------------------------------------------------------------- */
/* MUL4x1 (h0..h3 in x7..x10, d) -> r0..r4 in x1, x2, x16, x17, x0 ; x20 temp */
.macro MUL4x1 d
    mul   x1, x7, \d
    umulh x2, x7, \d
    mul   x20, x8, \d
    adds  x2, x2, x20
    umulh x16, x8, \d
    mul   x20, x9, \d
    adcs  x16, x16, x20
    umulh x17, x9, \d
    mul   x20, x10, \d
    adcs  x17, x17, x20
    umulh x0, x10, \d
    adc   x0, x0, xzr
.endm
/* MUL3x1 (h0..h2 in x13..x15, d) -> r0..r3 in x1, x2, x17, x0 ; x20 temp */
.macro MUL3x1 d
    mul   x1, x13, \d
    umulh x2, x13, \d
    mul   x20, x14, \d
    adds  x2, x2, x20
    umulh x17, x14, \d
    mul   x20, x15, \d
    adcs  x17, x17, x20
    umulh x0, x15, \d
    adc   x0, x0, xzr
.endm

    .p2align 2
    .globl _sc_mul
_sc_mul:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    mov   x19, x0
    bl    Lsc_prod                        /* p0..p7 in x3..x10: L = x3..x6, H = x7..x10 */
    adrp  x17, LSC_DELTA@PAGE
    add   x17, x17, LSC_DELTA@PAGEOFF
    ldp   x11, x12, [x17]                 /* d0, d1 (d2 = 1) */
    /* ---- fold 1: acc (x3..x6, x13, x14, x15) = L + H*d0 + H*d1<<64 + H<<128 */
    MUL4x1 x11                            /* H*d0 -> limbs 0..4 */
    adds  x3, x3, x1
    adcs  x4, x4, x2
    adcs  x5, x5, x16
    adcs  x6, x6, x17
    adcs  x13, x0, xzr
    cset  x14, cs
    mov   x15, xzr
    MUL4x1 x12                            /* H*d1 -> limbs 1..5 */
    adds  x4, x4, x1
    adcs  x5, x5, x2
    adcs  x6, x6, x16
    adcs  x13, x13, x17
    adcs  x14, x14, x0
    adc   x15, x15, xzr
    adds  x5, x5, x7                      /* H -> limbs 2..5 */
    adcs  x6, x6, x8
    adcs  x13, x13, x9
    adcs  x14, x14, x10
    adc   x15, x15, xzr
    /* ---- fold 2: H' = x13, x14, x15 (<= 130 bits); limb 4 in x16 */
    MUL3x1 x11                            /* H'*d0 -> limbs 0..3 */
    adds  x3, x3, x1
    adcs  x4, x4, x2
    adcs  x5, x5, x17
    adcs  x6, x6, x0
    cset  x16, cs
    MUL3x1 x12                            /* H'*d1 -> limbs 1..4 */
    adds  x4, x4, x1
    adcs  x5, x5, x2
    adcs  x6, x6, x17
    adc   x16, x16, x0
    adds  x5, x5, x13                     /* H' -> limbs 2..4 */
    adcs  x6, x6, x14
    adc   x16, x16, x15                   /* the value is < 2^260: x16 < 16 */
    /* ---- fold 3: h = x16 */
    mul   x1, x16, x11
    umulh x2, x16, x11
    mul   x17, x16, x12
    umulh x0, x16, x12
    adds  x3, x3, x1
    adcs  x4, x4, x2
    adcs  x5, x5, x16
    adcs  x6, x6, xzr
    cset  x13, cs
    adds  x4, x4, x17
    adcs  x5, x5, x0
    adcs  x6, x6, xzr
    cinc  x13, x13, cs                    /* bit 256: 0 / 1 */
    /* ---- fold 4: that bit (DELTA masked in, no branch) */
    neg   x14, x13
    and   x1, x11, x14
    and   x2, x12, x14
    adds  x3, x3, x1
    adcs  x4, x4, x2
    adcs  x5, x5, x13
    adc   x6, x6, xzr
    /* ---- v >= n  <=>  v + DELTA carries out of 2^256: then take v - n */
    adds  x7, x3, x11
    adcs  x8, x4, x12
    mov   x16, #1
    adcs  x9, x5, x16
    adcs  x10, x6, xzr
    csel  x3, x7, x3, cs
    csel  x4, x8, x4, cs
    csel  x5, x9, x5, cs
    csel  x6, x10, x6, cs
    stp   x3, x4, [x19]
    stp   x5, x6, [x19, #16]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

    .section __TEXT,__const
    .p2align 4
LSC_DELTA:
    .quad 0x402DA1732FC9BEBF, 0x4551231950B75FC4
    .text
