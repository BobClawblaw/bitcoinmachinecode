/* ============================================================================
 * secp256k1_glv.S -- AArch64 port of the GLV scalar primitives:
 *   sc_mul_512(r[8], a[4], b[4])         full 512-bit product, NO reduction
 *   sc_split_lambda(r1[4], r2[4], k[4])  GLV decomposition + identity check
 * (point_scalar_mul_glv lives in secp256k1_point.S, next to the primitives
 * it composes; this file holds only what secp256k1_scalar.asm owns.)
 *
 * Ported from asm/secp256k1_scalar.asm @ sc_mul_512/sc_split_lambda. The
 * arithmetic is limb-exact (same 4x64 little-endian limbs, same constants).
 *
 * sc_mul_512 is sc_mul's Phase 1 (16 schoolbook products with full carry
 * chains) exposed as a callable: the GLV split needs the raw product's
 * limbs 5..7, which the reduced sc_mul discards.
 *
 * sc_split_lambda returns 1 iff k == LAMBDA*r2 + r1 (mod n) -- the permanent
 * identity check libsecp runs only in VERIFY builds; the caller falls back
 * to the plain multiply when it fails, so a verify path degrades to
 * slow-and-correct, it never aborts. Requires k < n. r1/r2 must not alias k.
 * ========================================================================== */
	.text
	.balign 4

/* SCA_ADD/LAddr: identical definitions to secp256k1_scalar.S's (macros are
 * not visible across files; keep them byte-identical). */
	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm
	.macro SCA_ADD b, k, lo, hi
	ldr  x6, [\b, #((\k))*8]
	adds x6, x6, \lo
	str  x6, [\b, #((\k))*8]
	ldr  x6, [\b, #((\k)+1)*8]
	adcs x6, x6, \hi
	str  x6, [\b, #((\k)+1)*8]
	.if (\k)+2 <= 9
	ldr  x6, [\b, #((\k)+2)*8]
	adcs x6, x6, xzr
	str  x6, [\b, #((\k)+2)*8]
	.endif
	.if (\k)+3 <= 9
	ldr  x6, [\b, #((\k)+3)*8]
	adcs x6, x6, xzr
	str  x6, [\b, #((\k)+3)*8]
	.endif
	.if (\k)+4 <= 9
	ldr  x6, [\b, #((\k)+4)*8]
	adcs x6, x6, xzr
	str  x6, [\b, #((\k)+4)*8]
	.endif
	.if (\k)+5 <= 9
	ldr  x6, [\b, #((\k)+5)*8]
	adcs x6, x6, xzr
	str  x6, [\b, #((\k)+5)*8]
	.endif
	.if (\k)+6 <= 9
	ldr  x6, [\b, #((\k)+6)*8]
	adcs x6, x6, xzr
	str  x6, [\b, #((\k)+6)*8]
	.endif
	.if (\k)+7 <= 9
	ldr  x6, [\b, #((\k)+7)*8]
	adcs x6, x6, xzr
	str  x6, [\b, #((\k)+7)*8]
	.endif
	.endm

/* public curve parameters (mirrors asm/secp256k1_scalar.asm .rodata) */
	.balign 8
LAMBDA_LIMBS:   .quad 0xDF02967C1B23BD72, 0x122E22EA20816678, 0xA5261C028812645A, 0x5363AD4CC05C30E0
	.balign 8
MINUS_B1_LIMBS: .quad 0x6F547FA90ABFE4C3, 0xE4437ED6010E8828, 0x0000000000000000, 0x0000000000000000
	.balign 8
MINUS_B2_LIMBS: .quad 0xD765CDA83DB1562C, 0x8A280AC50774346D, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF
	.balign 8
G1_LIMBS:       .quad 0xE893209A45DBB031, 0x3DAA8A1471E8CA7F, 0xE86C90E49284EB15, 0x3086D221A7D46BCD
	.balign 8
G2_LIMBS:       .quad 0x1571B4AE8AC47F71, 0x221208AC9DF506C6, 0x6F547FA90ABFE4C4, 0xE4437ED6010E8828

/* ============================================================================
 * sc_mul_512(r=x0[8], a=x1[4], b=x2[4]) : r = a*b, the full 512-bit product,
 *   NO reduction. Schoolbook 4x4 into a 10-limb accumulator (mirrors
 *   sc_mul's Phase 1 via the same SCA_ADD macro: array[k] += (hi,lo) with
 *   carry propagation through k+2..9). a,b < n so the product is < 2^512.
 *   Preserves x19-x28; clobbers x0-x17 and the SCA_ADD scratch (x4-x6).
 * ========================================================================== */
	.global sc_mul_512
	.type   sc_mul_512, %function
sc_mul_512:
	stp x22, x30, [sp, #-16]!
	stp x18, x19, [sp, #-16]!
	stp x20, x21, [sp, #-16]!
	sub sp, sp, #96             /* cur[10] @ sp+0..79, out ptr @ sp+80 */
	mov x18, x1                 /* a */
	mov x19, x2                 /* b */
	add x20, sp, #0             /* cur */
	str x0, [sp, #80]
	/* zero cur[0..9] */
	mov x6, xzr
	mov x8, #10
1:	str x6, [x20], #8
	subs x8, x8, #1
	b.ne 1b
	add x20, sp, #0
	/* ---- 16 schoolbook products ---- */
	ldr x0, [x18, #0]
	ldr x1, [x19, #0]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 0, x4, x5
	ldr x1, [x19, #8]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 1, x4, x5
	ldr x1, [x19, #16]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 2, x4, x5
	ldr x1, [x19, #24]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 3, x4, x5
	ldr x0, [x18, #8]
	ldr x1, [x19, #0]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 1, x4, x5
	ldr x1, [x19, #8]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 2, x4, x5
	ldr x1, [x19, #16]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 3, x4, x5
	ldr x1, [x19, #24]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 4, x4, x5
	ldr x0, [x18, #16]
	ldr x1, [x19, #0]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 2, x4, x5
	ldr x1, [x19, #8]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 3, x4, x5
	ldr x1, [x19, #16]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 4, x4, x5
	ldr x1, [x19, #24]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 5, x4, x5
	ldr x0, [x18, #24]
	ldr x1, [x19, #0]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 3, x4, x5
	ldr x1, [x19, #8]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 4, x4, x5
	ldr x1, [x19, #16]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 5, x4, x5
	ldr x1, [x19, #24]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 6, x4, x5
	/* ---- store r[0..7] (limbs 8..9 are zero: a,b < 2^256) ---- */
	ldr x0, [sp, #80]
	add x20, sp, #0
	ldp x6, x7,  [x20, #0]
	ldp x8, x9,  [x20, #16]
	ldp x10, x11,[x20, #32]
	ldp x12, x13,[x20, #48]
	stp x6, x7,  [x0, #0]
	stp x8, x9,  [x0, #16]
	stp x10, x11,[x0, #32]
	stp x12, x13,[x0, #48]
	add sp, sp, #96
	ldp x20, x21, [sp], #16
	ldp x18, x19, [sp], #16
	ldp x22, x30, [sp], #16
	ret
	.size sc_mul_512, .-sc_mul_512

/* ============================================================================
 * sc_split_lambda(r1=x0[4], r2=x1[4], k=x2[4]) -> w0 1/0
 *   Frame (sp-relative after `stp x29,x30,[sp,#-160]!` — the first 16 bytes
 *   at the new sp hold the SAVED x29/x30, so locals start at +16):
 *     +16  prod[8]   (sc_mul_512's raw 512-bit product)
 *     +32  c1[4]     (overlaps prod[2..5] window? NO -- prod lives only while
 *      the two round() extractions read it; c1 is filled before c2's sc_mul_512
 *      overwrites prod. c1/c2 live at +32/+64, ABOVE nothing. The register
 *      save area is +96..143. t[] reuses prod at +16.)
 *   Layout: +16 prod/t (64B) | +32 c1 (32B) | +64 c2 (32B) | +96..143 saves.
 *   Preserves x19-x28. Calls sc_mul_512, sc_mul, sc_add, sc_sub.
 * ========================================================================== */
	.global sc_split_lambda
	.type   sc_split_lambda, %function
sc_split_lambda:
	stp x29, x30, [sp, #-224]!
	mov  x29, sp
	stp x19, x20, [sp, #144]
	stp x21, x22, [sp, #160]
	stp x23, x24, [sp, #176]
	stp x25, x26, [sp, #192]
	add x19, sp, #16            /* prod (saved x29/x30 sit at +0..15) */
	add x20, sp, #80            /* c1 -- MUST sit past prod's 64 bytes */
	add x21, sp, #112           /* c2   */
	mov x23, x0                 /* r1 out */
	mov x24, x1                 /* r2 out */
	mov x25, x2                 /* k (const through the body) */
	/* ---- c1 = round((k * G1) >> 384) ---- */
	mov x0, x19
	mov x1, x25
	adrp x2, G1_LIMBS
	add  x2, x2, :lo12:G1_LIMBS
	bl   sc_mul_512
	ldr x4, [x19, #40]          /* prod[5] */
	lsr x4, x4, #63             /* rounding bit 383 */
	ldr x5, [x19, #48]          /* prod[6] */
	adds x5, x5, x4
	str x5, [x20, #0]
	ldr x5, [x19, #56]          /* prod[7] */
	adc x5, x5, xzr
	str x5, [x20, #8]
	adc x5, xzr, xzr            /* 2^128 itself is reachable */
	str x5, [x20, #16]
	str xzr, [x20, #24]
	/* ---- c2 = round((k * G2) >> 384) ---- */
	mov x0, x19
	mov x1, x25
	adrp x2, G2_LIMBS
	add  x2, x2, :lo12:G2_LIMBS
	bl   sc_mul_512
	ldr x4, [x19, #40]
	lsr x4, x4, #63
	ldr x5, [x19, #48]
	adds x5, x5, x4
	str x5, [x21, #0]
	ldr x5, [x19, #56]
	adc x5, x5, xzr
	str x5, [x21, #8]
	adc x5, xzr, xzr
	str x5, [x21, #16]
	str xzr, [x21, #24]
	/* ---- c1 *= MINUS_B1 ; c2 *= MINUS_B2 (mod n; sc_mul stages its own
	 *      inputs, so in-place is fine) ---- */
	mov x0, x20
	mov x1, x20
	adrp x2, MINUS_B1_LIMBS
	add  x2, x2, :lo12:MINUS_B1_LIMBS
	bl   sc_mul
	mov x0, x21
	mov x1, x21
	adrp x2, MINUS_B2_LIMBS
	add  x2, x2, :lo12:MINUS_B2_LIMBS
	bl   sc_mul
	/* ---- r2 = c1 + c2 ---- */
	mov x0, x24
	mov x1, x20
	mov x2, x21
	bl   sc_add
	/* ---- t = r2 * LAMBDA ; r1 = k - t ---- */
	mov x0, x19                 /* t (prod area reused) */
	mov x1, x24
	adrp x2, LAMBDA_LIMBS
	add  x2, x2, :lo12:LAMBDA_LIMBS
	bl   sc_mul
	mov x0, x23
	mov x1, x25
	mov x2, x19
	bl   sc_sub
	/* ---- permanent identity check: LAMBDA*r2 + r1 == k ---- */
	mov x0, x19
	adrp x1, LAMBDA_LIMBS
	add  x1, x1, :lo12:LAMBDA_LIMBS
	mov x2, x24
	bl   sc_mul
	mov x0, x19
	mov x1, x19
	mov x2, x23
	bl   sc_add
	ldr x4, [x19, #0]
	ldr x5, [x25, #0]
	cmp  x4, x5
	b.ne .bad
	ldr x4, [x19, #8]
	ldr x5, [x25, #8]
	cmp  x4, x5
	b.ne .bad
	ldr x4, [x19, #16]
	ldr x5, [x25, #16]
	cmp  x4, x5
	b.ne .bad
	ldr x4, [x19, #24]
	ldr x5, [x25, #24]
	cmp  x4, x5
	b.ne .bad
	mov w0, #1
	b    .out
.bad:
	mov w0, #0
.out:
	ldp x25, x26, [sp, #192]
	ldp x23, x24, [sp, #176]
	ldp x21, x22, [sp, #160]
	ldp x19, x20, [sp, #144]
	ldp x29, x30, [sp], #224
	ret
	.size sc_split_lambda, .-sc_split_lambda
