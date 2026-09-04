/* ============================================================================
 * bitcoin_pubkey.S -- AArch64 (ARMv8-A) port of asm/bitcoin_pubkey.asm
 *
 *   void fe_pow(u64 out[4], const u64 base[4], const u64 exp[4])
 *        out = base^exp mod p  (MSB-first square-and-multiply, exp != 0)
 *   int  pubkey_parse(const u8* pub, u64 publen, u64 qx[4], u64 qy[4])
 *        parse compressed (33B 0x02/0x03) or uncompressed (65B 0x04) SEC1
 *        secp256k1 pubkey -> affine (qx,qy) as 4 LE limbs. Returns 1/0.
 *        y = sqrt(x^3+7) via exponent (p+1)/4, verifies y^2, fixes parity
 *        (compressed), or verifies the supplied y^2 (uncompressed).
 *
 * AAPCS64: fe_pow(x0,x1,x2); pubkey_parse(x0=pub,x1=publen,x2=qx,x3=qy).
 * Calls fe_sqr/fe_mul/fe_add/fe_sub (leaf, preserve x19+).
 * ========================================================================== */
	.text
	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm

	.section .rodata
	.balign 16
P_LIMBS:
	.quad 0xFFFFFFFEFFFFFC2F
	.quad 0xFFFFFFFFFFFFFFFF
	.quad 0xFFFFFFFFFFFFFFFF
	.quad 0xFFFFFFFFFFFFFFFF
	.balign 16
CURVE7:
	.quad 7, 0, 0, 0
	.balign 16
/* (p+1)/4 (QR/sqrt exponent) */
EXP_QR:
	.quad 0xFFFFFFFFBFFFFF0C
	.quad 0xFFFFFFFFFFFFFFFF
	.quad 0xFFFFFFFFFFFFFFFF
	.quad 0x3FFFFFFFFFFFFFFF
	.text

/* ============================================================================
 * fe_pow(x0=out, x1=base, x2=exp) -- square-and-multiply, bits 255..0
 * acc@sp+0 tmp@sp+32; persistent x19=out x20=base x21=exp x22=bit.
 * ========================================================================== */
	.global fe_pow
	.type   fe_pow, %function
fe_pow:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	sub  sp, sp, #64
	mov  x19, x0                 /* out */
	mov  x20, x1                 /* base */
	mov  x21, x2                 /* exp */
	/* acc = 1 */
	mov  x4, #1
	str  x4, [sp, #0]
	str  xzr, [sp, #8]
	str  xzr, [sp, #16]
	str  xzr, [sp, #24]
	mov  x22, #255               /* bit index */
.Lpb1:
	/* acc = acc^2 : fe_sqr(tmp@32, acc@0) */
	add  x0, sp, #32
	mov  x1, sp
	bl   fe_sqr
	/* acc = tmp */
	ldp  x4, x5,  [sp, #32]
	ldp  x6, x7,  [sp, #48]
	stp  x4, x5,  [sp, #0]
	stp  x6, x7,  [sp, #16]
	/* test exp bit x22 */
	lsr  x4, x22, #3
	and  x5, x22, #7
	ldrb w6, [x21, x4]
	lsrv x7, x6, x5
	and  w7, w7, #1
	cbz  x7, 1f
	/* acc = acc*base : fe_mul(tmp@32, acc@0, base) */
	add  x0, sp, #32
	mov  x1, sp
	mov  x2, x20
	bl   fe_mul
	/* acc = tmp */
	ldp  x4, x5,  [sp, #32]
	ldp  x6, x7,  [sp, #48]
	stp  x4, x5,  [sp, #0]
	stp  x6, x7,  [sp, #16]
1:	subs x22, x22, #1
	b.pl .Lpb1
	/* out = acc */
	mov  x0, x19
	ldp  x4, x5,  [sp, #0]
	ldp  x6, x7,  [sp, #16]
	stp  x4, x5,  [x0]
	stp  x6, x7,  [x0, #16]
	add  sp, sp, #64
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size fe_pow, .-fe_pow

/* ============================================================================
 * pubkey_parse(x0=pub, x1=publen, x2=qx, x3=qy)
 * Frame: x@sp+0 xl@sp+32 x2sq@sp+64 x3@sp+96 t@sp+128 y@sp+160 ; sub 192.
 * Persistent x19=pub x20=publen x21=qx x22=qy.
 * ========================================================================== */
	.global pubkey_parse
	.type   pubkey_parse, %function
pubkey_parse:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	sub  sp, sp, #192
	mov  x19, x0                 /* pub */
	mov  x20, x1                 /* publen */
	mov  x21, x2                 /* qx */
	mov  x22, x3                 /* qy */

	/* dispatch on publen */
	cmp  x20, #33
	b.eq .Lpc_comp
	cmp  x20, #65
	beq  .Lpc_uncomp
	mov  w0, #0
	b    .Lp_done

.Lpc_comp:
	ldrb w4, [x19]
	cmp  w4, #0x02
	b.eq 1f
	cmp  w4, #0x03
	b.ne .Lp_bad
1:	/* x-limbs from pub[1..32]: limb[j] = rev(load @pub+1+(3-j)*8) -> sp+32 */
	add  x8, x19, #1
	ldr  x5, [x8, #24]
	rev  x5, x5
	str  x5, [sp, #32]
	ldr  x5, [x8, #16]
	rev  x5, x5
	str  x5, [sp, #40]
	ldr  x5, [x8, #8]
	rev  x5, x5
	str  x5, [sp, #48]
	ldr  x5, [x8, #0]
	rev  x5, x5
	str  x5, [sp, #56]
	/* x2 = x^2 @sp+64 */
	add  x0, sp, #64
	add  x1, sp, #32
	bl   fe_sqr
	/* x3 = x2 * x @sp+96 */
	add  x0, sp, #96
	add  x1, sp, #64
	add  x2, sp, #32
	bl   fe_mul
	/* t = x3 + 7 @sp+128 */
	add  x0, sp, #128
	add  x1, sp, #96
	LAddr x2, CURVE7
	bl   fe_add
	/* y = t^((p+1)/4) @sp+160 */
	add  x0, sp, #160
	add  x1, sp, #128
	LAddr x2, EXP_QR
	bl   fe_pow
	/* y2 = y^2 @sp+64 (reuse); must equal t */
	add  x0, sp, #64
	add  x1, sp, #160
	bl   fe_sqr
	add  x3, sp, #128             /* t */
	ldr  x4, [sp, #64]
	ldr  x5, [x3, #0]
	cmp  x4, x5
	b.ne .Lp_bad
	ldr  x4, [sp, #72]
	ldr  x5, [x3, #8]
	cmp  x4, x5
	b.ne .Lp_bad
	ldr  x4, [sp, #80]
	ldr  x5, [x3, #16]
	cmp  x4, x5
	b.ne .Lp_bad
	ldr  x4, [sp, #88]
	ldr  x5, [x3, #24]
	cmp  x4, x5
	b.ne .Lp_bad
	/* parity fix: want (y&1)==(pub[0]&1) */
	ldrb w4, [x19]
	and  w5, w4, #1
	ldr  x6, [sp, #160]
	and  w7, w6, #1
	cmp  w7, w5
	b.eq .Lpc_store
	/* y = p - y */
	LAddr x8, P_LIMBS
	ldr  x9, [x8, #0]
	ldr  x10, [sp, #160]
	subs x9, x9, x10
	str  x9, [sp, #160]
	ldr  x9, [x8, #8]
	ldr  x10, [sp, #168]
	sbcs x9, x9, x10
	str  x9, [sp, #168]
	ldr  x9, [x8, #16]
	ldr  x10, [sp, #176]
	sbcs x9, x9, x10
	str  x9, [sp, #176]
	ldr  x9, [x8, #24]
	ldr  x10, [sp, #184]
	sbcs x9, x9, x10
	str  x9, [sp, #184]
.Lpc_store:
	/* qx = x @sp+32 ; qy = y @sp+160 */
	mov  x0, x21
	ldp  x4, x5,  [sp, #32]
	ldp  x6, x7,  [sp, #48]
	stp  x4, x5,  [x0]
	stp  x6, x7,  [x0, #16]
	mov  x0, x22
	ldp  x4, x5,  [sp, #160]
	ldp  x6, x7,  [sp, #176]
	stp  x4, x5,  [x0]
	stp  x6, x7,  [x0, #16]
	mov  w0, #1
	b    .Lp_done

.Lpc_uncomp:
	ldrb w4, [x19]
	/* CRY-2 (audit 2026-09-03): libsecp256k1's pubkey parse -- which Core's
	 * CPubKey::Verify uses -- accepts 65-byte keys with prefix 0x04, 0x06,
	 * 0x07. 0x06/0x07 are HYBRID encodings: the prefix carries the y parity
	 * redundantly, and the parse requires (prefix & 1) == (y_last_byte & 1)
	 * before the on-curve check. Core only rejects hybrids under
	 * SCRIPT_VERIFY_STRICTENC, a policy flag NEVER set for block validation,
	 * so a valid signature under a hybrid-encoded key is consensus-valid.
	 * The old branch accepted only 0x04 -> a FALSE REJECT against the live
	 * chain. */
	cmp  w4, #0x04
	b.eq .Lpc_uncomp_ok
	cmp  w4, #0x06
	b.eq .Lpc_hybrid
	cmp  w4, #0x07
	b.eq .Lpc_hybrid
	b    .Lp_bad
.Lpc_hybrid:
	/* (prefix & 1) must equal the parity of the last byte of y (pub[64]). */
	ldrb w5, [x19, #64]
	ubfx w6, w4, #0, #1             /* prefix & 1 */
	ubfx w5, w5, #0, #1             /* y[64] & 1 */
	cmp  w6, w5
	b.ne .Lp_bad
.Lpc_uncomp_ok:
	/* x limbs @sp+32 from pub[1..32]; y limbs @sp+160 from pub[33..64] */
	add  x8, x19, #1
	ldr  x5, [x8, #24]
	rev  x5, x5
	str  x5, [sp, #32]
	ldr  x5, [x8, #16]
	rev  x5, x5
	str  x5, [sp, #40]
	ldr  x5, [x8, #8]
	rev  x5, x5
	str  x5, [sp, #48]
	ldr  x5, [x8, #0]
	rev  x5, x5
	str  x5, [sp, #56]
	add  x8, x19, #33
	ldr  x5, [x8, #24]
	rev  x5, x5
	str  x5, [sp, #160]
	ldr  x5, [x8, #16]
	rev  x5, x5
	str  x5, [sp, #168]
	ldr  x5, [x8, #8]
	rev  x5, x5
	str  x5, [sp, #176]
	ldr  x5, [x8, #0]
	rev  x5, x5
	str  x5, [sp, #184]
	/* verify y^2 == x^3 + 7 */
	add  x0, sp, #64
	add  x1, sp, #32
	bl   fe_sqr                 /* x2 */
	add  x0, sp, #96
	add  x1, sp, #64
	add  x2, sp, #32
	bl   fe_mul                 /* x3 */
	add  x0, sp, #0
	add  x1, sp, #96
	LAddr x2, CURVE7
	bl   fe_add                 /* t @sp+0 */
	add  x0, sp, #64
	add  x1, sp, #160
	bl   fe_sqr                 /* y2 @sp+64 */
	add  x3, sp, #0             /* t */
	ldr  x4, [sp, #64]
	ldr  x5, [x3, #0]
	cmp  x4, x5
	b.ne .Lp_bad
	ldr  x4, [sp, #72]
	ldr  x5, [x3, #8]
	cmp  x4, x5
	b.ne .Lp_bad
	ldr  x4, [sp, #80]
	ldr  x5, [x3, #16]
	cmp  x4, x5
	b.ne .Lp_bad
	ldr  x4, [sp, #88]
	ldr  x5, [x3, #24]
	cmp  x4, x5
	b.ne .Lp_bad
	/* qx = x @sp+32 ; qy = y @sp+160 */
	mov  x0, x21
	ldp  x4, x5,  [sp, #32]
	ldp  x6, x7,  [sp, #48]
	stp  x4, x5,  [x0]
	stp  x6, x7,  [x0, #16]
	mov  x0, x22
	ldp  x4, x5,  [sp, #160]
	ldp  x6, x7,  [sp, #176]
	stp  x4, x5,  [x0]
	stp  x6, x7,  [x0, #16]
	mov  w0, #1
	b    .Lp_done

.Lp_bad:
	mov  w0, #0
.Lp_done:
	add  sp, sp, #192
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size pubkey_parse, .-pubkey_parse

	.section .note.GNU-stack,"",%progbits
