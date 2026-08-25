/* ============================================================================
 * bitcoin_script.S -- AArch64 port of the sig-preproc helpers from
 * asm/bitcoin_script.asm (Phase-2 slice that provides be_to_limbs +
 * der_parse_sig). These are the pre-processing half of checksig.
 *
 *   void be_to_limbs(u64 out[4], const u8* bytes, u64 len)
 *        -> 1..32 big-endian integer bytes -> 4 little-endian limbs,
 *           zero-padded on the left; out[0] = low 64 bits. Clobbers only
 *           x0-x9; preserves x19-x28, sp.
 *
 *   int der_parse_sig(const u8* sig, u64 slen,
 *                     u64 r_out[4], u64 s_out[4], int* hashtype)
 *        -> w0 1/0. Parses a minimal-ish DER ECDSA signature; strips ANY
 *           redundant leading 0x00 down to <=32 significant bytes each for
 *           r and s (pre-BIP66 tolerant -- a mainnet spend at height 124275
 *           has 34-byte r AND s with double leading zeros); optional 0x01
 *           hashtype byte after s (dht=1 else 0).
 *   AAPCS64: x0=sig x1=slen x2=r_out x3=s_out x4=&hashtype.
 * ========================================================================== */

	.text
	.global be_to_limbs
	.type be_to_limbs, %function
be_to_limbs:
	/* x0=out, x1=bytes, x2=len (1..32) */
	sub  sp, sp, #48
	/* zero buf[0..31] at sp */
	stp  xzr, xzr, [sp, #0]
	stp  xzr, xzr, [sp, #16]
	/* dest = buf + (32-len) */
	mov  x5, #32
	sub  x5, x5, x2
	add  x5, sp, x5
	/* copy len bytes x1 -> x5 */
	mov  x6, x1
0:	cbz  x2, 1f
	ldrb w7, [x6]
	strb w7, [x5]
	add  x6, x6, #1
	add  x5, x5, #1
	sub  x2, x2, #1
	b    0b
1:	/* limbs: out[j] = rev(buf + (3-j)*8) */
	mov  x7, #0                  /* j */
2:	cmp  x7, #4
	b.hs 3f
	mov  x8, #3
	sub  x8, x8, x7
	lsl  x8, x8, #3
	ldr  x9, [sp, x8]
	rev  x9, x9
	str  x9, [x0, x7, lsl #3]
	add  x7, x7, #1
	b    2b
3:	add  sp, sp, #48
	ret
	.size be_to_limbs, .-be_to_limbs

	.global der_parse_sig
	.type der_parse_sig, %function
der_parse_sig:
	/* x0=sig x1=slen x2=r_out x3=s_out x4=&hashtype
	   Frame locals at [sp]: +0 r_out, +8 s_out, +16 ht_ptr */
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	sub  sp, sp, #32            /* locals: [sp+0] r_out [sp+8] s_out [sp+16] ht_ptr */
	str  x2, [sp, #0]            /* r_out */
	str  x3, [sp, #8]            /* s_out */
	str  x4, [sp, #16]           /* ht_ptr */
	mov  x19, x0                 /* sig */
	mov  x20, x1                 /* slen */
	cmp  x20, #8
	b.lo .dps_fail
	ldrb w26, [x19]
	cmp  w26, #0x30
	b.ne .dps_fail
	ldrb w26, [x19, #2]
	cmp  w26, #0x02
	b.ne .dps_fail
	ldrb w8, [x19, #3]
	cbz  w8, .dps_fail
	add  x21, x19, #4            /* r base */
	mov  x22, x8                 /* r len */
	add  x6, x21, x22
	add  x7, x19, x20
	cmp  x6, x7
	b.hi .dps_fail
.r_strip:
	cmp  x22, #32
	b.ls .r_norm
	ldrb w8, [x21]
	cbnz w8, .dps_fail
	add  x21, x21, #1
	sub  x22, x22, #1
	b    .r_strip
.r_norm:
	ldr  x0, [sp, #0]
	mov  x1, x21
	mov  x2, x22
	bl   be_to_limbs
	/* s marker at [r_base + r_len] */
	add  x23, x21, x22
	ldrb w8, [x23]
	cmp  w8, #0x02
	b.ne .dps_fail
	ldrb w8, [x23, #1]           /* slen */
	cbz  w8, .dps_fail
	mov  x24, x8                 /* s len */
	add  x25, x23, #2            /* s base */
	add  x26, x25, x8            /* s_end (ORIGINAL, unstripped) */
	add  x7, x19, x20
	cmp  x26, x7
	b.hi .dps_fail
.s_strip:
	cmp  x24, #32
	b.ls .s_norm
	ldrb w9, [x25]
	cbnz w9, .dps_fail
	add  x25, x25, #1
	sub  x24, x24, #1
	b    .s_strip
.s_norm:
	ldr  x0, [sp, #8]
	mov  x1, x25
	mov  x2, x24
	bl   be_to_limbs
	/* hashtype: optional 0x01 right after s_end (x26) */
	mov  w9, #0
	add  x7, x19, x20
	cmp  x26, x7
	b.hs .ht_done
	ldrb w10, [x26]
	cmp  w10, #1
	b.ne .ht_done
	mov  w9, #1
.ht_done:
	ldr  x11, [sp, #16]
	str  w9, [x11]
	mov  w0, #1
	b    .dps_done
.dps_fail:
	mov  w0, #0
.dps_done:
	add  sp, sp, #32            /* drop locals */
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size der_parse_sig, .-der_parse_sig

	.section .note.GNU-stack,"",%progbits
