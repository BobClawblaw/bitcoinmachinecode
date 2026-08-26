/* ============================================================================
 * bitcoin_witness_segwit.S -- AArch64 port of the witness-v0 classification
 * helpers that asm/bitcoin_txv_classify.asm links against as C
 * (bitcoin_witness_v0.c). Providing them as AArch64 keeps txv_classify fully
 * self-contained asm. Same public ABI as the C twins:
 *
 *   int  sv_is_p2sh(const u8* spk, size_t spl)      -> 1/0
 *   int  sv_last_push(const u8* ss, u32 ssl, const u8** data, u32* len, u32* npush)
 *   int  sv_classify_segwit(const u8* spk, u32 spl, const u8* ss, u32 ssl,
 *                           u32* version, const u8** prog, u32* proglen, int* wrapped)
 *        -> 1 native / 2 P2SH-wrapped / -1 malleated-or-hash-mismatch / 0 legacy
 *
 * Uses the already-ported sv_witness_program_asm (bitcoin_segwit_classify.S)
 * and hash160. Mirrors bitcoin_witness_v0.c exactly (semantics not reinvented).
 * ========================================================================== */

	.text
	.global sv_is_p2sh
	.type sv_is_p2sh, %function
	.global sv_last_push
	.type sv_last_push, %function
	.global sv_classify_segwit
	.type sv_classify_segwit, %function

	.extern sv_witness_program_asm
	.extern hash160

/* ============================================================================
 * sv_is_p2sh(spk, spl) -> 1 if P2SH : 23 bytes, OP_HASH160 (0xa9),
 *   0x14, <20-byte hash>, OP_EQUAL (0x87).
 * ========================================================================== */
sv_is_p2sh:
	cmp  x1, #23
	b.ne .P2sh_no
	ldrb w9, [x0]
	cmp  w9, #0xa9
	b.ne .P2sh_no
	ldrb w9, [x0, #1]
	cmp  w9, #0x14
	b.ne .P2sh_no
	ldrb w9, [x0, #22]
	cmp  w9, #0x87
	b.ne .P2sh_no
	mov  w0, #1
	ret
.P2sh_no:
	mov  w0, #0
	ret
	.size sv_is_p2sh, .-sv_is_p2sh

/* ============================================================================
 * sv_last_push(ss, ssl, &data, &len, &npush) -> 1/0
 *   Walks a push-only scriptSig, returns its LAST push. Mirrors the C:
 *     op<=0x4b : push op; 0x4c/0x4d/0x4e : PUSHDATA1/2/4;
 *     0x00/0x4f/0x51-0x60 : empty push; any other non-push opcodes -> 0.
 *   Regs: x5=p, x6=n, x7=d, x8=dl (callee-saved below).
 * ========================================================================== */
sv_last_push:
	stp  x19, x20, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	mov  x19, x0                 /* ss */
	mov  x20, x1                 /* ssl */
	mov  x5, #0                  /* p */
	mov  x6, #0                  /* n */
	mov  x7, #0                  /* d */
	mov  x8, #0                  /* dl */
.Slp_loop:
	cmp  x5, x20
	b.hs .Slp_done
	ldrb w9, [x19, x5]           /* op */
	cmp  w9, #0x4b
	b.hi .Slp_checkbig
	add  x10, x5, #1
	uxtw x11, w9
	add  x10, x10, x11           /* p+1+op */
	cmp  x10, x20
	b.hi .Slp_fail
	add  x7, x19, x5
	add  x7, x7, #1              /* d = ss+p+1 */
	mov  x8, x11                 /* dl = op */
	mov  x5, x10
	b    .Slp_pushdone
.Slp_checkbig:
	cmp  w9, #0x4c
	b.eq .Slp_pd1
	cmp  w9, #0x4d
	b.eq .Slp_pd2
	cmp  w9, #0x4e
	b.eq .Slp_pd4
	cmp  w9, #0x00
	b.eq .Slp_small
	cmp  w9, #0x4f               /* OP_1NEGATE */
	b.eq .Slp_small
	cmp  w9, #0x51
	b.lo .Slp_fail               /* 0x50 + "reserved" below OP_1 -> not push-only */
	cmp  w9, #0x60
	b.hi .Slp_fail
	b    .Slp_small
.Slp_pd1:
	add  x10, x5, #2
	cmp  x10, x20
	b.hi .Slp_fail
	add  x9, x5, #1
	ldrb w8, [x19, x9]           /* dl = ss[p+1] */
	add  x10, x5, #2
	uxtw x11, w8
	add  x10, x10, x11           /* p+2+dl */
	cmp  x10, x20
	b.hi .Slp_fail
	add  x7, x19, x5
	add  x7, x7, #2              /* d = ss+p+2 */
	mov  x5, x10
	b    .Slp_pushdone
.Slp_pd2:
	add  x10, x5, #3
	cmp  x10, x20
	b.hi .Slp_fail
	add  x9, x5, #1
	ldrb w9, [x19, x9]
	add  x9, x5, #2
	ldrb w10, [x19, x9]
	orr  w8, w9, w10, lsl #8     /* dl = ss[p+1] | ss[p+2]<<8 */
	add  x10, x5, #3
	uxtw x11, w8
	add  x10, x10, x11           /* p+3+dl */
	cmp  x10, x20
	b.hi .Slp_fail
	add  x7, x19, x5
	add  x7, x7, #3              /* d = ss+p+3 */
	mov  x5, x10
	b    .Slp_pushdone
.Slp_pd4:
	add  x9, x5, #1
	ldr  w8, [x19, x9]           /* dl = ss[p+1..p+4] LE u32 */
	add  x10, x5, #5
	uxtw x11, w8
	add  x10, x10, x11           /* p+5+dl */
	cmp  x10, x20
	b.hi .Slp_fail
	add  x7, x19, x5
	add  x7, x7, #5              /* d = ss+p+5 */
	mov  x5, x10
	b    .Slp_pushdone
.Slp_small:
	add  x7, x19, x5
	mov  x8, #0
	add  x5, x5, #1
.Slp_pushdone:
	add  x6, x6, #1
	b    .Slp_loop
.Slp_done:
	cbz  x6, .Slp_fail
	str  x7, [x2]                /* *data = d */
	str  w8, [x3]                /* *len = dl */
	str  w6, [x4]                /* *npush = n */
	mov  w0, #1
	b    .Slp_ret
.Slp_fail:
	mov  w0, #0
.Slp_ret:
	ldp  x29, x30, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size sv_last_push, .-sv_last_push

/* ============================================================================
 * sv_classify_segwit(spk, spl, ss, ssl, &version, &prog, &proglen, &wrapped)
 *   Regs: x19=spk x20=spl x21=ss x22=ssl x23=&version x24=&prog x25=&proglen
 *         x26=&wrapped. hash[20]@sp.
 * ========================================================================== */
sv_classify_segwit:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #48             /* hash[20]@sp, rd@sp+20, rl@sp+28, np@sp+32 */
	mov  x19, x0
	mov  x20, x1
	mov  x21, x2
	mov  x22, x3
	mov  x23, x4
	mov  x24, x5
	mov  x25, x6
	mov  x26, x7
	str  wzr, [x26]              /* *wrapped = 0 */
	/* native: sv_witness_program_asm(spk, spl, &ver, &prog, &plen) */
	mov  x0, x19
	mov  x1, x20
	mov  x2, x23
	mov  x3, x24
	mov  x4, x25
	bl   sv_witness_program_asm
	cbz  x0, .Sc_p2sh
	mov  w0, #1
	b    .Sc_ret
.Sc_p2sh:
	/* sv_is_p2sh(spk, spl) */
	mov  x0, x19
	mov  x1, x20
	bl   sv_is_p2sh
	cbz  x0, .Sc_legacy
	/* sv_last_push(ss, ssl, &rd, &rl, &np) -- rd@sp+20 rl@sp+24 np@sp+28 */
	mov  x0, x21
	mov  x1, x22
	add  x2, sp, #20            /* rd */
	add  x3, sp, #28            /* rl */
	add  x4, sp, #32            /* np */
	bl   sv_last_push
	cbz  x0, .Sc_legacy
	/* sv_witness_program_asm(rd, rl, &ver, &prog, &plen) */
	ldr  x0, [sp, #20]           /* rd */
	ldr  w1, [sp, #28]           /* rl */
	mov  x2, x23
	mov  x3, x24
	mov  x4, x25
	bl   sv_witness_program_asm
	cbz  x0, .Sc_legacy
	/* np != 1 || ssl != 1+rl || ss[0] != rl  -> -1 (malleated P2SH) */
	ldr  w9, [sp, #32]           /* np */
	cmp  w9, #1
	b.ne .Sc_mal
	ldr  w9, [sp, #28]           /* rl */
	add  x10, x9, #1
	cmp  x22, x10
	b.ne .Sc_mal
	ldrb w10, [x21]              /* ss[0] */
	cmp  w10, w9
	b.ne .Sc_mal
	/* hash160(rd, rl, hash) ; memcmp(hash, spk+2, 20) != 0 -> -1 */
	mov  x0, sp
	ldr  x1, [sp, #20]
	ldr  w2, [sp, #28]
	bl   hash160
	ldr  x0, [x19, #2]           /* spk+2, bytes 0-7 */
	ldr  x1, [sp]
	cmp  x0, x1
	b.ne .Sc_mal_l
	ldr  x0, [x19, #10]          /* bytes 8-15 */
	ldr  x1, [sp, #8]
	cmp  x0, x1
	b.ne .Sc_mal_l
	ldr  w0, [x19, #18]          /* bytes 16-19 (4B: don't over-read) */
	ldr  w1, [sp, #16]
	cmp  w0, w1
	b.ne .Sc_mal_l
	mov  w0, #2
	b    .Sc_wrapped
.Sc_mal:
	mov  x0, #-1
	b    .Sc_ret
.Sc_mal_l:
	mov  x0, #-1
	b    .Sc_ret
.Sc_wrapped:
	mov  w9, #1
	str  w9, [x26]              /* *wrapped = 1 */
	mov  w0, #2
	b    .Sc_ret
.Sc_legacy:
	mov  w0, #0
.Sc_ret:
	add  sp, sp, #48
	ldp  x29, x30, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size sv_classify_segwit, .-sv_classify_segwit

	.section .note.GNU-stack,"",%progbits
