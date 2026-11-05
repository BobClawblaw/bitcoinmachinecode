/* ============================================================================
 * bitcoin_tx.S -- macOS (Darwin/Mach-O) AArch64 port of asm/bitcoin_tx.asm
 *
 * Branch: bmc_osx.  Public symbols (Mach-O `_`-prefixed), identical contracts:
 *   int tx_parse(txinfo *info, const u8 *tx, u64 txlen)   x0,x1,x2 -> w0
 *       info (64 bytes): +0 u64 tx_len | +8 u32 version | +12 u32 n_in |
 *       +16 u32 n_out | +20 u32 locktime | +24 u64 in0_script |
 *       +32 u64 in0_script_len | +40 u64 out0_value | +48 u64 out0_script |
 *       +56 u64 out0_script_len
 *   int tx_txid(u8 out[32], const u8 *tx, u64 txlen, u8 *buf, u64 buflen)
 *                                                          x0..x4 -> w0
 *       txid = sha256d(unwitnessed serialization reconstructed into buf).
 *
 * Semantics mirrored EXACTLY from the x86 original, including the VAL-8
 * audit hardening: every field read bounds-checks its width against `end`
 * BEFORE the load, every decoded count/length is capped at Core's MAX_SIZE
 * (0x02000000) where the x86 caps it, non-canonical CompactSize encodings
 * are accepted (the x86 accepts them too), and success does NOT require
 * cursor == end (txlen may carry trailing bytes).  tx_txid caps MAX_SIZE
 * only on the 0xff scriptlen branches and on the n_in/n_out counts, exactly
 * like the x86 (the 0xfd/0xfe scriptlen branches there are uncapped; the
 * `next <= end` check still rejects them for any real buffer).
 *
 * Darwin notes:
 *   - extern calls: `bl _sha256d` (bitcoin_hash.S), `bl _memcpy` (libSystem).
 *     sp is 16-byte aligned at every bl site; x30 saved in the frame.
 *   - x18/x28 untouched.  Temps x9-x15; state in x19-x27 (saved).
 *   - Internal varint helper .Ltx_varint is entered with `bl` and returns
 *     with `ret`; it NEVER branches to the function's fail label (that
 *     would return to the bl site, not the caller).  It reports truncation
 *     by clearing x11; every call site does `cbz x11, .Lfail`.
 *     Helper ABI: x9 = cursor in/out, x10 = decoded value (u64),
 *     x11 = 1 ok / 0 truncated, x12 = 1 iff the 0xff (8-byte) branch was
 *     taken (tx_txid needs that for its width-conditional cap).
 * ========================================================================== */

	.section	__TEXT,__text
	.globl	_tx_parse
	.globl	_tx_txid

/* MAX_SIZE = 0x02000000 (Core serialize.h ReadCompactSize range cap) */

/* ---------------------------------------------------------------------------
 * Shared CompactSize decoder (internal).
 * --------------------------------------------------------------------------- */
	.align	2
.Ltx_varint:
	mov	w11, #1			/* assume ok */
	mov	w12, #0			/* not the 0xff branch */
	cmp	x9, x21
	b.hs	.Ltxv_trunc
	ldrb	w10, [x9]
	cmp	w10, #0xfd
	b.lo	.Ltxv_1
	b.eq	.Ltxv_2
	cmp	w10, #0xfe
	b.eq	.Ltxv_4
	/* 0xff -> 8-byte payload */
	add	x13, x9, #9
	cmp	x13, x21
	b.hi	.Ltxv_trunc
	ldr	x10, [x9, #1]
	add	x9, x9, #9
	mov	w12, #1
	ret
.Ltxv_2:
	add	x13, x9, #3
	cmp	x13, x21
	b.hi	.Ltxv_trunc
	ldrh	w10, [x9, #1]
	add	x9, x9, #3
	ret
.Ltxv_4:
	add	x13, x9, #5
	cmp	x13, x21
	b.hi	.Ltxv_trunc
	ldr	w10, [x9, #1]
	add	x9, x9, #5
	ret
.Ltxv_1:
	add	x9, x9, #1
	ret
.Ltxv_trunc:
	mov	w11, #0
	ret

/* ---------------------------------------------------------------------------
 * tx_parse(info, tx, txlen) -> w0 = 1 valid / 0 invalid
 *   x19 = info   x20 = base   x21 = end   x22 = cursor
 *   x23 = n_in (original count, for input[0]/output[0] detection)
 *   x24 = loop counter   x25 = segwit flag   x26 = scriptlen/item count
 *   temps x9-x15
 * --------------------------------------------------------------------------- */
	.align	2
_tx_parse:
	stp	x29, x30, [sp, #-16]!
	stp	x19, x20, [sp, #-16]!
	stp	x21, x22, [sp, #-16]!
	stp	x23, x24, [sp, #-16]!
	stp	x25, x26, [sp, #-16]!

	mov	x19, x0			/* info */
	mov	x20, x1			/* base */
	mov	x21, x2
	add	x21, x20, x21		/* end = tx + txlen */
	mov	x22, x20		/* cursor */

	/* ---- version (4 bytes) ---- */
	add	x9, x22, #4
	cmp	x9, x21
	b.hi	.Ltxp_fail
	ldr	w9, [x22]
	str	w9, [x19, #8]		/* info.version */
	add	x22, x22, #4

	/* ---- SegWit marker/flag detection ---- */
	mov	w25, #0			/* legacy */
	add	x9, x22, #2
	cmp	x9, x21
	b.hi	.Ltxp_read_nin
	ldrb	w9, [x22]
	cbnz	w9, .Ltxp_read_nin
	ldrb	w9, [x22, #1]
	cmp	w9, #1
	b.ne	.Ltxp_read_nin
	mov	w25, #1
	add	x22, x22, #2

.Ltxp_read_nin:
	/* ---- varint n_in ---- */
	mov	x9, x22
	bl	.Ltx_varint
	cbz	x11, .Ltxp_fail
	mov	x22, x9
	/* cap MAX_SIZE (count) */
	mov	x14, x10		/* decoded count */
	mov	x9, #0x02000000
	cmp	x14, x9
	b.hi	.Ltxp_fail
	str	w14, [x19, #12]		/* info.n_in */
	mov	x23, x14		/* n_in for first-input test */
	mov	x24, x14		/* counter */

.Ltxp_next_in:
	cbz	x24, .Ltxp_ins_done
	/* prevout 32 bytes */
	add	x9, x22, #32
	cmp	x9, x21
	b.hi	.Ltxp_fail
	add	x22, x22, #32
	/* index 4 bytes */
	add	x9, x22, #4
	cmp	x9, x21
	b.hi	.Ltxp_fail
	add	x22, x22, #4
	/* scriptlen varint (VAL-8: first-byte bound inside helper) */
	mov	x9, x22
	bl	.Ltx_varint
	cbz	x11, .Ltxp_fail
	mov	x22, x9
	mov	x26, x10
	mov	x9, #0x02000000
	cmp	x26, x9
	b.hi	.Ltxp_fail
	/* script bytes */
	add	x9, x22, x26
	cmp	x9, x21
	b.hi	.Ltxp_fail
	/* seq 4 bytes */
	add	x9, x9, #4
	cmp	x9, x21
	b.hi	.Ltxp_fail
	/* first input? counter == n_in */
	mov	x22, x9			/* cursor = past seq (FIRST: x86 advances
					   the cursor before the in0 math) */
	cmp	x24, x23
	b.ne	.Ltxp_not_in0
	sub	x15, x9, x26		/* seq_end - len = script_start + 4 */
	sub	x15, x15, #4		/* script_start */
	sub	x9, x15, x20		/* in0_script offset from base */
	str	x9, [x19, #24]
	str	x26, [x19, #32]		/* in0_script_len */
.Ltxp_not_in0:
	sub	x24, x24, #1
	b	.Ltxp_next_in

.Ltxp_ins_done:
	/* ---- varint n_out ---- */
	mov	x9, x22
	bl	.Ltx_varint
	cbz	x11, .Ltxp_fail
	mov	x22, x9
	mov	x14, x10
	mov	x9, #0x02000000
	cmp	x14, x9
	b.hi	.Ltxp_fail
	str	w14, [x19, #16]		/* info.n_out */
	mov	x24, x14		/* counter */
	mov	x23, x14		/* n_out for output[0] detection */

.Ltxp_next_out:
	cbz	x24, .Ltxp_outs_done
	/* output[0] value offset */
	cmp	x24, x23
	b.ne	.Ltxp_not_out0v
	sub	x9, x22, x20
	str	x9, [x19, #40]		/* out0_value offset */
.Ltxp_not_out0v:
	/* value 8 bytes */
	add	x9, x22, #8
	cmp	x9, x21
	b.hi	.Ltxp_fail
	add	x22, x22, #8
	/* scriptlen varint */
	mov	x9, x22
	bl	.Ltx_varint
	cbz	x11, .Ltxp_fail
	mov	x22, x9
	mov	x26, x10
	mov	x9, #0x02000000
	cmp	x26, x9
	b.hi	.Ltxp_fail
	/* output[0] script offset/len (cursor is at script start now) */
	cmp	x24, x23
	b.ne	.Ltxp_not_out0s
	sub	x9, x22, x20
	str	x9, [x19, #48]		/* out0_script offset */
	str	x26, [x19, #56]		/* out0_script_len */
.Ltxp_not_out0s:
	/* script bytes */
	add	x9, x22, x26
	cmp	x9, x21
	b.hi	.Ltxp_fail
	mov	x22, x9
	sub	x24, x24, #1
	b	.Ltxp_next_out

.Ltxp_outs_done:
	/* ---- skip SegWit witness data ---- */
	cbz	w25, .Ltxp_nowit
	ldr	w24, [x19, #12]		/* witness n_in (reload: x23 now = n_out) */
.Ltxp_next_wit_in:
	cbz	x24, .Ltxp_nowit
	/* varint item count */
	mov	x9, x22
	bl	.Ltx_varint
	cbz	x11, .Ltxp_fail
	mov	x22, x9
	mov	x26, x10
	mov	x9, #0x02000000
	cmp	x26, x9
	b.hi	.Ltxp_fail
.Ltxp_next_wit_item:
	cbz	x26, .Ltxp_wit_in_done
	/* varint item len */
	mov	x9, x22
	bl	.Ltx_varint
	cbz	x11, .Ltxp_fail
	mov	x22, x9
	mov	x14, x10
	mov	x9, #0x02000000
	cmp	x14, x9
	b.hi	.Ltxp_fail
	/* skip item bytes */
	add	x9, x22, x14
	cmp	x9, x21
	b.hi	.Ltxp_fail
	mov	x22, x9
	sub	x26, x26, #1
	b	.Ltxp_next_wit_item
.Ltxp_wit_in_done:
	sub	x24, x24, #1
	b	.Ltxp_next_wit_in

.Ltxp_nowit:
	/* ---- locktime (4 bytes) ---- */
	add	x9, x22, #4
	cmp	x9, x21
	b.hi	.Ltxp_fail
	ldr	w10, [x22]
	str	w10, [x19, #20]		/* info.locktime */
	mov	x22, x9			/* cursor past locktime (x9 was the ADDRESS,
				   x10 the value -- storing x9 as cursor was
				   the tx_len corruption) */

	/* total consumed */
	sub	x9, x22, x20
	str	x9, [x19, #0]		/* info.tx_len */
	mov	w0, #1
	b	.Ltxp_out
.Ltxp_fail:
	mov	w0, #0
.Ltxp_out:
	ldp	x25, x26, [sp], #16
	ldp	x23, x24, [sp], #16
	ldp	x21, x22, [sp], #16
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16
	ret

/* ---------------------------------------------------------------------------
 * tx_txid(out32, tx, txlen, buf, buflen) -> w0 = 1 valid / 0 invalid
 *   x19 = out  x20 = tx  x21 = end  x22 = buf  x23 = buflen
 *   x24 = mid_len (callee-saved: survives memcpy/sha256d)
 *   x25 = cursor  x26 = segwit flag  x27 = inputs_start
 *   temps x9-x13 only across .Ltx_varint (helper contract: touches x9-x13,
 *   returns x10=value x11=ok x12=ff-branch); NOTHING caller-saved lives
 *   across _memcpy/_sha256d (AAPCS64 clobbers x0-x17).
 * --------------------------------------------------------------------------- */
	.align	2
_tx_txid:
	stp	x29, x30, [sp, #-16]!
	stp	x19, x20, [sp, #-16]!
	stp	x21, x22, [sp, #-16]!
	stp	x23, x24, [sp, #-16]!
	stp	x25, x26, [sp, #-16]!
	stp	x27, x27, [sp, #-16]!

	mov	x19, x0			/* out */
	mov	x20, x1			/* tx */
	mov	x22, x3			/* buf */
	mov	x23, x4			/* buflen */
	add	x21, x20, x2		/* end = tx + txlen (helper reads x21) */
	add	x27, x20, #4		/* inputs_start (legacy) */
	mov	x25, x27		/* cursor */

	/* ---- detect SegWit marker (version | 0x00 0x01) ---- */
	mov	w26, #0
	add	x9, x20, #6
	cmp	x9, x21
	b.hi	.Ltxi_det_done
	ldrb	w9, [x20, #4]
	cbnz	w9, .Ltxi_det_done
	ldrb	w9, [x20, #5]
	cmp	w9, #1
	b.ne	.Ltxi_det_done
	mov	w26, #1
.Ltxi_det_done:
	add	x27, x20, #4		/* inputs_start (legacy) */
	cbz	w26, .Ltxi_have_cur
	add	x27, x20, #6
	mov	x25, x27		/* cursor for segwit */
.Ltxi_have_cur:

	/* ---- varint n_in ---- */
	mov	x9, x25
	bl	.Ltx_varint
	cbz	x11, .Ltxi_fail
	mov	x25, x9
	mov	x14, x10
	mov	x9, #0x02000000
	cmp	x14, x9
	b.hi	.Ltxi_fail
	mov	x15, x14		/* loop counter (helper touches x9-x13 only) */

.Ltxi_next_in:
	cbz	x15, .Ltxi_ins_done
	/* fixed 36 bytes */
	add	x9, x25, #36
	cmp	x9, x21
	b.hi	.Ltxi_fail
	/* need >= 1 byte for the scriptlen varint (x9 == end -> fail) */
	cmp	x9, x21
	b.hs	.Ltxi_fail
	bl	.Ltx_varint
	cbz	x11, .Ltxi_fail
	/* width-conditional cap: only the 0xff branch is capped on x86 */
	cbz	w12, .Ltxi_s_nocap
	mov	x9, #0x02000000
	cmp	x10, x9
	b.hi	.Ltxi_fail
.Ltxi_s_nocap:
	/* next = varint_end + len + 4 */
	add	x9, x9, x10
	add	x9, x9, #4
	cmp	x9, x21
	b.hi	.Ltxi_fail
	mov	x25, x9
	sub	x15, x15, #1
	b	.Ltxi_next_in
.Ltxi_ins_done:

	/* ---- varint n_out ---- */
	mov	x9, x25
	bl	.Ltx_varint
	cbz	x11, .Ltxi_fail
	mov	x25, x9
	mov	x14, x10
	mov	x9, #0x02000000
	cmp	x14, x9
	b.hi	.Ltxi_fail
	mov	x15, x14

.Ltxi_next_out:
	cbz	x15, .Ltxi_outs_done
	/* value 8 bytes */
	add	x9, x25, #8
	cmp	x9, x21
	b.hi	.Ltxi_fail
	/* scriptlen varint at cursor+8 */
	cmp	x9, x21
	b.hs	.Ltxi_fail
	bl	.Ltx_varint
	cbz	x11, .Ltxi_fail
	cbz	w12, .Ltxi_p_nocap
	mov	x9, #0x02000000
	cmp	x10, x9
	b.hi	.Ltxi_fail
.Ltxi_p_nocap:
	add	x9, x9, x10
	cmp	x9, x21
	b.hi	.Ltxi_fail
	mov	x25, x9
	sub	x15, x15, #1
	b	.Ltxi_next_out
.Ltxi_outs_done:
	/* x25 = outputs_end */

	/* locktime start = end - 4 must be >= outputs_end */
	sub	x9, x21, #4
	cmp	x9, x25
	b.lo	.Ltxi_fail

	/* ---- reconstruct unwitnessed into buf ---- */
	sub	x24, x25, x27		/* mid_len (x24 callee-saved) */
	add	x9, x24, #8		/* unwit_len = 4 + mid + 4 */
	cmp	x9, x23
	b.hi	.Ltxi_fail
	/* version 4 bytes */
	mov	x0, x22
	mov	x1, x20
	mov	x2, #4
	bl	_memcpy
	/* mid */
	add	x0, x22, #4
	mov	x1, x27
	mov	x2, x24
	bl	_memcpy
	/* locktime 4 bytes at tx + txlen - 4 = end - 4 */
	add	x0, x22, #4
	add	x0, x0, x24
	sub	x1, x21, #4
	mov	x2, #4
	bl	_memcpy
	/* sha256d(out, buf, unwit_len) */
	mov	x0, x19
	mov	x1, x22
	add	x2, x24, #8
	bl	_sha256d
	mov	w0, #1
	b	.Ltxi_ret
.Ltxi_fail:
	mov	w0, #0
.Ltxi_ret:
	/* ldp x27,x27,[sp],#16 is CONSTRAINED UNPREDICTABLE (Rt==Rt2) and
	 * raises SIGILL on Apple Silicon.  Pop the doubled x27 slot with a
	 * single ldr; the pair's second 8 bytes are simply not addressed --
	 * fold them into the next ldp by popping x27 from [sp] and letting
	 * the following ldp take [sp+8].  Total pop must stay 96 bytes:
	 * ldr (8) + add (8) + 5x ldp (80) = 96, sp stays 16-aligned. */
	ldr	x27, [sp], #8
	add	sp, sp, #8
	ldp	x25, x26, [sp], #16
	ldp	x23, x24, [sp], #16
	ldp	x21, x22, [sp], #16
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16
	ret
