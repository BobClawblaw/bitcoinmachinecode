/* ============================================================================
 * bitcoin_tx.S -- AArch64 (ARMv8-A) port of asm/bitcoin_tx.asm
 *
 * Bitcoin transaction deserializer + txid. AAPCS64 (SysV x64 -> AArch64):
 *   int tx_parse(txinfo *info, const u8 *tx, unsigned long txlen)  // x0,x1,x2 -> w0
 *   int tx_txid (u8 out[32], const u8 *tx, unsigned long txlen,
 *                u8 *buf, unsigned long buflen)                    // x0..x4 -> w0
 *
 * txinfo is 64 bytes (offsets into raw tx):
 *   +0 u64 tx_len ; +8 u32 version ; +12 u32 n_in ; +16 u32 n_out
 *   +20 u32 locktime ; +24 u64 in0_script ; +32 u64 in0_script_len
 *   +40 u64 out0_value ; +48 u64 out0_script ; +56 u64 out0_script_len
 *
 * Wire format (LE): version(4) | [segwit 00 01] | varint n_in | n_in*
 * (prevout32 index4 varint scriptlen script seq4) | varint n_out | n_out*
 * (value8 varint scriptlen script) | [witness] | locktime(4)
 * varint (CompactSize): <0xfd 1B ; 0xfd 2B ; 0xfe 4B ; 0xff 8B.
 * ========================================================================== */

	.text

/* ---------------------------------------------------------------------------
 * macro: decode a CompactSize varint.
 *   rd   = result register number (w\rd/x\rd)
 *   curs = 64-bit register holding cursor (advances past prefix)
 *   end  = 64-bit register holding end bound
 *   fail = fail label
 * uses w17 (first byte), x15 (bound), then sets curs. Numeric locals 41-44.
 * ------------------------------------------------------------------------- */
	.macro VARINTP rd, curs, end, fail
	ldrb w17, [\curs]
	cmp  w17, #0xfd
	b.lo 41f
	cmp  w17, #0xfd
	b.eq 42f
	cmp  w17, #0xfe
	b.eq 43f
	/* 0xff -> 8 bytes */
	add  x15, \curs, #9
	cmp  x15, \end
	b.hi \fail
	ldr  x\rd, [\curs, #1]
	mov  \curs, x15
	b    44f
43:	/* 0xfe -> 4 bytes */
	add  x15, \curs, #5
	cmp  x15, \end
	b.hi \fail
	ldr  w\rd, [\curs, #1]
	mov  \curs, x15
	b    44f
42:	/* 0xfd -> 2 bytes */
	add  x15, \curs, #3
	cmp  x15, \end
	b.hi \fail
	ldrh w\rd, [\curs, #1]
	mov  \curs, x15
	b    44f
41:	/* <0xfd -> 1 byte */
	mov  w\rd, w17
	add  \curs, \curs, #1
44:
	.endm

/* ============================================================================
 * tx_parse(info, tx, txlen) -> w0 = 1 valid / 0 invalid
 * Pure byte-walk, no nested calls -> leaf; uses only caller-saved x0-x17 so no
 * prologue/epilogue is required.
 *   x0 = info ; x3 = base ; x4 = cursor ; x5 = end ; x6 = segwit flag
 * ========================================================================== */
	.global tx_parse
	.type tx_parse, %function
tx_parse:
	mov  x3, x1              /* base */
	add  x5, x1, x2         /* end = tx + txlen */
	mov  x4, x1             /* cursor */

	/* ---- version (4 bytes) ---- */
	add  x10, x4, #4
	cmp  x10, x5
	b.hi .Ltx_fail
	ldr  w9, [x4]
	str  w9, [x0, #8]       /* info.version */
	mov  x4, x10

	/* ---- segwit (BIP141) marker/flag detection ---- */
	mov  w6, #0
	add  x10, x4, #2
	cmp  x10, x5
	b.hi .Ltx_nin           /* too short -> legacy */
	ldrb w9, [x4]
	cbnz w9, .Ltx_nin
	ldrb w9, [x4, #1]
	cmp  w9, #1
	b.ne .Ltx_nin
	mov  w6, #1
	mov  x4, x10
.Ltx_nin:

	/* ---- varint n_in -> x7 ---- */
	VARINTP 7, x4, x5, .Ltx_fail
	str  w7, [x0, #12]      /* info.n_in */

	/* ---- walk n_in inputs ---- */
	mov  x11, x7            /* counter */
.Ltx_next_in:
	cbz  x11, .Ltx_ins_done
	/* prevout 32 */
	add  x10, x4, #32
	cmp  x10, x5
	b.hi .Ltx_fail
	mov  x4, x10
	/* index 4 */
	add  x10, x4, #4
	cmp  x10, x5
	b.hi .Ltx_fail
	mov  x4, x10
	/* scriptlen varint -> x8 */
	VARINTP 8, x4, x5, .Ltx_fail
	/* script bytes + seq(4) */
	add  x10, x4, x8
	cmp  x10, x5
	b.hi .Ltx_fail
	add  x10, x10, #4
	cmp  x10, x5
	b.hi .Ltx_fail
	/* record input[0] script offset/len if first input */
	ldr  w9, [x0, #12]      /* n_in */
	cmp  w11, w9
	mov  x4, x10
	b.ne .Ltx_not_in0
	sub  x9, x10, x8        /* new cursor - len */
	sub  x9, x9, #4         /* - seq */
	sub  x9, x9, x3         /* offset from base */
	str  x9, [x0, #24]      /* in0_script offset */
	str  x8, [x0, #32]      /* in0_script_len */
.Ltx_not_in0:
	sub  x11, x11, #1
	b    .Ltx_next_in
.Ltx_ins_done:

	/* ---- varint n_out -> x7 ---- */
	VARINTP 7, x4, x5, .Ltx_fail
	str  w7, [x0, #16]      /* info.n_out */

	/* ---- walk n_out outputs ---- */
	mov  x11, x7            /* counter */
.Ltx_next_out:
	cbz  x11, .Ltx_outs_done
	/* value (8), record offset for out[0] */
	ldr  w9, [x0, #16]
	cmp  w11, w9
	b.ne .Ltx_not_out0_v
	sub  x9, x4, x3         /* value offset from base */
	str  x9, [x0, #40]      /* out0_value */
.Ltx_not_out0_v:
	add  x10, x4, #8
	cmp  x10, x5
	b.hi .Ltx_fail
	mov  x4, x10
	/* scriptlen varint -> x8 */
	VARINTP 8, x4, x5, .Ltx_fail
	/* record out[0] script offset/len */
	ldr  w9, [x0, #16]
	cmp  w11, w9
	b.ne .Ltx_not_out0_s
	sub  x9, x4, x3         /* script offset from base */
	str  x9, [x0, #48]
	str  x8, [x0, #56]
.Ltx_not_out0_s:
	add  x10, x4, x8
	cmp  x10, x5
	b.hi .Ltx_fail
	mov  x4, x10
	sub  x11, x11, #1
	b    .Ltx_next_out
.Ltx_outs_done:

	/* ---- skip segwit witness data (only if segwit) ---- */
	cbz  x6, .Ltx_nowit
	ldr  w11, [x0, #12]     /* n_in */
.Ltx_next_wit_in:
	cbz  x11, .Ltx_nowit
	/* varint item count -> x8 */
	VARINTP 8, x4, x5, .Ltx_fail
.Ltx_next_wit_item:
	cbz  x8, .Ltx_wit_in_done
	/* varint item len -> x12 */
	VARINTP 12, x4, x5, .Ltx_fail
	add  x10, x4, x12
	cmp  x10, x5
	b.hi .Ltx_fail
	mov  x4, x10
	sub  x8, x8, #1
	b    .Ltx_next_wit_item
.Ltx_wit_in_done:
	sub  x11, x11, #1
	b    .Ltx_next_wit_in
.Ltx_nowit:

	/* ---- locktime (4 bytes) ---- */
	add  x10, x4, #4
	cmp  x10, x5
	b.hi .Ltx_fail
	ldr  w9, [x4]
	str  w9, [x0, #20]      /* info.locktime */
	mov  x4, x10

	/* total consumed = cursor - base */
	sub  x9, x4, x3
	str  x9, [x0, #0]       /* info.tx_len */

	mov  w0, #1
	ret
.Ltx_fail:
	mov  w0, #0
	ret
	.size tx_parse, .-tx_parse

/* ============================================================================
 * tx_txid(out, tx, txlen, buf, buflen) -> w0 = 1 valid / 0 invalid
 * Computes the BIP141 unwitnessed serialization (version | inputs..outputs |
 * locktime, witness dropped) into `buf`, then txid = sha256d(buf, unwit_len).
 * Non-leaf (calls sha256d) -> callee-saved packed.
 *   x19=out x20=buf x21=tx x22=txlen x23=buflen x24=inputs_start
 *   x9=end x10=cursor x7/x12 = varint results
 * ========================================================================== */
	.global tx_txid
	.type tx_txid, %function
tx_txid:
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	stp x29, x30, [sp, #-16]!

	mov  x19, x0            /* out */
	mov  x20, x3            /* buf */
	mov  x21, x1            /* tx */
	mov  x22, x2            /* txlen */
	mov  x23, x4            /* buflen */
	add  x9,  x1, x2        /* end = tx + txlen */

	/* ---- detect segwit marker (version | 0x00 0x01) ---- */
	mov  w11, #0
	add  x14, x21, #6
	cmp  x14, x9
	b.hi .Lid_noseg
	ldrb w16, [x21, #4]
	cbnz w16, .Lid_noseg
	ldrb w16, [x21, #5]
	cmp  w16, #1
	b.ne .Lid_noseg
	mov  w11, #1
.Lid_noseg:

	/* inputs_start = tx+4 (legacy) or tx+6 (segwit) */
	add  x24, x21, #4
	cbz  w11, .Lid_cur
	add  x24, x21, #6
.Lid_cur:
	mov  x10, x24           /* cursor */

	/* ---- varint n_in -> x7 ---- */
	VARINTP 7, x10, x9, .Lid_fail
	mov  x13, x7            /* counter = n_in */

.Lid_next_in:
	cbz  x13, .Lid_ins_done
	/* input: prevout(32) index(4) varint scriptlen script seq(4) */
	add  x14, x10, #36      /* ptr to scriptlen varint */
	VARINTP 12, x14, x9, .Lid_fail  /* len -> x12 */
	add  x15, x14, x12
	add  x15, x15, #4       /* + seq */
	cmp  x15, x9
	b.hi .Lid_fail
	mov  x10, x15
	sub  x13, x13, #1
	b    .Lid_next_in
.Lid_ins_done:

	/* ---- varint n_out -> x7 ---- */
	VARINTP 7, x10, x9, .Lid_fail
	mov  x13, x7            /* counter = n_out */
.Lid_next_out:
	cbz  x13, .Lid_outs_done
	/* output: value(8) varint scriptlen script */
	add  x14, x10, #8       /* ptr to scriptlen varint */
	VARINTP 12, x14, x9, .Lid_fail
	add  x15, x14, x12
	cmp  x15, x9
	b.hi .Lid_fail
	mov  x10, x15
	sub  x13, x13, #1
	b    .Lid_next_out
.Lid_outs_done:

	/* x10 = outputs_end. locktime_start = end-4 must be >= outputs_end */
	sub  x13, x9, #4
	cmp  x13, x10
	b.lo .Lid_fail

	/* ---- reconstruct unwitnessed into buf ---- */
	/* mid_len = outputs_end - inputs_start */
	sub  x14, x10, x24      /* x14 = mid_len */
	/* buflen check: 4 + mid_len + 4 <= buflen */
	add  x15, x14, #8
	cmp  x15, x23
	b.hi .Lid_fail

	/* copy version (4 bytes) */
	ldr  w16, [x21]
	str  w16, [x20]

	/* copy mid (x14 bytes) from x24 to buf+4 */
	mov  x13, x24           /* src */
	add  x15, x20, #4       /* dst */
	mov  x11, x14           /* count */
.Lid_cp:
	cbz  x11, .Lid_cpd
	ldrb w16, [x13], #1
	strb w16, [x15], #1
	sub  x11, x11, #1
	b    .Lid_cp
.Lid_cpd:

	/* copy locktime (4 bytes) from tx+txlen-4 to buf+4+mid_len */
	add  x13, x21, x22
	sub  x13, x13, #4
	ldr  w16, [x13]
	add  x15, x20, #4
	add  x15, x15, x14
	str  w16, [x15]

	/* unwit_len = 4 + mid_len + 4 ; sha256d(out, buf, unwit_len) */
	add  x12, x14, #8
	mov  x0, x19
	mov  x1, x20
	mov  x2, x12
	bl   sha256d

	mov  w0, #1
	b    .Lid_done
.Lid_fail:
	mov  w0, #0
.Lid_done:
	ldp x29, x30, [sp], #16
	ldp x23, x24, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ret
	.size tx_txid, .-tx_txid

	.section .note.GNU-stack,"",%progbits
