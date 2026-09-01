/* ============================================================================
 * bitcoin_sighash_all_ext.S -- AArch64 port of asm/bitcoin_sighash.asm's
 * `sighash_all` (legacy SIGHASH_ALL preimage builder). The already-ported
 * port/arm64/bitcoin_sighash.S exposes script_find_and_delete, script_push_encode
 * and legacy_sighash but NOT sighash_all; this new file supplies it (the daemon's
 * wallet_core.c references sighash_all), self-contained with its own local
 * parse_varint / write_varint / copy_bytes helpers.
 *
 *   int sighash_all(  out32,  tx, txlen, input_index,  script, script_len,
 *                     preimg, cap)   -> 1 ok / 0
 *   AArch64: x0=out x1=tx x2=txlen x3=input_index x4=script x5=script_len
 *            x6=preimg x7=cap
 *
 * Emits the legacy SIGHASH_ALL preimage into preimg/cap and sha256d's it into
 * out32: version(4) || varint n_in || per-input(prevout, script, seq) ||
 * raw tail || hashtype=1. ========================================================================== */

	.extern sha256d

	.text

	.equ S_LOC_SCRIPT,    0
	.equ S_LOC_SCRIPT_LEN,8
	.equ S_LOC_PREIMG,    16
	.equ S_LOC_CAP,       24
	.equ S_LOC_P,         32
	.equ S_LOC_P_END,     40
	.equ S_LOC_TXCUR,     48
	.equ S_LOC_TXEND,     56
	.equ S_LOC_TOTLEN,    64

/* ============================================================================
 * copy_bytes(dst=x0, src=x1, n=x2) -> x0,x1 advanced past the copy.
 * Leaf; clobbers x9,x10.
 * ========================================================================== */
	.type .Lsh_copy_bytes, %function
.Lsh_copy_bytes:
	mov  x9, #0
1:	cmp  x9, x2
	b.hs 2f
	ldrb w10, [x1, x9]
	strb w10, [x0, x9]
	add  x9, x9, #1
	b    1b
2:	add  x0, x0, x2
	add  x1, x1, x2
	ret
	.size .Lsh_copy_bytes, .-.Lsh_copy_bytes

/* ============================================================================
 * parse_varint(cursor=x0, end=x1) -> x0=value, x0? return value in x0 and
 * advanced cursor also in a register. We use the AAPCS-friendly form:
 * value returned in x0, cursor advanced in x0 too is impossible -- so we use
 * two out regs via the original x86 convention replicated: value in x0,
 * cursor (advanced) in x0 overwritten. To be unambiguous we adopt:
 *   value in x0, advanced cursor in x2 (a dedicated out).
 * Clobbers x0..x5.
 * ========================================================================== */
	.type .Lsh_parse_varint, %function
.Lsh_parse_varint:
	mov  x2, x0                       /* will hold advanced cursor */
	cmp  x0, x1
	b.hs .Lpv_fail
	ldrb w3, [x2]
	add  x2, x2, #1
	cmp  w3, #0xfd
	b.lo .Lpv_ret1                    /* value = w3 (0..0xfc) */
	/* width from prefix */
	cmp  w3, #0xfe
	b.eq .Lpv_w4
	cmp  w3, #0xff
	b.eq .Lpv_w8
	mov  x4, #2                       /* 0xfd -> 2 bytes */
	b    .Lpv_load
.Lpv_w4:
	mov  x4, #4
	b    .Lpv_load
.Lpv_w8:
	mov  x4, #8
.Lpv_load:
	add  x5, x2, x4
	cmp  x5, x1
	b.hi .Lpv_fail
	mov  x0, #0                       /* acc */
	mov  x5, #0                       /* shift bits */
.Lpv_b:
	ldrb w3, [x2]
	lsl  x3, x3, x5
	orr  x0, x0, x3
	add  x2, x2, #1
	add  x5, x5, #8
	sub  x4, x4, #1
	cbnz x4, .Lpv_b
	ret
.Lpv_ret1:
	mov  x0, x3                       /* value = byte (zero-extended) */
	ret
.Lpv_fail:
	mov  x0, #0
	/* x2 stays wherever the walk got to (x86 .pv_fail leaves rdi as-is):
	 * zeroing the cursor here sent txcur=NULL for a truncated varint prefix
	 * and the next raw copy dereferenced it (test_interp_legacy_spend). */
	ret
	.size .Lsh_parse_varint, .-.Lsh_parse_varint

/* ============================================================================
 * write_varint(cursor=x0, value=x1, end=x2) -> x0 advanced cursor.
 * Leaf; clobbers x3,x4.
 * ========================================================================== */
	.type .Lsh_write_varint, %function
.Lsh_write_varint:
	cmp  x1, #0xfc
	b.ls 1f
	movz x3, #0xffff
	cmp  x1, x3
	b.ls 2f
	movz x3, #0xffff
	movk x3, #0xffff, lsl #16
	cmp  x1, x3
	b.ls 4f
	/* 8-byte */
	mov  w3, #0xff
	strb w3, [x0, #0]
	str  x1, [x0, #1]
	add  x0, x0, #9
	ret
4:	mov  w3, #0xfe
	strb w3, [x0, #0]
	str  w1, [x0, #1]
	add  x0, x0, #5
	ret
2:	mov  w3, #0xfd
	strb w3, [x0, #0]
	strh w1, [x0, #1]
	add  x0, x0, #3
	ret
1:	strb w1, [x0, #0]
	add  x0, x0, #1
	ret
	.size .Lsh_write_varint, .-.Lsh_write_varint

/* ============================================================================
 * sighash_all -- see header.
 * ========================================================================== */
	.global sighash_all
	.type sighash_all, %function
sighash_all:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	sub  sp, sp, #96
	mov  x19, x0                       /* out32 */
	mov  x20, x1                       /* tx */
	mov  x21, x2                       /* txlen */
	mov  x22, x3                       /* input_index */
	str  x4, [sp, #S_LOC_SCRIPT]
	str  x5, [sp, #S_LOC_SCRIPT_LEN]
	str  x6, [sp, #S_LOC_PREIMG]
	str  x7, [sp, #S_LOC_CAP]
	add  x9, x1, x2
	str  x9, [sp, #S_LOC_TXEND]        /* txend */
	cmp  x2, #10
	b.lo .SHfail

	/* n_in varint at tx+4 */
	add  x9, x20, #4
	str  x9, [sp, #S_LOC_TXCUR]        /* txcur */
	mov  x0, x9
	ldr  x1, [sp, #S_LOC_TXEND]
	bl   .Lsh_parse_varint             /* x0=value, x2=advanced cursor */
	mov  x23, x0                       /* n_in */
	str  x2, [sp, #S_LOC_TXCUR]
	cmp  x23, #0
	b.eq .SHfail
	cmp  x22, x23
	b.hs .SHfail

	/* preimg cursor init */
	ldr  x9, [sp, #S_LOC_PREIMG]
	str  x9, [sp, #S_LOC_P]
	ldr  x9, [sp, #S_LOC_CAP]
	ldr  x10, [sp, #S_LOC_PREIMG]
	add  x9, x10, x9
	str  x9, [sp, #S_LOC_P_END]        /* p_end */

	/* version(4) */
	ldr  x9, [sp, #S_LOC_P]
	add  x9, x9, #4
	ldr  x10, [sp, #S_LOC_P_END]
	cmp  x9, x10
	b.hi .SHfail
	ldr  w11, [x20]                    /* tx.version */
	ldr  x9, [sp, #S_LOC_P]
	str  w11, [x9]
	ldr  x9, [sp, #S_LOC_P]
	add  x9, x9, #4
	str  x9, [sp, #S_LOC_P]

	/* varint n_in */
	ldr  x0, [sp, #S_LOC_P]            /* cursor */
	mov  x1, x23                       /* value = n_in */
	ldr  x2, [sp, #S_LOC_P_END]        /* end */
	bl   .Lsh_write_varint
	str  x0, [sp, #S_LOC_P]
	mov  x24, #0                       /* i */

.SHin_loop:
	cmp  x24, x23
	b.hs .SHin_done
	/* copy prevout(32)+index(4) = 36 raw bytes from txcur */
	ldr  x0, [sp, #S_LOC_P]
	ldr  x1, [sp, #S_LOC_TXCUR]
	mov  x2, #36
	bl   .Lsh_copy_bytes
	str  x0, [sp, #S_LOC_P]
	str  x1, [sp, #S_LOC_TXCUR]
	/* advance txcur past this input's scriptSig */
	ldr  x0, [sp, #S_LOC_TXCUR]
	ldr  x1, [sp, #S_LOC_TXEND]
	bl   .Lsh_parse_varint             /* x0 = scriptSig len, x2 = cursor */
	mov  x25, x0                       /* ssl */
	mov  x9, x2
	add  x9, x9, x25
	ldr  x10, [sp, #S_LOC_TXEND]
	cmp  x9, x10
	b.hi .SHfail
	str  x9, [sp, #S_LOC_TXCUR]
	/* script: target input emits given script; others empty */
	cmp  x24, x22
	b.eq .SHwrite_script
	/* empty: 1 byte 0x00 */
	ldr  x9, [sp, #S_LOC_P]
	add  x9, x9, #1
	ldr  x10, [sp, #S_LOC_P_END]
	cmp  x9, x10
	b.hi .SHfail
	ldr  x9, [sp, #S_LOC_P]
	strb wzr, [x9]
	ldr  x9, [sp, #S_LOC_P]
	add  x9, x9, #1
	str  x9, [sp, #S_LOC_P]
	b    .SHafter_script
.SHwrite_script:
	ldr  x0, [sp, #S_LOC_P]
	ldr  x1, [sp, #S_LOC_SCRIPT_LEN]
	ldr  x2, [sp, #S_LOC_P_END]
	bl   .Lsh_write_varint
	str  x0, [sp, #S_LOC_P]
	ldr  x0, [sp, #S_LOC_P]
	ldr  x1, [sp, #S_LOC_SCRIPT]
	ldr  x2, [sp, #S_LOC_SCRIPT_LEN]
	bl   .Lsh_copy_bytes
	str  x0, [sp, #S_LOC_P]
	ldr  x9, [sp, #S_LOC_P]
	ldr  x10, [sp, #S_LOC_P_END]
	cmp  x9, x10
	b.hi .SHfail
.SHafter_script:
	/* sequence(4) raw */
	ldr  x0, [sp, #S_LOC_P]
	ldr  x1, [sp, #S_LOC_TXCUR]
	mov  x2, #4
	bl   .Lsh_copy_bytes
	str  x0, [sp, #S_LOC_P]
	str  x1, [sp, #S_LOC_TXCUR]
	add  x24, x24, #1
	b    .SHin_loop

.SHin_done:
	/* tail: copy [txcur..txend] verbatim */
	ldr  x10, [sp, #S_LOC_TXEND]
	ldr  x11, [sp, #S_LOC_TXCUR]
	sub  x2, x10, x11
	ldr  x0, [sp, #S_LOC_P]
	mov  x1, x11
	bl   .Lsh_copy_bytes
	str  x0, [sp, #S_LOC_P]
	/* hashtype(4)=1 */
	ldr  x9, [sp, #S_LOC_P]
	add  x9, x9, #4
	ldr  x10, [sp, #S_LOC_P_END]
	cmp  x9, x10
	b.hi .SHfail
	ldr  x9, [sp, #S_LOC_P]
	mov  w10, #1
	str  w10, [x9]
	ldr  x9, [sp, #S_LOC_P]
	add  x9, x9, #4
	str  x9, [sp, #S_LOC_P]
	/* sha256d(out=out32, msg=preimg, len=p-preimg) */
	ldr  x9, [sp, #S_LOC_P]
	ldr  x10, [sp, #S_LOC_PREIMG]
	sub  x2, x9, x10
	mov  x0, x19
	mov  x1, x10
	bl   sha256d
	mov  w0, #1
	b    .SHdone
.SHfail:
	mov  w0, #0
.SHdone:
	add  sp, sp, #96
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size sighash_all, .-sighash_all

	.section .note.GNU-stack,"",%progbits
