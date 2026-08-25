/* ============================================================================
 * bitcoin_p2p.S -- AArch64 (ARMv8-A) port of asm/bitcoin_p2p.asm
 * Bitcoin P2P message payload builders/parsers. All wire integers LITTLE-endian.
 * AAPCS64: out=x0, and subsequent args in x1..x3.
 *   long p2p_getheaders (out, locator, count, stop)   -> len or -1
 *   long p2p_getdata_block(out, hash)                 -> 37
 *   long p2p_ping         (out, nonce)                -> 8
 *   long p2p_headers_count(payload, plen)             -> count or -1
 *   long p2p_inv_count    (payload, plen)             -> count or -1
 *   int  p2p_inv_get      (payload, i, out_type, out_hash) -> 1 ok / 0
 * NODE_PROTOCOL_VER = 70016 (0x00011180), from version.inc.
 * ========================================================================== */

	.text

/* ============================================================================
 * p2p_getheaders(out=x0, locator=x1, count=w2, stop=x3) -> len or -1
 * getheaders payload: [version LE u32][count varint][count*32 locator hashes]
 *                     [stop hash 32].
 * ========================================================================== */
	.global p2p_getheaders
	.type p2p_getheaders, %function
p2p_getheaders:
	mov x9, x0                     /* out */
	mov x10, x1                    /* locator */
	mov w11, w2                    /* count */
	mov x12, x3                    /* stop */
	cmp w11, #1
	b.lt .PGHE
	cmp w11, #252
	b.hi .PGHE
	/* protocol version 70016 = 0x00011180 */
	mov w13, #0x1180
	movk w13, #0x0001, lsl #16
	str w13, [x9, #0]
	strb w11, [x9, #4]             /* count varint */
	/* locator hashes at out+5, count*32 bytes */
	lsl x14, x11, #5               /* count*32 */
	mov x15, #0
.PGHCOPY:
	cmp x15, x14
	b.hs .PGHCDONE
	add x2, x10, x15
	ldrb w3, [x2]
	add x2, x9, #5
	add x2, x2, x15
	strb w3, [x2]
	add x15, x15, #1
	b .PGHCOPY
.PGHCDONE:
	/* stop hash at out+5+count*32, 32 bytes */
	mov x15, #0
.PGHST:
	cmp x15, #32
	b.hs .PGHSTEND
	add x2, x12, x15
	ldrb w3, [x2]
	add x2, x9, #5
	add x2, x2, x14
	add x2, x2, x15
	strb w3, [x2]
	add x15, x15, #1
	b .PGHST
.PGHSTEND:
	add x0, x14, #37               /* 5 + count*32 + 32 */
	ret
.PGHE:
	mov x0, #-1
	ret
	.size p2p_getheaders, .-p2p_getheaders

/* ============================================================================
 * p2p_getdata_block(out=x0, hash=x1) -> 37
 *   [count varint=1][type u32 LE=0x40000002 MSG_WITNESS_BLOCK][hash 32]
 * ========================================================================== */
	.global p2p_getdata_block
	.type p2p_getdata_block, %function
p2p_getdata_block:
	mov w2, #1
	strb w2, [x0, #0]
	mov w3, #0x0002
	movk w3, #0x4000, lsl #16      /* 0x40000002 */
	str w3, [x0, #1]
	mov x3, #0
.PGDCOPY:
	cmp x3, #32
	b.hs .PGDCDONE
	add x2, x1, x3
	ldrb w4, [x2]
	add x2, x0, #5
	add x2, x2, x3
	strb w4, [x2]
	add x3, x3, #1
	b .PGDCOPY
.PGDCDONE:
	mov x0, #37
	ret
	.size p2p_getdata_block, .-p2p_getdata_block

/* ============================================================================
 * p2p_ping(out=x0, nonce=x1) -> 8
 * ========================================================================== */
	.global p2p_ping
	.type p2p_ping, %function
p2p_ping:
	str x1, [x0]
	mov x0, #8
	ret
	.size p2p_ping, .-p2p_ping

/* ============================================================================
 * p2p_headers_count(payload=x0, plen=x1) -> count or -1
 *   headers payload = [count varint][count * 81-byte headers]
 * ========================================================================== */
	.global p2p_headers_count
	.type p2p_headers_count, %function
p2p_headers_count:
	cmp x1, #1
	b.lo .PHCE
	ldrb w4, [x0]
	mov x6, #1                      /* varint len */
	cmp w4, #0xfd
	b.lo .PHCHK
	cmp w4, #0xfc
	b.eq .PHCHK
	cmp w4, #0xfd
	b.ne .PHCE
	cmp x1, #3
	b.lo .PHCE
	ldrh w5, [x0, #1]
	mov x6, #3
	mov w4, w5
.PHCHK:
	/* bytes needed = varintlen + count*81 ; must be <= plen */
	mov x5, x4
	mov x7, #81
	mul x5, x5, x7
	add x5, x5, x6
	cmp x5, x1
	b.hi .PHCE
	mov x0, x4
	ret
.PHCE:
	mov x0, #-1
	ret
	.size p2p_headers_count, .-p2p_headers_count

/* ============================================================================
 * p2p_inv_count(payload=x0, plen=x1) -> count or -1
 *   inv payload = [count varint][count * 36 = type u32 LE + hash 32]
 * ========================================================================== */
	.global p2p_inv_count
	.type p2p_inv_count, %function
p2p_inv_count:
	cmp x1, #1
	b.lo .PICE
	ldrb w4, [x0]
	mov x6, #1
	cmp w4, #0xfd
	b.lo .PICHK
	cmp w4, #0xfe
	b.eq .PICE
	cmp w4, #0xfd
	b.ne .PICE
	cmp x1, #3
	b.lo .PICE
	ldrh w5, [x0, #1]
	mov x6, #3
	mov w4, w5
.PICHK:
	mov x5, x4
	mov x7, #36
	mul x5, x5, x7
	add x5, x5, x6
	cmp x5, x1
	b.hi .PICE
	mov x0, x4
	ret
.PICE:
	mov x0, #-1
	ret
	.size p2p_inv_count, .-p2p_inv_count

/* ============================================================================
 * p2p_inv_get(payload=x0, i=x1, out_type=x2, out_hash=x3) -> 1 ok / 0 range
 * ========================================================================== */
	.global p2p_inv_get
	.type p2p_inv_get, %function
p2p_inv_get:
	mov x9, x0                     /* payload */
	mov x10, x1                    /* i */
	mov x11, x2                    /* out_type */
	mov x12, x3                    /* out_hash */
	ldrb w4, [x9]
	mov x6, #1                     /* varint len */
	mov w13, w4                    /* count (1-byte) */
	cmp w4, #0xfd
	b.lo .PIGOK
	cmp w4, #0xfe
	b.eq .PIGE
	mov x6, #3
	ldrh w13, [x9, #1]
.PIGOK:
	/* if i >= count -> out of range */
	cmp x10, x13
	b.hs .PIGE
	/* offset = varintlen + i*36 */
	mov x5, x10
	mov x7, #36
	mul x5, x5, x7
	add x5, x5, x6
	add x5, x5, x9                 /* &type */
	ldr w14, [x5]
	str w14, [x11]                 /* type u32 LE */
	add x5, x5, #4                 /* &hash */
	/* copy 32 bytes hash -> out_hash */
	mov x15, #0
.PIGH:
	cmp x15, #32
	b.hs .PIGHDONE
	add x2, x5, x15
	ldrb w3, [x2]
	add x2, x12, x15
	strb w3, [x2]
	add x15, x15, #1
	b .PIGH
.PIGHDONE:
	mov x0, #1
	ret
.PIGE:
	mov x0, #0
	ret
	.size p2p_inv_get, .-p2p_inv_get

	.section .note.GNU-stack,"",%progbits
