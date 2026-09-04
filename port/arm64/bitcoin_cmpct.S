/* bitcoin_cmpct.S -- AArch64 port of asm/bitcoin_cmpct.asm (AAPCS64).
 * BIP152 compact blocks: SipHash-2-4 short-tx-ids + the wire codecs
 * (sendcmpct/cmpctblock/getblocktxn/blocktxn). Byte-exact vs Bitcoin Core.
 *   short-tx-id = SipHash24(key = sha256(hdr80||nonceLE8) low16, msg=wtxid) & 0xffffffffffff
 * Exports:
 *   u64  siphash24_uint256(k0, k1, msg32)
 *   void bip152_shortid(out6, hdr80, nonce, wtxid32)
 *   long p2p_sendcmpct(out, announce, version) -> 9
 *   long p2p_getblocktxn_build(out, bh32, idx16*, n) -> len
 *   long p2p_blocktxn_build(out, bh32, txs*, lens*, n) -> len  (txs = array of ptr, lens array)
 *   long cmpctblock_shorttxids_count(payload, plen) -> n / -1
 *   long cmpctblock_shorttxid(out6, payload, i) -> 1/0
 *   long block_txcount(blockbuf, blen) -> n/-1 (single-byte txcount only)
 *   long block_tx_at(blockbuf, blen, index, out_ptr*, out_len*) -> 1/0
 *   void tx_wtxid(out32, tx, txlen)
 *   long cmpctblock_build(out, blockbuf, blen, nonce) -> len / -1
 * NOTE: p2p_blocktxn_build's `txs` is an array of pointers (like x86). */
    .section .rodata
    .p2align 4
C0: .quad 0x736f6d6570736575
C1: .quad 0x646f72616e646f6d
C2: .quad 0x6c7967656e657261
C3: .quad 0x7465646279746573

    .bss
    .p2align 4
sid_buf:      .space 96
sid_scrat:    .space 32
sid6_scrat:   .space 8
s_txptr_local:.space 8
s_txlen_local:.space 8

    .text

/* ================= siphash24_uint256(k0=x0, k1=x1, msg=x2) -> x0 ================= */
    .global siphash24_uint256
    .type siphash24_uint256,%function
siphash24_uint256:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    mov  x29,sp
    mov  x5,x0                  /* k0 */
    mov  x6,x1                  /* k1 */
    mov  x7,x2                  /* msg */
    adrp x9,C0
    add  x9,x9,:lo12:C0
    ldr  x4,[x9]
    eor  x19,x4,x5              /* v0 = C0^k0 */
    ldr  x4,[x9,#8]
    eor  x20,x4,x6              /* v1 = C1^k1 */
    ldr  x4,[x9,#16]
    eor  x21,x4,x5              /* v2 = C2^k0 */
    ldr  x4,[x9,#24]
    eor  x22,x4,x6              /* v3 = C3^k1 */
    mov  x8,#0
.Ls0:
    cmp  x8,#4
    b.hs .Ls0d
    ldr  x3,[x7,x8,lsl#3]       /* d = LE64 msg word i */
    eor  x22,x22,x3             /* v3 ^= d */
    bl   .Lsipround2
    eor  x19,x19,x3             /* v0 ^= d */
    add  x8,x8,#1
    b    .Ls0
.Ls0d:
    mov  x3,#32
    lsl  x3,x3,#56              /* 32<<56 (final block) */
    eor  x22,x22,x3
    bl   .Lsipround2
    eor  x19,x19,x3
    eor  x21,x21,#0xff          /* v2 ^= 0xFF */
    mov  x8,#4
.Lsf0:
    bl   .Lsipround
    sub  x8,x8,#1
    cbnz x8,.Lsf0
    eor  x0,x19,x20
    eor  x0,x0,x21
    eor  x0,x0,x22
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
.Lsipround2:
    /* inner bls clobber x30; preserve the outer return on the stack
     * (x86 call/ret use the stack so this nesting was fine there) */
    str  x30,[sp,#-16]!
    bl   .Lsipround
    bl   .Lsipround
    ldr  x30,[sp],#16
    ret
    .size siphash24_uint256,.-siphash24_uint256

/* one SipRound on v0=x19 v1=x20 v2=x21 v3=x22 (clobbers x9 only) */
.Lsipround:
    add  x19,x19,x20            /* v0 += v1 */
    ror  x20,x20,#51            /* v1 = ROTL13 = ror51 */
    eor  x20,x20,x19            /* v1 ^= v0 */
    ror  x19,x19,#32            /* v0 = ROTL32 */
    add  x21,x21,x22            /* v2 += v3 */
    ror  x22,x22,#48            /* v3 = ROTL16 */
    eor  x22,x22,x21            /* v3 ^= v2 */
    add  x19,x19,x22            /* v0 += v3 */
    ror  x22,x22,#43            /* v3 = ROTL21 */
    eor  x22,x22,x19            /* v3 ^= v0 */
    add  x21,x21,x20            /* v2 += v1 */
    ror  x20,x20,#47            /* v1 = ROTL17 */
    eor  x20,x20,x21            /* v1 ^= v2 */
    ror  x21,x21,#32            /* v2 = ROTL32 */
    ret

/* ---------- memcpy_len(dst=x0, src=x1, n=x2) ---------- */
    .type __cp,%function
__cp:
    mov  x3,#0
.Lcp_l:
    cmp  x3,x2
    b.hs .Lcp_d
    ldrb w4,[x1,x3]
    strb w4,[x0,x3]
    add  x3,x3,#1
    b    .Lcp_l
.Lcp_d:
    ret
    .size __cp,.-__cp

/* ================= bip152_shortid(out6=x0, hdr=x1, nonce=x2, wtxid=x3) ================= */
    .global bip152_shortid
    .type bip152_shortid,%function
bip152_shortid:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    sub  sp,sp,#0x40
    mov  x29,sp
    mov  x19,x0                /* out6 */
    mov  x20,x1                /* hdr */
    mov  x21,x2                /* nonce */
    mov  x22,x3                /* wtxid */
    adrp x9,sid_buf
    add  x9,x9,:lo12:sid_buf
    mov  x0,x9
    mov  x1,x20
    mov  x2,#80
    bl   __cp
    str  x21,[x9,#80]          /* nonce LE8 */
    add  x0,sp,#0x08           /* digest */
    mov  x1,x9
    mov  x2,#88
    bl   sha256_full
    ldr  x0,[sp,#0x08]         /* k0 */
    ldr  x1,[sp,#0x10]         /* k1 */
    mov  x2,x22                /* wtxid */
    bl   siphash24_uint256
    and  x0,x0,#0xffffffffffff /* & 0xFFFFFFFFFFFF */
    mov  x8,x19
    strb w0,[x8]
    lsr  x0,x0,#8
    strb w0,[x8,#1]
    lsr  x0,x0,#8
    strb w0,[x8,#2]
    lsr  x0,x0,#8
    strb w0,[x8,#3]
    lsr  x0,x0,#8
    strb w0,[x8,#4]
    lsr  x0,x0,#8
    strb w0,[x8,#5]
    add  sp,sp,#0x40
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size bip152_shortid,.-bip152_shortid

/* ================= p2p_sendcmpct(out=x0, announce=w1, version=x2) -> 9 ================= */
    .global p2p_sendcmpct
    .type p2p_sendcmpct,%function
p2p_sendcmpct:
    strb w1,[x0]
    str  x2,[x0,#1]
    mov  w0,#9
    ret
    .size p2p_sendcmpct,.-p2p_sendcmpct

/* ---------- varint_put(dst=x0, val=x1) -> bytes (1/3/5/9) ---------- */
    .type varint_put,%function
varint_put:
    cmp  x1,#0xfd
    b.lo .Lv1
    mov  w9,#0xffff
    cmp  x1,x9
    b.ls .Lv3
    mov  w9,#0xffff
    movk w9,#0xffff,lsl#16
    cmp  x1,x9
    b.ls .Lv5
    mov  w9,#0xff
    strb w9,[x0]
    str  x1,[x0,#1]
    mov  w0,#9
    ret
.Lv5:
    mov  w9,#0xfe
    strb w9,[x0]
    str  w1,[x0,#1]
    mov  w0,#5
    ret
.Lv3:
    mov  w9,#0xfd
    strb w9,[x0]
    strh w1,[x0,#1]
    mov  w0,#3
    ret
.Lv1:
    strb w1,[x0]
    mov  w0,#1
    ret
    .size varint_put,.-varint_put

/* ======= p2p_getblocktxn_build(out=x0, bh=x1, indexes=x2, n=x3) -> len ======= */
    .global p2p_getblocktxn_build
    .type p2p_getblocktxn_build,%function
p2p_getblocktxn_build:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0                /* out */
    mov  x20,x1                /* bh */
    mov  x21,x2                /* indexes */
    mov  x22,x3                /* n */
    mov  x0,x19
    mov  x1,x20
    mov  x2,#32
    bl   __cp
    add  x0,x19,#32
    mov  x1,x22                /* count */
    bl   varint_put
    add  x23,x19,#32           /* cursor = out+32+varintlen */
    add  x23,x23,x0
    mov  x24,#0                /* shift */
    mov  x25,#0                /* i */
.Lgl:
    cmp  x25,x22
    b.hs .Lgd
    ldrh w9,[x21,x25,lsl#1]   /* v */
    mov  x10,x9
    sub  x10,x10,x24           /* stored = v - shift */
    mov  x0,x23
    mov  x1,x10
    bl   varint_put
    add  x23,x23,x0            /* cursor += bytes */
    ldrh w9,[x21,x25,lsl#1]
    add  x24,x9,#1             /* shift = v+1 */
    add  x25,x25,#1
    b    .Lgl
.Lgd:
    sub  x0,x23,x19
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size p2p_getblocktxn_build,.-p2p_getblocktxn_build

/* ======= p2p_blocktxn_build(out=x0, bh=x1, txs=x2(ptr array), lens=x3, n=x4) -> len ======= */
    .global p2p_blocktxn_build
    .type p2p_blocktxn_build,%function
p2p_blocktxn_build:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0                /* out */
    mov  x20,x1                /* bh */
    mov  x21,x2                /* txs */
    mov  x22,x3                /* lens */
    mov  x23,x4                /* n */
    mov  x0,x19
    mov  x1,x20
    mov  x2,#32
    bl   __cp
    add  x0,x19,#32
    mov  x1,x23
    bl   varint_put
    add  x24,x19,#32
    add  x24,x24,x0            /* cursor */
    mov  x25,#0                /* i */
.Lbl:
    cmp  x25,x23
    b.hs .Lbd
    ldr  x10,[x21,x25,lsl#3]   /* tx ptr */
    ldr  x11,[x22,x25,lsl#3]   /* tx len */
    mov  x0,x24
    mov  x1,x10
    mov  x2,x11
    bl   __cp
    add  x24,x24,x11           /* cursor += len */
    add  x25,x25,#1
    b    .Lbl
.Lbd:
    sub  x0,x24,x19
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size p2p_blocktxn_build,.-p2p_blocktxn_build

/* ======= cmpctblock_shorttxids_count(payload=x0, plen=x1) -> n / -1 ======= */
    .global cmpctblock_shorttxids_count
    .type cmpctblock_shorttxids_count,%function
cmpctblock_shorttxids_count:
    stp  x29,x30,[sp,#-16]!
    mov  x29,sp
    cmp  x1,#89
    b.lo .Lce
    ldrb w9,[x0,#88]
    cmp  w9,#0xfd
    b.lo .Lc1                /* single-byte count */
    cmp  w9,#0xfe
    b.hs .Lce                /* 0xfe/0xff unsupported -> err (x86: only 1/3-byte) */
    /* ==0xfd: 2-byte LE count, varintlen=3 */
    cmp  x1,#91
    b.lo .Lce
    ldrh w10,[x0,#89]
    mov  x11,#3
    b    .Lhave_fb
.Lc1:
    mov  w10,w9              /* count = byte */
    mov  x11,#1
.Lhave_fb:
    /* need 88 + varintlen + n*6 <= plen */
    mov  x12,x10
    mov  x13,#6
    mul  x12,x12,x13
    add  x12,x12,x11
    add  x12,x12,#88
    cmp  x12,x1
    b.hi .Lce
    mov  x0,x10
    b    .Lcr
.Lce:
    mov  x0,#-1
.Lcr:
    ldp  x29,x30,[sp],#16
    ret
    .size cmpctblock_shorttxids_count,.-cmpctblock_shorttxids_count


/* ======= cmpctblock_shorttxid(out6=x0, payload=x1, i=x2) -> 1/0 ======= */
    .global cmpctblock_shorttxid
    .type cmpctblock_shorttxid,%function
cmpctblock_shorttxid:
    stp  x29,x30,[sp,#-16]!
    ldrb w9,[x1,#88]
    mov  x10,#1                /* varintlen */
    mov  x13,#0
    cmp  w9,#0xfd
    b.lo .Lcot1
    mov  x10,#3
    ldrh w13,[x1,#89]
    b    .Lot2
.Lcot1:
    mov  w13,w9
.Lot2:
    cmp  x2,x13
    b.hs .Loe
    mov  x11,x2
    mov  x12,#6
    mul  x11,x11,x12
    add  x11,x11,x10
    add  x11,x11,#88
    add  x11,x11,x1            /* src = payload+88+varlen+i*6 */
    mov  x9,#0
.Lohc:
    cmp  x9,#6
    b.hs .Lohd
    ldrb w14,[x11,x9]
    strb w14,[x0,x9]
    add  x9,x9,#1
    b    .Lohc
.Lohd:
    mov  w0,#1
    b    .Locr
.Loe:
    mov  w0,#0
.Locr:
    ldp  x29,x30,[sp],#16
    ret
    .size cmpctblock_shorttxid,.-cmpctblock_shorttxid

/* ======= cs_read(ptr=x0, end=x1) -> x0 = value, x1 = width (0 = malformed) =======
 * SER-4 (audit 2026-09-03). All three BIP152 helpers read a block's tx-count
 * CompactSize as a SINGLE BYTE and started the transaction walk at block+81.
 * For any block with 253 or more transactions -- a 3, 5 or 9-byte varint --
 * the count was taken as the marker byte (253/254/255) and the cursor was
 * 2/4/8 bytes short, so every transaction boundary was misparsed.
 *
 * cons_verify, the consensus path, reads it correctly, so only the BIP152
 * SERVING helpers were affected: a peer asking for a cmpctblock or
 * getblocktxn on any modern block got the miss path and nothing at all.
 * Compact-block relay was effectively off for every real block.
 *
 * One reader, used by all three, rather than three more hand-written
 * varints. Bounds-checked against end: a truncated field returns width 0.
 * Leaf: x0/x1 only. */
cs_read:
	cmp  x0, x1
	b.hs .Lcsrb
	ldrb w9, [x0]
	cmp  w9, #0xfd
	b.hs .Lcsrw
	mov  w0, w9			/* the 1-byte value itself */
	mov  x1, #1
	ret
.Lcsrw:
	cmp  w9, #0xfd
	b.eq 1f
	cmp  w9, #0xfe
	b.eq 2f
	/* 0xff -> 8 bytes */
	add  x2, x0, #9
	cmp  x2, x1
	b.hi .Lcsrb
	ldr  x0, [x0, #1]
	mov  x1, #9
	ret
1:	/* 0xfd -> 2 bytes */
	add  x2, x0, #3
	cmp  x2, x1
	b.hi .Lcsrb
	ldrh w9, [x0, #1]
	mov  x0, x9
	mov  x1, #3
	ret
2:	/* 0xfe -> 4 bytes */
	add  x2, x0, #5
	cmp  x2, x1
	b.hi .Lcsrb
	ldr  w9, [x0, #1]
	mov  x0, x9
	mov  x1, #5
	ret
.Lcsrb:
	mov  x0, #0
	mov  x1, #0
	ret

/* ======= block_txcount(blockbuf=x0, blen=x1) -> n / -1 ======= */
    .global block_txcount
    .type block_txcount,%function
block_txcount:
	stp  x29,x30,[sp,#-16]!
	cmp  x1,#81
	b.lo .Lbtce
	/* SER-4: a real CompactSize, bounded by blen */
	add  x2,x0,#80
	add  x3,x0,x1		/* end = blk + blen */
	mov  x0,x2
	mov  x1,x3
	bl   cs_read
	cbz  x1,.Lbtce		/* width 0 = malformed/truncated */
	ldp  x29,x30,[sp],#16
	ret
.Lbtce:
	mov  x0,#-1
	ldp  x29,x30,[sp],#16
	ret
    .size block_txcount,.-block_txcount

/* ======= tx_wtxid(out=x0, tx=x1, txlen=x2) ======= */
    .global tx_wtxid
    .type tx_wtxid,%function
tx_wtxid:
    stp  x29,x30,[sp,#-16]!
    bl   sha256d               /* x0=out x1=tx x2=len */
    ldp  x29,x30,[sp],#16
    ret
    .size tx_wtxid,.-tx_wtxid

/* ======= block_tx_at(blockbuf=x0, blen=x1, index=x2, out_ptr=x3, out_len=x4) -> 1/0 ======= */
    .global block_tx_at
    .type block_tx_at,%function
block_tx_at:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    sub  sp,sp,#0x70           /* ntx@[sp] i@[sp+8] cursor@[sp+16] txinfo@[sp+0x20]
                               * (64B; saves live at sp+0x70+, so txinfo is clear) */
    mov  x29,sp
    mov  x19,x0
    mov  x20,x1
    mov  x21,x2
    mov  x22,x3
    mov  x23,x4
    cmp  x20,#82
    b.lo .Lbtf
    /* SER-4: header(80) + a REAL txcount CompactSize (1/3/5/9 bytes) */
    add  x0,x19,#80
    add  x1,x19,x20		/* end = blk + blen */
    bl   cs_read
    cbz  x1,.Lbtf		/* malformed/truncated count */
    str  x0,[sp]		/* ntx */
    str  xzr,[sp,#8]           /* i */
    add  x9,x19,#80
    add  x9,x9,x1              /* cursor = first tx, past the real varint */
    str  x9,[sp,#16]
.Lbtw:
    ldr  x9,[sp,#8]
    ldr  x10,[sp]
    cmp  x9,x10
    b.hs .Lbtf
    ldr  x9,[sp,#16]           /* cursor */
    add  x10,x19,x20           /* blockend */
    sub  x11,x10,x9            /* remaining */
    cmp  x11,#9
    b.lo .Lbtf
    add  x0,sp,#0x20           /* txinfo */
    mov  x1,x9
    mov  x2,x11
    bl   tx_parse
    cbz  x0,.Lbtf
    ldr  x9,[sp,#0x20]         /* txlen */
    cmp  x9,#0
    b.le .Lbtf
    ldr  x10,[sp,#8]
    cmp  x10,x21
    b.ne .Lbtn
    ldr  x9,[sp,#16]
    str  x9,[x22]
    ldr  x9,[sp,#0x20]
    str  x9,[x23]
    mov  w0,#1
    b    .Lbtr
.Lbtn:
    ldr  x9,[sp,#16]
    ldr  x10,[sp,#0x20]
    add  x9,x9,x10
    str  x9,[sp,#16]
    ldr  x9,[sp,#8]
    add  x9,x9,#1
    str  x9,[sp,#8]
    b    .Lbtw
.Lbtf:
    mov  w0,#0
.Lbtr:
    add  sp,sp,#0x70
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size block_tx_at,.-block_tx_at

/* ======= cmpctblock_build(out=x0, blockbuf=x1, blen=x2, nonce=x3) -> len / -1 ======= */
    .global cmpctblock_build
    .type cmpctblock_build,%function
cmpctblock_build:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0                /* out */
    mov  x20,x1                /* blockbuf */
    mov  x21,x2                /* blen */
    mov  x22,x3                /* nonce */
    mov  x0,x19
    mov  x1,x20
    mov  x2,#80
    bl   __cp                  /* header -> out */
    str  x22,[x19,#80]         /* nonce LE8 */
    /* SER-4: ntx from a REAL CompactSize; nshort = ntx-1 */
    add  x0,x20,#80
    add  x1,x20,x21		/* end = blk + blen */
    bl   cs_read
    cbz  x1,.Lcbf		/* malformed/truncated count */
    mov  x25,x0			/* ntx (callee-saved, loop bound) */
    sub  w10,w25,#1
    strb w10,[x19,#88]         /* nshort */
    add  x23,x19,#89           /* sid ptr */
    mov  x24,#1                /* i */
.Lcbl:
    cmp  x24,x25
    b.hs .Lcbp
    mov  x0,x20
    mov  x1,x21
    mov  x2,x24
    adrp x9,s_txptr_local
    add  x3,x9,:lo12:s_txptr_local
    adrp x10,s_txlen_local
    add  x4,x10,:lo12:s_txlen_local
    bl   block_tx_at
    cbz  w0,.Lcbf
    adrp x0,sid_scrat
    add  x0,x0,:lo12:sid_scrat
    adrp x9,s_txptr_local
    add  x1,x9,:lo12:s_txptr_local
    ldr  x1,[x1]
    adrp x10,s_txlen_local
    add  x2,x10,:lo12:s_txlen_local
    ldr  x2,[x2]
    bl   tx_wtxid
    adrp x0,sid6_scrat
    add  x0,x0,:lo12:sid6_scrat
    mov  x1,x20
    mov  x2,x22
    adrp x9,sid_scrat
    add  x3,x9,:lo12:sid_scrat
    bl   bip152_shortid
    adrp x9,sid6_scrat
    add  x9,x9,:lo12:sid6_scrat
    mov  x10,#0
.Lcbs:
    cmp  x10,#6
    b.hs .Lcbsd
    ldrb w11,[x9,x10]
    strb w11,[x23,x10]
    add  x10,x10,#1
    b    .Lcbs
.Lcbsd:
    add  x23,x23,#6
    add  x24,x24,#1
    b    .Lcbl
.Lcbp:
    mov  w9,#1
    strb w9,[x23]              /* nprefilled */
    strb wzr,[x23,#1]          /* index0 */
    add  x25,x23,#2            /* coinbase dest */
    mov  x0,x20
    mov  x1,x21
    mov  x2,#0
    adrp x9,s_txptr_local
    add  x3,x9,:lo12:s_txptr_local
    adrp x10,s_txlen_local
    add  x4,x10,:lo12:s_txlen_local
    bl   block_tx_at
    cbz  w0,.Lcbf
    adrp x9,s_txptr_local
    add  x9,x9,:lo12:s_txptr_local
    ldr  x1,[x9]
    adrp x10,s_txlen_local
    add  x10,x10,:lo12:s_txlen_local
    ldr  x2,[x10]
    mov  x0,x25
    bl   __cp
    adrp x9,s_txlen_local
    add  x9,x9,:lo12:s_txlen_local
    ldr  x9,[x9]               /* txlen */
    add  x25,x23,#2
    add  x25,x25,x9
    sub  x0,x25,x19
    b    .Lcbr
.Lcbf:
    mov  x0,#-1
.Lcbr:
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size cmpctblock_build,.-cmpctblock_build

    .section .note.GNU-stack,"",@progbits
