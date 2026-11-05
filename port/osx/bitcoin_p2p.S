/* ============================================================================
 * bitcoin_p2p.S -- P2P message payload builders and parsers in AArch64
 * assembly (Apple silicon), the counterpart of asm/bitcoin_p2p.asm. Replaces
 * p2p_twin.c on the Mac (2026-09-26); the twin stays in port/osx/test_support
 * as the oracle. Pure compute; wire integers little-endian.
 *
 *   long p2p_getheaders(u8* out, const u8* locator, long count,
 *                       const u8 stop[32]);     5 + 32*count + 32, or -1
 *        protocol version u32 | count (one byte: 1..252) | locator | stop
 *   long p2p_getdata_block(u8* out, const u8 hash[32]);          37
 *        count 1 | MSG_WITNESS_BLOCK 0x40000002 | hash -- the BIP144 type:
 *        plain MSG_BLOCK makes peers strip every witness (2026-08-22)
 *   long p2p_ping(u8* out, u64 nonce);                            8
 *   long p2p_headers_count(const u8* payload, long plen);  count / -1
 *        81-byte entries; a one-byte count or 0xfd u16 (0xfe/0xff refused);
 *        plen must hold the count and its entries
 *   long p2p_inv_count(const u8* payload, long plen);      count / -1
 *        36-byte items, the same count forms
 *   long p2p_inv_get(const u8* payload, long i, u32* type, u8 hash[32]);
 *        1 / 0 (i outside [0, count) or a 0xfe/0xff count)
 *
 * The protocol version is 70016, asm/version.inc's value, pinned here as in
 * the twin so a bump shows as a differential failure, not silent drift.
 * ========================================================================== */
#define NODE_PROTOCOL_VER 70016

    .text

/* p2p_getheaders(out=x0, locator=x1, count=x2, stop=x3) ; out x19, count x20,
 * stop x21 */
    .p2align 2
    .globl _p2p_getheaders
_p2p_getheaders:
    sub   x9, x2, #1
    cmp   x9, #251
    b.hi  9f                              /* count outside [1, 252] */
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x2
    mov   x21, x3
    movz  w9, #(NODE_PROTOCOL_VER & 0xffff)
    movk  w9, #(NODE_PROTOCOL_VER >> 16), lsl #16
    str   w9, [x19]
    strb  w20, [x19, #4]
    add   x0, x19, #5
    lsl   x2, x20, #5
    bl    _memcpy                         /* the locator */
    add   x0, x19, #5
    add   x0, x0, x20, lsl #5
    ldp   x9, x10, [x21]                  /* the stop hash */
    ldp   x11, x12, [x21, #16]
    stp   x9, x10, [x0]
    stp   x11, x12, [x0, #16]
    lsl   x0, x20, #5
    add   x0, x0, #37
    ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret
9:  mov   x0, #-1
    ret

/* p2p_getdata_block(out=x0, hash=x1) ; leaf */
    .p2align 2
    .globl _p2p_getdata_block
_p2p_getdata_block:
    mov   w9, #1
    strb  w9, [x0]
    movz  w9, #0x0002
    movk  w9, #0x4000, lsl #16            /* MSG_WITNESS_BLOCK */
    stur  w9, [x0, #1]
    ldp   x9, x10, [x1]
    ldp   x11, x12, [x1, #16]
    stur  x9, [x0, #5]
    stur  x10, [x0, #13]
    stur  x11, [x0, #21]
    stur  x12, [x0, #29]
    mov   x0, #37
    ret

/* p2p_ping(out=x0, nonce=x1) ; leaf */
    .p2align 2
    .globl _p2p_ping
_p2p_ping:
    str   x1, [x0]
    mov   x0, #8
    ret

/* Lcount(payload=x0, plen=x1, item=x2) -> x0 count / -1 ; leaf: a one-byte
 * count or 0xfd u16, and plen must hold count + count * item */
    .p2align 2
Lcount:
    cmp   x1, #1
    b.lt  9f
    ldrb  w9, [x0]
    cmp   w9, #0xfd
    b.lo  1f
    b.ne  9f                              /* 0xfe / 0xff */
    cmp   x1, #3
    b.lt  9f
    ldurh w9, [x0, #1]
    mov   x10, #3
    b     2f
1:  mov   x10, #1
2:  madd  x10, x9, x2, x10                /* the bytes needed */
    cmp   x10, x1
    b.gt  9f
    mov   x0, x9
    ret
9:  mov   x0, #-1
    ret

    .p2align 2
    .globl _p2p_headers_count
_p2p_headers_count:
    mov   x2, #81
    b     Lcount

    .p2align 2
    .globl _p2p_inv_count
_p2p_inv_count:
    mov   x2, #36
    b     Lcount

/* p2p_inv_get(payload=x0, i=x1, type=x2, hash=x3) ; leaf -- the count is
 * assumed validated by p2p_inv_count */
    .p2align 2
    .globl _p2p_inv_get
_p2p_inv_get:
    ldrb  w9, [x0]
    cmp   w9, #0xfd
    b.lo  1f
    b.ne  9f
    ldurh w9, [x0, #1]
    mov   x10, #3
    b     2f
1:  mov   x10, #1
2:  tbnz  x1, #63, 9f
    cmp   x1, x9
    b.ge  9f
    mov   x11, #36
    madd  x10, x1, x11, x10
    add   x10, x0, x10                    /* the item */
    ldr   w11, [x10]
    str   w11, [x2]
    ldur  x11, [x10, #4]
    ldur  x12, [x10, #12]
    stp   x11, x12, [x3]
    ldur  x11, [x10, #20]
    ldur  x12, [x10, #28]
    stp   x11, x12, [x3, #16]
    mov   x0, #1
    ret
9:  mov   x0, #0
    ret
