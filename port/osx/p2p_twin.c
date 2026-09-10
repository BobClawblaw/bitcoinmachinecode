/* ============================================================================
 * p2p_twin.c -- Bitcoin P2P message payload builders/parsers, macOS/AArch64.
 * Functional twin of asm/bitcoin_p2p.asm (branch bmc_osx). Pure compute --
 * no syscalls; all wire integers LITTLE-endian (Bitcoin convention).
 *
 *   long p2p_getheaders(u8 *out, const u8 *locator, long count,
 *                       const u8 stop[32]);
 *       -> payload length 5 + count*32 + 32, or -1 (count outside [1,252]).
 *          Wire: protocol version u32 LE | count CompactSize (1 byte, the
 *          whole accepted range fits) | count*32 locator hashes | stop hash.
 *          Stage A: multi-hash locator (count==1 callers unaffected).
 *   long p2p_getdata_block(u8 *out, const u8 hash[32]);          -> 37.
 *       [count varint=1][type int32 LE = MSG_WITNESS_BLOCK 0x40000002]
 *       [hash 32]. Plain MSG_BLOCK (2) makes peers strip every witness
 *       (2026-08-22 segwit finding) -- keep the BIP144 type.
 *   long p2p_ping(u8 *out, u64 nonce);                            -> 8.
 *   long p2p_headers_count(const u8 *payload, long plen);
 *       -> header-entry CompactSize count, or -1 malformed. Header entry
 *          is 81 bytes; accepts 1-byte varints (incl. 0xfc) and 0xfd u16;
 *          0xfe/0xff reject. plen must hold varintlen + count*81.
 *   long p2p_inv_count(const u8 *payload, long plen);
 *       -> inventory entry count, or -1. Item is 36B (type u32 LE + hash32);
 *          1-byte varints + 0xfd u16 only; 0xfe/0xff reject.
 *   long p2p_inv_get(const u8 *payload, long i, u32 *out_type,
 *                    u8 out_hash[32]);
 *       -> 1 ok / 0 (i out of range or bad varint). Assumes count validated
 *          by p2p_inv_count.
 *
 * NODE_PROTOCOL_VER single source of truth is asm/version.inc (70016);
 * the C side normally reads the Makefile-generated version_gen.h -- this
 * twin pins 70016 with that pointer so a version bump shows up as a
 * cross-arch differential failure instead of silent drift.
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef unsigned char u8;

#define NODE_PROTOCOL_VER 70016u   /* asm/version.inc -- do not bump here */
#define P2P_MSG_WITNESS_BLOCK 0x40000002u

long p2p_getheaders(u8 *out, const u8 *locator, long count, const u8 stop[32])
{
    if (count < 1 || count > 252) return -1;
    u32 ver = NODE_PROTOCOL_VER;
    memcpy(out + 0, &ver, 4);
    out[4] = (u8)count;
    memcpy(out + 5, locator, (size_t)count * 32);
    memcpy(out + 5 + (size_t)count * 32, stop, 32);
    return 5 + count * 32 + 32;
}

long p2p_getdata_block(u8 *out, const u8 hash[32])
{
    out[0] = 1;                                /* inventory count varint */
    u32 t = P2P_MSG_WITNESS_BLOCK;
    memcpy(out + 1, &t, 4);                    /* int32 LE at +1 (unaligned) */
    memcpy(out + 5, hash, 32);
    return 37;
}

long p2p_ping(u8 *out, u64 nonce)
{
    memcpy(out, &nonce, 8);                    /* 8-byte LE nonce */
    return 8;
}

long p2p_headers_count(const u8 *payload, long plen)
{
    if (plen < 1) return -1;
    u8 al = payload[0];
    long count, vlen;
    if (al < 0xfd || al == 0xfc) {             /* 1-byte path (0xfc never used) */
        count = al;
        vlen = 1;
    } else if (al == 0xfd) {
        if (plen < 3) return -1;
        u16 w;
        memcpy(&w, payload + 1, 2);            /* LE u16, unaligned-safe */
        count = w;
        vlen = 3;
    } else {
        return -1;                             /* 0xfe / 0xff */
    }
    long needed = vlen + count * 81;
    if (needed > plen) return -1;              /* (u64 math on x86; count<=0xffff */
    return count;                              /*  so no overflow in long) */
}

long p2p_inv_count(const u8 *payload, long plen)
{
    if (plen < 1) return -1;
    u8 al = payload[0];
    long count, vlen;
    if (al < 0xfd) {
        count = al;
        vlen = 1;
    } else if (al == 0xfd) {
        if (plen < 3) return -1;
        u16 w;
        memcpy(&w, payload + 1, 2);
        count = w;
        vlen = 3;
    } else {
        return -1;                             /* 0xfe / 0xff not used for inv */
    }
    long needed = vlen + count * 36;
    if (needed > plen) return -1;
    return count;
}

long p2p_inv_get(const u8 *payload, long i, u32 *out_type, u8 out_hash[32])
{
    u8 al = payload[0];
    long count, vlen;
    if (al < 0xfd) {
        count = al;
        vlen = 1;
    } else if (al == 0xfd) {
        u16 w;
        memcpy(&w, payload + 1, 2);
        count = w;
        vlen = 3;
    } else {
        return 0;                              /* 0xfe / 0xff */
    }
    if (i < 0 || i >= count) return 0;
    const u8 *item = payload + vlen + (size_t)i * 36;
    u32 t;
    memcpy(&t, item, 4);                       /* type u32 LE */
    *out_type = t;
    memcpy(out_hash, item + 4, 32);
    return 1;
}
