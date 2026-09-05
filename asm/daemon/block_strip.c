/* daemon/block_strip.c -- serialize a block WITHOUT witness data, for a peer
 * that requested a bare MSG_BLOCK (not MSG_WITNESS_BLOCK).
 *
 * WHY: the serve loop holds every block in its full (witness) serialization
 * and, until now, sent that for any block getdata -- correct for a modern
 * peer (which asks MSG_WITNESS_BLOCK and wants the witnesses), but a strict
 * pre-BIP144 peer that asked for a bare MSG_BLOCK cannot parse the segwit
 * marker/flag bytes and drops the message. Core serves the STRIPPED form to
 * exactly that request. This produces it: header + tx count + each
 * transaction in its non-witness serialization (the same bytes the merkle
 * root and txid commit to). Length == Core's `strippedsize`.
 *
 * Built on the KAT-proven strip_witness_asm (bitcoin_strip_witness.asm),
 * one transaction at a time -- no second stripping implementation.
 */
#include <string.h>

typedef unsigned char u8;

extern long strip_witness_asm(const u8* tx, long txlen, u8* out, long cap);

static unsigned long bs_varint(const u8* p, const u8* end, unsigned* consumed){
    *consumed = 0;
    if (p >= end) return 0;
    if (p[0] < 0xfd){ *consumed = 1; return p[0]; }
    if (p[0] == 0xfd){ if (p+3 > end) return 0; *consumed = 3; return (unsigned long)p[1] | ((unsigned long)p[2]<<8); }
    if (p[0] == 0xfe){ if (p+5 > end) return 0; *consumed = 5;
        return (unsigned long)p[1] | ((unsigned long)p[2]<<8) | ((unsigned long)p[3]<<16) | ((unsigned long)p[4]<<24); }
    if (p+9 > end) return 0;
    *consumed = 9;
    unsigned long v = 0; for (int i = 0; i < 8; i++) v |= (unsigned long)p[1+i] << (8*i);
    return v;
}

/* Walk one transaction to its end (full, witness-inclusive), returning its
 * length or 0 on malformation. Mirrors the serve/index walkers. */
static long bs_tx_len(const u8* p, const u8* end){
    const u8* s = p;
    if (p + 4 > end) return 0;
    p += 4;
    int segwit = (p + 2 <= end && p[0] == 0x00 && p[1] == 0x01);
    if (segwit) p += 2;
    unsigned cc;
    unsigned long nin = bs_varint(p, end, &cc); if (!cc || !nin) return 0;
    p += cc;
    for (unsigned long i = 0; i < nin; i++){
        if (p + 36 > end) return 0;
        p += 36;
        unsigned long sl = bs_varint(p, end, &cc); if (!cc) return 0;
        p += cc;
        /* VAL-15 (audit 2026-09-03): `< sl + 4` WRAPS for sl in
         * [2^64-4, 2^64-1], moving p BACKWARDS by 0..4 bytes instead of
         * refusing. Split so neither side can overflow -- the same form
         * tx_verify.c already uses. */
        { unsigned long avail = (unsigned long)(end - p);
          if (sl > avail || avail - sl < 4) return 0; }
        p += sl + 4;
    }
    unsigned long nout = bs_varint(p, end, &cc); if (!cc) return 0;
    p += cc;
    for (unsigned long i = 0; i < nout; i++){
        if (p + 8 > end) return 0;
        p += 8;
        unsigned long sl = bs_varint(p, end, &cc); if (!cc) return 0;
        p += cc;
        if ((unsigned long)(end - p) < sl) return 0;
        p += sl;
    }
    if (segwit){
        for (unsigned long i = 0; i < nin; i++){
            unsigned long items = bs_varint(p, end, &cc); if (!cc) return 0;
            p += cc;
            for (unsigned long k = 0; k < items; k++){
                unsigned long il = bs_varint(p, end, &cc); if (!cc) return 0;
                p += cc;
                if ((unsigned long)(end - p) < il) return 0;
                p += il;
            }
        }
    }
    if (p + 4 > end) return 0;
    p += 4;
    return (long)(p - s);
}

/* block_strip_witness(blk, blen, out, cap) -> stripped length, or 0.
 * If the block has no segwit transaction the output equals the input (a
 * legal no-op strip); either way the result is the non-witness form. */
long block_strip_witness(const u8* blk, long blen, u8* out, long cap){
    if (blen < 81 || cap < 81) return 0;
    const u8* end = blk + blen;
    memcpy(out, blk, 80);
    long o = 80;
    const u8* p = blk + 80;
    unsigned cc;
    unsigned long ntx = bs_varint(p, end, &cc);
    if (!cc || !ntx) return 0;
    if (o + (long)cc > cap) return 0;
    memcpy(out + o, p, cc); o += cc; p += cc;   /* tx count varint, unchanged */
    for (unsigned long t = 0; t < ntx; t++){
        long tl = bs_tx_len(p, end);
        if (tl <= 0) return 0;
        long sl = strip_witness_asm(p, tl, out + o, cap - o);
        if (sl <= 0) return 0;
        o += sl;
        p += tl;
    }
    return o;
}
