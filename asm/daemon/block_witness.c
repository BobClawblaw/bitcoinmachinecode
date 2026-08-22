/* block_witness.c -- BIP141 coinbase witness-commitment validation.
 * See block_witness.h for the Core citations and why this exists. */
#include <stdio.h>
#include <string.h>
#include "block_witness.h"

typedef uint8_t u8; typedef uint64_t u64;

extern void merkle_root(u8 out[32], u8* hashes, u64 n);           /* bitcoin_hash.asm: IN PLACE on hashes */
extern void sha256d(u8 out[32], const void* msg, int64_t len);    /* bitcoin_hash.asm */

static int rd_varint(const u8* p, const u8* end, u64* v, u64* used){
    if (p >= end) return 0;
    u8 b = p[0];
    if (b < 0xfd) { *v = b; *used = 1; return 1; }
    if (b == 0xfd){ if (p+3>end) return 0; *v = p[1] | ((u64)p[2]<<8); *used=3; return 1; }
    if (b == 0xfe){ if (p+5>end) return 0; *v = p[1]|((u64)p[2]<<8)|((u64)p[3]<<16)|((u64)p[4]<<24); *used=5; return 1; }
    if (p+9>end) return 0;
    *v = 0; for (int i=0;i<8;i++) *v |= (u64)p[1+i] << (8*i); *used = 9; return 1;
}

/* Wire form: version(4) [00 01] vin vout [witness] locktime(4).
 * The marker test is the same one tx_parse uses (bitcoin_tx.asm:73-76): a
 * legacy tx cannot have n_in == 0, so tx[4]==0x00 && tx[5]==0x01 is
 * unambiguous. */
int bw_walk_tx(const u8* tx, u64 len, int* has_witness,
               u64* in0_stack_n, u64* in0_item0_len, const u8** in0_item0,
               const u8** commit)
{
    const u8* end = tx + len; const u8* p = tx;
    u64 v, used, nin, nout;
    *has_witness = 0; *in0_stack_n = 0; *in0_item0_len = 0; *in0_item0 = 0; *commit = 0;
    if (len < 10) return 0;
    p += 4;
    int segwit = (len >= 6 && p[0] == 0x00 && p[1] == 0x01);
    if (segwit) p += 2;
    if (!rd_varint(p, end, &nin, &used)) return 0;
    p += used;
    for (u64 i = 0; i < nin; i++){
        if (p + 36 > end) return 0;
        p += 36;
        if (!rd_varint(p, end, &v, &used)) return 0;
        p += used;
        if (v > (u64)(end - p)) return 0;
        p += v;
        if (p + 4 > end) return 0;
        p += 4;
    }
    if (!rd_varint(p, end, &nout, &used)) return 0;
    p += used;
    for (u64 o = 0; o < nout; o++){
        if (p + 8 > end) return 0;
        p += 8;
        if (!rd_varint(p, end, &v, &used)) return 0;
        p += used;
        if (v > (u64)(end - p)) return 0;
        /* GetWitnessCommitmentIndex: LAST output wins; size >= 38 (MINIMUM_
         * WITNESS_COMMITMENT) and the 6-byte prefix OP_RETURN PUSH36 aa21a9ed. */
        if (v >= 38 && p[0]==0x6a && p[1]==0x24 && p[2]==0xaa && p[3]==0x21 && p[4]==0xa9 && p[5]==0xed)
            *commit = p + 6;
        p += v;
    }
    if (segwit){
        for (u64 i = 0; i < nin; i++){
            u64 nitems;
            if (!rd_varint(p, end, &nitems, &used)) return 0;
            p += used;
            if (i == 0) *in0_stack_n = nitems;
            for (u64 k = 0; k < nitems; k++){
                if (!rd_varint(p, end, &v, &used)) return 0;
                p += used;
                if (v > (u64)(end - p)) return 0;
                if (i == 0 && k == 0){ *in0_item0_len = v; *in0_item0 = p; }
                p += v;
            }
            if (nitems) *has_witness = 1;
        }
    }
    if (p + 4 > end) return 0;
    p += 4;                                        /* locktime */
    return p == end;
}

long block_check_witness_commitment(const void* txs, u64 ntx, u64 stride,
                                    int segwit_active,
                                    u8* scratch, u64 scratch_cap,
                                    const char** reason)
{
    if (ntx == 0) return 1;
    #define TX(i) ((const bw_txref_t*)((const u8*)txs + (i)*stride))
    int cb_wit; u64 cb_n, cb_len; const u8* cb_item; const u8* commit;
    if (!bw_walk_tx(TX(0)->ptr, TX(0)->len, &cb_wit, &cb_n, &cb_len, &cb_item, &commit)){
        *reason = "coinbase: malformed tx"; return -1;
    }

    /* validation.cpp:3888-3921 -- only when segwit is active and the coinbase
     * commits: nonce must be exactly one 32-byte item, then
     * sha256d(witness_root || nonce) must equal the committed 32 bytes, where
     * witness_root is the merkle root over wtxids with the coinbase's wtxid
     * taken as 0x00..00 (merkle.cpp:76-85). */
    if (segwit_active && commit){
        if (cb_n != 1 || cb_len != 32){ *reason = "bad-witness-nonce-size"; return 0; }
        if (scratch_cap < ntx * 32){ *reason = "witness-commitment: scratch too small"; return -1; }
        memset(scratch, 0, 32);
        /* wtxid = sha256d over the full witness serialization, i.e. the raw
         * bytes as stored (bitcoin_cmpct.asm's tx_wtxid is the same call). */
        for (u64 t = 1; t < ntx; t++) sha256d(scratch + t*32, TX(t)->ptr, (int64_t)TX(t)->len);
        u8 root[32], buf[64], h[32];
        merkle_root(root, scratch, ntx);
        memcpy(buf, root, 32); memcpy(buf + 32, cb_item, 32);
        sha256d(h, buf, 64);
        if (memcmp(h, commit, 32) != 0){ *reason = "bad-witness-merkle-match"; return 0; }
        return 1;
    }

    /* validation.cpp:3924-3930 -- no commitment (or segwit not active): no
     * transaction may carry witness data at all. */
    for (u64 t = 0; t < ntx; t++){
        int hw; u64 a, b; const u8* c; const u8* d;
        if (t == 0) hw = cb_wit;
        else if (!bw_walk_tx(TX(t)->ptr, TX(t)->len, &hw, &a, &b, &c, &d)){ *reason = "malformed tx"; return -1; }
        if (hw){ *reason = "unexpected-witness"; return 0; }
    }
    return 1;
    #undef TX
}
