/* daemon/blk_submit.c -- the download worker's half of `submitblock`.
 *
 * Evaluates a staged block against the chain state the worker owns and
 * answers with a BIP22 result string. THIS SLICE NEVER CONNECTS THE BLOCK:
 * a block that passes every check this file can run still answers
 * "inconclusive", which is BIP22's honest word for "this node cannot
 * conclusively evaluate" -- full evaluation (a UTXO-level dry run of the
 * apply path, then store append + apply + relay) is the follow-up slice,
 * and pretending otherwise by appending an un-dry-run block would let a
 * submitted block wedge catch-up exactly the way the 2026-08 witness-
 * stripped archive did. The checks that DO run produce Core's exact
 * reason strings:
 *   "duplicate"                the block is already our tip
 *   "high-hash"                header hash does not meet its own target
 *   "bad-txnmrklroot"          PoW fine, cons_verify still refuses (the
 *                              dominant remaining cause is the tx merkle)
 *   "bad-witness-merkle-match" BIP141 commitment mismatch (the check the
 *                              stripped-archive incident taught us to run)
 *   "inconclusive"             prev is not our tip (side chain / unknown),
 *                              or everything above passed
 */
#include <stdio.h>
#include <string.h>
typedef unsigned char u8;
typedef unsigned long long u64;
typedef unsigned int u32;

extern int  cons_verify(const void* block, long len, void* scratch, unsigned cap);
extern void sha256d(u8 out[32], const void* data, unsigned long len);
extern unsigned long long script_flags_for_block(unsigned long long height, const u8 hash[32]);

/* NULLDUMMY bit index in the flag schedule == segwit activation gate; the
 * same constant daemon/utxo_live.c uses (block_witness.h documents it). */
#include "block_witness.h"
#include "signet_block.h"

/* (ptr,len) span per tx -- the prefix block_check_witness_commitment reads. */
typedef struct { const u8* ptr; u64 len; } bsub_tx_t;
#define BSUB_MAX_TX 16384

static u64 bsub_varint(const u8* p, const u8* end, u64* v){
    if (p >= end) return 0;
    if (p[0] < 0xfd){ *v = p[0]; return 1; }
    if (p[0] == 0xfd){ if (p+3 > end) return 0; *v = (u64)p[1] | ((u64)p[2]<<8); return 3; }
    if (p[0] == 0xfe){ if (p+5 > end) return 0;
        *v = (u64)p[1]|((u64)p[2]<<8)|((u64)p[3]<<16)|((u64)p[4]<<24); return 5; }
    if (p+9 > end) return 0;
    *v = 0; for (int i=0;i<8;i++) *v |= (u64)p[1+i]<<(8*i); return 9;
}
/* length of one serialized tx at p (segwit-aware); 0 on parse failure */
static u64 bsub_txlen(const u8* p, const u8* end){
    const u8* q = p;
    if (q + 4 > end) return 0;
    q += 4;
    int segwit = (q + 2 <= end && q[0] == 0x00 && q[1] == 0x01);
    if (segwit) q += 2;
    u64 nin, c;
    if (!(c = bsub_varint(q, end, &nin))) return 0; q += c;
    if (nin == 0 || nin > 1u<<20) return 0;
    for (u64 i = 0; i < nin; i++){
        if (q + 36 > end) return 0; q += 36;
        u64 sl; if (!(c = bsub_varint(q, end, &sl))) return 0; q += c;
        if (q + sl + 4 > end) return 0; q += sl + 4;
    }
    u64 nout; if (!(c = bsub_varint(q, end, &nout))) return 0; q += c;
    if (nout == 0 || nout > 1u<<20) return 0;
    for (u64 i = 0; i < nout; i++){
        if (q + 8 > end) return 0; q += 8;
        u64 sl; if (!(c = bsub_varint(q, end, &sl))) return 0; q += c;
        if (q + sl > end) return 0; q += sl;
    }
    if (segwit){
        for (u64 i = 0; i < nin; i++){
            u64 items; if (!(c = bsub_varint(q, end, &items))) return 0; q += c;
            for (u64 k = 0; k < items; k++){
                u64 il; if (!(c = bsub_varint(q, end, &il))) return 0; q += c;
                if (q + il > end) return 0; q += il;
            }
        }
    }
    if (q + 4 > end) return 0;
    q += 4;
    return (u64)(q - p);
}

/* arith SetCompact for the PoW check (big-endian target bytes) */
static void bsub_target(u32 bits, u8 t[32]){
    memset(t, 0, 32);
    int size = bits >> 24; u32 word = bits & 0x007fffff;
    if (size <= 3){ word >>= 8*(3-size); t[31]=(u8)word; t[30]=(u8)(word>>8); t[29]=(u8)(word>>16); }
    else { int sh = size - 3;
        for (int i = 0; i < 3; i++){ int pos = 31 - sh - i;
            if (pos >= 0 && pos < 32) t[pos] = (u8)(word >> (8*i)); } }
}

/* 1 = would-be-acceptable so far (caller answers "inconclusive" this slice),
 * 0 = reason set. tip_hash/tip_height come from the store the worker owns. */
/* check_pow=0 is BIP23 proposal mode (Core TestBlockValidity's fCheckPOW=
 * false): the caller is validating an UNMINED template, so the hash-vs-
 * target check is skipped; everything else is identical. */
long blk_submit_evaluate_ex(const u8* blk, unsigned long len,
                            const u8 tip_hash[32], long tip_height,
                            int check_pow,
                            char* reason, unsigned long rcap){
    if (reason && rcap) reason[0] = 0;
#define RSN(s) do{ if (reason && rcap) snprintf(reason, rcap, "%s", s); }while(0)
    if (len < 81){ RSN("Block decode failed"); return 0; }

    u8 hash[32]; sha256d(hash, blk, 80);
    if (tip_hash && !memcmp(hash, tip_hash, 32)){ RSN("duplicate"); return 0; }

    /* PoW against the header's own bits (Core CheckProofOfWork) */
    if (check_pow){
      u32 bits = (u32)blk[72] | ((u32)blk[73]<<8) | ((u32)blk[74]<<16) | ((u32)blk[75]<<24);
      u8 target[32], hbe[32];
      bsub_target(bits, target);
      for (int i = 0; i < 32; i++) hbe[i] = hash[31-i];      /* LE hash -> BE */
      int cmp = memcmp(hbe, target, 32);
      if (cmp > 0){ RSN("high-hash"); return 0; } }

    /* full consensus structural check (merkle, sizes). PoW already passed,
     * so a refusal here is dominantly the tx merkle root -- Core's string. */
    { static u8 scratch[4u<<20];
      if (cons_verify(blk, (long)len, scratch, sizeof scratch) != 1){
          RSN("bad-txnmrklroot"); return 0; } }

    /* per-tx spans for the BIP141 witness-commitment check */
    { static bsub_tx_t txs[BSUB_MAX_TX];
      const u8* end = blk + len;
      const u8* q = blk + 80;
      u64 ntx, c = bsub_varint(q, end, &ntx);
      if (!c || ntx == 0 || ntx > BSUB_MAX_TX){ RSN("bad-blk-length"); return 0; }
      q += c;
      for (u64 i = 0; i < ntx; i++){
          u64 tl = bsub_txlen(q, end);
          if (!tl){ RSN("bad-blk-length"); return 0; }
          txs[i].ptr = q; txs[i].len = tl; q += tl;
      }
      if (q != end){ RSN("bad-blk-length"); return 0; }
      unsigned long long bflags = script_flags_for_block((unsigned long long)(tip_height + 1), hash);
      int segwit_active = (int)((bflags >> BW_SFC_BIT_NULLDUMMY) & 1ULL);
      const char* wreason = "?";
      static u8 wscratch[BSUB_MAX_TX * 32 * 2];
      if (block_check_witness_commitment(txs, ntx, sizeof(bsub_tx_t), segwit_active,
                                         wscratch, sizeof wscratch, &wreason) != 1){
          RSN("bad-witness-merkle-match"); return 0; }

      /* BIP325, gated on check_pow exactly as Core gates it on fCheckPOW
       * (validation.cpp:3947). That half of the gate is not decoration: BIP23
       * proposal mode passes fCheckPOW=0, and a proposal has no signature
       * yet, so demanding one would reject every legitimate template
       * proposal. A no-op on every chain but signet. */
      if (check_pow){
          const char* sreason = "?";
          if (signet_check_block_chain(txs, ntx, sizeof(bsub_tx_t), blk, &sreason) != 1){
              RSN(sreason); return 0; }
      } }

    /* linkage: only a tip-extending block is evaluable in this slice */
    if (tip_hash && memcmp(blk + 4, tip_hash, 32) != 0){ RSN("inconclusive"); return 0; }

    return 1;   /* consensus-clean and tip-extending; caller: "inconclusive" */
#undef RSN
}

/* legacy entry: full check including PoW (submitblock path, tests) */
long blk_submit_evaluate(const u8* blk, unsigned long len,
                         const u8 tip_hash[32], long tip_height,
                         char* reason, unsigned long rcap){
    return blk_submit_evaluate_ex(blk, len, tip_hash, tip_height, 1, reason, rcap);
}
