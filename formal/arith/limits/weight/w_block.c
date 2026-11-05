/* L-W: CheckBlock's size rules and ContextualCheckBlock's weight rule.
 *
 * bmc: the REAL text of apply_block_inner's empty-block return, Phase 0.10
 * (bad-blk-length) and Phase 0.27 (bad-blk-weight), asm/daemon/utxo_live.c,
 * cut into gen/ by gen.sh and run here in their original order. val_read_tx
 * is stubbed: it returns each transaction's stripped (TX_NO_WITNESS) size
 * and whether it decodes, both nondet -- that the real val_read_tx computes
 * Core's GetSerializeSize(TX_NO_WITNESS(tx)) is a separate obligation (see
 * NOTES.md, not covered here).
 *
 * Core v31.1 validation.cpp:
 *   CheckBlock:  if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT ||
 *                    ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
 *                    -> bad-blk-length
 *   ContextualCheckBlock: if (GetBlockWeight(block) > MAX_BLOCK_WEIGHT) -> bad-blk-weight
 *   GetBlockWeight = GetSerializeSize(TX_NO_WITNESS(block)) * (WITNESS_SCALE_FACTOR - 1)
 *                    + GetSerializeSize(TX_WITH_WITNESS(block))        (consensus/validation.h)
 * with TX_NO_WITNESS(block) = 80 header bytes + CompactSize(ntx) + sum of the
 * stripped tx sizes, and blocklen = the whole serialization (cons_verify
 * requires the transactions to end exactly at the end of the buffer).
 *
 * Domain: ntx <= MAXT (the loop bound) OR ntx * 4 > 4,000,000 (rejected
 * before the loop); consumed = the canonical CompactSize width of ntx (what
 * utxo_walk_read_varint returns, proved in cs/); stripped sizes and blocklen
 * below 2^40 (a block is < 4 MiB on the wire), sum of stripped <= blocklen.
 * -DNONEMPTY additionally assumes ntx >= 1. */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "../../lib/nondet.h"
typedef unsigned char u8; typedef unsigned long u64;
#define fprintf(...) ((void)0)
#define VAL_DECODE_FAILED "decode-failed"
static const char* g_last_reject; static int g_last_mutated; static long g_apply_height;
typedef struct { const u8* ptr; u64 len; } block_tx_t;
typedef struct { u64 stripped_len; } val_txinfo_t;
#define MAXT 3
static u64 g_sl[MAXT]; static int g_dec[MAXT];
/* stub: txs[t].len carries t, so the stub can answer per transaction */
static int val_read_tx(const u8* p, u64 len, val_txinfo_t* vi){
    (void)p; vi->stripped_len = g_sl[len]; return g_dec[len];
}
enum { ACCEPT = 1, REJECT = 0, DECODE = 2 };
static int bmc_check(u64 ntx, u64 consumed, block_tx_t* txs, u64 blocklen){
#include "../gen/w_ntx0.inc"
    u64 stripped = 0;
#include "../gen/w_phase010.inc"
#include "../gen/w_phase027.inc"
    return 1;
}
int main(void){
    u64 ntx = nondet_u64(), blocklen = nondet_u64();
    ASSUME(ntx <= 0x02000000ULL);                 /* utxo_walk_read_varint's range */
    ASSUME(ntx <= MAXT || ntx * 4 > 4000000ULL);
#ifdef NONEMPTY
    ASSUME(ntx >= 1);
#endif
    u64 consumed = ntx < 0xfd ? 1 : ntx <= 0xffff ? 3 : 5;
    block_tx_t txs[MAXT];
    u64 sum = 0; int all_dec = 1;
    for (u64 t = 0; t < MAXT; t++){
        txs[t].ptr = 0; txs[t].len = t;
        g_sl[t] = nondet_u64(); ASSUME(g_sl[t] < (1ULL << 40));
        g_dec[t] = nondet_int(); ASSUME(g_dec[t] == 0 || g_dec[t] == 1);
        if (t < ntx){ sum += g_sl[t]; if (!g_dec[t]) all_dec = 0; }
    }
    ASSUME(blocklen < (1ULL << 40) && sum <= blocklen);
    g_last_reject = ""; g_last_mutated = 0;
    int r = bmc_check(ntx, consumed, txs, blocklen);
    int bmc = r ? ACCEPT : (g_last_mutated ? DECODE : REJECT);
    /* Core */
    int core;
    if (ntx > MAXT) core = REJECT;                    /* vtx.size() * 4 > MAX_BLOCK_WEIGHT */
    else if (!all_dec) core = DECODE;                 /* the block does not deserialize */
    else {
        u64 S = 80 + consumed + sum;
        if (ntx == 0 || S * 4 > 4000000ULL) core = REJECT;
        else if (S * 3 + blocklen > 4000000ULL) core = REJECT;
        else core = ACCEPT;
    }
#ifdef REACH
    CHECK(core != ACCEPT, "REACH an accepted block");
    CHECK(!(core == REJECT && ntx >= 1 && ntx <= MAXT), "REACH a size/weight reject");
#else
    CHECK(bmc == core, "accept / reject / decode-failure equals Core");
#endif
    return 0;
}
