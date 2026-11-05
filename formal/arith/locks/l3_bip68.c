/* L3: BIP68 relative lock-time on the BLOCK path: CalculateSequenceLocks +
 * EvaluateSequenceLocks as ConnectBlock applies them.
 *
 * Real code: the Phase 4.55 block of apply_block_inner in
 * asm/daemon/utxo_live.c (gen/l3_bip68.inc, verbatim: the block holding
 * `long long min_height = -1, min_time = -1;`), which calls seqlocks.h's
 * val_seq_min_height / val_seq_min_time / val_seq_locks_ok (gen/seqlocks.h,
 * verbatim). Stubbed environment (trusted, not verified here):
 *   script_flags_for_block -> a free CSV-active bit (Core: nLockTimeFlags
 *                             has LOCKTIME_VERIFY_SEQUENCE iff CSV is active);
 *   val_read_tx            -> each tx's version / input count / sequences,
 *                             all free (the parser is not verified here);
 *   txvb_last_in_heights   -> the flat per-input coin-height ledger in block
 *                             order (what tx_verify.c exports), free heights
 *                             in [0, block height];
 *   val_mtp                -> a free but CONSISTENT function of the height
 *                             (memoised nondet; L1 proves val_mtp is Core's
 *                             GetMedianTimePast for a given window).
 * Reference: Core v31.1 consensus/tx_verify.cpp CalculateSequenceLocks /
 * EvaluateSequenceLocks, validation.cpp ConnectBlock (prevheights from
 * AccessCoin(...).nHeight; SequenceLocks(tx, nLockTimeFlags, prevheights,
 * *pindex) for every non-coinbase tx), Core types (version uint32_t,
 * nSequence uint32_t, heights int, times int64_t).
 *
 * BOUNDED: at most NTX transactions (coinbase + NTX-1) with at most KIN
 * inputs each; every version, sequence, coin height, height and MTP is free.
 * The per-input max-accumulation step is proved unbounded in l3_step.c. */
#include <stdint.h>
#include <string.h>
#include "../lib/nondet.h"
#include "core_locks.h"

#ifndef NTX
#define NTX 3
#endif
#ifndef KIN
#define KIN 2
#endif

typedef unsigned char u8; typedef unsigned long u64; typedef unsigned int u32;
#include "gen/seqlocks.h"
#include "gen/l_txinfo.inc"
#define VAL_SFC_BIT_CSV 10                       /* utxo_live.c, checked by gen.sh */
#define fprintf(...) ((void)0)

static long g_apply_height;
static const char* g_last_reject;
static const u8* blk_hash;
static int g_csv;
static unsigned long long script_flags_for_block(unsigned long long h, const u8* hash){
    (void)h; (void)hash;
    unsigned long long f = nondet_u64();
    f &= ~(1ULL << VAL_SFC_BIT_CSV);
    return f | ((unsigned long long)g_csv << VAL_SFC_BIT_CSV);
}
/* the transactions */
struct txref { const u8* ptr; u64 len; };
static u8 TAG[NTX];
static u32 g_ver[NTX]; static u64 g_nin[NTX]; static u32 g_seq[NTX][KIN];
static int val_read_tx(const u8* ptr, u64 len, val_txinfo_t* vi){
    (void)len;
    long t = ptr - TAG;
    __CPROVER_assert(t >= 0 && t < NTX, "val_read_tx called on a block tx");
    memset(vi, 0, sizeof *vi);
    vi->version = g_ver[t]; vi->in_count = g_nin[t];
    vi->seqs = g_seq[t]; vi->nseqs = (u32)g_nin[t];
    return 1;
}
/* the flat coin-height ledger (non-coinbase inputs, block order) */
static u64 g_in_h[NTX * KIN]; static unsigned int g_in_tx[NTX * KIN]; static unsigned long long g_nflat;
static const void* txvb_last_in_heights(unsigned long long* n, unsigned int** txidx){
    *n = g_nflat; *txidx = g_in_tx; return g_in_h;
}
/* MTP oracle: nondet, memoised so equal heights give equal times */
#define MQ (NTX * KIN + 2)
static long mq_h[MQ]; static u32 mq_v[MQ]; static int mq_n;
static u32 mtp_of(long h){
    for (int i = 0; i < MQ; i++){ if (i >= mq_n) break; if (mq_h[i] == h) return mq_v[i]; }
    __CPROVER_assert(mq_n < MQ, "MTP oracle table large enough");
    mq_h[mq_n] = h; mq_v[mq_n] = nondet_u32(); return mq_v[mq_n++];
}
static int val_mtp(long h, u32* out){ *out = mtp_of(h); return 1; }

static int bmc_bip68(struct txref* txs, u64 ntx){
#include "gen/l3_bip68.inc"
    return 1;
}

/* Core: ConnectBlock's per-tx SequenceLocks */
static int core_bip68(u64 ntx, int nHeight){
    if (!g_csv) return 1;                      /* flags lack LOCKTIME_VERIFY_SEQUENCE */
    u64 gi = 0;
    for (u64 t = 1; t < ntx; t++){
        int nMinHeight = -1; int64_t nMinTime = -1;
        int fEnforceBIP68 = g_ver[t] >= 2;
        for (u64 k = 0; k < g_nin[t]; k++){
            uint32_t nSequence = g_seq[t][k];
            int nCoinHeight = (int)g_in_h[gi++];
            if (!fEnforceBIP68) continue;
            if (nSequence & CORE_SEQ_DISABLE) continue;
            if (nSequence & CORE_SEQ_TYPE){
                const int64_t nCoinTime = (int64_t)mtp_of(core_maxi(nCoinHeight - 1, 0));
                nMinTime = core_max64(nMinTime, nCoinTime + (int64_t)((nSequence & CORE_SEQ_MASK) << CORE_SEQ_GRAN) - 1);
            } else {
                nMinHeight = core_maxi(nMinHeight, nCoinHeight + (int)(nSequence & CORE_SEQ_MASK) - 1);
            }
        }
        /* EvaluateSequenceLocks(block = the new block) */
        int64_t nBlockTime = (int64_t)mtp_of(nHeight - 1);
        if (nMinHeight >= nHeight || nMinTime >= nBlockTime) return 0;
    }
    return 1;
}

int main(void){
    u64 ntx = nondet_u64(); ASSUME(ntx >= 1 && ntx <= NTX);
    g_apply_height = nondet_long();
    ASSUME(g_apply_height >= 1 && g_apply_height <= 0x7fffffffL - 0x10000L);  /* Core int heights, no int overflow in coinHeight + 0xffff */
    g_csv = nondet_int(); ASSUME(g_csv == 0 || g_csv == 1);
    struct txref txs[NTX];
    g_nflat = 0;
    for (int t = 0; t < NTX; t++){
        txs[t].ptr = &TAG[t]; txs[t].len = 1;
        g_ver[t] = nondet_u32();
        g_nin[t] = nondet_u64(); ASSUME(g_nin[t] >= 1 && g_nin[t] <= KIN);
        for (int k = 0; k < KIN; k++) g_seq[t][k] = nondet_u32();
        if (t >= 1 && (u64)t < ntx){
            for (int k = 0; k < KIN; k++){
                if ((u64)k >= g_nin[t]) break;
                u64 ch = nondet_u64(); ASSUME(ch <= (u64)g_apply_height);
                g_in_h[g_nflat] = ch; g_in_tx[g_nflat] = (unsigned)t; g_nflat++;
            }
        }
    }
    mq_n = 0; g_last_reject = 0;
    int b = bmc_bip68(txs, ntx);
    int c = core_bip68(ntx, (int)g_apply_height);
    CHECK(b == c, "BIP68: bmc's block-path sequence locks accept iff Core's SequenceLocks accept");
#ifdef REACH
    CHECK(!(b == 0 && g_csv), "REACH: a BIP68 rejection (must FAIL)");
    CHECK(!(b == 1 && g_csv && ntx == NTX && g_ver[1] >= 2 && !(g_seq[1][0] & CORE_SEQ_DISABLE) && (g_seq[1][0] & CORE_SEQ_TYPE)),
          "REACH: an accepted time-locked input (must FAIL)");
#endif
    return 0;
}
