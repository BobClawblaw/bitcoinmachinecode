/* L-S1: the block sigop budget.
 *
 * bmc: the REAL text of apply_block_inner's Phase 4.6 (asm/daemon/utxo_live.c),
 * which sums tx_verify.c's per-transaction cost export and rejects
 * bad-blk-sigops once the running total exceeds 80,000. bmc has no separate
 * CheckBlock legacy-count check.
 *
 * Core v31.1 has TWO checks:
 *   CheckBlock (validation.cpp:4019): unsigned int nSigOps = sum of
 *     GetLegacySigOpCount(tx); if (nSigOps * WITNESS_SCALE_FACTOR >
 *     MAX_BLOCK_SIGOPS_COST) -> bad-blk-sigops
 *   ConnectBlock (validation.cpp:2571): nSigOpsCost += GetTransactionSigOpCost
 *     (tx, view, flags); if (nSigOpsCost > MAX_BLOCK_SIGOPS_COST) -> bad-blk-sigops
 * where GetTransactionSigOpCost = legacy*4 (+ p2sh*4 + witness, non-coinbase).
 *
 * Model: per tx t a nondet legacy count L_t and a nondet extra E_t >= 0
 * (E_0 = 0: the coinbase), and bmc's export cost_t = 4*L_t + E_t -- the
 * shape txv_sigop_cost_tx and the coinbase export compute (that they compute
 * Core's L_t and E_t from the scripts is the separate obligation covered by
 * the sigop differential, sg_diff). Claim: bmc rejects iff Core rejects.
 * Bounds: ntx in [1, MAXT]; L_t < 2^24 and E_t < 2^30 (a 4 MB block cannot
 * carry more: at most 20 sigops per script byte). */
#include <stdint.h>
#include <stdio.h>
#include "../../lib/nondet.h"
typedef unsigned char u8; typedef unsigned long u64;
#define fprintf(...) ((void)0)
static const char* g_last_reject; static long g_apply_height;
#define MAXT 4
static unsigned long long g_cost[MAXT]; static unsigned long long g_n;
static unsigned long long* txvb_last_tx_sigops(unsigned long long* n){ if (n) *n = g_n; return g_cost; }
static int bmc_phase46(u64 ntx){
#include "../gen/s_phase46.inc"
    return 1;
}
int main(void){
    u64 ntx = nondet_u64(); ASSUME(ntx >= 1 && ntx <= MAXT);
    unsigned int legacy_sum = 0;        /* Core: unsigned int nSigOps */
    long long cost_sum = 0;             /* Core: int64_t nSigOpsCost */
    int core_reject = 0;
    for (u64 t = 0; t < MAXT; t++){
        unsigned L = nondet_u32(); ASSUME(L < (1u << 24));
        unsigned long long E = nondet_u64(); ASSUME(E < (1ULL << 30));
        if (t == 0) ASSUME(E == 0);
        g_cost[t] = 4ULL * L + E;
        if (t < ntx){
            legacy_sum += L;
            cost_sum += (long long)(4ULL * L + E);
            if (cost_sum > 80000) core_reject = 1;          /* ConnectBlock, running */
        }
    }
    if (legacy_sum * 4u > 80000u) core_reject = 1;          /* CheckBlock */
    g_n = ntx;
    int bmc_accept = bmc_phase46(ntx);
#ifdef REACH
    CHECK(!bmc_accept, "REACH accept");
    CHECK(!(!bmc_accept && ntx > 1), "REACH reject with several txs");
#else
    CHECK(bmc_accept == !core_reject, "bad-blk-sigops decision equals Core's two checks");
#endif
    return 0;
}
