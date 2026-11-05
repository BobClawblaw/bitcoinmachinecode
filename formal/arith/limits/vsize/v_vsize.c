/* L-V: BIP141 weight/vsize and the sigops-adjusted virtual size (policy).
 *
 * bmc (asm/bitcoin_mempool_policy.c), REAL text:
 *   parse_tx:        m->weight = m->nonwit_len * 3 + txlen;  m->vsize = (m->weight + 3) / 4;
 *   mpol_add_core:   the bytespersigop block (sigops_x = the parked BIP141
 *                    sigop cost, x4 units; adjusted = max(weight, cost * bps))
 *   mpool_policy_set_bytespersigop (the configured value, 0 -> 20)
 * Core v31.1:
 *   GetTransactionWeight = stripped * (WITNESS_SCALE_FACTOR - 1) + total
 *   GetSigOpsAdjustedWeight(w, c, bps) = std::max(w, c * bps)      (policy.cpp:376)
 *   GetVirtualTransactionSize(w, c, bps) = (adjusted + 3) / 4       (policy.cpp:381)
 *   all int64_t; bps is unsigned int nBytesPerSigOp.
 * Claim: the entry vsize bmc uses equals Core's GetVirtualTransactionSize.
 * Domain: nonwit_len <= txlen < 2^32; sigop cost < 2^32; the configured
 * bytespersigop fixed per run with -DBPS= (run.sh: 1, the default 20, and
 * the config maximum 100000; node_config.c clamps -bytespersigop to
 * [1, 100000]). A symbolic bytespersigop did not close in 11 min (a 64x64
 * multiply on both sides), so the claim is per configured value.
 * -DBPS0 hands 0 to mpool_policy_set_bytespersigop (expected to FAIL: bmc
 * maps 0 to 20, Core's 0 disables the sigop term; bmc's config parser
 * refuses 0, so the daemon never passes it; see NOTES.md). */
#include <stdint.h>
#include "../../lib/nondet.h"
static uint64_t mpol_pending_sigops;
static uint64_t mpol_bytes_per_sigop = 20;
#include "../gen/v_set_bps.inc"
typedef struct { uint64_t nonwit_len, weight, vsize; } mpol_txmeta;
static void parse_tail(mpol_txmeta* m, unsigned long txlen){
#include "../gen/v_weight.inc"
}
static uint64_t entry_vsize(mpol_txmeta meta){
    uint64_t vsize = meta.vsize;
#include "../gen/v_adjusted.inc"
    return vsize;
}
int main(void){
    unsigned long txlen = nondet_u64(); ASSUME(txlen < (1ULL << 32));
    uint64_t nonwit = nondet_u64(); ASSUME(nonwit <= txlen);
    uint64_t cost = nondet_u64(); ASSUME(cost < (1ULL << 32));
#ifdef BPS0
    unsigned long long cfg = 0;          /* Core's -bytespersigop=0 (bmc's config refuses it) */
#else
    unsigned long long cfg = BPS;        /* one configured value per run (run.sh: 1, 20, 100000) */
#endif
    mpool_policy_set_bytespersigop(cfg);
    mpol_txmeta m; m.nonwit_len = nonwit;
    parse_tail(&m, txlen);
    mpol_pending_sigops = cost;
    uint64_t b = entry_vsize(m);
    /* Core */
    int64_t w = (int64_t)nonwit * 3 + (int64_t)txlen;
    unsigned int bps = (unsigned int)cfg;
    int64_t adj = w > (int64_t)cost * bps ? w : (int64_t)cost * bps;
    int64_t c = (adj + 4 - 1) / 4;
#ifdef REACH
    CHECK(!(cost * bps > (uint64_t)w), "REACH the sigop term dominates");
    CHECK(!(cost > 0 && cost * bps < (uint64_t)w), "REACH weight dominates with sigops");
#else
    CHECK(b == (uint64_t)c, "entry vsize equals Core GetVirtualTransactionSize");
    CHECK(m.weight == (uint64_t)w, "weight equals Core GetTransactionWeight");
    CHECK(mpol_pending_sigops == 0, "the parked count is consumed");
#endif
    return 0;
}
