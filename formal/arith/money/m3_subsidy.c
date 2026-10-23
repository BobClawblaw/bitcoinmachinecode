/* M3: the coinbase subsidy. Real code: asm/daemon/utxo_live.c val_subsidy
 * (gen/m3_subsidy.inc). Reference: Core v31.1 validation.cpp
 * GetBlockSubsidy (`halvings = nHeight / interval; if (halvings >= 64)
 * return 0; 50*COIN >> halvings`).
 *
 * UNBOUNDED in the height (no loops): every height Core can see (int,
 * >= 0; bmc's `long` holds the same value). The halving interval is fixed
 * per run with -DINTERVAL= to each value a supported chain uses (210000 on
 * main/testnet4/signet, 150 on regtest: daemon/chainparams.c, and Core's
 * kernel/chainparams.cpp). A symbolic divisor did not close in 10 min
 * (64-bit vs 32-bit signed division equivalence is hard for SAT), so the
 * claim is per chain, not for an arbitrary interval. bmc's fallback (no
 * chain selected, or interval <= 0 -> 50 BTC) is outside Core's domain. */
#include <stdint.h>
#include "../lib/nondet.h"
#include "core_amount.h"

typedef unsigned char u8; typedef unsigned long u64; typedef unsigned int u32;
typedef struct { long halving_interval; } chainparams_t;
static const chainparams_t* g_chainp;
#include "gen/m3_subsidy.inc"

int main(void){
    int height = nondet_int(), interval = INTERVAL;
    ASSUME(height >= 0);
    chainparams_t cp; cp.halving_interval = interval; g_chainp = &cp;
    u64 b = val_subsidy((long)height);
    CAmount c = core_GetBlockSubsidy(height, interval);
    CHECK(c >= 0 && b == (u64)c, "SUBSIDY: val_subsidy == GetBlockSubsidy for every int height >= 0 (this chain interval)");
#ifdef REACH
    CHECK(b != 0, "REACH: a zero subsidy (halvings >= 64) is reachable (must FAIL)");
    CHECK(b != 5000000000ULL >> 63, "REACH: the last nonzero shift is reachable (must FAIL)");
#endif
    return 0;
}
