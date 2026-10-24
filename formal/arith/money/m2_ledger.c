/* M2: ConnectBlock's value ledger -- CheckTxInputs' input-sum and in>=out
 * rules, the fee accumulator, and the coinbase cap (fees + subsidy).
 *
 * Real code: the Phase 4.5 block of apply_block_inner in
 * asm/daemon/utxo_live.c (gen/m2_ledger.inc, cut verbatim: the block that
 * holds `const u64* tx_in = txvb_last_tx_in_sums(...)`), plus val_subsidy
 * (gen/m3_subsidy.inc). Its inputs are modelled exactly as the product
 * produces them:
 *   tx_in[t]  = the u64 sum of the resolved prevout values of tx t, as
 *               tx_verify.c Phase 1 accumulates them
 *               (`g_tx_in_sums[in->tx_index] += value;`);
 *   ptx_out[t]= tx t's output total, which M1 proves equals Core's
 *               GetValueOut() and is in [0, MAX_MONEY] for every block that
 *               reaches this phase (money_bad rejects the rest first).
 * Reference: Core v31.1 validation.cpp ConnectBlock (the loop calling
 * Consensus::CheckTxInputs, `nFees += txfee; if (!MoneyRange(nFees))`, and
 * `blockReward = nFees + GetBlockSubsidy(...)`, `GetValueOut() > blockReward`)
 * and consensus/tx_verify.cpp CheckTxInputs (per-coin and running MoneyRange,
 * nValueIn < value_out, MoneyRange(txfee)).
 *
 * BOUNDED: at most NTX transactions (1 coinbase + NTX-1 others) with at most
 * KIN inputs each; every value and the height are free; the halving
 * interval is fixed per run (-DINTERVAL=210000 / 150, as in M3). The unbounded per-transaction step is proved separately in z3
 * (m2_ledger_induction.py), and the input-sum width argument in
 * m2_insum_width.py.
 *
 * ASSUMPTION A-UTXO: every coin a transaction spends has a value in
 * [0, MAX_MONEY] (each was an output that passed M1 when its block
 * connected). Core's per-coin MoneyRange(coin.out.nValue) is then always
 * true; the harness still evaluates it. */
#include <stdint.h>
#include <string.h>
#include "../lib/nondet.h"
#include "core_amount.h"

#ifndef NTX
#define NTX 4
#endif
#ifndef KIN
#define KIN 3
#endif

typedef unsigned char u8; typedef unsigned long u64; typedef unsigned int u32;
#define VAL_MAX_MONEY 2100000000000000ULL   /* checked equal to the product's by M1's cut */
typedef struct { long halving_interval; } chainparams_t;   /* the one field read */
static const chainparams_t* g_chainp;
static long g_apply_height;
static const char* g_last_reject;
static const u64* g_tx_in; static u64 g_tx_in_n;
static const u64* txvb_last_tx_in_sums(u64* n){ *n = g_tx_in_n; return g_tx_in; }
#define fprintf(...) ((void)0)

#include "gen/m3_subsidy.inc"

static int bmc_ledger(u64 ntx, u64* ptx_out){
#include "gen/m2_ledger.inc"
    return 1;
}

static const char* core_reason;
static int core_connect(u64 ntx, const int64_t coin[NTX][KIN], const u64 kin[NTX],
                        const int64_t out[NTX], int height, int interval){
    CAmount nFees = 0;
    for (u64 t = 1; t < ntx; t++){
        /* CheckTxInputs */
        CAmount nValueIn = 0;
        for (u64 i = 0; i < kin[t]; i++){
            nValueIn += coin[t][i];
            if (!core_MoneyRange(coin[t][i]) || !core_MoneyRange(nValueIn)){
                core_reason = "bad-txns-inputvalues-outofrange"; return 0;
            }
        }
        const CAmount value_out = out[t];
        if (nValueIn < value_out){ core_reason = "bad-txns-in-belowout"; return 0; }
        const CAmount txfee_aux = nValueIn - value_out;
        if (!core_MoneyRange(txfee_aux)){ core_reason = "bad-txns-fee-outofrange"; return 0; }
        /* ConnectBlock */
        nFees += txfee_aux;
        if (!core_MoneyRange(nFees)){ core_reason = "bad-txns-accumulated-fee-outofrange"; return 0; }
    }
    CAmount blockReward = nFees + core_GetBlockSubsidy(height, interval);
    if (out[0] > blockReward){ core_reason = "bad-cb-amount"; return 0; }
    return 1;
}

int main(void){
    u64 ntx = nondet_u64();
    ASSUME(ntx >= 1 && ntx <= NTX);
    int height = nondet_int(), interval = INTERVAL;   /* per chain, as M3 */
    ASSUME(height >= 0);
    chainparams_t cp; cp.halving_interval = interval; g_chainp = &cp;
    g_apply_height = height;

    int64_t coin[NTX][KIN]; u64 kin[NTX]; int64_t out[NTX];
    u64 tx_in[NTX]; u64 ptx_out[NTX];
    for (int t = 0; t < NTX; t++){
        kin[t] = nondet_u64(); ASSUME(kin[t] >= 1 && kin[t] <= KIN);
        u64 s = 0;
        for (int i = 0; i < KIN; i++){
            coin[t][i] = nondet_ll();
            ASSUME(coin[t][i] >= 0 && coin[t][i] <= CORE_MAX_MONEY);      /* A-UTXO */
            if ((u64)i < kin[t]) s += (u64)coin[t][i];                    /* tx_verify.c accumulator */
        }
        tx_in[t] = s;
        out[t] = nondet_ll();
        ASSUME(out[t] >= 0 && out[t] <= CORE_MAX_MONEY);                   /* M1 */
        ptx_out[t] = (u64)out[t];
    }
    g_tx_in = tx_in; g_tx_in_n = ntx;
    g_last_reject = 0; core_reason = 0;

    int b = bmc_ledger(ntx, ptx_out);
    int c = core_connect(ntx, (const int64_t (*)[KIN])coin, kin, out, height, interval);

    CHECK(b == c, "LEDGER: bmc accepts iff Core's CheckTxInputs + fees + bad-cb-amount accept");
    CHECK(b || c || (strcmp(core_reason, "bad-txns-accumulated-fee-outofrange") == 0
                       ? strcmp(g_last_reject, "bad-txns-fee-outofrange") == 0
                       : strcmp(g_last_reject, core_reason) == 0),
          "REASON: same reject string (the accumulated-fee case maps to bmc's bad-txns-fee-outofrange)");
#ifdef REACH
    CHECK(!(b && ntx == NTX), "REACH: a full-size accepted block exists (must FAIL)");
    CHECK(!(!b && core_reason && strcmp(core_reason, "bad-cb-amount") == 0), "REACH: bad-cb-amount reachable (must FAIL)");
    CHECK(!(!b && core_reason && strcmp(core_reason, "bad-txns-in-belowout") == 0), "REACH: in-belowout reachable (must FAIL)");
    CHECK(!(!b && core_reason && strcmp(core_reason, "bad-txns-accumulated-fee-outofrange") == 0), "REACH: accumulated-fee reachable (must FAIL)");
    CHECK(!(!b && core_reason && strcmp(core_reason, "bad-txns-inputvalues-outofrange") == 0), "REACH: inputvalues-outofrange reachable (must FAIL)");
#endif
    return 0;
}
