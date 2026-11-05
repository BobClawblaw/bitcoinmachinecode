/* M1: CheckTransaction's output-value rules on the BLOCK path.
 *
 * Real code: asm/daemon/utxo_live.c idxbuild_on_output (and the
 * idxbuild_ctx_t it updates, and VAL_MAX_MONEY), cut verbatim into
 * gen/m1_*.inc by run.sh. Reference: Core v31.1 consensus/tx_check.cpp
 * CheckTransaction, the loop over tx.vout:
 *     if (txout.nValue < 0)          -> bad-txns-vout-negative
 *     if (txout.nValue > MAX_MONEY)  -> bad-txns-vout-toolarge
 *     nValueOut += txout.nValue;
 *     if (!MoneyRange(nValueOut))    -> bad-txns-txouttotal-toolarge
 * Core reads nValue as int64 off the wire; bmc reads the same 8 bytes as
 * u64, so the harness feeds one 64-bit pattern to both, reinterpreted.
 *
 * UNBOUNDED by induction over the number of outputs. The relation
 *     R:  bmc.money_bad == core_bad
 *         && (!core_bad -> bmc.tx_out_sum == core_sum == *ptx_out
 *                          && 0 <= core_sum <= MAX_MONEY)
 * holds for the initial state (BASE, below: the ctx is built with
 * `idxbuild_ctx_t ic = { &bx, &bs, txid, t, 0 }` and *ptx_out zeroed by
 * memset) and is preserved by one output (STEP: any state satisfying R, any
 * 64-bit value). So after any number of outputs, bmc's reject bit equals
 * Core's and, when both accept, the per-tx output total handed to the fee
 * ledger (ptx_out[t]) equals Core's GetValueOut(). Core stops at the first
 * failure; once bad, core_bad stays 1 and bmc.money_bad is never cleared,
 * so the relation also covers bmc continuing the walk. */
#include <stddef.h>
#include <string.h>
#include "../lib/nondet.h"
#include "core_amount.h"

typedef unsigned char u8; typedef unsigned long u64; typedef unsigned int u32;
typedef struct bidx_t bidx_t; typedef struct bspent_t bspent_t;
/* callees with no effect on the money state: stubs */
static void bidx_insert(bidx_t* bx, const u8 key[36], u64 value, const u8* spk, u32 spklen,
                        u32 tx_index, u8 is_cb){ (void)bx;(void)key;(void)value;(void)spk;(void)spklen;(void)tx_index;(void)is_cb; }
static void* g_utxo_table;
static void utxo_prefetch(void* t, const u8* txid, u32 idx){ (void)t;(void)txid;(void)idx; }

#include "gen/m1_maxmoney.inc"
#include "gen/m1_ctx.inc"
#include "gen/m1_on_output.inc"

static u8 TXID[32];

int main(void){
    /* ---- BASE ---- */
    {
        idxbuild_ctx_t ic = { 0, 0, TXID, 0u, 0 };
        CHECK(ic.money_bad == 0 && ic.tx_out_sum == 0, "BASE: fresh ctx is (bad=0,sum=0) = Core's (ok, nValueOut=0)");
    }
    /* ---- STEP ---- */
    u64 ptx[1];
    idxbuild_ctx_t c;
    memset(&c, 0, sizeof c);
    c.txid = TXID; c.tx_index = 0; c.ptx_out = ptx;
    c.money_bad = nondet_int();
    c.tx_out_sum = nondet_u64();
    ptx[0] = nondet_u64();
    int core_bad = nondet_int();
    CAmount core_sum = nondet_ll();
    ASSUME(c.money_bad == 0 || c.money_bad == 1);
    ASSUME(core_bad == c.money_bad);
    ASSUME(core_bad || (core_sum >= 0 && core_sum <= CORE_MAX_MONEY &&
                        c.tx_out_sum == (u64)core_sum && ptx[0] == (u64)core_sum));

    u64 wire = nondet_u64();                  /* the 8 value bytes, LE */
    u32 out_index = nondet_u32();
    u8 script[4]; u32 slen = 0;

    idxbuild_on_output(&c, out_index, wire, script, slen);       /* bmc */

    if (!core_bad){                                              /* Core */
        CAmount nValue = (CAmount)wire;
        if (nValue < 0) core_bad = 1;
        else if (nValue > CORE_MAX_MONEY) core_bad = 1;
        else {
            core_sum += nValue;
            if (!core_MoneyRange(core_sum)) core_bad = 1;
        }
    }
    CHECK(c.money_bad == core_bad, "STEP: reject bit equals Core's");
    CHECK(core_bad || (c.tx_out_sum == (u64)core_sum && ptx[0] == (u64)core_sum
                       && core_sum >= 0 && core_sum <= CORE_MAX_MONEY),
          "STEP: accepted totals equal Core's nValueOut and stay in MoneyRange");
#ifdef REACH
    CHECK(!(core_bad == 0 && wire > 0), "REACH: an accepted nonzero output exists (must FAIL)");
    CHECK(!(core_bad == 1 && c.tx_out_sum < 5), "REACH: a rejected state exists (must FAIL)");
#endif
    return 0;
}
