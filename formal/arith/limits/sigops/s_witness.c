/* L-S3: WitnessSigOps for one witness program.
 *
 * bmc: the REAL txv_witness_sigops (asm/daemon/tx_verify.c), with
 * script_sigops_accurate stubbed as an opaque counter that records its
 * argument (both sides count the same bytes with the same function; that
 * function itself is checked by sg_diff against Core's GetSigOpCount).
 * The caller passes wit_last = the last witness item, or NULL when the
 * input's witness stack is empty (txv_sigop_cost_tx: in->nwit ? ... : 0).
 * Core v31.1 (script/interpreter.cpp WitnessSigOps):
 *     if (witversion == 0) {
 *         if (witprogram.size() == WITNESS_V0_KEYHASH_SIZE) return 1;
 *         if (witprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE && witness.stack.size() > 0)
 *             return CScript(witness.stack.back()).GetSigOpCount(true);
 *     }
 *     return 0;
 * -DALL: no assumption (expected to FAIL: a 20-byte v0 program with an
 * EMPTY witness stack counts 0 here, 1 in Core). Default: assumes a
 * non-empty stack for 20-byte v0 programs -- see NOTES.md for why the
 * excluded case cannot change a block's validity. */
#include <stdint.h>
#include "../../lib/nondet.h"
typedef unsigned char u8; typedef unsigned long u64;
static int g_called; static const u8* g_p; static unsigned long g_l; static long g_ret;
static long script_sigops_accurate(const u8* s, unsigned long l){ g_called = 1; g_p = s; g_l = l; return g_ret; }
#include "../gen/s_witness_sigops.inc"
int main(void){
    int wver = nondet_int(); ASSUME(wver >= 0 && wver <= 16);
    unsigned long proglen = nondet_u64(); ASSUME(proglen >= 2 && proglen <= 40);
    unsigned long nwit = nondet_u64(); ASSUME(nwit <= 3);
    static u8 item[4];
    unsigned long il = nondet_u64(); ASSUME(il <= 4);
    const u8* wl = nwit ? (const u8*)item : (const u8*)0; unsigned long wll = nwit ? il : 0;
    g_ret = nondet_long(); ASSUME(g_ret >= 0 && g_ret < 1000);
#ifndef ALL
    ASSUME(!(wver == 0 && proglen == 20 && nwit == 0));
#endif
    g_called = 0;
    u64 b = txv_witness_sigops(wver, proglen, wl, wll);
    long c = 0; int c_counts = 0;
    if (wver == 0){
        if (proglen == 20) c = 1;
        else if (proglen == 32 && nwit > 0){ c = g_ret; c_counts = 1; }
    }
#ifdef REACH
    CHECK(!(c_counts), "REACH a P2WSH count");
    CHECK(!(c == 1 && !c_counts), "REACH a P2WPKH count");
#else
    CHECK((long)b == c, "WitnessSigOps equals Core");
    CHECK(g_called == c_counts && (!c_counts || (g_p == item && g_l == il)),
          "counts exactly the last witness item, exactly when Core does");
#endif
    return 0;
}
