/* L1: BIP113 median-time-past. Real code: asm/daemon/utxo_live.c val_mtp
 * (gen/l1_mtp.inc, verbatim), with its header read powr_hdr_from_store
 * stubbed to return a free 32-bit nTime per height (the store read itself
 * is trusted). Reference: Core v31.1 chain.h CBlockIndex::GetMedianTimePast:
 * collect up to nMedianTimeSpan=11 times walking pprev from this block,
 * std::sort, return pbegin[(pend - pbegin) / 2].
 *
 * Core's result is specified here WITHOUT re-implementing a sort: the
 * returned value r must be one of the n window times with
 *     #{x < r} <= n/2  <  #{x <= r}
 * which defines the element at sorted index n/2 uniquely (whatever the
 * sort algorithm). Comparison is in int64 on Core's side (GetBlockTime()
 * widens the uint32 nTime), u32 on bmc's -- the same order for these values.
 *
 * COMPLETE for the window: every height h >= 0 (so n = min(11, h+1),
 * including the short chains near genesis), every 32-bit time. The only
 * loops are the 11-entry window and the insertion sort (unwind 12, with
 * unwinding assertions). */
#include <stdint.h>
#include <string.h>
#include "../lib/nondet.h"
#include "core_locks.h"

typedef unsigned char u8; typedef unsigned long u64; typedef unsigned int u32;
static void* g_bip30_store = (void*)1;
static long g_h;                 /* the queried height */
static u32  g_t[11];             /* free nTime of heights g_h, g_h-1, ... g_h-10 */
static int powr_hdr_from_store(void* ctx, long k, u8 hdr[80]){
    (void)ctx;
    long off = g_h - k;
    __CPROVER_assert(off >= 0 && off < 11, "val_mtp reads only inside its 11-block window");
    memset(hdr, 0, 80);
    memcpy(hdr + 68, &g_t[off], 4);
    return 1;
}
#include "gen/l1_mtp.inc"

int main(void){
    g_h = nondet_long();
    ASSUME(g_h >= 0 && g_h <= 0x7fffffffL);          /* Core's int nHeight */
    for (int i = 0; i < 11; i++) g_t[i] = nondet_u32();
    int n = g_h + 1 < 11 ? (int)(g_h + 1) : 11;     /* Core: i < 11 && pindex */

    u32 r = 0;
    int ok = val_mtp(g_h, &r);
    CHECK(ok == 1, "val_mtp evaluates whenever every header is readable");

    int lt = 0, le = 0, member = 0;
    for (int i = 0; i < 11; i++){
        if (i >= n) break;
        int64_t x = (int64_t)g_t[i];
        if (x <  (int64_t)r) lt++;
        if (x <= (int64_t)r) le++;
        if (x == (int64_t)r) member = 1;
    }
    CHECK(member && lt <= n / 2 && n / 2 < le,
          "MTP: bmc returns Core's pbegin[(pend-pbegin)/2] of the sorted window");
#ifdef REACH
    CHECK(!(n == 11 && g_t[0] != r && g_t[10] != r), "REACH: full window, median not at an end (must FAIL)");
    CHECK(n != 4, "REACH: short window near genesis (must FAIL)");
#endif
    return 0;
}
