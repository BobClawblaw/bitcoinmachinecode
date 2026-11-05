/* L2: IsFinalTx. Real code: asm/daemon/seqlocks.h val_is_final (copied
 * verbatim into gen/ by gen.sh) and its block-path adapter
 * asm/daemon/utxo_live.c val_is_final_tx (gen/l2_isfinal_tx.inc). The
 * mempool path calls val_is_final directly (bitcoin_mempool_policy.c) with
 * the next height and the tip's MTP, i.e. the same arguments as Core's
 * CheckFinalTxAtTip (validation.cpp: nBlockHeight = tip+1, nBlockTime =
 * tip MTP); the block path passes the block height and the BIP113 cutoff.
 * Reference: Core v31.1 consensus/tx_verify.cpp IsFinalTx.
 *
 * UNBOUNDED (no loops): every nLockTime (u32), every height Core can hold
 * (int >= 0), every cutoff time a u32 nTime/MTP can be, and both values
 * of "some input has nSequence != SEQUENCE_FINAL" (computing that flag from
 * the inputs is the parser's job and is not verified here). */
#include <stdint.h>
#include <string.h>
#include "../lib/nondet.h"
#include "core_locks.h"

typedef unsigned char u8; typedef unsigned long u64; typedef unsigned int u32;
#include "gen/seqlocks.h"
#include "gen/l_txinfo.inc"
#include "gen/l2_isfinal_tx.inc"

int main(void){
    val_txinfo_t vi; memset(&vi, 0, sizeof vi);
    vi.locktime = nondet_u32();
    vi.any_nonfinal_seq = nondet_int();
    ASSUME(vi.any_nonfinal_seq == 0 || vi.any_nonfinal_seq == 1);
    long height = nondet_long();
    ASSUME(height >= 0 && height <= 0x7fffffffL);
    u32 cutoff = nondet_u32();

    int b  = val_is_final_tx(&vi, height, cutoff);                                   /* block path */
    int bm = val_is_final((unsigned long)vi.locktime, vi.any_nonfinal_seq, height,   /* mempool path */
                          (unsigned long)cutoff);
    int c  = core_IsFinalTx(vi.locktime, vi.any_nonfinal_seq, (int)height, (int64_t)cutoff);
    CHECK(b == c,  "FINAL: block-path val_is_final_tx == IsFinalTx");
    CHECK(bm == c, "FINAL: mempool-path val_is_final == IsFinalTx");
#ifdef REACH
    CHECK(!(c == 0 && vi.locktime >= 500000000u), "REACH: a time-locked non-final tx (must FAIL)");
    CHECK(!(c == 0 && vi.locktime < 500000000u), "REACH: a height-locked non-final tx (must FAIL)");
#endif
    return 0;
}
