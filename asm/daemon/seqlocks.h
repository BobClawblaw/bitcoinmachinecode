/* daemon/seqlocks.h -- BIP68 relative-timelock arithmetic, in ONE place.
 *
 * VAL-4 (block connect, daemon/utxo_live.c) and MEM-1 (mempool admission,
 * bitcoin_mempool_policy.c) are the same consensus rule applied at two
 * points. They must agree exactly: a mempool that admits what the block path
 * rejects fills the pool with transactions that can never confirm and feeds
 * them to getblocktemplate; one that rejects what the block path accepts
 * drops valid relay.
 *
 * HEADER-ONLY on purpose. The two consumers do not share a link island --
 * TXACCEPTOBJS does not include daemon/utxo_live.c -- so a .c file here would
 * mean adding it to a dozen test link lines. static inline costs nothing and
 * keeps one definition of the arithmetic, which is the point: the alternative
 * was transcribing Core's formulas twice.
 *
 * consensus/tx_verify.cpp, CalculateSequenceLocks:
 *     height-based:  minHeight = max(minHeight, coinHeight + (seq & MASK) - 1)
 *     time-based:    minTime   = max(minTime, coinMTP + ((seq & MASK) << 9) - 1)
 * and EvaluateSequenceLocks:
 *     satisfied iff  minHeight < nBlockHeight  AND  minTime < MTP(prev)
 *
 * The << 9 is BIP68's 512-second granularity; the -1 makes a lock satisfied
 * AT its boundary rather than one past it. Both are off-by-ones that produce
 * a chain split rather than a failing test, so they are transcribed and then
 * pinned by tests/test_bip68_locks.c against values computed from the BIP.
 *
 * IsFinalTx (the nLockTime rule) lives here too, for the same reason.
 */
#ifndef BMC_SEQLOCKS_H
#define BMC_SEQLOCKS_H

#define VAL_SEQ_DISABLE        (1u << 31)   /* SEQUENCE_LOCKTIME_DISABLE_FLAG */
#define VAL_SEQ_TYPE           (1u << 22)   /* SEQUENCE_LOCKTIME_TYPE_FLAG    */
#define VAL_SEQ_MASK           0x0000ffffu  /* SEQUENCE_LOCKTIME_MASK         */
#define VAL_SEQ_GRANULARITY    9            /* SEQUENCE_LOCKTIME_GRANULARITY  */
#define VAL_SEQUENCE_FINAL     0xffffffffu
#define VAL_LOCKTIME_THRESHOLD 500000000UL  /* height below, UNIX time at/above */

static inline long long val_seq_min_height(unsigned long coin_height, unsigned seq){
    return (long long)coin_height + (long long)(seq & VAL_SEQ_MASK) - 1;
}
static inline long long val_seq_min_time(unsigned long coin_mtp, unsigned seq){
    return (long long)coin_mtp
         + (long long)(((unsigned long long)(seq & VAL_SEQ_MASK)) << VAL_SEQ_GRANULARITY) - 1;
}
static inline int val_seq_locks_ok(long long min_height, long long min_time,
                                   long height, unsigned long tip_mtp){
    if (min_height >= (long long)height) return 0;
    if (min_time   >= (long long)tip_mtp) return 0;
    return 1;
}

/* Core's IsFinalTx, verbatim in structure:
 *     if (nLockTime == 0) return true;
 *     if (nLockTime < (nLockTime < LOCKTIME_THRESHOLD ? height : blocktime))
 *         return true;
 *     for (txin : vin) if (txin.nSequence != SEQUENCE_FINAL) return false;
 *     return true;
 * `any_nonfinal_seq` must be exact over EVERY input -- a capped scan that
 * treats surplus inputs as final is the wrong direction here, because missing
 * a non-final input means accepting what Core rejects. */
static inline int val_is_final(unsigned long locktime, int any_nonfinal_seq,
                               long height, unsigned long timecutoff){
    if (locktime == 0) return 1;
    long long cutoff = (locktime < VAL_LOCKTIME_THRESHOLD)
                     ? (long long)height : (long long)timecutoff;
    if ((long long)locktime < cutoff) return 1;
    return !any_nonfinal_seq;
}

#endif /* BMC_SEQLOCKS_H */
