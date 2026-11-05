/* Bitcoin Core v31.1 time and lock rules, transcribed for the harnesses.
 * Types are Core's: nLockTime/nSequence/version uint32_t, nHeight int,
 * times int64_t. Source lines cited per function (src/ relative). */
#ifndef CORE_LOCKS_H
#define CORE_LOCKS_H
#include <stdint.h>
#define CORE_LOCKTIME_THRESHOLD 500000000          /* script/script.h */
#define CORE_SEQUENCE_FINAL 0xffffffffu             /* primitives/transaction.h */
#define CORE_SEQ_DISABLE (1U << 31)                 /* SEQUENCE_LOCKTIME_DISABLE_FLAG */
#define CORE_SEQ_TYPE    (1U << 22)                 /* SEQUENCE_LOCKTIME_TYPE_FLAG */
#define CORE_SEQ_MASK    0x0000ffffU                /* SEQUENCE_LOCKTIME_MASK */
#define CORE_SEQ_GRAN    9                          /* SEQUENCE_LOCKTIME_GRANULARITY */

/* consensus/tx_verify.cpp IsFinalTx; the input loop is summarised by
 * any_nonfinal = exists txin with nSequence != SEQUENCE_FINAL */
static inline int core_IsFinalTx(uint32_t nLockTime, int any_nonfinal, int nBlockHeight, int64_t nBlockTime){
    if (nLockTime == 0)
        return 1;
    if ((int64_t)nLockTime < ((int64_t)nLockTime < CORE_LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return 1;
    return !any_nonfinal;
}
static inline int64_t core_max64(int64_t a, int64_t b){ return a < b ? b : a; }
static inline int core_maxi(int a, int b){ return a < b ? b : a; }
#endif
