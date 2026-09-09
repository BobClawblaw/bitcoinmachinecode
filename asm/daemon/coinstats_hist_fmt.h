/* daemon/coinstats_hist_fmt.h -- the per-height rows of the coinstats index.
 *
 * Core's coinstatsindex persists a row per block so gettxoutsetinfo answers
 * at any height. This node's index (coinstats.dat) kept ONE record, the
 * running state at the applied tip, and refused historical queries. Since
 * 2026-09-08 the fold process also writes one row per committed height to
 * coinstats_hist.dat, positionally (row h at CSH_HDR + h * CSH_REC).
 *
 * A row carries the set's counters at that height (txouts, amount, bogo:
 * num minus den), the two MuHash accumulators (384 bytes each, so the digest
 * at that height is one finalize away), and the cumulative-since-baseline
 * amounts Core's index accumulates per block: prevout spent, coinbase,
 * new outputs excluding coinbase, unspendable scripts, genesis, BIP30, and
 * the subsidies. Core's RPC reports block_info as the DIFFERENCE between
 * two consecutive rows, so only the deltas matter and the baseline can be
 * zero; total_unspendable_amount is sum(subsidy 0..h) - total_amount, an
 * identity verified against Core at 800,000 and 966,000. The unclaimed
 * rewards of a block are subsidy + prevout_spent - new_outputs_ex_coinbase
 * - coinbase - genesis - bip30 - scripts, Core's own formula per block.
 *
 * gen: the generation. The index re-seeds from a walk after an invalidate;
 * the cumulatives restart at zero in a new generation and a delta is valid
 * only between rows of the same generation. The first row of a generation
 * (the baseline) has no block_info. */
#ifndef BMC_COINSTATS_HIST_FMT_H
#define BMC_COINSTATS_HIST_FMT_H
#include <stdint.h>
#define CSH_FILE    "coinstats_hist.dat"
/* 2026-09-08: the history is TWO files. The live index appends its rows to
 * coinstats_hist.dat (the tail, from the height it was seeded at); the
 * builder (daemon/build_coinstats_hist.c) writes coinstats_hist_base.dat
 * (the base, rows 0..to_height) to a temp name and renames it into place,
 * so the base is either whole or absent -- never half-written into the file
 * the daemon is appending to, which is what a build that died in pass 4
 * used to leave behind. The reader prefers the base for h <= to_height. */
#define CSH_BASE_FILE   "coinstats_hist_base.dat"
#define CSH_BASE_TMP    "coinstats_hist_base.dat.tmp"
#define CSH_BASE_MAGIC  0x42485343u   /* "CSHB" */
#define CSH_TMPDIR      "csh_tmp"     /* the builder's scratch, beside the archive; pass markers + a lock live here */
#define CSH_MAGIC   0x31485343u   /* "CSH1" */
#define CSH_ROW_TAG 0x52485343u   /* "CSHR" */
#define CSH_HDR     64
#define CSH_REC     1024
#define CSH_ACC     384
typedef struct __attribute__((packed)) {
    uint32_t magic, version, rec, gen;
    int64_t  first_height, last_height;
    uint8_t  pad[CSH_HDR - 32];
} csh_header_t;
/* the base's header (64 bytes, so row h sits at the same offset as in the
 * tail): complete is written LAST, after every row and an fsync; sum is the
 * sha256 over the concatenated row sums, so a boot check can verify the whole
 * file against one hash. */
typedef struct __attribute__((packed)) {
    uint32_t magic, version, rec, complete;
    int64_t  to_height, n_rows;
    uint8_t  sum[32];
} csh_base_header_t;
typedef struct __attribute__((packed)) {
    uint32_t tag, gen;
    int64_t  height;
    uint64_t txouts, amount, bogo;                       /* the set at this height (num - den) */
    uint64_t prevout_spent, coinbase, new_ex_cb;         /* cumulative since the generation's baseline */
    uint64_t unsp_scripts, unsp_genesis, unsp_bip30, subsidy_sum;
    uint8_t  num_acc[CSH_ACC], den_acc[CSH_ACC];
    uint8_t  pad[CSH_REC - 32 - (4 + 4 + 8 + 3 * 8 + 7 * 8 + 2 * CSH_ACC)];
    uint8_t  sum[32];                                    /* sha256 of everything before it */
} csh_row_t;
/* what the RPC needs for one height: the set, the per-block deltas, the digest */
typedef struct {
    long     height; uint32_t gen;
    uint64_t txouts, amount, bogo;
    uint64_t d_prevout, d_coinbase, d_new_ex_cb, d_scripts, d_genesis, d_bip30, d_unclaimed;
    uint64_t subsidy;                                    /* of this block */
    uint8_t  digest[32];                                 /* finalize order (the RPC reverses for display) */
    int      digest_valid;
} csi_hist_out_t;
/* BIP30's two unspendable coinbases, Core's rule (validation.cpp
 * IsBIP30Unspendable): heights 91,722 and 91,812 -- the ORIGINALS, whose
 * txids the coinbases of 91,842 and 91,880 repeated. Core's database
 * overwrote the originals with the duplicates (same txid, later height), so
 * the coins that exist carry the later heights and the originals' subsidy is
 * "unspendables.bip30". This node named the DUPLICATES here until
 * 2026-09-09: the coin count converged at the tip either way, but every
 * such coin hashed with the wrong height and the whole history base
 * disagreed with Core's MuHash from 91,722 on. One definition, used by the
 * builder and the live index's accounting. */
static inline int csh_bip30_unspendable(long h, int mainnet){ return mainnet && (h == 91722 || h == 91812); }
#endif
