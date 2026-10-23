/* daemon/hdrrules.h -- ContextualCheckBlockHeader's non-PoW rules.
 *
 * VAL-5 (audit 2026-09-03). The boot header fetch PoW-gates every header
 * since 141c786, and VAL-11 added the nBits range checks -- but Core's
 * ContextualCheckBlockHeader also enforces a timestamp floor, a timestamp
 * ceiling, and a minimum block version, and none of those existed here or in
 * reorg_analyze. 141c786's own message left them open, because wiring them
 * needed the parent's 11-header median window, which did not exist until
 * val_mtp landed with VAL-4.
 *
 * Core, validation.cpp:
 *   ContextualCheckBlockHeader
 *     block.GetBlockTime() <= pindexPrev->GetMedianTimePast()  -> "time-too-old"
 *     nVersion < 2 && height >= BIP34Height                    -> "bad-version"
 *     nVersion < 3 && height >= BIP66Height                    -> "bad-version"
 *     nVersion < 4 && height >= BIP65Height                    -> "bad-version"
 *   CheckBlockHeader / AcceptBlockHeader
 *     block.Time() > now + MAX_FUTURE_BLOCK_TIME (2 hours)     -> "time-too-new"
 *
 * WHY THE ACTIVATION HEIGHTS ARE NOT REPEATED HERE. Core keys the version
 * rules on BIP34/BIP66/BIP65 heights, which are per-chain. This tree already
 * generates those from Core's own chainparams into script_flags_consts.inc,
 * and script_flags_for_block() returns them as a bitmask. Taking the caller's
 * flags word means the rule follows the generated table rather than a second
 * copy of the numbers that could drift from it -- the same reason
 * gen_script_flags.py exists.
 *
 * BIP34 has no script flag of its own (it is not a script rule), so its
 * height is passed in; every caller already has val_bip34_height().
 *
 * HEADER-ONLY, like seqlocks.h: the callers -- daemon/main.c's boot fetch and
 * daemon/reorg.c -- do not share a link island, and this is four comparisons.
 */
#ifndef BMC_HDRRULES_H
#define BMC_HDRRULES_H

#include <string.h>
#include <stdint.h>

#define HDR_SFC_BIT_DERSIG 2   /* BIP66, script_flags_consts.inc */
#define HDR_SFC_BIT_CLTV   9   /* BIP65 */
#define HDR_MAX_FUTURE_BLOCK_TIME 7200L   /* Core MAX_FUTURE_BLOCK_TIME, 2h */

/* hdr = the 80-byte header. nVersion at +0, nTime at +68, both LE.
 * prev_mtp   = GetMedianTimePast() of the PARENT (0 disables the floor, for
 *              genesis or a window that could not be read -- the caller must
 *              decide whether that is acceptable; both current callers refuse
 *              rather than pass 0).
 * now        = current UNIX time (0 disables the ceiling, for replay of
 *              historical headers where "now" is meaningless).
 * flags      = script_flags_for_block(height, ...) for THIS height.
 * bip34_h    = the chain's BIP34 activation height.
 * Returns 1 ok, 0 with *reason set to Core's exact string. */
static inline int hdr_contextual_ok(long height, const unsigned char* hdr,
                                    unsigned long prev_mtp, long now,
                                    unsigned long long flags, long bip34_h,
                                    const char** reason){
    /* CON-5 (audit 2026-10-23): nVersion is Core's int32_t
     * (primitives/block.h), so a header with the top bit set is NEGATIVE
     * and fails every one of the version floors below. Read as unsigned,
     * 0x80000000.. passed them all and such a header was stored and its
     * block connected -- a chain Core refuses. */
    int32_t ver; unsigned int ntime;
    memcpy(&ver,   hdr,      4);
    memcpy(&ntime, hdr + 68, 4);

    if (prev_mtp && (unsigned long)ntime <= prev_mtp){ *reason = "time-too-old"; return 0; }
    if (now && (long)(unsigned long)ntime > now + HDR_MAX_FUTURE_BLOCK_TIME){
        *reason = "time-too-new"; return 0;
    }
    if (ver < 2 && height >= bip34_h){ *reason = "bad-version"; return 0; }
    if (ver < 3 && ((flags >> HDR_SFC_BIT_DERSIG) & 1ULL)){ *reason = "bad-version"; return 0; }
    if (ver < 4 && ((flags >> HDR_SFC_BIT_CLTV)   & 1ULL)){ *reason = "bad-version"; return 0; }
    return 1;
}

/* CON-8 (audit 2026-10-23): BIP94's timewarp rule, Core
 * ContextualCheckBlockHeader under consensus.enforce_BIP94 (testnet4; Core's
 * regtest only with -test=bip94, which this tree does not offer):
 *   if (nHeight % DifficultyAdjustmentInterval() == 0 &&
 *       block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP)
 *       -> "time-timewarp-attack"
 * MAX_TIMEWARP is 600 s; the interval is 2016 on every chain here
 * (bitcoin_pow_rules.c POW_INTERVAL). Both times are compared as int64, as
 * Core's GetBlockTime() returns them. prev_hdr = the parent's 80 bytes.
 * Returns 1 ok (or not enforced), 0 with *reason set. */
#define HDR_MAX_TIMEWARP 600L
#define HDR_DIFF_ADJ_INTERVAL 2016L
static inline int hdr_timewarp_ok(long height, const unsigned char* hdr,
                                  const unsigned char* prev_hdr, int enforce_bip94,
                                  const char** reason){
    if (!enforce_bip94 || height <= 0 || height % HDR_DIFF_ADJ_INTERVAL != 0) return 1;
    unsigned int t, pt;
    memcpy(&t,  hdr + 68, 4);
    memcpy(&pt, prev_hdr + 68, 4);
    if ((int64_t)t < (int64_t)pt - HDR_MAX_TIMEWARP){ *reason = "time-timewarp-attack"; return 0; }
    return 1;
}

#endif /* BMC_HDRRULES_H */
