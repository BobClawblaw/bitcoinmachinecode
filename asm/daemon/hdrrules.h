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
    unsigned int ver, ntime;
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

#endif /* BMC_HDRRULES_H */
