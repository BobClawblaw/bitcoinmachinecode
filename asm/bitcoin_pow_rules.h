/* bitcoin_pow_rules.h -- the ONE implementation of Core's GetNextWorkRequired
 * (pow.cpp), shared by getblocktemplate (rpc_chain.c) and header/block
 * VALIDATION (utxo_live apply, blk_submit dry-run, reorg fork evaluation).
 *
 * Extracted from rpc_chain.c's gbt_next_bits/rpc_chain_retarget so mining and
 * enforcement can never drift apart: a template this node builds is, by
 * construction, one its own validator accepts, and vice versa. rpc_chain.c's
 * exported rpc_chain_retarget(old_bits, ts) remains as a thin wrapper (the
 * hermetic KAT surface, vectors frozen from an arith_uint256-faithful
 * reference).
 *
 * Chain-awareness mirrors chainparams: fPowNoRetargeting (regtest),
 * fPowAllowMinDifficultyBlocks + the 20-minute exception + the walk-back
 * (testnet4), enforce_BIP94 (testnet4: the boundary retarget bases on the
 * FIRST block of the period), and the standard 2016-block retarget with
 * Satoshi's 2015-interval timespan (mainnet). Verified by
 * validation/pow_replay.c against EVERY header of the real mainnet chain
 * (964k+ heights, 478 retarget boundaries) and the real testnet4 chain
 * (149k+ heights, min-difficulty + BIP94 exercised) -- see LOG.md
 * 2026-08-27 and tests/test_pow_rules.
 */
#ifndef BITCOIN_POW_RULES_H
#define BITCOIN_POW_RULES_H

/* Header access: fill hdr80 with the 80-byte header at `height`; return 1 ok,
 * anything else = unavailable. Every consumer supplies its own reader (the
 * GBT path reads the archive, the replay tool an in-memory mirror). */
typedef int (*powr_hdr_fn)(void* ctx, long height, unsigned char hdr80[80]);

/* Core pow.cpp CalculateNextWorkRequired's arithmetic: retarget `base_bits`
 * by `actual_timespan` (clamped to [T/4, 4T]), capped at `pow_limit_bits`.
 * Pure; exact arith_uint256 semantics (40-byte big-int, truncating divide,
 * GetCompact normalization). */
unsigned int pow_retarget_bits(unsigned int base_bits, long actual_timespan,
                               unsigned int pow_limit_bits);

/* Core pow.cpp GetNextWorkRequired: the REQUIRED nBits for the block at
 * `height` (>= 1) whose header time is `blocktime` (consulted only on
 * min-difficulty chains), with ancestors read through get(ctx, h, hdr).
 * Chain rules are passed explicitly so validation paths cannot depend on a
 * hidden global being set: no_retarget / allow_min_diff / enforce_bip94 and
 * the chain's compact powLimit. Returns the expected compact bits, or 0 if
 * a needed ancestor header could not be read (callers treat 0 as
 * "cannot evaluate", never as a match). */
unsigned int pow_expected_bits(long height, long blocktime,
                               powr_hdr_fn get, void* ctx,
                               int no_retarget, int allow_min_diff,
                               int enforce_bip94, unsigned int pow_limit_bits);

/* Convenience for validators: 1 if `hdr80` (the header proposed at `height`)
 * carries exactly the required nBits, 0 if not, -1 if it cannot be evaluated
 * (missing ancestor). Reads blocktime and nBits out of the header itself. */
int pow_check_bits(long height, const unsigned char hdr80[80],
                   powr_hdr_fn get, void* ctx,
                   int no_retarget, int allow_min_diff,
                   int enforce_bip94, unsigned int pow_limit_bits);

#endif
