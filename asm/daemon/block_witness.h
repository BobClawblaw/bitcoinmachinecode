/* block_witness.h -- BIP141 coinbase witness-commitment validation.
 *
 * Mirrors Bitcoin Core's CheckWitnessMalleation (src/validation.cpp:3886-3930,
 * v31.99) + GetWitnessCommitmentIndex (src/consensus/validation.h:147-160) +
 * BlockWitnessMerkleRoot (src/consensus/merkle.cpp:76-85). Gated the way Core
 * gates it: ContextualCheckBlock passes
 * DeploymentActiveAfter(pindexPrev, SEGWIT) (validation.cpp:4185), i.e.
 * height >= SegwitHeight -- NOT the WITNESS script flag, which Core keeps on
 * from genesis. This codebase's script_flags_for_block sets SFC_BIT_NULLDUMMY
 * exactly when height >= SFC_HEIGHT_SEGWIT (bitcoin_script_flags.asm), so
 * that bit is the runtime source of truth for "segwit active".
 *
 * Why this exists (2026-08-22): the archive held witness-STRIPPED bodies for
 * every block >= 481824 (getdata asked for MSG_BLOCK, not MSG_WITNESS_BLOCK)
 * and nothing noticed, because the tx merkle root only commits to txids.
 * Core rejects a stripped block at once: the coinbase's 32-byte witness
 * nonce is gone -> "bad-witness-nonce-size". This check is what was missing.
 */
#ifndef BLOCK_WITNESS_H
#define BLOCK_WITNESS_H
#include <stdint.h>

/* Bit SFC_BIT_NULLDUMMY in script_flags_consts.inc (generated from Core's
 * chainparams). tests/test_witness_commitment.c cross-checks this value
 * against script_flags_for_block() at runtime so a regenerated .inc cannot
 * silently diverge from it. */
#define BW_SFC_BIT_NULLDUMMY 4

/* Leading 16 bytes of utxo_live.c's block_tx_t (ptr, len). The caller passes
 * its tx array plus the stride; block_witness never sees the rest. */
typedef struct { const uint8_t* ptr; uint64_t len; } bw_txref_t;

/* Returns 1 = block passes, 0 = reject (*reason = Core's reject string:
 * "bad-witness-nonce-size" | "bad-witness-merkle-match" |
 * "unexpected-witness"), -1 = internal error (malformed tx / scratch too
 * small; *reason set). `txs` is an array of `ntx` records of `stride` bytes
 * whose first 16 bytes are a bw_txref_t. `scratch` needs ntx*32 bytes. */
long block_check_witness_commitment(const void* txs, uint64_t ntx, uint64_t stride,
                                    int segwit_active,
                                    uint8_t* scratch, uint64_t scratch_cap,
                                    const char** reason);

/* Exposed for tests: walk one tx's wire form. Returns 1 ok / 0 malformed.
 * has_witness = 1 iff the tx carries the segwit marker AND at least one input
 * has a non-empty witness stack (Core's CTransaction::HasWitness). For the
 * coinbase the caller also wants input 0's stack shape. commit = pointer to
 * the 32-byte commitment in the LAST qualifying output, or NULL. */
int bw_walk_tx(const uint8_t* tx, uint64_t len, int* has_witness,
               uint64_t* in0_stack_n, uint64_t* in0_item0_len, const uint8_t** in0_item0,
               const uint8_t** commit);
#endif
