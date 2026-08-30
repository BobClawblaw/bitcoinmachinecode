/* daemon/signet_block.h -- BIP325 applied to a whole block.
 *
 * Core calls this from CheckBlock, right after CheckBlockHeader and only when
 * `signet_blocks && fCheckPOW` (validation.cpp:3947). The fCheckPOW half of
 * that gate is not decoration: BIP23 proposal mode passes fCheckPOW=0, and a
 * proposal has no signature yet.
 */
#ifndef SIGNET_BLOCK_H
#define SIGNET_BLOCK_H
#include <stdint.h>

/* Leading 16 bytes of utxo_live.c's block_tx_t, exactly as block_witness.h
 * does it: the caller passes its own tx array plus the stride. */
typedef struct { const uint8_t* ptr; uint64_t len; } signet_txref_t;

/* 1 = the block carries a valid signature, 0 = it does not (*reason is a
 * Core-style reject string), -1 = internal (scratch too small / no challenge
 * configured; *reason set). `scratch` needs ntx*32 + 2*largest_tx_len + 1024
 * + SIGNET_WORK_MIN bytes. */
long signet_check_block(const void* txs, unsigned long ntx, unsigned long stride,
                        const unsigned char hdr80[80],
                        const unsigned char* challenge, unsigned long challenge_len,
                        unsigned char* scratch, unsigned long cap,
                        const char** reason);

/* As above but owns its scratch (thread-local, grown on demand). Still
 * chain-agnostic: the caller supplies the challenge. */
long signet_check_block_auto(const void* txs, unsigned long ntx,
                             unsigned long stride,
                             const unsigned char hdr80[80],
                             const unsigned char* challenge,
                             unsigned long challenge_len,
                             const char** reason);

/* What block validation calls: the chain gate, in ONE place so the two call
 * sites cannot drift -- and the direction they would drift is one of them
 * forgetting the check, i.e. a node accepting unsigned blocks on a chain
 * where the signature IS the consensus rule.
 *
 * It is an inline rather than a function in signet_block.c so that reading
 * g_chainp is a dependency of the CALLERS, not of every binary that happens
 * to link signet_block.c. Unused, it emits no code and no reference.
 *
 * Returns 1 immediately on every chain but signet, so the mainnet
 * block-acceptance path gains one predictable branch and nothing else. */
#include "chainparams.h"
static inline long signet_check_block_chain(const void* txs, unsigned long ntx,
                                            unsigned long stride,
                                            const unsigned char hdr80[80],
                                            const char** reason){
    if (g_chainp->id != CHAIN_SIGNET) return 1;
    return signet_check_block_auto(txs, ntx, stride, hdr80,
                                   g_chainp->signet_challenge,
                                   (unsigned long)g_chainp->signet_challenge_len,
                                   reason);
}
#endif
