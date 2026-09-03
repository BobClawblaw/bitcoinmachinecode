/* bitcoin_taproot_ctx.h -- the checksig context the tapscript interpreter
 * callback receives.
 *
 * ONE definition, shared. It used to be defined twice: once in
 * bitcoin_taproot_sighash.c and once, by hand, in tests/test_taproot_sighash.c
 * -- with a comment in the copy warning that a stale one "would make
 * taproot_checksig_fn read past the end of whatever a caller here allocates --
 * garbage stack memory, not a compile error".
 *
 * That is exactly what happened on 2026-08-31: adding `hard_fail` to the real
 * struct made the callback write one field past the end of the test's smaller
 * copy, and the test died in stack_push with a corrupted return address, three
 * calls later and nowhere near the cause. The comment was right and could not
 * help, because a comment cannot make two definitions agree. A header can.
 */
#ifndef BITCOIN_TAPROOT_CTX_H
#define BITCOIN_TAPROOT_CTX_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    const uint8_t* tx; int64_t txlen; int64_t n_in;
    const uint8_t* prevouts; const uint8_t* amounts; const uint8_t* spks;
    int64_t num_inputs; const uint8_t* tapleaf; uint32_t codesep_pos;
    const uint8_t* annex; uint64_t annexlen;
    /* BIP342's sigops/witness-size validation-weight budget. Per verify call,
     * never shared, so no locking. */
    int64_t weight_left;
    /* Core's EvalChecksigTapscript distinguishes "the check produced FALSE"
     * (push false, the script continues) from "the script is INVALID"
     * (set_error, it fails immediately). The interpreter's callback can only
     * return 0/1, so the second case is flagged here and read after
     * script_eval. Without it, an empty pubkey pushes false and a script like
     * `OP_CHECKSIG OP_DROP OP_1` SUCCEEDS where Core fails it. */
    int hard_fail;
    /* Core's exact ScriptError for the hard failure (SCR-3, audit
     * 2026-09-03): EMPTY_PUBKEY vs VALIDATION_WEIGHT vs VERIFY matter to
     * the error code reported to RPC/accept; the verdict (fail) does not
     * change. 0 = not set. */
    int hard_err;
} taproot_checksig_ctx;

extern uint64_t taproot_checksig_fn(void*, const uint8_t*, size_t,
                                    const uint8_t*, size_t, const void*);
#endif
