/* test_taproot_scriptpath.c -- end-to-end BIP341/BIP342 script-path spend
 * dispatch (taproot_verify_input, bitcoin_taproot_sighash.c), the function
 * that closes the gap where P2TR spends with more than one effective
 * witness item used to be rejected outright ("p2tr keypath needs exactly
 * 1 witness item") rather than classified and verified.
 *
 * Vectors (validation/gen_taproot_scriptpath_vectors.py, independent Python
 * secp256k1/schnorr/taproot math, not derived from this project's own asm):
 *   - a real 2-leaf tree (exercises tap_merkle_root's branch-hash
 *     combination, not just the single-leaf passthrough every other
 *     taproot test in this repo happens to use)
 *   - three tampered variants of that same spend (signature / leaf script
 *     / control block each independently corrupted) -- must all FAIL,
 *     proving the commitment check and signature check are both real
 *   - an unknown leaf version with a deliberately-invalid script body --
 *     must PASS without executing anything (BIP341 future-softfork rule)
 *   - a BIP342 validation-weight-budget violation (many CHECKSIGs against
 *     a tiny witness) -- must FAIL
 *   - an annex present on both a script-path and a key-path spend -- must
 *     PASS (proves annex stripping doesn't break either classification)
 *   - a CHECKSIGADD 2-of-2 multisig-style tapscript -- must PASS
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "taproot_scriptpath_vec.h"

extern int taproot_verify_input(const uint8_t* spk,
                                const uint8_t* const* wit, const uint32_t* witlen, uint32_t nwit,
                                const uint8_t* tx, int64_t txlen, int64_t n_in,
                                const uint8_t* prevouts, const uint8_t* amounts,
                                const uint8_t* spks, int64_t num_inputs,
                                const char** reason);

static int g_fails = 0;

int main(void){
    for (int i = 0; i < sp_num_vectors; i++){
        const sp_vec_t* v = &sp_vectors[i];
        const char* reason = "(no reason set)";
        int ok = taproot_verify_input(v->spk, v->wit, v->witlen, v->nwit,
                                      v->tx, v->txlen, 0 /* n_in */,
                                      v->prevouts, v->amounts, v->spks, v->numin,
                                      &reason);
        int pass = (ok == v->expect);
        printf("%-32s expect=%d got=%d%s%s  %s\n", v->name, v->expect, ok,
               ok ? "" : "  reason=", ok ? "" : reason, pass ? "PASS" : "FAIL");
        if (!pass) g_fails++;
    }
    printf("\n%s (%d failure%s)\n", g_fails ? "FAILED" : "ALL PASSED",
           g_fails, g_fails == 1 ? "" : "s");
    return g_fails ? 1 : 0;
}
