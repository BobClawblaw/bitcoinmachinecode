/* daemon/signet_verify.c -- BIP325 layer 3: the block solution actually
 * verified, through the SAME script interpreter and secp256k1 that validate
 * mainnet script. A signet-only verifier would be a second consensus
 * implementation, which is the thing this project refuses to have.
 *
 * SEPARATE FROM signet.c ON PURPOSE. Layers 1 and 2 -- carving the solution
 * out of the coinbase commitment, and building the synthetic transactions --
 * are pure parsing and serialisation: they need a hash and a merkle root and
 * nothing else. This layer drags in the entire verifier. Keeping them in one
 * translation unit meant every test of the parsing layers had to link the
 * verifier too, and twice in this feature that silently broke their link
 * lines instead (2026-08-30). The dependency boundary is real, so it is a
 * file boundary.
 */
#include "signet.h"

/* ---- the verifier this drives: the production one, not a copy ---- */

extern int sv_verify_script(const unsigned char* scriptSig, unsigned long ssl,
                            const unsigned char* scriptPubKey, unsigned long spl,
                            unsigned long long flags, unsigned long nIn,
                            const unsigned char* tx, unsigned long txlen,
                            unsigned char* work, unsigned long workcap);
extern int sv_classify_segwit(const unsigned char* spk, unsigned int spl,
                              const unsigned char* ss, unsigned int ssl,
                              unsigned int* version, const unsigned char** prog,
                              unsigned int* proglen, int* wrapped);
extern int sv_verify_witness_v0(const unsigned char* prog, unsigned int proglen,
                                const unsigned char* const* wit,
                                const unsigned int* witlen, unsigned int nwit,
                                unsigned long long amount, unsigned long long flags,
                                unsigned long nIn, const unsigned char* tx,
                                unsigned long txlen, unsigned char* work,
                                unsigned long workcap);

int signet_check_solution(int nversion, const unsigned char prev32[32],
                          unsigned int ntime,
                          const unsigned char signet_merkle32[32],
                          const unsigned char* solution, unsigned long sol_len,
                          const unsigned char* challenge,
                          unsigned long challenge_len,
                          unsigned char* work, unsigned long workcap){
    if (!work || workcap < SIGNET_WORK_MIN) return -1;
    if (!prev32 || !signet_merkle32 || !challenge || challenge_len == 0) return 0;

    signet_solution_t s;
    s.script_sig = 0; s.script_sig_len = 0; s.nwit = 0;
    if (sol_len){
        /* An unparseable solution is an INVALID BLOCK, not a distinct error:
         * Core returns nullopt from SignetTxs::Create and the block fails. */
        if (!solution) return 0;
        if (signet_parse_solution(solution, sol_len, &s) != 0) return 0;
    }

    /* Carve the two transactions out of the caller's scratch. to_spend is
     * bounded by the challenge; to_sign by the solution. Both are far below
     * the reserve, but the split is explicit so neither can walk into the
     * interpreter's half. */
    unsigned long half = workcap / 4;
    unsigned char* to_spend = work;
    unsigned char* to_sign  = work + half;
    unsigned char* interp   = work + 2*half;
    unsigned long  interpcap = workcap - 2*half;

    long n = signet_build_to_spend(to_spend, half, nversion, prev32,
                                   signet_merkle32, ntime,
                                   challenge, challenge_len);
    if (n < 0) return 0;                       /* challenge too large to sign */

    unsigned char tsid[32];
    signet_txid(tsid, to_spend, (unsigned long)n);

    long m = signet_build_to_sign(to_sign, half, tsid, &s);
    if (m < 0) return 0;

    unsigned int wver = 0, wplen = 0;
    const unsigned char* wprog = 0;
    int wrapped = 0;
    int cls = sv_classify_segwit(challenge, (unsigned int)challenge_len,
                                 s.script_sig, (unsigned int)s.script_sig_len,
                                 &wver, &wprog, &wplen, &wrapped);
    if (cls < 0) return 0;                     /* malformed P2SH-wrapped push */

    if (cls > 0){
        /* Core's VerifyScript: a NATIVE witness program requires an empty
         * scriptSig, or witness malleability comes back. The P2SH-wrapped
         * form's exact-single-push requirement is what sv_classify_segwit
         * already enforced above. */
        if (!wrapped && s.script_sig_len != 0) return 0;

        /* Unknown witness versions are ACCEPTED, not rejected. Core reaches
         * "Higher version witness scripts return true for future softfork
         * compatibility" here, because BLOCK_SCRIPT_VERIFY_FLAGS does not
         * carry DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM. Rejecting instead
         * would feel safer and would be a FALSE REJECT of a chain Core
         * follows -- the same mistake as incident #22. Such a challenge is a
         * terrible choice (it makes every block trivially forgeable), but
         * that is the network operator's error to make, not ours to diverge
         * over. */
        if (wver != 0) return 1;

        /* sv_verify_witness_v0 wants 32-bit lengths. */
        static __thread unsigned int wl[SIGNET_MAX_WIT];
        for (unsigned long i = 0; i < s.nwit; i++) wl[i] = (unsigned int)s.witlen[i];
        return sv_verify_witness_v0(wprog, wplen, s.wit, wl,
                                    (unsigned int)s.nwit, 0ULL,
                                    SIGNET_VERIFY_FLAGS, 0,
                                    to_sign, (unsigned long)m,
                                    interp, interpcap) == 0;
    }

    /* Not a witness program. Core's VerifyScript ends with
     *   if (!hadWitness && !witness->IsNull()) return WITNESS_UNEXPECTED;
     * so a solution carrying witness data against, say, the DEFAULT signet
     * challenge (a bare 1-of-2 CHECKMULTISIG) is invalid. sv_verify_script
     * takes no witness argument and cannot notice, so the check is here or
     * it does not happen -- and this node would accept blocks Core rejects. */
    if (s.nwit != 0) return 0;

    return sv_verify_script(s.script_sig, s.script_sig_len,
                            challenge, challenge_len,
                            SIGNET_VERIFY_FLAGS, 0,
                            to_sign, (unsigned long)m,
                            interp, interpcap) == 0;
}
