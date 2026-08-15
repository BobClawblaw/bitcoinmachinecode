/* test_verify_p2sh.c -- self-contained regression for the script-level P2SH /
 * BIP16 VerifyScript (bitcoin_verify.c), using pre-generated GENUINE P2SH
 * spends (real legacy SIGHASH_ALL signatures, redeem as the signing script).
 *
 * These vectors are independently built by validation/gen_p2sh_vectors.py and
 * differentially validated against Bitcoin Core's script/interpreter.cpp
 * (validation/p2sh_diff.py -> zero divergence). If a fix here changes a
 * verdict, rerun the differential before trusting this test.
 *
 * Cases:
 *   - 2-of-3 OP_CHECKMULTISIG P2SH spend (2 real sigs)        -> ACCEPT (ERR_OK)
 *   - same spend under pre-BIP16 flags (P2SH off, no WITNESS) -> ACCEPT (sigs not
 *     enforced, redeem simply hashes to match) exactly as Core
 *   - wrong signature (non-member key)                        -> reject EVAL_FALSE
 *   - insufficient signatures (only 1 of 2)                   -> reject INVALID_STACK_OP
 *   - null dummy (non-empty)                                  -> reject SIG_NULLDUMMY
 *   - non-pushonly scriptSig                                  -> reject EVAL_FALSE
 *   - 1-of-1 P2PKH-shaped P2SH redeem (genuine)                -> ACCEPT
 *   - 1-of-1 wrong signature                                  -> reject EVAL_FALSE
 */
#include <stdio.h>
#include <string.h>

extern int verify_script(const unsigned char* scriptSig, unsigned long ssl,
                         const unsigned char* scriptPubKey, unsigned long spl,
                         unsigned long long flags, unsigned long nIn,
                         const unsigned char* tx, unsigned long txlen,
                         unsigned char* work, unsigned long workcap);

#define FLAGS_MODERN 0x20e15ULL   /* P2SH|WITNESS|TAPROOT|DERSIG|CLTV|CSV|NULLDUMMY */
#define FLAGS_PREB16 0x614ULL     /* DERSIG|CLTV|CSV|NULLDUMMY (no P2SH/WITNESS/TAPROOT) */

#include "p2sh_vectors.h"

/* expected error codes (Core ScriptError) */
#define ERR_OK 0
#define ERR_EVAL_FALSE 2
#define ERR_INVALID_STACK_OPERATION 18
#define ERR_SIG_NULLDUMMY 28

static int fails = 0;
static void run(const char* label, const unsigned char* ss, unsigned long ssn,
                const unsigned char* spk, unsigned long spkn,
                const unsigned char* tx, unsigned long txn,
                unsigned long long flags, int exp_ok, int exp_err){
    static unsigned char work[1<<20];
    int code = verify_script(ss, ssn, spk, spkn, flags, 0, tx, txn, work, sizeof(work));
    int ok_ = (code==ERR_OK);
    if (ok_ == exp_ok && (exp_ok==1 || code == exp_err))
        printf("ok  : %s (verify_script -> %d)\n", label, code);
    else {
        printf("FAIL: %s (got code %d exp ok=%d err=%d)\n", label, code, exp_ok, exp_err);
        fails++;
    }
}

#define LEN(a) (unsigned long)sizeof(a)
#define OK 1
#define NO 0

int main(void){
    /* --- genuine 2-of-3, modern height --- */
    run("2of3 genuine spend (2/3 sigs)   ", SS_23, LEN(SS_23), SPK_23, LEN(SPK_23),
        TX_23, LEN(TX_23), FLAGS_MODERN, OK, ERR_OK);
    /* --- same under pre-BIP16 (P2SH off): both Core & ASM accept (sigs not enforced) --- */
    run("2of3 pre-BIP16 (P2SH off)       ", SS_23, LEN(SS_23), SPK_23, LEN(SPK_23),
        TX_23, LEN(TX_23), FLAGS_PREB16, OK, ERR_OK);
    /* --- wrong signature --- */
    run("2of3 wrong signature             ", SS_WRONG, LEN(SS_WRONG), SPK_23, LEN(SPK_23),
        TX_WRONG, LEN(TX_WRONG), FLAGS_MODERN, NO, ERR_EVAL_FALSE);
    /* --- insufficient signatures --- */
    run("2of3 insufficient sigs          ", SS_INSUFF, LEN(SS_INSUFF), SPK_23, LEN(SPK_23),
        TX_INSUFF, LEN(TX_INSUFF), FLAGS_MODERN, NO, ERR_INVALID_STACK_OPERATION);
    /* --- null dummy --- */
    run("2of3 null dummy                  ", SS_NULLD, LEN(SS_NULLD), SPK_23, LEN(SPK_23),
        TX_NULLD, LEN(TX_NULLD), FLAGS_MODERN, NO, ERR_SIG_NULLDUMMY);
    /* --- non-pushonly scriptSig (bad redeem) --- */
    run("2of3 bad (non-pushonly) redeem   ", SS_BADREDEEM, LEN(SS_BADREDEEM), SPK_23, LEN(SPK_23),
        TX_BADREDEEM, LEN(TX_BADREDEEM), FLAGS_MODERN, NO, ERR_EVAL_FALSE);

    /* --- 1-of-1 P2PKH-shaped redeem --- */
    run("1of1 P2PKH redeem genuine        ", SS_1OF1, LEN(SS_1OF1), SPK_1OF1, LEN(SPK_1OF1),
        TX_1OF1, LEN(TX_1OF1), FLAGS_MODERN, OK, ERR_OK);
    run("1of1 wrong signature             ", SS_1OF1BAD, LEN(SS_1OF1BAD), SPK_1OF1, LEN(SPK_1OF1),
        TX_1OF1BAD, LEN(TX_1OF1BAD), FLAGS_MODERN, NO, ERR_EVAL_FALSE);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
