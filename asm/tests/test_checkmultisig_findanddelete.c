/* test_checkmultisig_findanddelete.c -- CHECKMULTISIG must strip EVERY
 * signature present on the stack from scriptCode ONCE, up front, before any
 * signature check runs -- not just "the signature currently under test" on
 * each individual checksig call (which is only correct for plain OP_CHECKSIG,
 * where there is just one signature). Real Core (script/interpreter.cpp)
 * does this with a loop over all nSigsCount signatures before the isig/ikey
 * matching loop even starts; interp_checkmultisig originally rebuilt
 * scriptCode fresh on every matching-loop iteration from the untouched base
 * script, which only ever removes the signature being checked THAT call.
 *
 * Real mainnet regression: block hash
 * 000000000000000051ac3606d0800821eee065e2b99f8bd652fe7cedb02a1cf5 (height
 * ~290328/290329), tx 5df1375ffe61ac35ca178ebb0cab9ea26dedbd0e96005dfcee7e
 * 379fa513232f, input 1: a 2-of-3 P2SH CHECKMULTISIG redeem script with a
 * duplicated real key (used twice) and a third "pubkey" slot that is
 * actually a verbatim copy of sig1's own DER bytes -- a legitimate, if
 * unusual, historical redundant-key construction, not malformed data.
 * Because sig1's bytes appear inside the redeem script, Core's real
 * algorithm strips that occurrence out of scriptCode for BOTH signature
 * checks; this codebase only stripped it while checking sig1, so sig2 was
 * hashed against the WRONG scriptCode and its ECDSA check failed, rejecting
 * an otherwise-valid confirmed mainnet block. Verified independently: the
 * transaction and its containing block are real, confirmed chain data
 * (cross-checked against a public block explorer), and sig2 verifies
 * correctly against the corrected (Core-style) scriptCode using this
 * codebase's own crypto primitives (der_parse_sig/pubkey_parse/ecdsa_verify).
 */
#include <stdio.h>
#include <stdint.h>

extern int sv_verify_script(const unsigned char* ss, unsigned long ssl,
                            const unsigned char* spk, unsigned long spl,
                            uint64_t flags, unsigned long nIn,
                            const unsigned char* tx, unsigned long txlen,
                            unsigned char* work, unsigned long workcap);
extern unsigned long long script_flags_for_block(unsigned long long height, const unsigned char hash32[32]);

static int fails = 0;

static int hex2bin(const char* h, unsigned char* out, int cap){
    int n=0; while(h[2*n] && h[2*n+1]){ if(n>=cap) return -1; unsigned v; sscanf(h+2*n,"%2x",&v); out[n]=(unsigned char)v; n++; } return n;
}

static void check(const char* label, int got, int want){
    if (got == want) printf("ok  : %s -> %d\n", label, got);
    else { printf("FAIL: %s -> got %d (SCRIPT_ERR code), want %d\n", label, got, want); fails++; }
}

/* Full raw transaction bytes, freshly extracted from the block dump. */
static const char* TX_HEX =
"0100000002f9cbafc519425637ba4227f8d0a0b7160b4e65168193d5af39747891de98b5b5"
"000000006b4830450221008dd619c563e527c47d9bd53534a770b102e40faa87f61433580"
"e04e271ef2f960220029886434e18122b53d5decd25f1f4acb2480659fea20aabd856987b"
"a3c3907e0121022b78b756e2258af13779c1a1f37ea6800259716ca4b7f0b87610e0bf3ab"
"52a01ffffffff42e7988254800876b69f24676b3e0205b77be476512ca4d970707dd5c605"
"98ab00000000fd260100483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51"
"c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d"
"2112721b134e2a1a53034930460221008431bdfa72bc67f9d41fe72e94c88fb8f359ffa30"
"b33c72c121c5a877d922e1002210089ef5fc22dd8bfc6bf9ffdb01a9862d27687d424d1fe"
"fbab9e9c7176844a187a014c9052483045022015bd0139bcccf990a6af6ec5c1c52ed8222"
"e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d"
"820ed58d2112721b134e2a1a5303210378d430274f8c5ec1321338151e9f27f4c676a008b"
"df8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf863"
"8d07c0b6be9ab35c7153aeffffffff01a08601000000000017a914d8dacdadb7462ae15cd"
"906f1878706d0da8660e68700000000";

/* Input 1's scriptSig: dummy, sig1 (SIGHASH_SINGLE), sig2 (SIGHASH_ALL),
 * redeem script push (2-of-3: pub1 pub1 blob=sig1-bytes). */
static const char* SPEND_SSIG_HEX =
"00483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2f"
"cd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a53"
"034930460221008431bdfa72bc67f9d41fe72e94c88fb8f359ffa30b33c72c121c5a877d9"
"22e1002210089ef5fc22dd8bfc6bf9ffdb01a9862d27687d424d1fefbab9e9c7176844a18"
"7a014c9052483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df1399"
"68525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b13"
"4e2a1a5303210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
"35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71"
"53ae";

/* The prevout's scriptPubKey: P2SH of the redeem script above. A P2SH
 * output has only one possible byte form given the redeem script's hash, so
 * this is exactly the real prevout script regardless of which prior
 * transaction created it. */
static const char* PREVOUT_SPK_HEX = "a914d8dacdadb7462ae15cd906f1878706d0da8660e687";

int main(void){
    static unsigned char work[1<<20];
    unsigned char tx[1024], ssig[512], spk[64];
    int txlen = hex2bin(TX_HEX, tx, sizeof tx);
    int ssl = hex2bin(SPEND_SSIG_HEX, ssig, sizeof ssig);
    int spklen = hex2bin(PREVOUT_SPK_HEX, spk, sizeof spk);

    unsigned char zero32[32] = {0};
    unsigned long long flags = script_flags_for_block(290329, zero32);
    printf("real block-290329 script flags = 0x%llx\n", flags);

    int r = sv_verify_script(ssig, (unsigned long)ssl, spk, (unsigned long)spklen, flags, 1,
                             tx, (unsigned long)txlen, work, sizeof work);
    check("real mainnet h~290328 2-of-3 CHECKMULTISIG w/ signature-as-decoy-pubkey", r, 0);

    printf("checkmultisig_findanddelete: 1 check(s), %d failure(s)\n", fails);
    return fails?1:0;
}
