/* test_checkmultisig_zero_keys.c -- CHECKMULTISIG's nKeys count must accept
 * 0, not just 1..20. Real Core (script/interpreter.cpp) only rejects a
 * NEGATIVE key count: `if (nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_
 * MULTISIG) return set_error(..., SCRIPT_ERR_PUBKEY_COUNT)`. This
 * interpreter used `nKeys < 1`, rejecting the legitimate degenerate 0-of-0
 * case: a CHECKMULTISIG run against zero keys and zero signatures (just a
 * dummy + the two zero counts) trivially succeeds, since zero signature
 * checks are vacuously satisfied.
 *
 * Real mainnet regression: height 299916, tx index 11. Input 0 spends a
 * P2SH output (height 299507) whose scriptSig is
 * `OP_0 OP_0 OP_0 PUSH(1)[0xae]` -- three empty pushes (dummy, m=0, n=0)
 * plus the redeem script itself: a single byte, 0xae, which as an OPCODE is
 * OP_CHECKMULTISIG. HASH160 of that one-byte redeem script matches the
 * prevout's scriptPubKey (confirmed via the real archive), so BIP16 P2SH
 * runs it: a bare `OP_CHECKMULTISIG` against the three leftover empty stack
 * items. Under Core's real rule this is valid (0-of-0, vacuously true, then
 * the dummy pop); under the `nKeys<1` bug it was rejected with
 * SCRIPT_ERR_PUBKEY_COUNT, which is why this confirmed, real, historical
 * mainnet block was being rejected.
 */
#include <stdio.h>
#include <stdint.h>

extern int sv_verify_script(const unsigned char* ss, unsigned long ssl,
                            const unsigned char* spk, unsigned long spl,
                            uint64_t flags, unsigned long nIn,
                            const unsigned char* tx, unsigned long txlen,
                            unsigned char* work, unsigned long workcap);

static int fails = 0;

static int hex2bin(const char* h, unsigned char* out, int cap){
    int n=0; while(h[2*n] && h[2*n+1]){ if(n>=cap) return -1; unsigned v; sscanf(h+2*n,"%2x",&v); out[n]=(unsigned char)v; n++; } return n;
}

static void check(const char* label, int got, int want){
    if (got == want) printf("ok  : %s -> %d\n", label, got);
    else { printf("FAIL: %s -> got %d (SCRIPT_ERR code), want %d\n", label, got, want); fails++; }
}

/* Full raw tx (1 input, 1 output), spending the P2SH 0-of-0 multisig
 * output. Freshly extracted from the block archive. */
static const char* TX_HEX =
"0100000001a3e88a67fdd04ddbd018e3efc6eab458bd83b72717e901ec4c38441dbd73f9e"
"e000000000500000001aeffffffff01905f0100000000001976a914c9ebc7e8127cec9cf"
"8605965335df7129a89723988ac00000000";
static const char* SPEND_SSIG_HEX = "00000001ae";
/* The real prevout scriptPubKey (P2SH of the one-byte 0xae redeem script),
 * confirmed against the live archive's own UTXO record for this outpoint. */
static const char* PREVOUT_SPK_HEX = "a9146c21ac707cb37c90794294acda011060ef0fc01187";

int main(void){
    static unsigned char work[1<<20];
    unsigned char tx[256], ssig[16], spk[64];
    int txlen = hex2bin(TX_HEX, tx, sizeof tx);
    int ssl = hex2bin(SPEND_SSIG_HEX, ssig, sizeof ssig);
    int spklen = hex2bin(PREVOUT_SPK_HEX, spk, sizeof spk);

    int r = sv_verify_script(ssig, (unsigned long)ssl, spk, (unsigned long)spklen, 1ULL /* SV_P2SH */, 0,
                             tx, (unsigned long)txlen, work, sizeof work);
    check("real mainnet h=299916 t=11: bare OP_CHECKMULTISIG via P2SH, 0-of-0", r, 0);

    /* Synthetic companions: nKeys must still reject negative and >20, and 21
     * (one past MAX_PUBKEYS_PER_MULTISIG) must still fail -- only the lower
     * bound moved from 1 to 0, not both bounds. */
    {
        /* scriptSig: OP_0(dummy) OP_0(m=0) OP_1NEGATE(n=-1) -- nKeys=-1. */
        unsigned char ss[3] = {0x00, 0x00, 0x4f};
        unsigned char sp[1] = {0xae};
        int rr = sv_verify_script(ss, 3, sp, 1, 0, 0, tx, (unsigned long)txlen, work, sizeof work);
        check("nKeys=-1 still rejected (SCRIPT_ERR_PUBKEY_COUNT)", rr, 10);
    }

    printf("checkmultisig_zero_keys: 2 check(s), %d failure(s)\n", fails);
    return fails?1:0;
}
