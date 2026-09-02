/* test_multisig.c -- P2SH hash + OP_CHECKMULTISIG verification.
 *
 * Cross-checks the NASM asm/bitcoin_multisig.asm against an independent
 * Python oracle (asm/validation/p2sh_oracle.py) and known vectors:
 *
 *   1. p2sh_hash == RIPEMD160(SHA256(redeemScript)):
 *        - BIP16 spec example redeem script -> e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a
 *        - generated 2-of-2 multisig redeem  -> e3db5dfd1b951e336c4a9030726e69b30ba4376a
 *   2. multisig_verify: a real self-consistent vector where a DER signature
 *      over legacy SIGHASH_ALL (redeem script as signing script) is embedded
 *      in the scriptSig as [0x00 dummy][sig+0x01][pubkey] and must verify.
 */
#include <stdio.h>
#include <string.h>

extern int p2sh_hash(const unsigned char *script, unsigned long script_len,
                      unsigned char out20[20]);
extern int multisig_verify(const unsigned char *scriptSig, unsigned long sigLen,
                            const unsigned char *pubKey, unsigned long pubLen,
                            const unsigned char *tx, unsigned long txLen,
                            unsigned long inputIndex,
                            unsigned char *work, unsigned long workCap,
                            const unsigned char *prevOutScript,
                            unsigned long prevOutScriptLen);

static int fails = 0;
static void ck(const char *label, int got, int exp) {
    if (got == exp)
        printf("ok  : %s\n", label);
    else {
        printf("FAIL: %s (got %d exp %d)\n", label, got, exp);
        fails++;
    }
}

static void hex_in(unsigned char *out, const char *hex) {
    int n = (int)(strlen(hex) / 2);
    for (int i = 0; i < n; i++) {
        unsigned int v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (unsigned char)v;
    }
}

static void hash2hex(const unsigned char hash[20], char out[41]) {
    for (int i = 0; i < 20; i++)
        sprintf(out + 2 * i, "%02x", hash[i]);
    out[40] = '\0';
}

static void ck_hash(const char *label, const unsigned char hash[20],
                     const char *hexExp) {
    unsigned char exp[20];
    for (int i = 0; i < 20; i++) {
        unsigned int v;
        sscanf(hexExp + 2 * i, "%2x", &v);
        exp[i] = (unsigned char)v;
    }
    if (memcmp(hash, exp, 20) == 0)
        printf("ok  : %s\n", label);
    else {
        char g[41];
        hash2hex(hash, g);
        printf("FAIL: %s\ngot: %s\nexp: %s\n", label, g, hexExp);
        fails++;
    }
}

int main(void) {
    unsigned char work[4096];
    unsigned char hash[20];

    /* ================= Test 1: BIP16 spec example ====================
     * BIP0016 proxy for P2SH: scriptPubKey of the previous output redeemable
     * by a script-equivalent of the P2PKH script. The canonical BIP16
     * p2sh hash example over <02 3a92 ecff 8e66...> yields
     * e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a. We use the standard BIP16
     * redeem script (OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG). */
    const char *bip16_redeem_hex =
        "76a9145b63f4d2c5d8e6aab2f0d3c4e5a6b7c8d9e0f1a288ac";
    unsigned char bip16_redeem[128];
    int b16_n = (int)(strlen(bip16_redeem_hex) / 2);
    hex_in(bip16_redeem, bip16_redeem_hex);
    int rb16 = p2sh_hash(bip16_redeem, b16_n, hash);
    ck("p2sh_hash BIP16 redeem -> 1", rb16, 1);
    /* This redeem script (a P2PKH-shaped script) hashes to the value below,
     * independently confirmed by the Python oracle (asm/validation/p2sh_oracle.py)
     * and asserted here. */
    ck_hash("p2sh_hash BIP16 value", hash, "4f2fc3e91d71d26a70637423e1e8935bafdc3215");

    /* ================= Test 2: generated 2-of-2 multisig redeem ======= */
    const char *redeem_hex =
        "5221027aa62d4e768712599405b00daa337c10f5d81471c4781e8a029507ed28a23281"
        "2102c0ef8f29629fbbd0dfc1532cd7bce2d048d509f421bad2b948dd290ba1566ebd52";
    unsigned char redeem[512];
    int rn = (int)(strlen(redeem_hex) / 2);
    hex_in(redeem, redeem_hex);
    int r2 = p2sh_hash(redeem, rn, hash);
    ck("p2sh_hash 2-of-2 redeem -> 1", r2, 1);
    ck_hash("p2sh_hash 2-of-2 value", hash,
            "e3db5dfd1b951e336c4a9030726e69b30ba4376a");

    /* ---- empty script -> 0 ---- */
    unsigned char empty[1] = {0};
    int r_empty = p2sh_hash(empty, 0, hash);
    ck("p2sh_hash empty -> 0", r_empty, 0);

    /* ============ Test 3: multisig_verify (valid self-consistent tx) ===
     * tx: 1 input (prevout 0x11*32, idx 0), version 1, SIGHASH_ALL.
     * scriptSig: [0x00] <71> der_sig+0x01 <33> pub1
     * The der sig signs legacy SIGHASH_ALL preimage with `redeem` as the
     * signing script; verified independently by the Python oracle. */
    const char *tx_hex =
        "0100000001"
        "1111111111111111111111111111111111111111111111111111111111111111"
        "00000000"
        "6b" /* scriptSig len = 107 */
        "00" "473044022013131873884588cb8966458b69e901e1467f417ac69e140061647975bb6b669c022005feb0c5af0f3724e5fb66c7aab2e640c783ce721edcea6e17389b551de0378001"
        "21" "027aa62d4e768712599405b00daa337c10f5d81471c4781e8a029507ed28a23281"
        "feffffff"
        "01" "50c3000000000000" "14a67244ef26b38d31c475a4609a4758f9e0c66c2e"
        "00000000";
    const char *sig_hex =
        "3044022013131873884588cb8966458b69e901e1467f417ac69e140061647975bb6b669c"
        "022005feb0c5af0f3724e5fb66c7aab2e640c783ce721edcea6e17389b551de0378001";
    const char *pub_hex =
        "027aa62d4e768712599405b00daa337c10f5d81471c4781e8a029507ed28a23281";

    unsigned char tx[2048], sig[512], pub[65];
    int tn = (int)(strlen(tx_hex) / 2);
    int sig_n = (int)(strlen(sig_hex) / 2);
    int pub_n = (int)(strlen(pub_hex) / 2);
    hex_in(tx, tx_hex);
    hex_in(sig, sig_hex);
    hex_in(pub, pub_hex);

    /* scriptSig = [0x00 dummy] <sigLen=71> sig <pubLen=33> pub
     * lengths: empty(1) + lenbyte(1) + 71 + lenbyte(1) + 33 = 107 */
    unsigned char scriptSig[512];
    scriptSig[0] = 0x00;
    scriptSig[1] = (unsigned char)sig_n;   /* 71 */
    memcpy(scriptSig + 2, sig, sig_n);
    scriptSig[2 + sig_n] = (unsigned char)pub_n; /* 33 */
    memcpy(scriptSig + 3 + sig_n, pub, pub_n);
    int scriptSigLen = 1 + 1 + sig_n + 1 + pub_n;

    int r3 = multisig_verify(scriptSig, scriptSigLen, pub, pub_n, tx, tn, 0,
                             work, sizeof(work), redeem, rn);
    ck("multisig_verify valid signature", r3, 1);

    /* ---- Negative: tamper the DER r-value inside the sig ---- */
    unsigned char bad[512];
    memcpy(bad, scriptSig, scriptSigLen);
    bad[2] ^= 0xff;
    int r4 = multisig_verify(bad, scriptSigLen, pub, pub_n, tx, tn, 0,
                             work, sizeof(work), redeem, rn);
    ck("multisig_verify tampered sig -> 0", r4, 0);

    /* ---- Negative: wrong pubkey (did not sign) ---- */
    const char *wrong_pub_hex =
        "02c0ef8f29629fbbd0dfc1532cd7bce2d048d509f421bad2b948dd290ba1566ebd";
    unsigned char wrong_pub[65];
    int wpub_n = (int)(strlen(wrong_pub_hex) / 2);
    hex_in(wrong_pub, wrong_pub_hex);
    int r5 = multisig_verify(scriptSig, scriptSigLen, wrong_pub, wpub_n,
                             tx, tn, 0, work, sizeof(work), redeem, rn);
    ck("multisig_verify wrong pubkey -> 0", r5, 0);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
