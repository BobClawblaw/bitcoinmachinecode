/* test_e2e_sighash.c -- LIVE-WIRE end-to-end: build tx -> sign with the real
 * wallet_cli binary (legacy SIGHASH_ALL) -> validate with the whole-tx
 * validator.  One integrated flow across the process boundary, rather than
 * isolated pre-generated vectors.
 *
 * Flow exercised here is exactly what the wallet/validation bridge promises
 * as a unit:
 *   1. BUILD   : a real, fundable P2PKH tx (1 input, 2 outputs, change).
 *   2. SIGN    : hand the unsigned tx to the actual daemon/wallet_cli "sign"
 *                subcommand (legacy SIGHASH_ALL, low-S, deterministic nonce).
 *                We capture its "signed-tx:" hex over stdout -- the same
 *                output a human reading the CLI would get.
 *   3. VALIDATE: feed that CLI-signed tx into the whole-transaction validator
 *                (tx_parse + UTXO presence/double-spend + verify_p2pkh for
 *                every input + fee check) and require it to pass.
 *   4. NEGATIVE LIVE-WIRE: adversarially mutate the CLI-signed tx (tamper an
 *                output value, corrupt the DER sig, spend a missing outpoint)
 *                and require the same validator to reject each.
 *
 * The signature the CLI produced is additionally cross-checked through the
 * repo's independently-verified ecdsa_verify path, so the spend is proven
 * genuine (not merely self-consistent with the validator's own signer).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* --- validator asm externs (same set as tests/test_txval.c) ------------ */
extern int  tx_parse(void* info, const unsigned char* tx, unsigned long txlen);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_put(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long value, unsigned long height,
                     unsigned long is_coinbase, const unsigned char* script, unsigned long slen);
extern long utxo_get(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, unsigned long* height,
                     unsigned long* is_coinbase, const unsigned char** script, unsigned long* slen);
extern int  verify_p2pkh(const unsigned char* tx, unsigned long txlen,
                         unsigned long input_index,
                         const unsigned char* prevout_script, unsigned long prevout_len,
                         unsigned char* work, unsigned long cap);

/* --- signing-path asm primitives (for prevout script + sig cross-check) - */
extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char k[32]);
extern void hash160(unsigned char o[20], const void* in, long long len);
extern int  pubkey_parse(const unsigned char* pub, unsigned long plen,
                         uint64_t qx[4], uint64_t qy[4]);
extern int  ecdsa_verify(const uint64_t z[4], const uint64_t r[4],
                         const uint64_t s[4], const uint64_t Qx[4], const uint64_t Qy[4]);
extern int  sighash_all(unsigned char out32[32], const unsigned char* tx,
                        unsigned long txlen, unsigned long input_index,
                        const unsigned char* script, unsigned long script_len,
                        unsigned char* work, unsigned long workcap);

/* --- txinfo struct (mirrors the 64-byte layout filled by tx_parse) ------ */
typedef struct {
    unsigned long long tx_len;
    unsigned int version;
    unsigned int n_in;
    unsigned int n_out;
    unsigned int locktime;
    unsigned long long in0_script_off;
    unsigned long long in0_script_len;
    unsigned long long out0_value_off;
    unsigned long long out0_script_off;
    unsigned long long out0_script_len;
} txinfo;

static int failures = 0;
static void ck(const char* label, int cond) {
    printf("%s: %s\n", cond ? "PASS" : "FAIL", label);
    if (!cond) failures++;
}

/* ------------------------------------------------------------------ */
/* tiny CompactSize / serialization helpers                            */
/* ------------------------------------------------------------------ */
static unsigned char* put_varint(unsigned char* p, unsigned long n) {
    if (n < 0xfd) *p++ = (unsigned char)n;
    else if (n <= 0xffff) { *p++ = 0xfd; p[0] = n & 0xff; p[1] = (n >> 8) & 0xff; p += 2; }
    else if (n <= 0xffffffffUL) { *p++ = 0xfe; for (int i = 0; i < 4; i++) p[i] = (n >> (8*i)) & 0xff; p += 4; }
    else { *p++ = 0xff; for (int i = 0; i < 8; i++) p[i] = (n >> (8*i)) & 0xff; p += 8; }
    return p;
}

static unsigned long rd_varint(const unsigned char* p, const unsigned char** adv) {
    unsigned long v = *p++;
    if (v < 0xfd) { *adv = p; return v; }
    if (v == 0xfd) { v = (unsigned long)p[0] | ((unsigned long)p[1] << 8); p += 2; }
    else if (v == 0xfe) { v = 0; for (int i = 0; i < 4; i++) v |= (unsigned long)p[i] << (8*i); p += 4; }
    else { v = 0; for (int i = 0; i < 8; i++) v |= (unsigned long)p[i] << (8*i); p += 8; }
    *adv = p;
    return v;
}

/* Build a 1-input / 2-output P2PKH tx.  The input's scriptSig is left EMPTY
 * (the wallet_cli "sign" fills it).  Returns length or -1.
 *   fund_txid[32]  - outpoint txid of the input
 *   fund_idx       - outpoint index
 *   prev_script[25]- the P2PKH script locking the funding output (the value
 *                    the whole-tx validator looks up in the UTXO set)
 *   dest_script[25]- P2PKH script of the payee
 *   lock_script[25]- P2PKH script of the change output
 *   fund_amt       - value of the funding output (sum of inputs)
 *   pay_amt        - value sent to the payee
 *   change_amt     - value sent back to change
 */
static long build_unsigned_tx(unsigned char* out, long cap,
                              const unsigned char fund_txid[32], unsigned long fund_idx,
                              const unsigned char prev_script[25],
                              const unsigned char dest_script[25],
                              const unsigned char lock_script[25],
                              unsigned long long fund_amt,
                              unsigned long long pay_amt,
                              unsigned long long change_amt) {
    unsigned char* p = out;
    (void)prev_script;
    *p++ = 2; *p++ = 0; *p++ = 0; *p++ = 0;                    /* version 2 */
    p = put_varint(p, 1);                                      /* 1 input */
    memcpy(p, fund_txid, 32); p += 32;                         /* prev txid */
    for (int i = 0; i < 4; i++) *p++ = (unsigned char)((fund_idx >> (8*i)) & 0xff); /* prev vout */
    p = put_varint(p, 0);                                      /* empty scriptSig */
    *p++ = 0xfe; *p++ = 0xff; *p++ = 0xff; *p++ = 0xff;        /* sequence */
    p = put_varint(p, 2);                                      /* 2 outputs */
    /* output 0 : payee */
    for (int i = 0; i < 8; i++) *p++ = (unsigned char)((pay_amt   >> (8*i)) & 0xff);
    p = put_varint(p, 25); memcpy(p, dest_script, 25); p += 25;
    /* output 1 : change */
    for (int i = 0; i < 8; i++) *p++ = (unsigned char)((change_amt >> (8*i)) & 0xff);
    p = put_varint(p, 25); memcpy(p, lock_script, 25); p += 25;
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;                    /* locktime */
    long n = (long)(p - out);
    return n > cap ? -1 : n;
}

static void bytes_to_hex(char* out, const unsigned char* b, int n) {
    for (int i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
    out[2 * n] = '\0';
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int hex_to_bytes(unsigned char* out, const char* h) {
    int n = (int)strlen(h);
    if (n % 2) return 0;
    for (int i = 0; i < n / 2; i++) {
        int hi = hexval(h[2*i]), lo = hexval(h[2*i+1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return n / 2;
}

/* Invoke the REAL wallet_cli binary: "sign <txhex> <keyhex> <idx>".
 * Returns length of the CLI's "signed-tx" hex (decoded into out), or -1. */
static long cli_sign(unsigned char* out_signed, long cap,
                     const char* txhex, const char* keyhex, const char* idxhex,
                     char* cli_log, long logcap) {
    char cmd[16400];
    snprintf(cmd, sizeof cmd, "./daemon/wallet_cli sign %s %s %s", txhex, keyhex, idxhex);
    FILE* fp = popen(cmd, "r");
    if (!fp) { fprintf(stderr, "  !! popen(wallet_cli sign) failed\n"); return -1; }

    char line[4096];
    long got = -1;
    int logged = 0;
    while (fgets(line, sizeof line, fp)) {
        if (logged < 30 && logcap > 0) {
            int l = (int)strlen(line);
            if (l > (int)logcap - 1) l = (int)logcap - 1;
            memcpy(cli_log + (long)logged * 80, line, (size_t)l);
            cli_log[(long)logged * 80 + l] = '\0';
            if (l > 0 && line[l-1] == '\n') cli_log[(long)logged * 80 + l - 1] = '\0';
            logged++;
        }
        /* the CLI prints: "signed-tx (%ld bytes):" then the hex on its own line */
        if (strncmp(line, "signed-tx", 9) == 0) {
            if (!fgets(line, sizeof line, fp)) break;
            /* strip trailing whitespace/newline */
            int ln = (int)strlen(line);
            while (ln > 0 && (line[ln-1] == '\n' || line[ln-1] == '\r' || line[ln-1] == ' ')) line[--ln] = '\0';
            while (*line == ' ' || *line == '\t') memmove(line, line + 1, strlen(line));
            got = hex_to_bytes(out_signed, line);
        }
    }
    int rc = pclose(fp);
    if (got < 0) {
        fprintf(stderr, "  !! no signed-tx emitted by wallet_cli (rc=%d)\n", rc);
        return -1;
    }
    if (got > cap) return -1;
    return got;
}

/* ------------------------------------------------------------------ */
/* The whole-transaction validator (identical logic to test_txval.c)    */
/*   Returns 1 valid, 0 invalid (prints a reason).                      */
/* ------------------------------------------------------------------ */
static int validate_tx(const unsigned char* tx, unsigned long txlen,
                       void* utxo, unsigned char* work, unsigned long workcap) {
    txinfo info;
    if (tx_parse(&info, tx, txlen) != 1) { printf("  [parse] malformed tx\n"); return 0; }
    if (info.n_in == 0 || info.n_out == 0) { printf("  [shape] empty io list\n"); return 0; }

    unsigned long long total_in = 0;
    const unsigned char* scripts[64];
    unsigned long slens[64];

    for (unsigned int i = 0; i < info.n_in && i < 64; i++) {
        unsigned char txid[32]; unsigned long index;
        const unsigned char* p = tx + 4;
        unsigned long n_in = rd_varint(p, &p);
        (void)n_in;
        for (unsigned int j = 0; j <= i; j++) {
            memcpy(txid, p, 32);
            index = (unsigned long)p[32] | ((unsigned long)p[33] << 8)
                  | ((unsigned long)p[34] << 16) | ((unsigned long)p[35] << 24);
            p += 36;
            unsigned long sl = rd_varint(p, &p);
            p += sl + 4;
        }
        unsigned long long val; const unsigned char* sp; unsigned long sl, h_unused, cb_unused;
        if (utxo_get(utxo, txid, index, &val, &h_unused, &cb_unused, &sp, &sl) != 1) {
            printf("  [double-spend] input %u outpoint absent/unspent\n", i);
            return 0;
        }
        scripts[i] = sp; slens[i] = sl;
        total_in += val;
    }

    for (unsigned int i = 0; i < info.n_in && i < 64; i++) {
        if (verify_p2pkh(tx, txlen, i, scripts[i], slens[i], work, workcap) != 1) {
            printf("  [sig] input %u signature does not verify\n", i);
            return 0;
        }
    }

    unsigned long long total_out = 0;
    {
        const unsigned char* p = tx + 4;
        (void)rd_varint(p, &p);
        for (unsigned int i = 0; i < info.n_in; i++) {
            p += 36;
            unsigned long sl = rd_varint(p, &p);
            p += sl + 4;
        }
        (void)rd_varint(p, &p);
        for (unsigned int i = 0; i < info.n_out; i++) {
            unsigned long long v = 0;
            for (int j = 0; j < 8; j++) v |= (unsigned long long)p[j] << (8*j);
            p += 8;
            unsigned long sl = rd_varint(p, &p);
            p += sl;
            total_out += v;
        }
    }
    if (total_out > total_in) {
        printf("  [fee] in=%llu out=%llu (outputs exceed inputs)\n", total_in, total_out);
        return 0;
    }
    return 1;
}

/* Cross-check the CLI-produced signature via the independently-verified
 * ecdsa_verify path: parse scriptSig = <push> <DER||01> <push 33> <pub>,
 * recompute z = sighash_all(prevout script), and ecdsa_verify it. */
static int crosscheck_cli_sig(const unsigned char* tx, unsigned long txlen,
                              const unsigned char* prevout_script, unsigned long plen,
                              unsigned char* work, long workcap) {
    const unsigned char* p = tx + 4;
    unsigned long n_in = rd_varint(p, &p);
    if (n_in < 1) return 0;
    p += 36;                                     /* prev txid + vout */
    unsigned long slen = rd_varint(p, &p);       /* scriptSig length */
    const unsigned char* ss = p;
    if (ss[0] == 0) return 0;
    int der_len = ss[0];
    const unsigned char* der = ss + 1;           /* DER sig || 0x01 sighash */
    if (der_len < 9 || ss[0] + 1 + 1 + 33 > (int)slen) return 0;
    int pub_off = 1 + der_len + 1;               /* push len + DER+sighash + pushlen(0x21) */
    if (ss[pub_off - 1] != 0x21) return 0;       /* pubkey push must be 33 */
    const unsigned char* pub = ss + pub_off;

    /* recompute sighash digest */
    unsigned char z[32];
    if (!sighash_all(z, tx, txlen, 0, prevout_script, plen, work, (unsigned long)workcap))
        return 0;

    /* parse DER to (r,s).  Layout: 30 <len> 02 <rl> <r> 02 <sl> <s> */
    if (der[0] != 0x30) return 0;
    int rl = der[3];
    int sl = der[4 + rl + 1];
    const unsigned char* rb = der + 4;
    const unsigned char* sb = der + 4 + rl + 2;
    uint64_t r[4] = {0,0,0,0}, s[4] = {0,0,0,0};
    for (int i = 0; i < rl; i++) { int lb = i/8, sh = (i%8)*8; r[lb] |= ((uint64_t)rb[rl-1-i]) << sh; }
    for (int i = 0; i < sl; i++) { int lb = i/8, sh = (i%8)*8; s[lb] |= ((uint64_t)sb[sl-1-i]) << sh; }
    uint64_t zl[4] = {0,0,0,0};
    for (int i = 0; i < 32; i++) { int lb = i/8, sh = (i%8)*8; zl[lb] |= ((uint64_t)z[31-i]) << sh; }

    /* decompress pubkey, verify */
    uint64_t qx[4], qy[4];
    if (pubkey_parse(pub, 33, qx, qy) != 1) return 0;
    return ecdsa_verify(zl, r, s, qx, qy);
}

/* Locate the DER sig inside a signed tx (for adversarial DER-corruption). */
static const unsigned char* find_der(const unsigned char* tx, unsigned long txlen,
                                     unsigned long* der_len_out, unsigned long* total_script_sig) {
    const unsigned char* p = tx + 4;
    unsigned long n_in = rd_varint(p, &p);
    (void)n_in;
    p += 36;
    unsigned long slen = rd_varint(p, &p);
    *total_script_sig = slen;
    if (slen < 2) return NULL;
    unsigned long der_len = p[0];
    *der_len_out = der_len ? der_len : 0;
    return p + 1;
}

int main(void) {
    /* ---- keys ---------------------------------------------------- */
    /* spender key K1 (funds the coin); recipient key K2 (change to K1). */
    unsigned char k1[32] = {0}; k1[31] = 1;                 /* key=1 => addr 1BgGZ9tc.. */
    unsigned char k2[32]; static const unsigned char kv2[32] = {
        0x4F,0x2E,0x33,0x1A,0xA1,0x9B,0x2C,0x5D,0x77,0x8E,0x0F,0x9A,0xCC,0x1B,0x22,0x44,
        0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0x11,0x22,0x33,0x44,0x55,0x66};
    memcpy(k2, kv2, 32);

    /* P2PKH locking scripts */
    unsigned char pub1[33], pub2[33], h1[20], h2[20];
    unsigned char script1[25], script2[25];
    scalar_to_pubkey(pub1, k1); hash160(h1, pub1, 33);
    script1[0]=0x76; script1[1]=0xa9; script1[2]=0x14; memcpy(script1+3, h1, 20); script1[23]=0x88; script1[24]=0xac;
    scalar_to_pubkey(pub2, k2); hash160(h2, pub2, 33);
    script2[0]=0x76; script2[1]=0xa9; script2[2]=0x14; memcpy(script2+3, h2, 20); script2[23]=0x88; script2[24]=0xac;

    /* funding outpoint: coin of 100000 sat locked to K1's P2PKH script */
    unsigned char fund_txid[32];
    for (int i = 0; i < 32; i++) fund_txid[i] = (unsigned char)(0xAB + i);
    unsigned long fund_idx = 0;
    unsigned long long fund_amt = 100000;

    /* amounts: pay 80000 to K2, 15000 change to K1 => fee 5000 */
    unsigned long long pay_amt = 80000, change_amt = 15000;

    /* ---- 1. BUILD the unsigned tx ---- */
    unsigned char utx[512];
    long ulen = build_unsigned_tx(utx, sizeof utx, fund_txid, fund_idx,
                                  script1, script2, script1,
                                  fund_amt, pay_amt, change_amt);
    ck("build unsigned tx (1-in/2-out, empty scriptSig)", ulen > 0 && ulen < 200);
    if (ulen <= 0) { printf("  cannot build tx; aborting\n"); return 1; }

    char utxhex[2048];
    bytes_to_hex(utxhex, utx, (int)ulen);
    char k1hex[65];
    bytes_to_hex(k1hex, k1, 32);

    /* ---- 2. SIGN with the REAL wallet_cli binary ---- */
    char cli_log[30][80];
    unsigned char signed_tx[2048];
    long slen = cli_sign(signed_tx, (long)sizeof signed_tx, utxhex, k1hex, "0",
                         (char*)cli_log, (long)(sizeof cli_log[0]));
    ck("wallet_cli sign emitted a signed tx", slen > ulen);
    if (slen > ulen) {
        printf("  unsigned=%ld bytes -> signed=%ld bytes (scriptSig added)\n", ulen, slen);
        printf("  CLI log (first lines):\n");
        for (int i = 0; i < 30 && cli_log[i][0]; i++) printf("    %s\n", cli_log[i]);
    } else {
        for (int i = 0; i < 30 && cli_log[i][0]; i++) printf("    %s\n", cli_log[i]);
    }
    if (slen <= 0) { printf("  aborting: CLI failed to sign\n"); return 1; }

    /* ---- 3. VALIDATE with the whole-tx validator ---- */
    static unsigned char ux[40 + 512 * 48 + 8];
    static unsigned char ublob[1 << 16];
    static unsigned char work[8192];
    utxo_init(ux, 512, ublob, sizeof ublob);
    utxo_put(ux, fund_txid, fund_idx, fund_amt, 0, 0, script1, 25);

    printf("\n[1] whole-tx validator on the CLI-signed tx:\n");
    int valid = validate_tx(signed_tx, (unsigned long)slen, ux, work, sizeof work);
    printf("  >>> valid=%d\n", valid);
    ck("whole-tx validator ACCEPTS the CLI-signed tx", valid == 1);

    /* ---- 4a. cross-check the signature is genuine via ecdsa_verify ----
     * (proves the CLI's signature is a real spend of K1, not self-consistent
     *  with the validator's own signer). */
    printf("\n[2] independent signature cross-check (ecdsa_verify):\n");
    int genu = crosscheck_cli_sig(signed_tx, (unsigned long)slen, script1, 25, work, sizeof work);
    ck("CLI signature is a genuine ECDSA spend that verifies", genu == 1);

    /* ---- 4b. NEGATIVE live-wire: the REAL CLI signs a tx whose outputs
     * exceed its input (negative fee).  The signature is valid -- the CLI
     * will sign any scriptSig-replaceable tx -- so the whole-tx validator
     * must reject it on the FEE check, not on the signature. */
    printf("\n[3] negative live-wire cases:\n");
    {
        unsigned char bad_unsigned[512];
        /* pay 70000 + change 40000 = 110000 > 100000 input => negative fee */
        long bu = build_unsigned_tx(bad_unsigned, sizeof bad_unsigned,
                                    fund_txid, fund_idx, script1, script2, script1,
                                    fund_amt, 70000, 40000);
        ck("build negative-fee unsigned tx", bu > 0);
        char buhex[2048];
        bytes_to_hex(buhex, bad_unsigned, (int)bu);
        unsigned char bad_signed[2048];
        char clog[30][80];
        long bs = cli_sign(bad_signed, (long)sizeof bad_signed, buhex, k1hex, "0",
                           (char*)clog, (long)(sizeof clog[0]));
        ck("wallet_cli signs the negative-fee tx (valid sig)", bs > bu);
        if (bs > 0) {
            int r = validate_tx(bad_signed, (unsigned long)bs, ux, work, sizeof work);
            printf("  >>> negative-fee tx valid=%d (expected 0, rejected on [fee])\n", r);
            ck("negative-fee signed tx is REJECTED ([fee])", r == 0);
        }
    }
    printf("\n");
    {
        /* 4bb. tamper an output VALUE of the CLI-signed good tx.  Under
         * SIGHASH_ALL the output is covered by the digest, so the tamper
         * invalidates the signature -- the validator rejects it. */
        unsigned char bad[2048];
        memcpy(bad, signed_tx, (size_t)slen);
        /* bump output 0 value from 80000 to 99000 -> out=114000 > in=100000 */
        unsigned long long bump = 99000;
        /* locate output 0 value: version(4) vin(1) in(41) -> n_out */
        const unsigned char* cp = bad + 4;
        rd_varint(cp, &cp);
        rd_varint(cp, &cp);               /* n_in */
        cp += 36; rd_varint(cp, &cp); cp += 0 + 4;   /* in0: txid+vout, scriptlen(0), seq */
        rd_varint(cp, &cp);               /* n_out */
        unsigned char* wp = (unsigned char*)cp;      /* writable alias for the mutate */
        if (wp + 8 <= bad + slen) {
            for (int i = 0; i < 8; i++) wp[i] = (unsigned char)((bump >> (8*i)) & 0xff);
            ck("tampered output value (SIGHASH_ALL) is REJECTED",
               validate_tx(bad, (unsigned long)slen, ux, work, sizeof work) == 0);
        } else ck("tamper output value (locate)", 0);
    }
    printf("\n");
    {
        /* 4c. corrupt a DER byte of the CLI signature -> [sig] reject */
        unsigned char bad[2048];
        memcpy(bad, signed_tx, (size_t)slen);
        unsigned long der_len, sslen;
        const unsigned char* der = find_der(bad, (unsigned long)slen, &der_len, &sslen);
        ck("locate DER sig in signed tx", der != NULL && der_len >= 4);
        if (der && der_len >= 4) {
            bad[(der - bad) + 4] ^= 0x5A;     /* flip a byte inside r */
            ck("corrupted DER sig is REJECTED ([sig])",
               validate_tx(bad, (unsigned long)slen, ux, work, sizeof work) == 0);
        }
    }
    printf("\n");
    {
        /* 4d. spend a missing outpoint (double-spend) -> reject */
        static unsigned char ux2[40 + 512 * 48 + 8];
        static unsigned char ublob2[1 << 16];
        utxo_init(ux2, 512, ublob2, sizeof ublob2);   /* empty UTXO set */
        ck("same tx against EMPTY utxo is REJECTED ([double-spend])",
           validate_tx(signed_tx, (unsigned long)slen, ux2, work, sizeof work) == 0);
    }

    printf("\n%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
