/* test_send.c -- verify the wallet "send" flow end to end in machine-backed C:
 *
 *   wallet_send_tx() builds a real P2PKH transaction from wallet-held UTXOs
 *   (createrawtx: select our unspent outputs, pay a destination + change, fee =
 *   total_in - amount), signs EVERY input via the verified asm ECDSA path
 *   (legacy SIGHASH_ALL, low-S), and returns the serialized signed tx.
 *
 * This harness then feeds that signed tx through the SAME whole-transaction
 * validator used by test_txval (UTXO presence/double-spend + per-input
 * verify_p2pkh + fee), so the spend must be genuinely valid -- not just
 * structurally signed.
 *
 * Cases:
 *   1. multi-input send (3 UTOXs -> pay destination + change, positive fee)
 *      -> validator ACCEPTS
 *   2. single-input send with exact change -> ACCEPTS
 *   3. underfunded (amount+fee exceeds balance) -> createrawtx REJECTS
 *   4. fee == 0 -> REJECTS
 *   5. send against an EMPTY UTXO store (outpoint absent) -> validator REJECTS
 *      (double-spend guard), proving the signed tx really references our UTOXs
 *
 * Reuses: bitcoin_utxo (utxo_init/put/get), bitcoin_script (verify_p2pkh),
 * bitcoin_tx (tx_parse), and asm/wallet_core.c (wallet_send_tx etc).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* asm externs */
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

/* wallet core (asm/wallet_core.c) */
extern long wallet_send_tx(unsigned char* out_tx, long cap,
                           const unsigned char toutid[][32], const unsigned long* tidx,
                           const unsigned long long* tval, unsigned long n,
                           const unsigned char to_h160[20],
                           unsigned long long amount, unsigned long long fee,
                           const unsigned char priv_be[32], unsigned long locktime);
extern void wallet_key_h160(unsigned char h[20], const unsigned char priv_be[32]);
extern void wallet_make_p2pkh_script(unsigned char script[25], const unsigned char priv_be[32]);
extern unsigned long long wallet_get_balance(const unsigned long long* tval, unsigned long n);

typedef struct {
    unsigned long long tx_len; unsigned int version, n_in, n_out, locktime;
    unsigned long long in0_script_off, in0_script_len, out0_value_off, out0_script_off, out0_script_len;
} txinfo;

/* ---- hex + varint helpers (same as test_txval) ---- */
static unsigned long rd_varint(const unsigned char* p, const unsigned char** adv) {
    unsigned long v = *p++;
    if (v < 0xfd) { *adv = p; return v; }
    if (v == 0xfd) { v = (unsigned long)p[0] | ((unsigned long)p[1] << 8); p += 2; }
    else if (v == 0xfe) { v = 0; for (int i = 0; i < 4; i++) v |= (unsigned long)p[i] << (8*i); p += 4; }
    else { v = 0; for (int i = 0; i < 8; i++) v |= (unsigned long)p[i] << (8*i); p += 8; }
    *adv = p;
    return v;
}
static int input_outpoint(const unsigned char* tx, unsigned int i,
                          unsigned char txid[32], unsigned long* index) {
    const unsigned char* p = tx + 4;
    unsigned long n_in = rd_varint(p, &p);
    if (i >= n_in) return 0;
    for (unsigned int j = 0; j <= i; j++) {
        memcpy(txid, p, 32);
        *index = (unsigned long)p[32] | ((unsigned long)p[33] << 8)
               | ((unsigned long)p[34] << 16) | ((unsigned long)p[35] << 24);
        p += 36;
        unsigned long sl = rd_varint(p, &p);
        p += sl + 4;
    }
    return 1;
}
static void hex_in(unsigned char* out, const char* h) {
    int n = (int)(strlen(h)) / 2;
    for (int i = 0; i < n; i++) { unsigned int v; sscanf(h + 2 * i, "%2x", &v); out[i] = (unsigned char)v; }
}

/* ---- whole-transaction validator (mirrors test_txval) ---- */
static int validate_signed_tx(const unsigned char* tx, unsigned long txlen,
                              void* utxo, unsigned char* work, unsigned long workcap) {
    txinfo info;
    if (tx_parse(&info, tx, txlen) != 1) { printf("  [parse] malformed\n"); return 0; }
    if (info.n_in == 0 || info.n_out == 0) { printf("  [shape]\n"); return 0; }
    unsigned long long total_in = 0;
    const unsigned char* scripts[64]; unsigned long slens[64]; unsigned long long vals[64];
    for (unsigned int i = 0; i < info.n_in && i < 64; i++) {
        unsigned char txid[32]; unsigned long index;
        input_outpoint(tx, i, txid, &index);
        unsigned long long val; const unsigned char* sp; unsigned long sl, h_unused, cb_unused;
        if (utxo_get(utxo, txid, index, &val, &h_unused, &cb_unused, &sp, &sl) != 1) {
            printf("  [double-spend] input %u absent/unspent\n", i); return 0;
        }
        scripts[i] = sp; slens[i] = sl; vals[i] = val; total_in += val;
    }
    for (unsigned int i = 0; i < info.n_in && i < 64; i++)
        if (verify_p2pkh(tx, txlen, i, scripts[i], slens[i], work, workcap) != 1) {
            printf("  [sig] input %u does not verify\n", i); return 0;
        }
    unsigned long long total_out = 0;
    {
        const unsigned char* p = tx + 4;
        (void)rd_varint(p, &p);
        for (unsigned int i = 0; i < info.n_in; i++) { p += 36; unsigned long sl = rd_varint(p, &p); p += sl + 4; }
        (void)rd_varint(p, &p);
        for (unsigned int i = 0; i < info.n_out; i++) {
            unsigned long long v = 0; for (int j = 0; j < 8; j++) v |= (unsigned long long)p[j] << (8*j);
            p += 8; unsigned long sl = rd_varint(p, &p); p += sl; total_out += v;
        }
    }
    if (total_out > total_in) { printf("  [fee] in=%llu out=%llu\n", total_in, total_out); return 0; }
    return 1;
}

static int fails = 0;
static void ck(const char* label, int got, int expected) {
    if (got == expected) printf("ok  : %s\n", label);
    else { printf("FAIL: %s (got %d exp %d)\n", label, got, expected); fails++; }
}

int main(void) {
    static unsigned char ux[40 + 512 * 48 + 8];
    static unsigned char ublob[1 << 16];
    static unsigned char work[8192];
    unsigned char signedtx[4096];

    /* sender key (fixed for determinism) */
    unsigned char priv[32];
    for (int i = 0; i < 32; i++) priv[i] = (unsigned char)(0xaa + i);
    /* three "our" UTOXs: different txids/indices, P2PKH script of priv */
    unsigned char scr[25]; wallet_make_p2pkh_script(scr, priv);
    unsigned long long vA = 5000000ULL, vB = 3000000ULL, vC = 2000000ULL; /* 10 BTC total */
    unsigned char tA[32], tB[32], tC[32], tZ[32];
    for (int i = 0; i < 32; i++) { tA[i] = (unsigned char)(0x10 + i); tB[i] = (unsigned char)(0x20 + i); tC[i] = (unsigned char)(0x30 + i); tZ[i] = (unsigned char)(0x90 + i); }
    unsigned long iA = 0, iB = 1, iC = 2;

    /* destination: a different key's h160 */
    unsigned char dpriv[32]; for (int i = 0; i < 32; i++) dpriv[i] = (unsigned char)(0x55 + i);
    unsigned char to_h[20]; wallet_key_h160(to_h, dpriv);

    /* ---- load UTXO store with our 3 UTOXs ---- */
    utxo_init(ux, 512, ublob, sizeof ublob);
    utxo_put(ux, tA, iA, vA, 0, 0, scr, 25);
    utxo_put(ux, tB, iB, vB, 0, 0, scr, 25);
    utxo_put(ux, tC, iC, vC, 0, 0, scr, 25);

    /* ---- case 1: multi-input send (3 inputs), pay 6 BTC, fee 10000 ---- */
    {
        unsigned long long tval[3] = { vA, vB, vC };
        unsigned long tidx[3] = { iA, iB, iC };
        unsigned char (*tid)[32] = malloc(3 * 32);
        memcpy(tid[0], tA, 32); memcpy(tid[1], tB, 32); memcpy(tid[2], tC, 32);
        unsigned char txid[32]; unsigned long idx;
        unsigned long total_in = vA + vB + vC;             /* 10,000,000 */
        unsigned long long amount = 6000000ULL;            /* 0.06 BTC */
        unsigned long long fee   = 10000ULL;               /* careful small fee */

        long n = wallet_send_tx(signedtx, (long)sizeof signedtx,
                                tid, tidx, tval, 3, to_h, amount, fee, priv, 0);
        ck("send: signed tx produced", n > 0, 1);

        /* validator must accept it (double-spend + build sig + fee) */
        ck("send: multi-input tx VALID", n > 0 &&
           validate_signed_tx(signedtx, (unsigned long)n, ux, work, sizeof work), 1);

        /* input count == 3, and all reference our UTOXs */
        txinfo info; tx_parse(&info, signedtx, (unsigned long)n);
        ck("send: 3 inputs", info.n_in, 3);
        ck("send: 2 outputs (dest + change)", info.n_out, 2);

        /* change output = total_in - amount - fee = 3,990,000 */
        {
            /* parse outputs: value0 = amount, value1 = change */
            const unsigned char* p = signedtx + 4;
            (void)rd_varint(p, &p);
            for (unsigned int i = 0; i < info.n_in; i++) { p += 36; unsigned long sl = rd_varint(p, &p); p += sl + 4; }
            (void)rd_varint(p, &p);
            unsigned long long out0=0, out1=0;
            for (int j = 0; j < 8; j++) out0 |= (unsigned long long)p[j] << (8*j); p += 8; unsigned long sl0 = rd_varint(p, &p); p += sl0;
            for (int j = 0; j < 8; j++) out1 |= (unsigned long long)p[j] << (8*j); p += 8; unsigned long sl1 = rd_varint(p, &p); p += sl1;
            ck("send: out0 == amount", out0 == amount, 1);
            ck("send: out1 == change (total-amount-fee)", out1, total_in - amount - fee);
            /* fee = in - (out0+out1) */
            ck("send: fee == in - out", (total_in - out0 - out1), fee);
        }

        /* each input's outpoint matches our tA/tB/tC in order */
        input_outpoint(signedtx, 0, txid, &idx);
        ck("send: in0 outpoint == tA:0", memcmp(txid, tA, 32) == 0 && idx == iA, 1);
        input_outpoint(signedtx, 1, txid, &idx);
        ck("send: in1 outpoint == tB:1", memcmp(txid, tB, 32) == 0 && idx == iB, 1);
        input_outpoint(signedtx, 2, txid, &idx);
        ck("send: in2 outpoint == tC:2", memcmp(txid, tC, 32) == 0 && idx == iC, 1);
        free(tid);
    }

    /* ---- case 2: single-input send, exact balance, tiny change ---- */
    {
        unsigned long long tval[1] = { vA };
        unsigned long tidx[1] = { iA };
        unsigned char (*tid)[32] = malloc(32);
        memcpy(tid[0], tA, 32);
        unsigned long long amount = 4980000ULL;   /* vA - fee */
        unsigned long long fee = 20000ULL;
        long n = wallet_send_tx(signedtx, (long)sizeof signedtx, tid, tidx, tval, 1,
                                to_h, amount, fee, priv, 0);
        ck("send1: signed", n > 0, 1);
        ck("send1: valid", n > 0 && validate_signed_tx(signedtx, (unsigned long)n, ux, work, sizeof work), 1);
        txinfo info; tx_parse(&info, signedtx, (unsigned long)n);
        /* vA=5,000,000, amount=4,980,000, fee=20,000 -> change = 0, so NO
         * change output: the tx has exactly 1 output (destination only). */
        ck("send1: 1 input, 1 output (exact balance, no change)", info.n_in == 1 && info.n_out == 1, 1);
        free(tid);
    }

    /* ---- case 3: underfunded (amount+fee > balance) -> reject ---- */
    {
        unsigned long long tval[1] = { vA };
        unsigned long tidx[1] = { iA };
        unsigned char (*tid)[32] = malloc(32);
        memcpy(tid[0], tA, 32);
        long n = wallet_send_tx(signedtx, (long)sizeof signedtx, tid, tidx, tval, 1,
                                to_h, 5100000ULL, 1000ULL, priv, 0);  /* 5.1M > 5.0M */
        ck("underfunded rejected", n < 0, 1);
        free(tid);
    }

    /* ---- case 4: zero fee -> reject ---- */
    {
        unsigned long long tval[1] = { vA };
        unsigned long tidx[1] = { iA };
        unsigned char (*tid)[32] = malloc(32);
        memcpy(tid[0], tA, 32);
        long n = wallet_send_tx(signedtx, (long)sizeof signedtx, tid, tidx, tval, 1,
                                to_h, 5000000ULL, 0ULL, priv, 0);
        ck("zero-fee rejected", n < 0, 1);
        free(tid);
    }

    /* ---- case 5: against an EMPTY UTXO store -> validator rejects (double
     *              spend guard), proving the tx references our UTOXs ---- */
    {
        unsigned char ux2[40 + 512*48 + 8]; unsigned char ublob2[1<<16];
        utxo_init(ux2, 512, ublob2, sizeof ublob2);
        unsigned long long tval[1] = { vB };
        unsigned long tidx[1] = { iB };
        unsigned char (*tid)[32] = malloc(32);
        memcpy(tid[0], tB, 32);
        long n = wallet_send_tx(signedtx, (long)sizeof signedtx, tid, tidx, tval, 1,
                                to_h, 2900000ULL, 100000ULL, priv, 0);
        ck("send5: signed produced", n > 0, 1);
        ck("send5: rejected on empty UTXO (proof of outpoint ref)",
           n > 0 && validate_signed_tx(signedtx, (unsigned long)n, ux2, work, sizeof work), 0);
        free(tid);
    }

    /* ---- case 6: getbalance sums the wallet's unspent prevouts ---- */
    {
        unsigned long long tv[3] = { vA, vB, vC };
        ck("balance == vA+vB+vC", (long long)wallet_get_balance(tv, 3),
           (long long)(vA + vB + vC));
        ck("balance of one == vA", (long long)wallet_get_balance(tv, 1),
           (long long)vA);
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
