/* test_bip39.c -- verify the BIP39 mnemonic<->seed assembly (bitcoin_bip39.asm)
 * against the INDEPENDENT Python oracle (validation/gen_bip39_vectors.py ->
 * tests/bip39_vec.h), which was itself cross-checked against the official
 * Bitcoin BIP39 vectors (empty-passphrase seeds via Python hashlib, and the
 * "TREZOR" passphrase seeds verbatim from the official bip-0039 vectors).
 *
 * Covers, for every vector:
 *   1. bip39_generate        : entropy -> mnemonic string == oracle
 *   2. bip39_validate        : returns the exact word count (checksum + wordlist)
 *   3. bip39_mnemonic_to_entropy : reverse == original entropy
 *   4. bip39_mnemonic_to_seed    : empty-passphrase seed == oracle
 *   5. bip39_mnemonic_to_seed    : "TREZOR"-passphrase seed == official oracle
 * Plus a set of non-empty passphrase vectors and a batch of negative/corruption
 * cases that must be rejected.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "bip39_vec.h"

/* ---------------- verified asm primitives ---------------- */
extern int  bip39_generate(char* out, const unsigned char* entropy, long ent_bits);
extern int  bip39_validate(const char* mnemonic);
extern int  bip39_mnemonic_to_entropy(unsigned char out[32], const char* mnemonic);
extern int  bip39_mnemonic_to_seed(unsigned char seed[64], const char* mnemonic,
                                   const char* passphrase, long passlen);

static int failures = 0;

static int hx_parse_byte(const char* s) { unsigned v; sscanf(s, "%2x", &v); return (int)v; }
static void hx_to(unsigned char* dst, const char* hex, int n) {
    for (int i = 0; i < n; i++) dst[i] = (unsigned char)hx_parse_byte(hex + i * 2);
}
static int hx_eq(const unsigned char* a, const unsigned char* b, int n) {
    return memcmp(a, b, (size_t)n) == 0;
}
static void pr_hex(const unsigned char* d, int n) {
    for (int i = 0; i < n; i++) printf("%02x", d[i]);
}

int main(void) {
    /* ---------- 1-4: entropy -> mnemonic -> seed (empty passphrase) ---------- */
    for (size_t i = 0; i < BIP39VEC_LEN; i++) {
        const struct bip39_vec* v = &BIP39VEC[i];
        unsigned char ent[32], exp_seed[64], got_seed[64], back[32];
        hx_to(ent, v->ent, 32);
        hx_to(exp_seed, v->seed_empty, 64);

        char mn[256];
        long ent_bits = (long)v->words * 32 / 3;
        int r = bip39_generate(mn, ent, ent_bits);
        if (r != 1 || strcmp(mn, v->mn) != 0) {
            printf("FAIL[%zu] generate\n  got %s\n  exp %s\n", i, r == 1 ? mn : "(err)", v->mn);
            failures++;
            continue;
        }

        int nw = bip39_validate(v->mn);
        if (nw != v->words) {
            printf("FAIL[%zu] validate got %d exp %d\n", i, nw, v->words);
            failures++;
        }

        long eb = bip39_mnemonic_to_entropy(back, v->mn);
        if (eb != ent_bits || !hx_eq(back, ent, (int)(ent_bits / 8))) {
            printf("FAIL[%zu] mnemonic_to_entropy (eb=%ld)\n  got  ", i, eb);
            pr_hex(back, (int)(ent_bits / 8)); printf("\n  exp  ");
            pr_hex(ent, (int)(ent_bits / 8)); printf("\n");
            failures++;
        }

        bip39_mnemonic_to_seed(got_seed, v->mn, NULL, 0);
        if (!hx_eq(got_seed, exp_seed, 64)) {
            printf("FAIL[%zu] seed(empty)\n  got  ", i); pr_hex(got_seed, 64);
            printf("\n  exp  "); pr_hex(exp_seed, 64); printf("\n");
            failures++;
        }

        /* 5: TREZOR-passphrase seed against official oracle */
        unsigned char exp_tz[64];
        hx_to(exp_tz, v->seed_trezor, 64);
        bip39_mnemonic_to_seed(got_seed, v->mn, "TREZOR", 6);
        if (!hx_eq(got_seed, exp_tz, 64)) {
            printf("FAIL[%zu] seed(TREZOR)\n  got  ", i); pr_hex(got_seed, 64);
            printf("\n  exp  "); pr_hex(exp_tz, 64); printf("\n");
            failures++;
        }
    }
    printf("vector round (gen+validate+entropy+seed empty/TREZOR): %d vectors\n",
           (int)BIP39VEC_LEN);

    /* ---------- extra passphrase vectors ---------- */
    for (size_t i = 0; i < BIP39PPVEC_LEN; i++) {
        const struct bip39_pp_vec* v = &BIP39PPVEC[i];
        unsigned char exp_seed[64], got_seed[64];
        hx_to(exp_seed, v->seed, 64);
        if (bip39_validate(v->mn) <= 0) { printf("FAIL pp validate %zu\n", i); failures++; }
        bip39_mnemonic_to_seed(got_seed, v->mn, v->pass, (long)strlen(v->pass));
        if (!hx_eq(got_seed, exp_seed, 64)) {
            printf("FAIL pp[%zu] pass='%s'\n  got  ", i, v->pass);
            pr_hex(got_seed, 64); printf("\n  exp  "); pr_hex(exp_seed, 64); printf("\n");
            failures++;
        }
    }

    /* ---------- negative / corruption cases (must be rejected) ---------- */
    const char* bad[] = {
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",          /* 11 words */
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",  /* 12 words valid list but WRONG checksum (final should be 'about') */
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzz",       /* unknown word */
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage",                          /* 11 words, mixed */
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about extra", /* 13 words */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int nw = bip39_validate(bad[i]);
        if (nw != -1) {
            printf("FAIL neg[%zu] expected -1 got %d: %s\n", i, nw, bad[i]);
            failures++;
        }
    }

    /* ---- WAL-11 (audit 2026-09-03): an over-long mnemonic must not write
     * past m39_idx.
     *
     * bip39_parse stored every valid word it found into m39_idx (24 dwords,
     * 96 bytes) and only checked the 12/15/18/21/24 word count AFTERWARDS, so
     * `wallet_cli seed "<400 valid words>"` ran 1,600 bytes forward through
     * m39_salt, m39_msg, m39_prev/cur/acc and m39_nw into the next object's
     * .bss. Reachable from the CLI and from a hand-edited store, not over RPC
     * (the mnemonic is capped there).
     *
     * The RETURN VALUE cannot detect this: 400 words was refused before the
     * fix too, at the word-count check, after doing the damage. So the
     * assertion is on m39_guard, the .bss canary sitting past the last of
     * those buffers. Delete the `cmp r13, 24` bound in bip39_parse and this
     * fails; that is what makes it a control and not a restatement. */
    {
        extern unsigned char m39_guard[512];
        /* 400 VALID words, so nothing short-circuits on an unknown word.
         * "zoo" and NOT "abandon": abandon is wordlist index 0, so the
         * overflow writes zeros and a zero-initialised canary still reads
         * clean -- the first version of this test used it and passed with
         * the bound removed. zoo is index 2047, which is visible. */
        static char longm[400 * 4 + 1];
        char* w = longm;
        for (int i = 0; i < 400; i++){ memcpy(w, i ? " zoo" : "zoo", i ? 4 : 3); w += i ? 4 : 3; }
        *w = 0;

        int guard_was_clean = 1;
        for (int i = 0; i < 512; i++) if (m39_guard[i]) guard_was_clean = 0;
        if (!guard_was_clean){ printf("FAIL WAL-11 canary dirty before the call\n"); failures++; }

        int nw = bip39_validate(longm);
        if (nw != -1){ printf("FAIL WAL-11 400-word mnemonic accepted (%d)\n", nw); failures++; }
        else printf("PASS WAL-11 400-word mnemonic rejected\n");

        int dirty = 0;
        for (int i = 0; i < 512; i++) if (m39_guard[i]) dirty++;
        if (dirty){ printf("FAIL WAL-11 parse wrote %d bytes past its buffers\n", dirty); failures++; }
        else printf("PASS WAL-11 nothing written past m39_idx (canary clean)\n");

        /* and the module still works afterwards */
        int ok = bip39_validate("abandon abandon abandon abandon abandon abandon "
                                "abandon abandon abandon abandon abandon about");
        if (ok != 12){ printf("FAIL WAL-11 valid 12-word mnemonic broken after (%d)\n", ok); failures++; }
        else printf("PASS WAL-11 a valid mnemonic still parses afterwards\n");
    }

    printf(failures ? "FAILURES %d\n" : "ALL TESTS PASSED (0 failures)\n", failures);
    return failures ? 1 : 0;
}
