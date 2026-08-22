/* test_segwit_txout_bound.c -- incident #21 regression: sw_ser_txout() wrote
 * an unbounded CTxOut (8 + compactsize(len) + scriptPubKey) into a 600-byte
 * STACK buffer during BIP143 sighashing.
 *
 * Bitcoin consensus places no limit on an output's scriptPubKey size -- only
 * relay standardness does -- so a mined transaction with a >589-byte output
 * scriptPubKey and one segwit-v0 input smashed the verifying thread's stack.
 * Both call sites were affected: the hashOutputs loop (every output) and the
 * SIGHASH_SINGLE branch (one output).
 *
 * Every expected sighash here is Bitcoin Core's own SignatureHash(...,
 * SigVersion::WITNESS_V0), taken from validation/core_verify_oracle.cpp's
 * BIP143 command and baked into tests/segwit_txout_vec.h by
 * validation/gen_segwit_txout_vectors.py; the oracle self-checks against
 * BIP-0143's published worked example first.  Our own implementation is
 * never its own ground truth.
 *
 * Three families, deliberately:
 *   - real_*        ordinary mainnet transactions (small scriptPubKeys, all
 *                   five hashtypes).  These must produce byte-identical
 *                   hashes before AND after the bound fix -- that is what
 *                   proves this changed bounds, not behaviour.
 *   - mainnetbig_*  REAL mainnet P2WPKH spends whose own transaction carries
 *                   an output scriptPubKey over the old ceiling (1007 B at
 *                   946,375 up to 1694 B at 952,325).  This shape is not
 *                   hypothetical and not rare: a census of 940,000..963,000
 *                   at step 25 found it in 7 of 920 blocks.  Every one of
 *                   these smashes the stack on unmodified main.
 *   - sweep_/single_/scale_  synthetic, to pin the boundary exactly (589
 *                   fits, 590 does not) and to reach sizes past anything the
 *                   chain has produced, up to the 4 MiB midstate cap.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "segwit_txout_vec.h"

extern long segwit_v0_sighash(uint8_t out32[32], const uint8_t* tx, int64_t txlen,
                              int64_t n_in, uint32_t nHashType, uint64_t amount,
                              const uint8_t* scriptCode, uint64_t scriptcode_len,
                              uint8_t* pre, long cap);
/* The real block-verification entry point for a witness-v0 input
 * (daemon/tx_verify.c txv_verify_one -> here), used below to show the
 * overflow is reachable from where a peer's block actually lands and not
 * only from the sighash function in isolation. */
extern int sv_verify_witness_v0(const uint8_t* prog, uint32_t proglen,
                                const uint8_t* const* wit, const uint32_t* witlen,
                                uint32_t nwit, uint64_t amount, uint64_t flags,
                                unsigned long nIn, const uint8_t* tx,
                                unsigned long txlen, uint8_t* work,
                                unsigned long workcap);
extern void hash160(uint8_t o[20], const void* in, long long len);

static int fails = 0, checks = 0;
static void ck(const char* what, int ok){
    checks++;
    if (!ok){ fails++; printf("  FAIL %s\n", what); }
    else      printf("  ok  %s\n", what);
}

static size_t unhex(const char* h, uint8_t** out){
    size_t n = strlen(h) / 2;
    uint8_t* b = (uint8_t*)malloc(n ? n : 1);
    for (size_t i = 0; i < n; i++){
        unsigned v; sscanf(h + 2*i, "%2x", &v); b[i] = (uint8_t)v;
    }
    *out = b; return n;
}
static void tohex(char* d, const uint8_t* b, int n){
    for (int i = 0; i < n; i++) sprintf(d + 2*i, "%02x", b[i]);
    d[2*n] = 0;
}

/* Same rule the generator used (gen_segwit_txout_vectors.py: pattern()). */
static void pattern(uint8_t* d, size_t n){
    for (size_t i = 0; i < n; i++) d[i] = (uint8_t)((i * 7 + 3) & 0xff);
}
static int put_cs_t(uint8_t* d, uint64_t n){
    if (n < 0xfd){ d[0] = (uint8_t)n; return 1; }
    if (n <= 0xffff){ d[0] = 0xfd; d[1] = (uint8_t)n; d[2] = (uint8_t)(n>>8); return 3; }
    d[0] = 0xfe; for (int i = 0; i < 4; i++) d[1+i] = (uint8_t)(n >> (8*i)); return 5;
}

/* Rebuild a scale vector's transaction: version 2, one input (the fixed
 * outpoint / vout 0 / empty scriptSig / nSequence fffffffe), one output of
 * 546 sats whose scriptPubKey is pattern(spklen), one 71-zero-byte witness
 * item, locktime 0.  Byte-for-byte what the generator handed Core. */
static size_t build_scale_tx(uint8_t* d, const uint8_t* op32, unsigned long spklen){
    size_t n = 0;
    d[n++] = 2; d[n++] = 0; d[n++] = 0; d[n++] = 0;      /* version 2 */
    d[n++] = 0x00; d[n++] = 0x01;                        /* marker+flag */
    d[n++] = 1;                                          /* nin */
    memcpy(d + n, op32, 32); n += 32;
    d[n++] = 0; d[n++] = 0; d[n++] = 0; d[n++] = 0;      /* vout 0 */
    d[n++] = 0;                                          /* scriptSig len 0 */
    d[n++] = 0xfe; d[n++] = 0xff; d[n++] = 0xff; d[n++] = 0xff;  /* nSequence */
    d[n++] = 1;                                          /* nout */
    d[n++] = 0x22; d[n++] = 0x02;                        /* value 546 LE */
    for (int i = 0; i < 6; i++) d[n++] = 0;
    n += (size_t)put_cs_t(d + n, (uint64_t)spklen);
    pattern(d + n, spklen); n += spklen;
    d[n++] = 1;                                          /* 1 witness item */
    d[n++] = 71; memset(d + n, 0, 71); n += 71;
    d[n++] = 0; d[n++] = 0; d[n++] = 0; d[n++] = 0;      /* locktime */
    return n;
}

int main(int argc, char** argv){
    /* "-q" prints only failures; any other argument selects a single vector
     * by exact name, so one shape can be driven on its own (which is how the
     * two call sites were shown to overflow independently under ASAN, and how
     * the old build's surviving vectors were dumped one process at a time). */
    /* "-dump" prints "name <tab> sighash" and nothing else, so the hashes
     * this file produces can be diffed byte-for-byte between two builds of
     * bitcoin_segwit.c -- which is how the bound fix was shown to leave every
     * ordinary transaction's sighash untouched. */
    int quiet = 0, dump = 0; const char* only = 0;
    for (int i = 1; i < argc; i++){
        if (!strcmp(argv[i], "-q")) quiet = 1;
        else if (!strcmp(argv[i], "-dump")) { dump = 1; quiet = 1; }
        else only = argv[i];
    }
    long precap = 1 << 16;               /* same cap the real consensus
                                            * caller uses (sv_checksig_witness_v0) */
    uint8_t* pre = (uint8_t*)malloc((size_t)precap);

    if (!dump){
        printf("== BIP143 sighash vs Core over CTxOut serialization (incident #21) ==\n");
        printf("   %d vectors, %d scale vectors; expectations from Core's SignatureHash\n",
               SWTO_NVEC, SWTO_NSCALE);
    }

    int nreal = 0, nbig = 0, nsyn = 0, realfail = 0;
    for (int i = 0; i < SWTO_NVEC; i++){
        const swto_vec_t* v = &SWTO_VECS[i];
        if (only && strcmp(v->name, only)) continue;
        uint8_t *tx, *sc, *want;
        size_t txlen = unhex(SWTO_TXS[v->tx], &tx);
        size_t sclen = unhex(v->sc_hex, &sc);
        unhex(v->sighash_hex, &want);
        uint8_t got[32]; char gh[80], nm[256];
        long n = segwit_v0_sighash(got, tx, (int64_t)txlen, v->n_in, v->nhashtype,
                                   v->amount, sc, (uint64_t)sclen, pre, precap);
        int ok = (n > 0) && memcmp(got, want, 32) == 0;
        int real = !strncmp(v->name, "real_", 5);
        int big  = !strncmp(v->name, "mainnetbig_", 11);
        if (real) nreal++; else if (big) nbig++; else nsyn++;
        if (!ok && real) realfail++;
        if (dump){
            tohex(gh, got, 32);
            printf("%s\t%s\t%ld\n", v->name, gh, n);
            free(tx); free(sc); free(want);
            continue;
        }
        snprintf(nm, sizeof nm, "%-24s %s", v->name, v->note);
        if (ok && quiet) checks++;                 /* counted, not printed */
        else ck(nm, ok);
        if (!ok){ tohex(gh, got, 32); printf("       got %s want %s (n=%ld)\n",
                                             gh, v->sighash_hex, n); }
        free(tx); free(sc); free(want);
    }
    if (!dump)
        printf("  -- %d ordinary mainnet (equivalence corpus), %d mainnet OVER the "
               "old 589-byte bound, %d synthetic; %d equivalence mismatches\n",
               nreal, nbig, nsyn, realfail);

    /* Scale: MAX_BLOCK_WEIGHT caps a real transaction near 3,999,000 bytes and
     * SW_MIDSTATE_CAP is 4 MiB, so the largest CTxOut set any valid block can
     * carry must still hash -- the fix must not false-reject at the ceiling. */
    if (!dump) printf("== scale: no false reject below the 4 MiB midstate cap ==\n");
    for (int i = 0; i < SWTO_NSCALE; i++){
        const swto_scale_t* s = &SWTO_SCALE[i];
        if (only && strcmp(s->name, only)) continue;
        uint8_t* op32; unhex(SWTO_SCALE_OUTPOINT, &op32);
        uint8_t* sc;   size_t sclen = unhex(SWTO_SCALE_SC, &sc);
        uint8_t* want; unhex(s->sighash_hex, &want);
        uint8_t* tx = (uint8_t*)malloc(s->spklen + 256);
        size_t txlen = build_scale_tx(tx, op32, s->spklen);
        uint8_t got[32];
        long n = segwit_v0_sighash(got, tx, (int64_t)txlen, 0, 1, SWTO_SCALE_AMOUNT,
                                   sc, (uint64_t)sclen, pre, precap);
        char nm[128];
        if (dump){ char gh[80]; tohex(gh, got, 32); printf("%s\t%s\t%ld\n", s->name, gh, n); }
        else {
            snprintf(nm, sizeof nm, "%s: spk=%lu B tx=%zu B matches Core",
                     s->name, s->spklen, txlen);
            ck(nm, n > 0 && memcmp(got, want, 32) == 0);
        }
        free(op32); free(sc); free(want); free(tx);
    }

    /* Above the cap the answer must be a clean refusal (0), never a write. */
    if (!dump) printf("== over-cap refusal is clean ==\n");
    if (!only || !strcmp(only, "overcap_5000000")){
        unsigned long spklen = 5000000UL;    /* > SW_MIDSTATE_CAP (4 MiB);
                                               * no valid block can hold this,
                                               * but a peer can still send it */
        uint8_t* op32; unhex(SWTO_SCALE_OUTPOINT, &op32);
        uint8_t* sc; size_t sclen = unhex(SWTO_SCALE_SC, &sc);
        uint8_t* tx = (uint8_t*)malloc(spklen + 256);
        size_t txlen = build_scale_tx(tx, op32, spklen);
        uint8_t got[32];
        long n = segwit_v0_sighash(got, tx, (int64_t)txlen, 0, 1, SWTO_SCALE_AMOUNT,
                                   sc, (uint64_t)sclen, pre, precap);
        if (dump) printf("overcap_5000000\t-\t%ld\n", n);
        else ck("5 MB scriptPubKey refused (returns 0), no overrun", n == 0);
        free(op32); free(sc); free(tx);
    }

    /* Reachability from the real entry point. daemon/tx_verify.c hands a
     * witness-v0 input straight to sv_verify_witness_v0 with the FULL
     * spending transaction, and the P2WPKH script's OP_CHECKSIG then runs
     * BIP143 over every one of that transaction's outputs -- before anything
     * has decided the transaction is invalid. So a peer's block reaches
     * sw_ser_txout with attacker-chosen output scriptPubKeys. Nothing in the
     * block or transaction path bounds an output's scriptPubKey: TXV_SPK_CAP
     * and the taproot 0xfd limit both apply to PREVOUT scripts coming out of
     * the UTXO set, never to the spending transaction's own outputs.
     *
     * The signature here is well-formed DER over a key that will not verify,
     * which is the point: the sighash is computed first, so the overflow
     * happens on a transaction that is about to be rejected anyway. Against
     * unmodified main this call smashes the stack; the only assertion is that
     * it returns a rejection instead.
     *
     * Skipped under -fsanitize=address: this arm runs the hand-written asm
     * interpreter (script_eval), which ASAN cannot instrument and which
     * SIGSEGVs under it regardless of output size -- verified by running this
     * exact call with a 20-byte scriptPubKey on the FIXED build, which faults
     * identically, and it still does after incident #20's tree-wide SysV
     * stack-ABI fix, so it is not that. Unexplained, out of scope here, and
     * recorded so the next reader does not mistake it for this bug. The plain
     * build is the one that matters anyway: gcc's default
     * -fstack-protector-strong turns the old overrun into a deterministic
     * "stack smashing detected" abort at 590 bytes and not at 589. */
#if defined(__SANITIZE_ADDRESS__)
    const int asan_build = 1;
#else
    const int asan_build = 0;
#endif
    if (!dump && !only && !asan_build){
        printf("== reachable from sv_verify_witness_v0 (the block path) ==\n");
        static const uint8_t pub[33] = {
            0x02,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,
            0xdd,0xee,0xff,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x10,0x32,
            0x54,0x76,0x98,0xba,0xdc,0xfe,0x01 };
        uint8_t prog[20]; hash160(prog, pub, 33);
        uint8_t sig[71];
        sig[0]=0x30; sig[1]=0x44; sig[2]=0x02; sig[3]=0x20;
        for (int i=0;i<32;i++) sig[4+i] = (uint8_t)(i?i:1);
        sig[36]=0x02; sig[37]=0x20;
        for (int i=0;i<32;i++) sig[38+i] = (uint8_t)(i?i:1);
        sig[70]=0x01;                                    /* SIGHASH_ALL */

        /* spending tx: 1 P2WPKH input, 1 output with a 700-byte scriptPubKey */
        uint8_t* op32; unhex(SWTO_SCALE_OUTPOINT, &op32);
        uint8_t* tx = (uint8_t*)malloc(4096);
        size_t txlen = build_scale_tx(tx, op32, 700);
        const uint8_t* wit[2]  = { sig, pub };
        uint32_t witlen[2]     = { 71, 33 };
        uint8_t* work = (uint8_t*)malloc(1u<<20);
        int err = sv_verify_witness_v0(prog, 20, wit, witlen, 2, 546, 0, 0,
                                       tx, (unsigned long)txlen, work, 1u<<20);
        ck("700-byte output scriptPubKey: block path rejects, does not overrun",
           err != 0);
        free(op32); free(tx); free(work);
    }

    if (!dump)
        printf("\n%s (%d checks, %d failures)\n",
               fails ? "FAILURES" : "ALL PASS", checks, fails);
    free(pre);
    return fails ? 1 : 0;
}
