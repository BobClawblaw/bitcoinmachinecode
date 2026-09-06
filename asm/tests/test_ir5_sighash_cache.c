#define _GNU_SOURCE
/* tests/test_ir5_sighash_cache.c -- IR-5 (INTERP_REVIEW_2026-09-05): the
 * BIP143 / BIP341 per-transaction aggregates are computed once per
 * transaction per thread, not once per signature.
 *
 *   A. digests are identical with and without a session, for every input
 *      and hashtype of a 4-input tx (ALL, NONE, SINGLE, |ANYONECANPAY);
 *      SINGLE's per-input hashOutputs must never come from the memo.
 *   B. the key is the identity: a different transaction written over the
 *      SAME buffer under a NEW key yields that transaction's digest, not the
 *      memoised one.
 *   C. the cost: a 14,000-input P2WPKH transaction with 14,000 real
 *      signatures through tx_verify_at_height (the daemon's path, sessions
 *      opened by tx_verify.c itself, workers included), the child PINNED TO
 *      ONE CPU so the measurement is the per-core cost the finding is about
 *      -- across 8 SHA-NI cores a 6,000-input run hid the recompute under
 *      the ECDSA cost entirely. Before: every signature re-parsed the ~2.3 MB
 *      transaction and re-hashed ~560 KB of aggregates (~280 us each on
 *      SHA-NI, seconds; tens of seconds without SHA-NI). After: once. Run
 *      under alarm(); watched to FAIL against the memo neutralised. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <sched.h>
typedef unsigned char u8; typedef unsigned long long u64; typedef unsigned int u32;

extern long segwit_v0_sighash(u8 out32[32], const u8* tx, int64_t txlen, int64_t n_in, u32 nHashType,
                              u64 amount, const u8* scriptCode, u64 scriptcode_len, u8* pre, long cap);
extern void swsig_session_begin(u64 key); extern void swsig_session_end(void);
typedef int (*rf_t)(void*, const u8[36], u32, u64*, u64*, u64*, const u8**, unsigned long*);
extern int  tx_verify_at_height(const u8*, u64, long, rf_t, void*, const char**);
extern int  tx_dispatch_init(void);
extern void scalar_to_pubkey(u8 pub[33], const u8 k[32]);
extern void hash160(u8 out[20], const void* in, long long len);
extern int  wallet_ecdsa_sign(uint64_t r[4], uint64_t s[4], const u8 z[32], const u8 priv[32]);

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }

static void limb_to_be(u8 out[33], const uint64_t v[4], int* olen){
    u8 tmp[32]; for (int i = 0; i < 32; i++) tmp[31-i] = (u8)(v[i/8] >> ((i%8)*8));
    int s = 0; while (s < 31 && tmp[s] == 0) s++;
    if (tmp[s] & 0x80){ out[0] = 0; memcpy(out+1, tmp+s, 32-s); *olen = 33-s; } else { memcpy(out, tmp+s, 32-s); *olen = 32-s; }
}
static int der_enc(u8* out, const uint64_t r[4], const uint64_t s[4]){
    uint64_t n[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
    uint64_t half[4]={0xDFE92F46681B20A0ULL,0x5D576E7357A4501DULL,0xFFFFFFFFFFFFFFFEULL,0x7FFFFFFFFFFFFFFFULL};
    uint64_t sn[4]; int borrow = 0;
    for (int i = 0; i < 4; i++){ unsigned __int128 u = (unsigned __int128)n[i]-s[i]-borrow; sn[i] = (uint64_t)u; borrow = (u>>64)&1; }
    int gt = 0; for (int i = 3; i >= 0; i--){ if (s[i] > half[i]){ gt = 1; break; } if (s[i] < half[i]) break; }
    const uint64_t* su = gt ? sn : s;
    u8 rb[33], sb[33]; int rl, sl; limb_to_be(rb, r, &rl); limb_to_be(sb, su, &sl);
    size_t k = 0; out[k++] = 0x30; size_t lp = k++; out[k++] = 0x02; out[k++] = (u8)rl; memcpy(out+k, rb, rl); k += rl;
    out[k++] = 0x02; out[k++] = (u8)sl; memcpy(out+k, sb, sl); k += sl; out[lp] = (u8)(k-2); out[k++] = 0x01;
    return (int)k;
}
static void put_cs(u8** p, u64 v){ if (v < 0xfd) *(*p)++ = (u8)v; else { *(*p)++ = 0xfd; *(*p)++ = (u8)v; *(*p)++ = (u8)(v>>8); } }

/* ---- a legacy-serialized tx with `nin` inputs (empty scriptSigs) and 2 outputs ---- */
static u64 build_stripped(u8* o, int nin, u64 out0_value){
    u8* p = o; *p++=2; *p++=0; *p++=0; *p++=0; put_cs(&p, (u64)nin);
    for (int i = 0; i < nin; i++){ memset(p, 0xAB, 32); p += 32; memcpy(p, &i, 4); p += 4; *p++ = 0; *p++=0xff; *p++=0xff; *p++=0xff; *p++=0xff; }
    *p++ = 2;
    memcpy(p, &out0_value, 8); p += 8; *p++ = 1; *p++ = 0x51;
    u64 v1 = 777; memcpy(p, &v1, 8); p += 8; *p++ = 1; *p++ = 0x51;
    *p++=0; *p++=0; *p++=0; *p++=0;
    return (u64)(p - o);
}

static u8 g_spk[22]; static u8 g_h160[20];
static int resolve_p2wpkh(void* ctx, const u8 op[36], u32 idx, u64* value, u64* height, u64* cb, const u8** spk, unsigned long* spklen){
    (void)ctx; (void)op; (void)idx; *value = 100000; *height = 700000; *cb = 0; *spk = g_spk; *spklen = 22; return 1;
}

int main(void){
    tx_dispatch_init();
    static u8 pre[1<<16];
    static const u8 SC[25] = {0x76,0xa9,0x14, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20, 0x88,0xac};

    /* ---- A. session == no session, every input x hashtype ---- */
    {
        static u8 tx[512]; u64 tl = build_stripped(tx, 4, 5000);
        const u32 hts[5] = { 1, 2, 3, 0x81, 0x83 };
        int all = 1;
        swsig_session_begin(7);
        for (int i = 0; i < 4 && all; i++) for (int h = 0; h < 5 && all; h++){
            u8 d1[32]; long l1 = segwit_v0_sighash(d1, tx, (int64_t)tl, i, hts[h], 100000, SC, 25, pre, sizeof pre);
            swsig_session_end();
            u8 d0[32]; long l0 = segwit_v0_sighash(d0, tx, (int64_t)tl, i, hts[h], 100000, SC, 25, pre, sizeof pre);
            swsig_session_begin(7);
            if (l0 <= 0 || l1 != l0 || memcmp(d0, d1, 32)){ printf("      mismatch at input %d hashtype 0x%02x (len %ld/%ld)\n", i, hts[h], l0, l1); all = 0; }
        }
        swsig_session_end();
        ck("A. 4 inputs x 5 hashtypes: session digest == no-session digest", all);
    }
    /* ---- B. a new transaction over the same buffer under a new key ---- */
    {
        static u8 buf[512]; u64 tl = build_stripped(buf, 4, 5000);
        u8 dA[32], dB[32], dBref[32];
        swsig_session_begin(11); segwit_v0_sighash(dA, buf, (int64_t)tl, 1, 1, 100000, SC, 25, pre, sizeof pre); swsig_session_end();
        build_stripped(buf, 4, 6000);                       /* same length, different output value */
        segwit_v0_sighash(dBref, buf, (int64_t)tl, 1, 1, 100000, SC, 25, pre, sizeof pre);   /* no session */
        swsig_session_begin(12); segwit_v0_sighash(dB, buf, (int64_t)tl, 1, 1, 100000, SC, 25, pre, sizeof pre); swsig_session_end();
        ck("B. new key over the same buffer: digest is the NEW transaction's", memcmp(dB, dBref, 32) == 0);
        ck("B. ...and differs from the memoised one", memcmp(dA, dB, 32) != 0);
    }
    /* ---- C. 6,000 real P2WPKH signatures through the daemon path ---- */
    {
        enum { N = 14000 };
        static u8 priv[32]; for (int i = 0; i < 32; i++) priv[i] = (u8)(i + 21);
        static u8 pub33[33]; scalar_to_pubkey(pub33, priv); hash160(g_h160, pub33, 33);
        g_spk[0] = 0x00; g_spk[1] = 0x14; memcpy(g_spk + 2, g_h160, 20);
        u8 sc[25]; memcpy(sc, SC, 25); memcpy(sc + 3, g_h160, 20);
        static u8 stripped[2<<20]; u64 sl = build_stripped(stripped, N, (u64)N * 100000 - 5000);
        static u8 sigs[N][80]; static int siglen[N];
        struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
        swsig_session_begin(99);                            /* the test's own signing is O(N) too */
        for (int i = 0; i < N; i++){
            u8 z[32]; if (segwit_v0_sighash(z, stripped, (int64_t)sl, i, 1, 100000, sc, 25, pre, sizeof pre) <= 0){ printf("FAIL: sighash %d\n", i); return 1; }
            uint64_t r[4], s[4]; wallet_ecdsa_sign(r, s, z, priv); siglen[i] = der_enc(sigs[i], r, s);
        }
        swsig_session_end();
        clock_gettime(CLOCK_MONOTONIC, &t1);
        printf("      signed %d inputs in %.0f ms\n", N, (t1.tv_sec-t0.tv_sec)*1e3 + (t1.tv_nsec-t0.tv_nsec)/1e6);
        /* assemble the full serialization: marker, inputs, outputs, witnesses, locktime */
        static u8 full[4<<20]; u8* p = full;
        memcpy(p, stripped, 4); p += 4; *p++ = 0x00; *p++ = 0x01;
        const u8* q = stripped + 4; u64 body = sl - 4 - 4;   /* everything between version and locktime */
        memcpy(p, q, body); p += body;
        for (int i = 0; i < N; i++){ *p++ = 2; *p++ = (u8)siglen[i]; memcpy(p, sigs[i], siglen[i]); p += siglen[i]; *p++ = 33; memcpy(p, pub33, 33); p += 33; }
        memcpy(p, stripped + sl - 4, 4); p += 4;
        u64 fl = (u64)(p - full);
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0){
            alarm(300);
            { cpu_set_t one; CPU_ZERO(&one); CPU_SET(0, &one); sched_setaffinity(0, sizeof one, &one); }   /* one core */
            const char* r = "";
            struct timespec a, b; clock_gettime(CLOCK_MONOTONIC, &a);
            int ok = tx_verify_at_height(full, fl, 900000, resolve_p2wpkh, NULL, &r);
            clock_gettime(CLOCK_MONOTONIC, &b);
            double ms = (b.tv_sec-a.tv_sec)*1e3 + (b.tv_nsec-a.tv_nsec)/1e6;
            if (ok != 1){ printf("FAIL: C. %d-input P2WPKH tx rejected: %s\n", N, r); fflush(stdout); _exit(2); }
            if (ms > 2500.0){ printf("FAIL: C. %d real P2WPKH signatures verified on one core in %.0f ms (aggregates recomputed per signature; want < 2500)\n", N, ms); fflush(stdout); _exit(3); }
            printf("ok  : C. %d real P2WPKH signatures verified on one core in %.0f ms\n", N, ms); fflush(stdout); _exit(0);
        }
        int st = 0; waitpid(pid, &st, 0); checks++;
        if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0)){ if (WIFSIGNALED(st)) printf("FAIL: C. child killed by signal %d\n", WTERMSIG(st)); fails++; }
    }
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
