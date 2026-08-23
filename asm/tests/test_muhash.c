/* tests/test_muhash.c -- differential test of bitcoin_muhash.asm against
 * Bitcoin Core's own MuHash3072.
 *
 * Every vector in muhash_vectors.h was PRINTED by Core's code
 * (validation/muhash_oracle.cpp, linked against libbitcoin_crypto.a) and
 * turned into a header by validation/gen_muhash_vectors.py -- none of it is
 * transcribed by hand, and the generator refuses to write an implausibly
 * short file (ENGINEERING_RULES.md 1 and 3).
 *
 * The test is layered on purpose. A single end-to-end set hash that
 * disagreed would tell you nothing about where; these say which of
 * ChaCha20 / ToNum3072 / Num3072::Multiply / Finalize diverged.
 *
 * The last case is the one the whole design rests on: the same elements
 * inserted in the reverse order, and two shards combined with
 * muhash_combine, must land on the identical hash. If MuHash were not
 * order-independent here, the LSM's own iteration order (which is neither
 * Core's nor numeric -- see bitcoin_muhash.asm's header) would silently
 * change the answer.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "muhash_vectors.h"

extern void muhash_init(void* acc);
extern void muhash_insert(void* acc, const void* data, unsigned long len);
extern void muhash_combine(void* acc, const void* other);
extern void muhash_finalize(unsigned char out[32], const void* acc);
extern void muhash_to_num3072(void* out384, const void* data, unsigned long len);
extern void num3072_mul(void* a, const void* b);
extern void num3072_set_one(void* a);
extern long num3072_is_overflow(const void* a);
extern void num3072_full_reduce(void* a);
extern void chacha20_keystream_k0(void* out, unsigned long blocks, const unsigned char key[32]);

static int g_fail = 0;

static size_t unhex(const char* h, unsigned char* out, size_t cap)
{
    size_t n = strlen(h) / 2;
    if (n > cap) { fprintf(stderr, "unhex overflow\n"); exit(1); }
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (unsigned char)v;
    }
    return n;
}

static void expect_bytes(const char* what, int idx, const unsigned char* got,
                         const char* want_hex, size_t n)
{
    unsigned char want[512];
    size_t wn = unhex(want_hex, want, sizeof want);
    if (wn != n) { printf("FAIL %s[%d]: vector length %zu != %zu\n", what, idx, wn, n); g_fail++; return; }
    if (memcmp(got, want, n) != 0) {
        printf("FAIL %s[%d]: mismatch\n  got  ", what, idx);
        for (size_t i = 0; i < n && i < 48; i++) printf("%02x", got[i]);
        printf("%s\n  want ", n > 48 ? "..." : "");
        for (size_t i = 0; i < n && i < 48; i++) printf("%02x", want[i]);
        printf("%s\n", n > 48 ? "..." : "");
        g_fail++;
        return;
    }
    printf("ok   %s[%d]\n", what, idx);
}

/* Mirrors muhash_oracle.cpp's Splitmix, so the SET vectors' elements can be
 * regenerated here instead of being carried as a blob. */
struct splitmix { uint64_t s; };
static uint64_t sm_next(struct splitmix* r)
{
    r->s += 0x9E3779B97F4A7C15ULL;
    uint64_t z = r->s;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void sm_fill(struct splitmix* r, unsigned char* p, size_t n)
{
    for (size_t i = 0; i < n; i++) p[i] = (unsigned char)(sm_next(r) & 0xff);
}
static void set_element(int i, unsigned char e[40])
{
    struct splitmix r;
    r.s = (uint64_t)i * 1000003ULL + 7ULL;
    sm_fill(&r, e, 40);
}

int main(void)
{
    unsigned char buf[384], key[32], a[384], b[384], h[32];

    /* ---- layer 1: ChaCha20 keystream ---- */
    for (size_t i = 0; i < sizeof(MUHASH_KS) / sizeof(MUHASH_KS[0]); i++) {
        unhex(MUHASH_KS[i].key, key, sizeof key);
        memset(buf, 0xAA, sizeof buf);
        chacha20_keystream_k0(buf, 6, key);
        expect_bytes("chacha20", (int)i, buf, MUHASH_KS[i].ks, 384);
    }

    /* ---- layer 2: ToNum3072 (SHA256 then keystream) ---- */
    for (size_t i = 0; i < sizeof(MUHASH_ELEM) / sizeof(MUHASH_ELEM[0]); i++) {
        unsigned char data[2048];
        size_t dn = unhex(MUHASH_ELEM[i].data, data, sizeof data);
        memset(buf, 0xAA, sizeof buf);
        muhash_to_num3072(buf, data, dn);
        expect_bytes("to_num3072", (int)i, buf, MUHASH_ELEM[i].num, 384);
    }

    /* ---- layer 3: Num3072::Multiply, reduction corner cases included ---- */
    for (size_t i = 0; i < sizeof(MUHASH_MUL) / sizeof(MUHASH_MUL[0]); i++) {
        unhex(MUHASH_MUL[i].a, a, sizeof a);
        unhex(MUHASH_MUL[i].b, b, sizeof b);
        num3072_mul(a, b);
        expect_bytes("num3072_mul", (int)i, a, MUHASH_MUL[i].r, 384);
    }

    /* ---- layer 4: whole-set hashes ---- */
    for (size_t i = 0; i < sizeof(MUHASH_SET) / sizeof(MUHASH_SET[0]); i++) {
        int n = MUHASH_SET[i].n;
        unsigned char acc[384];
        muhash_init(acc);
        for (int j = 0; j < n; j++) {
            unsigned char e[40];
            set_element(j, e);
            muhash_insert(acc, e, sizeof e);
        }
        muhash_finalize(h, acc);
        expect_bytes("set_hash", n, h, MUHASH_SET[i].hash, 32);

        /* finalize must not consume the accumulator */
        unsigned char h2[32];
        muhash_finalize(h2, acc);
        if (memcmp(h, h2, 32) != 0) {
            printf("FAIL set_hash[%d]: finalize is not idempotent\n", n);
            g_fail++;
        }
    }

    /* ---- the order-independence property the design depends on ---- */
    {
        const int n = 200;
        unsigned char fwd[384], rev[384], s1[384], s2[384];
        unsigned char hf[32], hr[32], hs[32];
        muhash_init(fwd);
        muhash_init(rev);
        muhash_init(s1);
        muhash_init(s2);
        for (int j = 0; j < n; j++) {
            unsigned char e[40];
            set_element(j, e);
            muhash_insert(fwd, e, sizeof e);
            muhash_insert(j % 2 ? s2 : s1, e, sizeof e);   /* interleaved shards */
        }
        for (int j = n - 1; j >= 0; j--) {
            unsigned char e[40];
            set_element(j, e);
            muhash_insert(rev, e, sizeof e);
        }
        muhash_combine(s1, s2);
        muhash_finalize(hf, fwd);
        muhash_finalize(hr, rev);
        muhash_finalize(hs, s1);
        if (memcmp(hf, hr, 32) != 0) { printf("FAIL order-independence: reversed insert differs\n"); g_fail++; }
        else printf("ok   order-independence (reversed insertion)\n");
        if (memcmp(hf, hs, 32) != 0) { printf("FAIL shard-combine: two shards combined differ from one pass\n"); g_fail++; }
        else printf("ok   shard-combine (muhash_combine of two interleaved halves)\n");

        /* NEGATIVE control: a set-hash comparison that cannot fail is
         * worthless. Perturb one byte of one element and require the hash to
         * move. */
        unsigned char alt[384], ha[32], e[40];
        muhash_init(alt);
        for (int j = 0; j < n; j++) {
            set_element(j, e);
            if (j == 137) e[7] ^= 0x01;
            muhash_insert(alt, e, sizeof e);
        }
        muhash_finalize(ha, alt);
        if (memcmp(hf, ha, 32) == 0) {
            printf("FAIL negative control: one-bit change left the set hash unchanged\n");
            g_fail++;
        } else {
            printf("ok   negative control (one-bit element change moves the hash)\n");
        }
    }

    /* ---- reduction helpers, exercised directly at their boundaries ---- */
    {
        unsigned char v[384];
        uint64_t lo;
        /* modulus - 1: not overflown */
        memset(v, 0xff, sizeof v);
        lo = ~0ULL - 1103717ULL - 1ULL;
        memcpy(v, &lo, 8);
        if (num3072_is_overflow(v) != 0) { printf("FAIL is_overflow(modulus-1) said yes\n"); g_fail++; }
        else printf("ok   is_overflow(modulus-1) == 0\n");
        /* exactly the modulus: overflown, and FullReduce takes it to 0 */
        lo = ~0ULL - 1103717ULL + 1ULL;
        memcpy(v, &lo, 8);
        if (num3072_is_overflow(v) != 1) { printf("FAIL is_overflow(modulus) said no\n"); g_fail++; }
        else printf("ok   is_overflow(modulus) == 1\n");
        num3072_full_reduce(v);
        int zero = 1;
        for (int i = 0; i < 384; i++) if (v[i]) zero = 0;
        if (!zero) { printf("FAIL full_reduce(modulus) != 0\n"); g_fail++; }
        else printf("ok   full_reduce(modulus) == 0\n");
        /* 1 * x == x */
        unsigned char one[384], x[384], xc[384];
        num3072_set_one(one);
        struct splitmix r; r.s = 99;
        sm_fill(&r, x, sizeof x);
        /* keep x below the modulus so the identity is exact in representation */
        x[383] &= 0x7f;
        memcpy(xc, x, sizeof x);
        num3072_mul(x, one);
        if (memcmp(x, xc, 384) != 0) { printf("FAIL x*1 != x\n"); g_fail++; }
        else printf("ok   x*1 == x\n");
    }

    if (g_fail) { printf("\ntest_muhash: %d FAILURES\n", g_fail); return 1; }
    printf("\ntest_muhash: all checks passed\n");
    return 0;
}
