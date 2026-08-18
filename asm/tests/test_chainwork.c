/* test_chainwork.c -- 100% AI-generated harness for bitcoin_chainwork.asm
 * (Stage A reorg/fork-choice primitive #1: chainwork tracking).
 *
 * Vectors for block_work were cross-checked offline against Bitcoin Core's
 * own GetBlockProof identity work = ((~target) / (target+1)) + 1, computed
 * with Python arbitrary-precision integers (target derived from the same
 * compact-nBits formula bitcoin_hash.asm's diff_target uses):
 *
 *   def diff_target(bits):
 *       exponent = bits >> 24; mantissa = bits & 0x00ffffff
 *       return mantissa << (8*(exponent-3)) if exponent > 3 else mantissa >> (8*(3-exponent))
 *   def block_work(bits):
 *       t = diff_target(bits)
 *       return (((1<<256)-1-t)//(t+1))+1
 *
 * Run in a throwaway temp dir (store_chainwork_* touch relative filenames).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

typedef unsigned char u8;

extern void block_work(u8 work[16], unsigned int bits);
extern void chainwork_add(u8 out[16], const u8 a[16], const u8 b[16]);
extern void u256_div(u8 q[32], const u8 a[32], const u8 b[32]);
extern int  store_chainwork_init(void* st);
extern int  store_chainwork_append(void* st, long height, const u8 work[16]);
extern int  store_chainwork_get_at(void* st, long height, u8 out[16]);
extern int  store_chainwork_get_tip(void* st, u8 out[16]);

static int failures = 0;
static void ck(const char* label, long got, long exp) {
    if (got == exp) printf("PASS %s (got %ld)\n", label, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", label, got, exp); failures++; }
}
static void ckm(const char* label, int cond) { ck(label, cond, 1); }

static unsigned __int128 le16_to_u128(const u8 b[16]) {
    unsigned __int128 v = 0;
    for (int i = 15; i >= 0; i--) v = (v << 8) | b[i];
    return v;
}
static void u128_to_le16(unsigned __int128 v, u8 out[16]) {
    for (int i = 0; i < 16; i++) { out[i] = (u8)(v & 0xff); v >>= 8; }
}
static void le32_set_u64(u8 buf[32], int limb, uint64_t v) {
    memcpy(buf + limb*8, &v, 8);
}
static uint64_t le32_get_u64(const u8 buf[32], int limb) {
    uint64_t v; memcpy(&v, buf + limb*8, 8); return v;
}

int main(void) {
    char tmpl[] = "/tmp/btccworkXXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) { printf("FAIL mkdtemp\n"); return 1; }
    chdir(dir);

    /* ---------- 1. block_work hand-checked vectors ---------- */
    struct { unsigned int bits; unsigned __int128 expect; const char* name; } vec[] = {
        { 0x1d00ffffu, (unsigned __int128)4295032833ULL,               "genesis 0x1d00ffff" },
        { 0x1f00ffffu, (unsigned __int128)65537ULL,                    "easy 0x1f00ffff" },
        { 0x1c00ffffu, (unsigned __int128)1099528405248ULL,            "0x1c00ffff" },
        { 0x1b0404cbu, (unsigned __int128)70040908352512ULL,           "0x1b0404cb" },
        { 0x170e0408u, 0, "0x170e0408 (real-scale diff)" }, /* filled in below: exceeds a 64-bit half */
        { 0x207fffffu, (unsigned __int128)2ULL,                        "min-diff-ish 0x207fffff" },
    };
    /* 0x170e0408's expected work (86254825629332260895102, hex
     * 0x1243e22ae039b885b97e) doesn't fit in a single 64-bit literal --
     * built here from its exact lo64/hi64 halves (lo64=0xe22ae039b885b97e,
     * hi64=0x1243), independently re-derived via Python arbitrary-precision
     * integers per the file header's oracle formula. */
    vec[4].expect = ((unsigned __int128)0x1243ULL << 64) | (unsigned __int128)0xe22ae039b885b97eULL;

    for (unsigned i = 0; i < sizeof(vec)/sizeof(vec[0]); i++) {
        u8 work[16];
        block_work(work, vec[i].bits);
        unsigned __int128 got = le16_to_u128(work);
        char label[128];
        snprintf(label, sizeof label, "block_work %s", vec[i].name);
        ckm(label, got == vec[i].expect);
    }

    /* target==0 edge case (exponent<3) -> work==0 */
    {
        u8 work[16];
        block_work(work, 0x02001234u); /* exponent=2 -> target=0 per compact_to_target_le's scope */
        unsigned __int128 got = le16_to_u128(work);
        ckm("block_work exponent<3 -> work=0", got == 0);
    }

    /* ---------- 2. u256_div direct sanity checks ---------- */
    {
        u8 a[32] = {0}, b[32] = {0}, q[32] = {0};
        le32_set_u64(a, 0, 100);
        le32_set_u64(b, 0, 7);
        u256_div(q, a, b);
        ck("u256_div 100/7", (long)le32_get_u64(q, 0), 14);
        ckm("u256_div 100/7 upper limbs zero",
            le32_get_u64(q,1)==0 && le32_get_u64(q,2)==0 && le32_get_u64(q,3)==0);
    }
    {
        /* (2^128) / 3 -- exercises carry across limb boundaries on both the
         * dividend and the quotient. floor(2^128/3) = (1<<128)//3, computed
         * with Python arbitrary-precision integers as an independent oracle
         * (deliberately NOT hand-derived -- an earlier draft of this test
         * hand-derived the high limb as 0, which is WRONG: 2^64 mod 3 == 1
         * makes the quotient's low and high 64-bit halves come out equal --
         * a good reminder that hand arithmetic on this stuff is exactly the
         * kind of thing worth cross-checking against a real oracle instead
         * of trusting). Split: lo64=6148914691236517205,
         * hi64=6148914691236517205 (same value in both limbs). */
        u8 a[32] = {0}, b[32] = {0}, q[32] = {0};
        le32_set_u64(a, 2, 1); /* a = 2^128 */
        le32_set_u64(b, 0, 3);
        u256_div(q, a, b);
        uint64_t expect_lo = 6148914691236517205ULL;
        uint64_t expect_hi = 6148914691236517205ULL;
        ck("u256_div 2^128/3 lo", (long)le32_get_u64(q,0), (long)expect_lo);
        ck("u256_div 2^128/3 hi", (long)le32_get_u64(q,1), (long)expect_hi);
        ckm("u256_div 2^128/3 upper limbs zero", le32_get_u64(q,2)==0 && le32_get_u64(q,3)==0);
    }

    /* ---------- 3. chainwork_add ---------- */
    {
        u8 a[16], b[16], out[16];
        unsigned __int128 av = (unsigned __int128)4295032833ULL;
        unsigned __int128 bv = (unsigned __int128)1099528405248ULL;
        u128_to_le16(av, a);
        u128_to_le16(bv, b);
        chainwork_add(out, a, b);
        ckm("chainwork_add basic", le16_to_u128(out) == av+bv);
    }
    {
        /* carry across the low/high limb boundary */
        u8 a[16], b[16], out[16];
        unsigned __int128 av = ((unsigned __int128)1 << 64) - 1; /* low limb all-ones */
        unsigned __int128 bv = 1;
        u128_to_le16(av, a);
        u128_to_le16(bv, b);
        chainwork_add(out, a, b);
        ckm("chainwork_add carries into high limb", le16_to_u128(out) == av+bv);
        ckm("chainwork_add carry result == 2^64", le16_to_u128(out) == ((unsigned __int128)1 << 64));
    }

    /* ---------- 4. store_chainwork_*: monotonic accumulation across a
     * synthetic chain of headers, verified against independently
     * accumulated __int128 expected totals. ---------- */
    {
        unsigned char st[128]; memset(st, 0, sizeof st);
        ck("store_chainwork_init", store_chainwork_init(st), 1);

        unsigned int bits_seq[] = { 0x1d00ffffu, 0x1d00ffffu, 0x1c00ffffu, 0x1b0404cbu, 0x1f00ffffu, 0x1d00ffffu };
        int n = (int)(sizeof(bits_seq)/sizeof(bits_seq[0]));
        unsigned __int128 running = 0;
        unsigned __int128 prev_running = 0;
        for (int h = 0; h < n; h++) {
            u8 w[16];
            block_work(w, bits_seq[h]);
            unsigned __int128 wv = le16_to_u128(w);
            prev_running = running;
            running += wv;

            char label[64];
            snprintf(label, sizeof label, "chainwork_append height %d", h);
            ck(label, store_chainwork_append(st, h, w), 1);

            u8 cached[16];
            ck("chainwork_get_tip ok", store_chainwork_get_tip(st, cached), 1);
            snprintf(label, sizeof label, "chainwork tip == expected running (h=%d)", h);
            ckm(label, le16_to_u128(cached) == running);

            u8 stored[16];
            snprintf(label, sizeof label, "chainwork_get_at(%d) ok", h);
            ck(label, store_chainwork_get_at(st, h, stored), 1);
            snprintf(label, sizeof label, "chainwork_get_at(%d) == running", h);
            ckm(label, le16_to_u128(stored) == running);

            snprintf(label, sizeof label, "chainwork strictly increasing at h=%d", h);
            ckm(label, running > prev_running);
        }

        /* re-derive independently via re-reading every persisted record and
         * summing the per-block deltas back out, to catch any off-by-one in
         * the persisted positional layout (not just the cached tip). */
        unsigned __int128 resum = 0;
        int ok_replay = 1;
        for (int h = 0; h < n; h++) {
            u8 cur[16];
            if (store_chainwork_get_at(st, h, cur) != 1) { ok_replay = 0; break; }
            unsigned __int128 cv = le16_to_u128(cur);
            if (cv <= resum && h > 0) { ok_replay = 0; break; } /* must strictly increase */
            resum = cv;
        }
        ckm("replayed persisted records strictly increasing end-to-end", ok_replay);
        ckm("final replayed cumulative == running total", resum == running);
    }

    printf("\n%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    /* best-effort cleanup */
    unlink("chainwork.dat");
    rmdir(dir);
    return failures ? 1 : 0;
}
