/* test_fe_pow_sqrt.c -- fe_pow_sqrt (secp256k1_fe.asm, an addition chain for
 * a^((p+1)/4)) against fe_pow(a, (p+1)/4) (bitcoin_pubkey.asm, the
 * square-and-multiply loop pubkey_parse used until 2026-09-27), byte for byte.
 *
 * fe_pow walks the exponent's bits; the chain is a fixed sequence of 253
 * squarings and 13 multiplies. The chain's exponent was checked in Python
 * before any asm existed:
 *   x = 2^223-1; x = (x<<23) + 2^22-1; x = (x<<6) + 3; x <<= 2  ==  (p+1)/4.
 * This test is the check that the asm computes it.
 *
 * Inputs: edge values (0, 1, 2, 7, p-1, p-2, 2^255, single bits, all-ones
 * limbs below p), then random field elements, then x^3+7 for random x -- the
 * exact value pubkey_parse feeds it. For every input the root is also checked
 * the way pubkey_parse checks it: r^2 == a exactly when a is a square, and
 * r^2 == -a otherwise (p == 3 mod 4), so the two outcomes must split about
 * evenly over random inputs.
 *
 * argv[1] = seed (default fixed), argv[2] = random count (default 200000). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;

extern void fe_pow_sqrt(u64 r[4], const u64 a[4]);
extern void fe_pow(u64 r[4], const u64 base[4], const u64 exp[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);

static const u64 P[4]   = {0xFFFFFFFEFFFFFC2FULL, ~0ULL, ~0ULL, ~0ULL};
static const u64 EXP[4] = {0xFFFFFFFFBFFFFF0CULL, ~0ULL, ~0ULL, 0x3FFFFFFFFFFFFFFFULL};
static const u64 ZERO[4] = {0,0,0,0};

static long failures, squares, nonsquares;
#define CK(c, ...) do{ if(!(c)){ if(failures++ < 10){ printf("FAIL "); printf(__VA_ARGS__); printf("\n"); } } }while(0)

static u64 rs;
static u64 rnd(void){ rs^=rs<<13; rs^=rs>>7; rs^=rs<<17; return rs; }
static int lt_p(const u64 a[4]){ for(int i=3;i>=0;i--){ if(a[i]<P[i]) return 1; if(a[i]>P[i]) return 0; } return 0; }
static void rnd_fe(u64 a[4]){ do { for(int i=0;i<4;i++) a[i]=rnd(); } while(!lt_p(a)); }

static void check(const u64 a[4], const char* what){
    u64 chain[4], ref[4], sq[4], neg[4];
    memset(chain, 0xAA, 32);
    fe_pow_sqrt(chain, a);
    fe_pow(ref, a, EXP);
    CK(!memcmp(chain, ref, 32), "%s: a=%016llx..%016llx chain=%016llx.. fe_pow=%016llx..",
       what, a[3], a[0], chain[3], ref[3]);
    fe_sqr(sq, chain);
    fe_sub(neg, ZERO, a);
    if (!memcmp(sq, a, 32)) squares++;
    else { CK(!memcmp(sq, neg, 32), "%s: r^2 is neither a nor -a", what); nonsquares++; }
}

int main(int argc, char** argv){
    rs = argc > 1 ? strtoull(argv[1], 0, 0) : 0xC0FFEE1234567891ULL;
    long n = argc > 2 ? atol(argv[2]) : 200000;
    printf("seed=0x%016llx n=%ld\n", rs, n);

    u64 a[4];
    u64 edges[][4] = {
        {0,0,0,0}, {1,0,0,0}, {2,0,0,0}, {7,0,0,0}, {4,0,0,0}, {9,0,0,0},
        {P[0]-1, P[1], P[2], P[3]}, {P[0]-2, P[1], P[2], P[3]},
        {0,0,0,1ULL<<63}, {0,0,1,0}, {0,1,0,0}, {~0ULL,0,0,0},
        {~0ULL,~0ULL,~0ULL,0x7FFFFFFFFFFFFFFFULL}, {0xFFFFFFFEFFFFFC2EULL, ~0ULL, ~0ULL, ~0ULL},
    };
    long ne = sizeof edges / sizeof edges[0];
    for (long i = 0; i < ne; i++) check(edges[i], "edge");
    for (int b = 0; b < 256; b++){ memset(a, 0, 32); a[b>>6] = 1ULL << (b&63); if (lt_p(a)) check(a, "bit"); }

    /* aliasing: r == a */
    rnd_fe(a); { u64 r[4], x[4]; memcpy(x, a, 32); fe_pow(r, a, EXP); fe_pow_sqrt(x, x);
        CK(!memcmp(x, r, 32), "alias: fe_pow_sqrt(a, a) differs"); }

    long s0 = squares, n0 = nonsquares;
    for (long i = 0; i < n; i++){ rnd_fe(a); check(a, "random"); }
    long rs_sq = squares - s0, rs_ns = nonsquares - n0;
    CK(rs_sq > n*45/100 && rs_ns > n*45/100, "random: %ld squares vs %ld non-squares, expected ~50/50", rs_sq, rs_ns);

    for (long i = 0; i < n/4; i++){
        u64 x[4], x2[4], x3[4], t[4]; const u64 seven[4] = {7,0,0,0};
        rnd_fe(x); fe_sqr(x2, x); fe_mul(x3, x2, x); fe_add(t, x3, seven);
        check(t, "x^3+7");
    }

    printf("fe_pow_sqrt vs fe_pow: %ld edge + 256 bit + %ld random + %ld x^3+7 inputs; %ld squares, %ld non-squares\n",
           ne, n, n/4, squares, nonsquares);
    if (failures){ printf("\nTESTS FAILED (%ld failures)\n", failures); return 1; }
    printf("\nALL TESTS PASSED (0 failures)\n");
    return 0;
}
