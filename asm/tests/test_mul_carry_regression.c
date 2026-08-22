/* test_mul_carry_regression.c -- two lost-carry bugs in the 256-bit modular
 * multiplies, found 2026-08-21 by the PERF_SCOPE 4.2 structured-input probes.
 *
 *   sc_mul (secp256k1_scalar.asm): the schoolbook MULACC macro propagated a
 *     partial-product carry only two limbs; when the third limb was exactly
 *     0xFFFFFFFFFFFFFFFF the carry out was dropped -- a lost 2^256 == DELTA
 *     (mod n). Deterministic on structured inputs: sc_inv(6), sc_inv(n-2),
 *     sc_inv(n-k) for small k were all wrong.
 *   fe_mul (secp256k1_fe.asm): Phase-2 fold 2 dropped the carry out of limb 3
 *     ("result < 2^256" was false) -- a lost 2^256 == C (mod p). fe_inv(p-k)
 *     for small k was wrong.
 *
 * Both are ~2^-64 / ~2^-190 events on random operands, which is why 20k-300k
 * random-pair differentials never saw them: only exact vectors and
 * structured chains do. Expected values are from Python big-int arithmetic.
 */
#include <stdio.h>
#include <string.h>
typedef unsigned long long u64;
extern void sc_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void sc_inv(u64 r[4], const u64 a[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);

static int failures = 0;
static void ck(const char* lbl, const u64 got[4], const u64 exp[4]){
    if (memcmp(got, exp, 32) == 0) printf("PASS %s\n", lbl);
    else { printf("FAIL %s\n  got %016llx %016llx %016llx %016llx\n  exp %016llx %016llx %016llx %016llx\n",
           lbl, got[3],got[2],got[1],got[0], exp[3],exp[2],exp[1],exp[0]); failures++; }
}
static const u64 N[4] = {0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
static const u64 P[4] = {0xFFFFFFFEFFFFFC2FULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL};
static const u64 ONE[4] = {1,0,0,0};

int main(void){
    u64 r[4];
    /* --- sc_mul: the exact squaring from the sc_inv(6) Fermat chain (step 447) --- */
    u64 sa[4]  = {0x9ff8651778090ae0ULL, 0x74727a26728c1ab4ULL, 0xaaaaaaaaaaaaaaaaULL, 0x2aaaaaaaaaaaaaaaULL};
    u64 saa[4] = {0xba8d8384a177ff06ULL, 0xbe617ee8b7191109ULL, 0x38e38e38e38e38e2ULL, 0xa38e38e38e38e38eULL};
    sc_mul(r, sa, sa); ck("sc_mul lost-carry vector (a*a, a from sc_inv(6) chain)", r, saa);
    u64 six[4] = {6,0,0,0};
    u64 inv6[4]  = {0x1fd9f975582d3661ULL, 0x463c62c03cbc8587ULL, 0x5555555555555554ULL, 0xd555555555555555ULL};
    sc_inv(r, six); ck("sc_inv(6)", r, inv6);
    u64 nm2[4] = {N[0]-2, N[1], N[2], N[3]};
    u64 invnm2[4] = {0xdfe92f46681b20a0ULL, 0x5d576e7357a4501dULL, 0xffffffffffffffffULL, 0x7fffffffffffffffULL};
    sc_inv(r, nm2); ck("sc_inv(n-2)", r, invnm2);
    /* --- fe_mul: squaring p - 2^31 used to lose the fold-2 carry --- */
    u64 fa[4]  = {0xfffffffe7ffffc2fULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL};
    u64 faa[4] = {0x4000000000000000ULL, 0, 0, 0};
    fe_mul(r, fa, fa); ck("fe_mul lost-carry vector ((p-2^31)^2 = 2^62)", r, faa);
    u64 pm2[4] = {P[0]-2, P[1], P[2], P[3]};
    u64 invpm2[4] = {0xffffffff7ffffe17ULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0x7fffffffffffffffULL};
    fe_inv(r, pm2); ck("fe_inv(p-2)", r, invpm2);
    u64 fe6inv[4] = {0x555555547ffffcd2ULL, 0x5555555555555555ULL, 0x5555555555555555ULL, 0xd555555555555555ULL};
    fe_inv(r, six); ck("fe_inv(6)", r, fe6inv);
    /* --- structured sweep: a * inv(a) == 1 for k and modulus-k, k = 1..256 --- */
    long bad = 0;
    for (u64 k = 1; k <= 256; k++){
        u64 a[4] = {k,0,0,0}, b[4] = {N[0]-k, N[1], N[2], N[3]}, c[4] = {P[0]-k, P[1], P[2], P[3]}, t[4];
        sc_inv(r, a); sc_mul(t, a, r); if (memcmp(t, ONE, 32)) bad++;
        sc_inv(r, b); sc_mul(t, b, r); if (memcmp(t, ONE, 32)) bad++;
        fe_inv(r, a); fe_mul(t, a, r); if (memcmp(t, ONE, 32)) bad++;
        fe_inv(r, c); fe_mul(t, c, r); if (memcmp(t, ONE, 32)) bad++;
    }
    if (bad) { printf("FAIL structured sweep: %ld of 1024 a*inv(a) != 1\n", bad); failures++; }
    else printf("PASS structured sweep: 1024 inverses (k, n-k, p-k for k=1..256) all satisfy a*inv(a)==1\n");
    printf("\n%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
