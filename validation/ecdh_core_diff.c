/* validation/ecdh_core_diff.c -- the constant-time k*P multiplies and the
 * BIP324 ECDH against Core v31.1's libsecp256k1, results and timing.
 * Built and run by validation/ecdh_core_diff.sh.
 *
 * 1. k*P: point_scalar_mul_glv_ct (A, the complete formulas) and
 *    point_scalar_mul_glvj_ct (B, the Jacobian port of ecmult_const) against
 *    secp256k1_ec_pubkey_tweak_mul, on edge scalars (1, 2, n-1, lambda and
 *    its neighbours, 2^128 +- 1, 2^129, (n +- 1)/2, and the k that drive the
 *    recoded s = (k + K)/2 to 0, 1 and n-1) times G, -G, lambda*G and random
 *    points, then random (k, P).
 * 2. The ECDH: our ellswift_ecdh against secp256k1_ellswift_xdh with the
 *    BIP324 hash, random secret keys and random 64-byte encodings (every
 *    64-byte string is a valid encoding), both roles.
 * 3. Timing on one pinned core, best of ROUNDS: A, B, our ECDH, Core's
 *    secp256k1_ellswift_xdh (what Core's BIP324_ECDH bench measures).
 *
 * argv[1] = random cases (default 20000), argv[2] = cpu to pin (default 2). */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <secp256k1.h>
#include <secp256k1_ellswift.h>

typedef unsigned long long u64;
extern void point_scalar_mul_glv_ct(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void point_scalar_mul_glvj_ct(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void point_scalar_mul_ct(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
extern void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);
extern void sc_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void sc_sub(u64 r[4], const u64 a[4], const u64 b[4]);
int ellswift_ecdh(unsigned char out32[32], const unsigned char their_ellswift64[64],
                  const unsigned char our_ellswift64[64], const unsigned char our_seckey32[32],
                  int initiating);
int ellswift_create(unsigned char ellswift64[64], const unsigned char seckey32[32],
                    const unsigned char* rnd, unsigned long rndlen);

static const u64 G_AFF[8] = {
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL };
static const u64 N[4] = { 0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL };
static const u64 LAMBDA[4] = { 0xDF02967C1B23BD72ULL, 0x122E22EA20816678ULL, 0xA5261C028812645AULL, 0x5363AD4CC05C30E0ULL };
static const u64 K_REC[4] = { 0xB5C2C1DCDE9798D9ULL, 0x589AE84826BA29E4ULL, 0xC2BDD6BF7C118D6BULL, 0xA4E88A7DCB13034EULL };
static const u64 ZERO[4] = { 0, 0, 0, 0 };

static long checks, failures;
#define CK(c, ...) do{ checks++; if(!(c)){ if(failures++ < 20){ printf("FAIL "); printf(__VA_ARGS__); printf("\n"); } } }while(0)
static u64 rs = 0x2545F4914F6CDD1DULL;
static u64 rnd(void){ rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static secp256k1_context* ctx;

static void be32_from(unsigned char b[32], const u64 v[4]){ for (int i = 0; i < 32; i++) b[i] = (unsigned char)(v[3 - i / 8] >> (56 - 8 * (i % 8))); }
static void from_be32(u64 v[4], const unsigned char b[32]){ for (int i = 0; i < 4; i++){ v[3 - i] = 0; for (int j = 0; j < 8; j++) v[3 - i] = (v[3 - i] << 8) | b[8 * i + j]; } }
static int lt_n(const u64 k[4]){ for (int i = 3; i >= 0; i--){ if (k[i] < N[i]) return 1; if (k[i] > N[i]) return 0; } return 0; }
static int to_aff(u64 x[4], u64 y[4], const u64 J[12]){
    if ((J[8] | J[9] | J[10] | J[11]) == 0) return 0;
    u64 zi[4], z2[4], z3[4];
    fe_inv(zi, J + 8); fe_sqr(z2, zi); fe_mul(z3, z2, zi);
    fe_mul(x, J, z2); fe_mul(y, J + 4, z3);
    return 1;
}
/* Core: k*P through secp256k1_ec_pubkey_tweak_mul; 0 if Core refuses */
static int core_mul(u64 x[4], u64 y[4], const u64 P[8], const u64 k[4]){
    unsigned char ser[65], kb[32]; secp256k1_pubkey pk; size_t len = 65;
    ser[0] = 4; be32_from(ser + 1, P); be32_from(ser + 33, P + 4); be32_from(kb, k);
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, ser, 65)) return 0;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &pk, kb)) return 0;
    secp256k1_ec_pubkey_serialize(ctx, ser, &len, &pk, SECP256K1_EC_UNCOMPRESSED);
    from_be32(x, ser + 1); from_be32(y, ser + 33);
    return 1;
}
static void check_mul(const u64 P[8], const u64 k[4], const char* what){
    u64 cx[4], cy[4], J[12], x[4], y[4];
    if (!core_mul(cx, cy, P, k)){ CK(0, "%s: Core refused k (k0=%016llx)", what, k[0]); return; }
    point_scalar_mul_glv_ct(J, P, k);
    CK(to_aff(x, y, J) && !memcmp(x, cx, 32) && !memcmp(y, cy, 32), "%s: A != Core (k0=%016llx)", what, k[0]);
    point_scalar_mul_glvj_ct(J, P, k);
    CK(to_aff(x, y, J) && !memcmp(x, cx, 32) && !memcmp(y, cy, 32), "%s: B != Core (k0=%016llx)", what, k[0]);
}
static void random_point(u64 P[8]){
    for (;;){ u64 s[4], J[12]; for (int i = 0; i < 4; i++) s[i] = rnd();
              point_scalar_mul_ct(J, G_AFF, s); if (to_aff(P, P + 4, J)) return; }
}
static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec * 1e-9; }
#define ROUNDS 7
#define BEST(iters, body) ({ double best = 1e30; for (int r_ = 0; r_ < ROUNDS; r_++){ double t0_ = now(); for (long i_ = 0; i_ < (iters); i_++){ body; } double t_ = now() - t0_; if (t_ < best) best = t_; } best / (double)(iters) * 1e9; })

int main(int argc, char** argv){
    long n = argc > 1 ? atol(argv[1]) : 20000;
    int cpu = argc > 2 ? atoi(argv[2]) : 2;
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof set, &set)) perror("sched_setaffinity");
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    printf("ecdh_core_diff: n=%ld, pinned to cpu %d, libsecp256k1 from Core v31.1\n", n, cpu);

    /* ---- 1. k*P edges ---- */
    u64 edges[24][4]; const char* names[24]; int ne = 0;
#define EDGE(nm, v) do{ memcpy(edges[ne], (v), 32); names[ne++] = (nm); }while(0)
    { u64 t[4], one[4] = { 1, 0, 0, 0 }, two[4] = { 2, 0, 0, 0 };
      EDGE("1", one); EDGE("2", two);
      u64 v3[4] = { 3, 0, 0, 0 }; EDGE("3", v3);
      sc_sub(t, ZERO, one); EDGE("n-1", t);
      sc_sub(t, ZERO, two); EDGE("n-2", t);
      EDGE("lambda", LAMBDA);
      sc_sub(t, LAMBDA, one); EDGE("lambda-1", t);
      sc_add(t, LAMBDA, one); EDGE("lambda+1", t);
      sc_sub(t, ZERO, LAMBDA); EDGE("n-lambda", t);
      u64 p128[4] = { 0, 0, 1, 0 }; EDGE("2^128", p128);
      u64 p128m[4] = { ~0ULL, ~0ULL, 0, 0 }; EDGE("2^128-1", p128m);
      u64 p128p[4] = { 1, 0, 1, 0 }; EDGE("2^128+1", p128p);
      u64 p129[4] = { 0, 0, 2, 0 }; EDGE("2^129", p129);
      u64 h[4] = { (N[0] >> 1) | (N[1] << 63), (N[1] >> 1) | (N[2] << 63), (N[2] >> 1) | (N[3] << 63), N[3] >> 1 };
      EDGE("(n-1)/2", h); sc_add(t, h, one); EDGE("(n+1)/2", t);
      /* s = (k + K)/2: k = -K gives s = 0, k = 2 - K gives s = 1, k = -K - 2 gives s = n-1 */
      sc_sub(t, ZERO, K_REC); EDGE("k: s=0", t);
      u64 t2[4]; sc_add(t2, t, two); EDGE("k: s=1", t2);
      sc_sub(t2, t, two); EDGE("k: s=n-1", t2);
      u64 ff[4] = { ~0ULL, ~0ULL, ~0ULL, 0x7FFFFFFFFFFFFFFFULL }; EDGE("2^255-1", ff); }
    u64 bases[4][8]; const char* bnames[4] = { "G", "-G", "lambda*G", "random" };
    memcpy(bases[0], G_AFF, 64);
    memcpy(bases[1], G_AFF, 32); fe_sub(bases[1] + 4, ZERO, G_AFF + 4);
    { u64 J[12]; point_scalar_mul_ct(J, G_AFF, LAMBDA); to_aff(bases[2], bases[2] + 4, J); }
    random_point(bases[3]);
    for (int b = 0; b < 4; b++) for (int e = 0; e < ne; e++){
        char what[64]; snprintf(what, sizeof what, "%s * %s", names[e], bnames[b]);
        check_mul(bases[b], edges[e], what);
    }
    /* ---- 1b. random (k, P) ---- */
    for (long i = 0; i < n; i++){
        u64 P[8], k[4]; random_point(P);
        do { for (int j = 0; j < 4; j++) k[j] = rnd(); } while (!lt_n(k) || !(k[0] | k[1] | k[2] | k[3]));
        check_mul(P, k, "random");
    }
    long mul_checks = checks;

    /* ---- 2. the ECDH, both roles ---- */
    for (long i = 0; i < n; i++){
        unsigned char sk[32], ours[64], theirs[64], a[32], b[32], rb[32];
        u64 k[4];
        do { for (int j = 0; j < 32; j++) sk[j] = (unsigned char)rnd(); from_be32(k, sk); } while (!lt_n(k) || !(k[0] | k[1] | k[2] | k[3]));
        for (int j = 0; j < 64; j++) theirs[j] = (unsigned char)rnd();
        for (int j = 0; j < 32; j++) rb[j] = (unsigned char)rnd();
        CK(ellswift_create(ours, sk, rb, 32), "ellswift_create failed");
        int init = (int)(i & 1);
        CK(ellswift_ecdh(a, theirs, ours, sk, init), "ellswift_ecdh failed");
        CK(secp256k1_ellswift_xdh(ctx, b, init ? ours : theirs, init ? theirs : ours, sk, init ? 0 : 1,
                                  secp256k1_ellswift_xdh_hash_function_bip324, NULL), "Core xdh failed");
        CK(!memcmp(a, b, 32), "ECDH %ld (%s): ours != Core", i, init ? "initiator" : "responder");
    }
    printf("k*P: %ld checks (A and B against Core, %d edge scalars x 4 bases + %ld random)\n", mul_checks, ne, n);
    printf("ECDH: %ld checks against secp256k1_ellswift_xdh\n", checks - mul_checks);

    /* ---- 3. timing ---- */
    { u64 P[8], k[4], J[12]; random_point(P);
      do { for (int j = 0; j < 4; j++) k[j] = rnd(); } while (!lt_n(k));
      unsigned char sk[32], ours[64], theirs[64], out[32];
      be32_from(sk, k); for (int j = 0; j < 64; j++) theirs[j] = (unsigned char)rnd();
      ellswift_create(ours, sk, NULL, 0);
      double a = BEST(4000, point_scalar_mul_glv_ct(J, P, k));
      double b = BEST(4000, point_scalar_mul_glvj_ct(J, P, k));
      double e = BEST(4000, ellswift_ecdh(out, theirs, ours, sk, 1));
      int okc = 1;
      double c = BEST(4000, okc &= secp256k1_ellswift_xdh(ctx, out, ours, theirs, sk, 0, secp256k1_ellswift_xdh_hash_function_bip324, NULL));
      CK(okc, "Core xdh failed while timing");
      printf("TIME A point_scalar_mul_glv_ct   %9.1f ns\n", a);
      printf("TIME B point_scalar_mul_glvj_ct  %9.1f ns   (B/A %.3f)\n", b, b / a);
      printf("TIME our ellswift_ecdh           %9.1f ns\n", e);
      printf("TIME Core secp256k1_ellswift_xdh %9.1f ns   (ours/Core %.3f)\n", c, e / c); }

    secp256k1_context_destroy(ctx);
    if (failures){ printf("\nTESTS FAILED (%ld failures)\n", failures); return 1; }
    printf("\nALL TESTS PASSED (0 failures)\n");
    return 0;
}
