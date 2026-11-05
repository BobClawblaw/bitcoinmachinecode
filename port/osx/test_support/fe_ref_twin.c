/* port/osx/test_support/fe_ref_twin.c -- the Mac stand-in for tests/fe_ref.asm,
 * the FROZEN pre-PERF_SCOPE-5 x86 field code that tests/test_fe_repr (and the
 * other *_repr / fe_inline tests) diff against. Test-only: it lives outside
 * the port/osx C twins so build_daemon.sh never links it into a daemon.
 *
 * What the tests need from it, and how each is met:
 *   fe_add_ref / fe_sub_ref must be BIT-IDENTICAL to the frozen asm on every
 *     input pair in [0, 2^256)^2, canonical or not (test_fe_repr check 4).
 *     They are transcriptions of its exact steps:
 *       add: s = a + b mod 2^256; if the top limb carried, s += C
 *            (C = 2^256 - p = 2^32 + 977, carried through, final carry
 *            dropped); then s -= p if s >= p.
 *       sub: d = a - b mod 2^256; if it borrowed, d += p mod 2^256.
 *   fe_mul_ref / fe_sqr_ref / fe_inv_ref return the CANONICAL value
 *     (a*b, a^2, a^(p-2) mod p) for any 256-bit input, as the frozen asm
 *     does, so any correct implementation is bit-identical to it. This one
 *     is written independently of port/osx/fe_twin.c -- a schoolbook
 *     512-bit product and plain folds over unsigned __int128, sharing no
 *     code with the implementation under test -- which is what a
 *     differential reference is for.
 */
#include <stdint.h>

typedef uint64_t u64;
typedef unsigned __int128 u128;

static const u64 P[4] = { 0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
                          0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL };
#define C_FOLD 0x1000003D1ULL

/* r = x - p if x >= p, else x (x < 2^256) */
static void cond_sub_p(u64 r[4], const u64 x[4]){
    u64 t[4]; u128 b = 0;
    for (int i = 0; i < 4; i++){
        u128 d = (u128)x[i] - P[i] - (u64)b;
        t[i] = (u64)d; b = (d >> 64) ? 1 : 0;
    }
    for (int i = 0; i < 4; i++) r[i] = b ? x[i] : t[i];
}

void fe_add_ref(u64 r[4], const u64 a[4], const u64 b[4]){
    u64 s[4]; u128 c = 0;
    for (int i = 0; i < 4; i++){ c += (u128)a[i] + b[i]; s[i] = (u64)c; c >>= 64; }
    u128 f = c ? C_FOLD : 0;                       /* the 257th bit folds in as C */
    for (int i = 0; i < 4; i++){ f += s[i]; s[i] = (u64)f; f >>= 64; }   /* final carry dropped, as the asm's adc chain */
    cond_sub_p(r, s);
}

void fe_sub_ref(u64 r[4], const u64 a[4], const u64 b[4]){
    u64 d[4]; u128 bw = 0;
    for (int i = 0; i < 4; i++){
        u128 x = (u128)a[i] - b[i] - (u64)bw;
        d[i] = (u64)x; bw = (x >> 64) ? 1 : 0;
    }
    u128 c = 0;
    for (int i = 0; i < 4; i++){ c += (u128)d[i] + (bw ? P[i] : 0); r[i] = (u64)c; c >>= 64; }   /* mod 2^256 */
}

/* a*b mod p, canonical, for any a, b < 2^256 */
void fe_mul_ref(u64 r[4], const u64 a[4], const u64 b[4]){
    u64 t[8] = {0};
    for (int i = 0; i < 4; i++){                    /* schoolbook 256x256 -> 512 */
        u128 c = 0;
        for (int j = 0; j < 4; j++){
            c += (u128)a[i] * b[j] + t[i + j];
            t[i + j] = (u64)c; c >>= 64;
        }
        t[i + 4] = (u64)c;
    }
    /* fold 1: t0 + t1*C -> five limbs (the fifth < 2^34) */
    u64 f[5]; u128 c = 0;
    for (int i = 0; i < 4; i++){ c += (u128)t[i + 4] * C_FOLD + t[i]; f[i] = (u64)c; c >>= 64; }
    f[4] = (u64)c;
    /* fold 2: f0..3 + f4*C, and whatever carries out of that folds once more
     * (after it the value is < 2^256 and, as p > 2^255, < 2p) */
    u128 top = (u128)f[4] * C_FOLD;
    for (;;){
        u128 k = top; top = 0;
        for (int i = 0; i < 4; i++){ k += f[i]; f[i] = (u64)k; k >>= 64; }
        if (!k) break;
        top = (u128)k * C_FOLD;
    }
    cond_sub_p(r, f);
}

void fe_sqr_ref(u64 r[4], const u64 a[4]){ fe_mul_ref(r, a, a); }

/* a^(p-2) mod p (Fermat); 0 -> 0, as the frozen asm */
void fe_inv_ref(u64 r[4], const u64 a[4]){
    static const u64 E[4] = { 0xFFFFFFFEFFFFFC2DULL, 0xFFFFFFFFFFFFFFFFULL,
                              0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL };
    u64 acc[4] = { 1, 0, 0, 0 }, base[4] = { a[0], a[1], a[2], a[3] };
    for (int i = 0; i < 256; i++){
        if ((E[i >> 6] >> (i & 63)) & 1) fe_mul_ref(acc, acc, base);
        fe_sqr_ref(base, base);
    }
    for (int i = 0; i < 4; i++) r[i] = acc[i];
}
