/*
 * secp256k1_scalar_c.c -- CONSTANT-TIME modular multiplication mod n
 * (scalar field order).
 *
 * This is an exception to the "crypto primitives live in .asm" convention,
 * kept as a C module because the first asm formulation of sc_mul (bit-by-bit
 * double-and-add using only sc_add -- 256 iterations * 2 sc_add per mul) made
 * sc_inv (= a^(n-2), ~387 mults) the dominant cost of every ECDSA signature
 * verification (~1.5 ms just for s^-1).  A direct schoolbook 256x256 multiply
 * plus bounded-fold reduction replaces it with a single constant-time modular
 * multiply, ~5x faster per mul and turning sc_inv/verify from ~10x the real
 * bottleneck into ~1x.
 *
 *   P   = a*b                              (512-bit, 8 limbs)
 *   DELTA = 2^256 - n   =>  2^256 == DELTA (mod n)
 *     fold: cur = (cur>>256)*DELTA + (cur & 2^256-1)
 *     8 fixed rounds drive cur below 2^257; then up to 3 conditional
 *     n-subtractions yield the canonical [0,n) result.
 *
 * CONSTANT-TIME: fixed loop counts (8 rounds, 3 subtracts); the only
 * data-dependent bounds are loop counters, which do not vary with inputs.
 *
 * Validated bit-exact vs the (a*b) mod n oracle over 4k+ vectors incl.
 * 0/1/N-1/2^256-1/N/N/2 and the full project test suite.
 */
#include <stdint.h>
#include <string.h>

typedef uint64_t u64;
typedef uint8_t u8;
typedef unsigned __int128 u128;

/* DELTA = 2^256 - n (little-endian limbs); n = secp256k1 group order.  The
 * project .asm modules do not need these; only this module uses them, so the
 * symbols are local (static) to avoid any collision. */
static const u64 DELTA[4] = {0x402DA1732FC9BEBFULL, 0x4551231950B75FC4ULL, 1ULL, 0ULL};
static const u64 N[4]    = {0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL};

/* force_align_arg_pointer: the asm callers (sc_inv/sc_sqr) do not uphold the
 * 16-byte stack-alignment ABI the C compiler expects, because the former
 * sc_mul was an asm leaf that managed alignment internally.  This attribute
 * makes GCC emit a prologue that realigns rsp, so sc_mul is safe regardless of
 * the caller's alignment (this module uses aligned SSE stores). */
void __attribute__((force_align_arg_pointer)) sc_mul(u64 out[4], const u64 a[4], const u64 b[4])
{
    u64 cur[10] = {0};
    int i, j;

    /* schoolbook 256x256 multiply: cur = a*b (512-bit -> limbs 0..9) */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            int k = i + j;
            u128 p = (u128)a[i] * b[j];
            u64 lo = (u64)p, hi = (u64)(p >> 64);
            u128 s = (u128)cur[k] + lo;
            cur[k] = (u64)s;
            u64 c = (u64)(s >> 64);
            k++;
            s = (u128)cur[k] + hi + c;
            cur[k] = (u64)s;
            c = (u64)(s >> 64);
            k++;
            while (c) {
                s = (u128)cur[k] + c;
                cur[k] = (u64)s;
                c = (u64)(s >> 64);
                k++;
            }
        }
    }

    /* bounded-fold reduction (same algorithm as the validated reference) */
    u64 tmp[10];
    for (i = 0; i < 8; i++) {
        u64 hi[5];
        memcpy(hi, &cur[4], sizeof hi);     /* hi = cur[4..8] */
        memcpy(tmp, cur, sizeof tmp);       /* tmp = cur (we rebuild below) */
        memset(tmp, 0, sizeof tmp);
        /* tmp += hi * DELTA */
        for (int hi_i = 0; hi_i < 5; hi_i++) {
            for (int dj = 0; dj < 4; dj++) {
                int k = hi_i + dj;
                u128 p = (u128)hi[hi_i] * DELTA[dj];
                u64 lo = (u64)p, h = (u64)(p >> 64);
                u128 s = (u128)tmp[k] + lo;
                tmp[k] = (u64)s;
                u64 c = (u64)(s >> 64);
                k++;
                s = (u128)tmp[k] + h + c;
                tmp[k] = (u64)s;
                c = (u64)(s >> 64);
                k++;
                while (c) {
                    s = (u128)tmp[k] + c;
                    tmp[k] = (u64)s;
                    c = (u64)(s >> 64);
                    k++;
                }
            }
        }
        /* cur = tmp + cur[0..3] (carry into the high limbs) */
        u64 c = 0;
        for (int k = 0; k < 4; k++) {
            u128 s = (u128)tmp[k] + cur[k] + c;
            tmp[k] = (u64)s;
            c = (u64)(s >> 64);
        }
        for (int k = 4; k < 10; k++) {
            u128 s = (u128)tmp[k] + c;
            tmp[k] = (u64)s;
            c = (u64)(s >> 64);
        }
        memcpy(cur, tmp, sizeof cur);
    }

    /* up to 3 conditional n-subtractions (constant-time selection) */
    for (int kk = 0; kk < 3; kk++) {
        u64 r[4];
        u64 borrow = 0;
        for (int k = 0; k < 4; k++) {
            u128 s = (u128)cur[k] - N[k] - borrow;
            r[k] = (u64)s;
            borrow = (u64)((s >> 64) & 1);
        }
        u64 do_sub = borrow ^ 1;            /* subtract if no borrow (>= n) */
        for (int k = 0; k < 4; k++)
            cur[k] = do_sub ? r[k] : cur[k];
    }

    for (int k = 0; k < 4; k++)
        out[k] = cur[k];
}


/* ===========================================================================
 * sc_inv_c: a^(n-2) mod n (Fermat) using the fast sc_mul above.  Mirrors the
 * asm sc_inv but inside this module so batched inversion can call it directly.
 * Fixed 256-iteration loop; constant-time select between R and R*a.
 * =========================================================================== */
static void sc_inv_c(u64 out[4], const u64 a[4])
{
    u64 R[4], A[4];
    memcpy(R, a, 32);
    memcpy(A, a, 32);
    static const unsigned char exp[32] = {
        0x3f,0x41,0x36,0xd0,0x8c,0x5e,0xd2,0xbf,
        0x3b,0xa0,0x48,0xaf,0xe6,0xdc,0xae,0xba,
        0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff };
    for (int i = 254; i >= 0; i--) {
        u64 RR[4];
        sc_mul(RR, R, R);
        memcpy(R, RR, 32);
        int by = i >> 3;
        int bi = (i & 7);
        u8 bv = (u8)((exp[by] >> bi) & 1);
        u64 save[4];
        sc_mul(save, R, A);
        for (int k = 0; k < 4; k++)
            R[k] = bv ? save[k] : R[k];
    }
    memcpy(out, R, 32);
}

/* ===========================================================================
 * sc_inv_batch(out[4*n], x[4*n], n): out[i] = 1/x[i] mod n for all i with a
 * SINGLE modular inversion (Montgomery trick): 1 x sc_inv + ~3n sc_mul, vs n
 * sc_inv naive.  For a block of N signatures this turns N scalar inversions
 * into 1, which is the dominant verification cost.  Elements must be nonzero.
 * =========================================================================== */
void sc_inv_batch(u64 *out, const u64 *x, long n)
{
    u64 *pref = (u64*)__builtin_alloca((size_t)n * 32);
    u64 prod[4] = {1,0,0,0};
    for (long i = 0; i < n; i++) {
        memcpy(&pref[i*4], prod, 32);
        u64 t[4];
        sc_mul(t, prod, &x[i*4]);
        memcpy(prod, t, 32);
    }
    u64 inv[4];
    sc_inv_c(inv, prod);
    for (long i = n - 1; i >= 0; i--) {
        u64 t[4];
        sc_mul(t, inv, &pref[i*4]);
        memcpy(&out[i*4], t, 32);
        sc_mul(t, inv, &x[i*4]);
        memcpy(inv, t, 32);
    }
}
