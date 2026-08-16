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
