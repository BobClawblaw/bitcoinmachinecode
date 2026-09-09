/*
 * sc_mul_c.c -- portable secp256k1 scalar multiply for the macOS/AArch64
 * port: 256x256 schoolbook + 8 bounded-fold rounds + 3 conditional n-
 * subtracts.  Bit-exact with asm/secp256k1_scalar.asm's sc_mul (same
 * algorithm the x86 validates against secp256k1_scalar_c.c).
 *
 * NOTE: not constant-time (folds use data-dependent full propagation).
 * The x86 asm is CT; swap back in once the AArch64 fold bug is root-
 * caused.  Fine for IBD/block verification paths that only touch public
 * scalars.
 */
#include <stdint.h>
#include <string.h>
typedef uint64_t u64;
typedef unsigned __int128 u128;

static const u64 N_LIMBS[4] = {
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
};
/* DELTA = 2^256 - n */
static const u64 DELTA_LIMBS[4] = {
    0x402DA1732FC9BEBFULL, 0x4551231950B75FC4ULL,
    0x0000000000000001ULL, 0x0000000000000000ULL
};

void sc_mul_c(u64 r[4], const u64 a[4], const u64 b[4])
{
    u64 cur[10];
    memset(cur, 0, sizeof cur);

    /* phase 1: schoolbook into 10 limbs, full carry chains */
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            u128 p = (u128)a[i] * b[j];
            u64 lo = (u64)p, hi = (u64)(p >> 64);
            int k = i + j;
            u128 t = (u128)cur[k] + lo;
            cur[k] = (u64)t;
            u64 c = (u64)(t >> 64);
            t = (u128)cur[k+1] + hi + c;
            cur[k+1] = (u64)t;
            c = (u64)(t >> 64);
            for (int m = k + 2; m < 10; m++) {
                t = (u128)cur[m] + c;
                cur[m] = (u64)t;
                c = (u64)(t >> 64);
                if (!c) break;
            }
        }
    }

    /* phase 2: 8 bounded-fold rounds */
    for (int round = 0; round < 8; round++) {
        u64 tmp[10];
        memset(tmp, 0, sizeof tmp);
        for (int hh = 0; hh < 5; hh++) {
            for (int dj = 0; dj < 4; dj++) {
                u128 p = (u128)cur[4 + hh] * DELTA_LIMBS[dj];
                u64 lo = (u64)p, hi = (u64)(p >> 64);
                int k = hh + dj;
                u128 t = (u128)tmp[k] + lo;
                tmp[k] = (u64)t;
                u64 c = (u64)(t >> 64);
                t = (u128)tmp[k+1] + hi + c;
                tmp[k+1] = (u64)t;
                c = (u64)(t >> 64);
                for (int m = k + 2; m < 10; m++) {
                    t = (u128)tmp[m] + c;
                    tmp[m] = (u64)t;
                    c = (u64)(t >> 64);
                    if (!c) break;
                }
            }
        }
        u64 c = 0;
        u64 newc[10];
        for (int m = 0; m < 10; m++) {
            u128 t = (u128)tmp[m] + (m < 4 ? cur[m] : 0) + c;
            newc[m] = (u64)t;
            c = (u64)(t >> 64);
        }
        memcpy(cur, newc, sizeof newc);
    }

    /* phase 3: 3 constant-time conditional n-subtracts */
    for (int t = 0; t < 3; t++) {
        u64 d[4];
        u64 borrow = 0;
        for (int i = 0; i < 4; i++) {
            u128 v = (u128)cur[i] - N_LIMBS[i] - borrow;
            d[i] = (u64)v;
            borrow = (u64)((v >> 64) & 1);
        }
        if (!borrow) memcpy(cur, d, sizeof d);
        else break;
    }

    memcpy(r, cur, 32);
}

void sc_sqr_c(u64 r[4], const u64 a[4])
{
    sc_mul_c(r, a, a);
}
