/*
 * secp256k1_scalar_c.c -- BATCH modular inversion mod n (scalar field order).
 *
 * sc_mul (constant-time 256x256 schoolbook multiply + bounded-fold reduction),
 * which this module used to implement, is now a NATIVE assembly implementation
 * in secp256k1_scalar.asm (the fast schoolbook method, not the abandoned slow
 * bit-by-bit double-and-add).  This closes the last "crypto in C" gap: all
 * mod-n scalar crypto now lives in assembly.
 *
 * This module keeps only:
 *   - sc_inv_c     : a^(n-2) mod n (Fermat, fixed 256-iteration loop), a local
 *                    copy so the batch helper avoids an asm<->C round trip.
 *   - sc_inv_batch : Montgomery batch inversion (1 inverse + ~3n squarings),
 *                    the dominant ECDSA verification cost for a block of sigs.
 *
 * Both glue the native asm primitives (sc_mul / sc_inv from
 * secp256k1_scalar.asm).
 */
#include <stdint.h>
#include <string.h>

typedef uint64_t u64;
typedef uint8_t u8;
typedef unsigned __int128 u128;

/* native constant-time modular multiply (secp256k1_scalar.asm) */
extern void sc_mul(u64 out[4], const u64 a[4], const u64 b[4]);


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
