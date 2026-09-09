/* ============================================================================
 * ecdsa_twin.c -- ECDSA verify for the macOS/AArch64 port.  Functional twin
 * of asm/secp256k1_ecdsa.asm (branch bmc_osx).
 *
 *   int  ecdsa_verify(const u64 z[4], const u64 r[4], const u64 s[4],
 *                     const u64 Qx[4], const u64 Qy[4]);
 *   int  ecdsa_x_eq_mod_n(const u64 r[4], const u64 X[4], const u64 Z[4]);
 *
 * Transcribed instruction-for-instruction from the x86 listing so the slot
 * flow (which decides WHERE each intermediate lives) matches exactly.
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <string.h>

typedef uint64_t u64;
typedef unsigned __int128 u128;

void fe_sqr(u64 r[4], const u64 a[4]);
void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);
int  sc_inv_var(u64 r[4], const u64 a[4]);
void sc_mul(u64 r[4], const u64 a[4], const u64 b[4]);
void point_scalar_mul_fixed(u64 r[12], const u64 k[4]);
void point_scalar_mul_glv(u64 r[12], const u64 xy[8], const u64 k[4]);
void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
void point_add(u64 r[12], const u64 p[12], const u64 q[12]);
int  bmc_ecdsa_glv_enabled(void);

/* n (group order), little-endian limbs */
static const u64 N_LIMBS[4] = {
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
};
/* p - n, little-endian limbs */
static const u64 PMN_LIMBS[4] = {
    0x402DA1732FC9BEBFULL, 0x4551231950B75FC4ULL,
    0x0000000000000001ULL, 0x0000000000000000ULL
};

/* 1 iff x > 0 and x < n (limb-by-limb big-endian compare, x86-faithful). */
static int in_range(const u64 x[4])
{
    if ((x[0] | x[1] | x[2] | x[3]) == 0) return 0;
    if (x[3] != N_LIMBS[3]) return x[3] < N_LIMBS[3];
    if (x[2] != N_LIMBS[2]) return x[2] < N_LIMBS[2];
    if (x[1] != N_LIMBS[1]) return x[1] < N_LIMBS[1];
    return x[0] < N_LIMBS[0];
}

int ecdsa_x_eq_mod_n(const u64 r[4], const u64 X[4], const u64 Z[4])
{
    u64 t[4], lhs[4], cand[4];

    fe_sqr(t, Z);                   /* t = Z^2 */
    fe_mul(lhs, r, t);              /* lhs = r*Z^2 (mod p) */

    /* primary: lhs == X limb-for-limb */
    if (lhs[0] == X[0] && lhs[1] == X[1] &&
        lhs[2] == X[2] && lhs[3] == X[3])
        return 1;

    /* second candidate only if r < p - n (then r + n < p) */
    if (!(r[3] < PMN_LIMBS[3])) return 0;   /* x86: jb .lt / ja .no */
    if (r[3] == PMN_LIMBS[3]) {
        if (r[2] < PMN_LIMBS[2]) goto lt;
        if (r[2] > PMN_LIMBS[2]) return 0;
        if (r[1] < PMN_LIMBS[1]) goto lt;
        if (r[1] > PMN_LIMBS[1]) return 0;
        if (r[0] >= PMN_LIMBS[0]) return 0;
    }
lt:
    /* cand = r + n (mod 2^256), plain adc chain */
    unsigned carry = 0;
    for (int i = 0; i < 4; i++) {
        u128 s = (u128)r[i] + N_LIMBS[i] + carry;
        cand[i] = (u64)s;
        carry = (unsigned)(s >> 64);
    }
    fe_mul(lhs, cand, t);           /* lhs = (r+n)*Z^2 (mod p) */
    if (lhs[0] == X[0] && lhs[1] == X[1] &&
        lhs[2] == X[2] && lhs[3] == X[3])
        return 1;
    return 0;
}

int ecdsa_verify(const u64 z[4], const u64 r[4], const u64 s[4],
                 const u64 Qx[4], const u64 Qy[4])
{
    u64 sbuf[4], w[4], u1[4], u2[4];
    u64 Q[8];
    u64 P1[12], P2[12], P[12];

    memcpy(sbuf, s, 32);
    if (!in_range(sbuf)) return 0;
    if (!in_range(r))    return 0;

    if (!sc_inv_var(w, sbuf)) return 0;   /* w = s^-1 mod n; s==0 rejected */

    sc_mul(u1, z, w);               /* u1 = z*w */
    sc_mul(u2, r, w);               /* u2 = r*w */

    memcpy(Q + 0, Qx, 32);
    memcpy(Q + 4, Qy, 32);

    point_scalar_mul_fixed(P1, u1); /* u1*G  (Jacobian) */

    if (bmc_ecdsa_glv_enabled()) {
        point_scalar_mul_glv(P2, Q, u2);
    } else {
        point_scalar_mul(P2, Q, u2);
    }

    point_add(P, P1, P2);

    if ((P[8] | P[9] | P[10] | P[11]) == 0) return 0;   /* infinity */

    return ecdsa_x_eq_mod_n(r, P, P + 8);
}
