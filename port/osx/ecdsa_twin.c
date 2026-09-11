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
#include <stdio.h>
#include <stdlib.h>
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
/* p - n, little-endian limbs.
 * BUG FIX (bmc_osx, 2026-09-11, same session as the dead-second-branch fix
 * below): this table read 0x402DA1732FC9BEBF -- two digit transcriptions
 * off from the x86 asm's 0x402DA1722FC9BAEE (secp256k1_ecdsa.asm PMN_LIMBS,
 * verified against python p-n). The wrong bound made the second-branch gate
 * admit r in [p-n_true, p-n_twin), whose r+n overflows p -- and combined
 * with the dead branch it never mattered before; pin both here. */
static const u64 PMN_LIMBS[4] = {
    0x402DA1722FC9BAEEULL, 0x4551231950B75FC4ULL,
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
    if (getenv("BMC_ECDSADBG")) {
        fprintf(stderr, "[xmod] primary: lhs1=%016llx%016llx%016llx%016llx r=%016llx%016llx%016llx%016llx\n",
            (unsigned long long)lhs[3],(unsigned long long)lhs[2],(unsigned long long)lhs[1],(unsigned long long)lhs[0],
            (unsigned long long)r[3],(unsigned long long)r[2],(unsigned long long)r[1],(unsigned long long)r[0]);
    }

    /* second candidate only if r < p - n (then r + n < p).
     *
     * BUG FIX (bmc_osx, testnet4 h=126,683 tx=93, 2026-09-11): the first
     * cut translated the x86 chain as `if (!(r[3] < PMN[3])) return 0;` --
     * which RETURNS on r[3] == PMN[3], where the x86 falls through to the
     * next limb (jb .lt / ja .no / fall). PMN[3] is 0, so every r with
     * r[3] == 0 -- i.e. EVERY r small enough for the second branch to be
     * reachable at all -- took the early return: the r+n branch was DEAD
     * CODE and ecdsa_x_eq_mod_n rejected every valid signature whose
     * R.x (affine) landed in [n, p) instead of [0, n). A uniformly random
     * differential vector hits that band with probability (p-n)/p ~ 2^-127,
     * which is why 1200+ random records plus every harness vector agreed
     * with the x86 while real blocks did not. h=126,683 tx=93 carries a
     * CONSTRUCTED signature (sha256 of a brute-forced 16-byte preimage is a
     * valid DER signature -- r is 10 bytes, s is 15 bytes) whose R.x sits in
     * the [n, p) band; the x86 verifies it, the twin returned
     * SCRIPT_ERR_EVAL_FALSE and the block was invalidated. False-negative
     * only (the bug rejects, never accepts). */
    if (r[3] < PMN_LIMBS[3]) goto lt;
    if (r[3] > PMN_LIMBS[3]) return 0;
    if (r[2] < PMN_LIMBS[2]) goto lt;
    if (r[2] > PMN_LIMBS[2]) return 0;
    if (r[1] < PMN_LIMBS[1]) goto lt;
    if (r[1] > PMN_LIMBS[1]) return 0;
    if (r[0] >= PMN_LIMBS[0]) return 0;
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
    if (getenv("BMC_ECDSADBG")) {
        fprintf(stderr, "[xmod] X   =%016llx%016llx%016llx%016llx\n",
            (unsigned long long)X[3],(unsigned long long)X[2],(unsigned long long)X[1],(unsigned long long)X[0]);
        fprintf(stderr, "[xmod] lhs2=%016llx%016llx%016llx%016llx cand=%016llx%016llx%016llx%016llx\n",
            (unsigned long long)lhs[3],(unsigned long long)lhs[2],(unsigned long long)lhs[1],(unsigned long long)lhs[0],
            (unsigned long long)cand[3],(unsigned long long)cand[2],(unsigned long long)cand[1],(unsigned long long)cand[0]);
    }
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
