/* ============================================================================
 * point_ct_twin.c -- constant-time point layer for the macOS/AArch64 port.
 * Functional twin of asm/secp256k1_point_ct.asm (branch bmc_osx).
 *
 *   pointh_add(r, p, q)           -- RCB Algorithm 7 (complete, branch-free)
 *   pointh_double(r, p)           -- complete doubling, a=0 (RCB Alg 9 shape)
 *   point_scalar_mul_ct(r, xy, k) -- fixed 256-round ladder, cmov select
 *
 * Transcribed step-for-step from the x86 asm.  fe ops from fe_twin.c.
 * The scalar_mul_ct emit stage preserves the x86's exact T mapping:
 *   out.x = Z!=0 ? X*Z : 1 ; out.y = Z!=0 ? Y*Z^2 : 1 ; out.z = Z.
 * (Not affine: the contract callers -- bip32_ckdpub/bip340_sign -- consume.)
 * ============================================================================ */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
void b39dbg_dump(const char* tag, const unsigned long long* v, int n) {
    fprintf(stderr, "%s=", tag);
    for (int i=n-1;i>=0;i--) fprintf(stderr, "%016llx", v[i]);
    fprintf(stderr, "\n");
}
typedef uint64_t u64;

void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
void fe_sqr(u64 r[4], const u64 a[4]);
void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);

static const u64 B3[4] = {21, 0, 0, 0};   /* b3 = 3*b, b = 7 */

static u64 fe_is_zero_ct(const u64 a[4]) {
    return ((a[0]|a[1]|a[2]|a[3]) == 0) ? 1u : 0u;
}


static void fe_dbl2(u64 r[4], const u64 a[4]) {
    u64 t[4];
    fe_add(t, a, a);
    memcpy(r, t, 32);
}
static void fe_tri(u64 r[4], const u64 a[4]) {
    u64 t[4];
    fe_add(t, a, a);
    fe_add(t, t, a);
    memcpy(r, t, 32);
}

/* ----------------------------------------------------------------------------
 * pointh_add(r, p, q) -- complete addition, a=0.  Branch-free.
 * r may alias p and/or q (inputs read fully before any output write).
 * -------------------------------------------------------------------------- */
void pointh_add(u64 r[12], const u64 p[12], const u64 q[12])
{
    u64 t0[4], t1[4], t2[4], t3[4], t4[4], X3[4], Y3[4], Z3[4];

    fe_mul(t0, p+0, q+0);           /* 1.  t0 = X1*X2 */
    fe_mul(t1, p+4, q+4);           /* 2.  t1 = Y1*Y2 */
    fe_mul(t2, p+8, q+8);           /* 3.  t2 = Z1*Z2 */
    fe_add(t3, p+0, p+4);           /* 4.  t3 = X1+Y1 */
    fe_add(t4, q+0, q+4);           /* 5.  t4 = X2+Y2 */
    fe_mul(t3, t3, t4);             /* 6.  t3 = t3*t4 */
    fe_sub(t3, t3, t0);             /* 7.  t3 -= t0 */
    fe_sub(t3, t3, t1);             /* 8.  t3 -= t1 */
    fe_add(t4, p+4, p+8);           /* 9.  t4 = Y1+Z1 */
    fe_add(X3, q+4, q+8);           /* 10. X3 = Y2+Z2 */
    fe_mul(t4, t4, X3);             /* 11. t4 = t4*X3 */
    fe_sub(t4, t4, t1);             /* 12. t4 -= t1 */
    fe_sub(t4, t4, t2);             /* 13. t4 -= t2 */
    fe_add(X3, p+0, p+8);           /* 14. X3 = X1+Z1 */
    fe_add(Y3, q+0, q+8);           /* 15. Y3 = X2+Z2 */
    fe_mul(X3, X3, Y3);             /* 16. X3 = X3*Y3 */
    /* 17+18: the x86 stores the X3-t0-t2 chain into the Y3 SLOT (-0x110);
     * step 24 then scales THAT value by b3.  Slot-faithful transcription. */
    fe_sub(Y3, X3, t0);             /* 17+18. Y3slot = X3 - t0 - t2 */
    fe_sub(Y3, Y3, t2);
    fe_tri(t0, t0);                 /* 19+20. t0 = 3*t0 */
    fe_mul(t2, B3, t2);             /* 21. t2 = b3*t2 */
    fe_add(Z3, t1, t2);             /* 22. Z3 = t1+t2 */
    fe_sub(t1, t1, t2);             /* 23. t1 = t1-t2 */
    fe_mul(Y3, B3, Y3);             /* 24. Y3 = b3*Y3slot */
    fe_mul(X3, t4, Y3);             /* 25. X3 = t4*Y3 */
    fe_mul(t2, t3, t1);             /* 26. t2 = t3*t1 */
    fe_sub(X3, t2, X3);             /* 27. X3 = t2-X3 */
    fe_mul(Y3, Y3, t0);             /* 28. Y3 = Y3*t0 */
    fe_mul(t1, t1, Z3);             /* 29. t1 = t1*Z3 */
    fe_add(Y3, t1, Y3);             /* 30. Y3 = t1+Y3 */
    fe_mul(t0, t0, t3);             /* 31. t0 = t0*t3 */
    fe_mul(Z3, Z3, t4);             /* 32. Z3 = Z3*t4 */
    fe_add(Z3, Z3, t0);             /* 33. Z3 = Z3+t0 */

    memcpy(r+0, X3, 32);
    memcpy(r+4, Y3, 32);
    memcpy(r+8, Z3, 32);
}

/* ----------------------------------------------------------------------------
 * pointh_double(r, p) -- complete doubling, a=0.  Branch-free.
 * -------------------------------------------------------------------------- */
void pointh_double(u64 r[12], const u64 p[12])
{
    u64 t0[4], t1[4], t2[4], X3[4], Y3[4], Z3[4];

    fe_sqr(t0, p+4);                /* 1.  t0 = Y1^2 */
    fe_dbl2(Z3, t0);                /* 2-4. Z3 = 8*t0 */
    fe_dbl2(Z3, Z3);
    fe_dbl2(Z3, Z3);
    fe_mul(t1, p+4, p+8);           /* 5.  t1 = Y1*Z1 */
    fe_sqr(t2, p+8);                /* 6.  t2 = Z1^2 */
    fe_mul(t2, B3, t2);             /* 7.  t2 = b3*t2 */
    fe_mul(X3, t2, Z3);             /* 8.  X3 = t2*Z3 */
    fe_add(Y3, t0, t2);             /* 9.  Y3 = t0+t2 */
    fe_mul(Z3, t1, Z3);             /* 10. Z3 = t1*Z3 */
    {                               /* 11+12. t2 = 3*t2 (x86: DBL; ADDM t2) */
        u64 tt[4];
        fe_add(tt, t2, t2);
        fe_add(t2, tt, t2);
    }
    fe_sub(t0, t0, t2);             /* 13. t0 = t0-t2 */
    fe_mul(Y3, t0, Y3);             /* 14. Y3 = t0*Y3 */
    fe_add(Y3, X3, Y3);             /* 15. Y3 = X3+Y3 */
    fe_mul(t1, p+0, p+4);           /* 16. t1 = X*Y */
    fe_mul(X3, t0, t1);             /* 17. X3 = t0*t1 */
    fe_dbl2(X3, X3);                /* 18. X3 = 2*X3 */

    memcpy(r+0, X3, 32);
    memcpy(r+4, Y3, 32);
    memcpy(r+8, Z3, 32);
}

/* ----------------------------------------------------------------------------
 * point_scalar_mul_ct(r, xy, k) -- constant-time fixed 256-round ladder.
 * -------------------------------------------------------------------------- */
void point_scalar_mul_ct(u64 r[12], const u64 xy[8], const u64 k[4])
{
    u64 kb[4];
    memcpy(kb, k, 32);

    u64 base[12];                   /* (xy, Z=1) */
    memcpy(base+0, xy, 64);
    base[8]=1; base[9]=0; base[10]=0; base[11]=0;

    u64 R[12];
    memset(R, 0, 96);
    R[0]=0; R[4]=1;                 /* x86: X=0, Y=1, Z=0 "R" start */
    /* NOTE: the x86 seeds R as (0, 1, 0) -- X=0!  Faithful copy. */

    u64 T[12];
    for (int i = 255; i >= 0; i--) {
        pointh_double(R, R);
        pointh_add(T, R, base);
        u64 bit = (kb[i>>6] >> (i & 63)) & 1;
        for (int l = 0; l < 12; l++) {
            u64 tv = T[l], rv = R[l];
            R[l] = bit ? tv : rv;
        }
    }

    /* emit (exact x86 contract) */
    u64 Z2[4], yz2[4], xz[4];
    fe_sqr(Z2, R+8);                /* Z^2 */
    fe_mul(yz2, R+4, Z2);           /* Y*Z^2 */
    fe_mul(xz, R+0, R+8);           /* X*Z */
    u64 rz = fe_is_zero_ct(R+8);
    u64 one[4] = {1,0,0,0}, zero[4] = {0,0,0,0};
    for (int l = 0; l < 4; l++) r[0+l]   = rz ? one[l] : xz[l];
    for (int l = 0; l < 4; l++) r[4+l]   = rz ? one[l] : yz2[l];
    for (int l = 0; l < 4; l++) r[8+l]   = R[8+l];
}

