/* port/osx/test_support/ecdsa_verify_ref_twin.c -- the Mac stand-in for
 * tests/ecdsa_verify_ref.asm: the FROZEN pre-PERF_SCOPE-4.2 x86 ecdsa_verify
 * that tests/test_ecdsa_inverse and tests/test_ecdsa_glv_switch compare the
 * live verifier's verdicts against. Test-only (outside the port/osx C twins).
 *
 * Transcribed from the .asm step for step. It is the textbook verify the
 * later levers replaced, on the LIVE primitives it calls (as the x86 copy
 * links them):
 *   s, r in (0, n)                      else invalid
 *   w  = sc_inv(s)                      Fermat, not the later sc_inv_var
 *   u1 = z*w, u2 = r*w (mod n)          sc_mul; z is used as given
 *   P  = u1*G (point_scalar_mul_fixed) + u2*Q (point_scalar_mul, the plain
 *        windowed ladder -- never GLV, so the switch test has a fixed side)
 *   P at infinity                       invalid
 *   x  = X * (Z^2)^-1 (fe_inv)          the affine compare lever A removed
 *   x mod n by ONE conditional subtract (x < p < 2n), then x == r
 */
#include <stdint.h>

typedef uint64_t u64;

extern void sc_inv(u64 r[4], const u64 a[4]);
extern void sc_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void point_scalar_mul_fixed(u64 r[12], const u64 k[4]);
extern void point_add(u64 r[12], const u64 p[12], const u64 q[12]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);

static const u64 N_ref[4] = { 0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
                              0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL };

/* x strictly in (0, n) */
static int in_range(const u64 x[4]){
    if (!(x[0] | x[1] | x[2] | x[3])) return 0;
    for (int i = 3; i >= 0; i--){
        if (x[i] < N_ref[i]) return 1;
        if (x[i] > N_ref[i]) return 0;
    }
    return 0;                                      /* x == n */
}

int ecdsa_verify_ref(const u64 z[4], const u64 r[4], const u64 s_in[4],
                     const u64 Qx[4], const u64 Qy[4])
{
    u64 s[4] = { s_in[0], s_in[1], s_in[2], s_in[3] };
    u64 w[4], u1[4], u2[4], Q[8], P1[12], P2[12], P[12], z2[4], zi[4], px[4], pxm[4];
    if (!in_range(s)) return 0;
    if (!in_range(r)) return 0;
    sc_inv(w, s);
    sc_mul(u1, z, w);
    for (int i = 0; i < 4; i++){ Q[i] = Qx[i]; Q[4 + i] = Qy[i]; }
    sc_mul(u2, r, w);
    point_scalar_mul_fixed(P1, u1);
    point_scalar_mul(P2, Q, u2);
    point_add(P, P1, P2);
    if (!(P[8] | P[9] | P[10] | P[11])) return 0;
    fe_mul(z2, P + 8, P + 8);
    fe_inv(zi, z2);
    fe_mul(px, P, zi);
    /* px mod n: one conditional subtract */
    u64 t[4]; unsigned __int128 b = 0;
    for (int i = 0; i < 4; i++){
        unsigned __int128 d = (unsigned __int128)px[i] - N_ref[i] - (u64)b;
        t[i] = (u64)d; b = (d >> 64) ? 1 : 0;
    }
    for (int i = 0; i < 4; i++) pxm[i] = b ? px[i] : t[i];
    return pxm[0] == r[0] && pxm[1] == r[1] && pxm[2] == r[2] && pxm[3] == r[3];
}
