/* ============================================================================
 * point_twin.c -- secp256k1 Jacobian point arithmetic for the macOS/AArch64
 * port.  Functional twin of asm/secp256k1_point.asm (branch bmc_osx).
 *
 * Same formulas, same 4x64 limb convention, same 12-limb Jacobian / 8-limb
 * affine layout, same infinity representation (Z=0 with X=Y=1) as the x86
 * asm.  Field ops come from fe_twin.c (fe_mul/fe_sqr/fe_add/fe_sub), scalar
 * split from port/osx/secp256k1_scalar.S, wNAF from secp256k1_glv_c.c.
 *
 * API (AAPCS64):
 *   void point_double(u64 r[12], const u64 p[12]);
 *   void point_add_mixed_zr(u64 r[12], const u64 p[12], const u64 xy[8], u64 zr[4]);
 *   void point_add_mixed(u64 r[12], const u64 p[12], const u64 xy[8]);
 *   void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
 *   void point_add(u64 r[12], const u64 p[12], const u64 q[12]);
 *   void point_scalar_mul_fixed(u64 r[12], const u64 k[4]);
 *   void point_scalar_mul_glv(u64 r[12], const u64 xy[8], const u64 k[4]);
 *
 * point_scalar_mul: w=4 windowed, variable-time (matches the x86).  GLV path:
 * variable-time wNAF + odd-multiples table on the isomorphic curve with the
 * captured z-ratios, falling back to point_scalar_mul on any split/wnaf
 * signal -- mirroring the x86 control flow.
 * ============================================================================ */
#include <stdint.h>
#include <string.h>
typedef uint64_t u64;
typedef int64_t i64;

void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
void fe_sqr(u64 r[4], const u64 a[4]);
void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);
int  sc_split_lambda(u64 r1[4], u64 r2[4], const u64 k[4]);
int  glv_wnaf(signed char *out, const u64 k[4]);

extern const unsigned char g_comb_table_data[];   /* 64*15*64 bytes, comb T[j][i] */
#define G_COMB_TABLE g_comb_table_data
static const u64 BETA[4] = {
    0xC1396C28719501EEULL, 0x9CF0497512F58995ULL,
    0x6E64479EAC3434E9ULL, 0x7AE96A2B657C0710ULL
};
static const u64 FE_ZERO4[4] = {0, 0, 0, 0};

static int fe_is_zero(const u64 a[4]) { return (a[0]|a[1]|a[2]|a[3]) == 0; }
static int fe_eq(const u64 a[4], const u64 b[4]) {
    return a[0]==b[0] && a[1]==b[1] && a[2]==b[2] && a[3]==b[3];
}

/* r = 2*a (field), aliasing allowed */
static void fe2_dbl(u64 r[4], const u64 a[4]) {
    u64 t[4];
    fe_add(t, a, a);
    memcpy(r, t, 32);
}

/* ============================================================================
 * point_double(r, p): r = 2*p, both Jacobian, a=0.  In-place safe.
 * ============================================================================ */
void point_double(u64 r[12], const u64 p[12])
{
    u64 A[4], B[4], C[4], D[4], E[4], F[4], t[4], yz[4], c8[4], edt[4];

    fe_sqr(A, p+0);                 /* A = X1^2 */
    fe_sqr(B, p+4);                 /* B = Y1^2 */
    fe_sqr(C, B);                   /* C = B^2 */
    fe_add(t, p+0, B);              /* T = X1 + B */
    fe_sqr(D, t);                   /* T^2 */
    fe_sub(D, D, A);                /* - A */
    fe_sub(D, D, C);                /* - C */
    fe2_dbl(D, D);                  /* D = 2*(T^2 - A - C) */
    fe2_dbl(E, A);                  /* E = 2*A */
    fe_add(E, E, A);                /* E = 3*A */
    fe_sqr(F, E);                   /* F = E^2 */
    fe_sub(t, F, D);                /* X3 = F - D - D below */
    fe_sub(t, t, D);                /* X3 = F - 2*D */
    fe_mul(yz, p+4, p+8);           /* Y1*Z1 (captured before r writes) */
    fe2_dbl(r+8, yz);               /* Z3 = 2*Y1*Z1 */
    u64 dx[4];
    fe_sub(dx, D, t);               /* D - X3 (X3 still in t) */
    fe_mul(edt, E, dx);             /* E*(D-X3) */
    fe2_dbl(c8, C);
    fe2_dbl(c8, c8);
    fe2_dbl(c8, c8);                /* 8*C */
    u64 y3[4];
    fe_sub(y3, edt, c8);            /* Y3 = E*(D-X3) - 8*C */
    memcpy(r+0, t, 32);             /* X3 */
    memcpy(r+4, y3, 32);            /* Y3 */
}

static void set_inf(u64 r[12]) {
    r[0]=1; r[1]=0; r[2]=0; r[3]=0;
    r[4]=1; r[5]=0; r[6]=0; r[7]=0;
    r[8]=0; r[9]=0; r[10]=0; r[11]=0;
}

/* ============================================================================
 * point_add_mixed_zr(r, p, xy, zr) : r = p + affine(xy); zr = H (= Z3/Z1).
 * zr == NULL for the plain entry point.
 * ============================================================================ */
void point_add_mixed_zr(u64 r[12], const u64 p[12], const u64 xy[8], u64 zr[4])
{
    u64 Z1Z1[4], U2[4], S2[4], V[4], H[4], Rr[4], HH[4], HHH[4], w[4], t[4];

    /* p infinity -> r = (xy, Z=1), zr = 1 */
    if (fe_is_zero(p+8)) {
        memcpy(r+0, xy, 64);
        r[8]=1; r[9]=0; r[10]=0; r[11]=0;
        if (zr) { zr[0]=1; zr[1]=0; zr[2]=0; zr[3]=0; }
        return;
    }

    fe_sqr(Z1Z1, p+8);              /* Z1Z1 = Z1^2 */
    fe_mul(U2, xy+0, Z1Z1);         /* U2 = X2*Z1Z1 */
    fe_mul(w, p+8, Z1Z1);           /* Z1*Z1Z1 */
    fe_mul(S2, xy+4, w);            /* S2 = Y2*Z1*Z1Z1 */

    if (fe_eq(U2, p+0)) {
        if (fe_eq(S2, p+4)) {
            /* same point -> double; zr = 2*Y1 (captured before the double) */
            if (zr) fe2_dbl(zr, p+4);
            point_double(r, p);
        } else {
            /* opposite point -> infinity; zr = 0 */
            set_inf(r);
            if (zr) { zr[0]=0; zr[1]=0; zr[2]=0; zr[3]=0; }
        }
        return;
    }

    /* distinct: H = U2 - X1 ; R = S2 - Y1 ; HH = H^2 ; HHH = H*HH ; V = X1*HH */
    fe_sub(H, U2, p+0);
    fe_sub(Rr, S2, p+4);
    fe_sqr(HH, H);
    fe_mul(HHH, H, HH);
    fe_mul(V, p+0, HH);
    /* X3 = R^2 - V - V - HHH */
    fe_sqr(t, Rr);
    fe_sub(t, t, V);
    fe_sub(t, t, V);
    fe_sub(t, t, HHH);
    memcpy(r+0, t, 32);             /* X3 (before reading X3 into more subs) */
    /* Y3 = R*(V - X3) - Y1*HHH */
    fe_sub(t, V, r+0);
    fe_mul(t, Rr, t);
    u64 y1hhh[4];
    fe_mul(y1hhh, p+4, HHH);
    fe_sub(t, t, y1hhh);
    memcpy(r+4, t, 32);             /* Y3 */
    /* Z3 = Z1*H */
    fe_mul(r+8, p+8, H);
    if (zr) memcpy(zr, H, 32);
}

void point_add_mixed(u64 r[12], const u64 p[12], const u64 xy[8])
{
    point_add_mixed_zr(r, p, xy, (u64*)0);
}

/* ============================================================================
 * point_add(r, p, q): r = p + q, both Jacobian.  In-place safe.
 * ============================================================================ */
void point_add(u64 r[12], const u64 p[12], const u64 q[12])
{
    u64 Z1Z1[4], Z22[4], U1[4], U2[4], S1[4], S2[4], H[4], Rr[4], HH[4],
        HHH[4], V[4], w[4], t[4], y3[4];

    /* p inf -> r = q ; q inf -> r = p (in-place safe) */
    if (fe_is_zero(p+8)) { memcpy(r, q, 96); return; }
    if (fe_is_zero(q+8)) { memcpy(r, p, 96); return; }

    fe_sqr(Z1Z1, p+8);              /* Z1Z1 */
    fe_sqr(Z22, q+8);               /* Z22 */
    fe_mul(U1, p+0, Z22);           /* U1 = X1*Z22 */
    fe_mul(U2, q+0, Z1Z1);          /* U2 = X2*Z1Z1 */
    fe_mul(w, q+8, Z22);            /* w = Z2*Z22 */
    fe_mul(S1, p+4, w);             /* S1 = Y1*w */
    fe_mul(w, p+8, Z1Z1);           /* w = Z1*Z1Z1 */
    fe_mul(S2, q+4, w);             /* S2 = Y2*w */

    if (fe_eq(U1, U2)) {
        if (fe_eq(S1, S2)) { point_double(r, p); }
        else               { set_inf(r); }
        return;
    }

    /* H = U2-U1 ; R = S2-S1 ; HH = H^2 ; HHH = H*HH ; V = U1*HH */
    fe_sub(H, U2, U1);
    fe_sub(Rr, S2, S1);
    fe_sqr(HH, H);
    fe_mul(HHH, H, HH);
    fe_mul(V, U1, HH);
    /* X3 = R^2 - V - V - HHH */
    fe_sqr(t, Rr);
    fe_sub(t, t, V);
    fe_sub(t, t, V);
    fe_sub(t, t, HHH);
    u64 x3[4];
    memcpy(x3, t, 32);
    /* Y3 = R*(V-X3) - S1*HHH */
    fe_sub(t, V, x3);
    fe_mul(t, Rr, t);
    u64 s1hhh[4];
    fe_mul(s1hhh, S1, HHH);
    fe_sub(y3, t, s1hhh);
    /* Z3 = Z1*Z2*H */
    fe_mul(w, p+8, q+8);
    fe_mul(r+8, w, H);
    memcpy(r+0, x3, 32);
    memcpy(r+4, y3, 32);
}


/* ============================================================================
 * point_scalar_mul(r, xy, k): r = k*affine(xy), w=4 windowed, variable-time.
 * ============================================================================ */
void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4])
{
    u64 kb[4];
    memcpy(kb, k, 32);
    if (fe_is_zero(kb)) { set_inf(r); return; }

    /* msb index */
    int msb = -1;
    for (int i = 3; i >= 0 && msb < 0; i--)
        if (kb[i]) { u64 v = kb[i]; int b = 63; while (!((v >> b) & 1)) b--; msb = i*64 + b; }
    int top_win = msb >> 2;

    /* build TAB[1..15] Jacobian: entry m at (m-1)*96 */
    u64 TAB[15*12];
    memcpy(TAB+0, xy, 64);          /* TAB[1] = base */
    TAB[8]=1; TAB[9]=0; TAB[10]=0; TAB[11]=0;
    for (int i = 2; i <= 15; i++)
        point_add_mixed(TAB + (i-1)*12, TAB + (i-2)*12, xy);

    /* top window: R = TAB[digit_top], digit_top >= 1 */
    int d = (int)((kb[(top_win*4)>>6] >> ((top_win*4) & 63)) & 0xF);
    memcpy(r, TAB + (d-1)*12, 96);

    for (int w = top_win - 1; w >= 0; w--) {
        point_double(r, r);
        point_double(r, r);
        point_double(r, r);
        point_double(r, r);         /* R = 16*R */
        d = (int)((kb[(w*4)>>6] >> ((w*4) & 63)) & 0xF);
        if (d) point_add(r, r, TAB + (d-1)*12);
    }
}

/* ============================================================================
 * point_scalar_mul_fixed(r, k): r = k*G via the w=4 comb table (no doublings).
 * ============================================================================ */
void point_scalar_mul_fixed(u64 r[12], const u64 k[4])
{
    u64 kb[4];
    memcpy(kb, k, 32);
    u64 R[12];
    set_inf(R);

    int started = 0;
    for (int j = 0; j < 64; j++) {
        int d = (int)((kb[(j*4)>>6] >> ((j*4) & 63)) & 0xF);
        if (!d) continue;
        const u64 *entry = (const u64*)(G_COMB_TABLE + ((j*15)+(d-1))*64);
        if (!started) {
            memcpy(R+0, entry, 64);     /* affine x,y */
            R[8]=1; R[9]=0; R[10]=0; R[11]=0;
            started = 1;
        } else {
            point_add_mixed(R, R, entry);
        }
    }
    if (!started) set_inf(R);
    memcpy(r, R, 96);
}

/* ============================================================================
 * point_scalar_mul_glv(r, xy, k): GLV + wNAF, variable-time, with fallback.
 * ============================================================================ */
void point_scalar_mul_glv(u64 r[12], const u64 xy[8], const u64 k[4])
{
    u64 K[4];
    memcpy(K, k, 32);
    if (fe_is_zero(K)) { set_inf(r); return; }

    u64 R1[4], R2[4];
    if (!sc_split_lambda(R1, R2, K)) { point_scalar_mul(r, xy, K); return; }

    signed char W1[129], W2[129];
    int b1 = glv_wnaf(W1, R1);
    if (b1 < 0) { point_scalar_mul(r, xy, K); return; }
    int b2 = glv_wnaf(W2, R2);
    if (b2 < 0) { point_scalar_mul(r, xy, K); return; }
    int bits = b1 > b2 ? b1 : b2;
    if (bits == 0) { set_inf(r); return; }

    /* 3a. odd-multiples table on the isomorphic curve */
    u64 AI[12], D[12], TABX[8][4], TABY[8][4], AUX[8][4], ZR[8][4], ZS[4], TMP[4], ZG[4];
    memcpy(AI+0, xy, 64); AI[8]=1; AI[9]=0; AI[10]=0; AI[11]=0;
    point_double(D, AI);                        /* D = 2*Q (isomorphic) */
    fe_sqr(ZS, D+8);                            /* C^2 */
    fe_mul(TABX[0], xy+0, ZS);                  /* TAB[0].x = Qx*C^2 */
    fe_mul(TMP, ZS, D+8);                       /* C^3 */
    fe_mul(TABY[0], xy+4, TMP);                 /* TAB[0].y = Qy*C^3 */
    memcpy(AI+0, TABX[0], 32);
    memcpy(AI+4, TABY[0], 32);
    AI[8]=1; AI[9]=0; AI[10]=0; AI[11]=0;
    memcpy(ZR[0], D+8, 32);                     /* ZR[0] = C */
    for (int i = 1; i <= 7; i++) {
        point_add_mixed_zr(AI, AI, D, ZR[i]);   /* AI += 2Q ; ZR[i] */
        memcpy(TABX[i], AI+0, 32);
        memcpy(TABY[i], AI+4, 32);
    }
    fe_mul(ZG, AI+8, D+8);                      /* ZG = AI.z * C */

    /* 3b. globalz: TAB[j] scaled by zs = ZR[j+1]*...*ZR[7], j = 6..0 */
    memcpy(ZS, ZR[7], 32);
    for (int j = 6; j >= 0; j--) {
        if (j != 6) {
            u64 t[4];
            fe_mul(t, ZS, ZR[j+1]);
            memcpy(ZS, t, 32);
        }
        fe_sqr(TMP, ZS);                        /* zs^2 */
        fe_mul(TABX[j], TABX[j], TMP);          /* x *= zs^2 */
        fe_mul(TMP, TMP, ZS);                   /* zs^3 */
        fe_mul(TABY[j], TABY[j], TMP);          /* y *= zs^3 */
    }

    /* 3c. AUXX[i] = TABX[i] * beta */
    for (int i = 0; i < 8; i++) fe_mul(AUX[i], TABX[i], BETA);

    /* 4. ladder: R = inf; for i = bits-1..0: R = 2R; per stream digit adds */
    set_inf(r);
    for (int i = bits - 1; i >= 0; i--) {
        point_double(r, r);
        for (int stream = 0; stream < 2; stream++) {
            const signed char *W = stream ? W2 : W1;
            int d = W[i];
            if (!d) continue;
            int ad = d < 0 ? -d : d;
            int idx = (ad - 1) / 2;
            u64 aff[8];
            memcpy(aff+0, stream ? AUX[idx] : TABX[idx], 32);
            memcpy(aff+4, TABY[idx], 32);
            if (d < 0) fe_sub(aff+4, FE_ZERO4, aff+4);   /* y = -y */
            point_add_mixed(r, r, aff);
        }
    }

    /* 5. leave the isomorphic curve: R.z *= ZG */
    u64 z[4];
    fe_mul(z, r+8, ZG);
    memcpy(r+8, z, 32);
}
