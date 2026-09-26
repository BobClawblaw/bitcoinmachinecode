/* port/osx/test_support/point_ref_twin.c -- the Mac stand-in for
 * tests/point_ref.asm AND tests/point_ct_ref.asm (both, in this one file): the FROZEN x86 EC layer
 * (main @ 91b7c9d, symbols suffixed _ref) that tests/test_point_repr diffs the
 * live point code against, limb for limb, on arbitrary (off-curve) operands,
 * in place and out of place. Test-only: outside the port/osx C twins, so no
 * daemon links it.
 *
 * HOW IT IS WRITTEN, and why
 *   Bit-identity on off-curve inputs means every routine must evaluate the
 *   frozen code's exact formulas, and in-place calls (r == p) mean it must
 *   also READ its inputs and WRITE its outputs at the same points the asm
 *   does. So each routine below is a step-for-step transcription: one line
 *   per asm field call, the same destination (a numbered scratch slot, or the
 *   output limb it wrote), in the same order. Squarings stay fe_mul(a, a),
 *   as in the frozen code. It was transcribed from the .asm files, not from
 *   port/osx/point_twin.c, which is what makes the test a differential and
 *   not a tautology.
 *
 *   Like the x86 reference it links the LIVE field layer (fe_add/fe_sub/
 *   fe_mul, all alias-safe) and the live sc_split_lambda / glv_wnaf: the
 *   field has its own frozen reference (fe_ref_twin.c), so a difference here
 *   is a difference in the point layer. The fixed-base comb table is the
 *   frozen copy (g_comb_table_ref_data.c, generated from
 *   tests/g_comb_table_ref.inc), not the live table.
 */
#include <stdint.h>
#include <string.h>

typedef uint64_t u64;

extern void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern int  sc_split_lambda(u64 r1[4], u64 r2[4], const u64 k[4]);
extern int  glv_wnaf(signed char out[129], const u64 s[4]);
/* the frozen comb table, compiled into this file so the twin is one
 * translation unit (it also stands in for point_ct_ref.o) */
#include "g_comb_table_ref_data.c"

static const u64 BETA_ref[4] = { 0xC1396C28719501EEULL, 0x9CF0497512F58995ULL,
                                 0x6E64479EAC3434E9ULL, 0x7AE96A2B657C0710ULL };
static const u64 FE_ZERO_ref[4] = { 0, 0, 0, 0 };
static const u64 B3_ref[4] = { 21, 0, 0, 0 };

#define X(p) ((p) + 0)
#define Y(p) ((p) + 4)
#define Z(p) ((p) + 8)

static int fe_is_zero(const u64 a[4]){ return (a[0] | a[1] | a[2] | a[3]) == 0; }
static int fe_eq(const u64 a[4], const u64 b[4]){ return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]; }
static void set_inf(u64 r[12]){ memset(r, 0, 96); r[0] = 1; r[4] = 1; }   /* canonical Jacobian infinity (1,1,0) */

/* ---- point_double_ref: A=X1^2 B=Y1^2 C=B^2 D=2((X1+B)^2-A-C) E=3A F=E^2
 *      X3=F-2D  Y3=E(D-X3)-8C  Z3=2Y1Z1, with the frozen code's in-place
 *      ordering (Z3 from Y1,Z1 before Y3 is written) and its recomputation of
 *      E*(D-X3). ---- */
void point_double_ref(u64 r[12], const u64 p[12]){
    u64 S0[4], S1[4], S2[4], S3[4], S4[4], S5[4], S6[4], S7[4];
    fe_mul(S0, X(p), X(p));          /* A */
    fe_mul(S1, Y(p), Y(p));          /* B */
    fe_mul(S2, S1, S1);              /* C */
    fe_add(S3, X(p), S1);            /* X1+B */
    fe_mul(S3, S3, S3);
    fe_sub(S3, S3, S0);
    fe_sub(S3, S3, S2);
    fe_add(S3, S3, S3);              /* D */
    fe_add(S4, S0, S0);
    fe_add(S4, S4, S0);              /* E */
    fe_mul(S5, S4, S4);              /* F */
    fe_add(S6, S3, S3);              /* 2D */
    fe_sub(X(r), S5, S6);            /* X3 */
    fe_sub(S6, S3, X(r));            /* D - X3 */
    fe_mul(S6, S4, S6);              /* E(D-X3), overwritten below as the asm does */
    fe_add(S7, S2, S2);
    fe_add(S7, S7, S7);
    fe_add(S7, S7, S7);              /* 8C */
    fe_mul(S6, Y(p), Z(p));          /* Y1*Z1 (input still intact) */
    fe_add(Z(r), S6, S6);            /* Z3 */
    fe_sub(S6, S3, X(r));            /* recompute D - X3 */
    fe_mul(S6, S4, S6);
    fe_sub(Y(r), S6, S7);            /* Y3 */
}

/* ---- point_add_mixed_ref / _zr_ref: r = p + affine(xy); zr = Z3/Z1 ---- */
static void add_mixed_body(u64 r[12], const u64 p[12], const u64 xy[8], u64 *zr){
    u64 S0[4], S1[4], S2[4], S3[4], S4[4], S5[4], S6[4], S7[4], S8[4], S9[4];
    if (fe_is_zero(Z(p))){                          /* p infinity -> (xy, 1) */
        memmove(r, xy, 64);
        r[8] = 1; r[9] = r[10] = r[11] = 0;
        if (zr){ zr[0] = 1; zr[1] = zr[2] = zr[3] = 0; }
        return;
    }
    fe_mul(S0, Z(p), Z(p));          /* Z1Z1 */
    fe_mul(S1, X(xy), S0);           /* U2 */
    fe_mul(S8, Z(p), S0);            /* Z1*Z1Z1 */
    fe_mul(S3, Y(xy), S8);           /* S2 */
    if (fe_eq(S1, X(p))){
        if (!fe_eq(S3, Y(p))){
            set_inf(r);
            if (zr) memset(zr, 0, 32);
            return;
        }
        if (zr) fe_add(zr, Y(p), Y(p));             /* 2*Y1, before an in-place double */
        point_double_ref(r, p);
        return;
    }
    fe_sub(S4, S1, X(p));            /* H */
    fe_sub(S5, S3, Y(p));            /* R */
    fe_mul(S6, S4, S4);              /* HH */
    fe_mul(S7, S4, S6);              /* HHH */
    fe_mul(S2, X(p), S6);            /* V */
    fe_mul(S8, S5, S5);              /* R^2 */
    fe_add(S9, S2, S2);              /* 2V */
    fe_sub(X(r), S8, S9);
    fe_sub(X(r), X(r), S7);          /* X3 */
    fe_sub(S8, S2, X(r));            /* V - X3 */
    fe_mul(S8, S5, S8);
    fe_mul(S9, Y(p), S7);            /* Y1*HHH */
    fe_sub(Y(r), S8, S9);            /* Y3 */
    fe_mul(Z(r), Z(p), S4);          /* Z3 */
    if (zr) memcpy(zr, S4, 32);
}
void point_add_mixed_ref(u64 r[12], const u64 p[12], const u64 xy[8]){ add_mixed_body(r, p, xy, 0); }
void point_add_mixed_zr_ref(u64 r[12], const u64 p[12], const u64 xy[8], u64 zr[4]){ add_mixed_body(r, p, xy, zr); }

/* ---- point_add_ref: r = p + q, both Jacobian ---- */
void point_add_ref(u64 r[12], const u64 p[12], const u64 q[12]){
    u64 S0[4], S1[4], S2[4], S3[4], S4[4], S5[4], S6[4], S7[4], S8[4], S9[4], S10[4], S11[4];
    if (fe_is_zero(Z(p))){ memmove(r, q, 96); return; }
    if (fe_is_zero(Z(q))){ memmove(r, p, 96); return; }
    fe_mul(S0, Z(p), Z(p));          /* Z1Z1 */
    fe_mul(S5, Z(q), Z(q));          /* Z2Z2 */
    fe_mul(S2, X(p), S5);            /* U1 */
    fe_mul(S3, X(q), S0);            /* U2 */
    fe_mul(S11, Z(q), S5);
    fe_mul(S1, Y(p), S11);           /* S1 */
    fe_mul(S11, Z(p), S0);
    fe_mul(S4, Y(q), S11);           /* S2 */
    if (fe_eq(S2, S3)){
        if (!fe_eq(S1, S4)){ set_inf(r); return; }
        point_double_ref(r, p);
        return;
    }
    fe_sub(S6, S3, S2);              /* H */
    fe_sub(S7, S4, S1);              /* R */
    fe_mul(S8, S6, S6);              /* HH */
    fe_mul(S9, S6, S8);              /* HHH */
    fe_mul(S10, S2, S8);             /* V */
    fe_mul(S5, S7, S7);              /* R^2 */
    fe_add(S11, S10, S10);           /* 2V */
    fe_sub(X(r), S5, S11);
    fe_sub(X(r), X(r), S9);          /* X3 */
    fe_sub(S5, S10, X(r));
    fe_mul(S5, S7, S5);
    fe_mul(S11, S1, S9);
    fe_sub(Y(r), S5, S11);           /* Y3 */
    fe_mul(S11, Z(p), Z(q));
    fe_mul(Z(r), S11, S6);           /* Z3 */
}

/* window digit d (4 bits) of k at window w */
static unsigned nibble(const u64 k[4], unsigned w){ unsigned b = w * 4; return (unsigned)(k[b >> 6] >> (b & 63)) & 15; }

/* ---- point_scalar_mul_ref: w=4 window, TAB[i] = i*base built by mixed adds ---- */
void point_scalar_mul_ref(u64 r[12], const u64 xy[8], const u64 kin[4]){
    u64 k[4] = { kin[0], kin[1], kin[2], kin[3] };
    u64 TAB[15][12];
    if (!(k[0] | k[1] | k[2] | k[3])){ set_inf(r); return; }
    int msb = k[3] ? 192 + 63 - __builtin_clzll(k[3]) : k[2] ? 128 + 63 - __builtin_clzll(k[2])
            : k[1] ? 64 + 63 - __builtin_clzll(k[1]) : 63 - __builtin_clzll(k[0]);
    int top = msb >> 2;
    memcpy(TAB[0], xy, 64); TAB[0][8] = 1; TAB[0][9] = TAB[0][10] = TAB[0][11] = 0;
    for (int i = 2; i <= 15; i++) point_add_mixed_ref(TAB[i - 1], TAB[i - 2], xy);
    memcpy(r, TAB[nibble(k, (unsigned)top) - 1], 96);
    for (int w = top - 1; w >= 0; w--){
        point_double_ref(r, r); point_double_ref(r, r);
        point_double_ref(r, r); point_double_ref(r, r);
        unsigned d = nibble(k, (unsigned)w);
        if (d) point_add_ref(r, r, TAB[d - 1]);
    }
}

/* ---- point_scalar_mul_fixed_ref: k*G over the frozen w=4 comb ---- */
void point_scalar_mul_fixed_ref(u64 out[12], const u64 kin[4]){
    u64 k[4] = { kin[0], kin[1], kin[2], kin[3] };
    u64 R[12], Rc[12];
    unsigned j = 0, d = 0;
    if (!(k[0] | k[1] | k[2] | k[3])){ set_inf(R); memcpy(out, R, 96); return; }
    for (; j < 64; j++) if ((d = nibble(k, j))) break;
    if (j == 64){ set_inf(R); memcpy(out, R, 96); return; }
    memcpy(R, G_COMB_TABLE_ref + ((j * 15) + (d - 1)) * 8, 64);
    R[8] = 1; R[9] = R[10] = R[11] = 0;
    for (j++; j < 64; j++){
        if (!(d = nibble(k, j))) continue;
        memcpy(Rc, R, 96);
        point_add_mixed_ref(R, Rc, G_COMB_TABLE_ref + ((j * 15) + (d - 1)) * 8);
    }
    memcpy(out, R, 96);
}

/* ---- point_scalar_mul_glv_ref: GLV + width-5 wNAF, isomorphic-curve table ---- */
void point_scalar_mul_glv_ref(u64 r[12], const u64 xy[8], const u64 kin[4]){
    u64 K[4] = { kin[0], kin[1], kin[2], kin[3] };
    u64 R1[4], R2[4], ZG[4], ZS[4], D[12], AI[12], TAB[8][8], AUXX[8][4], ZR[8][4], TMP[8];
    signed char W[2][129];
    if (!(K[0] | K[1] | K[2] | K[3])){ set_inf(r); return; }
    if (!sc_split_lambda(R1, R2, K)) goto fallback;
    int b1 = glv_wnaf(W[0], R1); if (b1 < 0) goto fallback;
    int b2 = glv_wnaf(W[1], R2); if (b2 < 0) goto fallback;
    int bits = b1 > b2 ? b1 : b2;
    if (bits == 0){ set_inf(r); return; }

    /* 3a. AI = (Qx, Qy, 1); D = 2*AI; C = D.z; TAB[0] = (Qx*C^2, Qy*C^3) */
    memcpy(AI, xy, 64); AI[8] = 1; AI[9] = AI[10] = AI[11] = 0;
    point_double_ref(D, AI);
    fe_mul(ZS, Z(D), Z(D));
    fe_mul(TAB[0], X(xy), ZS);
    fe_mul(ZS, ZS, Z(D));
    fe_mul(TAB[0] + 4, Y(xy), ZS);
    memcpy(AI, TAB[0], 64);                         /* AI.z stays 1 */
    memcpy(ZR[0], Z(D), 32);
    for (int i = 1; i < 8; i++){
        point_add_mixed_zr_ref(AI, AI, D, ZR[i]);   /* d_ge = (D.x, D.y) */
        memcpy(TAB[i], AI, 64);
    }
    fe_mul(ZG, Z(AI), Z(D));

    /* 3b. globalz */
    memcpy(ZS, ZR[7], 32);
    for (int j = 6; j >= 0; j--){
        if (j != 6) fe_mul(ZS, ZS, ZR[j + 1]);
        fe_mul(TMP, ZS, ZS);
        fe_mul(TAB[j], TAB[j], TMP);
        fe_mul(TMP, TMP, ZS);
        fe_mul(TAB[j] + 4, TAB[j] + 4, TMP);
    }
    /* 3c. lambda table */
    for (int i = 0; i < 8; i++) fe_mul(AUXX[i], TAB[i], BETA_ref);

    /* 4. ladder over both streams */
    set_inf(r);
    for (int i = bits - 1; i >= 0; i--){
        point_double_ref(r, r);
        for (int s = 0; s < 2; s++){
            int d = W[s][i];
            if (!d) continue;
            int idx = ((d < 0 ? -d : d) - 1) >> 1;
            memcpy(TMP, s ? AUXX[idx] : TAB[idx], 32);
            if (d > 0) memcpy(TMP + 4, TAB[idx] + 4, 32);
            else fe_sub(TMP + 4, FE_ZERO_ref, TAB[idx] + 4);
            point_add_mixed_ref(r, r, TMP);
        }
    }
    /* 5. leave the isomorphic curve */
    fe_mul(Z(r), Z(r), ZG);
    return;
fallback:
    point_scalar_mul_ref(r, xy, K);
}

/* ---- point_ct_ref.asm: complete formulas, homogeneous (Renes-Costello-Batina) ---- */
void pointh_add_ref(u64 r[12], const u64 p[12], const u64 q[12]){
    u64 t0[4], t1[4], t2[4], t3[4], t4[4], X3[4], Y3[4], Z3[4];
    fe_mul(t0, X(p), X(q));          /* 1 */
    fe_mul(t1, Y(p), Y(q));          /* 2 */
    fe_mul(t2, Z(p), Z(q));          /* 3 */
    fe_add(t3, X(p), Y(p));          /* 4 */
    fe_add(t4, X(q), Y(q));          /* 5 */
    fe_mul(t3, t3, t4);              /* 6 */
    fe_add(t4, t0, t1);              /* 7 */
    fe_sub(t3, t3, t4);              /* 8 */
    fe_add(t4, Y(p), Z(p));          /* 9 */
    fe_add(X3, Y(q), Z(q));          /* 10 */
    fe_mul(t4, t4, X3);              /* 11 */
    fe_add(X3, t1, t2);              /* 12 */
    fe_sub(t4, t4, X3);              /* 13 */
    fe_add(X3, X(p), Z(p));          /* 14 */
    fe_add(Y3, X(q), Z(q));          /* 15 */
    fe_mul(X3, X3, Y3);              /* 16 */
    fe_add(Y3, t0, t2);              /* 17 */
    fe_sub(Y3, X3, Y3);              /* 18 */
    fe_add(X3, t0, t0);              /* 19 */
    fe_add(t0, X3, t0);              /* 20 */
    fe_mul(t2, B3_ref, t2);          /* 21 */
    fe_add(Z3, t1, t2);              /* 22 */
    fe_sub(t1, t1, t2);              /* 23 */
    fe_mul(Y3, B3_ref, Y3);          /* 24 */
    fe_mul(X3, t4, Y3);              /* 25 */
    fe_mul(t2, t3, t1);              /* 26 */
    fe_sub(X3, t2, X3);              /* 27 */
    fe_mul(Y3, Y3, t0);              /* 28 */
    fe_mul(t1, t1, Z3);              /* 29 */
    fe_add(Y3, t1, Y3);              /* 30 */
    fe_mul(t0, t0, t3);              /* 31 */
    fe_mul(Z3, Z3, t4);              /* 32 */
    fe_add(Z3, Z3, t0);              /* 33 */
    memcpy(X(r), X3, 32); memcpy(Y(r), Y3, 32); memcpy(Z(r), Z3, 32);
}

void pointh_double_ref(u64 r[12], const u64 p[12]){
    u64 t0[4], t1[4], t2[4], X3[4], Y3[4], Z3[4];
    fe_mul(t0, Y(p), Y(p));          /* 1 */
    fe_add(Z3, t0, t0);              /* 2 */
    fe_add(Z3, Z3, Z3);              /* 3 */
    fe_add(Z3, Z3, Z3);              /* 4 */
    fe_mul(t1, Y(p), Z(p));          /* 5 */
    fe_mul(t2, Z(p), Z(p));          /* 6 */
    fe_mul(t2, B3_ref, t2);          /* 7 */
    fe_mul(X3, t2, Z3);              /* 8 */
    fe_add(Y3, t0, t2);              /* 9 */
    fe_mul(Z3, t1, Z3);              /* 10 */
    fe_add(t1, t2, t2);              /* 11 */
    fe_add(t2, t1, t2);              /* 12 */
    fe_sub(t0, t0, t2);              /* 13 */
    fe_mul(Y3, t0, Y3);              /* 14 */
    fe_add(Y3, X3, Y3);              /* 15 */
    fe_mul(t1, X(p), Y(p));          /* 16 */
    fe_mul(X3, t0, t1);              /* 17 */
    fe_add(X3, X3, X3);              /* 18 */
    memcpy(X(r), X3, 32); memcpy(Y(r), Y3, 32); memcpy(Z(r), Z3, 32);
}

void point_scalar_mul_ct_ref(u64 r[12], const u64 xy[8], const u64 kin[4]){
    u64 k[4] = { kin[0], kin[1], kin[2], kin[3] };
    u64 R[12], T[12], Pb[12];
    memcpy(Pb, xy, 64); Pb[8] = 1; Pb[9] = Pb[10] = Pb[11] = 0;
    memset(R, 0, 96); R[4] = 1;                    /* identity (0:1:0) */
    for (int i = 255; i >= 0; i--){
        pointh_double_ref(R, R);
        pointh_add_ref(T, R, Pb);
        if ((k[i >> 6] >> (i & 63)) & 1) memcpy(R, T, 96);
    }
    /* homogeneous -> Jacobian (X*Z, Y*Z^2, Z); T[0..3] = Z^2 scratch */
    fe_mul(T, Z(R), Z(R));
    fe_mul(T + 4, Y(R), T);          /* Jacobian Y */
    fe_mul(T + 8, X(R), Z(R));       /* Jacobian X */
    int inf = fe_is_zero(Z(R));
    r[0] = inf ? 1 : T[8];  r[1] = inf ? 0 : T[9];  r[2] = inf ? 0 : T[10]; r[3] = inf ? 0 : T[11];
    r[4] = inf ? 1 : T[4];  r[5] = inf ? 0 : T[5];  r[6] = inf ? 0 : T[6];  r[7] = inf ? 0 : T[7];
    r[8] = R[8]; r[9] = R[9]; r[10] = R[10]; r[11] = R[11];
}
