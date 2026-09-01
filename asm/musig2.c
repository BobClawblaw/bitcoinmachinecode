/* musig2.c -- BIP327 MuSig2 (see musig2.h). Everything here is the BIP's
 * reference algorithm written over the node's own field/point/scalar
 * kernels; the libsecp256k1 copy of the BIP vectors is the proof. */
#include <string.h>
#include <stdint.h>
#include "musig2.h"
typedef unsigned char u8;
extern void sha256_full(u8 out[32], const void* msg, unsigned long len);
extern void point_scalar_mul_ct(uint64_t r[12], const uint64_t xy[8], const uint64_t k[4]);
extern void point_add(uint64_t r[12], const uint64_t p[12], const uint64_t q[12]);
extern void fe_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void fe_sqr(uint64_t r[4], const uint64_t a[4]);
extern void fe_inv(uint64_t r[4], const uint64_t a[4]);
extern void fe_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void sc_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void sc_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void sc_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);

static const uint64_t N_LIMBS[4] = { 0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL };
static const uint64_t P_LIMBS[4] = { 0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL };
static const uint64_t G_AFF[8] = {
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL };
static const uint64_t ZERO[4] = {0,0,0,0};
static const uint64_t ONE[4]  = {1,0,0,0};

typedef struct { uint64_t x[4], y[4]; int inf; } pt_t;

/* ---- byte/limb helpers ---- */
static void be32_to_limbs(uint64_t out[4], const u8 be[32]){
    for (int i = 0; i < 4; i++) out[i] = 0;
    for (int i = 0; i < 32; i++) out[i/8] |= ((uint64_t)be[31 - i]) << ((i % 8) * 8);
}
static void limbs_to_be32(u8 be[32], const uint64_t in[4]){
    for (int i = 0; i < 32; i++) be[31 - i] = (u8)((in[i/8] >> ((i % 8) * 8)) & 0xff);
}
static int limb_cmp(const uint64_t a[4], const uint64_t b[4]){
    for (int i = 3; i >= 0; i--){ if (a[i] < b[i]) return -1; if (a[i] > b[i]) return 1; }
    return 0;
}
static int is_zero(const uint64_t a[4]){ return (a[0] | a[1] | a[2] | a[3]) == 0; }
static void reduce_n(uint64_t r[4], const uint64_t a[4]){       /* a < 2n */
    memcpy(r, a, 32);
    if (limb_cmp(r, N_LIMBS) >= 0){
        uint64_t c = 0;
        for (int i = 0; i < 4; i++){ uint64_t s = r[i] - N_LIMBS[i] - c; c = (r[i] < N_LIMBS[i] + c) ? 1 : 0; r[i] = s; }
    }
}
static void neg_n(uint64_t r[4], const uint64_t a[4]){ sc_sub(r, ZERO, a); }
static int sc_from_be(uint64_t r[4], const u8 be[32]){ be32_to_limbs(r, be); return limb_cmp(r, N_LIMBS) < 0; }
static void hash_to_sc(uint64_t r[4], const u8 h[32]){ uint64_t t[4]; be32_to_limbs(t, h); reduce_n(r, t); }

/* ---- tagged hash ---- */
static void tagged(u8 out[32], const char* tag, const u8* data, unsigned long len){
    static u8 buf[64 + 8192];
    u8 th[32]; sha256_full(th, tag, strlen(tag));
    if (len > sizeof buf - 64) { memset(out, 0, 32); return; }
    memcpy(buf, th, 32); memcpy(buf + 32, th, 32); memcpy(buf + 64, data, len);
    sha256_full(out, buf, 64 + len);
}

/* ---- field ---- */
static int fe_sqrt(uint64_t r[4], const uint64_t a[4]){          /* r = a^((p+1)/4); 1 if r^2 == a */
    static const u8 EXP[32] = { 0x3F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                                0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xBF,0xFF,0xFF,0x0C };
    uint64_t acc[4] = {1,0,0,0}, t[4];
    for (int i = 0; i < 256; i++){
        fe_sqr(t, acc); memcpy(acc, t, 32);
        if ((EXP[i / 8] >> (7 - (i % 8))) & 1){ fe_mul(t, acc, a); memcpy(acc, t, 32); }
    }
    fe_sqr(t, acc);
    memcpy(r, acc, 32);
    return memcmp(t, a, 32) == 0;
}
static void fe_neg(uint64_t r[4], const uint64_t a[4]){ if (is_zero(a)) memcpy(r, a, 32); else fe_sub(r, ZERO, a); }
static int has_even_y(const pt_t* p){ return (p->y[0] & 1) == 0; }

/* ---- points ---- */
static int pt_from_bytes(pt_t* p, const u8 c[33]){                /* compressed -> affine; 0 if invalid */
    if (c[0] != 0x02 && c[0] != 0x03) return 0;
    uint64_t x[4]; be32_to_limbs(x, c + 1);
    if (limb_cmp(x, P_LIMBS) >= 0) return 0;
    uint64_t x2[4], x3[4], rhs[4], y[4];
    fe_sqr(x2, x); fe_mul(x3, x2, x);
    { static const uint64_t seven[4] = {7,0,0,0}; uint64_t n7[4]; fe_neg(n7, seven); fe_sub(rhs, x3, n7); }   /* x^3 + 7 */
    if (!fe_sqrt(y, rhs)) return 0;
    if (((y[0] & 1) != 0) != (c[0] == 0x03)) fe_neg(y, y);
    memcpy(p->x, x, 32); memcpy(p->y, y, 32); p->inf = 0;
    return 1;
}
static void pt_to_bytes(u8 c[33], const pt_t* p){ c[0] = (p->y[0] & 1) ? 0x03 : 0x02; limbs_to_be32(c + 1, p->x); }
static void pt_to_bytes_ext(u8 c[33], const pt_t* p){ if (p->inf) memset(c, 0, 33); else pt_to_bytes(c, p); }
static int pt_from_bytes_ext(pt_t* p, const u8 c[33]){
    static const u8 Z33[33] = {0};
    if (!memcmp(c, Z33, 33)){ p->inf = 1; memset(p->x, 0, 32); memset(p->y, 0, 32); return 1; }
    return pt_from_bytes(p, c);
}
static int jac_to_pt(pt_t* p, const uint64_t J[12]){
    if (is_zero(J + 8)){ p->inf = 1; memset(p->x, 0, 32); memset(p->y, 0, 32); return 1; }
    uint64_t z2[4], z3[4], zi2[4], zi3[4];
    fe_sqr(z2, J + 8); fe_mul(z3, z2, J + 8); fe_inv(zi2, z2); fe_inv(zi3, z3);
    fe_mul(p->x, J, zi2); fe_mul(p->y, J + 4, zi3); p->inf = 0;
    return 1;
}
static void pt_to_jac(uint64_t J[12], const pt_t* p){ memcpy(J, p->x, 32); memcpy(J + 4, p->y, 32); memcpy(J + 8, ONE, 32); }
static void pt_add(pt_t* r, const pt_t* a, const pt_t* b){
    if (a->inf){ *r = *b; return; }
    if (b->inf){ *r = *a; return; }
    uint64_t A[12], B[12], R[12]; pt_to_jac(A, a); pt_to_jac(B, b);
    point_add(R, A, B); jac_to_pt(r, R);
}
static void pt_neg(pt_t* r, const pt_t* a){ *r = *a; if (!a->inf) fe_neg(r->y, a->y); }
static void pt_mul(pt_t* r, const uint64_t k[4], const pt_t* p){    /* r = k*p */
    if (p->inf || is_zero(k)){ r->inf = 1; memset(r->x, 0, 32); memset(r->y, 0, 32); return; }
    uint64_t xy[8]; memcpy(xy, p->x, 32); memcpy(xy + 4, p->y, 32);
    uint64_t R[12]; point_scalar_mul_ct(R, xy, k); jac_to_pt(r, R);
}
static void pt_mul_g(pt_t* r, const uint64_t k[4]){ pt_t g; memcpy(g.x, G_AFF, 32); memcpy(g.y, G_AFF + 4, 32); g.inf = 0; pt_mul(r, k, &g); }
static int pt_eq(const pt_t* a, const pt_t* b){
    if (a->inf || b->inf) return a->inf == b->inf;
    return !memcmp(a->x, b->x, 32) && !memcmp(a->y, b->y, 32);
}

/* ---- KeyAgg ---- */
static void keyagg_coeff(uint64_t a[4], const musig2_keyagg_t* ka, const u8 pk[33]){
    if (!memcmp(pk, ka->pk2, 33)){ memcpy(a, ONE, 32); return; }
    u8 buf[65]; memcpy(buf, ka->L, 32); memcpy(buf + 32, pk, 33);
    u8 h[32]; tagged(h, "KeyAgg coefficient", buf, 65); hash_to_sc(a, h);
}
int musig2_key_agg(musig2_keyagg_t* ka, const unsigned char (*pks)[33], int n){
    if (n < 1 || n > MUSIG2_MAX_KEYS) return 0;
    memset(ka, 0, sizeof *ka);
    ka->n = n; memcpy(ka->pks, pks, (size_t)n * 33);
    static u8 lbuf[MUSIG2_MAX_KEYS * 33];
    for (int i = 0; i < n; i++) memcpy(lbuf + i * 33, pks[i], 33);
    tagged(ka->L, "KeyAgg list", lbuf, (unsigned long)n * 33);
    memset(ka->pk2, 0, 33);
    for (int i = 1; i < n; i++) if (memcmp(pks[i], pks[0], 33)){ memcpy(ka->pk2, pks[i], 33); break; }
    pt_t Q; Q.inf = 1; memset(Q.x, 0, 32); memset(Q.y, 0, 32);
    for (int i = 0; i < n; i++){
        pt_t P, T, S; if (!pt_from_bytes(&P, pks[i])) return 0;
        uint64_t a[4]; keyagg_coeff(a, ka, pks[i]);
        pt_mul(&T, a, &P); pt_add(&S, &Q, &T); Q = S;
    }
    if (Q.inf) return 0;
    memcpy(ka->Qx, Q.x, 32); memcpy(ka->Qy, Q.y, 32);
    memcpy(ka->gacc, ONE, 32); memcpy(ka->tacc, ZERO, 32);
    return 1;
}
int musig2_tweak(musig2_keyagg_t* ka, const unsigned char t[32], int is_xonly){
    uint64_t T[4]; if (!sc_from_be(T, t)) return 0;
    pt_t Q; memcpy(Q.x, ka->Qx, 32); memcpy(Q.y, ka->Qy, 32); Q.inf = 0;
    int neg = is_xonly && !has_even_y(&Q);
    uint64_t g[4]; if (neg) neg_n(g, ONE); else memcpy(g, ONE, 32);
    pt_t gQ, TG, Qn;
    if (neg) pt_neg(&gQ, &Q); else gQ = Q;
    pt_mul_g(&TG, T); pt_add(&Qn, &gQ, &TG);
    if (Qn.inf) return 0;
    uint64_t gacc[4], gt[4], tacc[4];
    sc_mul(gacc, g, ka->gacc);
    sc_mul(gt, g, ka->tacc); sc_add(tacc, T, gt);
    memcpy(ka->Qx, Qn.x, 32); memcpy(ka->Qy, Qn.y, 32);
    memcpy(ka->gacc, gacc, 32); memcpy(ka->tacc, tacc, 32);
    return 1;
}
void musig2_agg_xonly(unsigned char out[32], const musig2_keyagg_t* ka){ limbs_to_be32(out, ka->Qx); }
void musig2_agg_plain(unsigned char out[33], const musig2_keyagg_t* ka){ pt_t Q; memcpy(Q.x, ka->Qx, 32); memcpy(Q.y, ka->Qy, 32); Q.inf = 0; pt_to_bytes(out, &Q); }

/* ---- nonces ---- */
int musig2_nonce_gen(unsigned char secnonce[97], unsigned char pubnonce[66],
                     const unsigned char rand32[32], const unsigned char* sk,
                     const unsigned char pk[33], const unsigned char* aggpk32,
                     const unsigned char* msg, unsigned long msglen,
                     const unsigned char* extra, unsigned long extralen){
    u8 rnd[32];
    if (sk){ u8 h[32]; tagged(h, "MuSig/aux", rand32, 32); for (int i = 0; i < 32; i++) rnd[i] = sk[i] ^ h[i]; }
    else memcpy(rnd, rand32, 32);
    if (msglen > 4096 || extralen > 1024) return 0;
    static u8 buf[32 + 1 + 33 + 1 + 32 + 9 + 4096 + 4 + 1024 + 1];
    unsigned long o = 0;
    memcpy(buf + o, rnd, 32); o += 32;
    buf[o++] = 33; memcpy(buf + o, pk, 33); o += 33;
    if (aggpk32){ buf[o++] = 32; memcpy(buf + o, aggpk32, 32); o += 32; } else buf[o++] = 0;
    if (msg){ buf[o++] = 1; for (int i = 7; i >= 0; i--) buf[o++] = (u8)(msglen >> (8 * i)); memcpy(buf + o, msg, msglen); o += msglen; }
    else buf[o++] = 0;
    for (int i = 3; i >= 0; i--) buf[o++] = (u8)(extralen >> (8 * i));
    if (extra && extralen){ memcpy(buf + o, extra, extralen); o += extralen; }
    uint64_t k[2][4];
    for (int i = 0; i < 2; i++){
        buf[o] = (u8)i;
        u8 h[32]; tagged(h, "MuSig/nonce", buf, o + 1);
        hash_to_sc(k[i], h);
        if (is_zero(k[i])) return 0;
    }
    for (int i = 0; i < 2; i++){
        pt_t R; pt_mul_g(&R, k[i]);
        limbs_to_be32(secnonce + 32 * i, k[i]);
        pt_to_bytes(pubnonce + 33 * i, &R);
    }
    memcpy(secnonce + 64, pk, 33);
    return 1;
}
int musig2_pubnonce_valid(const unsigned char pn[66]){ pt_t a, b; return pt_from_bytes(&a, pn) && pt_from_bytes(&b, pn + 33); }
int musig2_nonce_agg(unsigned char aggnonce[66], const unsigned char (*pns)[66], int n){
    for (int j = 0; j < 2; j++){
        pt_t R; R.inf = 1; memset(R.x, 0, 32); memset(R.y, 0, 32);
        for (int i = 0; i < n; i++){
            pt_t P, S; if (!pt_from_bytes(&P, pns[i] + 33 * j)) return 0;
            pt_add(&S, &R, &P); R = S;
        }
        pt_to_bytes_ext(aggnonce + 33 * j, &R);
    }
    return 1;
}

/* ---- session ---- */
int musig2_session(musig2_session_t* s, const musig2_keyagg_t* ka,
                   const unsigned char aggnonce[66], const unsigned char* msg, unsigned long msglen){
    pt_t R1, R2; if (!pt_from_bytes_ext(&R1, aggnonce) || !pt_from_bytes_ext(&R2, aggnonce + 33)) return 0;
    if (msglen > 4096) return 0;
    u8 qx[32]; limbs_to_be32(qx, ka->Qx);
    static u8 buf[66 + 32 + 4096];
    memcpy(buf, aggnonce, 66); memcpy(buf + 66, qx, 32); memcpy(buf + 98, msg, msglen);
    u8 h[32]; tagged(h, "MuSig/noncecoef", buf, 98 + msglen); hash_to_sc(s->b, h);
    pt_t bR2, R; pt_mul(&bR2, s->b, &R2); pt_add(&R, &R1, &bR2);
    if (R.inf){ memcpy(R.x, G_AFF, 32); memcpy(R.y, G_AFF + 4, 32); R.inf = 0; }
    memcpy(s->Rx, R.x, 32); memcpy(s->Ry, R.y, 32);
    u8 cb[64 + 4096]; limbs_to_be32(cb, R.x); memcpy(cb + 32, qx, 32); memcpy(cb + 64, msg, msglen);
    tagged(h, "BIP0340/challenge", cb, 64 + msglen); hash_to_sc(s->e, h);
    return 1;
}
static int session_coeff(uint64_t a[4], const musig2_keyagg_t* ka, const u8 pk[33]){
    int found = 0; for (int i = 0; i < ka->n; i++) if (!memcmp(ka->pks[i], pk, 33)){ found = 1; break; }
    if (!found) return 0;
    keyagg_coeff(a, ka, pk); return 1;
}
static int verify_internal(const uint64_t sc[4], const u8 pubnonce[66], const u8 pk[33],
                           const musig2_keyagg_t* ka, const musig2_session_t* s){
    pt_t R1, R2; if (!pt_from_bytes(&R1, pubnonce) || !pt_from_bytes(&R2, pubnonce + 33)) return 0;
    pt_t bR2, Re; pt_mul(&bR2, s->b, &R2); pt_add(&Re, &R1, &bR2);
    pt_t R; memcpy(R.x, s->Rx, 32); memcpy(R.y, s->Ry, 32); R.inf = 0;
    if (!has_even_y(&R)){ pt_t t; pt_neg(&t, &Re); Re = t; }
    pt_t P; if (!pt_from_bytes(&P, pk)) return 0;
    uint64_t a[4]; if (!session_coeff(a, ka, pk)) return 0;
    pt_t Q; memcpy(Q.x, ka->Qx, 32); memcpy(Q.y, ka->Qy, 32); Q.inf = 0;
    uint64_t g[4]; if (has_even_y(&Q)) memcpy(g, ONE, 32); else neg_n(g, ONE);
    uint64_t gp[4], ea[4], eag[4]; sc_mul(gp, g, ka->gacc); sc_mul(ea, s->e, a); sc_mul(eag, ea, gp);
    pt_t lhs, t2, rhs; pt_mul_g(&lhs, sc); pt_mul(&t2, eag, &P); pt_add(&rhs, &Re, &t2);
    return pt_eq(&lhs, &rhs);
}
int musig2_partial_sign(unsigned char psig[32], const unsigned char secnonce[97],
                        const unsigned char sk[32], const musig2_keyagg_t* ka,
                        const musig2_session_t* s){
    uint64_t k1[4], k2[4], d0[4];
    if (!sc_from_be(k1, secnonce) || is_zero(k1) || !sc_from_be(k2, secnonce + 32) || is_zero(k2)) return 0;
    if (!sc_from_be(d0, sk) || is_zero(d0)) return 0;
    pt_t R; memcpy(R.x, s->Rx, 32); memcpy(R.y, s->Ry, 32); R.inf = 0;
    if (!has_even_y(&R)){ uint64_t t[4]; neg_n(t, k1); memcpy(k1, t, 32); neg_n(t, k2); memcpy(k2, t, 32); }
    pt_t P; pt_mul_g(&P, d0); u8 pk[33]; pt_to_bytes(pk, &P);
    if (memcmp(pk, secnonce + 64, 33)) return 0;
    uint64_t a[4]; if (!session_coeff(a, ka, pk)) return 0;
    pt_t Q; memcpy(Q.x, ka->Qx, 32); memcpy(Q.y, ka->Qy, 32); Q.inf = 0;
    uint64_t g[4]; if (has_even_y(&Q)) memcpy(g, ONE, 32); else neg_n(g, ONE);
    uint64_t gg[4], d[4], bk2[4], ea[4], ead[4], sum[4], sc[4];
    sc_mul(gg, g, ka->gacc); sc_mul(d, gg, d0);
    sc_mul(bk2, s->b, k2); sc_mul(ea, s->e, a); sc_mul(ead, ea, d);
    sc_add(sum, k1, bk2); sc_add(sc, sum, ead);
    /* own pubnonce for the mandatory self-check */
    u8 pn[66]; { uint64_t kk[4]; pt_t T; sc_from_be(kk, secnonce); pt_mul_g(&T, kk); pt_to_bytes(pn, &T);
                 sc_from_be(kk, secnonce + 32); pt_mul_g(&T, kk); pt_to_bytes(pn + 33, &T); }
    if (!verify_internal(sc, pn, pk, ka, s)) return 0;
    limbs_to_be32(psig, sc);
    return 1;
}
int musig2_partial_sig_verify(const unsigned char psig[32], const unsigned char pubnonce[66],
                              const unsigned char pk[33], const musig2_keyagg_t* ka,
                              const musig2_session_t* s){
    uint64_t sc[4]; if (!sc_from_be(sc, psig)) return 0;
    return verify_internal(sc, pubnonce, pk, ka, s);
}
int musig2_partial_sig_agg(unsigned char sig[64], const musig2_session_t* s,
                           const musig2_keyagg_t* ka, const unsigned char (*psigs)[32], int n){
    uint64_t acc[4] = {0,0,0,0};
    for (int i = 0; i < n; i++){ uint64_t si[4], t[4]; if (!sc_from_be(si, psigs[i])) return 0; sc_add(t, acc, si); memcpy(acc, t, 32); }
    pt_t Q; memcpy(Q.x, ka->Qx, 32); memcpy(Q.y, ka->Qy, 32); Q.inf = 0;
    uint64_t g[4]; if (has_even_y(&Q)) memcpy(g, ONE, 32); else neg_n(g, ONE);
    uint64_t eg[4], egt[4], out[4]; sc_mul(eg, s->e, g); sc_mul(egt, eg, ka->tacc); sc_add(out, acc, egt);
    limbs_to_be32(sig, s->Rx); limbs_to_be32(sig + 32, out);
    return 1;
}
