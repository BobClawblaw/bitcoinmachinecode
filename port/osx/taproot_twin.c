/* ============================================================================
 * taproot_twin.c -- BIP341 taproot commitment/tweak layer for the
 * macOS/AArch64 port.  Functional twin of asm/secp256k1_taproot.asm.
 *
 *   void tagged_hash256(u8 out[32], const char* tag, u64 taglen,
 *                       const u8* msg, u64 msglen);
 *   void tap_branch_hash(u8 out[32], const u8* a, const u8* b);
 *   long tap_leaf_hash(u8 out[32], u8 ver, const u8* script, u64 slen);
 *   long taproot_tweak_pubkey(u8 out_x[32], const u8 internal_x[32],
 *                             const u8 merkle_root[32]);
 *   long tap_merkle_root(u8 out[32], const u8* leaf_hashes, u64 count,
 *                        const u8* control, u64 clen);
 *   __thread u8 *tagh_buf, *tap_preimg;   (lazy 4 MiB scratch, BMC_TLS_BUF
 *                                          convention, mirrors the .tbss)
 *
 * tagged_hash256: h = SHA256(tag); out = SHA256(h || h || msg).
 * tap_branch_hash: TapBranch over the lexicographically SORTED pair
 *   (cmpsb semantics: first differing byte decides; all-equal -> a first).
 * tap_leaf_hash: TapLeaf(ver || compactsize(slen) || script); rejects
 *   slen > TAP_PREIMG_CAP - 70 with 0 (out untouched), the x86's own bound.
 * taproot_tweak_pubkey: rejects internal_x >= p (BE byte compare) and
 *   t >= n; P = lift_x via pubkey_parse(0x02||x); Q = P + t*G (point_scalar_mul
 *   + point_add); affine; captures the tweaked Y parity BEFORE even-
 *   normalising and returns 1 (even Y) / 2 (odd Y) -- BIP341 control[0]&1
 *   commits to exactly this bit; negates Y (P - y, borrow chain) when odd.
 * tap_merkle_root: node = leaf_hashes[0]; then per control sibling
 *   (innermost first, control+33+i*32) node = TapBranch(sorted(node,sib)).
 *   count is ignored exactly as on x86 (callers pass 1); depth comes from
 *   clen: (clen-33)/32 when control non-null and clen >= 33.
 *
 * C twin per the escape hatch (TLS scratch + Core-quirk ordering); every
 * bound and rule transcribed.  Calls: sha256_full (sha256.S), pubkey_parse
 * (pubkey_schnorr_twin), point_scalar_mul/point_add (point_twin), fe_sqr/
 * fe_mul/fe_inv (fe_twin).
 * ==========================================================================*/
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint64_t u64;
typedef unsigned char u8;
typedef __uint128_t u128;

extern void sha256_full(u8* out, const void* msg, long long len);
extern int  pubkey_parse(const u8* pub, unsigned long plen, u64 qx[4], u64 qy[4]);
extern void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void point_add(u64 r[12], const u64 p[12], const u64 q[12]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);

#define TAP_PREIMG_CAP (4 * 1024 * 1024)

__thread u8* tagh_buf;
__thread u8* tap_preimg;

static void tls_init(void){
    if (!tagh_buf){
        tagh_buf = malloc(32);
        if (!tagh_buf) abort();
    }
    if (!tap_preimg){
        tap_preimg = malloc(TAP_PREIMG_CAP);
        if (!tap_preimg) abort();
    }
}

void tagged_hash256(u8* out, const char* tag, unsigned long long taglen,
                    const u8* msg, unsigned long long msglen){
    tls_init();
    sha256_full(tagh_buf, tag, (long long)taglen);
    memcpy(tap_preimg, tagh_buf, 32);
    memcpy(tap_preimg + 32, tagh_buf, 32);
    memcpy(tap_preimg + 64, msg, msglen);
    sha256_full(out, tap_preimg, (long long)(msglen + 64));
}

static const char TAPBRANCH_TAG[] = "TapBranch";

void tap_branch_hash(u8 out[32], const u8* a, const u8* b){
    u8 msg[64];
    if (memcmp(b, a, 32) < 0){          /* cmpsb: CF = b-a < 0 -> b first */
        memcpy(msg, b, 32);
        memcpy(msg + 32, a, 32);
    } else {                            /* a <= b -> a first */
        memcpy(msg, a, 32);
        memcpy(msg + 32, b, 32);
    }
    tagged_hash256(out, TAPBRANCH_TAG, sizeof TAPBRANCH_TAG - 1, msg, 64);
}

long tap_leaf_hash(u8 out[32], u8 ver, const u8* script, unsigned long long slen){
    tls_init();
    if (slen > (unsigned long long)(TAP_PREIMG_CAP - 70)) return 0;
    static const char TAPLEAF_TAG[] = "TapLeaf";
    u8* m = tap_preimg + 64;
    unsigned long long n = 0;
    m[n++] = ver;
    if (slen >= 0xfd){
        if (slen >= 0x10000){
            m[n++] = 0xfe;
            m[n++] = slen & 0xff; m[n++] = (slen >> 8) & 0xff;
            m[n++] = (slen >> 16) & 0xff; m[n++] = (slen >> 24) & 0xff;
        } else {
            m[n++] = 0xfd;
            m[n++] = slen & 0xff; m[n++] = (slen >> 8) & 0xff;
        }
    } else {
        m[n++] = (u8)slen;
    }
    memcpy(m + n, script, slen); n += slen;
    tagged_hash256(out, TAPLEAF_TAG, sizeof TAPLEAF_TAG - 1, m, n);
    return 1;
}

/* p (field prime) big-endian for the internal_x >= p range check */
static const u8 P_BE[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F };
static const u64 P_LIMBS[4] = {
    0xFFFFFFFEFFFFFC2Full, 0xFFFFFFFFFFFFFFFFull,
    0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull };

/* secp256k1 G, affine LE limbs (same table as the x86 G_AFF_TR / keys) */
static const u64 G_AFF_TR[8] = {
    0x59F2815B16F81798ull, 0x029BFCDB2DCE28D9ull,
    0x55A06295CE870B07ull, 0x79BE667EF9DCBBACull,
    0x9C47D08FFB10D4B8ull, 0xFD17B448A6855419ull,
    0x5DA4FBFC0E1108A8ull, 0x483ADA7726A3C465ull };

long taproot_tweak_pubkey(u8 out_x[32], const u8 internal_x[32],
                          const u8 merkle_root[32]){
    u8 msg[64], digest[32], kscr[33];
    u64 t[4], pj[12], tg[12], q[12], z2[4], zi[4], xr[4], yr[4];

    /* MSG = internal_x || [merkle_root] */
    memcpy(msg, internal_x, 32);
    unsigned long long mlen = 32;
    if (merkle_root){ memcpy(msg + 32, merkle_root, 32); mlen = 64; }

    static const char TAPTWEAK_TAG[] = "TapTweak";
    tagged_hash256(digest, TAPTWEAK_TAG, sizeof TAPTWEAK_TAG - 1, msg, mlen);

    /* t = BE digest -> 4 LE limbs (bswap per limb) */
    for (int j = 0; j < 4; j++){
        u64 v = 0;
        for (int k = 0; k < 8; k++) v = (v << 8) | digest[j*8 + k];
        t[3 - j] = v;
    }
    /* reject t >= n (limb-wise BE order: limb3 is most significant) */
    for (int j = 3; j >= 0; j--){
        static const u64 N_LIMBS[4] = {
            0xBFD25E8CD0364141ull, 0xBAAEDCE6AF48A03Bull,
            0xFFFFFFFFFFFFFFFEull, 0xFFFFFFFFFFFFFFFFull };
        if (t[j] > N_LIMBS[j]) return 0;
        if (t[j] < N_LIMBS[j]) break;
        if (j == 0) return 0;            /* t == n exactly -> reject */
    }

    /* reject internal_x >= p (BE byte compare) */
    for (int i = 0; i < 32; i++){
        if (internal_x[i] < P_BE[i]) break;
        if (internal_x[i] > P_BE[i]) return 0;
    }

    /* P = lift_x(internal) via pubkey_parse(0x02 || x) */
    kscr[0] = 0x02;
    memcpy(kscr + 1, internal_x, 32);
    u64 px[4], py[4];
    if (!pubkey_parse(kscr, 33, px, py)) return 0;

    /* PJ = (Px, Py, 1) Jacobian */
    memcpy(pj, px, 32);
    memcpy(pj + 4, py, 32);
    pj[8] = 1; pj[9] = 0; pj[10] = 0; pj[11] = 0;

    /* TG = t*G ; Q = PJ + TG */
    point_scalar_mul(tg, G_AFF_TR, t);
    point_add(q, pj, tg);
    if (!(q[8] | q[9] | q[10] | q[11])) return 0;    /* Q infinite */

    /* affine: z2 = Z^2, zi = 1/z2, xr = X*zi ; z3 = Z*z2, zi = 1/z3, yr = Y*zi */
    u64 z3[4];
    fe_sqr(z2, q + 8);
    fe_mul(z3, q + 8, z2);
    fe_inv(zi, z2);
    fe_mul(xr, q + 0, zi);
    fe_inv(zi, z3);
    fe_mul(yr, q + 4, zi);

    /* capture Y parity BEFORE even-normalising; negate Y (P - y) when odd */
    unsigned parity = 0;
    if (yr[0] & 1){
        parity = 1;
        u64 borrow = 0;
        for (int i = 0; i < 4; i++){
            u128 s = (u128)P_LIMBS[i] - yr[i] - borrow;
            yr[i] = (u64)s;
            borrow = (u64)((s >> 64) & 1);
        }
    }

    /* out_x = BE bytes of xr */
    for (int j = 0; j < 4; j++){
        u64 v = xr[3 - j];
        for (int k = 0; k < 8; k++) out_x[j*8 + k] = (u8)(v >> (56 - 8*k));
    }
    return 1 + (long)parity;             /* 1 even Y, 2 odd Y */
}

long tap_merkle_root(u8 out[32], const u8* leaf_hashes, unsigned long long count,
                     const u8* control, unsigned long long clen){
    (void)count;                          /* ignored exactly as on x86 */
    unsigned long long depth = 0;
    if (control && clen >= 33) depth = (clen - 33) / 32;
    u8 node[32], msg[64], tmp[32];
    memcpy(node, leaf_hashes, 32);
    for (unsigned long long i = 0; i < depth; i++){
        const u8* sib = control + 33 + i * 32;
        if (memcmp(sib, node, 32) < 0){   /* CF = sib - node < 0 -> sib first */
            memcpy(msg, sib, 32);
            memcpy(msg + 32, node, 32);
        } else {
            memcpy(msg, node, 32);
            memcpy(msg + 32, sib, 32);
        }
        tagged_hash256(tmp, TAPBRANCH_TAG, sizeof TAPBRANCH_TAG - 1, msg, 64);
        memcpy(node, tmp, 32);
    }
    memcpy(out, node, 32);
    return 1;
}
