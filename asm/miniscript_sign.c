/* miniscript_sign.c -- witnesses for miniscript-locked inputs (see the header). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "miniscript.h"
#include "miniscript_sign.h"
typedef unsigned char u8;
extern void hash160(u8 out[20], const void* in, long long len);
extern int  wallet_ecdsa_sign(unsigned long long out_r[4], unsigned long long out_s[4], const u8 z[32], const u8 priv[32]);
extern int  der_signature_export(u8* out, const unsigned long long r[4], const unsigned long long s[4]);
extern int  bip340_sign(u8 sig[64], const u8* msg, unsigned long msglen, const u8 priv_be[32], const u8 aux[32]);
extern int  bip32_pubkey_decompress(const u8 pub33[33], u8 out65[65]);

/* the key table the script decodes against: every pubkey the script names,
 * with the signer's private key when it holds one */
#define SK_MAX 1024
typedef struct { u8 pub[33]; int have_priv; int kidx; } skey_t;
typedef struct {
    int tap;
    skey_t* keys; int n;
    unsigned char (*kpriv)[32]; unsigned char (*kpub)[33]; const int* ncomp; int nkeys;
    const unsigned char (*pubs)[33]; int npubs;
    const u8* z; int hashtype; unsigned seq; unsigned long locktime;
    const ms_preimages_t* pre;
} sctx_t;
static int sk_find_or_add(sctx_t* c, const u8 pub[33]){
    for (int i = 0; i < c->n; i++) if (!memcmp(c->keys[i].pub, pub, 33)) return i;
    if (c->n >= SK_MAX) return -1;
    skey_t* k = &c->keys[c->n]; memcpy(k->pub, pub, 33); k->have_priv = 0; k->kidx = -1;
    for (int h = 0; h < c->nkeys; h++){
        if (c->tap){ if (!memcmp(c->kpub[h] + 1, pub + 1, 32)){ k->have_priv = 1; k->kidx = h; break; } }
        else if (c->ncomp[h] && !memcmp(c->kpub[h], pub, 33)){ k->have_priv = 1; k->kidx = h; break; }
    }
    return c->n++;
}
static int s_key_from_str(void* u, const char* s, size_t n, int* key, char* err, size_t errcap){ (void)u; (void)s; (void)n; (void)key; (void)err; (void)errcap; return 0; }
static int s_key_from_bytes(void* u, const u8* b, size_t n, int* key){
    sctx_t* c = u; u8 pub[33];
    if (c->tap){ if (n != 32) return 0; pub[0] = 2; memcpy(pub + 1, b, 32); }
    else { if (n != 33 || (b[0] != 2 && b[0] != 3)) return 0; memcpy(pub, b, 33); }
    int k = sk_find_or_add(c, pub); if (k < 0) return 0; *key = k; return 1;
}
static int s_key_from_hash(void* u, const u8 h[20], int* key){
    sctx_t* c = u;
    /* keys named by hash resolve against what the signer knows: its own keys and the pubkeys the
     * descriptor/PSBT supplied (Core: the SigningProvider's GetPubKey) */
    for (int q = 0; q < c->nkeys; q++){
        u8 hh[20];
        if (c->tap) hash160(hh, c->kpub[q] + 1, 32); else { if (!c->ncomp[q]) continue; hash160(hh, c->kpub[q], 33); }
        if (!memcmp(hh, h, 20)){ int k = sk_find_or_add(c, c->kpub[q]); if (k < 0) return 0; *key = k; return 1; }
    }
    for (int q = 0; q < c->npubs; q++){
        u8 hh[20]; if (c->tap) hash160(hh, c->pubs[q] + 1, 32); else hash160(hh, c->pubs[q], 33);
        if (!memcmp(hh, h, 20)){ int k = sk_find_or_add(c, c->pubs[q]); if (k < 0) return 0; *key = k; return 1; }
    }
    return 0;
}
static int s_key_bytes(void* u, int key, u8 out[33], int* n){ sctx_t* c = u; if (c->tap){ memcpy(out, c->keys[key].pub + 1, 32); *n = 32; } else { memcpy(out, c->keys[key].pub, 33); *n = 33; } return 1; }
static int s_key_hash(void* u, int key, u8 out[20]){ u8 b[33]; int n; s_key_bytes(u, key, b, &n); hash160(out, b, n); return 1; }
static int s_key_to_str(void* u, int key, char* out, size_t cap){ sctx_t* c = u; if (cap < 67) return 0; u8 b[33]; int n; s_key_bytes(u, key, b, &n); for (int i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]); out[2 * n] = 0; (void)c; return 1; }
static int s_key_cmp(void* u, int a, int b){ sctx_t* c = u; return memcmp(c->keys[a].pub, c->keys[b].pub, 33); }

static int s_sign(void* u, int key, u8* sig, size_t* siglen, size_t cap){
    sctx_t* c = u; skey_t* k = &c->keys[key];
    if (!k->have_priv) return MS_AVAIL_NO;
    if (c->tap){
        if (cap < 65) return MS_AVAIL_NO;
        u8 aux[32] = { 0 };
        if (!bip340_sign(sig, c->z, 32, c->kpriv[k->kidx], aux)) return MS_AVAIL_NO;
        if (c->hashtype){ sig[64] = (u8)c->hashtype; *siglen = 65; } else *siglen = 64;
        return MS_AVAIL_YES;
    }
    if (cap < 74) return MS_AVAIL_NO;
    unsigned long long r[4], s[4]; wallet_ecdsa_sign(r, s, c->z, c->kpriv[k->kidx]);
    int dl = der_signature_export(sig, r, s); sig[dl++] = (u8)c->hashtype; *siglen = (size_t)dl;
    return MS_AVAIL_YES;
}
/* BIP68 / BIP65 as the interpreter will judge them */
static int s_older(void* u, uint32_t k){
    sctx_t* c = u; uint32_t seq = c->seq;
    if (seq & 0x80000000u) return 0;
    if ((k & (1u << 22)) != (seq & (1u << 22))) return 0;
    return (k & 0xffff) <= (seq & 0xffff);
}
static int s_after(void* u, uint32_t k){
    sctx_t* c = u;
    if ((k < 500000000u) != (c->locktime < 500000000u)) return 0;
    if ((unsigned long)k > c->locktime) return 0;
    return c->seq != 0xffffffffu;
}
static int s_preimage(void* u, int frag, const u8* hash, u8 out[32]){
    sctx_t* c = u; if (!c->pre) return MS_AVAIL_NO;
    int hl = (frag == MS_SHA256 || frag == MS_HASH256) ? 32 : 20;
    for (int i = 0; i < c->pre->n; i++) if (c->pre->hlen[i] == hl && !memcmp(c->pre->hash[i], hash, (size_t)hl)){ memcpy(out, c->pre->pre[i], 32); return MS_AVAIL_YES; }
    return MS_AVAIL_NO;
}

static int sign_common(int tap, const u8* script, size_t sl, const u8 z[32], int hashtype, unsigned seq, unsigned long locktime,
                       unsigned char (*kpriv)[32], unsigned char (*kpub)[33], const int* ncomp, int nkeys,
                       const unsigned char (*pubs)[33], int npubs, const ms_preimages_t* pre,
                       u8* wit, unsigned long witcap, unsigned long* witlen, int* wititems, const char** err){
    static skey_t keys[SK_MAX];            /* the raw signer is single-threaded (its own buffers are static too) */
    sctx_t c; memset(&c, 0, sizeof c);
    c.tap = tap; c.keys = keys; c.n = 0; c.kpriv = kpriv; c.kpub = kpub; c.ncomp = ncomp; c.nkeys = nkeys;
    c.z = z; c.hashtype = hashtype; c.seq = seq; c.locktime = locktime; c.pre = pre; c.pubs = pubs; c.npubs = npubs;
    ms_ctx_t ctx; memset(&ctx, 0, sizeof ctx); ctx.user = &c;
    ctx.key_from_str = s_key_from_str; ctx.key_from_bytes = s_key_from_bytes; ctx.key_from_hash = s_key_from_hash;
    ctx.key_bytes = s_key_bytes; ctx.key_hash = s_key_hash; ctx.key_to_str = s_key_to_str; ctx.key_cmp = s_key_cmp;
    ms_tree_t t; ms_tree_init(&t, tap);
    int root = ms_decode(&t, &ctx, script, sl);
    if (root < 0){ ms_tree_free(&t); return 0; }
    ms_sat_ctx_t sc = { &c, s_sign, s_older, s_after, s_preimage };
    ms_witness_t w = { 0 };
    int av = ms_satisfy(&t, &ctx, &sc, root, 1, &w);
    int ok = 0;
    if (av != MS_AVAIL_YES){
        /* say why, the way Core's PSBT analysis would */
        int any_key = 0; for (int i = 0; i < c.n; i++) if (c.keys[i].have_priv) any_key = 1;
        *err = !any_key ? "Keys not provided for this input" : "Missing signatures, preimages or unmet timelocks for this miniscript input";
    } else if (w.len > witcap){ *err = "witness too large"; }
    else { memcpy(wit, w.buf, w.len); *witlen = w.len; *wititems = w.nelems; ok = 1; }
    ms_witness_free(&w); ms_tree_free(&t);
    return ok ? 1 : -1;
}
int ms_sign_witness_v0(const u8* ws, size_t wl, const u8 z[32], int hashtype, unsigned seq, unsigned long locktime,
                       unsigned char (*kpriv)[32], unsigned char (*kpub)[33], const int* ncomp, int nkeys,
                       const unsigned char (*pubs)[33], int npubs, const ms_preimages_t* pre,
                       u8* wit, unsigned long witcap, unsigned long* witlen, int* wititems, const char** err){
    return sign_common(0, ws, wl, z, hashtype, seq, locktime, kpriv, kpub, ncomp, nkeys, pubs, npubs, pre, wit, witcap, witlen, wititems, err);
}
int ms_sign_witness_tapleaf(const u8* leaf, size_t ll, const u8 z[32], int hashtype, unsigned seq, unsigned long locktime,
                            unsigned char (*kpriv)[32], unsigned char (*kpub)[33], int nkeys,
                            const unsigned char (*pubs)[33], int npubs, const ms_preimages_t* pre,
                            u8* wit, unsigned long witcap, unsigned long* witlen, int* wititems, const char** err){
    static int ones[SK_MAX]; for (int i = 0; i < nkeys && i < SK_MAX; i++) ones[i] = 1;
    return sign_common(1, leaf, ll, z, hashtype, seq, locktime, kpriv, kpub, ones, nkeys, pubs, npubs, pre, wit, witcap, witlen, wititems, err);
}
