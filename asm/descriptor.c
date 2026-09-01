/* descriptor.c -- output script descriptors, Core's descriptor.cpp in C.
 *
 * Parsing is a recursive descent over the descriptor text with the same
 * context rules Core enforces (what may appear at top level, inside sh(),
 * inside wsh(), inside tr()), the same key rules (uncompressed keys only
 * where legacy scripts allow them, x-only keys inside tr()), and the same
 * limits (3 keys in bare multisig, 20 in CHECKMULTISIG, 520-byte P2SH
 * redeem scripts). Expansion produces Core's exact scriptPubKeys, proven
 * against 43 of Core's own descriptor_tests.cpp vectors
 * (tests/test_descriptor_vectors.c); the miniscript and musig() forms are
 * refused by name rather than half-parsed. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "descriptor.h"

typedef unsigned char u8;
extern void hash160(u8 out[20], const void* in, long long len);
extern void sha256_full(u8 out[32], const void* msg, unsigned long len);
extern int  wallet_base58check_decode(u8* out, long cap, long* outlen, const char* str);
extern void base58check_encode(char* out, const u8* payload, long long paylen);
extern void scalar_to_pubkey(u8 pub[33], const u8 k[32]);
extern int  bip32_ckd_priv(u8 k[32], u8 c[32], const u8 kpar[32], const u8 cpar[32], unsigned index);
extern int  bip32_ckdpub_step_pub(const u8 Kpar[33], const u8 ccpar[32], unsigned index, u8 Kout[33], u8 ccout[32]);
extern int  bip32_pubkey_decompress(const u8 pub33[33], u8 out65[65]);
extern int  pubkey_parse(const u8* pub, unsigned long publen, uint64_t qx[4], uint64_t qy[4]);
extern int  bip32_xonly_tweak_add(const u8 x[32], const u8 t[32], u8 out_x[32]);
#include "musig2.h"
/* BIP390: the chaincode of the synthetic xpub a musig() derives from */
static const u8 MUSIG_CC[32] = { 0x86,0x80,0x87,0xca,0x02,0xa6,0xf9,0x74,0xc4,0x59,0x89,0x24,0xc3,0x6b,0x57,0x76,
                                 0x2d,0x32,0xcb,0x45,0x71,0x71,0x67,0xe3,0x00,0x62,0x2c,0x71,0x67,0xe3,0x89,0x65 };

/* BIP340 tagged hashes in plain C (the consensus taproot kernel keeps its
 * scratch in thread-local storage, which is the wrong dependency for an
 * RPC-side engine that must link into any thread) */
static void tagged_hash(u8 out[32], const char* tag, const u8* a, unsigned long alen, const u8* b, unsigned long blen){
    u8 th[32]; sha256_full(th, tag, strlen(tag));
    u8* buf = malloc(64 + alen + blen + 1); if (!buf){ memset(out, 0, 32); return; }
    unsigned long n = 0;
    memcpy(buf, th, 32); memcpy(buf + 32, th, 32); n = 64;
    memcpy(buf + n, a, alen); n += alen;
    if (b && blen){ memcpy(buf + n, b, blen); n += blen; }
    sha256_full(out, buf, n);
    free(buf);
}
static long tap_leaf_hash(u8 out[32], u8 leaf_version, const u8* script, uint64_t slen){
    u8 pre[4]; int pl = 0; pre[pl++] = leaf_version;   /* [4]: a leaf of 253+ bytes needs the 0xfd form (miniscript leaves can) */
    if (slen < 0xfd) pre[pl++] = (u8)slen; else { pre[pl++] = 0xfd; pre[pl++] = (u8)slen; pre[pl++] = (u8)(slen >> 8); }
    if (slen > 65535) return 0;
    u8* tmp = malloc(4 + (size_t)slen); if (!tmp) return 0;
    memcpy(tmp, pre, (size_t)pl); memcpy(tmp + pl, script, (size_t)slen);
    tagged_hash(out, "TapLeaf", tmp, (unsigned long)(pl + slen), NULL, 0);
    free(tmp);
    return 1;
}
static long tap_branch_hash(u8 out[32], const u8* a, const u8* b){
    if (memcmp(a, b, 32) <= 0) tagged_hash(out, "TapBranch", a, 32, b, 32);
    else                       tagged_hash(out, "TapBranch", b, 32, a, 32);
    return 1;
}
/* 1 on success (parity is not needed for a scriptPubKey), 0 on failure */
static long taproot_tweak_pubkey(u8* out_x, const u8* internal_x, const u8* merkle_root){
    u8 t[32];
    tagged_hash(t, "TapTweak", internal_x, 32, merkle_root, merkle_root ? 32 : 0);
    return bip32_xonly_tweak_add(internal_x, t, out_x) ? 1 : 0;
}
extern int  wallet_validate_address(const char* str, int* type_, u8* version, u8 h160[20], u8 prog32[32]);

static char g_err[256];
const char* descr_last_error(void){ return g_err; }
#define ERR(...) do{ snprintf(err, errcap, __VA_ARGS__); return 0; }while(0)
#define ERRN(...) do{ snprintf(err, errcap, __VA_ARGS__); return -1; }while(0)

/* ---- checksum (BIP380) ------------------------------------------------- */
static uint64_t polymod(uint64_t c, int val){
    u8 c0 = (u8)(c >> 35);
    c = ((c & 0x7ffffffffULL) << 5) ^ (uint64_t)val;
    if (c0 & 1)  c ^= 0xf5dee51989ULL;
    if (c0 & 2)  c ^= 0xa9fdca3312ULL;
    if (c0 & 4)  c ^= 0x1bab10e32dULL;
    if (c0 & 8)  c ^= 0x3706b1677aULL;
    if (c0 & 16) c ^= 0x644d626ffdULL;
    return c;
}
int descr_checksum(const char* span, char out[9]){
    static const char* IN =
        "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    static const char* CK = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    uint64_t c = 1; int cls = 0, clscount = 0;
    for (const char* p = span; *p; p++){
        const char* q = strchr(IN, *p); if (!q) return 0;
        int pos = (int)(q - IN);
        c = polymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        if (++clscount == 3){ c = polymod(c, cls); cls = 0; clscount = 0; }
    }
    if (clscount > 0) c = polymod(c, cls);
    for (int j = 0; j < 8; ++j) c = polymod(c, 0);
    c ^= 1;
    for (int j = 0; j < 8; ++j) out[j] = CK[(c >> (5 * (7 - j))) & 31];
    out[8] = 0;
    return 1;
}

/* ---- small helpers ---------------------------------------------------- */
static int hex1(int c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
static int hex_decode(const char* s, size_t n, u8* out, size_t cap){
    if (n & 1 || n/2 > cap) return -1;
    for (size_t i = 0; i < n/2; i++){ int h = hex1(s[2*i]), l = hex1(s[2*i+1]); if (h<0||l<0) return -1; out[i] = (u8)((h<<4)|l); }
    return (int)(n/2);
}
static void hex_encode(char* out, const u8* b, int n){ static const char* H="0123456789abcdef"; for (int i=0;i<n;i++){ out[2*i]=H[b[i]>>4]; out[2*i+1]=H[b[i]&15]; } out[2*n]=0; }
/* split s[0..n) at top-level commas (not inside () {} []); returns count */
static int split_args(const char* s, size_t n, const char** as, size_t* al, int cap){
    int depth = 0, cnt = 0; size_t start = 0;
    for (size_t i = 0; i <= n; i++){
        char c = i < n ? s[i] : ',';
        if (i < n && (c=='('||c=='{'||c=='[')) depth++;
        else if (i < n && (c==')'||c=='}'||c==']')) depth--;
        else if (c == ',' && depth == 0){
            if (cnt >= cap) return -1;
            as[cnt] = s + start; al[cnt] = i - start; cnt++; start = i + 1;
        }
    }
    return cnt;
}
static int push_data(u8* out, int o, int cap, const u8* d, int n){
    if (n < 0x4c){ if (o + 1 + n > cap) return -1; out[o++] = (u8)n; }
    else if (n <= 0xff){ if (o + 2 + n > cap) return -1; out[o++] = 0x4c; out[o++] = (u8)n; }
    else { if (o + 3 + n > cap) return -1; out[o++] = 0x4d; out[o++] = (u8)n; out[o++] = (u8)(n>>8); }
    memcpy(out + o, d, (size_t)n); return o + n;
}
static int push_num(u8* out, int o, int cap, int v){
    if (v == 0){ if (o+1>cap) return -1; out[o++] = 0x00; return o; }
    if (v >= 1 && v <= 16){ if (o+1>cap) return -1; out[o++] = (u8)(0x50 + v); return o; }
    u8 b[4]; int n = 0; int x = v;
    while (x){ b[n++] = (u8)(x & 0xff); x >>= 8; }
    if (b[n-1] & 0x80) b[n++] = 0;
    return push_data(out, o, cap, b, n);
}

/* ---- miniscript key context ------------------------------------------- */
static int add_key(descr_t* d, const char* s, size_t n, int ctx, char* err, unsigned long errcap);
static int key_pub_at(const descr_t* d, const descr_key_t* k, long idx, u8 pub[65], int* publen);
static int key_bytes(const descr_t* d, int ki, long idx, int xonly, u8 out[65], int* n);
static void sb_key_to(const descr_t* d, int ki, int with_priv, char* out, unsigned long cap);
static int dms_key_from_str(void* u, const char* s, size_t n, int* key, char* err, size_t errcap){
    descr_msuser_t* m = (descr_msuser_t*)u;
    int k = add_key((descr_t*)m->d, s, n, m->tr ? 3 /* CTX_TR */ : 2 /* CTX_WSH */, err, errcap);
    if (k < 0){ m->key_err = 1; return 0; }
    *key = k; return 1;
}
static int dms_key_from_bytes(void* u, const u8* b, size_t n, int* key){ (void)u; (void)b; (void)n; (void)key; return 0; }
static int dms_key_from_hash(void* u, const u8 h[20], int* key){ (void)u; (void)h; (void)key; return 0; }
static int dms_key_bytes(void* u, int key, u8 out[33], int* n){
    descr_msuser_t* m = (descr_msuser_t*)u; u8 kb[65]; int kl;
    if (!key_bytes(m->d, key, m->idx, m->tr, kb, &kl)) return 0;
    if (kl > 33) return 0;
    memcpy(out, kb, (size_t)kl); *n = kl; return 1;
}
static int dms_key_hash(void* u, int key, u8 out[20]){ u8 kb[33]; int n; if (!dms_key_bytes(u, key, kb, &n)) return 0; hash160(out, kb, n); return 1; }
static int dms_key_to_str(void* u, int key, char* out, size_t cap){ descr_msuser_t* m = (descr_msuser_t*)u; sb_key_to(m->d, key, m->with_priv, out, cap); return out[0] != 0; }
/* Core's KeyParser::KeyCompare: the pubkeys at index 0 */
static int dms_key_cmp(void* u, int a, int b){
    descr_msuser_t* m = (descr_msuser_t*)u; u8 pa[65], pb[65]; int la = 0, lb = 0;
    int oa = key_bytes(m->d, a, 0, 0, pa, &la), ob = key_bytes(m->d, b, 0, 0, pb, &lb);
    if (!oa || !ob) return a - b;
    int c = memcmp(pa, pb, (size_t)(la < lb ? la : lb)); if (c) return c; return la - lb;
}
void descr_ms_tree(const descr_t* d, ms_tree_t* out){
    memset(out, 0, sizeof *out);
    out->nodes = (ms_node_t*)d->msnodes; out->nn = d->msnn; out->ncap = MS_DESC_NODES;
    out->subs = (int32_t*)d->mssubs; out->ns = d->msns; out->scap = MS_DESC_SUBS;
    out->keys = (int32_t*)d->mskeys; out->nk = d->msnk; out->kcap = MS_DESC_KEYS;
    out->growable = 0; out->tapscript = d->ms_tapscript;
}
void descr_ms_ctx(const descr_t* d, long idx, int with_priv, descr_msuser_t* u, ms_ctx_t* ctx){
    memset(u, 0, sizeof *u); u->d = d; u->idx = idx; u->tr = d->ms_tapscript; u->with_priv = with_priv;
    memset(ctx, 0, sizeof *ctx); ctx->user = u;
    ctx->key_from_str = dms_key_from_str; ctx->key_from_bytes = dms_key_from_bytes; ctx->key_from_hash = dms_key_from_hash;
    ctx->key_bytes = dms_key_bytes; ctx->key_hash = dms_key_hash; ctx->key_to_str = dms_key_to_str; ctx->key_cmp = dms_key_cmp;
}

/* ---- key expressions -------------------------------------------------- */
/* one path element "N", "Nh", "N'" -> value with the hardened bit; 1 ok / 0 err */
static int parse_path_num(const char* s, size_t cl, int* apostrophe, unsigned* out, char* err, unsigned long errcap){
    if (cl == 0) ERR("Key path value is not a valid uint32");
    int hard = 0; char last = s[cl-1];
    if (last == '\'' || last == 'h' || last == 'H'){ hard = 1; cl--; if (last == '\'') *apostrophe = 1; else *apostrophe = 0; }
    if (cl == 0) ERR("Key path value is not a valid uint32");
    unsigned long long v = 0;
    for (size_t q = 0; q < cl; q++){
        if (s[q] < '0' || s[q] > '9'){ char t[48]; size_t m = cl < 40 ? cl : 40; memcpy(t, s, m); t[m]=0; ERR("Key path value '%s' is not a valid uint32", t); }
        v = v * 10 + (unsigned)(s[q]-'0'); if (v > 0xffffffffULL) ERR("Key path value %llu is out of range", v);
    }
    if (v > 0x7fffffffULL) ERR("Key path value %llu is out of range", v);
    *out = (unsigned)v | (hard ? 0x80000000u : 0);
    return 1;
}
static int parse_path_elems_mp(const char* s, size_t n, unsigned* path, int* plen, int* ranged, int* range_hard,
                               int* apostrophe, int allow_range, int allow_mp, int* mp_pos, int* mp_n, unsigned* mp_vals,
                               char* err, unsigned long errcap){
    /* s = "/a/b'/<c;d>/.../STAR" (STAR = the range marker) -- s[0] is '/' */
    size_t i = 0; *plen = 0; *ranged = 0; *range_hard = 0; *mp_pos = -1; *mp_n = 0;
    while (i < n){
        if (s[i] != '/') ERR("Key path value is not a valid uint32");
        i++;
        size_t j = i; while (j < n && s[j] != '/') j++;
        size_t cl = j - i;
        if (cl == 0) ERR("Key path value is not a valid uint32");
        if (s[i] == '<' && s[j-1] == '>'){                       /* BIP389 multipath element */
            if (!allow_mp){ char t[64]; size_t m = cl < 60 ? cl : 60; memcpy(t, s+i, m); t[m]=0; ERR("Key path value '%s' specifies multipath in a section where multipath is not allowed", t); }
            if (*mp_pos >= 0) ERR("Multiple multipath key path specifiers found");
            size_t a = i + 1, e = j - 1; int cnt = 0;
            if (a >= e) ERR("Multipath key path specifiers must have at least two items");      /* "<>" */
            while (a <= e){
                size_t b = a; while (b < e && s[b] != ';') b++;
                if (cnt >= DESCR_MP_MAX) ERR("Multipath key path specifier has too many items");
                if (b == a) ERR("Key path value '' is not a valid uint32");
                unsigned v; if (!parse_path_num(s + a, b - a, apostrophe, &v, err, errcap)) return 0;
                for (int q = 0; q < cnt; q++) if (mp_vals[q] == v) ERR("Duplicated key path value %u in multipath specifier", v & 0x7fffffffu);
                mp_vals[cnt++] = v;
                if (b >= e) break;
                a = b + 1;
                if (a >= e) ERR("Key path value '' is not a valid uint32");
            }
            if (cnt < 2) ERR("Multipath key path specifiers must have at least two items");
            if (*plen >= DESCR_MAX_PATH) ERR("Key path too deep");
            *mp_pos = *plen; *mp_n = cnt; path[(*plen)++] = mp_vals[0];
            i = j; continue;
        }
        int hard = 0;
        char last = s[j-1];
        if (last == '\'' || last == 'h' || last == 'H'){ hard = 1; cl--; if (last == '\'') *apostrophe = 1; else *apostrophe = 0; }
        if (cl == 1 && s[i] == '*'){
            if (!allow_range) ERR("Key path value '*' is not a valid uint32");
            if (j != n) ERR("'*' must be the last path element");   /* Core: Multipath/range must be last */
            *ranged = 1; *range_hard = hard; return 1;
        }
        unsigned long long v = 0;
        for (size_t q = 0; q < cl; q++){
            if (s[i+q] < '0' || s[i+q] > '9'){ char t[48]; size_t m = cl < 40 ? cl : 40; memcpy(t, s+i, m); t[m]=0; ERR("Key path value '%s' is not a valid uint32", t); }
            v = v * 10 + (unsigned)(s[i+q]-'0'); if (v > 0xffffffffULL) ERR("Key path value %llu is out of range", v);
        }
        if (v > 0x7fffffffULL) ERR("Key path value %llu is out of range", v);
        if (*plen >= DESCR_MAX_PATH) ERR("Key path too deep");
        path[(*plen)++] = (unsigned)v | (hard ? 0x80000000u : 0);
        i = j;
    }
    return 1;
}
static int parse_path_elems(const char* s, size_t n, unsigned* path, int* plen, int* ranged, int* range_hard,
                            int* apostrophe, int allow_range, char* err, unsigned long errcap){
    int mp = -1, mn = 0; unsigned mv[DESCR_MP_MAX];
    return parse_path_elems_mp(s, n, path, plen, ranged, range_hard, apostrophe, allow_range, 0, &mp, &mn, mv, err, errcap);
}

static int parse_key(const char* s, size_t n, int ctx_tr, int allow_range, descr_key_t* k, char* err, unsigned long errcap){
    memset(k, 0, sizeof *k); k->apostrophe = 1;
    size_t i = 0;
    if (n && s[0] == '['){
        size_t rb = 1; while (rb < n && s[rb] != ']') rb++;
        if (rb >= n) ERR("Key origin start '[' with no matching ']'");
        /* [fp/path] */
        if (rb - 1 < 8) ERR("Fingerprint is not 4 bytes (%zu characters instead of 8 characters)", rb - 1 < 8 ? rb - 1 : 8);
        if (hex_decode(s + 1, 8, k->origin_fp, 4) != 4) ERR("Fingerprint '%.8s' is not hex", s + 1);
        int rg, rh;
        if (rb - 9 > 0){
            if (s[9] != '/') ERR("Fingerprint is not 4 bytes (%zu characters instead of 8 characters)", rb - 1);
            if (!parse_path_elems(s + 9, rb - 9, k->origin, &k->origin_len, &rg, &rh, &k->apostrophe, 0, err, errcap)) return 0;
        }
        k->has_origin = 1; i = rb + 1;
    }
    size_t j = i; while (j < n && s[j] != '/') j++;
    size_t kl = j - i; const char* kb = s + i;
    if (kl == 0) ERR("No key provided");
    char key[1400]; if (kl >= sizeof key) ERR("Key too long");
    memcpy(key, kb, kl); key[kl] = 0;
    int ok = 0;
    /* hex pubkey */
    if (kl == 66 || kl == 130 || (kl == 64 && ctx_tr)){
        int good = 1; for (size_t q = 0; q < kl; q++) if (hex1(key[q]) < 0) good = 0;
        if (good){
            u8 b[65]; int bl = hex_decode(key, kl, b, 65);
            if (kl == 130 && (b[0] == 0x06 || b[0] == 0x07)) ERR("Hybrid public keys are not allowed");
            if (kl == 64){ memcpy(k->pub, b, 32); k->publen = 32; k->xonly = 1; k->compressed = 1;
                           u8 c[33]; c[0] = 0x02; memcpy(c+1, b, 32); uint64_t qx[4], qy[4];
                           if (!pubkey_parse(c, 33, qx, qy)) ERR("Pubkey '%s' is invalid", key); }
            else { uint64_t qx[4], qy[4];
                   if (!pubkey_parse(b, (unsigned long)bl, qx, qy)) ERR("Pubkey '%s' is invalid", key);
                   memcpy(k->pub, b, (size_t)bl); k->publen = bl; k->compressed = (bl == 33); }
            k->kind = DK_HEX; ok = 1;
        }
    }
    if (!ok){
        u8 dec[128]; long dl = 0;
        if (wallet_base58check_decode(dec, sizeof dec, &dl, key)){
            if (dl == 78 && ((dec[0]==0x04&&dec[1]==0x88&&dec[2]==0xB2&&dec[3]==0x1E) || (dec[0]==0x04&&dec[1]==0x88&&dec[2]==0xAD&&dec[3]==0xE4) ||
                             (dec[0]==0x04&&dec[1]==0x35&&dec[2]==0x87&&dec[3]==0xCF) || (dec[0]==0x04&&dec[1]==0x35&&dec[2]==0x83&&dec[3]==0x94))){
                int priv = (dec[3]==0xE4 || dec[3]==0x94);
                memcpy(k->ver, dec, 4); k->depth = dec[4]; memcpy(k->parentfp, dec+5, 4);
                k->child = ((unsigned)dec[9]<<24)|((unsigned)dec[10]<<16)|((unsigned)dec[11]<<8)|dec[12];
                memcpy(k->cc, dec+13, 32);
                k->testnet = (dec[1] == 0x35);
                if (priv){
                    if (dec[45] != 0) ERR("key '%s' is not valid", key);
                    memcpy(k->xkey, dec+46, 32); k->kind = DK_XPRV; k->has_priv = 1;
                    scalar_to_pubkey(k->pub, k->xkey); k->publen = 33;
                } else {
                    uint64_t qx[4], qy[4];
                    if ((dec[45] != 0x02 && dec[45] != 0x03) || !pubkey_parse(dec+45, 33, qx, qy)) ERR("key '%s' is not valid", key);
                    memcpy(k->pub, dec+45, 33); k->publen = 33; k->kind = DK_XPUB;
                }
                k->compressed = 1; ok = 1;
            } else if ((dl == 33 || dl == 34) && (dec[0] == 0x80 || dec[0] == 0xef)){
                if (dl == 34 && dec[33] != 0x01) ERR("key '%s' is not valid", key);
                memcpy(k->priv, dec+1, 32); k->compressed = (dl == 34); k->testnet = (dec[0] == 0xef);
                k->kind = DK_WIF; k->has_priv = 1;
                scalar_to_pubkey(k->pub, k->priv); k->publen = 33;
                if (!k->compressed){ u8 u[65]; if (!bip32_pubkey_decompress(k->pub, u)) ERR("key '%s' is not valid", key); memcpy(k->pub, u, 65); k->publen = 65; }
                ok = 1;
            }
        }
    }
    if (!ok) ERR("key '%s' is not valid", key);
    if (j < n){
        if (k->kind == DK_HEX || k->kind == DK_WIF) ERR("Key path is not allowed for a non-extended key");   /* Core: "... is not valid" -- kept specific */
        if (!parse_path_elems_mp(s + j, n - j, k->path, &k->pathlen, &k->ranged, &k->range_hard, &k->apostrophe, allow_range, 1, &k->mp_pos, &k->mp_n, k->mp_vals, err, errcap)) return 0;
    } else k->mp_pos = -1;
    return 1;
}

/* ---- script expressions ----------------------------------------------- */
enum { CTX_TOP = 0, CTX_SH = 1, CTX_WSH = 2, CTX_TR = 3 };

static int new_node(descr_t* d, int type, char* err, unsigned long errcap){
    if (d->nn >= DESCR_MAX_NODES) ERRN("Descriptor too complex");
    descr_node_t* n = &d->nodes[d->nn]; memset(n, 0, sizeof *n); n->type = type; n->child[0] = n->child[1] = -1;
    return d->nn++;
}
static int add_key(descr_t* d, const char* s, size_t n, int ctx, char* err, unsigned long errcap){
    if (d->nk >= DESCR_MAX_KEYS) ERRN("Too many keys in descriptor");
    if (n >= 6 && !memcmp(s, "musig(", 6)){
        /* BIP390 musig(KEY,...)[/path][/ *] -- Core's ParsePubkey rules and messages */
        if (ctx != CTX_TR) ERRN("musig() is only allowed in tr() and rawtr()");
        size_t close = 0; int nclose = 0;
        for (size_t i = 0; i < n; i++) if (s[i] == ')'){ if (!nclose) close = i; nclose++; }
        if (nclose > 1) ERRN("Too many ')' in musig() expression");
        if (nclose == 0) ERRN("Invalid musig() expression");
        const char* in = s + 6; size_t il = close - 6;
        const char* rest = s + close + 1; size_t rl = n - close - 1;
        int slot = d->nk++;                                   /* the aggregate's own slot, reserved first */
        descr_key_t* k = &d->keys[slot]; memset(k, 0, sizeof *k);
        k->kind = DK_MUSIG; k->compressed = 1; k->tr_ctx = 1; k->apostrophe = 1; k->mp_pos = -1;
        const char* as[DESCR_MUSIG_MAX + 1]; size_t al[DESCR_MUSIG_MAX + 1];
        int na = il == 0 ? 0 : split_args(in, il, as, al, DESCR_MUSIG_MAX + 1);
        if (na < 0) ERRN("musig(): too many participants");
        if (na == 0) ERRN("musig(): Must contain key expressions");
        int all_bip32 = 1, any_ranged = 0, any_priv = 0;
        for (int q = 0; q < na; q++){
            if (al[q] >= 6 && !memcmp(as[q], "musig(", 6)) ERRN("musig(): musig() is only allowed in tr() and rawtr()");
            char e2[512];
            int pk = add_key(d, as[q], al[q], CTX_WSH, e2, sizeof e2);   /* a participant: a compressed key, ranges allowed, no x-only */
            if (pk < 0) ERRN("musig(): %s", e2);
            descr_key_t* p = &d->keys[pk]; p->tr_ctx = 0;
            if (p->kind != DK_XPUB && p->kind != DK_XPRV) all_bip32 = 0;
            if (p->ranged) any_ranged = 1;
            if (p->has_priv) any_priv = 1;
            k = &d->keys[slot]; k->musig_parts[k->musig_n++] = pk;
        }
        k = &d->keys[slot];
        if (rl){
            if (rest[0] != '/') ERRN("Invalid musig() expression");
            if (!all_bip32) ERRN("musig(): derivation requires all participants to be xpubs or xprvs");
            if (any_ranged) ERRN("musig(): Cannot have ranged participant keys if musig() also has derivation");
            int rg = 0, rh = 0, ap = 1;
            if (!parse_path_elems_mp(rest, rl, k->path, &k->pathlen, &rg, &rh, &ap, 1, 1, &k->mp_pos, &k->mp_n, k->mp_vals, err, errcap)){ char t[512]; snprintf(t, sizeof t, "%s", err); snprintf(err, errcap, "musig(): %s", t); return -1; }
            if (rh) ERRN("musig(): Cannot have hardened child derivation");
            for (int i = 0; i < k->pathlen; i++) if (k->path[i] & 0x80000000u) ERRN("musig(): cannot have hardened derivation steps");
            for (int i = 0; i < k->mp_n; i++) if (k->mp_vals[i] & 0x80000000u) ERRN("musig(): cannot have hardened derivation steps");
            k->ranged = rg;
        }
        { /* BIP389 in musig(): participants may be multipath (equal lengths) unless the aggregate's own path is */
          int pm = 0, mism = 0;
          for (int q = 0; q < k->musig_n; q++){ int m = d->keys[k->musig_parts[q]].mp_n; if (m > 1){ if (pm && m != pm) mism = 1; pm = m; } }
          if (mism) ERRN("musig(): Multipath derivation paths have mismatched lengths");
          if (pm && k->mp_n > 1) ERRN("musig(): Cannot have multipath participant keys if musig() is also multipath");
          if (pm) k->mp_n = pm; }
        k->musig_parts_ranged = any_ranged; k->has_priv = any_priv;
        if (k->ranged || any_ranged) d->ranged = 1;
        if (any_priv) d->has_priv = 1;
        return slot;
    }
    descr_key_t* k = &d->keys[d->nk];
    if (!parse_key(s, n, ctx == CTX_TR, 1, k, err, errcap)) return -1;
    if (ctx != CTX_TOP && ctx != CTX_SH && !k->compressed) ERRN("Uncompressed keys are not allowed");
    k->tr_ctx = (ctx == CTX_TR);
    if (k->ranged) d->ranged = 1;
    if (k->ranged && k->range_hard) d->has_hardened_range = 1;
    if (k->has_priv) d->has_priv = 1;
    return d->nk++;
}

static int parse_script(descr_t* d, const char* s, size_t n, int ctx, char* err, unsigned long errcap);

static int parse_tree(descr_t* d, const char* s, size_t n, char* err, unsigned long errcap){
    if (n && s[0] == '{'){
        if (s[n-1] != '}') ERRN("tr(): tree not closed with '}'");
        const char* as[3]; size_t al[3];
        int na = split_args(s + 1, n - 2, as, al, 3);
        if (na != 2) ERRN("tr(): a branch must have exactly two children");
        int b = new_node(d, DN_BRANCH, err, errcap); if (b < 0) return -1;
        int l = parse_tree(d, as[0], al[0], err, errcap); if (l < 0) return -1;
        int r = parse_tree(d, as[1], al[1], err, errcap); if (r < 0) return -1;
        d->nodes[b].child[0] = l; d->nodes[b].child[1] = r;
        return b;
    }
    return parse_script(d, s, n, CTX_TR, err, errcap);
}

static int parse_script(descr_t* d, const char* s, size_t n, int ctx, char* err, unsigned long errcap){
    size_t p = 0; while (p < n && s[p] != '(') p++;
    if (p == 0 || p >= n || s[n-1] != ')'){
        char t[64]; size_t m = n < 48 ? n : 48; memcpy(t, s, m); t[m] = 0;
        if (ctx == CTX_TR) ERRN("'%s' is not a valid descriptor function", t);
        ERRN("'%s' is not a valid descriptor function", t);
    }
    char fn[24]; if (p >= sizeof fn) { char t[64]; size_t m = n < 48 ? n : 48; memcpy(t, s, m); t[m]=0; ERRN("'%s' is not a valid descriptor function", t); }
    memcpy(fn, s, p); fn[p] = 0;
    const char* in = s + p + 1; size_t il = n - p - 2;
    const char* as[DESCR_NODE_KEYS + 2]; size_t al[DESCR_NODE_KEYS + 2];

    if (!strcmp(fn, "pk") || !strcmp(fn, "pkh") || !strcmp(fn, "wpkh")){
        int t = fn[0]=='w' ? DN_WPKH : fn[2]=='h' ? DN_PKH : DN_PK;
        if (t == DN_WPKH && ctx != CTX_TOP && ctx != CTX_SH) ERRN("Can only have wpkh() at top level or inside sh()");
        int nd = new_node(d, t, err, errcap); if (nd < 0) return -1;
        int k = add_key(d, in, il, ctx, err, errcap);
        if (k < 0){ char t2[1400]; snprintf(t2, sizeof t2, "%s", err); snprintf(err, errcap, "%s(): %s", fn, t2); return -1; }   /* Core prefixes the key error */
        if (t == DN_WPKH && !d->keys[k].compressed) ERRN("Uncompressed keys are not allowed");
        d->nodes[nd].keys[0] = k; d->nodes[nd].nkeys = 1; return nd;
    }
    if (!strcmp(fn, "combo")){
        if (ctx != CTX_TOP) ERRN("Can only have combo() at top level");
        int nd = new_node(d, DN_COMBO, err, errcap); if (nd < 0) return -1;
        int k = add_key(d, in, il, ctx, err, errcap); if (k < 0) return -1;
        d->nodes[nd].keys[0] = k; d->nodes[nd].nkeys = 1; return nd;
    }
    if (!strcmp(fn, "multi") || !strcmp(fn, "sortedmulti") || !strcmp(fn, "multi_a") || !strcmp(fn, "sortedmulti_a")){
        int tap = strstr(fn, "_a") != NULL, sorted = fn[0] == 's';
        if (tap && ctx != CTX_TR) ERRN("Can only have %s() inside tr()", fn);
        if (!tap && ctx == CTX_TR) ERRN("Can only have %s() at top level, in sh(), or in wsh()", fn);
        int na = split_args(in, il, as, al, DESCR_NODE_KEYS + 2);
        if (na < 2) ERRN("Multi threshold and at least one key required");
        if (na - 1 > DESCR_NODE_KEYS) ERRN("Cannot have %d keys in multisig; must have between 1 and %d keys, inclusive", na - 1, tap ? DESCR_NODE_KEYS : 20);
        long thr = 0; for (size_t q = 0; q < al[0]; q++){ if (as[0][q] < '0' || as[0][q] > '9') ERRN("Multi threshold '%.*s' is not valid", (int)al[0], as[0]); thr = thr*10 + (as[0][q]-'0'); if (thr > 100000) break; }
        if (thr < 1) ERRN("Multisig threshold cannot be %ld, must be at least 1", thr);
        if (thr > na - 1) ERRN("Multisig threshold cannot be larger than the number of keys; threshold is %ld but only %d keys specified", thr, na - 1);
        if (!tap && na - 1 > 20) ERRN("Cannot have %d keys in multisig; must have between 1 and 20 keys, inclusive", na - 1);
        int nd = new_node(d, tap ? (sorted ? DN_SORTEDMULTI_A : DN_MULTI_A) : (sorted ? DN_SORTEDMULTI : DN_MULTI), err, errcap); if (nd < 0) return -1;
        d->nodes[nd].k = (int)thr;
        int anyuncomp = 0;
        for (int q = 1; q < na; q++){
            int k = add_key(d, as[q], al[q], ctx, err, errcap); if (k < 0) return -1;
            if (!d->keys[k].compressed) anyuncomp = 1;
            d->nodes[nd].keys[d->nodes[nd].nkeys++] = k;
        }
        { int pm = 0; for (int q = 0; q < d->nodes[nd].nkeys; q++){ int m = d->keys[d->nodes[nd].keys[q]].mp_n; if (m > 1){ if (pm && m != pm) ERRN("%s(): Multipath derivation paths have mismatched lengths", fn); pm = m; } } }
        if (!tap && ctx == CTX_TOP && na - 1 > 3) ERRN("Cannot have %d pubkeys in bare multisig: only at most 3 pubkeys", na - 1);
        if (!tap && ctx == CTX_SH){
            /* Core: the redeemScript must fit 520 bytes */
            int sz = 3; for (int q = 0; q < d->nodes[nd].nkeys; q++) sz += 1 + d->keys[d->nodes[nd].keys[q]].publen;
            if (sz > 520) ERRN("P2SH script is too large, %d bytes is larger than 520 bytes", sz);
        }
        (void)anyuncomp;
        return nd;
    }
    if (!strcmp(fn, "sh")){
        if (ctx != CTX_TOP) ERRN("Can only have sh() at top level");
        int nd = new_node(d, DN_SH, err, errcap); if (nd < 0) return -1;
        int c = parse_script(d, in, il, CTX_SH, err, errcap); if (c < 0) return -1;
        d->nodes[nd].child[0] = c; return nd;
    }
    if (!strcmp(fn, "wsh")){
        if (ctx != CTX_TOP && ctx != CTX_SH) ERRN("Can only have wsh() at top level or inside sh()");
        int nd = new_node(d, DN_WSH, err, errcap); if (nd < 0) return -1;
        int c = parse_script(d, in, il, CTX_WSH, err, errcap); if (c < 0) return -1;
        int ct = d->nodes[c].type;
        if (ct == DN_WPKH || ct == DN_WSH || ct == DN_SH) ERRN("Can only have %s() at top level%s", ct==DN_WPKH?"wpkh":ct==DN_WSH?"wsh":"sh", ct==DN_SH?"":" or inside sh()");
        d->nodes[nd].child[0] = c; return nd;
    }
    if (!strcmp(fn, "tr")){
        if (ctx != CTX_TOP) ERRN("Can only have tr at top level");
        int na = split_args(in, il, as, al, 3);
        if (na < 1 || na > 2) ERRN("tr(): must have a key and optionally a tree");
        int nd = new_node(d, DN_TR, err, errcap); if (nd < 0) return -1;
        int k = add_key(d, as[0], al[0], CTX_TR, err, errcap);
        if (k < 0){ char t[1400]; snprintf(t, sizeof t, "%s", err); snprintf(err, errcap, "tr(): %s", t); return -1; }   /* Core prefixes the key error */
        d->nodes[nd].keys[0] = k; d->nodes[nd].nkeys = 1;
        if (na == 2){ int k0 = d->nk; int t = parse_tree(d, as[1], al[1], err, errcap); if (t < 0) return -1; d->nodes[nd].child[0] = t;
            int mx = d->keys[k].mp_n > 1 ? d->keys[k].mp_n : 1;
            for (int q = k0; q < d->nk; q++) if (d->keys[q].mp_n > mx) mx = d->keys[q].mp_n;
            for (int q = k0; q < d->nk; q++){ int m = d->keys[q].mp_n; if (m > 1 && m != mx) ERRN("tr(): Multipath subscripts have mismatched lengths"); }
            if (d->keys[k].mp_n > 1 && d->keys[k].mp_n != mx) ERRN("tr(): Multipath internal key mismatches multipath subscripts lengths"); }
        return nd;
    }
    if (!strcmp(fn, "rawtr")){
        if (ctx != CTX_TOP) ERRN("Can only have rawtr at top level");
        int nd = new_node(d, DN_RAWTR, err, errcap); if (nd < 0) return -1;
        int k = add_key(d, in, il, CTX_TR, err, errcap); if (k < 0) return -1;
        d->nodes[nd].keys[0] = k; d->nodes[nd].nkeys = 1; return nd;
    }
    if (!strcmp(fn, "addr")){
        if (ctx != CTX_TOP) ERRN("Can only have addr() at top level");
        char a[160]; if (il >= sizeof a) ERRN("Address too long");
        memcpy(a, in, il); a[il] = 0;
        int type = 0; u8 ver = 0, h160[20], prog[32];
        if (!wallet_validate_address(a, &type, &ver, h160, prog)) ERRN("Address is not valid");
        u8* sp = d->raw; int sl = 0;
        switch (type){
            case 1: sp[0]=0x76;sp[1]=0xa9;sp[2]=0x14;memcpy(sp+3,h160,20);sp[23]=0x88;sp[24]=0xac;sl=25; break;
            case 2: sp[0]=0x00;sp[1]=0x14;memcpy(sp+2,h160,20);sl=22; break;
            case 3: sp[0]=0xa9;sp[1]=0x14;memcpy(sp+2,h160,20);sp[22]=0x87;sl=23; break;
            case 4: sp[0]=0x00;sp[1]=0x20;memcpy(sp+2,prog,32);sl=34; break;
            case 5: sp[0]=0x51;sp[1]=0x20;memcpy(sp+2,prog,32);sl=34; break;
            default: ERRN("Address is not valid");
        }
        d->rawlen = sl;
        int nd = new_node(d, DN_ADDR, err, errcap); return nd;
    }
    if (!strcmp(fn, "raw")){
        if (ctx != CTX_TOP) ERRN("Can only have raw() at top level");
        int l = hex_decode(in, il, d->raw, DESCR_MAX_SPK);
        if (l < 0) ERRN("Raw script is not hex");
        d->rawlen = l;
        int nd = new_node(d, DN_RAW, err, errcap); return nd;
    }
    if (!strcmp(fn, "musig")) ERRN("musig() is not supported by this node");
    /* Miniscript (Core: tried for any expression no named function took;
     * outside wsh()/tr() a successful parse is itself the error). The keys
     * are parsed in the P2WSH rules unless this is a tr() leaf. */
    {
        int tap = (ctx == CTX_TR);
        if (d->msnn == 0) d->ms_tapscript = tap;
        else if (d->ms_tapscript != tap) ERRN("Descriptor mixes P2WSH and tapscript miniscripts");
        ms_tree_t mt; descr_ms_tree(d, &mt);
        descr_msuser_t mu; ms_ctx_t mctx; descr_ms_ctx(d, 0, 0, &mu, &mctx);
        mu.tr = tap; mu.err = err; mu.errcap = errcap;
        char kerr[256]; kerr[0] = 0;
        int root = ms_parse(&mt, &mctx, s, n, kerr, sizeof kerr);
        d->msnn = mt.nn; d->msns = mt.ns; d->msnk = mt.nk;
        if (mu.key_err) ERRN("%s", kerr);
        if (root >= 0){
            if (ctx != CTX_WSH && ctx != CTX_TR) ERRN("Miniscript expressions can only be used in wsh or tr.");
            if (!ms_is_sane(&mt, root) || ms_is_not_satisfiable(&mt, root)){
                int ins = ms_find_insane_sub(&mt, root); if (ins < 0) ins = root;
                char* txt = malloc(4096); if (!txt) ERRN("out of memory");
                if (!ms_to_string(&mt, &mctx, ins, txt, 4096)) snprintf(txt, 4096, "<miniscript>");
                const char* why;
                if (!ms_is_valid(&mt, ins)) why = " is invalid";
                else if (!ms_is_sane(&mt, root)){
                    if (!ms_is_nonmalleable(&mt, ins)) why = " is not sane: malleable witnesses exist";
                    else if (ins == root && !ms_needs_signature(&mt, ins)) why = " is not sane: witnesses without signature exist";
                    else if (!ms_check_timelocks_mix(&mt, ins)) why = " is not sane: contains mixes of timelocks expressed in blocks and seconds";
                    else if (!ms_check_duplicate_key(&mt, ins)) why = " is not sane: contains duplicate public keys";
                    else if (!ms_valid_satisfactions(&mt, ins)) why = " is not sane: needs witnesses that may exceed resource limits";
                    else why = " is not sane";
                } else why = " is not satisfiable";
                snprintf(err, errcap, "%s%s", txt, why); free(txt); return -1;
            }
            int nd = new_node(d, DN_MINISCRIPT, err, errcap); if (nd < 0) return -1;
            d->nodes[nd].ms_root = root;
            { int pm = 0; for (int q = 0; q < d->nk; q++){ int m = d->keys[q].mp_n; if (m > 1){ if (pm && m != pm) ERRN("Miniscript: Multipath derivation paths have mismatched lengths"); pm = m; } } }
            return nd;
        }
    }
    { char t[64]; size_t m = p < 48 ? p : 48; memcpy(t, s, m); t[m] = 0;
      ERRN("'%s' is not a valid descriptor function", t); }
}

int descr_parse(const char* text, descr_t* d, char* err, unsigned long errcap){
    memset(d, 0, sizeof *d); d->root = -1;
    const char* hash = strchr(text, '#');
    size_t cl = hash ? (size_t)(hash - text) : strlen(text);
    if (cl >= sizeof d->text) ERR("Descriptor too long");
    memcpy(d->text, text, cl); d->text[cl] = 0;
    if (!descr_checksum(d->text, d->checksum)) ERR("Invalid characters in descriptor");
    if (hash){
        if (strlen(hash + 1) != 8) ERR("Expected 8 character checksum, not %zu characters", strlen(hash + 1));
        if (strcmp(hash + 1, d->checksum)) ERR("Provided checksum '%s' does not match computed checksum '%s'", hash + 1, d->checksum);
        d->had_checksum = 1;
    }
    if (cl == 0) ERR("'' is not a valid descriptor function");
    int r = parse_script(d, d->text, cl, CTX_TOP, err, errcap);
    if (r < 0) return 0;
    d->root = r;
    /* BIP389: the expansion count; every key path already holds expansion 0 */
    d->mp_n = 1; d->mp_sel = 0;
    for (int q = 0; q < d->nk; q++) if (d->keys[q].mp_n > d->mp_n) d->mp_n = d->keys[q].mp_n;
    return 1;
}
int descr_multipath_n(const descr_t* d){ return d->mp_n > 1 ? d->mp_n : 1; }
int descr_multipath_select(descr_t* d, int sel){
    if (sel < 0 || sel >= descr_multipath_n(d)) return 0;
    for (int q = 0; q < d->nk; q++){ descr_key_t* k = &d->keys[q]; if (k->mp_n > 1 && k->mp_pos >= 0 && k->mp_pos < k->pathlen) k->path[k->mp_pos] = k->mp_vals[sel]; }
    d->mp_sel = sel; return 1;
}

/* ---- derivation ------------------------------------------------------- */
static int musig_cmp33(const void* a, const void* b){ return memcmp(a, b, 33); }
/* the aggregate of a DK_MUSIG key at idx: agg33 (untweaked, underived), the sorted participants, the derived key */
static int musig_derive(const descr_t* d, const descr_key_t* k, long idx, u8 agg33[33], u8 (*parts)[33], int* np, u8 derived[33], unsigned* path, int* plen){
    u8 pk[DESCR_MUSIG_MAX][33]; int n = k->musig_n;
    for (int i = 0; i < n; i++){
        u8 pub[65]; int pl;
        if (!key_pub_at(d, &d->keys[k->musig_parts[i]], idx, pub, &pl)) return 0;
        if (pl != 33) return 0;
        memcpy(pk[i], pub, 33);
    }
    qsort(pk, (size_t)n, 33, musig_cmp33);                    /* Core sorts the participants before KeyAgg */
    musig2_keyagg_t* ka = malloc(sizeof *ka); if (!ka) return 0;
    if (!musig2_key_agg(ka, (const u8 (*)[33])pk, n)){ free(ka); snprintf(g_err, sizeof g_err, "musig(): key aggregation failed"); return 0; }
    musig2_agg_plain(agg33, ka); free(ka);
    if (parts){ memcpy(parts, pk, (size_t)n * 33); } if (np) *np = n;
    u8 K[33], cc[32]; memcpy(K, agg33, 33); memcpy(cc, MUSIG_CC, 32);
    int pl2 = 0;
    for (int i = 0; i < k->pathlen; i++){ u8 K2[33], c2[32]; if (bip32_ckdpub_step_pub(K, cc, k->path[i], K2, c2) != 1) return 0; memcpy(K, K2, 33); memcpy(cc, c2, 32); if (path) path[pl2] = k->path[i]; pl2++; }
    if (k->ranged){ if (idx < 0 || idx > 0x7fffffffL) return 0; u8 K2[33], c2[32]; if (bip32_ckdpub_step_pub(K, cc, (unsigned)idx, K2, c2) != 1) return 0; memcpy(K, K2, 33); if (path) path[pl2] = (unsigned)idx; pl2++; }
    memcpy(derived, K, 33); if (plen) *plen = pl2;
    return 1;
}
int descr_musig_info(const descr_t* d, int key, long idx, u8 agg33[33], u8 (*parts)[33], int* nparts, u8 derived33[33], unsigned* path, int* plen){
    if (key < 0 || key >= d->nk || d->keys[key].kind != DK_MUSIG) return 0;
    return musig_derive(d, &d->keys[key], idx, agg33, parts, nparts, derived33, path, plen);
}
int descr_top_key(const descr_t* d){
    if (d->root < 0) return -1;
    const descr_node_t* n = &d->nodes[d->root];
    return (n->type == DN_TR || n->type == DN_RAWTR) ? n->keys[0] : -1;
}
static int key_pub_at(const descr_t* d, const descr_key_t* k, long idx, u8 pub[65], int* publen){
    if (k->kind == DK_MUSIG){ u8 agg[33]; if (!musig_derive(d, k, idx, agg, NULL, NULL, pub, NULL, NULL)) return 0; *publen = 33; return 1; }
    if (k->kind == DK_HEX || k->kind == DK_WIF){ memcpy(pub, k->pub, (size_t)k->publen); *publen = k->publen; return 1; }
    if (k->ranged && (idx < 0 || idx > 0x7fffffffL)) return 0;
    if (k->kind == DK_XPUB){
        int hard = k->ranged && k->range_hard;
        for (int i = 0; i < k->pathlen; i++) if (k->path[i] & 0x80000000u) hard = 1;
        if (hard){ snprintf(g_err, sizeof g_err, "Cannot derive script without private keys"); return 0; }
        u8 K[33], cc[32]; memcpy(K, k->pub, 33); memcpy(cc, k->cc, 32);
        for (int i = 0; i < k->pathlen; i++){ u8 Kn[33], cn[32]; if (!bip32_ckdpub_step_pub(K, cc, k->path[i], Kn, cn)) return 0; memcpy(K, Kn, 33); memcpy(cc, cn, 32); }
        if (k->ranged){ u8 Kn[33], cn[32]; if (!bip32_ckdpub_step_pub(K, cc, (unsigned)idx, Kn, cn)) return 0; memcpy(K, Kn, 33); }
        memcpy(pub, K, 33); *publen = 33; return 1;
    }
    u8 kk[32], cc[32]; memcpy(kk, k->xkey, 32); memcpy(cc, k->cc, 32);
    for (int i = 0; i < k->pathlen; i++){ u8 kn[32], cn[32]; if (bip32_ckd_priv(kn, cn, kk, cc, k->path[i]) != 1) return 0; memcpy(kk, kn, 32); memcpy(cc, cn, 32); }
    if (k->ranged){ u8 kn[32], cn[32]; unsigned ix = (unsigned)idx | (k->range_hard ? 0x80000000u : 0); if (bip32_ckd_priv(kn, cn, kk, cc, ix) != 1) return 0; memcpy(kk, kn, 32); }
    scalar_to_pubkey(pub, kk); *publen = 33; return 1;
}
int descr_key_pub_at(const descr_t* d, int key, long idx, u8 pub[65], int* publen){
    if (key < 0 || key >= d->nk) return 0;
    return key_pub_at(d, &d->keys[key], idx, pub, publen);
}
int descr_key_priv_at(const descr_t* d, int key, long idx, u8 priv[32], int* compressed){
    if (key < 0 || key >= d->nk) return 0;
    const descr_key_t* k = &d->keys[key];
    if (!k->has_priv || k->kind == DK_MUSIG) return 0;    /* an aggregate has no private key; its participants are keys of their own */
    if (compressed) *compressed = k->compressed;
    if (k->kind == DK_WIF){ memcpy(priv, k->priv, 32); return 1; }
    u8 kk[32], cc[32]; memcpy(kk, k->xkey, 32); memcpy(cc, k->cc, 32);
    for (int i = 0; i < k->pathlen; i++){ u8 kn[32], cn[32]; if (bip32_ckd_priv(kn, cn, kk, cc, k->path[i]) != 1) return 0; memcpy(kk, kn, 32); memcpy(cc, cn, 32); }
    if (k->ranged){ if (idx < 0 || idx > 0x7fffffffL) return 0; u8 kn[32], cn[32]; unsigned ix = (unsigned)idx | (k->range_hard ? 0x80000000u : 0); if (bip32_ckd_priv(kn, cn, kk, cc, ix) != 1) return 0; memcpy(kk, kn, 32); }
    memcpy(priv, kk, 32); return 1;
}

/* ---- script construction ---------------------------------------------- */
#define SCRIPT_CAP 40000   /* a tapscript leaf may be a 999-key multi_a; buffers this size live on the heap */
/* pubkey bytes of key `ki` at idx, x-only when in tr context */
static int key_bytes(const descr_t* d, int ki, long idx, int xonly, u8 out[65], int* n){
    u8 pub[65]; int pl;
    if (!key_pub_at(d, &d->keys[ki], idx, pub, &pl)){ if (!g_err[0]) snprintf(g_err, sizeof g_err, "Key derivation failed"); return 0; }
    if (xonly){
        if (pl == 32){ memcpy(out, pub, 32); *n = 32; return 1; }
        if (pl == 65){ snprintf(g_err, sizeof g_err, "Uncompressed keys are not allowed"); return 0; }
        memcpy(out, pub + 1, 32); *n = 32; return 1;
    }
    if (pl == 32){ out[0] = 0x02; memcpy(out + 1, pub, 32); *n = 33; return 1; }   /* x-only outside tr: even-Y form (Core does the same for XOnlyPubKey::GetEvenCorrespondingCPubKey) */
    memcpy(out, pub, (size_t)pl); *n = pl; return 1;
}
static int cmp_key(const void* a, const void* b){
    const u8* x = a; const u8* y = b; int lx = x[0], ly = y[0];
    int m = lx < ly ? lx : ly; int c = memcmp(x + 1, y + 1, (size_t)m);
    return c ? c : lx - ly;
}
/* the script for node ni (a leaf-level script: pk/pkh/wpkh/multi*/
static int node_script(const descr_t* d, int ni, long idx, int tr, u8* out, int cap){
    const descr_node_t* n = &d->nodes[ni];
    int o = 0;
    switch (n->type){
    case DN_PK: { u8 kb[65]; int kl; if (!key_bytes(d, n->keys[0], idx, tr, kb, &kl)) return -1;
        o = push_data(out, o, cap, kb, kl); if (o < 0) return -1; out[o++] = 0xac; return o; }
    case DN_PKH: { u8 kb[65]; int kl, h[20]; if (!key_bytes(d, n->keys[0], idx, tr, kb, &kl)) return -1;
        u8 hh[20]; hash160(hh, kb, kl); (void)h;
        if (o + 25 > cap) return -1;
        out[o++]=0x76; out[o++]=0xa9; out[o++]=0x14; memcpy(out+o, hh, 20); o+=20; out[o++]=0x88; out[o++]=0xac; return o; }
    case DN_WPKH: { u8 kb[65]; int kl; if (!key_bytes(d, n->keys[0], idx, 0, kb, &kl)) return -1;
        if (kl != 33){ snprintf(g_err, sizeof g_err, "Uncompressed keys are not allowed"); return -1; }
        u8 hh[20]; hash160(hh, kb, kl); if (o + 22 > cap) return -1;
        out[o++]=0x00; out[o++]=0x14; memcpy(out+o, hh, 20); return o + 20; }
    case DN_MULTI: case DN_SORTEDMULTI: {
        u8 keys[DESCR_NODE_KEYS][66]; int nk = n->nkeys;
        for (int q = 0; q < nk; q++){ int kl; if (!key_bytes(d, n->keys[q], idx, 0, keys[q] + 1, &kl)) return -1; keys[q][0] = (u8)kl; }
        if (n->type == DN_SORTEDMULTI) qsort(keys, (size_t)nk, 66, cmp_key);
        o = push_num(out, o, cap, n->k); if (o < 0) return -1;
        for (int q = 0; q < nk; q++){ o = push_data(out, o, cap, keys[q] + 1, keys[q][0]); if (o < 0) return -1; }
        o = push_num(out, o, cap, nk); if (o < 0 || o + 1 > cap) return -1;
        out[o++] = 0xae; return o; }
    case DN_MULTI_A: case DN_SORTEDMULTI_A: {
        u8 keys[DESCR_NODE_KEYS][33]; int nk = n->nkeys;
        for (int q = 0; q < nk; q++){ int kl; if (!key_bytes(d, n->keys[q], idx, 1, keys[q] + 1, &kl)) return -1; keys[q][0] = 32; }
        if (n->type == DN_SORTEDMULTI_A) qsort(keys, (size_t)nk, 33, cmp_key);
        for (int q = 0; q < nk; q++){
            o = push_data(out, o, cap, keys[q] + 1, 32); if (o < 0 || o + 1 > cap) return -1;
            out[o++] = q == 0 ? 0xac : 0xba;            /* CHECKSIG, then CHECKSIGADD */
        }
        o = push_num(out, o, cap, n->k); if (o < 0 || o + 1 > cap) return -1;
        out[o++] = 0x9c; return o; }                     /* NUMEQUAL */
    case DN_MINISCRIPT: {
        ms_tree_t mt; descr_ms_tree(d, &mt);
        descr_msuser_t mu; ms_ctx_t mctx; descr_ms_ctx(d, idx, 0, &mu, &mctx); mu.tr = tr;
        int l = ms_to_script(&mt, &mctx, n->ms_root, out, (size_t)cap);
        if (l < 0){ if (!g_err[0]) snprintf(g_err, sizeof g_err, "Key derivation failed"); return -1; }
        return l; }
    default:
        snprintf(g_err, sizeof g_err, "Descriptor node cannot be a script"); return -1;
    }
}
int descr_ms_root(const descr_t* d, long idx, const u8* leaf, int leaflen){
    if (d->root < 0) return -1;
    const descr_node_t* r = &d->nodes[d->root];
    if (r->type == DN_SH && r->child[0] >= 0 && d->nodes[r->child[0]].type == DN_WSH) r = &d->nodes[r->child[0]];
    if (r->type == DN_WSH){ const descr_node_t* c = &d->nodes[r->child[0]]; return c->type == DN_MINISCRIPT ? c->ms_root : -1; }
    if (r->type != DN_TR || r->child[0] < 0 || !leaf) return -1;
    /* walk the tree for the leaf whose script matches */
    int stack[256]; int sp = 0; stack[sp++] = r->child[0];
    while (sp){
        const descr_node_t* n = &d->nodes[stack[--sp]];
        if (n->type == DN_BRANCH){ if (sp + 2 <= 256){ stack[sp++] = n->child[0]; stack[sp++] = n->child[1]; } continue; }
        if (n->type != DN_MINISCRIPT) continue;
        u8* sc = malloc(SCRIPT_CAP); if (!sc) return -1;
        int sl = node_script(d, (int)(n - d->nodes), idx, 1, sc, SCRIPT_CAP);
        int hit = (sl == leaflen && !memcmp(sc, leaf, (size_t)sl)); free(sc);
        if (hit) return n->ms_root;
    }
    return -1;
}
/* merkle root of a tap tree rooted at ni; 1 ok */
static int tree_hash(const descr_t* d, int ni, long idx, u8 out[32], int depth){
    if (depth > 128){ snprintf(g_err, sizeof g_err, "tr() tree too deep"); return 0; }
    const descr_node_t* n = &d->nodes[ni];
    if (n->type == DN_BRANCH){
        u8 l[32], r[32];
        if (!tree_hash(d, n->child[0], idx, l, depth + 1) || !tree_hash(d, n->child[1], idx, r, depth + 1)) return 0;
        tap_branch_hash(out, l, r); return 1;
    }
    u8* sc = malloc(SCRIPT_CAP); if (!sc){ snprintf(g_err, sizeof g_err, "out of memory"); return 0; }
    int sl = node_script(d, ni, idx, 1, sc, SCRIPT_CAP);
    if (sl < 0){ free(sc); return 0; }
    int ok = tap_leaf_hash(out, 0xc0, sc, (uint64_t)sl) == 1; free(sc);
    if (!ok){ snprintf(g_err, sizeof g_err, "tapleaf hash failed"); return 0; }
    return 1;
}
/* ---- tr() tree enumeration for the PSBT Updater (2026-09-01) ----------
 * Leaves in DFS order with depth, script, leaf hash and the BIP341 control
 * block (leaf version | output parity, internal key, merkle path from the
 * leaf up). Also the internal x-only key, the merkle root and the output
 * key parity. Returns the leaf count (0 = no tree), -1 on error. */
static int tr_walk(const descr_t* d, int ni, long idx, int depth, descr_leaf_t* out, int cap, int* n, u8 hash_out[32], u8 (*path)[32], int plen){
    const descr_node_t* nd = &d->nodes[ni];
    if (depth > 128) return -1;
    if (nd->type == DN_BRANCH){
        u8 l[32], r[32];
        /* hash both children first (each needs the other's hash as a path element) */
        if (tr_walk(d, nd->child[0], idx, depth + 1, NULL, 0, NULL, l, NULL, 0) < 0) return -1;
        if (tr_walk(d, nd->child[1], idx, depth + 1, NULL, 0, NULL, r, NULL, 0) < 0) return -1;
        tap_branch_hash(hash_out, l, r);
        if (out){
            u8 (*p2)[32] = malloc(sizeof(u8[32]) * (size_t)(plen + 1)); if (!p2) return -1;
            if (plen) memcpy(p2, path, sizeof(u8[32]) * (size_t)plen);
            memcpy(p2[plen], r, 32); int a = tr_walk(d, nd->child[0], idx, depth + 1, out, cap, n, l, p2, plen + 1);
            memcpy(p2[plen], l, 32); int b = a < 0 ? -1 : tr_walk(d, nd->child[1], idx, depth + 1, out, cap, n, r, p2, plen + 1);
            free(p2); if (a < 0 || b < 0) return -1;
        }
        return 1;
    }
    u8* sc = malloc(SCRIPT_CAP); if (!sc) return -1;
    int sl = node_script(d, ni, idx, 1, sc, SCRIPT_CAP);
    if (sl < 0 || tap_leaf_hash(hash_out, 0xc0, sc, (uint64_t)sl) != 1){ free(sc); return -1; }
    if (out){
        if (*n >= cap || sl > (int)sizeof out[0].script){ free(sc); return -1; }
        descr_leaf_t* L = &out[*n]; memset(L, 0, sizeof *L);
        L->depth = depth; L->leaf_ver = 0xc0; L->slen = sl; memcpy(L->script, sc, (size_t)sl); memcpy(L->leaf_hash, hash_out, 32);
        /* merkle path: the path array holds sibling hashes from the ROOT down; the control block wants leaf up */
        L->npath = plen; for (int i = 0; i < plen; i++) memcpy(L->path[i], path[plen - 1 - i], 32);
        (*n)++;
    }
    free(sc); return 1;
}
int descr_tr_leaves(const descr_t* d, long idx, descr_leaf_t* out, int cap, u8 internal32[32], u8 root32[32], int* has_root, int* odd){
    if (d->root < 0) return -1;
    const descr_node_t* n = &d->nodes[d->root];
    if (n->type != DN_TR && n->type != DN_RAWTR) return -1;
    u8 ik[65]; int il; if (!key_bytes(d, n->keys[0], idx, 1, ik, &il) || il != 32) return -1;
    memcpy(internal32, ik, 32);
    *has_root = 0; int cnt = 0;
    const u8* rp = NULL;
    if (n->type == DN_TR && n->child[0] >= 0){
        if (tr_walk(d, n->child[0], idx, 0, out, cap, &cnt, root32, NULL, 0) < 0) return -1;
        *has_root = 1; rp = root32;
    }
    /* output key parity for the control blocks */
    u8 q[32]; int par = 0;
    extern int bip32_xonly_tweak_add_par(const unsigned char x[32], const unsigned char t[32], unsigned char out_x[32], int* odd);
    { u8 t[32]; u8 pre[64]; memcpy(pre, internal32, 32); if (rp){ memcpy(pre + 32, rp, 32); tagged_hash(t, "TapTweak", pre, 32, rp, 32); } else tagged_hash(t, "TapTweak", pre, 32, NULL, 0);
      if (!bip32_xonly_tweak_add_par(internal32, t, q, &par)) return -1; }
    if (odd) *odd = par;
    for (int i = 0; i < cnt; i++){
        out[i].ctrl[0] = (u8)(0xc0 | (par & 1)); memcpy(out[i].ctrl + 1, internal32, 32);
        for (int k = 0; k < out[i].npath; k++) memcpy(out[i].ctrl + 33 + 32 * k, out[i].path[k], 32);
        out[i].ctrl_len = 33 + 32 * out[i].npath;
    }
    return cnt;
}
/* scriptPubKey of the wrapper/leaf node ni at the top level */
static int spk_of(const descr_t* d, int ni, long idx, u8* out, int cap){
    const descr_node_t* n = &d->nodes[ni];
    switch (n->type){
    case DN_SH: {
        u8* sc = malloc(SCRIPT_CAP); if (!sc){ snprintf(g_err, sizeof g_err, "out of memory"); return -1; }
        int sl;
        int ct = d->nodes[n->child[0]].type;
        if (ct == DN_WSH || ct == DN_WPKH){ sl = spk_of(d, n->child[0], idx, sc, SCRIPT_CAP); }
        else { sl = node_script(d, n->child[0], idx, 0, sc, SCRIPT_CAP); }
        if (sl < 0){ free(sc); return -1; }
        if (sl > 520){ snprintf(g_err, sizeof g_err, "P2SH script is too large, %d bytes is larger than 520 bytes", sl); free(sc); return -1; }
        u8 h[20]; hash160(h, sc, sl); free(sc);
        if (cap < 23) return -1;
        out[0]=0xa9; out[1]=0x14; memcpy(out+2, h, 20); out[22]=0x87; return 23; }
    case DN_WSH: {
        u8* sc = malloc(SCRIPT_CAP); if (!sc){ snprintf(g_err, sizeof g_err, "out of memory"); return -1; }
        int sl = node_script(d, n->child[0], idx, 0, sc, SCRIPT_CAP);
        if (sl < 0){ free(sc); return -1; }
        u8 h[32]; sha256_full(h, sc, (unsigned long)sl); free(sc);
        if (cap < 34) return -1;
        out[0]=0x00; out[1]=0x20; memcpy(out+2, h, 32); return 34; }
    case DN_TR: { u8 ik[65]; int il; if (!key_bytes(d, n->keys[0], idx, 1, ik, &il)) return -1;
        u8 root[32]; const u8* rp = NULL;
        if (n->child[0] >= 0){ if (!tree_hash(d, n->child[0], idx, root, 0)) return -1; rp = root; }
        u8 q[32]; if (taproot_tweak_pubkey(q, ik, rp) < 1){ snprintf(g_err, sizeof g_err, "taproot tweak failed"); return -1; }
        if (cap < 34) return -1;
        out[0]=0x51; out[1]=0x20; memcpy(out+2, q, 32); return 34; }
    case DN_RAWTR: { u8 ik[65]; int il; if (!key_bytes(d, n->keys[0], idx, 1, ik, &il)) return -1;
        if (cap < 34) return -1;
        out[0]=0x51; out[1]=0x20; memcpy(out+2, ik, 32); return 34; }
    case DN_ADDR: case DN_RAW:
        if (cap < d->rawlen) return -1;
        memcpy(out, d->raw, (size_t)d->rawlen); return d->rawlen;
    default: return node_script(d, ni, idx, 0, out, cap);
    }
}
int descr_expand(const descr_t* d, long idx, descr_spk_t* out, int cap){
    g_err[0] = 0;
    if (d->root < 0 || cap < 1){ snprintf(g_err, sizeof g_err, "Descriptor not parsed"); return -1; }
    const descr_node_t* n = &d->nodes[d->root];
    if (n->type == DN_COMBO){
        u8 kb[65]; int kl; if (!key_bytes(d, n->keys[0], idx, 0, kb, &kl)) return -1;
        int c = 0; u8 h[20]; hash160(h, kb, kl);
        if (cap < 2) return -1;
        { int o = push_data(out[c].spk, 0, DESCR_MAX_SPK, kb, kl); out[c].spk[o++] = 0xac; out[c].len = o; c++; }
        { u8* s = out[c].spk; s[0]=0x76;s[1]=0xa9;s[2]=0x14;memcpy(s+3,h,20);s[23]=0x88;s[24]=0xac; out[c].len=25; c++; }
        if (kl == 33 && cap >= 4){
            { u8* s = out[c].spk; s[0]=0x00;s[1]=0x14;memcpy(s+2,h,20); out[c].len=22; c++; }
            { u8 rd[22]={0x00,0x14}; memcpy(rd+2,h,20); u8 rh[20]; hash160(rh, rd, 22);
              u8* s = out[c].spk; s[0]=0xa9;s[1]=0x14;memcpy(s+2,rh,20);s[22]=0x87; out[c].len=23; c++; }
        }
        return c;
    }
    int l = spk_of(d, d->root, idx, out[0].spk, DESCR_MAX_SPK);
    if (l < 0){ if (!g_err[0]) snprintf(g_err, sizeof g_err, "Key derivation failed"); return -1; }
    out[0].len = l; return 1;
}
int descr_inner_script_at(const descr_t* d, long idx, u8* out, int cap, int* which){
    if (d->root < 0) return 0;
    const descr_node_t* n = &d->nodes[d->root];
    if (n->type == DN_SH){
        int c = n->child[0]; int ct = d->nodes[c].type;
        if (ct == DN_WSH){ int l = node_script(d, d->nodes[c].child[0], idx, 0, out, cap); if (l < 0) return 0; *which = 3; return l; }
        int l = (ct == DN_WPKH) ? spk_of(d, c, idx, out, cap) : node_script(d, c, idx, 0, out, cap);
        if (l < 0) return 0;
        *which = 1; return l;
    }
    if (n->type == DN_WSH){ int l = node_script(d, n->child[0], idx, 0, out, cap); if (l < 0) return 0; *which = 2; return l; }
    return 0;
}
int descr_has_address(const descr_t* d){
    if (d->root < 0) return 0;
    int t = d->nodes[d->root].type;
    if (t == DN_PK || t == DN_COMBO || t == DN_MULTI || t == DN_SORTEDMULTI) return 0;
    if (t == DN_RAW){   /* only standard forms have a destination */
        int l = d->rawlen; const u8* s = d->raw;
        return (l==25&&s[0]==0x76&&s[1]==0xa9&&s[2]==0x14&&s[23]==0x88&&s[24]==0xac) || (l==23&&s[0]==0xa9&&s[1]==0x14&&s[22]==0x87) ||
               (l==22&&s[0]==0x00&&s[1]==0x14) || (l==34&&(s[0]==0x00||s[0]==0x51)&&s[1]==0x20);
    }
    return 1;
}

/* ---- to string -------------------------------------------------------- */
typedef struct { char* p; unsigned long cap, n; int ovf; int mpform; } sb_t;
static void sb_put(sb_t* b, const char* s){ unsigned long l = strlen(s); if (b->n + l + 1 > b->cap){ b->ovf = 1; return; } memcpy(b->p + b->n, s, l + 1); b->n += l; }
static void sb_path(sb_t* b, const unsigned* path, int n, int apostrophe){
    for (int i = 0; i < n; i++){ char t[24]; snprintf(t, sizeof t, "/%u%s", path[i] & 0x7fffffffu, (path[i] & 0x80000000u) ? (apostrophe ? "'" : "h") : ""); sb_put(b, t); }
}
/* the key's derivation path; in multipath form the placeholder prints as <a;b;...> */
static int g_print_mp;   /* descr_to_string_multipath in progress: keys printed through the miniscript printer show <a;b> too */
static void sb_kpath(sb_t* b, const descr_key_t* k){
    for (int i = 0; i < k->pathlen; i++){
        char t[24 * DESCR_MP_MAX + 4];
        if ((b->mpform || g_print_mp) && k->mp_n > 1 && i == k->mp_pos){
            int o = 0; o += snprintf(t + o, sizeof t - (size_t)o, "/<");
            for (int q = 0; q < k->mp_n; q++) o += snprintf(t + o, sizeof t - (size_t)o, "%s%u%s", q ? ";" : "", k->mp_vals[q] & 0x7fffffffu, (k->mp_vals[q] & 0x80000000u) ? (k->apostrophe ? "'" : "h") : "");
            snprintf(t + o, sizeof t - (size_t)o, ">");
        } else snprintf(t, sizeof t, "/%u%s", k->path[i] & 0x7fffffffu, (k->path[i] & 0x80000000u) ? (k->apostrophe ? "'" : "h") : "");
        sb_put(b, t);
    }
}
static void sb_key(sb_t* b, const descr_t* d, const descr_key_t* k, int with_priv){
    if (k->kind == DK_MUSIG){
        sb_put(b, "musig(");
        for (int i = 0; i < k->musig_n; i++){ if (i) sb_put(b, ","); sb_key(b, d, &d->keys[k->musig_parts[i]], with_priv); }
        sb_put(b, ")");
        sb_kpath(b, k);
        if (k->ranged) sb_put(b, "/*");
        return;
    }
    if (k->has_origin){ char t[16]; hex_encode(t, k->origin_fp, 4); sb_put(b, "["); sb_put(b, t); sb_path(b, k->origin, k->origin_len, k->apostrophe); sb_put(b, "]"); }
    char t[200];
    if (k->kind == DK_HEX || (k->kind == DK_WIF && !with_priv)){
        /* Core prints a WIF key under tr() x-only; a hex key prints as it was given */
        if (k->tr_ctx && k->kind == DK_WIF && k->publen == 33) hex_encode(t, k->pub + 1, 32);
        else hex_encode(t, k->pub, k->publen);
        sb_put(b, t);
    } else if (k->kind == DK_WIF){
        if (with_priv){
            u8 pay[34]; pay[0] = k->testnet ? 0xef : 0x80; memcpy(pay+1, k->priv, 32); pay[33] = 1;
            base58check_encode(t, pay, k->compressed ? 34 : 33); sb_put(b, t);
        } else {
            hex_encode(t, k->pub, k->publen); sb_put(b, t);
        }
    } else {
        u8 ser[78]; int priv = (k->kind == DK_XPRV) && with_priv;
        ser[0]=0x04; ser[1]=k->testnet?0x35:0x88; ser[2]=k->testnet?(priv?0x83:0x87):(priv?0xAD:0xB2); ser[3]=k->testnet?(priv?0x94:0xCF):(priv?0xE4:0x1E);
        ser[4]=k->depth; memcpy(ser+5,k->parentfp,4); ser[9]=(u8)(k->child>>24); ser[10]=(u8)(k->child>>16); ser[11]=(u8)(k->child>>8); ser[12]=(u8)k->child;
        memcpy(ser+13,k->cc,32);
        if (priv){ ser[45]=0; memcpy(ser+46,k->xkey,32); }
        else memcpy(ser+45,k->pub,33);
        base58check_encode(t, ser, 78); sb_put(b, t);
    }
    sb_kpath(b, k);
    if (k->ranged) sb_put(b, k->range_hard ? (k->apostrophe ? "/*'" : "/*h") : "/*");
}
static void sb_key_to(const descr_t* d, int ki, int with_priv, char* out, unsigned long cap){
    sb_t b = { out, cap, 0, 0, 0 }; out[0] = 0;
    if (ki < 0 || ki >= d->nk) return;
    sb_key(&b, d, &d->keys[ki], with_priv);
    if (b.ovf) out[0] = 0;
}
static void sb_node(sb_t* b, const descr_t* d, int ni, int with_priv){
    const descr_node_t* n = &d->nodes[ni];
    static const char* NAMES[] = { "", "pk", "pkh", "wpkh", "combo", "multi", "sortedmulti", "multi_a", "sortedmulti_a", "sh", "wsh", "tr", "addr", "raw", "rawtr", "", "" };
    if (n->type == DN_MINISCRIPT){
        ms_tree_t mt; descr_ms_tree(d, &mt);
        descr_msuser_t mu; ms_ctx_t mctx; descr_ms_ctx(d, 0, with_priv, &mu, &mctx);
        char* txt = malloc(65536); if (!txt){ b->ovf = 1; return; }
        if (!ms_to_string(&mt, &mctx, n->ms_root, txt, 65536)) b->ovf = 1; else sb_put(b, txt);
        free(txt); return;
    }
    if (n->type == DN_BRANCH){ sb_put(b, "{"); sb_node(b, d, n->child[0], with_priv); sb_put(b, ","); sb_node(b, d, n->child[1], with_priv); sb_put(b, "}"); return; }
    sb_put(b, NAMES[n->type]); sb_put(b, "(");
    switch (n->type){
    case DN_SH: case DN_WSH: sb_node(b, d, n->child[0], with_priv); break;
    case DN_TR: sb_key(b, d, &d->keys[n->keys[0]], with_priv); if (n->child[0] >= 0){ sb_put(b, ","); sb_node(b, d, n->child[0], with_priv); } break;
    case DN_MULTI: case DN_SORTEDMULTI: case DN_MULTI_A: case DN_SORTEDMULTI_A: {
        char t[16]; snprintf(t, sizeof t, "%d", n->k); sb_put(b, t);
        for (int q = 0; q < n->nkeys; q++){ sb_put(b, ","); sb_key(b, d, &d->keys[n->keys[q]], with_priv); } break; }
    case DN_ADDR: case DN_RAW: {
        if (n->type == DN_RAW){ char* h = malloc((size_t)d->rawlen * 2 + 1); if (h){ hex_encode(h, d->raw, d->rawlen); sb_put(b, h); free(h); } }
        else { /* re-render the address from the script */
            extern int wallet_script_to_address(char* out, long cap, const u8* script, long slen);
            char a[128]; if (wallet_script_to_address(a, sizeof a, d->raw, d->rawlen) > 0) sb_put(b, a); }
        break; }
    default: sb_key(b, d, &d->keys[n->keys[0]], with_priv); break;
    }
    sb_put(b, ")");
}
int descr_to_string(const descr_t* d, int with_priv, char* out, unsigned long cap){
    if (d->root < 0 || cap == 0) return 0;
    sb_t b = { out, cap, 0, 0, 0 }; out[0] = 0;
    sb_node(&b, d, d->root, with_priv);
    return !b.ovf;
}
int descr_to_string_multipath(const descr_t* d, int with_priv, char* out, unsigned long cap){
    if (d->root < 0 || cap == 0) return 0;
    sb_t b = { out, cap, 0, 0, 1 }; out[0] = 0;
    g_print_mp = 1; sb_node(&b, d, d->root, with_priv); g_print_mp = 0;
    return !b.ovf;
}
