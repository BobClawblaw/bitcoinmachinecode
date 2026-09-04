/* psbt_update.c -- the PSBT Updater role from descriptors (BIP174/BIP371),
 * 2026-09-01. For every input whose spending script a descriptor expansion
 * produces (and every output it produces), add what Core's UpdatePSBTInput /
 * UpdatePSBTOutput add before signing:
 *   inputs : redeem_script (0x04), witness_script (0x05), bip32_derivs
 *            (0x06); tr(): tap_leaf_script (0x15) per leaf with its control
 *            block, tap_bip32_derivation (0x16) with leaf hashes, internal
 *            key (0x17), merkle root (0x18)
 *   outputs: redeem_script (0x00), witness_script (0x01), bip32_derivs
 *            (0x02); tr(): internal key (0x05), tree (0x06), derivs (0x07)
 * Fields already present are kept; nothing is removed. musig() aggregates
 * are the musig updater's business (rpc_commands.c) and are skipped here.
 * Self-contained PSBT map handling so this file merges independently of the
 * PSBT-version work in rpc_commands.c. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "descriptor.h"
#include "psbt_update.h"
typedef unsigned char u8;
extern void hash160(u8 out[20], const void* in, long long len);
extern void sha256_full(u8 out[32], const void* msg, unsigned long len);

typedef struct { const u8* k; unsigned long kl; const u8* v; unsigned long vl; } kv_t;
#define PU_MAXIO 1000
#define PU_MAXKV 160
static unsigned long rd_varint(const u8* p, unsigned long* cc){
    if (p[0] < 0xfd){ *cc = 1; return p[0]; }
    if (p[0] == 0xfd){ *cc = 3; return (unsigned long)p[1] | ((unsigned long)p[2] << 8); }
    if (p[0] == 0xfe){ *cc = 5; return (unsigned long)p[1] | ((unsigned long)p[2] << 8) | ((unsigned long)p[3] << 16) | ((unsigned long)p[4] << 24); }
    *cc = 9; unsigned long v = 0; for (int i = 0; i < 8; i++) v |= (unsigned long)p[1+i] << (8*i); return v;
}
/* ---------------------------------------------------------------- WAL-14
 * (audit 2026-09-03) A CompactSize read that cannot leave the buffer.
 *
 * rd_varint above takes a bare pointer and reads up to NINE bytes from it,
 * so it runs off the end whenever it is called near the buffer's tail -- and
 * parse_map called it exactly there, then advanced by the length it returned
 * without comparing that length to what remained. A PSBT with a 0xff-varint
 * key length walked `p` far past `blen`, and ser_map/has_key then read from
 * wherever it landed. The audit rated this PLAUSIBLE because reachability
 * depends on how completely psbt_v2_normalize validates first; a parser that
 * is only safe because of what runs before it is one refactor away from not
 * being safe, so it is bounded here regardless.
 *
 * Returns 1 and fills the value and consumed-count, or 0 if the encoding
 * would read past `avail`.
 */
static int rd_varint_b(const u8* p, unsigned long avail, unsigned long* out, unsigned long* cc){
    if (avail < 1) return 0;
    if (p[0] < 0xfd){ *cc = 1; *out = p[0]; return 1; }
    if (p[0] == 0xfd){ if (avail < 3) return 0; *cc = 3;
        *out = (unsigned long)p[1] | ((unsigned long)p[2] << 8); return 1; }
    if (p[0] == 0xfe){ if (avail < 5) return 0; *cc = 5;
        *out = (unsigned long)p[1] | ((unsigned long)p[2] << 8) |
               ((unsigned long)p[3] << 16) | ((unsigned long)p[4] << 24); return 1; }
    if (avail < 9) return 0;
    *cc = 9;
    { unsigned long v = 0; for (int i = 0; i < 8; i++) v |= (unsigned long)p[1+i] << (8*i); *out = v; }
    return 1;
}
static long wr_varint(u8* o, unsigned long long v){
    if (v < 0xfd){ o[0] = (u8)v; return 1; }
    if (v <= 0xffff){ o[0] = 0xfd; o[1] = (u8)v; o[2] = (u8)(v >> 8); return 3; }
    if (v <= 0xffffffffULL){ o[0] = 0xfe; for (int i = 0; i < 4; i++) o[1+i] = (u8)(v >> (8*i)); return 5; }
    o[0] = 0xff; for (int i = 0; i < 8; i++) o[1+i] = (u8)(v >> (8*i)); return 9;
}
static int b64dec(const char* in, u8* out, long cap, long* outn){
    static signed char T[256]; static int init = 0;
    if (!init){ for (int i = 0; i < 256; i++) T[i] = -1; const char* B = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; for (int i = 0; i < 64; i++) T[(u8)B[i]] = (signed char)i; init = 1; }
    long o = 0; unsigned v = 0; int bits = 0;
    for (const char* p = in; *p; p++){
        if (*p == '=') break;
        if (*p == '\n' || *p == '\r' || *p == ' ') continue;
        int d = T[(u8)*p]; if (d < 0) return 0;
        v = (v << 6) | (unsigned)d; bits += 6;
        if (bits >= 8){ bits -= 8; if (o >= cap) return 0; out[o++] = (u8)((v >> bits) & 0xff); }
    }
    *outn = o; return 1;
}
static void b64enc(char* out, const u8* in, long n){
    static const char* B = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; long o = 0;
    for (long i = 0; i < n; i += 3){ unsigned v = (unsigned)in[i] << 16 | (i+1 < n ? (unsigned)in[i+1] << 8 : 0) | (i+2 < n ? in[i+2] : 0);
        out[o++] = B[v >> 18]; out[o++] = B[(v >> 12) & 63]; out[o++] = i+1 < n ? B[(v >> 6) & 63] : '='; out[o++] = i+2 < n ? B[v & 63] : '='; }
    out[o] = 0;
}
/* WAL-14: every read below is bounded by `blen`, and a malformed map is
 * reported as -1 rather than as a count. The callers check it: letting a
 * negative flow into their loops happens to be harmless today (find_kv with
 * n < 0 iterates zero times) but that is luck, not design. */
static int parse_map(const u8* buf, long blen, long* pp, kv_t* kvs, int cap){
    int n = 0; long p = *pp;
    if (p < 0 || p > blen) return -1;
    while (p < blen){
        unsigned long cc, kl, vl;
        unsigned long avail = (unsigned long)(blen - p);
        if (!rd_varint_b(buf + p, avail, &kl, &cc)) return -1;
        p += (long)cc;
        if (kl == 0){ *pp = p; return n; }            /* 0x00 terminates the map */
        if (kl > (unsigned long)(blen - p)) return -1;
        const u8* k = buf + p; p += (long)kl;
        if (!rd_varint_b(buf + p, (unsigned long)(blen - p), &vl, &cc)) return -1;
        p += (long)cc;
        if (vl > (unsigned long)(blen - p)) return -1;
        const u8* v = buf + p; p += (long)vl;
        if (n < cap){ kvs[n].k = k; kvs[n].kl = kl; kvs[n].v = v; kvs[n].vl = vl; n++; }
    }
    return -1;                                        /* ran out with no terminator */
}
static long ser_map(u8* out, const kv_t* kvs, int n){
    long o = 0;
    for (int i = 0; i < n; i++){ o += wr_varint(out+o, kvs[i].kl); memcpy(out+o, kvs[i].k, kvs[i].kl); o += kvs[i].kl; o += wr_varint(out+o, kvs[i].vl); memcpy(out+o, kvs[i].v, kvs[i].vl); o += kvs[i].vl; }
    out[o++] = 0; return o;
}
static const kv_t* find_kv(const kv_t* kv, int n, u8 t){ for (int i = 0; i < n; i++) if (kv[i].kl >= 1 && kv[i].k[0] == t) return &kv[i]; return NULL; }
static int has_key(const kv_t* kv, int n, const u8* k, unsigned long kl){ for (int i = 0; i < n; i++) if (kv[i].kl == kl && !memcmp(kv[i].k, k, kl)) return 1; return 0; }
/* bump arena for the fields added in one call */
static u8* g_arena; static unsigned long g_arena_n, g_arena_cap;
static u8* ar(unsigned long n){ if (!g_arena || g_arena_n + n > g_arena_cap) return NULL; u8* p = g_arena + g_arena_n; g_arena_n += n; return p; }
static int add_kv(kv_t* kv, int* n, const u8* k, unsigned long kl, const u8* v, unsigned long vl){
    if (*n >= PU_MAXKV || has_key(kv, *n, k, kl)) return 0;
    u8* kk = ar(kl); u8* vv = ar(vl); if (!kk || (vl && !vv)) return 0;
    memcpy(kk, k, kl); if (vl) memcpy(vv, v, vl);
    kv[*n].k = kk; kv[*n].kl = kl; kv[*n].v = vv; kv[*n].vl = vl; (*n)++; return 1;
}
/* the unsigned tx: input outpoints and output scripts */
typedef struct { const u8* op; } tin_t;
typedef struct { const u8* spk; unsigned long len; const u8* value; } tout_t;
static int walk_tx(const u8* tx, unsigned long len, tin_t* ins, int icap, int* nin, tout_t* outs, int ocap, int* nout){
    if (len < 10) return 0;
    unsigned long p = 4, cc;
    if (tx[4] == 0 && tx[5] == 1) p = 6;
    unsigned long ni;
    if (!rd_varint_b(tx+p, len - p, &ni, &cc)) return 0;
    p += cc; if (ni > (unsigned long)icap) return 0;
    for (unsigned long i = 0; i < ni; i++){
        if (p + 36 > len) return 0;
        ins[i].op = tx+p; p += 36;
        unsigned long sl;
        if (!rd_varint_b(tx+p, len - p, &sl, &cc)) return 0;
        p += cc;
        /* VAL-15 shape: `p += cc + sl + 4; if (p > len)` WRAPS for sl near
         * 2^64 and passes the check on a wrapped pointer. Split so neither
         * side can overflow. */
        if (sl > len - p || len - p - sl < 4) return 0;
        p += sl + 4; }
    unsigned long no;
    if (!rd_varint_b(tx+p, len - p, &no, &cc)) return 0;
    p += cc; if (no > (unsigned long)ocap) return 0;
    for (unsigned long i = 0; i < no; i++){
        if (p + 9 > len) return 0;
        outs[i].value = tx+p; p += 8;
        unsigned long sl;
        if (!rd_varint_b(tx+p, len - p, &sl, &cc)) return 0;
        p += cc;
        if (sl > len - p) return 0;                   /* VAL-15 shape, split */
        outs[i].spk = tx+p; outs[i].len = sl; p += sl; }
    *nin = (int)ni; *nout = (int)no; return 1;
}
/* the input's scriptPubKey: witness_utxo, else the non-witness parent's output */
static int input_spk(const kv_t* kv, int n, const u8* op, const u8** spk, unsigned long* spklen, const u8** value){
    *value = NULL;
    const kv_t* wu = find_kv(kv, n, 0x01);
    if (wu && wu->vl >= 9){ unsigned long cc; unsigned long sl = rd_varint(wu->v + 8, &cc); if (8 + cc + sl <= wu->vl){ *spk = wu->v + 8 + cc; *spklen = sl; return 1; } }
    const kv_t* nw = find_kv(kv, n, 0x00);
    if (!nw) return 0;
    unsigned long vout = (unsigned long)op[32] | ((unsigned long)op[33] << 8) | ((unsigned long)op[34] << 16) | ((unsigned long)op[35] << 24);
    static tin_t ti[PU_MAXIO]; static tout_t to[PU_MAXIO]; int a, b;
    if (!walk_tx(nw->v, nw->vl, ti, PU_MAXIO, &a, to, PU_MAXIO, &b) || vout >= (unsigned long)b) return 0;
    *spk = to[vout].spk; *spklen = to[vout].len; *value = to[vout].value; return 1;
}
/* key origin per Core's KeyOriginInfo: origin fingerprint+path, else the extended key's own
 * fingerprint, else hash160(pub)[0:4]; then the key's derivation path and the range index */
static int key_origin(const descr_t* d, int ki, long idx, u8* out, unsigned long cap){
    const descr_key_t* k = &d->keys[ki];
    unsigned long o = 0; unsigned pp[DESCR_MAX_PATH * 2 + 2]; int pn = 0;
    if (k->has_origin){ memcpy(out, k->origin_fp, 4); for (int z = 0; z < k->origin_len; z++) pp[pn++] = k->origin[z]; }
    else { u8 h[20];
           if (k->publen == 32){ u8 c[33]; c[0] = 0x02; memcpy(c + 1, k->pub, 32); hash160(h, c, 33); }   /* Core: an x-only key's even-Y compressed form */
           else hash160(h, k->pub, (k->kind == DK_XPUB || k->kind == DK_XPRV) ? 33 : k->publen);
           memcpy(out, h, 4); }
    o = 4;
    if (k->kind == DK_XPUB || k->kind == DK_XPRV){
        for (int z = 0; z < k->pathlen; z++) pp[pn++] = k->path[z];
        if (k->ranged) pp[pn++] = (unsigned)idx | (k->range_hard ? 0x80000000u : 0);
    }
    if (o + 4 * (unsigned long)pn > cap) return 0;
    for (int z = 0; z < pn; z++){
        out[o] = (u8)pp[z]; out[o+1] = (u8)(pp[z] >> 8); out[o+2] = (u8)(pp[z] >> 16); out[o+3] = (u8)(pp[z] >> 24); o += 4; }
    return (int)o;
}
static int is_musig_part(const descr_t* d, int ki){
    for (int q = 0; q < d->nk; q++) if (d->keys[q].kind == DK_MUSIG) for (int z = 0; z < d->keys[q].musig_n; z++) if (d->keys[q].musig_parts[z] == ki) return 1;
    return 0;
}
static int script_has_xonly(const u8* sc, int sl, const u8 x[32]){
    for (int i = 0; i + 33 <= sl; i++) if (sc[i] == 0x20 && !memcmp(sc + i + 1, x, 32)) return 1;
    return 0;
}
/* add the fields for one matched (descriptor, idx) to a map; `side` 0 = input, 1 = output */
static int fill(kv_t* kv, int* n, descr_t* d, long idx, int side, int* changed){
    int t = d->nodes[d->root].type;
    u8 tmp[4200]; int added = 0;
    if (t == DN_RAWTR){
        /* rawtr(): the key IS the output key -- no internal key, no tree; the
         * musig() updater (rpc_commands.c) owns the participant fields */
        return 1;
    }
    if (t == DN_TR){
        static descr_leaf_t leaves[128]; u8 internal[32], root[32]; int has_root = 0, odd = 0;
        int nl = descr_tr_leaves(d, idx, leaves, 128, internal, root, &has_root, &odd);
        if (nl < 0) return 0;
        u8 k1 = side ? 0x05 : 0x17;
        added += add_kv(kv, n, &k1, 1, internal, 32);
        if (!side && has_root){ u8 k2 = 0x18; added += add_kv(kv, n, &k2, 1, root, 32); }
        if (!side){
            for (int i = 0; i < nl; i++){
                if (leaves[i].slen + 1 > (int)sizeof tmp) continue;
                u8* key = ar(1 + (unsigned long)leaves[i].ctrl_len); if (!key) break;
                key[0] = 0x15; memcpy(key + 1, leaves[i].ctrl, (size_t)leaves[i].ctrl_len);
                memcpy(tmp, leaves[i].script, (size_t)leaves[i].slen); tmp[leaves[i].slen] = (u8)leaves[i].leaf_ver;
                added += add_kv(kv, n, key, 1 + (unsigned long)leaves[i].ctrl_len, tmp, (unsigned long)leaves[i].slen + 1);
            }
        } else if (nl > 0){
            /* taproot_tree: (depth, leaf_ver, script) per leaf in DFS order */
            u8* tree = ar(4200 * 4); if (!tree) return 0; unsigned long o = 0;
            /* Core's TaprootBuilder::GetTreeTuples lists the leaves right-most first (its Combine puts
             * the newer node's leaves ahead of the older's); the PSBT_OUT_TAP_TREE field must match */
            for (int i = nl - 1; i >= 0; i--){ if (o + 2 + 9 + (unsigned long)leaves[i].slen > 4200 * 4) break; tree[o++] = (u8)leaves[i].depth; tree[o++] = (u8)leaves[i].leaf_ver; o += wr_varint(tree + o, (unsigned long long)leaves[i].slen); memcpy(tree + o, leaves[i].script, (size_t)leaves[i].slen); o += leaves[i].slen; }
            u8 k3 = 0x06; added += add_kv(kv, n, &k3, 1, tree, o);
        }
        /* tap bip32 derivations: internal key (no leaf hashes) and every leaf key with its leaf hashes */
        for (int ki = 0; ki < d->nk; ki++){
            const descr_key_t* k = &d->keys[ki];
            if (k->kind == DK_MUSIG || is_musig_part(d, ki)) continue;
            u8 pub[65]; int pl; if (!descr_key_pub_at(d, ki, idx, pub, &pl)) continue;
            const u8* x = pl == 32 ? pub : pub + 1; if (pl != 32 && pl != 33) continue;
            int nlh = 0; u8 lhs[128][32];
            for (int i = 0; i < nl; i++) if (script_has_xonly(leaves[i].script, leaves[i].slen, x)) memcpy(lhs[nlh++], leaves[i].leaf_hash, 32);
            int is_internal = !memcmp(x, internal, 32);
            if (!nlh && !is_internal) continue;
            u8 key[33]; key[0] = side ? 0x07 : 0x16; memcpy(key + 1, x, 32);
            unsigned long o = 0; o += wr_varint(tmp + o, (unsigned long long)nlh); for (int i = 0; i < nlh; i++){ memcpy(tmp + o, lhs[i], 32); o += 32; }
            int ol = key_origin(d, ki, idx, tmp + o, sizeof tmp - o); if (ol <= 0) continue; o += ol;
            added += add_kv(kv, n, key, 33, tmp, o);
        }
    } else if (t != DN_ADDR && t != DN_RAW){
        u8 inner[1400]; int which = 0; int il = descr_inner_script_at(d, idx, inner, (int)sizeof inner, &which);
        if (il > 0){
            if (which == 2 || which == 3){ u8 k5 = side ? 0x01 : 0x05; added += add_kv(kv, n, &k5, 1, inner, (unsigned long)il); }
            if (which == 1){ u8 k4 = side ? 0x00 : 0x04; added += add_kv(kv, n, &k4, 1, inner, (unsigned long)il); }
            if (which == 3){ u8 rd[34]; rd[0] = 0; rd[1] = 0x20; sha256_full(rd + 2, inner, (unsigned long)il); u8 k4 = side ? 0x00 : 0x04; added += add_kv(kv, n, &k4, 1, rd, 34); }
        }
        for (int ki = 0; ki < d->nk; ki++){
            const descr_key_t* k = &d->keys[ki];
            if (k->kind == DK_MUSIG || is_musig_part(d, ki)) continue;
            u8 pub[65]; int pl; if (!descr_key_pub_at(d, ki, idx, pub, &pl) || (pl != 33 && pl != 65)) continue;
            u8 key[66]; key[0] = side ? 0x02 : 0x06; memcpy(key + 1, pub, (size_t)pl);
            int ol = key_origin(d, ki, idx, tmp, sizeof tmp); if (ol <= 0) continue;
            added += add_kv(kv, n, key, 1 + (unsigned long)pl, tmp, (unsigned long)ol);
        }
    }
    if (added) *changed = 1;
    return 1;
}
static int match_desc(pu_desc_t* dv, int nd, const u8* spk, unsigned long spklen, descr_t** dout, long* idx_out){
    for (int di = 0; di < nd; di++){
        descr_t* d = dv[di].d;
        for (long idx = dv[di].lo; idx <= dv[di].hi; idx++){
            descr_spk_t sp[4]; int n = descr_expand(d, idx, sp, 4);
            for (int q = 0; q < n; q++) if ((unsigned long)sp[q].len == spklen && !memcmp(sp[q].spk, spk, spklen)){ *dout = d; *idx_out = idx; return 1; }
        }
    }
    return 0;
}
long psbt_update_bytes_from_descs(const u8* buf, long blen, pu_desc_t* dv, int nd, u8* outbuf, long outcap){
    if (blen < 5 || memcmp(buf, "psbt\xff", 5)) return -1;
    long p = 5;
    static kv_t gkv[PU_MAXKV]; int gn = parse_map(buf, blen, &p, gkv, PU_MAXKV);
    if (gn < 0) return -1;                            /* WAL-14: malformed map */
    const kv_t* utx = find_kv(gkv, gn, 0x00); if (!utx) return -1;
    static tin_t ins[PU_MAXIO]; static tout_t outs[PU_MAXIO]; int n_in, n_out;
    if (!walk_tx(utx->v, utx->vl, ins, PU_MAXIO, &n_in, outs, PU_MAXIO, &n_out)) return -1;
    static kv_t ikv[PU_MAXIO][PU_MAXKV]; static int in_n[PU_MAXIO];
    static kv_t okv[PU_MAXIO][PU_MAXKV]; static int out_n[PU_MAXIO];
    for (int i = 0; i < n_in; i++){ in_n[i] = parse_map(buf, blen, &p, ikv[i], PU_MAXKV); if (in_n[i] < 0) return -1; }
    for (int i = 0; i < n_out; i++){ out_n[i] = parse_map(buf, blen, &p, okv[i], PU_MAXKV); if (out_n[i] < 0) return -1; }
    static u8 arena[8u << 20]; g_arena = arena; g_arena_n = 0; g_arena_cap = sizeof arena;
    int changed = 0;
    for (int i = 0; i < n_in; i++){
        const u8* spk; unsigned long sl; const u8* value;
        if (!input_spk(ikv[i], in_n[i], ins[i].op, &spk, &sl, &value)) continue;
        descr_t* d; long idx; if (!match_desc(dv, nd, spk, sl, &d, &idx)) continue;
        /* Core's signer step puts a witness_utxo on every witness input it touches
         * (SignPSBTInput: "If we have a witness signature, put a witness UTXO") --
         * including nested segwit, where the witness program hides inside sh(...) */
        int is_wit = (sl == 22 && spk[0] == 0x00 && spk[1] == 0x14) || (sl == 34 && (spk[0] == 0x00 || spk[0] == 0x51) && spk[1] == 0x20);
        if (!is_wit && sl == 23 && spk[0] == 0xa9){
            u8 inner[1400]; int which = 0; int il = descr_inner_script_at(d, idx, inner, (int)sizeof inner, &which);
            if (which == 3) is_wit = 1;                                                          /* sh(wsh(...)) */
            if (which == 1 && il >= 4 && ((il == 22 && inner[0] == 0x00 && inner[1] == 0x14) || (il == 34 && inner[0] == 0x00 && inner[1] == 0x20))) is_wit = 1;   /* sh(wpkh) */
        }
        if (is_wit && value && !find_kv(ikv[i], in_n[i], 0x01) && sl < 200){
            u8 wu[8 + 9 + 200]; unsigned long o = 0; memcpy(wu, value, 8); o = 8; o += wr_varint(wu + o, sl); memcpy(wu + o, spk, sl); o += sl;
            u8 k1 = 0x01; if (add_kv(ikv[i], &in_n[i], &k1, 1, wu, o)) changed = 1;
            /* the spk pointer now aliases the arena copy; re-resolve for fill() */
            if (!input_spk(ikv[i], in_n[i], ins[i].op, &spk, &sl, &value)) continue;
            if (!match_desc(dv, nd, spk, sl, &d, &idx)) continue;
        }
        fill(ikv[i], &in_n[i], d, idx, 0, &changed);
    }
    for (int i = 0; i < n_out; i++){
        descr_t* d; long idx; if (!match_desc(dv, nd, outs[i].spk, outs[i].len, &d, &idx)) continue;
        fill(okv[i], &out_n[i], d, idx, 1, &changed);
    }
    if (!changed) return 0;
    long need = 5; for (int i = 0; i < gn; i++) need += 20 + (long)gkv[i].kl + (long)gkv[i].vl;
    for (int i = 0; i < n_in; i++) for (int k = 0; k < in_n[i]; k++) need += 20 + (long)ikv[i][k].kl + (long)ikv[i][k].vl;
    for (int i = 0; i < n_out; i++) for (int k = 0; k < out_n[i]; k++) need += 20 + (long)okv[i][k].kl + (long)okv[i][k].vl;
    if (need + 8 > outcap) return -1;
    long o = 0; memcpy(outbuf, "psbt\xff", 5); o = 5;
    o += ser_map(outbuf + o, gkv, gn);
    for (int i = 0; i < n_in; i++) o += ser_map(outbuf + o, ikv[i], in_n[i]);
    for (int i = 0; i < n_out; i++) o += ser_map(outbuf + o, okv[i], out_n[i]);
    return o;
}
char* psbt_update_from_descs(const char* b64, pu_desc_t* dv, int nd){
    static u8 buf[200000]; long blen = 0;
    if (!b64dec(b64, buf, sizeof buf, &blen)) return NULL;
    static u8 out[240000];
    long o = psbt_update_bytes_from_descs(buf, blen, dv, nd, out, sizeof out);
    if (o <= 0) return NULL;
    char* b = malloc((size_t)((o + 2) / 3) * 4 + 1); if (!b) return NULL;
    b64enc(b, out, o); return b;
}
