/* tests/test_psbt_update.c -- the PSBT Updater from descriptors (psbt_update.c),
 * 2026-09-01. A PSBT that carries only witness_utxo; descriptorprocesspsbt /
 * utxoupdatepsbt must add what Core's Updater adds:
 *   1. tr(K2,{pk(K1),multi_a(2,K0,K1)}) with PUBLIC keys: taproot_scripts
 *      (both leaves, control blocks), taproot_internal_key, taproot_merkle_root,
 *      taproot_bip32_derivs with the right leaf hashes; nothing signed;
 *   2. the same with K1's private key: signs leaf A -- no fields pre-supplied;
 *   3. wsh(multi(2,K0,K1)): witness_script + bip32_derivs (fingerprint =
 *      hash160(pub)[0:4], empty path);
 *   4. an xpub with an origin: bip32_derivs carry the origin fingerprint and
 *      the full path incl. the range index;
 *   5. output-side fields for an output paying a tr() expansion (internal key,
 *      taproot_tree, taproot_bip32_derivs);
 *   6. utxoupdatepsbt with descriptors adds the same. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../rpc_commands.h"
#include "../rpc_json.h"
#include "../descriptor.h"
typedef unsigned char u8;
extern void scalar_to_pubkey(u8 pub[33], const u8 priv_be[32]);
extern void sha256_full(u8 out[32], const void* msg, unsigned long len);
extern void base58check_encode(char* out, const u8* payload, int len);
extern int  bip32_xonly_tweak_add_par(const u8* x, const u8* t, u8* out_x, int* odd);
extern void hash160(u8 out[20], const void* in, long long len);
static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }
static void hexs(char* o, const u8* b, int n){ for (int i = 0; i < n; i++) sprintf(o + 2*i, "%02x", b[i]); o[2*n] = 0; }
static const char* S(rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o, k) : NULL; return v ? v->str : NULL; }
static const char* SH(rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o, k) : NULL; if (!v) return NULL; if (v->typ == RJ_OBJ){ rj_val* h = rj_obj_get(v, "hex"); return h ? h->str : NULL; } return v->str; }
static rj_val* call(const char* m, const char* pj, long* ec, const char** em){ rj_val* p = rj_parse(pj, strlen(pj)); rj_val* r = NULL; rpc_wallet w; memset(&w, 0, sizeof w); *ec = 0; *em = NULL; int ok = rpc_dispatch(m, p, &w, &r, ec, em); rj_free(p); if (!ok){ if (r) rj_free(r); return NULL; } return r; }
static long vi(u8* o, unsigned long v){ if (v < 0xfd){ o[0] = (u8)v; return 1; } o[0] = 0xfd; o[1] = (u8)v; o[2] = (u8)(v >> 8); return 3; }
static long kv(u8* o, const u8* k, unsigned long kl, const u8* v, unsigned long vl){ long n = 0; n += vi(o+n, kl); memcpy(o+n, k, kl); n += kl; n += vi(o+n, vl); memcpy(o+n, v, vl); n += vl; return n; }
static void b64(char* out, const u8* in, long n){ static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; long o = 0; for (long i = 0; i < n; i += 3){ unsigned v = in[i] << 16 | (i+1 < n ? in[i+1] << 8 : 0) | (i+2 < n ? in[i+2] : 0); out[o++] = T[v >> 18]; out[o++] = T[(v >> 12) & 63]; out[o++] = i+1 < n ? T[(v >> 6) & 63] : '='; out[o++] = i+2 < n ? T[v & 63] : '='; } out[o] = 0; }
static void tagged(u8 out[32], const char* tag, const u8* a, unsigned long al, const u8* b, unsigned long bl){ u8 th[32]; sha256_full(th, tag, strlen(tag)); u8* buf = malloc(64 + al + bl); memcpy(buf, th, 32); memcpy(buf+32, th, 32); memcpy(buf+64, a, al); if (bl) memcpy(buf+64+al, b, bl); sha256_full(out, buf, 64 + al + bl); free(buf); }
static void leafhash(u8 out[32], const u8* sc, unsigned long n){ u8* b = malloc(2 + n); b[0] = 0xc0; b[1] = (u8)n; memcpy(b+2, sc, n); tagged(out, "TapLeaf", b, 2 + n, NULL, 0); free(b); }
static void branch(u8 out[32], const u8* a, const u8* b){ if (memcmp(a, b, 32) <= 0) tagged(out, "TapBranch", a, 32, b, 32); else tagged(out, "TapBranch", b, 32, a, 32); }
/* unsigned tx: 1 input (txid 03..), 1 output paying `ospk` */
static long mk_utx(u8* o, const u8* ospk, int ol){ long n = 0; o[n++]=2;o[n++]=0;o[n++]=0;o[n++]=0; o[n++]=1; memset(o+n, 3, 32); n += 32; o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=0; o[n++]=0; o[n++]=0xfd;o[n++]=0xff;o[n++]=0xff;o[n++]=0xff; o[n++]=1; unsigned long long v = 99000000ULL; for (int i = 0; i < 8; i++) o[n++] = (u8)(v >> (8*i)); o[n++] = (u8)ol; memcpy(o+n, ospk, ol); n += ol; o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=0; return n; }
static void mk_psbt(char* out, const u8* utx, long ul, const u8* spk, int sl){
    static u8 ps[4000]; long o = 0; ps[o++]='p'; ps[o++]='s'; ps[o++]='b'; ps[o++]='t'; ps[o++]=0xff;
    { u8 k = 0; o += kv(ps+o, &k, 1, utx, ul); ps[o++] = 0; }
    { u8 wu[200]; long w = 0; unsigned long long val = 100000000ULL; for (int i = 0; i < 8; i++) wu[w++] = (u8)(val >> (8*i)); wu[w++] = (u8)sl; memcpy(wu+w, spk, sl); w += sl; u8 k = 1; o += kv(ps+o, &k, 1, wu, (unsigned long)w); ps[o++] = 0; }
    ps[o++] = 0; b64(out, ps, o);
}
static rj_val* decode(const char* b64s){ char pj[8000]; snprintf(pj, sizeof pj, "[\"%s\"]", b64s); long ec; const char* em; return call("decodepsbt", pj, &ec, &em); }
static rj_val* in0(rj_val* d){ rj_val* ins = d ? rj_obj_get(d, "inputs") : NULL; return ins && ins->nitems ? ins->items[0] : NULL; }
static rj_val* out0(rj_val* d){ rj_val* outs = d ? rj_obj_get(d, "outputs") : NULL; return outs && outs->nitems ? outs->items[0] : NULL; }
int main(void){
    u8 priv[3][32], pub[3][33]; char wif[3][64], xh[3][65], ph[3][67];
    for (int k = 0; k < 3; k++){ for (int i = 0; i < 32; i++) priv[k][i] = (u8)(0x11*(k+1)); scalar_to_pubkey(pub[k], priv[k]); hexs(xh[k], pub[k]+1, 32); hexs(ph[k], pub[k], 33);
        u8 pay[34]; pay[0] = 0x80; memcpy(pay+1, priv[k], 32); pay[33] = 1; base58check_encode(wif[k], pay, 34); }
    /* the tree: A = pk(x1), B = multi_a(2,x0,x1), internal x2 */
    u8 la[34]; la[0] = 0x20; memcpy(la+1, pub[1]+1, 32); la[33] = 0xac;
    u8 lb[70]; int lo = 0; lb[lo++] = 0x20; memcpy(lb+lo, pub[0]+1, 32); lo += 32; lb[lo++] = 0xac; lb[lo++] = 0x20; memcpy(lb+lo, pub[1]+1, 32); lo += 32; lb[lo++] = 0xba; lb[lo++] = 0x52; lb[lo++] = 0x9c;
    u8 ha[32], hb[32], root[32]; leafhash(ha, la, 34); leafhash(hb, lb, (unsigned long)lo); branch(root, ha, hb);
    u8 t[32]; tagged(t, "TapTweak", pub[2]+1, 32, root, 32); u8 Q[32]; int odd = 0; bip32_xonly_tweak_add_par(pub[2]+1, t, Q, &odd);
    u8 spk[34]; spk[0] = 0x51; spk[1] = 0x20; memcpy(spk+2, Q, 32);
    char hah[65], hbh[65], rooth[65]; hexs(hah, ha, 32); hexs(hbh, hb, 32); hexs(rooth, root, 32);
    static u8 utx[400]; long ul = mk_utx(utx, spk, 34);   /* the output pays the SAME tr() (change-like): output-side fields expected */
    static char ps64[6000], pj[8000]; long ec; const char* em; rj_val* r; rj_val* d;
    mk_psbt(ps64, utx, ul, spk, 34);
    char desc_pub[400]; snprintf(desc_pub, sizeof desc_pub, "tr(%s,{pk(%s),multi_a(2,%s,%s)})", xh[2], xh[1], xh[0], xh[1]);

    printf("== 1. tr() with public keys: the Updater fills the taproot fields, nothing signs ==\n");
    snprintf(pj, sizeof pj, "[\"%s\", [\"%s\"], \"DEFAULT\", true, false]", ps64, desc_pub);
    r = call("descriptorprocesspsbt", pj, &ec, &em);
    ck("descriptorprocesspsbt returns", r && S(r, "psbt")); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
    ck("...complete=false (no private keys)", r && S(r, "complete") && S(r, "complete")[0] == '0');
    d = r && S(r, "psbt") ? decode(S(r, "psbt")) : NULL; rj_val* i0 = in0(d);
    { rj_val* ts = i0 ? rj_obj_get(i0, "taproot_scripts") : NULL;
      ck("taproot_scripts: both leaves", ts && ts->nitems == 2);
      int ok = ts && ts->nitems == 2; char lah[80]; hexs(lah, la, 34); char lbh[160]; hexs(lbh, lb, lo);
      int seen_a = 0, seen_b = 0;
      for (unsigned long q = 0; ok && q < ts->nitems; q++){ const char* sc = S(ts->items[q], "script"); rj_val* cb = rj_obj_get(ts->items[q], "control_blocks");
          if (sc && !strcmp(sc, lah)){ seen_a = cb && cb->nitems == 1 && cb->items[0]->str && strlen(cb->items[0]->str) == 130 && !strncmp(cb->items[0]->str + 2, xh[2], 64) && !strcmp(cb->items[0]->str + 66, hbh); }
          if (sc && !strcmp(sc, lbh)){ seen_b = cb && cb->nitems == 1 && cb->items[0]->str && !strcmp(cb->items[0]->str + 66, hah); } }
      ck("...leaf A's control block = parity|internal|hash(B), leaf B's = ...|hash(A)", seen_a && seen_b);
      { const char* c0 = ts && ts->nitems ? (rj_obj_get(ts->items[0], "control_blocks") ? rj_obj_get(ts->items[0], "control_blocks")->items[0]->str : NULL) : NULL;
        ck("...control byte carries the output parity", c0 && ((c0[1] == '0' && !odd) || (c0[1] == '1' && odd))); }
      ck("taproot_internal_key", i0 && S(i0, "taproot_internal_key") && !strcmp(S(i0, "taproot_internal_key"), xh[2]));
      ck("taproot_merkle_root", i0 && S(i0, "taproot_merkle_root") && !strcmp(S(i0, "taproot_merkle_root"), rooth));
      rj_val* dv = i0 ? rj_obj_get(i0, "taproot_bip32_derivs") : NULL;
      ck("taproot_bip32_derivs: internal + x0 + x1", dv && dv->nitems == 3);
      int ok1 = 0, ok0 = 0, oki = 0;
      for (unsigned long q = 0; dv && q < dv->nitems; q++){ rj_val* e = dv->items[q]; const char* pk = S(e, "pubkey"); rj_val* lh = rj_obj_get(e, "leaf_hashes");
          u8 h[20]; char fp[9];
          if (pk && !strcmp(pk, xh[1])){ ok1 = lh && lh->nitems == 2; u8 c2[33]; c2[0] = 2; memcpy(c2+1, pub[1]+1, 32); hash160(h, c2, 33); hexs(fp, h, 4); ok1 = ok1 && S(e, "master_fingerprint") && !strcmp(S(e, "master_fingerprint"), fp) && S(e, "path") && !strcmp(S(e, "path"), "m"); }
          if (pk && !strcmp(pk, xh[0])){ ok0 = lh && lh->nitems == 1 && lh->items[0]->str && !strcmp(lh->items[0]->str, hbh); }
          if (pk && !strcmp(pk, xh[2])){ oki = lh && lh->nitems == 0; } }
      ck("...x1 in both leaves with hash160 fingerprint and path m; x0 in leaf B only; internal key with no leaf hashes", ok1 && ok0 && oki);
      rj_val* o0 = out0(d);
      ck("output paying the same tr(): taproot_internal_key, taproot_tree (2 leaves), taproot_bip32_derivs", o0 && S(o0, "taproot_internal_key") && rj_obj_get(o0, "taproot_tree") && rj_obj_get(o0, "taproot_tree")->nitems == 2 && rj_obj_get(o0, "taproot_bip32_derivs") && rj_obj_get(o0, "taproot_bip32_derivs")->nitems == 3);
      { rj_val* tt = o0 ? rj_obj_get(o0, "taproot_tree") : NULL; ck("...tree leaves at depth 1 with leaf_ver 192", tt && tt->nitems == 2 && S(tt->items[0], "depth") && !strcmp(S(tt->items[0], "depth"), "1") && !strcmp(S(tt->items[0], "leaf_ver"), "192")); } }
    if (d) rj_free(d); if (r) rj_free(r);

    printf("== 2. with x1's private key: signs leaf A with no fields pre-supplied ==\n");
    snprintf(pj, sizeof pj, "[\"%s\", [\"tr(%s,{pk(%s),multi_a(2,%s,%s)})\"]]", ps64, xh[2], wif[1], xh[0], xh[1]);
    r = call("descriptorprocesspsbt", pj, &ec, &em);
    ck("complete via leaf A", r && S(r, "complete") && S(r, "complete")[0] == '1'); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
    { const char* h = r ? S(r, "hex") : NULL; char lah[80]; hexs(lah, la, 34); ck("...the witness carries leaf A and a control block naming the internal key", h && strstr(h, lah) && strstr(h, xh[2])); }
    if (r) rj_free(r);

    printf("== 3. wsh(multi(2,K0,K1)) public: witness_script + bip32_derivs ==\n");
    { u8 ws[71]; int o = 0; ws[o++] = 0x52; ws[o++] = 33; memcpy(ws+o, pub[0], 33); o += 33; ws[o++] = 33; memcpy(ws+o, pub[1], 33); o += 33; ws[o++] = 0x52; ws[o++] = 0xae;
      u8 wsh[32]; sha256_full(wsh, ws, (unsigned long)o); u8 wspk[34]; wspk[0] = 0; wspk[1] = 0x20; memcpy(wspk+2, wsh, 32);
      static u8 utx2[400]; long ul2 = mk_utx(utx2, wspk, 34); mk_psbt(ps64, utx2, ul2, wspk, 34);
      snprintf(pj, sizeof pj, "[\"%s\", [\"wsh(multi(2,%s,%s))\"], \"ALL\", true, false]", ps64, ph[0], ph[1]);
      r = call("descriptorprocesspsbt", pj, &ec, &em); d = r && S(r, "psbt") ? decode(S(r, "psbt")) : NULL; i0 = in0(d);
      char wsh_hex[160]; hexs(wsh_hex, ws, o);
      ck("witness_script filled", i0 && SH(i0, "witness_script") && !strcmp(SH(i0, "witness_script"), wsh_hex)); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
      rj_val* dv = i0 ? rj_obj_get(i0, "bip32_derivs") : NULL; u8 h[20]; char fp[9]; hash160(h, pub[0], 33); hexs(fp, h, 4);
      ck("bip32_derivs for both keys with hash160 fingerprints", dv && dv->nitems == 2 && S(dv->items[0], "master_fingerprint") && (!strcmp(S(dv->items[0], "master_fingerprint"), fp) || !strcmp(S(dv->items[1], "master_fingerprint"), fp)));
      rj_val* o0 = out0(d); ck("the change-like output gets witness_script + bip32_derivs too", o0 && SH(o0, "witness_script") && rj_obj_get(o0, "bip32_derivs") && rj_obj_get(o0, "bip32_derivs")->nitems == 2);
      if (d) rj_free(d); if (r) rj_free(r);
      printf("== 6. utxoupdatepsbt with descriptors adds the same ==\n");
      snprintf(pj, sizeof pj, "[\"%s\", [\"wsh(multi(2,%s,%s))\"]]", ps64, ph[0], ph[1]);
      r = call("utxoupdatepsbt", pj, &ec, &em); d = r && r->str ? decode(r->str) : NULL; i0 = in0(d);
      ck("utxoupdatepsbt(descriptors): witness_script + bip32_derivs", i0 && SH(i0, "witness_script") && rj_obj_get(i0, "bip32_derivs")); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
      if (d) rj_free(d); if (r) rj_free(r); }

    printf("== 4. an xpub with an origin: fingerprint + full path incl. the index ==\n");
    { const char* xp = "[d34db33f/84h/0h/0h]xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/*";
      static descr_spk_t sp[4];
      static descr_t dd; char err[256]; char dtext[400]; snprintf(dtext, sizeof dtext, "wpkh(%s)", xp);
      ck("parse", descr_parse(dtext, &dd, err, sizeof err)); int n = descr_expand(&dd, 7, sp, 4); ck("expand at 7", n == 1);
      static u8 utx3[400]; long ul3 = mk_utx(utx3, sp[0].spk, sp[0].len); mk_psbt(ps64, utx3, ul3, sp[0].spk, sp[0].len);
      snprintf(pj, sizeof pj, "[\"%s\", [{\"desc\":\"%s\",\"range\":10}], \"ALL\", true, false]", ps64, dtext);
      r = call("descriptorprocesspsbt", pj, &ec, &em); d = r && S(r, "psbt") ? decode(S(r, "psbt")) : NULL; i0 = in0(d);
      rj_val* dv = i0 ? rj_obj_get(i0, "bip32_derivs") : NULL;
      ck("bip32_derivs: origin fingerprint d34db33f, path m/84h/0h/0h/0/7", dv && dv->nitems == 1 && S(dv->items[0], "master_fingerprint") && !strcmp(S(dv->items[0], "master_fingerprint"), "d34db33f") && S(dv->items[0], "path") && !strcmp(S(dv->items[0], "path"), "m/84h/0h/0h/0/7"));
      if (!r) printf("    (%ld: %s)\n", ec, em ? em : ""); if (dv && dv->nitems) printf("    (path %s)\n", S(dv->items[0], "path") ? S(dv->items[0], "path") : "-");
      if (d) rj_free(d); if (r) rj_free(r); }


    printf("== 7. partial signatures: wsh(multi) signed by K0 then K1 (finalize=false carry) ==\n");
    { u8 ws[71]; int o = 0; ws[o++] = 0x52; ws[o++] = 33; memcpy(ws+o, pub[0], 33); o += 33; ws[o++] = 33; memcpy(ws+o, pub[1], 33); o += 33; ws[o++] = 0x52; ws[o++] = 0xae;
      u8 wsh[32]; sha256_full(wsh, ws, (unsigned long)o); u8 wspk[34]; wspk[0] = 0; wspk[1] = 0x20; memcpy(wspk+2, wsh, 32);
      static u8 utx2[400]; long ul2 = mk_utx(utx2, wspk, 34); mk_psbt(ps64, utx2, ul2, wspk, 34);
      snprintf(pj, sizeof pj, "[\"%s\", [\"wsh(multi(2,%s,%s))\"], \"ALL\", true, false]", ps64, wif[0], ph[1]);
      r = call("descriptorprocesspsbt", pj, &ec, &em);
      ck("K0 alone: not complete", r && S(r, "complete") && S(r, "complete")[0] == '0'); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
      char* half = r && S(r, "psbt") ? strdup(S(r, "psbt")) : NULL; if (r) rj_free(r);
      d = half ? decode(half) : NULL; i0 = in0(d);
      { rj_val* ps = i0 ? rj_obj_get(i0, "partial_signatures") : NULL;
        { long jl = 0; char* js = ps ? rj_write_alloc(ps, 0, &jl) : NULL; printf("    (partial_signatures: %s)\n", js ? js : "(none)"); free(js); }
        ck("...partial_signatures carries exactly K0's signature", ps && rj_obj_get(ps, ph[0]) && !rj_obj_get(ps, ph[1]));
        ck("...no final fields", i0 && !rj_obj_get(i0, "final_scriptwitness")); }
      if (d) rj_free(d);
      if (half){ snprintf(pj, sizeof pj, "[\"%s\", [\"wsh(multi(2,%s,%s))\"]]", half, ph[0], wif[1]);
          r = call("descriptorprocesspsbt", pj, &ec, &em);
          ck("K1 completes it using K0's carried partial", r && S(r, "complete") && S(r, "complete")[0] == '1'); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
          if (r) rj_free(r); free(half); } }

    printf("== 8. partial signatures: wsh(and_v(v:pk(K0),pk(K1))) miniscript, K1 first then K0 ==\n");
    { char dtext[300]; snprintf(dtext, sizeof dtext, "wsh(and_v(v:pk(%s),pk(%s)))", ph[0], ph[1]);
      static descr_t dd; char err[256]; static descr_spk_t sp[4];
      ck("parse", descr_parse(dtext, &dd, err, sizeof err)); ck("expand", descr_expand(&dd, 0, sp, 4) == 1);
      static u8 utx3[400]; long ul3 = mk_utx(utx3, sp[0].spk, sp[0].len); mk_psbt(ps64, utx3, ul3, sp[0].spk, sp[0].len);
      snprintf(pj, sizeof pj, "[\"%s\", [\"wsh(and_v(v:pk(%s),pk(%s)))\"], \"ALL\", true, false]", ps64, ph[0], wif[1]);
      r = call("descriptorprocesspsbt", pj, &ec, &em);
      ck("K1 alone: not complete", r && S(r, "complete") && S(r, "complete")[0] == '0'); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
      char* half = r && S(r, "psbt") ? strdup(S(r, "psbt")) : NULL; if (r) rj_free(r);
      d = half ? decode(half) : NULL; i0 = in0(d);
      { rj_val* ps = i0 ? rj_obj_get(i0, "partial_signatures") : NULL;
        ck("...partial_signatures carries K1's signature (the satisfier's own)", ps && rj_obj_get(ps, ph[1]) && !rj_obj_get(ps, ph[0]));
        ck("...witness_script from the Updater", i0 && SH(i0, "witness_script")); }
      if (d) rj_free(d);
      if (half){ snprintf(pj, sizeof pj, "[\"%s\", [\"wsh(and_v(v:pk(%s),pk(%s)))\"]]", half, wif[0], ph[1]);
          r = call("descriptorprocesspsbt", pj, &ec, &em);
          ck("K0 completes the miniscript input with K1's carried partial", r && S(r, "complete") && S(r, "complete")[0] == '1'); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
          if (r) rj_free(r); free(half); } }

    printf("== 9. tapscript miniscript leaf: tr(K2,and_v(v:pk(x0),pk(x1))), x0 first then x1 ==\n");
    { char dtext[300]; snprintf(dtext, sizeof dtext, "tr(%s,and_v(v:pk(%s),pk(%s)))", xh[2], xh[0], xh[1]);
      static descr_t dd; char err[256]; static descr_spk_t sp[4];
      ck("parse", descr_parse(dtext, &dd, err, sizeof err)); ck("expand", descr_expand(&dd, 0, sp, 4) == 1);
      static u8 utx4[400]; long ul4 = mk_utx(utx4, sp[0].spk, sp[0].len); mk_psbt(ps64, utx4, ul4, sp[0].spk, sp[0].len);
      snprintf(pj, sizeof pj, "[\"%s\", [\"tr(%s,and_v(v:pk(%s),pk(%s)))\"], \"DEFAULT\", true, false]", ps64, xh[2], wif[0], xh[1]);
      r = call("descriptorprocesspsbt", pj, &ec, &em);
      ck("x0 alone: not complete", r && S(r, "complete") && S(r, "complete")[0] == '0'); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
      char* half = r && S(r, "psbt") ? strdup(S(r, "psbt")) : NULL; if (r) rj_free(r);
      d = half ? decode(half) : NULL; i0 = in0(d);
      { rj_val* sp2 = i0 ? rj_obj_get(i0, "taproot_script_path_sigs") : NULL;
        ck("...taproot_script_path_sigs carries x0's signature with the leaf hash", sp2 && sp2->nitems == 1 && S(sp2->items[0], "pubkey") && !strcmp(S(sp2->items[0], "pubkey"), xh[0]) && S(sp2->items[0], "leaf_hash"));
        ck("...the Updater put the leaf and control block in", i0 && rj_obj_get(i0, "taproot_scripts")); }
      if (d) rj_free(d);
      if (half){ snprintf(pj, sizeof pj, "[\"%s\", [\"tr(%s,and_v(v:pk(%s),pk(%s)))\"]]", half, xh[2], xh[0], wif[1]);
          r = call("descriptorprocesspsbt", pj, &ec, &em);
          ck("x1 completes the leaf with x0's carried partial", r && S(r, "complete") && S(r, "complete")[0] == '1'); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
          if (r) rj_free(r); free(half); } }

    printf("== 10. two-leaf tree {pk(x2), multi_a(2,x0,x1)} with a NUMS internal key: x0's partial lands ==\n");
    { const char* NUMS = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
      char dtext[400]; snprintf(dtext, sizeof dtext, "tr(%s,{pk(%s),multi_a(2,%s,%s)})", NUMS, xh[2], xh[0], xh[1]);
      static descr_t dd; char err[256]; static descr_spk_t sp[4];
      ck("parse", descr_parse(dtext, &dd, err, sizeof err)); ck("expand", descr_expand(&dd, 0, sp, 4) == 1);
      static u8 utx5[400]; long ul5 = mk_utx(utx5, sp[0].spk, sp[0].len); mk_psbt(ps64, utx5, ul5, sp[0].spk, sp[0].len);
      snprintf(pj, sizeof pj, "[\"%s\", [\"tr(%s,{pk(%s),multi_a(2,%s,%s)})\"], \"DEFAULT\", true, false]", ps64, NUMS, xh[2], wif[0], xh[1]);
      r = call("descriptorprocesspsbt", pj, &ec, &em);
      ck("x0 alone: not complete", r && S(r, "complete") && S(r, "complete")[0] == '0'); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
      d = r && S(r, "psbt") ? decode(S(r, "psbt")) : NULL; i0 = in0(d);
      { rj_val* sp2 = i0 ? rj_obj_get(i0, "taproot_script_path_sigs") : NULL;
        ck("...taproot_script_path_sigs carries x0's partial for the multi_a leaf", sp2 && sp2->nitems >= 1 && S(sp2->items[0], "pubkey") && !strcmp(S(sp2->items[0], "pubkey"), xh[0]));
        if (!sp2) { long jl = 0; char* js = i0 ? rj_write_alloc(i0, 0, &jl) : NULL; printf("    (input: %.900s)\n", js ? js : "-"); free(js); } }
      if (d) rj_free(d); if (r) rj_free(r); }
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
