/* tests/test_rpc_psbt_taproot.c -- taproot PSBT fields (BIP371) through
 * descriptorprocesspsbt + decodepsbt (2026-09-01).
 *
 * One P2TR output: internal key = key 2, tree {A, B} with A = pk(x0) and
 * B = multi_a(2, x0, x1). The PSBT carries witness_utxo, both leaves
 * (PSBT_IN_TAP_LEAF_SCRIPT), the internal key and the merkle root.
 *   1. decodepsbt names the fields as Core does;
 *   2. a descriptor holding the internal key signs the KEY path (round 0);
 *   3. a descriptor holding only x0 signs leaf A (round 1) -- 3 witness items;
 *   4. x0 + x1 with sign-but-don't-finalize yields PSBT_IN_TAP_SCRIPT_SIG
 *      partials for leaf B... after leaf A completes first (x0 alone is
 *      enough for A), so the partial case uses a tree with only leaf B;
 *   5. x0 alone against a B-only tree: incomplete, ONE partial sig, and the
 *      same PSBT then completed by x1 through the partial-signature carry.
 * The signatures themselves are Core-verified in validation/signer_cases.c
 * (p2tr-scriptpath-*); this file pins the PSBT plumbing around them. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../rpc_commands.h"
#include "../rpc_json.h"
typedef unsigned char u8;
extern void scalar_to_pubkey(u8 pub[33], const u8 priv_be[32]);
extern void sha256_full(u8 out[32], const void* msg, unsigned long len);
extern void base58check_encode(char* out, const u8* payload, int len);
extern int  bip32_xonly_tweak_add_par(const u8* x, const u8* t, u8* out_x, int* odd);
static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }
static void hexs(char* o, const u8* b, int n){ for (int i = 0; i < n; i++) sprintf(o + 2*i, "%02x", b[i]); o[2*n] = 0; }
static const char* S(rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o, k) : NULL; return v ? v->str : NULL; }
static rj_val* call(const char* m, const char* pj, long* ec, const char** em){ rj_val* p = rj_parse(pj, strlen(pj)); rj_val* r = NULL; rpc_wallet w; memset(&w, 0, sizeof w); *ec = 0; *em = NULL; int ok = rpc_dispatch(m, p, &w, &r, ec, em); rj_free(p); if (!ok){ if (r) rj_free(r); return NULL; } return r; }
static long vi(u8* o, unsigned long v){ if (v < 0xfd){ o[0] = (u8)v; return 1; } o[0] = 0xfd; o[1] = (u8)v; o[2] = (u8)(v >> 8); return 3; }
static long kv(u8* o, const u8* k, unsigned long kl, const u8* v, unsigned long vl){ long n = 0; n += vi(o+n, kl); memcpy(o+n, k, kl); n += kl; n += vi(o+n, vl); memcpy(o+n, v, vl); n += vl; return n; }
static void b64(char* out, const u8* in, long n){ static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; long o = 0; for (long i = 0; i < n; i += 3){ unsigned v = in[i] << 16 | (i+1 < n ? in[i+1] << 8 : 0) | (i+2 < n ? in[i+2] : 0); out[o++] = T[v >> 18]; out[o++] = T[(v >> 12) & 63]; out[o++] = i+1 < n ? T[(v >> 6) & 63] : '='; out[o++] = i+2 < n ? T[v & 63] : '='; } out[o] = 0; }
static void tagged(u8 out[32], const char* tag, const u8* a, unsigned long al, const u8* b, unsigned long bl){ u8 th[32]; sha256_full(th, tag, strlen(tag)); u8* buf = malloc(64 + al + bl); memcpy(buf, th, 32); memcpy(buf+32, th, 32); memcpy(buf+64, a, al); if (bl) memcpy(buf+64+al, b, bl); sha256_full(out, buf, 64 + al + bl); free(buf); }
static void leafhash(u8 out[32], const u8* sc, unsigned long n){ u8 pre[3] = { 0xc0, (u8)n, 0 }; u8* b = malloc(2 + n); b[0] = 0xc0; b[1] = (u8)n; memcpy(b+2, sc, n); tagged(out, "TapLeaf", b, 2 + n, NULL, 0); free(b); (void)pre; }
static void branch(u8 out[32], const u8* a, const u8* b){ if (memcmp(a, b, 32) <= 0) tagged(out, "TapBranch", a, 32, b, 32); else tagged(out, "TapBranch", b, 32, a, 32); }
/* PSBT: unsigned 1-in 1-out tx + witness_utxo + the given leaves (script,len,control) + internal + root */
static const u8 UTX[] = { 2,0,0,0, 1, 3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3, 0,0,0,0, 0, 0xfd,0xff,0xff,0xff, 1, 0x60,0x5a,0xf4,0x05,0,0,0,0, 25, 0x76,0xa9,0x14, 0xfc,0x72,0x50,0xa2,0x11,0xde,0xdd,0xc7,0x0e,0xe5,0xa2,0x73,0x8d,0xe5,0xf0,0x78,0x17,0x35,0x1c,0xef, 0x88,0xac, 0,0,0,0 };
static void mk_psbt(char* out, const u8 Q[32], const u8* const* leaves, const unsigned long* llen, const u8* const* ctrls, int nleaf, const u8* internal, const u8* root){
    static u8 ps[4000]; long o = 0; ps[o++]='p'; ps[o++]='s'; ps[o++]='b'; ps[o++]='t'; ps[o++]=0xff;
    { u8 k = 0x00; o += kv(ps+o, &k, 1, UTX, sizeof UTX); ps[o++] = 0; }
    { u8 wu[64]; long w = 0; unsigned long long val = 100000000ULL; for (int i = 0; i < 8; i++) wu[w++] = (u8)(val >> (8*i)); wu[w++] = 34; wu[w++] = 0x51; wu[w++] = 0x20; memcpy(wu+w, Q, 32); w += 32;
      u8 k = 0x01; o += kv(ps+o, &k, 1, wu, (unsigned long)w); }
    for (int i = 0; i < nleaf; i++){ u8 k[66]; k[0] = 0x15; memcpy(k+1, ctrls[i], 65); u8 v[200]; memcpy(v, leaves[i], llen[i]); v[llen[i]] = 0xc0; o += kv(ps+o, k, 66, v, llen[i] + 1); }
    if (internal){ u8 k = 0x17; o += kv(ps+o, &k, 1, internal, 32); }
    if (root){ u8 k = 0x18; o += kv(ps+o, &k, 1, root, 32); }
    ps[o++] = 0; ps[o++] = 0;
    b64(out, ps, o);
}
int main(void){
    u8 priv[3][32], pub[3][33]; char wif[3][64], xh[3][65];
    for (int k = 0; k < 3; k++){ for (int i = 0; i < 32; i++) priv[k][i] = (u8)(0x11*(k+1)); scalar_to_pubkey(pub[k], priv[k]); hexs(xh[k], pub[k]+1, 32);
        u8 pay[34]; pay[0] = 0x80; memcpy(pay+1, priv[k], 32); pay[33] = 1; base58check_encode(wif[k], pay, 34); }
    u8 la[34]; la[0] = 0x20; memcpy(la+1, pub[0]+1, 32); la[33] = 0xac;
    u8 lb[70]; int lo = 0; lb[lo++] = 0x20; memcpy(lb+lo, pub[0]+1, 32); lo += 32; lb[lo++] = 0xac; lb[lo++] = 0x20; memcpy(lb+lo, pub[1]+1, 32); lo += 32; lb[lo++] = 0xba; lb[lo++] = 0x52; lb[lo++] = 0x9c;
    u8 ha[32], hb[32], root[32]; leafhash(ha, la, 34); leafhash(hb, lb, (unsigned long)lo); branch(root, ha, hb);
    u8 t[32]; tagged(t, "TapTweak", pub[2]+1, 32, root, 32); u8 Q[32]; int odd = 0; ck("tweak", bip32_xonly_tweak_add_par(pub[2]+1, t, Q, &odd));
    u8 ca[65], cb[65]; ca[0] = (u8)(0xc0 | odd); memcpy(ca+1, pub[2]+1, 32); memcpy(ca+33, hb, 32); cb[0] = ca[0]; memcpy(cb+1, pub[2]+1, 32); memcpy(cb+33, ha, 32);
    const u8* leaves[2] = { la, lb }; unsigned long llen[2] = { 34, (unsigned long)lo }; const u8* ctrls[2] = { ca, cb };
    static char ps64[6000], pj[7000]; long ec; const char* em; rj_val* r;
    char hah[65], hbh[65], rooth[65]; hexs(hah, ha, 32); hexs(hbh, hb, 32); hexs(rooth, root, 32);

    printf("== 1. decodepsbt ==\n");
    mk_psbt(ps64, Q, leaves, llen, ctrls, 2, pub[2]+1, root);
    snprintf(pj, sizeof pj, "[\"%s\"]", ps64); r = call("decodepsbt", pj, &ec, &em);
    ck("decodepsbt succeeds", r != NULL); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
    { rj_val* ins = r ? rj_obj_get(r, "inputs") : NULL; rj_val* in0 = ins && ins->nitems ? ins->items[0] : NULL;
      rj_val* ts = in0 ? rj_obj_get(in0, "taproot_scripts") : NULL;
      ck("taproot_scripts lists both leaves", ts && ts->nitems == 2);
      ck("...each with leaf_ver 192 and one control block", ts && ts->nitems == 2 && S(ts->items[0], "leaf_ver") && !strcmp(S(ts->items[0], "leaf_ver"), "192") && rj_obj_get(ts->items[0], "control_blocks") && rj_obj_get(ts->items[0], "control_blocks")->nitems == 1);
      ck("taproot_internal_key", in0 && S(in0, "taproot_internal_key") && !strcmp(S(in0, "taproot_internal_key"), xh[2]));
      ck("taproot_merkle_root", in0 && S(in0, "taproot_merkle_root") && !strcmp(S(in0, "taproot_merkle_root"), rooth)); }
    rj_free(r);

    printf("== 2. key path with a tree (internal key held) ==\n");
    snprintf(pj, sizeof pj, "[\"%s\", [\"tr(%s,{pk(%s),multi_a(2,%s,%s)})\"]]", ps64, wif[2], xh[0], xh[0], xh[1]);
    r = call("descriptorprocesspsbt", pj, &ec, &em);
    ck("descriptorprocesspsbt with the internal key completes", r && S(r, "complete") && S(r, "complete")[0] == '1'); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
    { const char* h = r ? S(r, "hex") : NULL; ck("...one witness item (key-path signature)", h && strlen(h) > 100 && strstr(h, "0140") ); }
    rj_free(r);

    printf("== 3. script path, leaf A (only x0 held) ==\n");
    snprintf(pj, sizeof pj, "[\"%s\", [\"tr(%s,{pk(%s),multi_a(2,%s,%s)})\"]]", ps64, xh[2], wif[0], xh[0], xh[1]);
    r = call("descriptorprocesspsbt", pj, &ec, &em);
    ck("x0 alone completes via leaf A", r && S(r, "complete") && S(r, "complete")[0] == '1'); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
    { const char* h = r ? S(r, "hex") : NULL; char lah[80]; hexs(lah, la, 34); ck("...witness carries the leaf script and control block", h && strstr(h, lah) && strstr(h, xh[2])); }
    rj_free(r);
    /* the same, sign-only: partials are TAP_SCRIPT_SIG entries naming x0 + leaf A */
    snprintf(pj, sizeof pj, "[\"%s\", [\"tr(%s,{pk(%s),multi_a(2,%s,%s)})\"], \"DEFAULT\", true, false]", ps64, xh[2], wif[0], xh[0], xh[1]);
    r = call("descriptorprocesspsbt", pj, &ec, &em);
    ck("sign-only call returns a PSBT", r && S(r, "psbt")); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
    if (r && S(r, "psbt")){ snprintf(pj, sizeof pj, "[\"%s\"]", S(r, "psbt")); rj_val* d = call("decodepsbt", pj, &ec, &em);
        rj_val* ins = d ? rj_obj_get(d, "inputs") : NULL; rj_val* in0 = ins && ins->nitems ? ins->items[0] : NULL; rj_val* sp = in0 ? rj_obj_get(in0, "taproot_script_path_sigs") : NULL;
        ck("...decodepsbt shows one taproot_script_path_sigs entry", sp && sp->nitems == 1);
        ck("...for pubkey x0 and leaf A", sp && sp->nitems == 1 && S(sp->items[0], "pubkey") && !strcmp(S(sp->items[0], "pubkey"), xh[0]) && S(sp->items[0], "leaf_hash") && !strcmp(S(sp->items[0], "leaf_hash"), hah));
        ck("...and no final fields yet", in0 && !rj_obj_get(in0, "final_scriptwitness"));
        rj_free(d); }
    rj_free(r);

    printf("== 4. B-only tree: multi_a partial then completion ==\n");
    { u8 t2[32]; tagged(t2, "TapTweak", pub[2]+1, 32, hb, 32); u8 Q2[32]; int odd2 = 0; bip32_xonly_tweak_add_par(pub[2]+1, t2, Q2, &odd2);
      u8 cb2[33]; cb2[0] = (u8)(0xc0 | odd2); memcpy(cb2+1, pub[2]+1, 32);
      static u8 ps[4000]; long o = 0; ps[o++]='p'; ps[o++]='s'; ps[o++]='b'; ps[o++]='t'; ps[o++]=0xff;
      { u8 k = 0x00; o += kv(ps+o, &k, 1, UTX, sizeof UTX); ps[o++] = 0; }
      { u8 wu[64]; long w = 0; unsigned long long val = 100000000ULL; for (int i = 0; i < 8; i++) wu[w++] = (u8)(val >> (8*i)); wu[w++] = 34; wu[w++] = 0x51; wu[w++] = 0x20; memcpy(wu+w, Q2, 32); w += 32; u8 k = 0x01; o += kv(ps+o, &k, 1, wu, (unsigned long)w); }
      { u8 k[34]; k[0] = 0x15; memcpy(k+1, cb2, 33); u8 v[80]; memcpy(v, lb, lo); v[lo] = 0xc0; o += kv(ps+o, k, 34, v, lo + 1); }
      { u8 k = 0x17; o += kv(ps+o, &k, 1, pub[2]+1, 32); } { u8 k = 0x18; o += kv(ps+o, &k, 1, hb, 32); }
      ps[o++] = 0; ps[o++] = 0; b64(ps64, ps, o);
      snprintf(pj, sizeof pj, "[\"%s\", [\"tr(%s,multi_a(2,%s,%s))\"], \"DEFAULT\", true, false]", ps64, xh[2], wif[0], xh[1]);
      r = call("descriptorprocesspsbt", pj, &ec, &em);
      ck("x0 alone: incomplete", r && S(r, "complete") && S(r, "complete")[0] == '0'); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
      char* half = NULL;
      if (r && S(r, "psbt")){ half = strdup(S(r, "psbt")); snprintf(pj, sizeof pj, "[\"%s\"]", half); rj_val* d = call("decodepsbt", pj, &ec, &em);
          rj_val* ins = d ? rj_obj_get(d, "inputs") : NULL; rj_val* in0 = ins && ins->nitems ? ins->items[0] : NULL; rj_val* sp = in0 ? rj_obj_get(in0, "taproot_script_path_sigs") : NULL;
          ck("...one partial TAP_SCRIPT_SIG for x0 / leaf B", sp && sp->nitems == 1 && S(sp->items[0], "pubkey") && !strcmp(S(sp->items[0], "pubkey"), xh[0]) && !strcmp(S(sp->items[0], "leaf_hash"), hbh));
          rj_free(d); }
      rj_free(r);
      if (half){ snprintf(pj, sizeof pj, "[\"%s\", [\"tr(%s,multi_a(2,%s,%s))\"]]", half, xh[2], xh[0], wif[1]);
          r = call("descriptorprocesspsbt", pj, &ec, &em);
          ck("x1 then completes (2 of 2) and finalizes", r && S(r, "complete") && S(r, "complete")[0] == '1'); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
          rj_free(r); free(half); } }

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
