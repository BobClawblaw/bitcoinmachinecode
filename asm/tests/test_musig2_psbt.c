/* tests/test_musig2_psbt.c -- a complete 2-of-2 MuSig2 key-path signing
 * session through the RPC surface (descriptorprocesspsbt / combinepsbt /
 * decodepsbt / finalizepsbt via rpc_dispatch), with no Core in the loop:
 *   round 1 each participant publishes a pubnonce (PSBT_IN_MUSIG2_PUB_NONCE),
 *   round 2 each produces a partial signature once both nonces are present,
 *   round 3 whoever holds both partial signatures aggregates into the
 *   BIP340 key-path signature, the witness and the transaction.
 * The aggregated signature is verified by the consensus schnorr_verify over
 * the BIP341 sighash computed independently here; secret-nonce hygiene
 * (erased on use, lost with the process) is pinned. The Core-judged version
 * of this flow is validation/musig_core_diff.py. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../rpc_commands.h"
#include "../rpc_json.h"
#include "../musig2.h"
typedef unsigned char u8;
extern void sha256_full(u8 out[32], const void* msg, unsigned long len);
extern void scalar_to_pubkey(u8 pub[33], const u8 priv_be[32]);
extern void base58check_encode(char* out, const u8* payload, long long paylen);
extern int  schnorr_verify(const u8* sig, const u8* pk, const u8* msg, int msglen);
extern void rpc_musig2_forget_sessions(void);
static int fails = 0, checks = 0;
static void ck(const char* l, int c){ checks++; if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static void hexs(char* o, const u8* b, int n){ for (int i=0;i<n;i++) sprintf(o+2*i,"%02x",b[i]); o[2*n]=0; }
static int hex1(char c){ return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1; }
static int unhex(u8* out, const char* h){ int n=(int)strlen(h)/2; for (int i=0;i<n;i++) out[i]=(u8)((hex1(h[2*i])<<4)|hex1(h[2*i+1])); return n; }
static void b64(char* out, const u8* in, long n){
    static const char* B="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; long o=0;
    for (long i=0;i<n;i+=3){ long r=n-i; unsigned b0=in[i], b1=r>1?in[i+1]:0, b2=r>2?in[i+2]:0;
        out[o++]=B[b0>>2]; out[o++]=B[((b0&3)<<4)|(b1>>4)]; out[o++]=r>1?B[((b1&15)<<2)|(b2>>6)]:'='; out[o++]=r>2?B[b2&63]:'='; }
    out[o]=0;
}
static long kv(u8* o, const u8* k, unsigned long kl, const u8* v, unsigned long vl){ long p=0; o[p++]=(u8)kl; memcpy(o+p,k,kl); p+=kl; o[p++]=(u8)vl; memcpy(o+p,v,vl); p+=vl; return p; }
static rj_val* call(const char* method, const char* pj){
    rj_val* p = rj_parse(pj, strlen(pj)); rj_val* r = NULL; rpc_wallet w; memset(&w, 0, sizeof w); long ec = 0; const char* em = NULL;
    int ok = rpc_dispatch(method, p, &w, &r, &ec, &em); rj_free(p);
    if (!ok){ printf("    rpc %s failed: %ld %s\n", method, ec, em ? em : ""); if (r) rj_free(r); return NULL; }
    return r;
}
static const char* S(rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o, k) : NULL; return v && v->str ? v->str : ""; }
static int B(rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o, k) : NULL; return v && v->str && v->str[0]=='1'; }
static long arrlen(rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o, k) : NULL; return v && v->typ == RJ_ARR ? (long)v->nitems : 0; }
static void tagged(u8 out[32], const char* tag, const u8* d, unsigned long n){ u8 th[32]; sha256_full(th, tag, strlen(tag)); u8 b[512]; memcpy(b, th, 32); memcpy(b+32, th, 32); memcpy(b+64, d, n); sha256_full(out, b, 64+n); }
static char* process(const char* psbt, const char* wif, int* complete, char* hexout){
    char pj[4000]; snprintf(pj, sizeof pj, "[\"%s\",[\"pk(%s)\"]]", psbt, wif);
    rj_val* r = call("descriptorprocesspsbt", pj); if (!r) return NULL;
    *complete = B(r, "complete"); if (hexout) strcpy(hexout, S(r, "hex"));
    char* out = strdup(S(r, "psbt")); rj_free(r); return out;
}
static rj_val* decode_in0(const char* psbt){ char pj[4000]; snprintf(pj, sizeof pj, "[\"%s\"]", psbt); rj_val* d = call("decodepsbt", pj); if (!d) return NULL; rj_val* ins = rj_obj_get(d, "inputs"); return ins && ins->nitems ? ins->items[0] : NULL; }
static char* combine(const char* a, const char* b){ char pj[8000]; snprintf(pj, sizeof pj, "[[\"%s\",\"%s\"]]", a, b); rj_val* r = call("combinepsbt", pj); if (!r) return NULL; char* out = strdup(r->str ? r->str : ""); rj_free(r); return out; }

int main(void){
    /* participants */
    u8 priv[2][32], pub[2][33]; char wif[2][64];
    for (int p = 0; p < 2; p++){ for (int i = 0; i < 32; i++) priv[p][i] = (u8)(0x11 * (p + 1) + i); scalar_to_pubkey(pub[p], priv[p]);
        u8 pay[34]; pay[0] = 0x80; memcpy(pay+1, priv[p], 32); pay[33] = 1; base58check_encode(wif[p], pay, 34); }
    /* the aggregate and the P2TR output key (no script tree) */
    musig2_keyagg_t ka; ck("KeyAgg of the two participants", musig2_key_agg(&ka, pub, 2));
    u8 agg33[33], aggx[32]; musig2_agg_plain(agg33, &ka); musig2_agg_xonly(aggx, &ka);
    u8 t[32]; tagged(t, "TapTweak", aggx, 32); ck("taproot tweak of the aggregate", musig2_tweak(&ka, t, 1));
    u8 qx[32]; musig2_agg_xonly(qx, &ka);
    u8 spk[34]; spk[0] = 0x51; spk[1] = 0x20; memcpy(spk+2, qx, 32);
    /* unsigned tx: 1 input, 1 P2WPKH output */
    u8 utx[200]; long u = 0;
    utx[u++]=2;utx[u++]=0;utx[u++]=0;utx[u++]=0; utx[u++]=1; for (int i = 0; i < 32; i++) utx[u++] = 0xaa; utx[u++]=0;utx[u++]=0;utx[u++]=0;utx[u++]=0; utx[u++]=0; utx[u++]=0xff;utx[u++]=0xff;utx[u++]=0xff;utx[u++]=0xff;
    utx[u++]=1; unsigned long long outv = 90000; for (int i = 0; i < 8; i++) utx[u++] = (u8)(outv >> (8*i)); utx[u++]=22; utx[u++]=0x00; utx[u++]=0x14; for (int i = 0; i < 20; i++) utx[u++] = (u8)(0x40+i);
    utx[u++]=0;utx[u++]=0;utx[u++]=0;utx[u++]=0;
    /* PSBT: witness_utxo, tap internal key = aggregate, participants */
    u8 wu[9+34]; unsigned long long inv = 100000; for (int i = 0; i < 8; i++) wu[i] = (u8)(inv >> (8*i)); wu[8] = 34; memcpy(wu+9, spk, 34);
    u8 ps[600]; long p = 0; memcpy(ps, "psbt\xff", 5); p = 5;
    u8 k00 = 0x00; p += kv(ps+p, &k00, 1, utx, (unsigned long)u); ps[p++] = 0;
    u8 k01 = 0x01, k17 = 0x17; p += kv(ps+p, &k01, 1, wu, sizeof wu); p += kv(ps+p, &k17, 1, aggx, 32);
    u8 k1a[34]; k1a[0] = 0x1a; memcpy(k1a+1, agg33, 33); u8 parts[66]; memcpy(parts, pub[0], 33); memcpy(parts+33, pub[1], 33); p += kv(ps+p, k1a, 34, parts, 66); ps[p++] = 0;
    ps[p++] = 0;
    char psbt[1200]; b64(psbt, ps, p);
    { rj_val* i0 = decode_in0(psbt);
      ck("decodepsbt: one aggregate with two participant pubkeys (Core's field names)", i0 && arrlen(i0, "musig2_participant_pubkeys") == 1
         && arrlen(rj_obj_get(i0, "musig2_participant_pubkeys")->items[0], "participant_pubkeys") == 2);
      char ah[67]; hexs(ah, agg33, 33);
      ck("decodepsbt: aggregate_pubkey is the plain 33-byte aggregate", i0 && !strcmp(S(rj_obj_get(i0, "musig2_participant_pubkeys")->items[0], "aggregate_pubkey"), ah)); }

    printf("== round 1: nonces ==\n");
    int c1, c2; char* n1 = process(psbt, wif[0], &c1, NULL); char* n2 = process(psbt, wif[1], &c2, NULL);
    ck("neither participant is complete after its nonce", n1 && n2 && !c1 && !c2);
    { rj_val* i0 = decode_in0(n1); char ph[67]; hexs(ph, pub[0], 33);
      ck("participant 1's PSBT holds exactly its pubnonce", i0 && arrlen(i0, "musig2_pubnonces") == 1 && arrlen(i0, "musig2_partial_sigs") == 0);
      ck("...keyed by participant 1 and the tweaked aggregate", i0 && arrlen(i0, "musig2_pubnonces") == 1 && !strcmp(S(rj_obj_get(i0, "musig2_pubnonces")->items[0], "participant_pubkey"), ph)
         && strlen(S(rj_obj_get(i0, "musig2_pubnonces")->items[0], "pubnonce")) == 132); }
    char* comb1 = combine(n1, n2);
    { rj_val* i0 = decode_in0(comb1); ck("combinepsbt: both pubnonces", i0 && arrlen(i0, "musig2_pubnonces") == 2); }

    printf("== round 2: partial signatures ==\n");
    char* s1 = process(comb1, wif[0], &c1, NULL); char* s2 = process(comb1, wif[1], &c2, NULL);
    ck("neither is complete after its partial signature", s1 && s2 && !c1 && !c2);
    { rj_val* i0 = decode_in0(s1); ck("participant 1's PSBT holds its partial signature (64 hex)", i0 && arrlen(i0, "musig2_partial_sigs") == 1 && strlen(S(rj_obj_get(i0, "musig2_partial_sigs")->items[0], "partial_sig")) == 64); }
    { char* again = process(comb1, wif[0], &c1, NULL); rj_val* i0 = decode_in0(again);
      ck("signing again with the same nonces yields NO second partial signature (secnonce erased on use)", i0 && arrlen(i0, "musig2_partial_sigs") == 0); free(again); }
    char* comb2 = combine(s1, s2);
    { rj_val* i0 = decode_in0(comb2); ck("combinepsbt: both partial signatures", i0 && arrlen(i0, "musig2_partial_sigs") == 2); }

    printf("== round 3: aggregation ==\n");
    static char hex[4000]; char* fin = process(comb2, wif[0], &c1, hex);
    ck("aggregation reports complete with a transaction", fin && c1 && strlen(hex) > 100);
    { rj_val* i0 = decode_in0(fin); ck("the finalized input carries only its final witness (musig fields dropped)", i0 && arrlen(i0, "musig2_partial_sigs") == 0 && arrlen(i0, "musig2_pubnonces") == 0); }
    /* the witness signature verifies for the output key over the BIP341 sighash */
    { u8 tx[2000]; int n = unhex(tx, hex);
      /* [ver4][00 01][nin=1][op36][ss0][seq4][nout=1][val8][22][spk22][wit: 01 40 sig64][lock4] */
      ck("transaction shape: segwit, one input, one output, 64-byte key-path signature", n == 4+2+1+36+1+4+1+8+1+22+2+64+4 && tx[4]==0 && tx[5]==1 && tx[80]==1 && tx[81]==64);
      const u8* sig = tx + 82;
      u8 sha_prevouts[32], sha_amounts[32], sha_spks[32], sha_seqs[32], sha_outs[32], z[32];
      sha256_full(sha_prevouts, utx + 5, 36); u8 am[8]; for (int i = 0; i < 8; i++) am[i] = (u8)(inv >> (8*i)); sha256_full(sha_amounts, am, 8);
      u8 sp[35]; sp[0] = 34; memcpy(sp+1, spk, 34); sha256_full(sha_spks, sp, 35); u8 sq[4] = {0xff,0xff,0xff,0xff}; sha256_full(sha_seqs, sq, 4);
      sha256_full(sha_outs, utx + 5+36+1+4+1, 8+1+22);
      u8 m[200]; long ml = 0; m[ml++] = 0x00; m[ml++] = 0x00; memcpy(m+ml, utx, 4); ml += 4; memcpy(m+ml, utx+u-4, 4); ml += 4;
      memcpy(m+ml, sha_prevouts, 32); ml += 32; memcpy(m+ml, sha_amounts, 32); ml += 32; memcpy(m+ml, sha_spks, 32); ml += 32; memcpy(m+ml, sha_seqs, 32); ml += 32; memcpy(m+ml, sha_outs, 32); ml += 32;
      m[ml++] = 0x00; m[ml++]=0;m[ml++]=0;m[ml++]=0;m[ml++]=0;
      tagged(z, "TapSighash", m, (unsigned long)ml);
      ck("the aggregated signature verifies (consensus schnorr_verify) for the tweaked aggregate over the BIP341 sighash", schnorr_verify(sig, qx, z, 32) == 1); }
    { char pj[4000]; snprintf(pj, sizeof pj, "[\"%s\"]", fin); rj_val* r = call("finalizepsbt", pj);
      ck("finalizepsbt agrees: complete, same transaction", r && B(r, "complete") && !strcmp(S(r, "hex"), hex)); if (r) rj_free(r); }
    { char pj[4000]; snprintf(pj, sizeof pj, "[\"%s\"]", comb2); rj_val* r = call("finalizepsbt", pj);
      ck("finalizepsbt of the un-aggregated PSBT is NOT complete", r && !B(r, "complete")); if (r) rj_free(r); }

    printf("== sessions are per process ==\n");
    { char* a = process(psbt, wif[0], &c1, NULL); char* b = process(psbt, wif[1], &c2, NULL); char* c = combine(a, b);
      rpc_musig2_forget_sessions();
      char* d = process(c, wif[0], &c1, NULL); rj_val* i0 = decode_in0(d);
      ck("after a restart (sessions forgotten) the nonce round must be redone: no partial signature", i0 && arrlen(i0, "musig2_partial_sigs") == 0);
      free(a); free(b); free(c); free(d); }
    { /* a participant whose key we do not hold: nothing is added */
      u8 pv[32]; for (int i = 0; i < 32; i++) pv[i] = (u8)(0x77 + i); u8 pay[34]; pay[0] = 0x80; memcpy(pay+1, pv, 32); pay[33] = 1; char w3[64]; base58check_encode(w3, pay, 34);
      char* x = process(psbt, w3, &c1, NULL); rj_val* i0 = decode_in0(x);
      ck("a non-participant key adds nothing", i0 && arrlen(i0, "musig2_pubnonces") == 0 && !c1); free(x); }
    free(n1); free(n2); free(comb1); free(s1); free(s2); free(comb2); free(fin);
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
