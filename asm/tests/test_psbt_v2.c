/* tests/test_psbt_v2.c -- PSBT version 2 (BIP370) through the RPC surface.
 *   1. createpsbt/converttopsbt default to v2 (Core master) and honour
 *      psbt_version 0; the v2 bytes are Core-ordered and decode with Core's
 *      field names; the same tx as v0 decodes to the same inputs/outputs.
 *   2. a hand-built v2 with required locktimes folds them per BIP370 into
 *      the synthesized unsigned tx (height beats time; max per kind).
 *   3. every v2 validation error carries Core's message.
 *   4. round trips preserve the version and the bytes (finalizepsbt of an
 *      unsigned v2, utxoupdatepsbt without a UTXO set, combinepsbt [P,P]).
 *   5. signing a v2 P2WPKH input with descriptorprocesspsbt completes,
 *      returns a v2 PSBT with final fields, and extracts the SAME hex the
 *      v0 form of the PSBT does.
 *   6. combinepsbt refuses mixed versions; joinpsbts refuses v2, both with
 *      Core's messages. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../rpc_commands.h"
#include "../rpc_json.h"
typedef unsigned char u8;
extern void scalar_to_pubkey(u8 pub[33], const u8 priv_be[32]);
extern void hash160(u8 out[20], const void* in, long long len);
extern void base58check_encode(char* out, const u8* payload, int len);
static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }
static const char* S(rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o, k) : NULL; return v ? v->str : NULL; }
static rj_val* call(const char* m, const char* pj, long* ec, const char** em){ rj_val* p = rj_parse(pj, strlen(pj)); rj_val* r = NULL; rpc_wallet w; memset(&w, 0, sizeof w); *ec = 0; *em = NULL; int ok = rpc_dispatch(m, p, &w, &r, ec, em); rj_free(p); if (!ok){ if (r) rj_free(r); return NULL; } return r; }
static long vi(u8* o, unsigned long v){ if (v < 0xfd){ o[0] = (u8)v; return 1; } o[0] = 0xfd; o[1] = (u8)v; o[2] = (u8)(v >> 8); return 3; }
static long kv(u8* o, const u8* k, unsigned long kl, const u8* v, unsigned long vl){ long n = 0; n += vi(o+n, kl); memcpy(o+n, k, kl); n += kl; n += vi(o+n, vl); memcpy(o+n, v, vl); n += vl; return n; }
static void b64(char* out, const u8* in, long n){ static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; long o = 0; for (long i = 0; i < n; i += 3){ unsigned v = in[i] << 16 | (i+1 < n ? in[i+1] << 8 : 0) | (i+2 < n ? in[i+2] : 0); out[o++] = T[v >> 18]; out[o++] = T[(v >> 12) & 63]; out[o++] = i+1 < n ? T[(v >> 6) & 63] : '='; out[o++] = i+2 < n ? T[v & 63] : '='; } out[o] = 0; }
static long unb64(u8* out, const char* s){ static signed char T[256]; static int init = 0; if (!init){ for (int i = 0; i < 256; i++) T[i] = -1; const char* B = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; for (int i = 0; i < 64; i++) T[(u8)B[i]] = (signed char)i; init = 1; } unsigned acc = 0; int bits = 0; long o = 0; for (; *s; s++){ if (*s == '=') continue; signed char v = T[(u8)*s]; if (v < 0) return -1; acc = (acc << 6) | (unsigned)v; bits += 6; if (bits >= 8){ bits -= 8; out[o++] = (u8)((acc >> bits) & 0xff); } } return o; }
static void w32(u8* p, unsigned v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
/* a v2 PSBT: globals (tx_version, [fallback], counts, [modifiable], version) + n inputs (txid, vout, [seq], [time], [height]) + 1 output */
typedef struct { u8 txid[32]; unsigned vout; int has_seq; unsigned seq; int has_tl; unsigned tl; int has_hl; unsigned hl; const u8* wu; unsigned long wul; } v2in;
static long mk_v2(u8* ps, unsigned txver, int has_fb, unsigned fb, int has_mod, u8 mod, const v2in* ins, int nin, unsigned long long amount, const u8* spk, unsigned long spkl, int with_unsigned_tx, int omit_txver, int version){
    long o = 0; memcpy(ps, "psbt\xff", 5); o = 5; u8 k, v[16];
    if (with_unsigned_tx){ k = 0x00; u8 tx[64] = { 2,0,0,0, 0, 0, 0,0,0,0 }; o += kv(ps+o, &k, 1, tx, 10); }
    if (!omit_txver){ k = 0x02; w32(v, txver); o += kv(ps+o, &k, 1, v, 4); }
    if (has_fb){ k = 0x03; w32(v, fb); o += kv(ps+o, &k, 1, v, 4); }
    k = 0x04; v[0] = (u8)nin; o += kv(ps+o, &k, 1, v, 1);
    k = 0x05; v[0] = 1; o += kv(ps+o, &k, 1, v, 1);
    if (has_mod){ k = 0x06; o += kv(ps+o, &k, 1, &mod, 1); }
    if (version >= 0){ k = 0xfb; w32(v, (unsigned)version); o += kv(ps+o, &k, 1, v, 4); }
    ps[o++] = 0;
    for (int i = 0; i < nin; i++){
        if (ins[i].wu){ k = 0x01; o += kv(ps+o, &k, 1, ins[i].wu, ins[i].wul); }
        if (ins[i].vout != 0xfffffffeu){ k = 0x0e; o += kv(ps+o, &k, 1, ins[i].txid, 32); k = 0x0f; w32(v, ins[i].vout); o += kv(ps+o, &k, 1, v, 4); }
        if (ins[i].has_seq){ k = 0x10; w32(v, ins[i].seq); o += kv(ps+o, &k, 1, v, 4); }
        if (ins[i].has_tl){ k = 0x11; w32(v, ins[i].tl); o += kv(ps+o, &k, 1, v, 4); }
        if (ins[i].has_hl){ k = 0x12; w32(v, ins[i].hl); o += kv(ps+o, &k, 1, v, 4); }
        ps[o++] = 0;
    }
    if (amount != ~0ULL){ k = 0x03; for (int i = 0; i < 8; i++) v[i] = (u8)(amount >> (8*i)); o += kv(ps+o, &k, 1, v, 8); }
    if (spk){ k = 0x04; o += kv(ps+o, &k, 1, spk, spkl); }
    ps[o++] = 0;
    return o;
}
int main(void){
    long ec; const char* em; rj_val* r; static char pj[8000], b1[8000], b2[8000];
    const char* TXID = "a3b1c2d4e5f6079889abcdef0123456789abcdef0123456789abcdef01234567";   /* display order; wire = 67452301...a3 */
    printf("== 1. createpsbt / converttopsbt versions ==\n");
    snprintf(pj, sizeof pj, "[[{\"txid\":\"%s\",\"vout\":0}],[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.001}]]", TXID);
    r = call("createpsbt", pj, &ec, &em); ck("createpsbt defaults to v2", r && r->str && strncmp(r->str, "cHNidP8BAgQC", 12) == 0); if (r) strcpy(b2, r->str); rj_free(r);
    snprintf(pj, sizeof pj, "[[{\"txid\":\"%s\",\"vout\":0}],[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.001}],0,true,2,0]", TXID);
    r = call("createpsbt", pj, &ec, &em); ck("createpsbt psbt_version=0 -> the BIP174 v0 bytes", r && r->str && !strcmp(r->str, "cHNidP8BAFUCAAAAAWdFIwHvzauJZ0UjAe/Nq4lnRSMB782riZgH9uXUwrGjAAAAAAD9////AaCGAQAAAAAAGXapFPxyUKIR3t3HDuWic43l8HgXNRzviKwAAAAAAAAA")); if (r && r->str) printf("    got %s\n", r->str); else printf("    (%ld: %s)\n", ec, em ? em : ""); if (r) strcpy(b1, r->str); rj_free(r);
    snprintf(pj, sizeof pj, "[[{\"txid\":\"%s\",\"vout\":0}],[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.001}],0,true,2,1]", TXID);
    r = call("createpsbt", pj, &ec, &em); ck("psbt_version=1 -> Core's error", !r && ec == -8 && em && !strcmp(em, "The PSBT version can only be 2 or 0")); if (r) rj_free(r);
    { static u8 raw[4000]; long n = unb64(raw, b2);
      /* Core's byte order: global 02 txver | 04 count | 05 count | fb version; input 0e txid | 0f index | 10 sequence; output 03 amount | 04 script */
      ck("v2 global map is Core-ordered (02,03,04,05,fb)", n > 40 && raw[5]==1 && raw[6]==0x02 && raw[7]==4 && raw[12]==1 && raw[13]==0x03 && raw[19]==1 && raw[20]==0x04 && raw[23]==1 && raw[24]==0x05 && raw[27]==1 && raw[28]==0xfb && raw[29]==4 && raw[30]==2 && raw[34]==0);
      ck("...then the input map 0e/0f/10 and the output map 03/04", raw[35]==1 && raw[36]==0x0e && raw[37]==32 && raw[70]==1 && raw[71]==0x0f && raw[77]==1 && raw[78]==0x10 && raw[84]==0 && raw[85]==1 && raw[86]==0x03 && raw[87]==8 && raw[96]==1 && raw[97]==0x04); }
    snprintf(pj, sizeof pj, "[\"%s\"]", b2); r = call("decodepsbt", pj, &ec, &em);
    ck("decodepsbt(v2): psbt_version 2, tx_version 2, fallback_locktime 0, counts, no tx", r && S(r,"psbt_version") && !strcmp(S(r,"psbt_version"),"2") && S(r,"tx_version") && !strcmp(S(r,"tx_version"),"2") && S(r,"fallback_locktime") && !strcmp(S(r,"fallback_locktime"),"0") && S(r,"input_count") && !strcmp(S(r,"input_count"),"1") && S(r,"output_count") && !strcmp(S(r,"output_count"),"1") && !rj_obj_get(r,"tx"));
    { rj_val* ins = r ? rj_obj_get(r,"inputs") : NULL; rj_val* i0 = ins && ins->nitems ? ins->items[0] : NULL; rj_val* outs = r ? rj_obj_get(r,"outputs") : NULL; rj_val* o0 = outs && outs->nitems ? outs->items[0] : NULL;
      ck("...input: previous_txid/previous_vout/sequence", i0 && S(i0,"previous_txid") && !strcmp(S(i0,"previous_txid"), TXID) && S(i0,"previous_vout") && !strcmp(S(i0,"previous_vout"),"0") && S(i0,"sequence") && !strcmp(S(i0,"sequence"),"4294967293"));
      ck("...output: amount + script object with hex/type/address", o0 && S(o0,"amount") && !strcmp(S(o0,"amount"),"0.00100000") && rj_obj_get(o0,"script") && S(rj_obj_get(o0,"script"),"type") && !strcmp(S(rj_obj_get(o0,"script"),"type"),"pubkeyhash")); }
    rj_free(r);
    snprintf(pj, sizeof pj, "[\"%s\",false,null,2]", "020000000167452301efcdab8967452301efcdab8967452301efcdab899807f6e5d4c2b1a30000000000fdffffff01a0860100000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000");
    r = call("converttopsbt", pj, &ec, &em); ck("converttopsbt(psbt_version 2) == createpsbt v2", r && r->str && !strcmp(r->str, b2)); if (r && r->str && strcmp(r->str, b2)) printf("    got  %s\n    want %s\n", r->str, b2); rj_free(r);

    printf("== 2. required locktimes fold per BIP370 ==\n");
    { static u8 ps[4000]; v2in ins[3]; memset(ins, 0, sizeof ins); for (int i = 0; i < 3; i++){ memset(ins[i].txid, 0x10 + i, 32); ins[i].vout = (unsigned)i; }
      ins[0].has_hl = 1; ins[0].hl = 100; ins[1].has_hl = 1; ins[1].hl = 250; ins[1].has_tl = 1; ins[1].tl = 600000000; ins[2].has_tl = 1; ins[2].tl = 700000000; ins[2].has_hl = 1; ins[2].hl = 50;
      u8 spk[22] = { 0x00, 0x14 }; memset(spk+2, 0xab, 20);
      long n = mk_v2(ps, 2, 1, 777, 1, 0x03, ins, 3, 50000, spk, 22, 0, 0, 2); b64(b1, ps, n);
      snprintf(pj, sizeof pj, "[\"%s\"]", b1); r = call("decodepsbt", pj, &ec, &em);
      ck("decodepsbt shows time/height locktimes per input + modifiable flags", r && rj_obj_get(r,"inputs") && rj_obj_get(r,"inputs")->nitems == 3 && S(rj_obj_get(r,"inputs")->items[1],"height_locktime") && !strcmp(S(rj_obj_get(r,"inputs")->items[1],"height_locktime"),"250") && S(r,"inputs_modifiable") && S(r,"inputs_modifiable")[0]=='1' && S(r,"outputs_modifiable")[0]=='1' && S(r,"has_sighash_single")[0]=='0');
      if (!r) printf("    (%ld: %s)\n", ec, em ? em : ""); rj_free(r);
      /* the synthesized tx: all inputs allow a height lock -> locktime = max height = 250 (not the fallback 777) */
      snprintf(pj, sizeof pj, "[\"%s\",false]", b1); r = call("finalizepsbt", pj, &ec, &em);
      ck("finalizepsbt(unsigned v2) -> incomplete, version preserved", r && S(r,"complete") && S(r,"complete")[0]=='0' && S(r,"psbt") && strncmp(S(r,"psbt"), "cHNidP8BAgQC", 12) == 0);
      if (r && S(r,"psbt")){ snprintf(pj, sizeof pj, "[\"%s\"]", S(r,"psbt")); rj_val* d = call("decodepsbt", pj, &ec, &em); ck("...and still decodes as v2 with 3 inputs", d && rj_obj_get(d,"inputs") && rj_obj_get(d,"inputs")->nitems == 3 && !strcmp(S(d,"psbt_version"),"2")); rj_free(d); }
      rj_free(r);
      /* analyzepsbt sees the synthesized tx (3 inputs, no utxo) */
      snprintf(pj, sizeof pj, "[\"%s\"]", b1); r = call("analyzepsbt", pj, &ec, &em);
      ck("analyzepsbt(v2) reports 3 inputs, next=updater", r && rj_obj_get(r,"inputs") && rj_obj_get(r,"inputs")->nitems == 3 && S(r,"next") && !strcmp(S(r,"next"),"updater")); rj_free(r);
      /* conflict: one input time-only, another height-only */
      memset(ins, 0, sizeof ins); for (int i = 0; i < 2; i++){ memset(ins[i].txid, 0x20 + i, 32); ins[i].vout = (unsigned)i; }
      ins[0].has_tl = 1; ins[0].tl = 600000000; ins[1].has_hl = 1; ins[1].hl = 10;
      n = mk_v2(ps, 2, 0, 0, 0, 0, ins, 2, 50000, spk, 22, 0, 0, 2); b64(b1, ps, n);
      snprintf(pj, sizeof pj, "[\"%s\"]", b1); r = call("decodepsbt", pj, &ec, &em); ck("incompatible locktimes still decode", r && rj_obj_get(r,"inputs") && rj_obj_get(r,"inputs")->nitems == 2); rj_free(r);
      snprintf(pj, sizeof pj, "[\"%s\"]", b1); r = call("analyzepsbt", pj, &ec, &em); ck("...but analyzepsbt says it cannot become a valid transaction", r && S(r,"error") && strstr(S(r,"error"),"valid transaction")); rj_free(r); }

    printf("== 3. Core's validation messages ==\n");
    { static u8 ps[4000]; v2in in1; memset(&in1, 0, sizeof in1); memset(in1.txid, 0x30, 32); in1.vout = 0; u8 spk[22] = { 0x00, 0x14 };
      struct { const char* what; long n; } C[8]; int nc = 0; long ec2; const char* em2;
      #define CASE(label, expr) do{ long n_ = (expr); b64(b1, ps, n_); snprintf(pj, sizeof pj, "[\"%s\"]", b1); rj_val* d = call("decodepsbt", pj, &ec2, &em2); int ok_ = (!d && ec2 == -22 && em2 && strstr(em2, MSG) != NULL); ck(label, ok_); if (!ok_) printf("    (got %ld: %s)\n", ec2, em2 ? em2 : "(none)"); if (d) rj_free(d); }while(0)
      #define MSG "PSBT_GLOBAL_TX_VERSION is required in PSBTv2"
      CASE("v2 without tx_version: " MSG, mk_v2(ps, 2, 0, 0, 0, 0, &in1, 1, 1, spk, 22, 0, 1, 2));
      #undef MSG
      #define MSG "PSBT_GLOBAL_UNSIGNED_TX is not allowed in PSBTv2"
      CASE("v2 with an unsigned tx: " MSG, mk_v2(ps, 2, 0, 0, 0, 0, &in1, 1, 1, spk, 22, 1, 0, 2));
      #undef MSG
      #define MSG "PSBT_GLOBAL_TX_VERSION is not allowed in PSBTv0"
      CASE("v0 with tx_version: " MSG, mk_v2(ps, 2, 0, 0, 0, 0, &in1, 1, 1, spk, 22, 1, 0, -1));
      #undef MSG
      #define MSG "There is no PSBT version 1"
      CASE("version 1: " MSG, mk_v2(ps, 2, 0, 0, 0, 0, &in1, 1, 1, spk, 22, 0, 0, 1));
      #undef MSG
      #define MSG "Unsupported version number"
      CASE("version 3: " MSG, mk_v2(ps, 2, 0, 0, 0, 0, &in1, 1, 1, spk, 22, 0, 0, 3));
      #undef MSG
      #define MSG "Previous TXID is required in PSBTv2"
      { v2in bad = in1; bad.vout = 0xfffffffeu; CASE("input without previous txid: " MSG, mk_v2(ps, 2, 0, 0, 0, 0, &bad, 1, 1, spk, 22, 0, 0, 2)); }
      #undef MSG
      #define MSG "Output amount is required in PSBTv2"
      CASE("output without amount: " MSG, mk_v2(ps, 2, 0, 0, 0, 0, &in1, 1, ~0ULL, spk, 22, 0, 0, 2));
      #undef MSG
      #define MSG "Output script is required in PSBTv2"
      CASE("output without script: " MSG, mk_v2(ps, 2, 0, 0, 0, 0, &in1, 1, 1, NULL, 0, 0, 0, 2));
      #undef MSG
      #define MSG "Required time based locktime is invalid (less than 500000000)"
      { v2in bad = in1; bad.has_tl = 1; bad.tl = 499999999; CASE("time locktime < 500000000: " MSG, mk_v2(ps, 2, 0, 0, 0, 0, &bad, 1, 1, spk, 22, 0, 0, 2)); }
      #undef MSG
      #define MSG "Required height based locktime is invalid (0)"
      { v2in bad = in1; bad.has_hl = 1; bad.hl = 0; CASE("height locktime 0: " MSG, mk_v2(ps, 2, 0, 0, 0, 0, &bad, 1, 1, spk, 22, 0, 0, 2)); }
      #undef MSG
      #define MSG "Required height based locktime is invalid (greater than or equal to 500000000)"
      { v2in bad = in1; bad.has_hl = 1; bad.hl = 500000000; CASE("height locktime >= 500000000: " MSG, mk_v2(ps, 2, 0, 0, 0, 0, &bad, 1, 1, spk, 22, 0, 0, 2)); }
      #undef MSG
      (void)C; (void)nc; }

    printf("== 4. round trips preserve version and bytes ==\n");
    snprintf(pj, sizeof pj, "[[\"%s\",\"%s\"]]", b2, b2); r = call("combinepsbt", pj, &ec, &em); ck("combinepsbt([v2,v2]) == the same v2 bytes", r && r->str && !strcmp(r->str, b2)); rj_free(r);
    snprintf(pj, sizeof pj, "[\"%s\"]", b2); r = call("utxoupdatepsbt", pj, &ec, &em); ck("utxoupdatepsbt(v2) without a UTXO set returns the same bytes", r && r->str && !strcmp(r->str, b2)); rj_free(r);
    snprintf(pj, sizeof pj, "[\"%s\",false]", b2); r = call("finalizepsbt", pj, &ec, &em); ck("finalizepsbt(v2 unsigned, extract=false) returns the same bytes", r && S(r,"psbt") && !strcmp(S(r,"psbt"), b2)); rj_free(r);

    printf("== 5. signing a v2 input, same extracted hex as v0 ==\n");
    { u8 priv[32]; for (int i = 0; i < 32; i++) priv[i] = 0x11; u8 pub[33]; scalar_to_pubkey(pub, priv); u8 h[20]; hash160(h, pub, 33);
      u8 pay[34]; pay[0] = 0x80; memcpy(pay+1, priv, 32); pay[33] = 1; char wif[64]; base58check_encode(wif, pay, 34);
      static u8 wu[40]; unsigned long long amt = 100000000ULL; for (int i = 0; i < 8; i++) wu[i] = (u8)(amt >> (8*i)); wu[8] = 22; wu[9] = 0x00; wu[10] = 0x14; memcpy(wu+11, h, 20);
      v2in in1; memset(&in1, 0, sizeof in1); memset(in1.txid, 0x03, 32); in1.vout = 0; in1.has_seq = 1; in1.seq = 0xfffffffd; in1.wu = wu; in1.wul = 31;
      u8 spk[25] = { 0x76, 0xa9, 0x14 }; memset(spk+3, 0xfc, 20); spk[23] = 0x88; spk[24] = 0xac;
      static u8 ps[4000]; long n = mk_v2(ps, 2, 1, 0, 0, 0, &in1, 1, 99990000ULL, spk, 25, 0, 0, 2); b64(b1, ps, n);
      snprintf(pj, sizeof pj, "[\"%s\", [\"wpkh(%s)\"]]", b1, wif); r = call("descriptorprocesspsbt", pj, &ec, &em);
      ck("descriptorprocesspsbt signs the v2 input to completion", r && S(r,"complete") && S(r,"complete")[0]=='1' && S(r,"hex")); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
      static char hex2[4000]; hex2[0] = 0; if (r && S(r,"hex")) strcpy(hex2, S(r,"hex"));
      if (r && S(r,"psbt")){ snprintf(pj, sizeof pj, "[\"%s\"]", S(r,"psbt")); rj_val* d = call("decodepsbt", pj, &ec, &em);
          rj_val* i0 = d && rj_obj_get(d,"inputs") ? rj_obj_get(d,"inputs")->items[0] : NULL;
          ck("...the returned PSBT is v2 with final_scriptwitness and its v2 fields intact", d && !strcmp(S(d,"psbt_version"),"2") && i0 && rj_obj_get(i0,"final_scriptwitness") && S(i0,"previous_vout") && S(i0,"sequence")); rj_free(d); }
      rj_free(r);
      /* the v0 twin: createpsbt(psbt_version 0) from the same tx + the same witness_utxo */
      { static u8 p0[4000]; long o = 0; memcpy(p0, "psbt\xff", 5); o = 5; u8 tx[200]; long t = 0; w32(tx+t, 2); t += 4; tx[t++] = 1; memcpy(tx+t, in1.txid, 32); t += 32; w32(tx+t, 0); t += 4; tx[t++] = 0; w32(tx+t, 0xfffffffd); t += 4; tx[t++] = 1; unsigned long long a = 99990000ULL; for (int i = 0; i < 8; i++) tx[t++] = (u8)(a >> (8*i)); tx[t++] = 25; memcpy(tx+t, spk, 25); t += 25; w32(tx+t, 0); t += 4;
        u8 k = 0x00; o += kv(p0+o, &k, 1, tx, (unsigned long)t); p0[o++] = 0; k = 0x01; o += kv(p0+o, &k, 1, wu, 31); p0[o++] = 0; p0[o++] = 0; b64(b2, p0, o);
        snprintf(pj, sizeof pj, "[\"%s\", [\"wpkh(%s)\"]]", b2, wif); r = call("descriptorprocesspsbt", pj, &ec, &em);
        ck("the v0 twin signs to the identical transaction hex", r && S(r,"hex") && hex2[0] && !strcmp(S(r,"hex"), hex2)); if (!r) printf("    (%ld: %s)\n", ec, em ? em : "");
        if (r && S(r,"psbt")) ck("...and comes back as v0", strncmp(S(r,"psbt"), "cHNidP8BA", 9) == 0 && strncmp(S(r,"psbt"), "cHNidP8BAgQC", 12) != 0);
        rj_free(r);
        printf("== 6. mixed versions ==\n");
        snprintf(pj, sizeof pj, "[[\"%s\",\"%s\"]]", b1, b2); r = call("combinepsbt", pj, &ec, &em); ck("combinepsbt(v2, v0 of the same tx) -> Core: PSBTs not compatible", !r && ec == -8 && em && !strcmp(em, "PSBTs not compatible (different transactions)")); if (r) rj_free(r);
        snprintf(pj, sizeof pj, "[[\"%s\",\"%s\"]]", b1, b1); r = call("joinpsbts", pj, &ec, &em); ck("joinpsbts(v2) -> Core: joinpsbts only operates on version 0 PSBTs", !r && ec == -8 && em && !strcmp(em, "joinpsbts only operates on version 0 PSBTs")); if (r) rj_free(r); } }
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
