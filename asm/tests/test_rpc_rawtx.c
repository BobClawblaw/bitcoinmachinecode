/* test_rpc_rawtx.c -- createrawtransaction over rpc_dispatch, with Bitcoin Core
 * known-answer vectors. Every expected hex below is the exact output Bitcoin
 * Core (scratch oracle, master/v31) produced for the same params; verified
 * byte-for-byte live, frozen here for CI. All inputs use one txid:
 *   a3b1c2d4e5f6079889abcdef0123456789abcdef0123456789abcdef01234567
 * Covers all five output script types, multi-in/out, OP_RETURN data, locktime,
 * and Core's replaceable-default (true -> sequence 0xfffffffd) vs =false. */
#include <stdio.h>
#include <string.h>
#include "../rpc_commands.h"
#include "../rpc_json.h"

static int fails=0, checks=0;
static void ck(const char* what, int cond){ checks++; if(cond) printf("ok  : %s\n",what); else { printf("FAIL: %s\n",what); fails++; } }

static rj_val* call(const char* params_json, long* ec, const char** em){
    rj_val* params = rj_parse(params_json, strlen(params_json));
    rj_val* res=NULL; rpc_wallet w; memset(&w,0,sizeof w);
    rpc_dispatch("createrawtransaction", params, &w, &res, ec, em);
    rj_free(params);
    return res;
}
static void kat(const char* label, const char* params, const char* want){
    long ec; const char* em; rj_val* r = call(params, &ec, &em);
    ck(label, r && r->typ==RJ_STR && !strcmp(r->str, want));
    if (r && r->typ==RJ_STR && strcmp(r->str,want)) printf("     got:  %s\n     want: %s\n", r->str, want);
    rj_free(r);
}
#define T "a3b1c2d4e5f6079889abcdef0123456789abcdef0123456789abcdef01234567"

int main(void){
    /* --- Core known-answer vectors (replaceable defaults true -> fdffffff) --- */
    kat("P2PKH out",
        "[[{\"txid\":\"" T "\",\"vout\":0}],[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.001}]]",
        "020000000167452301efcdab8967452301efcdab8967452301efcdab899807f6e5d4c2b1a30000000000fdffffff01a0860100000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000");
    kat("P2SH out",
        "[[{\"txid\":\"" T "\",\"vout\":1}],[{\"3P14159f73E4gFr7JterCCQh9QjiTjiZrG\":0.5}]]",
        "020000000167452301efcdab8967452301efcdab8967452301efcdab899807f6e5d4c2b1a30100000000fdffffff0180f0fa020000000017a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a8700000000");
    kat("P2WPKH out",
        "[[{\"txid\":\"" T "\",\"vout\":2}],[{\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\":1.25}]]",
        "020000000167452301efcdab8967452301efcdab8967452301efcdab899807f6e5d4c2b1a30200000000fdffffff014059730700000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000");
    kat("P2TR out",
        "[[{\"txid\":\"" T "\",\"vout\":3}],[{\"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0\":2.0}]]",
        "020000000167452301efcdab8967452301efcdab8967452301efcdab899807f6e5d4c2b1a30300000000fdffffff0100c2eb0b0000000022512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000");
    kat("OP_RETURN data",
        "[[{\"txid\":\"" T "\",\"vout\":0}],[{\"data\":\"deadbeefcafe\"}]]",
        "020000000167452301efcdab8967452301efcdab8967452301efcdab899807f6e5d4c2b1a30000000000fdffffff010000000000000000086a06deadbeefcafe00000000");
    kat("2-in 2-out",
        "[[{\"txid\":\"" T "\",\"vout\":0},{\"txid\":\"" T "\",\"vout\":7}],[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.001},{\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\":2.3}]]",
        "020000000267452301efcdab8967452301efcdab8967452301efcdab899807f6e5d4c2b1a30000000000fdffffff67452301efcdab8967452301efcdab8967452301efcdab899807f6e5d4c2b1a30700000000fdffffff02a0860100000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac8085b50d00000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000");
    /* explicit replaceable=false, no locktime -> sequence 0xffffffff */
    kat("replaceable=false",
        "[[{\"txid\":\"" T "\",\"vout\":0}],[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.001}],0,false]",
        "020000000167452301efcdab8967452301efcdab8967452301efcdab899807f6e5d4c2b1a30000000000ffffffff01a0860100000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000");
    /* replaceable=false + locktime 777 -> sequence 0xfffffffe, locktime 09030000 */
    kat("rbf=false + locktime",
        "[[{\"txid\":\"" T "\",\"vout\":0}],[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.001}],777,false]",
        "020000000167452301efcdab8967452301efcdab8967452301efcdab899807f6e5d4c2b1a30000000000feffffff01a0860100000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac09030000");

    /* --- createpsbt: PSBTv0 (BIP174) wrapping the same unsigned tx.
     * This exact base64 was validated LIVE by Core's decodepsbt (psbt_version 0,
     * correct tx/inputs/outputs). Structure: 70736274ff | 0100 <txlen> <tx> | 00
     * (end global) | 00 (input map) | 00 (output map). --- */
    { long ec; const char* em; const char* pj = "[[{\"txid\":\"" T "\",\"vout\":0}],[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.001}]]";
      rj_val* params = rj_parse(pj, strlen(pj));
      rj_val* res=NULL; rpc_wallet w; memset(&w,0,sizeof w);
      rpc_dispatch("createpsbt", params, &w, &res, &ec, &em);
      ck("createpsbt -> Core-validated v0 PSBT",
         res && res->typ==RJ_STR && !strcmp(res->str,
         "cHNidP8BAFUCAAAAAWdFIwHvzauJZ0UjAe/Nq4lnRSMB782riZgH9uXUwrGjAAAAAAD9////AaCGAQAAAAAAGXapFPxyUKIR3t3HDuWic43l8HgXNRzviKwAAAAAAAAA"));
      if (res && res->typ==RJ_STR) printf("     psbt: %s\n", res->str);
      rj_free(res); rj_free(params); }

    /* --- converttopsbt: an unsigned raw tx -> the same PSBTv0 as createpsbt;
     * a signed tx errors without permitsigdata (Core-exact message). --- */
    { long ec; const char* em; rpc_wallet w; memset(&w,0,sizeof w);
      const char* raw = "[\"020000000167452301efcdab8967452301efcdab8967452301efcdab899807f6e5d4c2b1a30000000000fdffffff01a0860100000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000\"]";
      rj_val* p1=rj_parse(raw,strlen(raw)); rj_val* r1=NULL; rpc_dispatch("converttopsbt",p1,&w,&r1,&ec,&em);
      ck("converttopsbt(unsigned) == createpsbt PSBT", r1 && r1->typ==RJ_STR && !strcmp(r1->str,
         "cHNidP8BAFUCAAAAAWdFIwHvzauJZ0UjAe/Nq4lnRSMB782riZgH9uXUwrGjAAAAAAD9////AaCGAQAAAAAAGXapFPxyUKIR3t3HDuWic43l8HgXNRzviKwAAAAAAAAA"));
      rj_free(r1); rj_free(p1);
      const char* sg = "[\"02000000010100000000000000000000000000000000000000000000000000000000000000000000006b483045022100d9836bd05f96d48ac2540efe54033e1e1576c92212bfd116b63eea1669ff06ea02207f686907e6d374de78bd500cb6d4d26cd20e2aef4206c7a0b37e3745f7ad56aa0121034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aafdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000\"]";
      rj_val* p2=rj_parse(sg,strlen(sg)); rj_val* r2=NULL; long e2; const char* m2; int rc=rpc_dispatch("converttopsbt",p2,&w,&r2,&e2,&m2);
      ck("converttopsbt(signed) errors -22", rc==0 && e2==-22 && m2 && strstr(m2,"scriptSigs"));
      rj_free(r2); rj_free(p2); }

    /* --- combinepsbt: idempotent merge of identical PSBTs == the PSBT (matches
     * Core); the field-union across differing PSBTs is verified live vs Core. --- */
    { long ec; const char* em; rpc_wallet w; memset(&w,0,sizeof w);
      const char* P = "cHNidP8BAFUCAAAAAWdFIwHvzauJZ0UjAe/Nq4lnRSMB782riZgH9uXUwrGjAAAAAAD9////AaCGAQAAAAAAGXapFPxyUKIR3t3HDuWic43l8HgXNRzviKwAAAAAAAAA";
      char pj[512]; snprintf(pj,sizeof pj,"[[\"%s\",\"%s\"]]",P,P);
      rj_val* p1=rj_parse(pj,strlen(pj)); rj_val* r1=NULL; rpc_dispatch("combinepsbt",p1,&w,&r1,&ec,&em);
      ck("combinepsbt([P,P]) == P (idempotent, Core-matched)", r1 && r1->typ==RJ_STR && !strcmp(r1->str,P));
      rj_free(r1); rj_free(p1);
      /* different unsigned txs -> Core-exact error */
      const char* P2 = "cHNidP8BAFUCAAAAAWdFIwHvzauJZ0UjAe/Nq4lnRSMB782riZgH9uXUwrGjAkAAAAD9////AaCGAQAAAAAAGXapFPxyUKIR3t3HDuWic43l8HgXNRzviKwAAAAAAAAA";
      char pj2[512]; snprintf(pj2,sizeof pj2,"[[\"%s\",\"%s\"]]",P,P2);
      rj_val* p3=rj_parse(pj2,strlen(pj2)); rj_val* r3=NULL; long e3; const char* m3; int rc3=rpc_dispatch("combinepsbt",p3,&w,&r3,&e3,&m3);
      ck("combinepsbt(different txs) errors -8", rc3==0 && e3==-8 && m3 && strstr(m3,"same transaction"));
      rj_free(r3); rj_free(p3); }

    /* --- decodepsbt round-trip (our createpsbt PSBT -> our decodepsbt),
     * byte-identical to Core's decodepsbt (verified live). --- */
    { long ec; const char* em;
      const char* pj = "[\"cHNidP8BAFUCAAAAAWdFIwHvzauJZ0UjAe/Nq4lnRSMB782riZgH9uXUwrGjAAAAAAD9////AaCGAQAAAAAAGXapFPxyUKIR3t3HDuWic43l8HgXNRzviKwAAAAAAAAA\"]";
      rj_val* params = rj_parse(pj, strlen(pj)); rj_val* res=NULL; rpc_wallet w; memset(&w,0,sizeof w);
      rpc_dispatch("decodepsbt", params, &w, &res, &ec, &em);
      rj_val* txo = res?rj_obj_get(res,"tx"):NULL;
      rj_val* pv = res?rj_obj_get(res,"psbt_version"):NULL;
      rj_val* ins = res?rj_obj_get(res,"inputs"):NULL;
      rj_val* outs = res?rj_obj_get(res,"outputs"):NULL;
      ck("decodepsbt psbt_version 0", pv && !strcmp(pv->str,"0"));
      ck("decodepsbt inputs/outputs counts", ins&&ins->nitems==1 && outs&&outs->nitems==1);
      ck("decodepsbt tx decoded (has txid+version)", txo && rj_obj_get(txo,"txid") && rj_obj_get(txo,"version"));
      rj_free(res); rj_free(params); }

    /* --- decoderawtransaction now returns the FULL Core shape (was minimal
     * {locktime,vin,vout}); has txid/version/size/vsize/weight, no "hex". --- */
    { long ec; const char* em;
      const char* pj = "[\"020000000167452301efcdab8967452301efcdab8967452301efcdab899807f6e5d4c2b1a30000000000fdffffff01a0860100000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000\"]";
      rj_val* params = rj_parse(pj, strlen(pj)); rj_val* res=NULL; rpc_wallet w; memset(&w,0,sizeof w);
      rpc_dispatch("decoderawtransaction", params, &w, &res, &ec, &em);
      ck("decoderaw has txid (64 hex)", res && rj_obj_get(res,"txid") && strlen(rj_obj_get(res,"txid")->str)==64);
      ck("decoderaw version 2", res && rj_obj_get(res,"version") && !strcmp(rj_obj_get(res,"version")->str,"2"));
      ck("decoderaw has size/vsize/weight", res && rj_obj_get(res,"size") && rj_obj_get(res,"vsize") && rj_obj_get(res,"weight"));
      ck("decoderaw omits 'hex' (Core parity)", res && rj_obj_get(res,"hex")==NULL);
      rj_val* sp = res && rj_obj_get(res,"vout") && rj_obj_get(res,"vout")->nitems ? rj_obj_get(rj_obj_get(res,"vout")->items[0],"scriptPubKey") : NULL;
      ck("decoderaw scriptPubKey.asm populated", sp && rj_obj_get(sp,"asm") && strlen(rj_obj_get(sp,"asm")->str)>0);
      rj_free(res); rj_free(params); }

    /* --- error parity --- */
    long ec; const char* em;
    { rj_val* r=call("[[{\"txid\":\"" T "\",\"vout\":0}],[{\"notanaddress\":0.1}]]",&ec,&em);
      ck("invalid address -> -5", r==NULL && ec==-5); rj_free(r); }
    { rj_val* r=call("[[{\"txid\":\"" T "\",\"vout\":0}],[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.123456789}]]",&ec,&em);
      ck("amount >8 decimals -> -3", r==NULL && ec==-3); rj_free(r); }
    { rj_val* r=call("[[{\"txid\":\"deadbeef\",\"vout\":0}],[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.1}]]",&ec,&em);
      ck("short txid -> -8", r==NULL && ec==-8); rj_free(r); }

    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
