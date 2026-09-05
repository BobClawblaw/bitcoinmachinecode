/* test_rpc_rawtx.c -- createrawtransaction over rpc_dispatch, with Bitcoin Core
 * known-answer vectors. Every expected hex below is the exact output Bitcoin
 * Core (scratch oracle, master/v31) produced for the same params; verified
 * byte-for-byte live, frozen here for CI. All inputs use one txid:
 *   a3b1c2d4e5f6079889abcdef0123456789abcdef0123456789abcdef01234567
 * Covers all five output script types, multi-in/out, OP_RETURN data, locktime,
 * and Core's replaceable-default (true -> sequence 0xfffffffd) vs =false. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
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
    { long ec; const char* em; const char* pj = "[[{\"txid\":\"" T "\",\"vout\":0}],[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.001}],0,true,2,0]";   /* psbt_version 0: Core master defaults to 2 */
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
      const char* raw = "[\"020000000167452301efcdab8967452301efcdab8967452301efcdab899807f6e5d4c2b1a30000000000fdffffff01a0860100000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000\",false,null,0]";
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
      ck("combinepsbt(different txs) errors -8 (Core: \"PSBTs not compatible (different transactions)\")", rc3==0 && e3==-8 && m3 && strstr(m3,"not compatible"));
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

    /* --- joinpsbts: merge two distinct v0 PSBTs into one whose unsigned tx
     * spends all inputs and creates all outputs. Core's joinpsbts SHUFFLES the
     * inputs/outputs (privacy), so there is no byte-stable Core target; parity
     * is SEMANTIC: same version/locktime and same multiset of inputs/outputs.
     * Our output is deterministic (P1-first concat); this exact base64 was fed
     * LIVE to Core's decodepsbt and matched Core's own joinpsbts output as a set
     * (version 2, locktime 0, both outpoints, both output scripts). --- */
    { long ec; const char* em; rpc_wallet w; memset(&w,0,sizeof w);
      const char* J1 = "cHNidP8BAFICAAAAAREAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA";
      const char* J2 = "cHNidP8BAFUCAAAAASIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC7AwAAAAD+////AUANAwAAAAAAGXapFHe/8gxg5SLfqjNQw5sDCl0AToOaiKwgoQcAAAAA";
      char pj[600]; snprintf(pj,sizeof pj,"[[\"%s\",\"%s\"]]",J1,J2);
      rj_val* p=rj_parse(pj,strlen(pj)); rj_val* r=NULL; int rc=rpc_dispatch("joinpsbts",p,&w,&r,&ec,&em);
      ck("joinpsbts([J1,J2]) deterministic v0 PSBT (Core-validated as set)",
         rc==1 && r && r->typ==RJ_STR && !strcmp(r->str,
         "cHNidP8BAJ0CAAAAAhEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACqAAAAAAD9////IgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALsDAAAAAP7///8CoIYBAAAAAAAWABR1HnboGZGW1FSUHEXRs6Mj8UM71kANAwAAAAAAGXapFHe/8gxg5SLfqjNQw5sDCl0AToOaiKwAAAAAAAAAAAA="));
      if (r && r->typ==RJ_STR) printf("     join: %s\n", r->str);
      rj_free(r); rj_free(p);
      /* fewer than two PSBTs -> Core-exact -8 */
      char pj1[400]; snprintf(pj1,sizeof pj1,"[[\"%s\"]]",J1);
      rj_val* pa=rj_parse(pj1,strlen(pj1)); rj_val* ra=NULL; long e2; const char* m2; int rc2=rpc_dispatch("joinpsbts",pa,&w,&ra,&e2,&m2);
      ck("joinpsbts(one psbt) errors -8", rc2==0 && e2==-8 && m2 && strstr(m2,"two PSBTs"));
      rj_free(ra); rj_free(pa);
      /* our joined PSBT decodes (round-trips) to 2-in/2-out v0 */
      char dj[700]; snprintf(dj,sizeof dj,"[\"cHNidP8BAJ0CAAAAAhEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACqAAAAAAD9////IgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALsDAAAAAP7///8CoIYBAAAAAAAWABR1HnboGZGW1FSUHEXRs6Mj8UM71kANAwAAAAAAGXapFHe/8gxg5SLfqjNQw5sDCl0AToOaiKwAAAAAAAAAAAA=\"]");
      rj_val* pd=rj_parse(dj,strlen(dj)); rj_val* rd=NULL; rpc_dispatch("decodepsbt",pd,&w,&rd,&ec,&em);
      rj_val* txo=rd?rj_obj_get(rd,"tx"):NULL;
      rj_val* vin=txo?rj_obj_get(txo,"vin"):NULL; rj_val* vout=txo?rj_obj_get(txo,"vout"):NULL;
      ck("joined PSBT round-trips to 2-in 2-out", vin&&vin->nitems==2 && vout&&vout->nitems==2);
      rj_free(rd); rj_free(pd); }

    /* --- analyzepsbt: every expectation below is the EXACT field value the
     * scratch Core oracle produced live for the same PSBT (14-vector diff, all
     * match; representative 8 frozen here). Covers: no-UTXO; P2WPKH missing
     * pubkey vs missing sig (updater vs signer hinges on whether the pubkey is
     * derivable from bip32_deriv/partial_sig); finalized (extractor); P2SH
     * missing redeem via non_witness_utxo (missing reported) vs via
     * witness_utxo only (missing DROPPED -- Core's require_witness_sig early-
     * return in SignPSBTInput fires before out_sigdata is filled); vsize with
     * Core's 71-byte dummy sig (2-input case is the discriminator: 72 would
     * give 181, Core says 180); P2SH-P2WPKH redeem-push scriptSig accounting
     * (vsize 136); and sign-aware fee/feerate with CFeeRate's floor-toward
     * -inf division on a negative-fee PSBT (-0.00367648, not -0.00367647). */
    { rpc_wallet w; memset(&w,0,sizeof w);
      struct { const char* name; const char* psbt; const char* next;
               const char* in0_next; int has_utxo, is_final;
               const char* vsize; const char* feerate; const char* fee;
               const char* miss_kind; } av[] = {
      {"bare (no utxo)",
       "cHNidP8BAFICAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD9////AZBfAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA",
       "updater","updater",0,0,NULL,NULL,NULL,NULL},
      {"P2WPKH wutxo, pubkey unknown -> updater/missing pubkeys",
       "cHNidP8BAFICAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD9////AZBfAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAEBH6CGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAA==",
       "updater","updater",1,0,NULL,NULL,"0.00010000","pubkeys"},
      {"P2WPKH + bip32 -> signer, vsize 110",
       "cHNidP8BAFICAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD9////AZBfAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAEBH6CGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YiBgJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmAR1HnboACICAnm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYBHUedugA",
       "signer","signer",1,0,"110","0.00090909","0.00010000","signatures"},
      {"finalized -> extractor",
       "cHNidP8BAFICAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD9////AZBfAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAEBH6CGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YBCGsCRzBEAiABljnub793/La6NrQeZQMfPMYhNGZuuAQHlaxwpDEilwIgUG5CAnvALdjQTQNljhbTU0NALvDJ6Bd8uxizBWhYIBUBIQJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmAAiAgJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmAR1HnboAA==",
       "extractor","extractor",1,1,"110","0.00090909","0.00010000",NULL},
      {"P2SH missing redeem via non_witness_utxo -> missing.redeemscript",
       "cHNidP8BAFUCAAAAAf3g0y6Njj4QeRVZXgdyFdOgZlejCVYA19+4QmcLLWYRAAAAAAD9////AZBfAQAAAAAAGXapFHUedugZkZbUVJQcRdGzoyPxQzvWiKwAAAAAAAEAUwIAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP////8BoIYBAAAAAAAXqRR1HnboGZGW1FSUHEXRs6Mj8UM71ocAAAAAAAA=",
       "updater","updater",1,0,NULL,NULL,"0.00010000","redeemscript"},
      {"P2SH missing redeem via witness_utxo only -> missing DROPPED",
       "cHNidP8BAFUCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACqAAAAAAD9////AZBfAQAAAAAAGXapFHUedugZkZbUVJQcRdGzoyPxQzvWiKwAAAAAAAEBIKCGAQAAAAAAF6kUdR526BmRltRUlBxF0bOjI/FDO9aHAAA=",
       "updater","updater",1,0,NULL,NULL,"0.00010000",NULL},
      {"2x P2WPKH + bip32 -> vsize 180 (71-byte dummy sig)",
       "cHNidP8BAH4CAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADMAAAAAAD9////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM0BAAAAAP3///8B8EkCAAAAAAAZdqkUdR526BmRltRUlBxF0bOjI/FDO9aIrAAAAAAAAQEfoIYBAAAAAAAWABR1HnboGZGW1FSUHEXRs6Mj8UM71iIGAnm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYCHUedugAAAAAAAEBH6CGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YiBgJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmAh1HnboAAAAAAAA",
       "signer","signer",1,0,"180","0.00277777","0.00050000","signatures"},
      {"P2SH-P2WPKH negative fee -> -0.00050000 / feerate floor -0.00367648",
       "cHNidP8BAFUCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADMAAAAAAD9////AfBJAgAAAAAAGXapFHUedugZkZbUVJQcRdGzoyPxQzvWiKwAAAAAAAEBIKCGAQAAAAAAF6kUvP63KLWEJT1fP3C8t4Dp7yGKaPSHAQQWABR1HnboGZGW1FSUHEXRs6Mj8UM71iIGAnm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYCHUedugAAAAAAAA=",
       "signer","signer",1,0,"136","-0.00367648","-0.00050000","signatures"},
      };
      for (unsigned k=0;k<sizeof av/sizeof av[0];k++){
        char pj[4096]; snprintf(pj,sizeof pj,"[\"%s\"]",av[k].psbt);
        long ec2; const char* em2; rj_val* pr=rj_parse(pj,strlen(pj)); rj_val* r=NULL;
        int rc=rpc_dispatch("analyzepsbt",pr,&w,&r,&ec2,&em2);
        char lbl[160]; snprintf(lbl,sizeof lbl,"analyzepsbt: %s",av[k].name);
        rj_val* nx=r?rj_obj_get(r,"next"):NULL;
        rj_val* ins=r?rj_obj_get(r,"inputs"):NULL;
        rj_val* i0=ins&&ins->nitems?ins->items[0]:NULL;
        rj_val* i0n=i0?rj_obj_get(i0,"next"):NULL;
        rj_val* hu=i0?rj_obj_get(i0,"has_utxo"):NULL;
        rj_val* fi=i0?rj_obj_get(i0,"is_final"):NULL;
        rj_val* vs=r?rj_obj_get(r,"estimated_vsize"):NULL;
        rj_val* fr=r?rj_obj_get(r,"estimated_feerate"):NULL;
        rj_val* fe=r?rj_obj_get(r,"fee"):NULL;
        rj_val* ms=i0?rj_obj_get(i0,"missing"):NULL;
        int ok = rc==1 && nx && !strcmp(nx->str,av[k].next)
              && i0n && !strcmp(i0n->str,av[k].in0_next)
              && hu && hu->typ==RJ_BOOL && (hu->str[0]=='1')==(av[k].has_utxo!=0)
              && fi && fi->typ==RJ_BOOL && (fi->str[0]=='1')==(av[k].is_final!=0)
              && ((av[k].vsize==NULL)==(vs==NULL)) && (!vs || !strcmp(vs->str,av[k].vsize))
              && ((av[k].feerate==NULL)==(fr==NULL)) && (!fr || !strcmp(fr->str,av[k].feerate))
              && ((av[k].fee==NULL)==(fe==NULL)) && (!fe || !strcmp(fe->str,av[k].fee))
              && ((av[k].miss_kind==NULL)==(ms==NULL)) && (!ms || rj_obj_get(ms,av[k].miss_kind)!=NULL);
        ck(lbl, ok);
        if (!ok && r){ printf("     next=%s in0=%s vs=%s fr=%s fee=%s miss=%s\n",
            nx?nx->str:"-", i0n?i0n->str:"-", vs?vs->str:"-", fr?fr->str:"-", fe?fe->str:"-", ms?"y":"-"); }
        rj_free(r); rj_free(pr);
      }
    }

    /* --- wallet-state RPCs over the journal: ROUND-TRIP through the REAL
     * txlog_append writer (crc'd BMCTX v1 records) in an isolated tmpdir.
     * The verification bound is stated in rpc_commands.c: no oracle wallet
     * exists, so the proof is that what the wallet recorded is what the
     * RPCs report, in Core's shapes and sign conventions. --- */
    { char tdir[] = "/tmp/bmc_wsl_XXXXXX";
      if (!mkdtemp(tdir)){ ck("wsl mkdtemp", 0); }
      else {
        char oldcwd[512]; if (!getcwd(oldcwd, sizeof oldcwd)){ ck("wsl getcwd", 0); oldcwd[0] = 0; }
        if (chdir(tdir) != 0) ck("wsl chdir into the temp dir", 0);
        extern int txlog_append(const char*, unsigned long long, const unsigned char*,
                                long long, long long, const unsigned char*, unsigned long, long);
        unsigned char tx1[32], tx2[32], dest[20];
        memset(tx1, 0x11, 32); memset(tx2, 0x22, 32);
        /* dest = hash160 whose P2PKH address the entry must render */
        { const char* DH = "fc7250a211deddc70ee5a2738de5f07817351cef"; /* 1Q1pE5vP... KAT addr */
          for (int i=0;i<20;i++){ unsigned v; sscanf(DH+2*i,"%2x",&v); dest[i]=(unsigned char)v; } }
        ck("wsl journal write 1", txlog_append("bmcwallet.dat.txlog", 1787000000ULL, tx1, 50000, 1000, dest, 2, 226)==0);
        ck("wsl journal write 2", txlog_append("bmcwallet.dat.txlog", 1787000100ULL, tx2, 70000, 1500, dest, 1, 191)==0);
        /* torn record must be skipped (bad crc) */
        { FILE* f=fopen("bmcwallet.dat.txlog","a"); fprintf(f,"1787000200 sent %064d 1 1 %040d 1 1 deadbeef\n",0,0); fclose(f); }

        rpc_wallet w; memset(&w,0,sizeof w);
        long ec2; const char* em2;
        { rj_val* pr=rj_parse("[]",2); rj_val* r2=NULL;
          rpc_dispatch("listtransactions",pr,&w,&r2,&ec2,&em2);
          ck("listtransactions -> 2 entries (torn record skipped)", r2 && r2->typ==RJ_ARR && r2->nitems==2);
          rj_val* e0 = r2 && r2->nitems ? r2->items[0] : NULL;   /* oldest first */
          ck("entry category send + negative amount (Core sign convention)",
             e0 && rj_obj_get(e0,"category") && !strcmp(rj_obj_get(e0,"category")->str,"send")
             && rj_obj_get(e0,"amount") && !strcmp(rj_obj_get(e0,"amount")->str,"-0.00050000"));
          ck("entry fee negative", e0 && rj_obj_get(e0,"fee") && !strcmp(rj_obj_get(e0,"fee")->str,"-0.00001000"));
          ck("entry address rendered from dest h160",
             e0 && rj_obj_get(e0,"address") && !strcmp(rj_obj_get(e0,"address")->str,"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9"));
          ck("entry txid display order (11.. internal -> reversed)",
             e0 && rj_obj_get(e0,"txid") && !strncmp(rj_obj_get(e0,"txid")->str,"1111",4));
          ck("entry time + confirmations 0", e0 && rj_obj_get(e0,"time")
             && !strcmp(rj_obj_get(e0,"time")->str,"1787000000")
             && rj_obj_get(e0,"confirmations") && !strcmp(rj_obj_get(e0,"confirmations")->str,"0"));
          rj_free(r2); rj_free(pr); }
        { rj_val* pr=rj_parse("[\"*\", 1]",8); rj_val* r2=NULL;
          rpc_dispatch("listtransactions",pr,&w,&r2,&ec2,&em2);
          ck("listtransactions count=1 -> newest only", r2 && r2->typ==RJ_ARR && r2->nitems==1
             && !strncmp(rj_obj_get(r2->items[0],"txid")->str,"2222",4));
          rj_free(r2); rj_free(pr); }
        { char pj2[128];
          snprintf(pj2,sizeof pj2,"[\"%s\"]",
                   "2222222222222222222222222222222222222222222222222222222222222222");
          rj_val* pr=rj_parse(pj2,strlen(pj2)); rj_val* r2=NULL;
          int rc2=rpc_dispatch("gettransaction",pr,&w,&r2,&ec2,&em2);
          ck("gettransaction by display txid", rc2==1 && r2 && rj_obj_get(r2,"amount")
             && !strcmp(rj_obj_get(r2,"amount")->str,"-0.00070000"));
          ck("gettransaction details[0] is the send entry", r2 && rj_obj_get(r2,"details")
             && rj_obj_get(r2,"details")->nitems==1);
          rj_free(r2); rj_free(pr); }
        { rj_val* pr=rj_parse("[\"3333333333333333333333333333333333333333333333333333333333333333\"]",68);
          (void)pr; if(pr) rj_free(pr);
          const char* pj3 = "[\"3333333333333333333333333333333333333333333333333333333333333333\"]";
          rj_val* p3=rj_parse(pj3,strlen(pj3)); rj_val* r3=NULL;
          int rc3=rpc_dispatch("gettransaction",p3,&w,&r3,&ec2,&em2);
          ck("gettransaction unknown -> -5 Core message", rc3==0 && ec2==-5
             && em2 && !strcmp(em2,"Invalid or non-wallet transaction id"));
          rj_free(r3); rj_free(p3); }
        { rj_val* pr=rj_parse("[]",2); rj_val* r2=NULL;
          rpc_dispatch("getwalletinfo",pr,&w,&r2,&ec2,&em2);
          ck("getwalletinfo txcount 2 + format bmc + keys disabled (no seed)",
             r2 && rj_obj_get(r2,"txcount") && !strcmp(rj_obj_get(r2,"txcount")->str,"2")
             && rj_obj_get(r2,"format") && !strcmp(rj_obj_get(r2,"format")->str,"bmc")
             && rj_obj_get(r2,"private_keys_enabled") && rj_obj_get(r2,"private_keys_enabled")->str[0]=='0');
          /* ORACLE-DIFFED 2026-08-25 (the scratch Core ran disablewallet=1
           * until then): Core's modern getwalletinfo has NO balance fields --
           * they moved to getbalances -- and DOES carry blank/flags. */
          ck("getwalletinfo emits no balance fields (Core parity)",
             r2 && rj_obj_get(r2,"balance")==NULL && rj_obj_get(r2,"unconfirmed_balance")==NULL
             && rj_obj_get(r2,"immature_balance")==NULL && rj_obj_get(r2,"paytxfee")==NULL);
          ck("getwalletinfo has blank + flags (Core parity)",
             r2 && rj_obj_get(r2,"blank") && rj_obj_get(r2,"flags")
             && rj_obj_get(r2,"flags")->typ==RJ_ARR);
          rj_free(r2); rj_free(pr); }
        /* ORACLE-DIFFED 2026-08-25 against a REAL Core wallet holding a real
         * mainnet transaction (watch-only import of a recently-active
         * address). Two shape corrections the diff forced:
         *   - gettransaction.details[] entries are Core's REDUCED shape
         *     {address,category,amount,vout,fee,abandoned}, NOT a copy of a
         *     listtransactions entry: we had been putting six top-level
         *     fields (txid/time/timereceived/confirmations/walletconflicts)
         *     inside details[0], where Core never puts them;
         *   - every entry carries `vout` and `mempoolconflicts`.
         * `fee` IS correct here: Core documents it as "negative and only
         * available for the send category", and every journal record is a
         * send. */
        { char pj4[128];
          snprintf(pj4,sizeof pj4,"[\"%s\"]",
                   "1111111111111111111111111111111111111111111111111111111111111111");
          rj_val* p4=rj_parse(pj4,strlen(pj4)); rj_val* r4=NULL;
          rpc_dispatch("gettransaction",p4,&w,&r4,&ec2,&em2);
          rj_val* det = r4 ? rj_obj_get(r4,"details") : NULL;
          rj_val* d0 = det && det->nitems ? det->items[0] : NULL;
          ck("details[0] is Core's REDUCED shape (no txid/time/confirmations)",
             d0 && rj_obj_get(d0,"txid")==NULL && rj_obj_get(d0,"time")==NULL
             && rj_obj_get(d0,"confirmations")==NULL && rj_obj_get(d0,"walletconflicts")==NULL);
          ck("details[0] has address/category/amount/vout/fee/abandoned",
             d0 && rj_obj_get(d0,"address") && rj_obj_get(d0,"category")
             && rj_obj_get(d0,"amount") && rj_obj_get(d0,"vout")
             && rj_obj_get(d0,"fee") && rj_obj_get(d0,"abandoned"));
          rj_free(r4); rj_free(p4); }
        { rj_val* pr=rj_parse("[]",2); rj_val* r2=NULL;
          rpc_dispatch("listtransactions",pr,&w,&r2,&ec2,&em2);
          rj_val* e0 = r2 && r2->nitems ? r2->items[0] : NULL;
          ck("entry has vout + mempoolconflicts (Core parity)",
             e0 && rj_obj_get(e0,"vout") && rj_obj_get(e0,"mempoolconflicts")
             && rj_obj_get(e0,"mempoolconflicts")->typ==RJ_ARR);
          rj_free(r2); rj_free(pr); }
        { rj_val* pr=rj_parse("[]",2); rj_val* r2=NULL;
          rpc_dispatch("getbalances",pr,&w,&r2,&ec2,&em2);
          rj_val* mine = r2 ? rj_obj_get(r2,"mine") : NULL;
          ck("getbalances mine.{trusted,untrusted_pending,immature,nonmempool}",
             mine && rj_obj_get(mine,"trusted") && rj_obj_get(mine,"untrusted_pending")
             && rj_obj_get(mine,"immature") && rj_obj_get(mine,"nonmempool"));
          rj_free(r2); rj_free(pr); }
        if (oldcwd[0] && chdir(oldcwd) != 0) ck("wsl chdir back", 0);
      } }

    /* --- error parity --- */
    long ec; const char* em;
    { rj_val* r=call("[[{\"txid\":\"" T "\",\"vout\":0}],[{\"notanaddress\":0.1}]]",&ec,&em);
      ck("invalid address -> -5", r==NULL && ec==-5); rj_free(r); }
    { rj_val* r=call("[[{\"txid\":\"" T "\",\"vout\":0}],[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.123456789}]]",&ec,&em);
      ck("amount >8 decimals -> -3", r==NULL && ec==-3); rj_free(r); }
    { rj_val* r=call("[[{\"txid\":\"deadbeef\",\"vout\":0}],[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.1}]]",&ec,&em);
      ck("short txid -> -8", r==NULL && ec==-8); rj_free(r); }

    /* ---- RPX-5 (audit 2026-09-03): the 80-byte OP_RETURN cap was wrong HERE
     * Core's createrawtransaction builds OP_RETURN <data> for ANY size -- the
     * 80-byte limit is relay policy, applied when a transaction is accepted,
     * not by the builder. A raw tx Core will happily construct (to sign or
     * inspect offline) was refused with "Data too long for OP_RETURN".
     *
     * 100 bytes needs PUSHDATA1 (0x4c 0x64); 300 needs PUSHDATA2, which the
     * OLD code could not encode at all -- it emitted PUSHDATA1 with a
     * truncated length byte, unreachable only because of the cap it sat
     * behind. Both had to change together, so both are checked. */
    { long ec; const char* em;
      char pj[2048]; char hex200[201]; memset(hex200,'a',200); hex200[200]=0;
      snprintf(pj,sizeof pj,"[[{\"txid\":\"" T "\",\"vout\":0}],[{\"data\":\"%s\"}]]",hex200);
      rj_val* r=call(pj,&ec,&em);
      ck("RPX-5 a 100-byte OP_RETURN is BUILT, not refused", r && r->typ==RJ_STR);
      if (r && r->typ==RJ_STR)
          ck("RPX-5   and uses PUSHDATA1 (6a4c64)", strstr(r->str,"6a4c64")!=NULL);
      rj_free(r); }
    { long ec; const char* em;
      char pj[2048]; char hex600[601]; memset(hex600,'b',600); hex600[600]=0;
      snprintf(pj,sizeof pj,"[[{\"txid\":\"" T "\",\"vout\":0}],[{\"data\":\"%s\"}]]",hex600);
      rj_val* r=call(pj,&ec,&em);
      ck("RPX-5 a 300-byte OP_RETURN is BUILT", r && r->typ==RJ_STR);
      if (r && r->typ==RJ_STR)
          ck("RPX-5   and uses PUSHDATA2 (6a4d2c01)", strstr(r->str,"6a4d2c01")!=NULL);
      rj_free(r); }
    /* the control: an 80-byte payload must still encode exactly as before */
    { long ec; const char* em;
      char pj[512]; char hex160[161]; memset(hex160,'c',160); hex160[160]=0;
      snprintf(pj,sizeof pj,"[[{\"txid\":\"" T "\",\"vout\":0}],[{\"data\":\"%s\"}]]",hex160);
      rj_val* r=call(pj,&ec,&em);
      ck("RPX-5 an 80-byte OP_RETURN still uses PUSHDATA1 (6a4c50)",
         r && r->typ==RJ_STR && strstr(r->str,"6a4c50")!=NULL);
      rj_free(r); }

    /* ---- RPX-6 (audit 2026-09-03): duplicate address, and locktime range ---- */
    { long ec=0; const char* em=NULL;
      rj_val* r=call("[[{\"txid\":\"" T "\",\"vout\":0}],"
                     "[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.001},"
                     "{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.002}]]",&ec,&em);
      ck("RPX-6 a repeated address is refused, as Core does", r==NULL && ec==-8);
      rj_free(r); }
    { long ec=0; const char* em=NULL;   /* two DIFFERENT addresses stay legal */
      rj_val* r=call("[[{\"txid\":\"" T "\",\"vout\":0}],"
                     "[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.001},"
                     "{\"3P14159f73E4gFr7JterCCQh9QjiTjiZrG\":0.002}]]",&ec,&em);
      ck("RPX-6 two different addresses are still accepted", r && r->typ==RJ_STR);
      rj_free(r); }
    { long ec=0; const char* em=NULL;   /* several data outputs stay legal */
      rj_val* r=call("[[{\"txid\":\"" T "\",\"vout\":0}],"
                     "[{\"data\":\"aabb\"},{\"data\":\"ccdd\"}]]",&ec,&em);
      ck("RPX-6 repeated `data` outputs are still accepted", r && r->typ==RJ_STR);
      rj_free(r); }
    { long ec=0; const char* em=NULL;
      rj_val* r=call("[[{\"txid\":\"" T "\",\"vout\":0}],"
                     "[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.001}],4294967296]",&ec,&em);
      ck("RPX-6 a locktime past 0xffffffff is refused, not truncated", r==NULL && ec==-8);
      rj_free(r); }
    { long ec=0; const char* em=NULL;
      rj_val* r=call("[[{\"txid\":\"" T "\",\"vout\":0}],"
                     "[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.001}],-1]",&ec,&em);
      ck("RPX-6 a negative locktime is refused, not wrapped", r==NULL && ec==-8);
      rj_free(r); }
    { long ec=0; const char* em=NULL;   /* the boundary itself is legal */
      rj_val* r=call("[[{\"txid\":\"" T "\",\"vout\":0}],"
                     "[{\"1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9\":0.001}],4294967295]",&ec,&em);
      ck("RPX-6 locktime 0xffffffff (the boundary) is accepted", r && r->typ==RJ_STR);
      rj_free(r); }

    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
