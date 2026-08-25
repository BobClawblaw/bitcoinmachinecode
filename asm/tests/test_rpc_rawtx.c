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
