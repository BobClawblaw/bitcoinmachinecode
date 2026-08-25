/* test_rpc_msg.c -- signmessagewithprivkey / verifymessage over rpc_dispatch,
 * with a Bitcoin Core known-answer vector.
 *
 * Cross-verified live against the scratch Core oracle (both are non-wallet RPCs
 * Core serves): our signature verifies under Core and Core's verifies under
 * ours, bidirectionally. That live check can't run in CI (needs a live node),
 * so the interop is frozen here as a known-answer: CORE_SIG below is the actual
 * base64 signature Bitcoin Core's signmessagewithprivkey produced for
 * (WIF, MSG); verifymessage must accept it. Plus a round-trip (our sign -> our
 * verify) and tamper/negative controls.
 *
 * Key: priv = 0x11*32  ->  WIF KwntMbt...  ->  P2PKH 1Q1pE5... (a canonical key).
 */
#include <stdio.h>
#include <string.h>
#include "../rpc_commands.h"
#include "../rpc_json.h"

static const char* WIF  = "KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp";
static const char* ADDR = "1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9";
static const char* MSG  = "BitcoinMachineCode parity check 2026";
/* the exact signature Bitcoin Core (oracle) emitted for (WIF, MSG): */
static const char* CORE_SIG = "H2lLId0zuWcM/t0QOyIA3qxPfjeAKdx4Lt7xQbyP2sfxRxXtE8BjUDdr1Gtt43lN1uuxQNKunz1CTWtPaxe/DM0=";

static int fails = 0, checks = 0;
static void ck(const char* what, int cond){ checks++; if (cond) printf("ok  : %s\n", what); else { printf("FAIL: %s\n", what); fails++; } }

/* call rpc_dispatch with a JSON params string */
static rj_val* call(const char* method, const char* params_json, long* ec, const char** em){
    rj_val* params = rj_parse(params_json, strlen(params_json));
    rj_val* res = NULL; rpc_wallet w; memset(&w, 0, sizeof w);
    rpc_dispatch(method, params, &w, &res, ec, em);
    rj_free(params);
    return res;
}
static int is_true(const rj_val* v){ return v && v->typ == RJ_BOOL && v->str && v->str[0] == '1'; }
static int is_false(const rj_val* v){ return v && v->typ == RJ_BOOL && v->str && v->str[0] == '0'; }

int main(void){
    char p[512]; long ec; const char* em;

    /* 1. Core's signature must verify under our verifymessage (interop KAT) */
    snprintf(p, sizeof p, "[\"%s\",\"%s\",\"%s\"]", ADDR, CORE_SIG, MSG);
    { rj_val* r = call("verifymessage", p, &ec, &em);
      ck("verifymessage accepts Core's signature (interop)", is_true(r)); rj_free(r); }

    /* 2. our sign -> our verify round-trip */
    snprintf(p, sizeof p, "[\"%s\",\"%s\"]", WIF, MSG);
    { rj_val* sig = call("signmessagewithprivkey", p, &ec, &em);
      ck("signmessagewithprivkey returns a base64 string", sig && sig->typ == RJ_STR && strlen(sig->str) > 80);
      if (sig && sig->typ == RJ_STR){
          char p2[512]; snprintf(p2, sizeof p2, "[\"%s\",\"%s\",\"%s\"]", ADDR, sig->str, MSG);
          rj_val* r = call("verifymessage", p2, &ec, &em);
          ck("our signature verifies under our verifymessage", is_true(r)); rj_free(r);
          /* tamper: same sig, different message -> false */
          char p3[512]; snprintf(p3, sizeof p3, "[\"%s\",\"%s\",\"%s\"]", ADDR, sig->str, "tampered message");
          rj_val* r2 = call("verifymessage", p3, &ec, &em);
          ck("verifymessage rejects a mismatched message", is_false(r2)); rj_free(r2);
      }
      rj_free(sig); }

    /* 3. wrong address -> false (valid sig, different signer) */
    snprintf(p, sizeof p, "[\"%s\",\"%s\",\"%s\"]", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", CORE_SIG, MSG);
    { rj_val* r = call("verifymessage", p, &ec, &em);
      ck("verifymessage rejects a different address", is_false(r)); rj_free(r); }

    /* 4. malformed base64 signature -> error -5 */
    snprintf(p, sizeof p, "[\"%s\",\"%s\",\"%s\"]", ADDR, "not-base64!!!", MSG);
    { long e2; const char* m2; rj_val* r = call("verifymessage", p, &e2, &m2);
      ck("malformed signature -> error -5", r == NULL && e2 == -5); rj_free(r); }

    /* 5. invalid WIF -> error -5 */
    { long e2; const char* m2; rj_val* r = call("signmessagewithprivkey", "[\"notawif\",\"hi\"]", &e2, &m2);
      ck("invalid WIF -> error -5", r == NULL && e2 == -5); rj_free(r); }

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
