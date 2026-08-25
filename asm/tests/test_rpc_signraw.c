/* test_rpc_signraw.c -- signrawtransactionwithkey over rpc_dispatch.
 *
 * Each signed-tx hex below was VALIDATED LIVE by Bitcoin Core's own script
 * engine: feeding our signed tx back to the scratch oracle's
 * signrawtransactionwithkey with an empty key set returned complete:true for
 * every type (P2PKH, P2WPKH, P2SH-P2WPKH), i.e. Core's VerifyScript accepted
 * our legacy + BIP143 sighashes, ECDSA (low-S) signatures, DER encoding, and
 * segwit serialization. That live check can't run in CI, so the deterministic
 * output (nonce = sha256d(z||priv), fully reproducible) is frozen here.
 *
 * Key: priv 0x11*32 -> WIF KwntMbt... (compressed). Prevout txid = ...0001,
 * vout 0, amount 1.0 BTC; single output 0.999 to the key's own P2PKH address.
 */
#include <stdio.h>
#include <string.h>
#include "../rpc_commands.h"
#include "../rpc_json.h"

static int fails=0, checks=0;
static void ck(const char* w,int c){ checks++; if(c) printf("ok  : %s\n",w); else { printf("FAIL: %s\n",w); fails++; } }

static rj_val* call(const char* method, const char* params_json, long* ec, const char** em){
    rj_val* p=rj_parse(params_json,strlen(params_json));
    rj_val* res=NULL; rpc_wallet w; memset(&w,0,sizeof w);
    rpc_dispatch(method,p,&w,&res,ec,em); rj_free(p); return res;
}
#define WIF "KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp"
#define UNSIGNED "020000000101000000000000000000000000000000000000000000000000000000000000000000000000fdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000"
#define PREV(spk,extra) "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"" spk "\",\"amount\":1.0" extra "}"

/* sign UNSIGNED with WIF against one prevtx; assert exact hex + complete=true */
static void kat(const char* label, const char* prevtx, const char* want_hex){
    char p[1200]; snprintf(p,sizeof p,"[\"%s\",[\"%s\"],[%s]]", UNSIGNED, WIF, prevtx);
    long ec; const char* em; rj_val* r=call("signrawtransactionwithkey",p,&ec,&em);
    rj_val* hex = r?rj_obj_get(r,"hex"):NULL; rj_val* comp = r?rj_obj_get(r,"complete"):NULL;
    ck(label, hex && hex->typ==RJ_STR && !strcmp(hex->str,want_hex) && comp && comp->str[0]=='1');
    if (hex && hex->typ==RJ_STR && strcmp(hex->str,want_hex)) printf("     got:  %s\n     want: %s\n", hex->str, want_hex);
    rj_free(r);
}

int main(void){
    kat("P2PKH sign (Core-validated)", PREV("76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac",""),
        "02000000010100000000000000000000000000000000000000000000000000000000000000000000006b483045022100d9836bd05f96d48ac2540efe54033e1e1576c92212bfd116b63eea1669ff06ea02207f686907e6d374de78bd500cb6d4d26cd20e2aef4206c7a0b37e3745f7ad56aa0121034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aafdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000");
    kat("P2WPKH sign (Core-validated)", PREV("0014fc7250a211deddc70ee5a2738de5f07817351cef",""),
        "0200000000010101000000000000000000000000000000000000000000000000000000000000000000000000fdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac02483045022100e7dd7afe5b1c87f0e7b7272df3f25fb22b6b784b8b1c1db7a932d6c8a43e6cc302201617f313539c960fe924d2d21bc1f1b3abdc55495c7b423fc2f9b0c66c1dc5660121034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa00000000");
    kat("P2SH-P2WPKH sign (Core-validated)", PREV("a914ec8f3d9c2763a0997a465b968d99db47e82e69d287",",\"redeemScript\":\"0014fc7250a211deddc70ee5a2738de5f07817351cef\""),
        "0200000000010101000000000000000000000000000000000000000000000000000000000000000000000017160014fc7250a211deddc70ee5a2738de5f07817351ceffdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac02483045022100e7dd7afe5b1c87f0e7b7272df3f25fb22b6b784b8b1c1db7a932d6c8a43e6cc302201617f313539c960fe924d2d21bc1f1b3abdc55495c7b423fc2f9b0c66c1dc5660121034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa00000000");

    /* no key -> complete:false + errors[] with the input identified */
    { char p[1200]; snprintf(p,sizeof p,"[\"%s\",[],[%s]]", UNSIGNED, PREV("0014fc7250a211deddc70ee5a2738de5f07817351cef",""));
      long ec; const char* em; rj_val* r=call("signrawtransactionwithkey",p,&ec,&em);
      rj_val* comp=r?rj_obj_get(r,"complete"):NULL; rj_val* errs=r?rj_obj_get(r,"errors"):NULL;
      ck("no key -> complete:false", comp && comp->str[0]=='0');
      ck("no key -> errors[] populated", errs && errs->typ==RJ_ARR && errs->nitems==1 && rj_obj_get(errs->items[0],"error"));
      rj_free(r); }

    /* unsupported type (P2TR) -> error entry, complete:false */
    { char p[1200]; snprintf(p,sizeof p,"[\"%s\",[\"%s\"],[%s]]", UNSIGNED, WIF,
        PREV("5120fc7250a211deddc70ee5a2738de5f07817351ceffc7250a211deddc70ee5a2738d",""));
      long ec; const char* em; rj_val* r=call("signrawtransactionwithkey",p,&ec,&em);
      rj_val* comp=r?rj_obj_get(r,"complete"):NULL;
      ck("P2TR (no Schnorr signer) -> complete:false with error", comp && comp->str[0]=='0' && rj_obj_get(r,"errors"));
      rj_free(r); }

    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
