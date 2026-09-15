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
#include <stdlib.h>
#include "../rpc_json.h"

/* ---- signrawtransactionwithwallet / simulaterawtransaction ----------------
 * Both source keys from the WALLET rather than the params, so they need a
 * seeded rpc_wallet. Everything expected below is derived here from the same
 * primitives the implementation uses, so these are round trips, not frozen
 * strings that could drift with the derivation path. */
extern int  bip32_derive_path(unsigned char k[32], unsigned char c[32],
                              const unsigned char* seed, long seedlen,
                              const unsigned* indexes, long n);
extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char priv_be[32]);
extern void hash160(unsigned char out[20], const void* in, long long len);

static unsigned char WSEED[64];

/* hash160 of the wallet key at m/84'/0'/0'/<i>/<chain>. */
static int wallet_h160(unsigned i, int chain, unsigned char h[20]){
    unsigned idx[5] = {0x80000000u|84u, 0x80000000u, 0x80000000u, i, (unsigned)chain};
    unsigned char k[32], c[32], pub[33];
    if (bip32_derive_path(k, c, WSEED, 64, idx, 5) != 1) return 0;
    scalar_to_pubkey(pub, k);
    hash160(h, pub, 33);
    return 1;
}
static void hexify(char* out, const unsigned char* b, int n){
    static const char* H="0123456789abcdef";
    for (int i=0;i<n;i++){ out[i*2]=H[b[i]>>4]; out[i*2+1]=H[b[i]&15]; }
    out[n*2]=0;
}

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

    /* a P2TR output that is not the tweak of a given key -> error entry, complete:false */
    { char p[1200]; snprintf(p,sizeof p,"[\"%s\",[\"%s\"],[%s]]", UNSIGNED, WIF,
        PREV("5120fc7250a211deddc70ee5a2738de5f07817351ceffc7250a211deddc70ee5a2738d",""));
      long ec; const char* em; rj_val* r=call("signrawtransactionwithkey",p,&ec,&em);
      rj_val* comp=r?rj_obj_get(r,"complete"):NULL;
      ck("P2TR whose key we do not hold -> complete:false with error", comp && comp->str[0]=='0' && rj_obj_get(r,"errors"));
      rj_free(r); }


    /* ==== CHECKMULTISIG / P2TR key-path signing (2026-09-01) ==============
     * Every signed hex below was VALIDATED by Bitcoin Core v31.99's own
     * script engine: validation/signer_core_diff.sh feeds each one to a
     * scratch regtest bitcoind's signrawtransactionwithkey with an empty
     * key set, whose "complete" is Core's VerifyScript verdict -- true for
     * every complete case, false for the partials. Keys: privs 0x11*(k+1),
     * k = 0..2, compressed. Nonces are deterministic (ECDSA: sha256d(z||d);
     * BIP340 aux: sha256d(z||d')), so the outputs are frozen here. */
    {
        extern void base58check_encode(char* out, const unsigned char* payload, long long paylen);
        unsigned char priv[3][32]; char wif[3][64];
        for (int k=0;k<3;k++){ for (int i=0;i<32;i++) priv[k][i]=(unsigned char)(0x11*(k+1));
            unsigned char pay[34]; pay[0]=0x80; memcpy(pay+1,priv[k],32); pay[33]=1; base58check_encode(wif[k],pay,34); }
        char keys1[100], keys2[200], keys3[300];
        snprintf(keys1,sizeof keys1,"[\"%s\"]",wif[0]); snprintf(keys2,sizeof keys2,"[\"%s\",\"%s\"]",wif[0],wif[1]);
        snprintf(keys3,sizeof keys3,"[\"%s\",\"%s\",\"%s\"]",wif[0],wif[1],wif[2]);
        #define MSKAT(label, keys, prevtx, shtarg, want_complete, want_hex, want_err) do{ \
            char p[4000]; snprintf(p,sizeof p,"[\"%s\",%s,[%s]%s]", UNSIGNED, keys, prevtx, shtarg); \
            long ec; const char* em; rj_val* r=call("signrawtransactionwithkey",p,&ec,&em); \
            rj_val* hex=r?rj_obj_get(r,"hex"):NULL; rj_val* comp=r?rj_obj_get(r,"complete"):NULL; rj_val* errs=r?rj_obj_get(r,"errors"):NULL; \
            int okc = comp && comp->str[0]==((want_complete)?'1':'0'); \
            int okh = hex && hex->typ==RJ_STR && !strcmp(hex->str,want_hex); \
            int oke = !(want_err)[0] || (errs && errs->nitems && strstr(rj_obj_get(errs->items[0],"error")->str, want_err)); \
            ck(label, okc && okh && oke); \
            if (!okh && hex && hex->typ==RJ_STR) printf("     got:  %s\n     want: %s\n", hex->str, want_hex); \
            rj_free(r); }while(0)
        MSKAT("p2wsh-2of3-2keys (Core-validated)", keys2, "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"0020090e494a0afd279cb8de52b66664aed6fde1021cf0fede59088653fbb87dfe46\",\"amount\":1.0,\"witnessScript\":\"5221034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae\"}", "", 1, "0200000000010101000000000000000000000000000000000000000000000000000000000000000000000000fdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac0400483045022100f0f9272ce50a56edbbecd4236c86371eae668824cad924e49c8c93ca84c7591f02204b6a80d405f03a2455f898fb130194db9f18c95b663c4bbf237b452647011cba0147304402207122f4489d5a7776e82ce66323598edd4c52f38e7e55b9c7630e54d4bc3e074502205f2f2c17ce386a734be8c0de86a90353d4176957fa773b273f71272d060a79d901695221034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae00000000", "");
        MSKAT("p2wsh-2of3-1key-partial (Core-validated)", keys1, "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"0020090e494a0afd279cb8de52b66664aed6fde1021cf0fede59088653fbb87dfe46\",\"amount\":1.0,\"witnessScript\":\"5221034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae\"}", "", 0, "0200000000010101000000000000000000000000000000000000000000000000000000000000000000000000fdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac0300483045022100f0f9272ce50a56edbbecd4236c86371eae668824cad924e49c8c93ca84c7591f02204b6a80d405f03a2455f898fb130194db9f18c95b663c4bbf237b452647011cba01695221034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae00000000", "Missing signatures: have 1 of 2");
        MSKAT("p2wsh-2of3-3keys (Core-validated)", keys3, "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"0020090e494a0afd279cb8de52b66664aed6fde1021cf0fede59088653fbb87dfe46\",\"amount\":1.0,\"witnessScript\":\"5221034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae\"}", "", 1, "0200000000010101000000000000000000000000000000000000000000000000000000000000000000000000fdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac0400483045022100f0f9272ce50a56edbbecd4236c86371eae668824cad924e49c8c93ca84c7591f02204b6a80d405f03a2455f898fb130194db9f18c95b663c4bbf237b452647011cba0147304402207122f4489d5a7776e82ce66323598edd4c52f38e7e55b9c7630e54d4bc3e074502205f2f2c17ce386a734be8c0de86a90353d4176957fa773b273f71272d060a79d901695221034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae00000000", "");
        MSKAT("p2sh-p2wsh-2of3 (Core-validated)", keys2, "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"a9149874cbf3ba7eec9fd18eb1e9c4c9eded95c791c787\",\"amount\":1.0,\"redeemScript\":\"0020090e494a0afd279cb8de52b66664aed6fde1021cf0fede59088653fbb87dfe46\",\"witnessScript\":\"5221034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae\"}", "", 1, "0200000000010101000000000000000000000000000000000000000000000000000000000000000000000023220020090e494a0afd279cb8de52b66664aed6fde1021cf0fede59088653fbb87dfe46fdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac0400483045022100f0f9272ce50a56edbbecd4236c86371eae668824cad924e49c8c93ca84c7591f02204b6a80d405f03a2455f898fb130194db9f18c95b663c4bbf237b452647011cba0147304402207122f4489d5a7776e82ce66323598edd4c52f38e7e55b9c7630e54d4bc3e074502205f2f2c17ce386a734be8c0de86a90353d4176957fa773b273f71272d060a79d901695221034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae00000000", "");
        MSKAT("p2sh-legacy-2of2 (Core-validated)", keys2, "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"a91463859964ea29ad5a0916500860e2c4adec0a6b2787\",\"amount\":1.0,\"redeemScript\":\"5221034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2752ae\"}", "", 1, "0200000001010000000000000000000000000000000000000000000000000000000000000000000000d900483045022100e448028852ef65d415b2e95822786e6c369b478e647cd60c024e174804a65461022023d8bc793dd45cb0aa91477e476ba129f278a9b901976400ef7cbaf094205f4c0146304302202965c54a964d677213aa151818047c53b038c55da2eb12c6c4a32885f08c86b2021f29b7b021ad0abb214f280e1d561e761b36ce9b32f37f3355a6f7fad0a4430001475221034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2752aefdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000", "");
        MSKAT("p2sh-legacy-2of2-1key-partial (Core-validated)", keys1, "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"a91463859964ea29ad5a0916500860e2c4adec0a6b2787\",\"amount\":1.0,\"redeemScript\":\"5221034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2752ae\"}", "", 0, "02000000010100000000000000000000000000000000000000000000000000000000000000000000009200483045022100e448028852ef65d415b2e95822786e6c369b478e647cd60c024e174804a65461022023d8bc793dd45cb0aa91477e476ba129f278a9b901976400ef7cbaf094205f4c01475221034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2752aefdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000", "Missing signatures: have 1 of 2");
        MSKAT("p2wsh-pk-checksig (Core-validated)", keys1, "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"00208f30ec1925eaa1916f4d67a9742d938c247d220c796bef6550111eaa90327245\",\"amount\":1.0,\"witnessScript\":\"21034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaac\"}", "", 1, "0200000000010101000000000000000000000000000000000000000000000000000000000000000000000000fdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac02483045022100c75e8eb4fbb7dc67641982498ce552cd946a09b3d244bfce445b20ea78062ebe02201943bbfed99f26a77ec0d00f2eec60bb72b5d0d3e4746c473e1d3fefb22a4e20012321034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaac00000000", "");
        MSKAT("p2tr-keypath-default (Core-validated)", keys1, "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"51202a64b1ee3375f3bb4b367b8cb8384a47f73cf231717f827c6c6fbbf5aecf0c36\",\"amount\":1.0}", "", 1, "0200000000010101000000000000000000000000000000000000000000000000000000000000000000000000fdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac01405d30c2d9f19fbf6cbd7e975c07663303f1deb5cc93a4640d372eef28a2e685c3ee6824b8f7f831c13b8c5d92c30c8afadabe200bc1d95576cb7cd08ead5e2d5a00000000", "");
        MSKAT("p2tr-keypath-all (Core-validated)", keys1, "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"51202a64b1ee3375f3bb4b367b8cb8384a47f73cf231717f827c6c6fbbf5aecf0c36\",\"amount\":1.0}", ",\"ALL\"", 1, "0200000000010101000000000000000000000000000000000000000000000000000000000000000000000000fdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac01413dead70442be0b23e01f25da8a2798f48b808815de77bfe658acc8a245ca5ebd08e366b06b5f1765cdf1c1a02d0dbfea6bbe36733179ee47ad5d7bd3071c89b40100000000", "");
        MSKAT("p2tr-keypath-single-acp (Core-validated)", keys1, "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"51202a64b1ee3375f3bb4b367b8cb8384a47f73cf231717f827c6c6fbbf5aecf0c36\",\"amount\":1.0}", ",\"SINGLE|ANYONECANPAY\"", 1, "0200000000010101000000000000000000000000000000000000000000000000000000000000000000000000fdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac0141bb38dbc956074d0d12b4d2283f29b708d10fa473d703eea814b16cd4750a97c8fbd7ea53320e92074b3bcc04cec0eb0e360e41503368438c25de45150654dfbc8300000000", "");
        MSKAT("p2tr-keypath-wrongkey (Core-validated)", "[\"L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1\"]", "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"51202a64b1ee3375f3bb4b367b8cb8384a47f73cf231717f827c6c6fbbf5aecf0c36\",\"amount\":1.0}", "", 0, "020000000101000000000000000000000000000000000000000000000000000000000000000000000000fdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000", "Keys not provided for this input (a P2TR key path needs the internal key of tr(KEY) with no script tree)");
        #undef MSKAT
    }

    /* ==== signrawtransactionwithwallet ==================================
     * Same delegate as signrawtransactionwithkey, keys taken from the wallet.
     * Note the ARGUMENT SHIFT: Core's wallet form is
     * (hexstring, prevtxs, sighashtype) -- no key array. */
    for (int i=0;i<64;i++) WSEED[i]=(unsigned char)(0x11*(i+1));
    { rpc_wallet ww; memset(&ww,0,sizeof ww); ww.seed = WSEED;

      unsigned char h[20]; char hh[41];
      ck("derived the wallet's receive key hash160", wallet_h160(0,0,h)==1);
      hexify(hh,h,20);

      /* the wallet's other output types (2026-09-01): once active, the wallet
       * signs for its legacy (44'), p2sh-segwit (49') and bech32m (86')
       * keys too -- P2PKH, P2SH-P2WPKH (redeemScript from the key) and the
       * P2TR key path (BIP341 tweak of the 86' key). */
      { extern void rpc_wops_set_active_types_for_test(int mask);
        extern void rpc_wops_type_path(int t, unsigned i, int chain, unsigned idx[5]);
        extern int  rpc_wops_type_spk(int t, const unsigned char pub[33], unsigned char spk[34], unsigned long* spklen, unsigned char h20[20]);
        rpc_wops_set_active_types_for_test(0xf);
        const char* names[3] = { "legacy", "p2sh-segwit", "bech32m" };
        for (int t = 1; t <= 3; t++){
            unsigned idx[5]; rpc_wops_type_path(t, 0, 0, idx);
            unsigned char k[32], c[32], pub[33], spk[34], h20[20]; unsigned long sl;
            ck("derived the wallet's key for the type", bip32_derive_path(k, c, WSEED, 64, idx, 5) == 1);
            scalar_to_pubkey(pub, k);
            ck("...and its scriptPubKey", rpc_wops_type_spk(t, pub, spk, &sl, h20));
            char spkh[80]; hexify(spkh, spk, (int)sl);
            char extra[80] = ""; if (t == 2){ unsigned char kh[20]; hash160(kh, pub, 33); char khh[41]; hexify(khh, kh, 20); snprintf(extra, sizeof extra, ",\"redeemScript\":\"0014%s\"", khh); }
            char pv[400], pj[1400];
            snprintf(pv, sizeof pv, "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"%s\",\"amount\":1.0%s}", spkh, extra);
            snprintf(pj, sizeof pj, "[\"%s\",[%s]]", UNSIGNED, pv);
            rj_val* p = rj_parse(pj, strlen(pj)); rj_val* r = NULL; long ec; const char* em;
            int rc = rpc_dispatch("signrawtransactionwithwallet", p, &ww, &r, &ec, &em);
            rj_val* comp = r ? rj_obj_get(r, "complete") : NULL;
            char label[120]; snprintf(label, sizeof label, "the wallet signs its %s coin to completion", names[t-1]);
            ck(label, rc == 1 && comp && comp->str[0] == '1');
            if (!(rc == 1 && comp && comp->str[0] == '1') && r && rj_obj_get(r, "errors")) printf("     (%s)\n", rj_obj_get(rj_obj_get(r, "errors")->items[0], "error")->str);
            rj_free(r); rj_free(p);
        }
        rpc_wops_set_active_types_for_test(1); }

      /* a P2WPKH prevout the wallet owns -> signs to completion */
      { char pv[400], pj[1400];
        snprintf(pv,sizeof pv,
          "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\","
          "\"vout\":0,\"scriptPubKey\":\"0014%s\",\"amount\":1.0}", hh);
        snprintf(pj,sizeof pj,"[\"%s\",[%s]]", UNSIGNED, pv);
        rj_val* p=rj_parse(pj,strlen(pj)); rj_val* r=NULL; long ec; const char* em;
        int rc=rpc_dispatch("signrawtransactionwithwallet",p,&ww,&r,&ec,&em);
        rj_val* comp=r?rj_obj_get(r,"complete"):NULL;
        rj_val* hex =r?rj_obj_get(r,"hex"):NULL;
        ck("signrawtransactionwithwallet dispatched", rc==1 && r);
        ck("a prevout the WALLET owns -> complete:true",
           comp && comp->str && comp->str[0]=='1');
        ck("...and the hex actually changed (a signature was added)",
           hex && hex->str && strcmp(hex->str, UNSIGNED) != 0);
        rj_free(r); rj_free(p); }

      /* the change branch is inside the key window too */
      { unsigned char hc[20]; char hch[41];
        if (wallet_h160(0,1,hc)){
          hexify(hch,hc,20);
          char pv[400], pj[1400];
          snprintf(pv,sizeof pv,
            "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\","
            "\"vout\":0,\"scriptPubKey\":\"0014%s\",\"amount\":1.0}", hch);
          snprintf(pj,sizeof pj,"[\"%s\",[%s]]", UNSIGNED, pv);
          rj_val* p=rj_parse(pj,strlen(pj)); rj_val* r=NULL; long ec; const char* em;
          rpc_dispatch("signrawtransactionwithwallet",p,&ww,&r,&ec,&em);
          rj_val* comp=r?rj_obj_get(r,"complete"):NULL;
          ck("the CHANGE branch is in the key window too",
             comp && comp->str && comp->str[0]=='1');
          rj_free(r); rj_free(p); } }

      /* a prevout the wallet does NOT own -> complete:false with an error
       * entry, never a silently-unsigned tx reported as done */
      { char pj[1400];
        snprintf(pj,sizeof pj,"[\"%s\",[%s]]", UNSIGNED,
                 PREV("0014fc7250a211deddc70ee5a2738de5f07817351cef",""));
        rj_val* p=rj_parse(pj,strlen(pj)); rj_val* r=NULL; long ec; const char* em;
        rpc_dispatch("signrawtransactionwithwallet",p,&ww,&r,&ec,&em);
        rj_val* comp=r?rj_obj_get(r,"complete"):NULL;
        rj_val* errs=r?rj_obj_get(r,"errors"):NULL;
        ck("a prevout the wallet does NOT own -> complete:false",
           comp && comp->str && comp->str[0]=='0');
        ck("...and the unsignable input is named in errors[]",
           errs && errs->typ==RJ_ARR && errs->nitems==1);
        rj_free(r); rj_free(p); }

      /* no wallet loaded -> -4, not a false success */
      { char pj[900]; snprintf(pj,sizeof pj,"[\"%s\"]", UNSIGNED);
        rj_val* p=rj_parse(pj,strlen(pj)); rj_val* r=NULL; long ec=0; const char* em=NULL;
        rpc_wallet empty; memset(&empty,0,sizeof empty);
        int rc=rpc_dispatch("signrawtransactionwithwallet",p,&empty,&r,&ec,&em);
        ck("no wallet loaded -> -4", rc==0 && ec==-4);
        rj_free(r); rj_free(p); }

      /* ==== simulaterawtransaction =================================== */
      { /* a tx paying 1.0 BTC to our own P2WPKH: +100000000 sat */
        unsigned char spk[22]; spk[0]=0x00; spk[1]=0x14; memcpy(spk+2,h,20);
        char spkh[45]; hexify(spkh,spk,22);
        char txh[600];
        /* version | vin=1 | outpoint (UNSIGNED's) | empty scriptSig | seq |
         * vout=1 | 1.0 BTC | 22-byte P2WPKH spk | locktime */
        snprintf(txh,sizeof txh,
          "02000000" "01"
          "0100000000000000000000000000000000000000000000000000000000000000"
          "00000000" "00" "fdffffff"
          "01" "00e1f50500000000" "16" "%s" "00000000", spkh);
        char pj[800]; snprintf(pj,sizeof pj,"[[\"%s\"]]", txh);
        rj_val* p=rj_parse(pj,strlen(pj)); rj_val* r=NULL; long ec; const char* em;
        int rc=rpc_dispatch("simulaterawtransaction",p,&ww,&r,&ec,&em);
        rj_val* bc=r?rj_obj_get(r,"balance_change"):NULL;
        ck("simulaterawtransaction dispatched", rc==1 && r);
        ck("an output paying OUR script counts as +1.00000000",
           bc && bc->str && !strcmp(bc->str,"1.00000000"));
        rj_free(r); rj_free(p); }

      { /* the same tx paying somebody else: no change to our balance */
        char txh[600];
        snprintf(txh,sizeof txh, "%s",
          "02000000" "01"
          "0100000000000000000000000000000000000000000000000000000000000000"
          "00000000" "00" "fdffffff"
          "01" "00e1f50500000000" "16"
          "0014fc7250a211deddc70ee5a2738de5f07817351cef" "00000000");
        char pj[800]; snprintf(pj,sizeof pj,"[[\"%s\"]]", txh);
        rj_val* p=rj_parse(pj,strlen(pj)); rj_val* r=NULL; long ec; const char* em;
        rpc_dispatch("simulaterawtransaction",p,&ww,&r,&ec,&em);
        rj_val* bc=r?rj_obj_get(r,"balance_change"):NULL;
        ck("an output paying SOMEBODY ELSE leaves the balance unchanged",
           bc && bc->str && !strcmp(bc->str,"0.00000000"));
        rj_free(r); rj_free(p); }

      { /* spending one of OUR utxos: the value leaves */
        static unsigned char utxid[1][32];
        static unsigned long uidx[1] = {0};
        static unsigned long long uval[1] = {150000000ULL};
        /* DISPLAY order, which is what rpc_wallet.utxo_txid holds: the wire
         * outpoint is 01 00 00 ... so the display txid is ... 00 00 01. */
        memset(utxid[0],0,32); utxid[0][31]=0x01;
        rpc_wallet sw; memset(&sw,0,sizeof sw);
        sw.seed = WSEED; sw.utxo_txid = utxid; sw.utxo_idx = uidx;
        sw.utxo_val = uval; sw.utxo_n = 1;
        char pj[800]; snprintf(pj,sizeof pj,"[[\"%s\"]]", UNSIGNED);
        rj_val* p=rj_parse(pj,strlen(pj)); rj_val* r=NULL; long ec; const char* em;
        rpc_dispatch("simulaterawtransaction",p,&sw,&r,&ec,&em);
        rj_val* bc=r?rj_obj_get(r,"balance_change"):NULL;
        /* UNSIGNED pays 0.999 to a script that is not ours, so the whole
         * 1.5 BTC input leaves and nothing comes back */
        ck("spending one of OUR utxos subtracts its full value",
           bc && bc->str && !strcmp(bc->str,"-1.50000000"));
        rj_free(r); rj_free(p); }

      { /* garbage in -> -22, never a fabricated balance */
        const char* pj = "[[\"zzzz\"]]";
        rj_val* p=rj_parse(pj,strlen(pj)); rj_val* r=NULL; long ec=0; const char* em=NULL;
        int rc=rpc_dispatch("simulaterawtransaction",p,&ww,&r,&ec,&em);
        ck("undecodable tx -> -22, not a fabricated balance", rc==0 && ec==-22);
        rj_free(r); rj_free(p); } }

    { /* THE SEGWIT MARKER. signrawtransactionwithkey read the input count at
       * offset 4 unconditionally. A segwit transaction carries 0x00 0x01 there,
       * so n_in parsed as ZERO: the signing loop never ran, `complete` came
       * back TRUE and `errors` was empty -- the node answered "fully signed"
       * for a transaction it had not looked at. Core answers complete:false
       * with one error per input.
       *
       * It was masked by an n_in == 0 guard that rejected such a transaction as
       * "TX decode failed" -- wrong, but safe -- until that guard was relaxed
       * (correctly) for empty PSBT templates on 2026-09-15, turning a wrong
       * error into a wrong success. Found the same day by the RPC differential.
       *
       * A minimal signed segwit tx: version, marker+flag, 1 input, 1 output,
       * a 2-item witness, locktime. Its prevout is unknown here, so the answer
       * must be complete:false with exactly one error. */
      const char* SEGWIT_TX =
        "02000000000101"                                     /* ver, marker, flag, n_in=1 */
        "0000000000000000000000000000000000000000000000000000000000000001" "00000000"
        "00" "ffffffff"                                      /* empty scriptSig, sequence */
        "01" "a086010000000000" "160014" "0655b93e82502a2183e4f1ca3a1414b5223bad13"
        "0201aa01bb"                                         /* witness: 2 items */
        "00000000";                                          /* locktime */
      char pj[1024]; snprintf(pj, sizeof pj, "[\"%s\",[]]", SEGWIT_TX);
      rpc_wallet w2; memset(&w2, 0, sizeof w2);      /* no wallet needed: keys come from the argument */
      rj_val* p2=rj_parse(pj,strlen(pj)); rj_val* r=NULL; long ec=0; const char* em=NULL;
      int rc=rpc_dispatch("signrawtransactionwithkey",p2,&w2,&r,&ec,&em);
      ck("a signed SEGWIT tx is decoded, not silently skipped", rc==1 && r);
      rj_val* comp = r ? rj_obj_get(r,"complete") : NULL;
      ck("...and an unresolvable input means complete:FALSE, not true",
         comp && comp->str && !strcmp(comp->str,"0"));
      rj_val* errs = r ? rj_obj_get(r,"errors") : NULL;
      ck("...with one errors entry, as Core reports",
         errs && errs->typ==RJ_ARR && errs->nitems==1);
      /* THE WITNESS MUST SURVIVE. This function skipped each scriptSig without
       * storing it and never read the witness section, so an input it did not
       * re-sign came out BARE: a 444-character signed transaction returned as
       * 226, its witness gone, where Core returns it unchanged. In a
       * multi-party flow that destroys the previous signer's work.
       * Found 2026-09-15 by the RPC shape differential. */
      rj_val* hx = r ? rj_obj_get(r,"hex") : NULL;
      ck("...and the transaction comes back UNCHANGED, witness intact",
         hx && hx->str && !strcmp(hx->str, SEGWIT_TX));
      rj_free(r); rj_free(p2); }


    /* ---- the `errors` entries carry Core's witness and scriptSig ----------
     * Core's TxInErrorToJSON emits txid, vout, witness, scriptSig, sequence,
     * error (rpc/rawtransaction_util.cpp). This node emitted only txid, vout,
     * sequence, error, so a caller could not see which input data was already
     * present on a failed input -- the whole point of the array in a
     * multi-party signing flow. The fields were unimplementable until the
     * witness-preservation fix above began parsing that data (2026-09-15).
     *
     * Both fixtures are real mainnet transactions and the expected arrays are
     * Bitcoin Core v31.1's own output for them, byte for byte, rendered
     * compact so KEY ORDER is pinned as well as the values. Every input errors
     * because its coin is long spent -- exactly the case where Core reports
     * the data the transaction arrived with. */
    /* mainnet 259f72646124bf05d42293ecdc5cdacd43341d33f55329ee95499bad0330900b
     * one legacy input (scriptSig, empty witness) + one taproot (witness, empty scriptSig) */
    { const char* hex =
        "020000000001027001cb94068f4a0dd7c2847921d96d216f65cfd90cf059553926dba323c820a4000000006a"
        "47304402205295f7ec757af5aa00b10c0dca9b0ee19fb657c174934b9e106c5764d2c8a33002201e188f4fd2"
        "4a9dab80180a4418cd72cbe7ab61cb23fea69ac545f16178220d3e012102ae8a901ef9d3336264a753291f69"
        "1d47ed258e9539495b7a78f3447fb744edbeffffffff8addf97956ac2ea39b6185035e1f553d9deb2cafe584"
        "a1b350e4785008699e560100000000ffffffff0222020000000000001976a914adfb8786f19039b78a78a999"
        "e04d68348d0571be88ac0e80980000000000225120bc8ae4ec38922b39f35e4970a3cf1196984f740ea583ec"
        "3418a9b119040c0d8c00014008087516840c65964301dedbe48668990cab2cc6424f7e8fa8e7f1d271c081d8"
        "aca01de586815a40f88fe0b0329006e43279e2d1f08a1a31ea50d14af28a00b400000000";
      const char* want =
        "[{\"txid\":\"a420c823a3db26395559f00cd9cf656f216dd9217984c2d70d4a8f0694cb0170\",\"vout\""
        ":0,\"witness\":[],\"scriptSig\":\"47304402205295f7ec757af5aa00b10c0dca9b0ee19fb657c17493"
        "4b9e106c5764d2c8a33002201e188f4fd24a9dab80180a4418cd72cbe7ab61cb23fea69ac545f16178220d3e"
        "012102ae8a901ef9d3336264a753291f691d47ed258e9539495b7a78f3447fb744edbe\",\"sequence\":42"
        "94967295,\"error\":\"Input not found or already spent\"},{\"txid\":\"569e69085078e450b3a"
        "184e5af2ceb9d3d551f5e0385619ba32eac5679f9dd8a\",\"vout\":1,\"witness\":[\"08087516840c65"
        "964301dedbe48668990cab2cc6424f7e8fa8e7f1d271c081d8aca01de586815a40f88fe0b0329006e43279e2"
        "d1f08a1a31ea50d14af28a00b4\"],\"scriptSig\":\"\",\"sequence\":4294967295,\"error\":\"Inp"
        "ut not found or already spent\"}]";
      char pb[16384]; snprintf(pb,sizeof pb,"[\"%s\",[]]",hex);
      long ec=0; const char* em=NULL;
      rj_val* r=call("signrawtransactionwithkey",pb,&ec,&em);
      rj_val* ea = r ? rj_obj_get(r,"errors") : NULL;
      char* got = ea ? rj_write_alloc(ea,0,NULL) : NULL;
      ck("errors[] is Core byte for byte -- witness, scriptSig, key order (one legacy input (scriptSig, empty witness) + one taproot (witness, empty scriptSig))",
         got && !strcmp(got,want));
      if (got && strcmp(got,want)) printf("      core: %s\n      ours: %s\n", want, got);
      free(got); rj_free(r); }
    /* mainnet 8af4b62182df50cd2e2b0578d7bb50b76ebe1affbe32501c37c6cc536ba792fd
     * five inputs, one of them P2SH-P2WPKH: scriptSig AND witness on the SAME input */
    { const char* hex =
        "02000000000105639f16cead97340691813ff439db64c7fcf5c82298e5d69c5a24b21de57dc9190100000000"
        "fdffffff52935189c2ee147f968d5835b400c15519756e7692be97d31a1b4aa9757b9d532300000017160014"
        "e94a42fb0e6f130b63f0e84cbc37cd63a5f570a0fdffffffa7ba5dc410490f286b7c018ffd2d7d0ff1c7ec76"
        "92c769ebd234fbbfecfee30d0000000000fdffffffc97689c9ac367618ec8f422462fa1e777736226d586c9c"
        "2d9f17ff787a5b67000200000000fdffffffd7f9abf88fb8dd2d1f12bc648e13c0216c74785d3d6f580e9b2e"
        "9c18139324504200000000fdffffff02e904140000000000160014d80fd04807dc2155f47d1b7ce224610ad8"
        "47094aca88fb0200000000160014a6c1c328d18548e1b13287a4fc91d6a77779b19302473044022011cc5adf"
        "835405b39a3b2d2f442b0563560a1d464cee02622017be9a09793d3f02206d9e7ce1e09a1b317849f4451fa7"
        "17ffcdff1186384ed130057e623fed34d0ca01210367b45a14714638ab73adb9712c742dfe9b5be26ff84e86"
        "f75a05474105e926060247304402202ea4d5196a164f255b97a2abfc3026b11a805c16c286eeeb1706331e03"
        "adc529022031c3007cb59b79952e4afbae2b1a5056471d6b5145a3265538bc261dbd0f14d001210206265212"
        "30b668ad0ea3630e2e91bceb412647184371cda4f907d9962687da160247304402205633aa1f8d0cde9224ff"
        "b8f8442c4e545c2bcfa8bab6a53e13751e3c6050939102202cd5622b4450f74b887f724343725257cd5de6dc"
        "ed41308313bbd5354b02b738012103ed966da33acdb5245427d92ddc46811d51d906fe105ec90e0eced3328f"
        "f279570247304402200978f4d7d14bf5b71749bd1d60c422554549de1e6dfe2b265798d877c2345750022046"
        "82aca036d973d58e85f3f4c6e1462992d324052abffaaea58f824a5817adb901210285e5a5052d1468ed0f11"
        "a2a99652d08fc9bba3b19e7d6fd6a60da83d0bf215c80247304402201b11dd67142600909f644bcd698d2f83"
        "1e79c2f2cfb06622243eeedf44c42e9c02205e95571be191b7e65d3eaab3f0e0b181fa84379e8ed97499535d"
        "d3076f6aed2b012103c04ac46c971816e19c7cb9cbeab92bee07e1433f4e99e66571b4d0fc0c2ffd19000000"
        "00";
      const char* want =
        "[{\"txid\":\"19c97de51db2245a9cd6e59822c8f5fcc764db39f43f8191063497adce169f63\",\"vout\""
        ":1,\"witness\":[\"3044022011cc5adf835405b39a3b2d2f442b0563560a1d464cee02622017be9a09793d"
        "3f02206d9e7ce1e09a1b317849f4451fa717ffcdff1186384ed130057e623fed34d0ca01\",\"0367b45a147"
        "14638ab73adb9712c742dfe9b5be26ff84e86f75a05474105e92606\"],\"scriptSig\":\"\",\"sequence"
        "\":4294967293,\"error\":\"Input not found or already spent\"},{\"txid\":\"539d7b75a94a1b"
        "1ad397be92766e751955c100b435588d967f14eec289519352\",\"vout\":35,\"witness\":[\"30440220"
        "2ea4d5196a164f255b97a2abfc3026b11a805c16c286eeeb1706331e03adc529022031c3007cb59b79952e4a"
        "fbae2b1a5056471d6b5145a3265538bc261dbd0f14d001\",\"020626521230b668ad0ea3630e2e91bceb412"
        "647184371cda4f907d9962687da16\"],\"scriptSig\":\"160014e94a42fb0e6f130b63f0e84cbc37cd63a"
        "5f570a0\",\"sequence\":4294967293,\"error\":\"Input not found or already spent\"},{\"txi"
        "d\":\"0de3feecbffb34d2eb69c79276ecc7f10f7d2dfd8f017c6b280f4910c45dbaa7\",\"vout\":0,\"wi"
        "tness\":[\"304402205633aa1f8d0cde9224ffb8f8442c4e545c2bcfa8bab6a53e13751e3c6050939102202"
        "cd5622b4450f74b887f724343725257cd5de6dced41308313bbd5354b02b73801\",\"03ed966da33acdb524"
        "5427d92ddc46811d51d906fe105ec90e0eced3328ff27957\"],\"scriptSig\":\"\",\"sequence\":4294"
        "967293,\"error\":\"Input not found or already spent\"},{\"txid\":\"00675b7a78ff179f2d9c6"
        "c586d223677771efa6224428fec187636acc98976c9\",\"vout\":2,\"witness\":[\"304402200978f4d7"
        "d14bf5b71749bd1d60c422554549de1e6dfe2b265798d877c234575002204682aca036d973d58e85f3f4c6e1"
        "462992d324052abffaaea58f824a5817adb901\",\"0285e5a5052d1468ed0f11a2a99652d08fc9bba3b19e7"
        "d6fd6a60da83d0bf215c8\"],\"scriptSig\":\"\",\"sequence\":4294967293,\"error\":\"Input no"
        "t found or already spent\"},{\"txid\":\"50249313189c2e9b0e586f3d5d78746c21c0138e64bc121f"
        "2dddb88ff8abf9d7\",\"vout\":66,\"witness\":[\"304402201b11dd67142600909f644bcd698d2f831e"
        "79c2f2cfb06622243eeedf44c42e9c02205e95571be191b7e65d3eaab3f0e0b181fa84379e8ed97499535dd3"
        "076f6aed2b01\",\"03c04ac46c971816e19c7cb9cbeab92bee07e1433f4e99e66571b4d0fc0c2ffd19\"],"
        "\"scriptSig\":\"\",\"sequence\":4294967293,\"error\":\"Input not found or already spent"
        "\"}]";
      char pb[16384]; snprintf(pb,sizeof pb,"[\"%s\",[]]",hex);
      long ec=0; const char* em=NULL;
      rj_val* r=call("signrawtransactionwithkey",pb,&ec,&em);
      rj_val* ea = r ? rj_obj_get(r,"errors") : NULL;
      char* got = ea ? rj_write_alloc(ea,0,NULL) : NULL;
      ck("errors[] is Core byte for byte -- witness, scriptSig, key order (five inputs, one of them P2SH-P2WPKH: scriptSig AND witness on the SAME input)",
         got && !strcmp(got,want));
      if (got && strcmp(got,want)) printf("      core: %s\n      ours: %s\n", want, got);
      free(got); rj_free(r); }

    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
