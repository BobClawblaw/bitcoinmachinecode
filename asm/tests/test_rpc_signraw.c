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

    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
