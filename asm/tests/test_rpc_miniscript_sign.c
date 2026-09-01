/* tests/test_rpc_miniscript_sign.c -- miniscript-locked inputs through the
 * raw signer and the PSBT Signer, over rpc_dispatch:
 *   1. signrawtransactionwithkey with a wsh(miniscript) witnessScript, the
 *      keys and a preimage: complete=true, the witness has the satisfier's
 *      items plus the script, and it is the NON-malleable one (or_d takes the
 *      key branch, not the timelocked one);
 *   2. the same input without the preimage: complete=false with the reason;
 *   3. descriptorprocesspsbt on a hand-built PSBT carrying witness_utxo,
 *      witness_script and a PSBT_IN_SHA256_PREIMAGES field, with a private
 *      wsh(miniscript) descriptor: complete=true, finalized hex;
 *   4. the older() branch is taken only when the input's nSequence allows it.
 * Validity of every witness produced here is judged by Bitcoin Core in
 * validation/miniscript_core_diff.sh; this test pins the plumbing. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../rpc_commands.h"
#include "../rpc_json.h"
#include "../descriptor.h"
extern void sha256_full(unsigned char out[32], const void* msg, unsigned long len);
extern void base58check_encode(char* out, const unsigned char* payload, long long paylen);
typedef unsigned char u8;
static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }
static void hexify(char* out, const u8* b, size_t n){ static const char* H = "0123456789abcdef"; for (size_t i = 0; i < n; i++){ out[i*2] = H[b[i]>>4]; out[i*2+1] = H[b[i]&15]; } out[n*2] = 0; }
static int unhex(const char* s, u8* out, size_t cap){ size_t n = strlen(s); if (n & 1 || n/2 > cap) return -1; for (size_t i = 0; i < n/2; i++){ unsigned v; if (sscanf(s + 2*i, "%2x", &v) != 1) return -1; out[i] = (u8)v; } return (int)(n/2); }
static rj_val* call(const char* method, const char* params, long* ec, const char** em){
    rj_val* p = rj_parse(params, strlen(params)); rj_val* res = NULL; rpc_wallet w; memset(&w, 0, sizeof w);
    rpc_dispatch(method, p, &w, &res, ec, em); rj_free(p); return res;
}
static void wif_of(char* out, u8 fill){ u8 pay[34]; pay[0] = 0x80; memset(pay + 1, fill, 32); pay[33] = 1; base58check_encode(out, pay, 34); }
static const char* b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void b64(char* out, const u8* d, size_t n){
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3){
        unsigned v = (unsigned)d[i] << 16 | (i + 1 < n ? (unsigned)d[i+1] << 8 : 0) | (i + 2 < n ? d[i+2] : 0);
        out[o++] = b64chars[(v >> 18) & 63]; out[o++] = b64chars[(v >> 12) & 63];
        out[o++] = i + 1 < n ? b64chars[(v >> 6) & 63] : '='; out[o++] = i + 2 < n ? b64chars[v & 63] : '=';
    }
    out[o] = 0;
}
#define UNSIGNED "020000000101000000000000000000000000000000000000000000000000000000000000000000000000fdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000"

/* the witnessScript of a wsh(<ms>) descriptor via the descriptor engine */
static int wsh_script(const char* desc, u8* out, int cap, char* spkhex){
    static descr_t d; char err[256];
    if (!descr_parse(desc, &d, err, sizeof err)){ printf("  parse: %s\n", err); return -1; }
    int which = 0; int l = descr_inner_script_at(&d, 0, out, cap, &which);
    descr_spk_t sp[4]; if (descr_expand(&d, 0, sp, 4) != 1) return -1;
    hexify(spkhex, sp[0].spk, (size_t)sp[0].len);
    return which == 2 ? l : -1;
}
/* the witness of input 0 of a signed tx: items count and the item lengths */
static int witness_items(const char* txhex, int* lens, int cap){
    static u8 tx[8000]; int n = unhex(txhex, tx, sizeof tx); if (n < 0) return -1;
    if (tx[4] != 0 || tx[5] != 1) return -1;     /* segwit marker */
    size_t p = 6; int nin = tx[p++];
    for (int i = 0; i < nin; i++){ p += 36; int sl = tx[p++]; p += (size_t)sl + 4; }
    int nout = tx[p++]; for (int i = 0; i < nout; i++){ p += 8; int sl = tx[p++]; p += (size_t)sl; }
    int items = tx[p++];
    for (int i = 0; i < items && i < cap; i++){ unsigned l = tx[p++]; if (l == 0xfd){ l = tx[p] | (tx[p+1] << 8); p += 2; } lens[i] = (int)l; p += l; }
    return items;
}

int main(void){
    char W1[64], W2[64]; wif_of(W1, 0x11); wif_of(W2, 0x22);
    extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char priv_be[32]);
    u8 p1[32], p2[32]; memset(p1, 0x11, 32); memset(p2, 0x22, 32); u8 pub1[33], pub2[33]; scalar_to_pubkey(pub1, p1); scalar_to_pubkey(pub2, p2);
    char PUB1[67], PUB2[67]; hexify(PUB1, pub1, 33); hexify(PUB2, pub2, 33);
    u8 pre[32]; memset(pre, 0x77, 32); u8 h[32]; sha256_full(h, pre, 32); char hh[65], ph[65]; hexify(hh, h, 32); hexify(ph, pre, 32);
    /* key branch, or a second key after 2 blocks; and a hash challenge on the whole */
    char desc[512]; snprintf(desc, sizeof desc, "wsh(and_v(v:sha256(%s),or_d(pk(%s),and_v(v:pkh(%s),older(2)))))", hh, W1, W2);
    static u8 ws[4000]; char spk[80]; int wl = wsh_script(desc, ws, sizeof ws, spk);
    ck("descriptor parses and yields its witnessScript", wl > 0);
    char wsh[8001]; hexify(wsh, ws, (size_t)wl);

    printf("== 1. signrawtransactionwithkey: key branch with the preimage ==\n");
    char params[12000];
    snprintf(params, sizeof params, "[\"%s\",[\"%s\"],[{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"%s\",\"amount\":1.0,\"witnessScript\":\"%s\",\"pubkeys\":[\"%s\"],\"preimages\":[{\"hash\":\"%s\",\"preimage\":\"%s\"}]}]]",
             UNSIGNED, W1, spk, wsh, PUB2, hh, ph);
    long ec = 0; const char* em = NULL; rj_val* r = call("signrawtransactionwithkey", params, &ec, &em);
    rj_val* comp = r ? rj_obj_get(r, "complete") : NULL; rj_val* hex = r ? rj_obj_get(r, "hex") : NULL;
    ck("complete=true", comp && comp->str[0] == '1');
    int lens[16]; int items = hex && hex->typ == RJ_STR ? witness_items(hex->str, lens, 16) : -1;
    /* and_v(v:sha256(H), or_d(pk(A), ...)): the sha256 executes first, so its preimage is the TOP
     * item; or_d takes A's signature alone. Bottom-first: sigA, preimage, script. */
    ck("witness = sigA, preimage, the script (the non-malleable or_d key branch)", items == 3 && lens[0] >= 70 && lens[0] <= 73 && lens[1] == 32 && lens[2] == wl);
    if (!(items == 3 && lens[1] == 32)) printf("  items=%d lens=%d,%d,%d\n", items, lens[0], lens[1], lens[2]);
    rj_free(r);

    printf("== 2. without the preimage: refused with the reason ==\n");
    snprintf(params, sizeof params, "[\"%s\",[\"%s\"],[{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"%s\",\"amount\":1.0,\"witnessScript\":\"%s\",\"pubkeys\":[\"%s\"]}]]", UNSIGNED, W1, spk, wsh, PUB2);
    r = call("signrawtransactionwithkey", params, &ec, &em);
    comp = r ? rj_obj_get(r, "complete") : NULL; rj_val* errs = r ? rj_obj_get(r, "errors") : NULL;
    ck("complete=false", comp && comp->str[0] == '0');
    { int said = 0; if (errs && errs->typ == RJ_ARR && errs->nitems){ rj_val* e0 = rj_obj_get(errs->items[0], "error"); if (e0 && e0->typ == RJ_STR && strstr(e0->str, "preimages")) said = 1; }
      ck("the error names the missing preimage/timelock", said); }
    rj_free(r);

    printf("== 3. the second key needs older(2): refused at nSequence final, signed at nSequence 2 ==\n");
    snprintf(params, sizeof params, "[\"%s\",[\"%s\"],[{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"%s\",\"amount\":1.0,\"witnessScript\":\"%s\",\"pubkeys\":[\"%s\"],\"preimages\":[{\"hash\":\"%s\",\"preimage\":\"%s\"}]}]]",
             UNSIGNED, W2, spk, wsh, PUB1, hh, ph);
    r = call("signrawtransactionwithkey", params, &ec, &em);
    comp = r ? rj_obj_get(r, "complete") : NULL;
    ck("key B alone with nSequence 0xfffffffd: older(2) unmet -> incomplete", comp && comp->str[0] == '0');
    rj_free(r);
    /* same tx with nSequence = 2 on the input */
    static char unsigned_seq2[400]; strcpy(unsigned_seq2, UNSIGNED); memcpy(unsigned_seq2 + 84, "02000000", 8);
    snprintf(params, sizeof params, "[\"%s\",[\"%s\"],[{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"%s\",\"amount\":1.0,\"witnessScript\":\"%s\",\"pubkeys\":[\"%s\"],\"preimages\":[{\"hash\":\"%s\",\"preimage\":\"%s\"}]}]]",
             unsigned_seq2, W2, spk, wsh, PUB1, hh, ph);
    r = call("signrawtransactionwithkey", params, &ec, &em);
    comp = r ? rj_obj_get(r, "complete") : NULL; hex = r ? rj_obj_get(r, "hex") : NULL;
    ck("key B with nSequence 2: complete=true", comp && comp->str[0] == '1');
    items = hex && hex->typ == RJ_STR ? witness_items(hex->str, lens, 16) : -1;
    /* or_d: Z's satisfaction (sigB, pubB) under X's dissatisfaction (empty); the preimage on top; bottom-first:
     * sigB, pubB, <empty>, preimage, script */
    ck("witness = sigB, pubB, the empty dissatisfaction of pk(A), preimage, the script", items == 5 && lens[1] == 33 && lens[2] == 0 && lens[3] == 32 && lens[4] == wl);
    if (!(items == 5 && lens[3] == 32)) printf("  items=%d lens=%d,%d,%d,%d,%d\n", items, lens[0], lens[1], lens[2], lens[3], lens[4]);
    rj_free(r);

    printf("== 4. descriptorprocesspsbt over a PSBT with witness_utxo, witness_script and a sha256 preimage ==\n");
    { static u8 psbt[9000]; size_t o = 0; static u8 utx[400]; int ul = unhex(UNSIGNED, utx, sizeof utx);
      memcpy(psbt + o, "psbt\xff", 5); o += 5;
      psbt[o++] = 1; psbt[o++] = 0x00; psbt[o++] = (u8)ul; memcpy(psbt + o, utx, (size_t)ul); o += (size_t)ul; psbt[o++] = 0;   /* global: unsigned tx */
      /* input 0: witness_utxo (1.0 BTC, spk), witness_script, sha256 preimage */
      u8 spkb[64]; int spl = unhex(spk, spkb, sizeof spkb);
      psbt[o++] = 1; psbt[o++] = 0x01; psbt[o++] = (u8)(8 + 1 + spl);
      unsigned long long amt = 100000000ULL; for (int i = 0; i < 8; i++) psbt[o++] = (u8)(amt >> (8*i));
      psbt[o++] = (u8)spl; memcpy(psbt + o, spkb, (size_t)spl); o += (size_t)spl;
      psbt[o++] = 1; psbt[o++] = 0x05; if (wl < 253) psbt[o++] = (u8)wl; else { psbt[o++] = 0xfd; psbt[o++] = (u8)wl; psbt[o++] = (u8)(wl >> 8); }
      memcpy(psbt + o, ws, (size_t)wl); o += (size_t)wl;
      psbt[o++] = 33; psbt[o++] = 0x0b; memcpy(psbt + o, h, 32); o += 32; psbt[o++] = 32; memcpy(psbt + o, pre, 32); o += 32;
      psbt[o++] = 0;                                    /* end of input map */
      psbt[o++] = 0;                                    /* output 0: empty map */
      static char pb[16000]; b64(pb, psbt, o);
      snprintf(params, sizeof params, "[\"%s\",[\"%s\"]]", pb, desc);
      r = call("descriptorprocesspsbt", params, &ec, &em);
      comp = r ? rj_obj_get(r, "complete") : NULL; hex = r ? rj_obj_get(r, "hex") : NULL;
      ck("descriptorprocesspsbt: complete=true with the private descriptor", comp && comp->str[0] == '1');
      if (!r) printf("  rpc error %ld: %s\n", ec, em ? em : "");
      items = hex && hex->typ == RJ_STR ? witness_items(hex->str, lens, 16) : -1;
      ck("...finalized: sigA, preimage, script", items == 3 && lens[1] == 32 && lens[2] == wl);
      if (!(items == 3 && lens[1] == 32)) printf("  items=%d lens=%d,%d,%d\n", items, lens[0], lens[1], lens[2]);
      rj_free(r);
    }
    printf("== 5. a tapscript miniscript leaf: descriptorprocesspsbt over a PSBT with tap_leaf_script + internal key ==\n");
    {
        static const char* NUMS = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
        char tdesc[512]; snprintf(tdesc, sizeof tdesc, "tr(%s,and_v(v:pk(%s),pk(%s)))", NUMS, W1, W2);
        static descr_t d; char err[256];
        ck("tr(NUMS, and_v(v:pk(A),pk(B))) parses", descr_parse(tdesc, &d, err, sizeof err));
        int msroot = -1; for (int i = 0; i < d.nn; i++) if (d.nodes[i].type == DN_MINISCRIPT) msroot = d.nodes[i].ms_root;
        ck("...with a miniscript leaf", msroot >= 0);
        ms_tree_t mt; descr_ms_tree(&d, &mt); descr_msuser_t mu; ms_ctx_t mctx; descr_ms_ctx(&d, 0, 0, &mu, &mctx);
        static u8 leaf[400]; int ll = msroot >= 0 ? ms_to_script(&mt, &mctx, msroot, leaf, sizeof leaf) : -1;
        ck("...whose script is the leaf", ll > 0);
        descr_spk_t sp[4]; int nsp = descr_expand(&d, 0, sp, 4);
        ck("...and a P2TR scriptPubKey", nsp == 1 && sp[0].len == 34 && sp[0].spk[0] == 0x51);
        u8 ctrl[33]; ctrl[0] = 0xc0; unhex(NUMS, ctrl + 1, 32);
        static u8 psbt[4000]; size_t o = 0; static u8 utx[400]; int ul = unhex(UNSIGNED, utx, sizeof utx);
        memcpy(psbt + o, "psbt\xff", 5); o += 5;
        psbt[o++] = 1; psbt[o++] = 0x00; psbt[o++] = (u8)ul; memcpy(psbt + o, utx, (size_t)ul); o += (size_t)ul; psbt[o++] = 0;
        psbt[o++] = 1; psbt[o++] = 0x01; psbt[o++] = (u8)(8 + 1 + 34);
        unsigned long long amt = 100000000ULL; for (int i = 0; i < 8; i++) psbt[o++] = (u8)(amt >> (8*i));
        psbt[o++] = 34; memcpy(psbt + o, sp[0].spk, 34); o += 34;
        psbt[o++] = 34; psbt[o++] = 0x15; memcpy(psbt + o, ctrl, 33); o += 33;           /* TAP_LEAF_SCRIPT: key = 0x15 || control block */
        psbt[o++] = (u8)(ll + 1); memcpy(psbt + o, leaf, (size_t)ll); o += (size_t)ll; psbt[o++] = 0xc0;   /* value = script || leaf version */
        psbt[o++] = 1; psbt[o++] = 0x17; psbt[o++] = 32; unhex(NUMS, psbt + o, 32); o += 32;   /* TAP_INTERNAL_KEY */
        psbt[o++] = 0; psbt[o++] = 0;
        static char pb[8000]; b64(pb, psbt, o);
        snprintf(params, sizeof params, "[\"%s\",[\"%s\"]]", pb, tdesc);
        r = call("descriptorprocesspsbt", params, &ec, &em);
        comp = r ? rj_obj_get(r, "complete") : NULL; hex = r ? rj_obj_get(r, "hex") : NULL;
        ck("descriptorprocesspsbt signs the miniscript leaf: complete=true", comp && comp->str[0] == '1');
        if (!r) printf("  rpc error %ld: %s\n", ec, em ? em : "");
        items = hex && hex->typ == RJ_STR ? witness_items(hex->str, lens, 16) : -1;
        /* and_v(v:pk(A),pk(B)): A's signature on top -> bottom-first: sigB, sigA, leaf, control (64-byte DEFAULT sigs) */
        ck("witness = sigB, sigA (64 bytes each), the leaf script, the control block", items == 4 && lens[0] == 64 && lens[1] == 64 && lens[2] == ll && lens[3] == 33);
        if (!(items == 4 && lens[0] == 64)) printf("  items=%d lens=%d,%d,%d,%d\n", items, lens[0], lens[1], lens[2], lens[3]);
        rj_free(r);
        /* only A: the leaf cannot be satisfied -> incomplete, no crash */
        char tdesc_a[512]; snprintf(tdesc_a, sizeof tdesc_a, "tr(%s,and_v(v:pk(%s),pk(%s)))", NUMS, W1, PUB2);
        snprintf(params, sizeof params, "[\"%s\",[\"%s\"]]", pb, tdesc_a);
        r = call("descriptorprocesspsbt", params, &ec, &em);
        comp = r ? rj_obj_get(r, "complete") : NULL;
        ck("with A only the leaf stays unsatisfied: complete=false", r && comp && comp->str[0] == '0');
        rj_free(r);
    }
    printf("== 6. musig(): descriptorprocesspsbt is the Updater too -- participants/derivation fields, then the rounds ==\n");
    for (int variant = 0; variant < 2; variant++){
        /* variant 0: tr(musig(A,B)) -- we hold both keys: fields, two pubnonces, then the rounds run to a key-path signature
         * variant 1: tr(musig(xprv,xpub)/0/*) -- derivation: the bip32 field appears; we hold one key: one pubnonce, never complete */
        char mdesc[700];
        if (variant == 0) snprintf(mdesc, sizeof mdesc, "tr(musig(%s,%s))", W1, W2);
        else snprintf(mdesc, sizeof mdesc, "tr(musig(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y)/0/*)");
        static descr_t d; char err[256];
        ck(variant ? "tr(musig(xprv,xpub)/0/*) parses" : "tr(musig(A,B)) parses", descr_parse(mdesc, &d, err, sizeof err));
        long idx = variant ? 3 : 0;
        descr_spk_t sp[4]; int nsp = descr_expand(&d, idx, sp, 4);
        ck("...and expands to a P2TR output", nsp == 1 && sp[0].len == 34 && sp[0].spk[0] == 0x51);
        static u8 psbt[4000]; size_t o = 0; static u8 utx[400]; int ul = unhex(UNSIGNED, utx, sizeof utx);
        memcpy(psbt + o, "psbt\xff", 5); o += 5;
        psbt[o++] = 1; psbt[o++] = 0x00; psbt[o++] = (u8)ul; memcpy(psbt + o, utx, (size_t)ul); o += (size_t)ul; psbt[o++] = 0;
        psbt[o++] = 1; psbt[o++] = 0x01; psbt[o++] = (u8)(8 + 1 + 34);
        unsigned long long amt = 100000000ULL; for (int i = 0; i < 8; i++) psbt[o++] = (u8)(amt >> (8*i));
        psbt[o++] = 34; memcpy(psbt + o, sp[0].spk, 34); o += 34;
        psbt[o++] = 0; psbt[o++] = 0;
        static char pb[8000]; b64(pb, psbt, o);
        snprintf(params, sizeof params, "[\"%s\",[{\"desc\":\"%s\",\"range\":[0,5]}]]", pb, mdesc);
        r = call("descriptorprocesspsbt", params, &ec, &em);
        ck("round 1 answers", r != NULL); if (!r) printf("  rpc error %ld: %s\n", ec, em ? em : "");
        rj_val* p1 = r ? rj_obj_get(r, "psbt") : NULL;
        if (p1 && p1->typ == RJ_STR){
            char dp[9000]; snprintf(dp, sizeof dp, "[\"%s\"]", p1->str);
            rj_val* dec = call("decodepsbt", dp, &ec, &em);
            rj_val* ins = dec ? rj_obj_get(dec, "inputs") : NULL; rj_val* in0 = ins && ins->typ == RJ_ARR && ins->nitems ? ins->items[0] : NULL;
            rj_val* mp = in0 ? rj_obj_get(in0, "musig2_participant_pubkeys") : NULL;
            rj_val* pn = in0 ? rj_obj_get(in0, "musig2_pubnonces") : NULL;
            rj_val* ik = in0 ? rj_obj_get(in0, "taproot_internal_key") : NULL;
            rj_val* bd = in0 ? rj_obj_get(in0, "taproot_bip32_derivs") : NULL;
            ck("the PSBT now carries one musig2 aggregate with 2 participants", mp && mp->typ == RJ_ARR && mp->nitems == 1 && rj_obj_get(mp->items[0], "participant_pubkeys") && rj_obj_get(mp->items[0], "participant_pubkeys")->nitems == 2);
            ck("...the taproot internal key", ik && ik->typ == RJ_STR && strlen(ik->str) == 64);
            if (variant) ck("...a taproot bip32 derivation for the derived aggregate", bd && bd->typ == RJ_ARR && bd->nitems >= 1);
            ck(variant ? "...and our one pubnonce (the xpub participant is not ours)" : "...and our two pubnonces (round 1 done for both keys we hold)", pn && pn->typ == RJ_ARR && pn->nitems == (variant ? 1 : 2));
            if (!(mp && pn)) { long L = 0; char* js = rj_write_alloc(in0 ? in0 : dec, 0, &L); printf("  decoded input: %.600s\n", js ? js : "null"); free(js); }
            rj_free(dec);
        }
        if (variant){ rj_free(r); continue; }
        /* keep processing until the key-path signature is aggregated */
        int done = 0; char cur[9000]; if (p1 && p1->typ == RJ_STR) snprintf(cur, sizeof cur, "%s", p1->str); else cur[0] = 0;
        rj_free(r);
        for (int round = 2; round <= 4 && cur[0] && !done; round++){
            snprintf(params, sizeof params, "[\"%s\",[{\"desc\":\"%s\",\"range\":[0,5]}]]", cur, mdesc);
            r = call("descriptorprocesspsbt", params, &ec, &em);
            comp = r ? rj_obj_get(r, "complete") : NULL; hex = r ? rj_obj_get(r, "hex") : NULL; rj_val* pp = r ? rj_obj_get(r, "psbt") : NULL;
            if (comp && comp->str[0] == '1' && hex && hex->typ == RJ_STR){ done = 1; items = witness_items(hex->str, lens, 16);
                ck("the key-path spend completes: one 64-byte BIP340 signature", items == 1 && lens[0] == 64); }
            if (pp && pp->typ == RJ_STR) snprintf(cur, sizeof cur, "%s", pp->str); else cur[0] = 0;
            rj_free(r);
        }
        ck("musig() key path signed within three rounds by a signer holding both keys", done);
    }
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
