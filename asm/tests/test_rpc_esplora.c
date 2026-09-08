/* test_rpc_esplora.c -- the Esplora facade's routes and reshaping, driven by
 * a canned rpc_dispatch (this file defines it), so every route is exercised
 * without a node: the JSON that Core-shaped handlers return is fixed here
 * and the Esplora JSON the facade must produce is asserted field by field. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../rpc_esplora.h"
#include "../rpc_json.h"
static int fails = 0, checks = 0;
static void ok(int c, const char* w){ checks++; printf("  %s %s\n", c ? "ok " : "FAIL", w); if (!c) fails++; }
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);

/* ---- the canned node ------------------------------------------------------- */
#define BH "000000000000000000029c2a5a3b6b1d2e0d0c0b0a090807060504030201000f"
#define TX1 "1111111111111111111111111111111111111111111111111111111111111111"
#define TX2 "2222222222222222222222222222222222222222222222222222222222222222"
#define TX3 "3333333333333333333333333333333333333333333333333333333333333333"
static int g_spender_index = 1; static int g_calls_gettxout = 0; static int g_big = 0;
static rj_val* J(const char* lit){ return rj_parse(lit, strlen(lit)); }
int rpc_dispatch(const char* method, const rj_val* params, const rpc_wallet* w, rj_val** result, long* ec, const char** em){
    (void)w; const char* p0 = params && params->typ == RJ_ARR && params->nitems ? params->items[0]->str : 0;
    long p1 = params && params->nitems > 1 && params->items[1]->str ? strtol(params->items[1]->str, 0, 10) : -1;
    if (!strcmp(method, "getblockchaininfo")){ *result = rj_parse("{\"blocks\":700000,\"bestblockhash\":\"" BH "\"}", strlen("{\"blocks\":700000,\"bestblockhash\":\"" BH "\"}")); return 1; }
    if (!strcmp(method, "getblockhash")){ if (p0 && !strcmp(p0, "700000")){ *result = rj_str(BH); return 1; } *ec = -8; *em = "Block height out of range"; return 0; }
    if (!strcmp(method, "getblockheader")){ if (!p0 || strcmp(p0, BH)){ *ec = -5; *em = "Block not found"; return 0; }
        if (params->nitems > 1 && params->items[1]->typ == RJ_BOOL && params->items[1]->str[0] == '0'){ *result = rj_str("00e0ff2f" "aa"); return 1; }
        *result = J("{\"height\":700000,\"time\":1631000000}"); return 1; }
    if (!strcmp(method, "getblock")){
        if (!p0 || strcmp(p0, BH)){ *ec = -5; *em = "Block not found"; return 0; }
        if (p1 == 0){ *result = rj_str("0102"); return 1; }
        const char* blk = "{\"hash\":\"" BH "\",\"confirmations\":3,\"height\":700000,\"version\":536870912,\"versionHex\":\"20000000\",\"merkleroot\":\"ab\",\"time\":1631000000,\"mediantime\":1630999000,\"nonce\":42,\"bits\":\"170f2c8d\",\"difficulty\":18000000000000.5,\"nTx\":3,\"size\":1234,\"weight\":4000,\"previousblockhash\":\"" TX3 "\",\"tx\":[";
        char* buf = malloc(8192);
        if (p1 <= 1) snprintf(buf, 8192, "%s\"" TX1 "\",\"" TX2 "\",\"" TX3 "\"]}", blk);
        else snprintf(buf, 8192, "%s"
            "{\"txid\":\"" TX1 "\",\"version\":1,\"locktime\":0,\"size\":100,\"weight\":400,\"vin\":[{\"coinbase\":\"03e0ae0a\",\"txinwitness\":[\"00\"],\"sequence\":4294967295}],\"vout\":[{\"value\":6.25,\"n\":0,\"scriptPubKey\":{\"hex\":\"0014aabb\",\"type\":\"witness_v0_keyhash\",\"address\":\"bc1qtest\"}}]},"
            "{\"txid\":\"" TX2 "\",\"version\":2,\"locktime\":699999,\"size\":222,\"weight\":561,\"fee\":0.00000377,\"vin\":[{\"txid\":\"" TX3 "\",\"vout\":1,\"scriptSig\":{\"hex\":\"\"},\"txinwitness\":[\"3044aa\",\"02bb\"],\"sequence\":4294967293,\"prevout\":{\"generated\":false,\"height\":699990,\"value\":0.03612294,\"scriptPubKey\":{\"hex\":\"00146ffe291a\",\"type\":\"witness_v0_keyhash\",\"address\":\"bc1qprev\"}}}],\"vout\":[{\"value\":0.03611917,\"n\":0,\"scriptPubKey\":{\"hex\":\"76a914aa88ac\",\"type\":\"pubkeyhash\",\"address\":\"1test\"}},{\"value\":0.00000000,\"n\":1,\"scriptPubKey\":{\"hex\":\"6a04deadbeef\",\"type\":\"nulldata\"}}]},"
            "{\"txid\":\"" TX3 "\",\"version\":2,\"locktime\":0,\"size\":50,\"weight\":200,\"vin\":[{\"txid\":\"" TX1 "\",\"vout\":0,\"scriptSig\":{\"hex\":\"51\"},\"sequence\":0}],\"vout\":[{\"value\":1.5,\"n\":0,\"scriptPubKey\":{\"hex\":\"51\",\"type\":\"nonstandard\"}}]}]}", blk);
        *result = rj_parse(buf, strlen(buf)); free(buf); return 1; }
    if (!strcmp(method, "getrawtransaction")){
        if (p0 && !strcmp(p0, TX2)){
            if (p1 == 0){ *result = rj_str("0200aa"); return 1; }            if (g_big){ char* big = malloc(1300000); memset(big, 'a', 1200000); big[1200000] = 0;
                char* t = malloc(1400000); snprintf(t, 1400000, "{\"txid\":\"" TX2 "\",\"version\":2,\"locktime\":0,\"size\":1,\"weight\":4,\"fee\":0.00000001,\"blockhash\":\"" BH "\",\"vin\":[{\"txid\":\"" TX3 "\",\"vout\":0,\"scriptSig\":{\"hex\":\"\"},\"txinwitness\":[\"%s\"],\"sequence\":0}],\"vout\":[]}", big);
                *result = J(t); free(t); free(big); return 1; }
            const char* t = "{\"txid\":\"" TX2 "\",\"version\":2,\"locktime\":699999,\"size\":222,\"weight\":561,\"fee\":0.00000377,\"blockhash\":\"" BH "\",\"confirmations\":3,\"blocktime\":1631000000,\"vin\":[{\"txid\":\"" TX3 "\",\"vout\":1,\"scriptSig\":{\"hex\":\"\"},\"txinwitness\":[\"3044aa\"],\"sequence\":4294967293,\"prevout\":{\"generated\":false,\"height\":699990,\"value\":0.03612294,\"scriptPubKey\":{\"hex\":\"00146ffe291a\",\"type\":\"witness_v0_keyhash\",\"address\":\"bc1qprev\"}}}],\"vout\":[{\"value\":0.03611917,\"n\":0,\"scriptPubKey\":{\"hex\":\"76a914aa88ac\",\"type\":\"pubkeyhash\",\"address\":\"1test\"}},{\"value\":0,\"n\":1,\"scriptPubKey\":{\"hex\":\"6a04deadbeef\",\"type\":\"nulldata\"}}]}";
            *result = rj_parse(t, strlen(t)); return 1; }
        if (p0 && !strcmp(p0, "4444444444444444444444444444444444444444444444444444444444444444")){   /* an unconfirmed tx: no prevout, no fee, no blockhash */
            const char* t = "{\"txid\":\"4444444444444444444444444444444444444444444444444444444444444444\",\"version\":2,\"locktime\":0,\"size\":110,\"weight\":440,\"vin\":[{\"txid\":\"" TX2 "\",\"vout\":0,\"scriptSig\":{\"hex\":\"\"},\"sequence\":0}],\"vout\":[{\"value\":0.03,\"n\":0,\"scriptPubKey\":{\"hex\":\"0014cc\",\"type\":\"witness_v0_keyhash\",\"address\":\"bc1qout\"}}]}";
            *result = rj_parse(t, strlen(t)); return 1; }
        *ec = -5; *em = "No such mempool or blockchain transaction"; return 0; }
    if (!strcmp(method, "getmempoolentry")){ *result = J("{\"vsize\":110,\"fees\":{\"base\":0.00000500}}"); return 1; }
    if (!strcmp(method, "gettxout")){ g_calls_gettxout++;
        if (p0 && !strcmp(p0, TX2) && p1 == 0){ *result = J("{\"value\":0.03611917,\"scriptPubKey\":{\"hex\":\"76a914aa88ac\",\"type\":\"pubkeyhash\",\"address\":\"1test\"}}"); return 1; }
        *result = rj_null(); return 1; }
    if (!strcmp(method, "gettxspendingprevout")){ if (!g_spender_index){ *ec = -1; *em = "txospenderindex is unavailable"; return 0; }
        const char* s = "[{\"txid\":\"" TX2 "\",\"vout\":0,\"spendingtxid\":\"4444444444444444444444444444444444444444444444444444444444444444\",\"spendingvin\":0},{\"txid\":\"" TX2 "\",\"vout\":1}]";
        *result = rj_parse(s, strlen(s)); return 1; }
    if (!strcmp(method, "getrawmempool")){ if (params->items[0]->str[0] == '1'){ *result = J("{\"4444444444444444444444444444444444444444444444444444444444444444\":{\"vsize\":110,\"fees\":{\"base\":0.000005}}}"); return 1; }
        *result = J("[\"4444444444444444444444444444444444444444444444444444444444444444\"]"); return 1; }
    if (!strcmp(method, "getmempoolinfo")){ *result = J("{\"size\":1,\"bytes\":110,\"total_fee\":0.000005}"); return 1; }
    if (!strcmp(method, "sendrawtransaction")){ if (p0 && !strcmp(p0, "0200aa")){ *result = rj_str("4444444444444444444444444444444444444444444444444444444444444444"); return 1; } *ec = -26; *em = "TX rejected"; return 0; }
    *ec = -32601; *em = "Method not found"; return 0;
}

static char* g_out; static size_t g_outlen; static int g_status; static const char* g_ctype;
static rj_val* GET(const char* path){ free(g_out); g_out = 0; esplora_handle("GET", 3, path, strlen(path), "", 0, 0, &g_out, &g_outlen, &g_status, &g_ctype); return g_status == 200 && !strcmp(g_ctype, "application/json") ? rj_parse(g_out, g_outlen) : 0; }
static rj_val* POST(const char* path, const char* body){ free(g_out); g_out = 0; esplora_handle("POST", 4, path, strlen(path), body, strlen(body), 0, &g_out, &g_outlen, &g_status, &g_ctype); return g_status == 200 && !strcmp(g_ctype, "application/json") ? rj_parse(g_out, g_outlen) : 0; }
static const char* S(const rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o, k) : 0; return v && v->str ? v->str : ""; }
static rj_val* G(const rj_val* o, const char* k){ return o ? rj_obj_get(o, k) : 0; }
static int streq(const char* a, const char* b){ return a && b && !strcmp(a, b); }

int main(void){
    printf("---- rpc_esplora ----\n");
    /* pure helpers */
    ok(esplora_sats_of_amount("0.01000000") == 1000000 && esplora_sats_of_amount("6.25") == 625000000 && esplora_sats_of_amount("0") == 0 && esplora_sats_of_amount("21000000") == 2100000000000000L, "sats from Core's decimal amounts, no floating point");
    ok(esplora_sats_of_amount("0.000000001") == 0 && esplora_sats_of_amount("x") == -1, "a 9th decimal is dropped; garbage is -1");
    { char a[512]; esplora_asm_of_hex("76a914000102030405060708090a0b0c0d0e0f1011121388ac", a, sizeof a);
      ok(streq(a, "OP_DUP OP_HASH160 OP_PUSHBYTES_20 000102030405060708090a0b0c0d0e0f10111213 OP_EQUALVERIFY OP_CHECKSIG"), "asm: P2PKH in mempool's own notation"); }
    { char a[512]; esplora_asm_of_hex("0014aabb", a, sizeof a); ok(streq(a, "OP_0 OP_PUSHBYTES_20 aabb"), "asm: a short push is emitted with what bytes there are (mempool's loop)"); }
    { char a[512]; esplora_asm_of_hex("6a4c03aabbcc", a, sizeof a); ok(streq(a, "OP_RETURN OP_PUSHDATA1 aabbcc"), "asm: OP_PUSHDATA1"); }
    { char a[512]; esplora_asm_of_hex("5152b1b2bbba4f", a, sizeof a); ok(streq(a, "OP_PUSHNUM_1 OP_PUSHNUM_2 OP_CLTV OP_CSV OP_RETURN_187 OP_CHECKSIGADD OP_PUSHNUM_NEG1"), "asm: PUSHNUM, CLTV, CSV, an unknown opcode as OP_RETURN_n, CHECKSIGADD, NEG1"); }
    ok(streq(esplora_spk_type("witness_v1_taproot"), "v1_p2tr") && streq(esplora_spk_type("nulldata"), "op_return") && streq(esplora_spk_type("witness_unknown"), "unknown"), "scriptpubkey_type map");
    /* merkle branch: 3 leaves, the branch of leaf 1 must rebuild the root */
    { unsigned char ids[3][32]; for (int i = 0; i < 3; i++) memset(ids[i], 0x11 * (i + 1), 32);
      unsigned char br[8][32]; int nb = esplora_merkle_branch(ids, 3, 1, br, 8);
      unsigned char pair[64], h[32], root[32];
      memcpy(pair, ids[0], 32); memcpy(pair + 32, ids[1], 32); sha256d(h, pair, 64);              /* level 1, node 0 */
      unsigned char h2[32]; memcpy(pair, ids[2], 32); memcpy(pair + 32, ids[2], 32); sha256d(h2, pair, 64);
      memcpy(pair, h, 32); memcpy(pair + 32, h2, 32); sha256d(root, pair, 64);
      /* rebuild from the branch: leaf 1 with sibling br[0] (=leaf 0, on the left), then br[1] (=h2, on the right) */
      unsigned char acc[32]; memcpy(pair, br[0], 32); memcpy(pair + 32, ids[1], 32); sha256d(acc, pair, 64);
      memcpy(pair, acc, 32); memcpy(pair + 32, br[1], 32); sha256d(acc, pair, 64);
      ok(nb == 2 && !memcmp(acc, root, 32), "merkle branch of leaf 1 in a 3-leaf tree rebuilds the root (odd level paired with itself)"); }

    /* routes */
    GET("/blocks/tip/height"); ok(g_status == 200 && streq(g_out, "700000"), "GET /blocks/tip/height -> 700000 as text");
    GET("/blocks/tip/hash"); ok(streq(g_out, BH), "GET /blocks/tip/hash");
    GET("/block-height/700000"); ok(streq(g_out, BH), "GET /block-height/700000");
    GET("/block-height/9"); ok(g_status == 404, "GET /block-height/<unknown> -> 404");
    { rj_val* b = GET("/block/" BH);
      ok(b && streq(S(b, "id"), BH) && streq(S(b, "height"), "700000") && streq(S(b, "timestamp"), "1631000000") && streq(S(b, "merkle_root"), "ab") && streq(S(b, "tx_count"), "3") && streq(S(b, "previousblockhash"), TX3), "GET /block/:hash -> Esplora Block fields");
      ok(b && streq(S(b, "bits"), "386870413") && streq(S(b, "mediantime"), "1630999000") && G(b, "stale") && G(b, "stale")->typ == RJ_BOOL, "...bits as a number (0x170f2c8d), mediantime, stale:false");
      rj_free(b); }
    GET("/block/" BH "/header"); ok(g_status == 200 && streq(g_out, "00e0ff2faa"), "GET /block/:hash/header -> header hex");
    GET("/block/" BH "/raw"); ok(g_status == 200 && g_outlen == 2 && (unsigned char)g_out[0] == 1 && (unsigned char)g_out[1] == 2 && streq(g_ctype, "application/octet-stream"), "GET /block/:hash/raw -> binary");
    { rj_val* t = GET("/block/" BH "/txids"); ok(t && t->typ == RJ_ARR && t->nitems == 3 && streq(t->items[1]->str, TX2), "GET /block/:hash/txids"); rj_free(t); }
    GET("/block/" BH "/txid/2"); ok(streq(g_out, TX3), "GET /block/:hash/txid/2");
    { rj_val* txs = GET("/internal/block/" BH "/txs");
      ok(txs && txs->typ == RJ_ARR && txs->nitems == 3, "GET /internal/block/:hash/txs -> every transaction");
      rj_val* cb = txs ? txs->items[0] : 0; rj_val* cbin = G(cb, "vin") ? G(cb, "vin")->items[0] : 0;
      ok(cbin && streq(S(cbin, "txid"), "0000000000000000000000000000000000000000000000000000000000000000") && streq(S(cbin, "vout"), "4294967295") && G(cbin, "is_coinbase")->str[0] == '1' && streq(S(cbin, "scriptsig"), "03e0ae0a") && G(cbin, "prevout")->typ == RJ_NULL, "coinbase input: zero txid, vout 4294967295, is_coinbase, scriptsig = coinbase hex, prevout null");
      ok(cb && streq(S(cb, "fee"), "0") && streq(S(G(cb, "status"), "block_height"), "700000") && streq(S(G(cb, "status"), "block_hash"), BH), "coinbase fee 0; status carries the block");
      rj_val* t2 = txs ? txs->items[1] : 0; rj_val* in0 = G(t2, "vin") ? G(t2, "vin")->items[0] : 0; rj_val* pv = G(in0, "prevout");
      ok(t2 && streq(S(t2, "fee"), "377") && streq(S(t2, "weight"), "561") && streq(S(t2, "locktime"), "699999"), "tx fee in sats from Core's decimal, weight, locktime");
      ok(pv && streq(S(pv, "value"), "3612294") && streq(S(pv, "scriptpubkey_address"), "bc1qprev") && streq(S(pv, "scriptpubkey_type"), "v0_p2wpkh") && streq(S(pv, "scriptpubkey_asm"), "OP_0 OP_PUSHBYTES_20 6ffe291a"), "prevout: value in sats, address, esplora type, asm");
      ok(in0 && G(in0, "witness") && G(in0, "witness")->nitems == 2 && streq(S(in0, "inner_redeemscript_asm"), ""), "witness stack copied; inner_* asm fields present");
      rj_val* o1 = G(t2, "vout") ? G(t2, "vout")->items[1] : 0;
      ok(o1 && streq(S(o1, "scriptpubkey_type"), "op_return") && !G(o1, "scriptpubkey_address") && streq(S(o1, "value"), "0"), "an OP_RETURN output: type op_return, no address, value 0");
      rj_val* t3 = txs ? txs->items[2] : 0;
      ok(t3 && streq(S(t3, "fee"), "0"), "a tx without prevouts in Core's JSON gets fee 0 rather than a lie");
      rj_free(txs); }
    { rj_val* txs = GET("/block/" BH "/txs/1"); ok(txs && txs->nitems == 2 && streq(S(txs->items[0], "txid"), TX2), "GET /block/:hash/txs/1 -> from index 1"); rj_free(txs); }
    { rj_val* t = GET("/tx/" TX2);
      ok(t && streq(S(t, "txid"), TX2) && streq(S(t, "fee"), "377") && streq(S(G(t, "status"), "block_height"), "700000") && streq(S(G(t, "status"), "block_time"), "1631000000"), "GET /tx/:txid -> confirmed tx with fee and status (height via getblockheader)");
      rj_free(t); }
    GET("/tx/" TX2 "/hex"); ok(streq(g_out, "0200aa"), "GET /tx/:txid/hex");
    { rj_val* st = GET("/tx/" TX2 "/status"); ok(st && G(st, "confirmed")->str[0] == '1' && streq(S(st, "block_hash"), BH), "GET /tx/:txid/status"); rj_free(st); }
    GET("/tx/" TX1 "/status"); ok(g_status == 404, "GET /tx/<unknown>/status -> 404");
    GET("/tx/zz"); ok(g_status == 400, "a non-hex txid -> 400");
    { rj_val* m = GET("/tx/" TX2 "/merkle-proof"); ok(m && streq(S(m, "block_height"), "700000") && streq(S(m, "pos"), "1") && G(m, "merkle") && G(m, "merkle")->nitems == 2, "GET /tx/:txid/merkle-proof -> height, pos 1, 2 siblings"); rj_free(m); }
    { rj_val* o = GET("/tx/" TX2 "/outspends");
      ok(o && o->nitems == 2 && G(o->items[0], "spent")->str[0] == '1' && streq(S(o->items[0], "txid"), "4444444444444444444444444444444444444444444444444444444444444444") && streq(S(o->items[0], "vin"), "0") && G(o->items[1], "spent")->str[0] == '0', "outspends from the txospender index: spent by txid/vin, unspent");
      ok(o && G(G(o->items[0], "status"), "confirmed")->str[0] == '0', "...an unconfirmed spender has status.confirmed false");
      rj_free(o); }
    { g_spender_index = 0; g_calls_gettxout = 0; rj_val* o = GET("/tx/" TX2 "/outspends");
      ok(o && o->nitems == 2 && G(o->items[0], "spent")->str[0] == '0' && G(o->items[1], "spent")->str[0] == '1' && g_calls_gettxout == 2, "without the index: gettxout per output decides spent (unspent output 0, spent output 1)");
      rj_free(o); g_spender_index = 1; }
    { rj_val* o = GET("/tx/" TX2 "/outspend/1"); ok(o && G(o, "spent")->str[0] == '0', "GET /tx/:txid/outspend/1"); rj_free(o); }
    { rj_val* t = GET("/tx/4444444444444444444444444444444444444444444444444444444444444444");
      ok(t && G(G(t, "status"), "confirmed")->str[0] == '0' && streq(S(t, "fee"), "500"), "an unconfirmed tx: status unconfirmed, fee from getmempoolentry");
      rj_val* pv = G(G(t, "vin")->items[0], "prevout"); ok(pv && streq(S(pv, "value"), "3611917") && streq(S(pv, "scriptpubkey_address"), "1test"), "...its prevout filled from gettxout(include_mempool)");
      rj_free(t); }
    { rj_val* m = GET("/mempool/txids"); ok(m && m->nitems == 1, "GET /mempool/txids"); rj_free(m); }
    { rj_val* m = GET("/mempool"); ok(m && streq(S(m, "count"), "1") && streq(S(m, "vsize"), "110") && streq(S(m, "total_fee"), "500"), "GET /mempool -> count, vsize, total_fee in sats"); rj_free(m); }
    { rj_val* m = GET("/mempool/recent"); ok(m && m->nitems == 1 && streq(S(m->items[0], "fee"), "500"), "GET /mempool/recent"); rj_free(m); }
    { rj_val* m = GET("/internal/mempool/txs?max_txs=5"); ok(m && m->nitems == 1 && streq(S(m->items[0], "txid"), "4444444444444444444444444444444444444444444444444444444444444444"), "GET /internal/mempool/txs -> full transactions"); rj_free(m); }
    { rj_val* m = POST("/internal/txs", "[\"" TX2 "\",\"" TX1 "\"]"); ok(m && m->nitems == 1 && streq(S(m->items[0], "txid"), TX2), "POST /internal/txs -> the known ones"); rj_free(m); }
    { rj_val* m = POST("/internal/txs/outspends/by-txid", "[\"" TX2 "\"]"); ok(m && m->nitems == 1 && m->items[0]->nitems == 2, "POST /internal/txs/outspends/by-txid"); rj_free(m); }
    POST("/tx", "0200aa\n"); ok(g_status == 200 && streq(g_out, "4444444444444444444444444444444444444444444444444444444444444444"), "POST /tx broadcasts and returns the txid");
    POST("/tx", "bad"); ok(g_status == 400, "POST /tx with a rejected tx -> 400 with the node's reason");
    GET("/address/bc1qtest"); ok(g_status == 501, "GET /address/... -> 501 until the history index (stage 2)");
    GET("/nothing/here"); ok(g_status == 404, "an unknown route -> 404");
    /* a response over 1 MiB: the writer reports the needed length, the reply must grow (found live: garbage after the first MiB) */
    { g_big = 1; rj_val* m = POST("/internal/txs", "[\"" TX2 "\"]"); g_big = 0;
      ok(m && m->nitems == 1 && g_outlen > (1u << 20) && g_out[g_outlen - 1] == ']', "a >1 MiB response is complete and well-formed"); rj_free(m); }
    free(g_out);
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
