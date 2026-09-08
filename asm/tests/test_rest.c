/* tests/test_rest.c -- Core's REST interface (rest.c) against a fake RPC
 * dispatch: every route, the three formats, Core's error texts and status
 * codes from src/rest.cpp. The differential proof against Core's own /rest/
 * is validation/rest_regtest_diff.sh. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../rest.h"
#include "../rpc_json.h"
static int fails = 0, checks = 0;
static void ok(int c, const char* w){ checks++; printf("  %s %s\n", c ? "ok " : "FAIL", w); if (!c) fails++; }
#define BH  "000000000000000000029c2a5a3b6b1d2e0d0c0b0a090807060504030201000f"
#define BH2 "00000000000000000002aaaa5a3b6b1d2e0d0c0b0a090807060504030201000f"
#define TX1 "1111111111111111111111111111111111111111111111111111111111111111"
#define TX2 "2222222222222222222222222222222222222222222222222222222222222222"
static rj_val* J(const char* s){ return rj_parse(s, strlen(s)); }
static int g_filter_index = 1; static int g_undo = 1; static int g_calls = 0;
int rpc_dispatch(const char* method, const rj_val* params, const rpc_wallet* w, rj_val** result, long* ec, const char** em){
    (void)w; g_calls++;
    const char* p0 = params && params->typ == RJ_ARR && params->nitems ? params->items[0]->str : 0;
    const char* p1s = params && params->nitems > 1 ? params->items[1]->str : 0; long p1 = p1s ? strtol(p1s, 0, 10) : -1;
    if (!strcmp(method, "getblockchaininfo")){ *result = J("{\"chain\":\"main\",\"blocks\":700000,\"headers\":700000,\"bestblockhash\":\"" BH2 "\"}"); return 1; }
    if (!strcmp(method, "getblockhash")){ if (p0 && !strcmp(p0, "699999")){ *result = rj_str(BH); return 1; } if (p0 && !strcmp(p0, "700000")){ *result = rj_str(BH2); return 1; } *ec = -8; *em = "Block height out of range"; return 0; }
    if (!strcmp(method, "getblockheader")){
        int verbose = !(params->nitems > 1 && params->items[1]->typ == RJ_BOOL && params->items[1]->str[0] == '0');
        if (p0 && !strcmp(p0, BH)){ if (!verbose){ *result = rj_str("00e0ff2f" "aa"); return 1; }
            *result = J("{\"hash\":\"" BH "\",\"confirmations\":2,\"height\":699999,\"version\":536870912,\"versionHex\":\"20000000\",\"merkleroot\":\"" TX1 "\",\"time\":1631000000,\"mediantime\":1630999000,\"nonce\":42,\"bits\":\"1703a30c\",\"difficulty\":1.0,\"chainwork\":\"00\",\"nTx\":2,\"previousblockhash\":\"" TX2 "\",\"nextblockhash\":\"" BH2 "\"}"); return 1; }
        if (p0 && !strcmp(p0, BH2)){ *result = J("{\"hash\":\"" BH2 "\",\"confirmations\":1,\"height\":700000,\"version\":536870912,\"versionHex\":\"20000000\",\"merkleroot\":\"" TX2 "\",\"time\":1631000600,\"mediantime\":1631000000,\"nonce\":43,\"bits\":\"1703a30c\",\"difficulty\":1.0,\"chainwork\":\"00\",\"nTx\":1,\"previousblockhash\":\"" BH "\"}"); return 1; }
        *ec = -5; *em = "Block not found"; return 0; }
    if (!strcmp(method, "getblock")){
        if (!p0 || strcmp(p0, BH)){ *ec = -5; *em = "Block not found"; return 0; }
        if (p1 == 0){ *result = rj_str("0102030405060708"); return 1; }
        if (p1 == 1){ *result = J("{\"hash\":\"" BH "\",\"confirmations\":2,\"height\":699999,\"tx\":[\"" TX1 "\",\"" TX2 "\"]}"); return 1; }
        char b[2048]; snprintf(b, sizeof b, "{\"hash\":\"" BH "\",\"confirmations\":2,\"height\":699999,\"tx\":[{\"txid\":\"" TX1 "\",\"vin\":[{\"coinbase\":\"03\"}],\"vout\":[]},{\"txid\":\"" TX2 "\",\"vin\":[{\"txid\":\"" TX1 "\",\"vout\":0%s}],\"vout\":[]}]}",
            g_undo ? ",\"prevout\":{\"generated\":true,\"height\":100,\"value\":0.50000000,\"scriptPubKey\":{\"asm\":\"OP_DUP\",\"desc\":\"addr(1x)#00\",\"hex\":\"76a9\",\"address\":\"1x\",\"type\":\"pubkeyhash\"}}" : "");
        *result = J(b); return 1; }
    if (!strcmp(method, "getrawtransaction")){
        if (!p0 || strcmp(p0, TX2)){ *ec = -5; *em = "No such mempool or blockchain transaction. Use gettransaction for wallet transactions."; return 0; }
        if (p1 == 0){ *result = rj_str("0200aabb"); return 1; }
        *result = J("{\"in_active_chain\":true,\"txid\":\"" TX2 "\",\"hash\":\"" TX2 "\",\"version\":2,\"size\":4,\"vsize\":4,\"weight\":16,\"locktime\":0,\"vin\":[],\"vout\":[],\"hex\":\"0200aabb\",\"blockhash\":\"" BH "\",\"confirmations\":2,\"blocktime\":1631000000,\"time\":1631000000}"); return 1; }
    if (!strcmp(method, "gettxout")){
        int mp = params->nitems > 2 && params->items[2]->typ == RJ_BOOL && params->items[2]->str[0] == '1';
        if (p0 && !strcmp(p0, TX2) && p1 == 0){ *result = J("{\"bestblock\":\"" BH2 "\",\"confirmations\":2,\"value\":0.03611917,\"scriptPubKey\":{\"asm\":\"0 aabb\",\"desc\":\"addr(bc1q)#00\",\"hex\":\"0014aabb\",\"address\":\"bc1q\",\"type\":\"witness_v0_keyhash\"},\"coinbase\":false}"); return 1; }
        if (mp && p0 && !strcmp(p0, TX1) && p1 == 1){ *result = J("{\"bestblock\":\"" BH2 "\",\"confirmations\":0,\"value\":1.00000000,\"scriptPubKey\":{\"asm\":\"\",\"desc\":\"raw(51)#00\",\"hex\":\"51\",\"type\":\"nonstandard\"},\"coinbase\":false}"); return 1; }
        *result = rj_null(); return 1; }
    if (!strcmp(method, "getmempoolinfo")){ *result = J("{\"loaded\":true,\"size\":1,\"bytes\":110}"); return 1; }
    if (!strcmp(method, "getrawmempool")){ if (p0 && p0[0] == '1'){ *result = J("{\"" TX2 "\":{\"vsize\":110}}"); return 1; } *result = J("[\"" TX2 "\"]"); return 1; }
    if (!strcmp(method, "getdeploymentinfo")){ *result = J(p0 ? "{\"hash\":\"" BH "\",\"height\":699999,\"deployments\":{}}" : "{\"hash\":\"" BH2 "\",\"height\":700000,\"deployments\":{}}"); return 1; }
    if (!strcmp(method, "getblockfilter")){ if (!g_filter_index){ *ec = -1; *em = "Index is not enabled for filtertype basic"; return 0; }
        if (p0 && !strcmp(p0, BH)){ *result = J("{\"filter\":\"0189aabb\",\"header\":\"" TX1 "\"}"); return 1; }
        if (p0 && !strcmp(p0, BH2)){ *result = J("{\"filter\":\"01cc\",\"header\":\"" TX2 "\"}"); return 1; }
        *ec = -5; *em = "Block not found"; return 0; }
    *ec = -32601; *em = "Method not found"; return 0;
}
static char* g_out; static size_t g_outlen; static int g_status; static const char* g_ctype;
static void REQ(const char* method, const char* path, const char* body, size_t blen){ free(g_out); g_out = 0; rest_handle(method, strlen(method), path, strlen(path), body, blen, 0, &g_out, &g_outlen, &g_status, &g_ctype); }
static void GET(const char* path){ REQ("GET", path, "", 0); }
static int body_is(const char* s){ return g_out && g_outlen == strlen(s) && !memcmp(g_out, s, g_outlen); }
static int err_is(int st, const char* msg){ char b[600]; snprintf(b, sizeof b, "%s\r\n", msg); return g_status == st && !strcmp(g_ctype, "text/plain") && body_is(b); }
static rj_val* JSON(void){ return g_status == 200 && !strcmp(g_ctype, "application/json") && g_outlen && g_out[g_outlen-1] == '\n' ? rj_parse(g_out, g_outlen - 1) : 0; }
static const char* S(const rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o, k) : 0; return v && v->str ? v->str : ""; }
int main(void){
    printf("---- rest ----\n");
    ok(rest_is_path("/rest/tx/x", 10) && !rest_is_path("/", 1) && !rest_is_path("/restful", 8), "rest_is_path: the /rest/ prefix only");
    /* tx */
    GET("/rest/tx/" TX2 ".json"); { rj_val* t = JSON(); ok(t && !strcmp(S(t, "txid"), TX2) && !rj_obj_get(t, "confirmations") && !rj_obj_get(t, "in_active_chain") && !rj_obj_get(t, "time") && !strcmp(S(t, "blockhash"), BH) && t->members[0].key[0] == 't', "tx.json: TxToUniv's fields (txid first, blockhash kept, confirmations/time/in_active_chain dropped)"); if (t) rj_free(t); }
    GET("/rest/tx/" TX2 ".hex"); ok(g_status == 200 && !strcmp(g_ctype, "text/plain") && body_is("0200aabb\n"), "tx.hex: the raw hex + newline");
    GET("/rest/tx/" TX2 ".bin"); ok(g_status == 200 && !strcmp(g_ctype, "application/octet-stream") && g_outlen == 4 && !memcmp(g_out, "\x02\x00\xaa\xbb", 4), "tx.bin: the raw bytes");
    GET("/rest/tx/" TX2); ok(err_is(404, "output format not found (available: .bin, .hex, .json)"), "tx without a suffix: Core's 404 text");
    GET("/rest/tx/" TX2 ".xml"); ok(err_is(400, "Invalid hash: " TX2 ".xml"), "tx with an unknown suffix: the suffix stays on the hash and the hash check fires first (Core's order)");
    GET("/rest/tx/" TX1 ".json"); ok(err_is(404, TX1 " not found"), "tx unknown: 404 '<hash> not found'");
    GET("/rest/tx/zz.json"); ok(err_is(400, "Invalid hash: zz"), "tx bad hash: 400 'Invalid hash: zz'");
    /* block */
    GET("/rest/block/" BH ".json"); { rj_val* b = JSON(); rj_val* tx = b ? rj_obj_get(b, "tx") : 0; ok(b && tx && tx->nitems == 2 && rj_obj_get(tx->items[1], "vin") && rj_obj_get(rj_obj_get(tx->items[1], "vin")->items[0], "prevout"), "block.json: getblock verbosity 3 (details and prevouts)"); if (b) rj_free(b); }
    GET("/rest/block/notxdetails/" BH ".json"); { rj_val* b = JSON(); rj_val* tx = b ? rj_obj_get(b, "tx") : 0; ok(b && tx && tx->nitems == 2 && tx->items[0]->typ == RJ_STR, "block/notxdetails.json: verbosity 1 (txids)"); if (b) rj_free(b); }
    GET("/rest/block/" BH ".hex"); ok(body_is("0102030405060708\n"), "block.hex");
    GET("/rest/block/" BH ".bin"); ok(g_outlen == 8 && g_out[0] == 1 && g_out[7] == 8, "block.bin");
    GET("/rest/block/" BH2 ".json"); ok(err_is(404, BH2 " not found"), "block unknown: 404 '<hash> not found'");
    GET("/rest/block/" BH); ok(err_is(404, "output format not found (available: .bin, .hex, .json)"), "block without a suffix");
    /* blockpart */
    GET("/rest/blockpart/" BH ".bin?offset=2&size=3"); ok(g_status == 200 && g_outlen == 3 && g_out[0] == 3 && g_out[2] == 5, "blockpart.bin: bytes [offset, offset+size)");
    GET("/rest/blockpart/" BH ".hex?offset=6&size=2"); ok(body_is("0708\n"), "blockpart.hex");
    GET("/rest/blockpart/" BH ".bin?offset=6&size=3"); ok(err_is(400, "Bad block part offset/size 6/3 for " BH), "blockpart past the end: Core's 400");
    GET("/rest/blockpart/" BH ".bin?size=3"); ok(err_is(400, "Block part offset missing or invalid"), "blockpart without offset");
    GET("/rest/blockpart/" BH ".bin?offset=1"); ok(err_is(400, "Block part size missing or invalid"), "blockpart without size");
    GET("/rest/blockpart/" BH ".json?offset=0&size=1"); ok(err_is(400, "JSON output is not supported for this request type"), "blockpart.json refused");
    /* headers */
    GET("/rest/headers/" BH ".json?count=2"); { rj_val* a = JSON(); ok(a && a->typ == RJ_ARR && a->nitems == 2 && !strcmp(S(a->items[1], "hash"), BH2), "headers.json?count=2: the walk along nextblockhash"); if (a) rj_free(a); }
    GET("/rest/headers/" BH ".json"); { rj_val* a = JSON(); ok(a && a->nitems == 2, "headers.json: count defaults to 5, the chain ends after 2"); if (a) rj_free(a); }
    GET("/rest/headers/1/" BH ".json"); { rj_val* a = JSON(); ok(a && a->nitems == 1, "headers/<count>/<hash>: the deprecated path form"); if (a) rj_free(a); }
    GET("/rest/headers/" BH ".bin?count=1"); { unsigned char want[80] = {0}; want[0] = 0; want[1] = 0; want[2] = 0; want[3] = 0x20; ok(g_status == 200 && g_outlen == 80 && !memcmp(g_out, want, 4) && (unsigned char)g_out[4] == 0x22 && (unsigned char)g_out[36] == 0x11 && (unsigned char)g_out[72] == 0x0c && (unsigned char)g_out[75] == 0x17 && (unsigned char)g_out[76] == 42, "headers.bin: 80 bytes rebuilt from the verbose header (version LE, prev and merkle internal order, bits LE, nonce)"); }
    GET("/rest/headers/" BH ".hex?count=1"); ok(g_status == 200 && g_outlen == 161 && g_out[160] == '\n' && !memcmp(g_out, "00000020", 8), "headers.hex");
    GET("/rest/headers/" TX1 ".json"); { rj_val* a = JSON(); ok(a && a->typ == RJ_ARR && a->nitems == 0, "headers from an unknown hash: an empty list, 200 (Core)"); if (a) rj_free(a); }
    GET("/rest/headers/" BH ".json?count=0"); ok(err_is(400, "Header count is invalid or out of acceptable range (1-2000): 0"), "headers count 0");
    GET("/rest/headers/" BH ".json?count=2001"); ok(err_is(400, "Header count is invalid or out of acceptable range (1-2000): 2001"), "headers count 2001");
    GET("/rest/headers/" BH ".json?count=x"); ok(err_is(400, "Header count is invalid or out of acceptable range (1-2000): x"), "headers count x");
    GET("/rest/headers/a/b/c.json"); ok(err_is(400, "Invalid URI format. Expected /rest/headers/<hash>.<ext>?count=<count>"), "headers with three parts");
    GET("/rest/headers/zz.json"); ok(err_is(400, "Invalid hash: zz"), "headers bad hash");
    /* blockhashbyheight */
    GET("/rest/blockhashbyheight/699999.json"); { rj_val* o = JSON(); ok(o && !strcmp(S(o, "blockhash"), BH), "blockhashbyheight.json"); if (o) rj_free(o); }
    GET("/rest/blockhashbyheight/699999.hex"); ok(body_is(BH "\n"), "blockhashbyheight.hex");
    GET("/rest/blockhashbyheight/699999.bin"); ok(g_status == 200 && g_outlen == 32 && (unsigned char)g_out[0] == 0x0f && (unsigned char)g_out[31] == 0x00, "blockhashbyheight.bin: internal byte order");
    GET("/rest/blockhashbyheight/700001.json"); ok(err_is(404, "Block height out of range"), "blockhashbyheight past the tip");
    GET("/rest/blockhashbyheight/-1.json"); ok(err_is(400, "Invalid height: -1"), "blockhashbyheight -1");
    GET("/rest/blockhashbyheight/abc.json"); ok(err_is(400, "Invalid height: abc"), "blockhashbyheight abc");
    /* chaininfo, deploymentinfo, mempool */
    GET("/rest/chaininfo.json"); { rj_val* o = JSON(); ok(o && !strcmp(S(o, "chain"), "main"), "chaininfo.json = getblockchaininfo"); if (o) rj_free(o); }
    GET("/rest/chaininfo.hex"); ok(err_is(404, "output format not found (available: json)"), "chaininfo.hex: json only");
    GET("/rest/deploymentinfo.json"); { rj_val* o = JSON(); ok(o && !strcmp(S(o, "hash"), BH2), "deploymentinfo.json (the tip)"); if (o) rj_free(o); }
    GET("/rest/deploymentinfo/" BH ".json"); { rj_val* o = JSON(); ok(o && !strcmp(S(o, "hash"), BH), "deploymentinfo/<hash>.json"); if (o) rj_free(o); }
    GET("/rest/deploymentinfo/" TX1 ".json"); ok(err_is(400, "Block not found"), "deploymentinfo unknown hash: 400 'Block not found'");
    GET("/rest/mempool/info.json"); { rj_val* o = JSON(); ok(o && !strcmp(S(o, "size"), "1"), "mempool/info.json = getmempoolinfo"); if (o) rj_free(o); }
    GET("/rest/mempool/contents.json"); { rj_val* o = JSON(); ok(o && o->typ == RJ_OBJ && rj_obj_get(o, TX2), "mempool/contents.json: verbose by default"); if (o) rj_free(o); }
    GET("/rest/mempool/contents.json?verbose=false"); { rj_val* o = JSON(); ok(o && o->typ == RJ_ARR && o->nitems == 1, "mempool/contents.json?verbose=false: txids"); if (o) rj_free(o); }
    GET("/rest/mempool/contents.json?verbose=maybe"); ok(err_is(400, "The \"verbose\" query parameter must be either \"true\" or \"false\"."), "mempool contents bad verbose");
    GET("/rest/mempool/contents.json?mempool_sequence=true"); ok(err_is(400, "Verbose results cannot contain mempool sequence values. (hint: set \"verbose=false\")"), "mempool contents: verbose + sequence refused as Core does");
    GET("/rest/mempool/contents.json?verbose=false&mempool_sequence=true"); ok(g_status == 400 && strstr(g_out, "mempool_sequence is not available"), "mempool_sequence: an explicit refusal (no sequence counter on this node)");
    GET("/rest/mempool/other.json"); ok(err_is(400, "Invalid URI format. Expected /rest/mempool/<info|contents>.json"), "mempool other");
    GET("/rest/mempool/info.hex"); ok(err_is(404, "output format not found (available: json)"), "mempool info.hex");
    /* blockfilter */
    GET("/rest/blockfilter/basic/" BH ".json"); { rj_val* o = JSON(); ok(o && !strcmp(S(o, "filter"), "0189aabb"), "blockfilter.json"); if (o) rj_free(o); }
    GET("/rest/blockfilter/basic/" BH ".hex"); { char want[200]; snprintf(want, sizeof want, "00%s040189aabb\n", "0f00010203040506070809000000000000000000000000000000000000000000"); /* type, hash internal order, compactsize 4, filter */
        char got[200]; snprintf(got, sizeof got, "%.*s", (int)g_outlen, g_out); ok(g_status == 200 && !memcmp(g_out, "00", 2) && (unsigned char)g_out[2] == '0' && (unsigned char)g_out[3] == 'f' && !strcmp(g_out + 66, "040189aabb\n"), "blockfilter.hex: type byte, block hash (internal order), compactsize length, filter bytes"); (void)want; (void)got; }
    GET("/rest/blockfilter/basic/" BH ".bin"); ok(g_status == 200 && g_outlen == 1 + 32 + 1 + 4 && g_out[0] == 0 && (unsigned char)g_out[1] == 0x0f && g_out[33] == 4 && (unsigned char)g_out[34] == 0x01, "blockfilter.bin");
    GET("/rest/blockfilter/fancy/" BH ".json"); ok(err_is(400, "Unknown filtertype fancy"), "blockfilter unknown type");
    GET("/rest/blockfilter/basic/" TX1 ".json"); ok(err_is(404, TX1 " not found"), "blockfilter unknown block");
    GET("/rest/blockfilter/basic.json"); ok(err_is(400, "Invalid URI format. Expected /rest/blockfilter/<filtertype>/<blockhash>"), "blockfilter one part");
    g_filter_index = 0; GET("/rest/blockfilter/basic/" BH ".json"); ok(err_is(400, "Index is not enabled for filtertype basic"), "blockfilter without the index: Core's 400"); g_filter_index = 1;
    GET("/rest/blockfilterheaders/basic/" BH ".json?count=2"); { rj_val* a = JSON(); ok(a && a->nitems == 2 && !strcmp(a->items[0]->str, TX1) && !strcmp(a->items[1]->str, TX2), "blockfilterheaders.json: the walk, one header per block"); if (a) rj_free(a); }
    GET("/rest/blockfilterheaders/basic/2/" BH ".bin"); ok(g_status == 200 && g_outlen == 64 && (unsigned char)g_out[0] == 0x11 && (unsigned char)g_out[32] == 0x22, "blockfilterheaders/<type>/<count>/<hash>.bin: 32 bytes each, internal order");
    GET("/rest/blockfilterheaders/basic/" BH ".hex?count=1"); ok(body_is(TX1 "\n"), "blockfilterheaders.hex (a palindromic hash reads the same reversed)");
    GET("/rest/blockfilterheaders/" BH ".json"); ok(err_is(400, "Invalid URI format. Expected /rest/blockfilterheaders/<filtertype>/<blockhash>.<ext>?count=<count>"), "blockfilterheaders without a type");
    /* spenttxouts */
    GET("/rest/spenttxouts/" BH ".json"); { rj_val* a = JSON(); ok(a && a->typ == RJ_ARR && a->nitems == 2 && a->items[0]->nitems == 0 && a->items[1]->nitems == 1 && !strcmp(S(a->items[1]->items[0], "value"), "0.50000000") && !strcmp(S(rj_obj_get(a->items[1]->items[0], "scriptPubKey"), "hex"), "76a9"), "spenttxouts.json: [] for the coinbase, then each input's prevout {value, scriptPubKey}"); if (a) rj_free(a); }
    GET("/rest/spenttxouts/" BH ".hex"); ok(body_is("02" "00" "01" "80f0fa0200000000" "02" "76a9" "\n"), "spenttxouts.hex: compactsize(2), 0 for the coinbase, 1 prevout: int64 sats, script");
    GET("/rest/spenttxouts/" BH ".bin"); ok(g_status == 200 && g_outlen == 1 + 1 + 1 + 8 + 1 + 2, "spenttxouts.bin");
    g_undo = 0; GET("/rest/spenttxouts/" BH ".json"); ok(err_is(404, BH " undo not available"), "spenttxouts without undo data: 404 '<hash> undo not available'"); g_undo = 1;
    GET("/rest/spenttxouts/" TX1 ".json"); ok(err_is(404, TX1 " not found"), "spenttxouts unknown block");
    /* getutxos */
    GET("/rest/getutxos/" TX2 "-0/" TX1 "-1.json"); { rj_val* o = JSON(); rj_val* u = o ? rj_obj_get(o, "utxos") : 0;
        ok(o && !strcmp(S(o, "chainHeight"), "700000") && !strcmp(S(o, "chaintipHash"), BH2) && !strcmp(S(o, "bitmap"), "10") && u && u->nitems == 1 && !strcmp(S(u->items[0], "height"), "699999") && !strcmp(S(u->items[0], "value"), "0.03611917") && !strcmp(S(rj_obj_get(u->items[0], "scriptPubKey"), "type"), "witness_v0_keyhash"), "getutxos.json: chainHeight, tip, bitmap '10', the hit's height = chain height - confirmations + 1"); if (o) rj_free(o); }
    GET("/rest/getutxos/checkmempool/" TX2 "-0/" TX1 "-1.json"); { rj_val* o = JSON(); rj_val* u = o ? rj_obj_get(o, "utxos") : 0; ok(o && !strcmp(S(o, "bitmap"), "11") && u && u->nitems == 2 && !strcmp(S(u->items[1], "height"), "2147483647"), "getutxos/checkmempool: the mempool output too, at MEMPOOL_HEIGHT"); if (o) rj_free(o); }
    GET("/rest/getutxos/" TX2 "-0.hex"); ok(g_status == 200 && !memcmp(g_out, "60ae0a00", 8) && g_out[g_outlen-1] == '\n', "getutxos.hex: int32 height 700000 = 0xaae60, LE first");
    GET("/rest/getutxos/" TX2 "-0.bin"); ok(g_status == 200 && g_outlen == 4 + 32 + 1 + 1 + 1 + (4 + 4 + 8 + 1 + 4) && g_out[36] == 1 && g_out[37] == 1 && g_out[38] == 1, "getutxos.bin: height, tip, bitmap (1 byte), 1 coin: dummy, height, value, script");
    { /* Core reads the body's first byte as the outpoint count (its checkmempool
       * flag comes from the length prefix, so any body checks the mempool) */
      unsigned char body[1 + 36]; body[0] = 1; for (int i = 0; i < 32; i++) body[1 + i] = 0x22; body[33] = 0; body[34] = 0; body[35] = 0; body[36] = 0;
      REQ("POST", "/rest/getutxos.bin", (const char*)body, sizeof body); ok(g_status == 200 && g_outlen == 4 + 32 + 1 + 1 + 1 + 21 && g_out[37] == 1, "getutxos.bin with a POST body: count + vector<COutPoint>, as Core's parse reads it"); }
    { unsigned char body[1 + 36]; body[0] = 1; for (int i = 0; i < 32; i++) body[1 + i] = 0x11; body[33] = 1; body[34] = 0; body[35] = 0; body[36] = 0;
      REQ("POST", "/rest/getutxos.bin", (const char*)body, sizeof body); ok(g_status == 200 && g_out[37] == 1, "...and any body checks the mempool (Core's length-prefix quirk): the mempool output is a hit"); }
    REQ("POST", "/rest/getutxos.hex", "01" "2222222222222222222222222222222222222222222222222222222222222222" "00000000", 2 + 64 + 8); ok(g_status == 200 && !memcmp(g_out, "60ae0a00", 8), "getutxos.hex with a hex POST body");
    REQ("POST", "/rest/getutxos.bin", "\x02\x00", 2); ok(err_is(400, "Parse error"), "a short outpoint vector is 'Parse error'");
    REQ("POST", "/rest/getutxos/" TX2 "-0.bin", "\x00\x01", 2); ok(err_is(400, "Combination of URI scheme inputs and raw post data is not allowed"), "getutxos: URI outpoints plus a body is refused");
    GET("/rest/getutxos.json"); ok(err_is(400, "Error: empty request"), "getutxos.json with nothing");
    GET("/rest/getutxos/" TX2 "-0-1.json"); ok(err_is(400, "Parse error"), "getutxos: a bad outpoint is 'Parse error'");
    GET("/rest/getutxos/zz-0.json"); ok(err_is(400, "Parse error"), "getutxos: a bad txid is 'Parse error'");
    { char path[2048] = "/rest/getutxos"; for (int i = 0; i < 16; i++){ strcat(path, "/" TX2 "-"); char n[8]; snprintf(n, sizeof n, "%d", i); strcat(path, n); } strcat(path, ".json");
      GET(path); ok(err_is(400, "Error: max outpoints exceeded (max: 15, tried: 16)"), "getutxos: 16 outpoints exceed Core's 15"); }
    GET("/rest/getutxos/" TX2 "-0"); ok(err_is(404, "output format not found (available: .bin, .hex, .json)"), "getutxos without a suffix");
    /* the dispatcher */
    GET("/rest/nothing/here"); ok(g_status == 404 && g_outlen == 0, "an unknown /rest/ path: a bare 404");
    GET("/rest/block/notxdetails/" BH ".hex"); ok(body_is("0102030405060708\n"), "the longer prefix wins (block/notxdetails before block/)");
    printf("%s: %d checks, %d failure(s)\n", fails ? "FAILED" : "PASS", checks, fails);
    return fails ? 1 : 0;
}
