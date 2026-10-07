/* test_rpc_esplora.c -- the Esplora facade's routes and reshaping, driven by
 * a canned rpc_dispatch (this file defines it), so every route is exercised
 * without a node: the JSON that Core-shaped handlers return is fixed here
 * and the Esplora JSON the facade must produce is asserted field by field. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../rpc_esplora.h"
#include "../rpc_json.h"
#include "../rpc_node.h"           /* rpc_mp_item, for the batched mempool read */
static int fails = 0, checks = 0;
static void ok(int c, const char* w){ checks++; printf("  %s %s\n", c ? "ok " : "FAIL", w); if (!c) fails++; }
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);

/* ---- the canned node ------------------------------------------------------- */
#define BH "000000000000000000029c2a5a3b6b1d2e0d0c0b0a090807060504030201000f"
#define TX1 "1111111111111111111111111111111111111111111111111111111111111111"
#define TX2 "2222222222222222222222222222222222222222222222222222222222222222"
#define TX3 "3333333333333333333333333333333333333333333333333333333333333333"
static const char* S(const rj_val* o, const char* k);
static int g_spender_index = 1; static int g_calls_gettxout = 0; static int g_big = 0;
/* ---- the address routes' sources, canned ---------------------------------- */
#include "../daemon/addr_hist_fmt.h"
#include "../daemon/addr_index_fmt.h"
static const unsigned char KEY_A[20] = {0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11};
int wallet_validate_address(const char* addr, int* type, unsigned char* ver, unsigned char h160[20], unsigned char prog[32]){
    (void)ver; (void)prog; if (!strcmp(addr, "bc1qaddrA")){ *type = 2; memcpy(h160, KEY_A, 20); return 1; } return 0;
}
static int g_tail_on = 0, g_tail_add_only = 0, g_mp_on = 0;
/* ---- the facade's batched mempool read (2026-10-01) ----
 * Strong definitions of the two helpers rpc_esplora.c references weakly. Off
 * (the default) the batch returns -1 and the facade takes the per-transaction
 * path, so every other case here is unchanged. "Raw bytes" are the txid's own
 * 64 characters; decoderawtransaction below maps them back to the JSON. */
static int g_batch_on = 0, g_pool_takes = 0;
static const char* MPX[] = { "4444444444444444444444444444444444444444444444444444444444444444",
                             "6666666666666666666666666666666666666666666666666666666666666666",
                             "7777777777777777777777777777777777777777777777777777777777777777" };
long rpc_node_mempool_many(const unsigned char (*w)[32], long n, rpc_mp_item* out){
    if (!g_batch_on) return -1;
    g_pool_takes += (int)((n + 255) / 256);                 /* one pool-lock hold per slice */
    long found = 0;
    for (long i = 0; i < n; i++){
        char d[65]; for (int b = 0; b < 32; b++) snprintf(d + 2*b, 3, "%02x", w[i][31 - b]);
        out[i].present = 0; out[i].raw = 0; out[i].len = 0; out[i].fee = 0;
        for (int k = 0; k < 3; k++) if (!strcmp(d, MPX[k])){
            out[i].raw = (unsigned char*)malloc(64); memcpy(out[i].raw, d, 64); out[i].len = 64;
            out[i].present = 1; out[i].fee = 500; found++; }
    }
    return found;
}
/* The index lookup must run under the facade's execution lock (2026-10-03):
 * rpc_chain's txid-index run set is rewritten in place by irs_refresh, and an
 * unlocked lookup racing getrawtransaction read a NULL map -- production
 * segfaulted on it eleven times. Count the calls made without the lock. */
static int g_idx_calls = 0, g_idx_unlocked = 0;
static int g_locks, g_unlocks;
/* 2026-10-05: the lookup runs in rpc_chain's txindex LANE (its own mutex
 * guards irs_refresh), so the batch must call the _many form ONCE with NO
 * execution lock held -- taking the exclusive lock per parent was the convoy
 * production logged for two days. g_idx_unlocked now counts the opposite
 * fault: a lookup made WITH the execution lock held. */
static int g_many_calls = 0;
int rpc_chain_tx_blockhash(const char* t, char out[65]){
    if (!g_batch_on) return 0;
    g_idx_calls++;
    if (!strcmp(t, TX2) || !strcmp(t, TX3) || !strcmp(t, "5555555555555555555555555555555555555555555555555555555555555555")){
        snprintf(out, 65, "%s", BH); return 1; }
    out[0] = 0; return 0;
}
long rpc_chain_tx_blockhash_many(const char* const* ids, long n, char (*out)[65]){
    g_many_calls++; if (g_locks - g_unlocks != 0) g_idx_unlocked++;
    long hits = 0;
    for (long i = 0; i < n; i++){ out[i][0] = 0; hits += rpc_chain_tx_blockhash(ids[i], out[i]); }
    return hits;
}
long axt_read_events(int type, const unsigned char hash[32], long min_height,
                     int (*cb)(void*, int, const unsigned char*, unsigned, unsigned long long, unsigned), void* ctx){
    if (!(g_tail_on || g_tail_add_only) || type != 2 || memcmp(hash, KEY_A, 20)) return 0;
    unsigned char t3[32]; memset(t3, 0x55, 32); unsigned char t4[32]; memset(t4, 0x44, 32);
    long n = 0;
    /* height 700001: tx 0x55.. funds A with 700 sats (ADD); height 700002: tx 0x44.. spends it (DEL of 0x55:0, TOUCH 0x44) */
    if (700001 > min_height){ if (cb && !cb(ctx, AXF_OP_ADD, t3, 0, 700, 700001)) return n; n++; }
    if (700002 > min_height && !g_tail_add_only){ if (cb && !cb(ctx, AXF_OP_DEL, t3, 0, 700, 700002)) return n; n++; if (cb && !cb(ctx, AXF_OP_TOUCH, t4, 0, 0, 700002)) return n; n++; }
    return n;
}
/* a base with one key (A): FUND at 700000/txpos 1 (TX2, 3611917), SPEND at 700000/txpos 2 (TX3 spends it, value 3611917) */
static void write_base(void){
    FILE* f = fopen(AH_FILE, "wb"); ah_header hd; memset(&hd, 0, sizeof hd); hd.magic = AH_MAGIC; hd.version = AH_VERSION; hd.to_height = 700000; hd.body_off = AH_HDR_BYTES;
    unsigned char zero[AH_HDR_BYTES] = {0}; fwrite(zero, 1, AH_HDR_BYTES, f);
    ah_group_hdr g; g.type = 2; memset(g.hash, 0, 32); memcpy(g.hash, KEY_A, 20); g.n = 2; fwrite(&g, 1, AH_GROUP_HDR, f);
    ah_event e1 = { AH_FUND, 700000, 1, 0, 3611917 }; ah_event e2 = { AH_SPEND, 700000, 2, 0, 3611917 }; fwrite(&e1, 1, AH_EVENT_BYTES, f); fwrite(&e2, 1, AH_EVENT_BYTES, f);
    hd.n_keys = 1; hd.n_events = 2; hd.body_len = AH_GROUP_HDR + 2 * AH_EVENT_BYTES; hd.sparse_off = AH_HDR_BYTES + hd.body_len; hd.sparse_n = 1;
    ah_sparse sp; sp.type = 2; memcpy(sp.hash, g.hash, 32); sp.off = 0; fwrite(&sp, AH_SPARSE_BYTES, 1, f);
    fseek(f, 0, SEEK_SET); fwrite(&hd, 1, sizeof hd, f); fclose(f);
}
static rj_val* J(const char* lit){ return rj_parse(lit, strlen(lit)); }
static void tlock(void){ g_locks++; } static void tunlock(void){ g_unlocks++; }
int rpc_dispatch(const char* method, const rj_val* params, const rpc_wallet* w, rj_val** result, long* ec, const char** em){
    (void)w; const char* p0 = params && params->typ == RJ_ARR && params->nitems ? params->items[0]->str : 0;
    long p1 = params && params->nitems > 1 && params->items[1]->str ? strtol(params->items[1]->str, 0, 10) : -1;
    if (!strcmp(method, "estimatesmartfee")){
        /* BTC/kvB, as Core reports it. Targets 1..6 and 144 answer; everything
         * else has "no answer", which the route must OMIT rather than send as
         * zero -- a zero feerate is a claim that a transaction pays nothing. */
        long t = p0 ? strtol(p0, 0, 10) : 0;
        if (t == 1)        { *result = J("{\"feerate\":0.00012500,\"blocks\":1}");  return 1; }
        if (t == 2)        { *result = J("{\"feerate\":0.00010100,\"blocks\":2}");  return 1; }
        if (t >= 3 && t <= 6){ *result = J("{\"feerate\":0.00002000,\"blocks\":6}"); return 1; }
        if (t == 144)      { *result = J("{\"feerate\":0.00001000,\"blocks\":144}"); return 1; }
        /* a target that answers with a ZERO feerate. Distinct from "no answer"
         * above: the field is PRESENT, so only the value check can reject it.
         * Without this case the omission rule is enforced by the missing-field
         * guard alone and a reintroduction of the zero passes unnoticed. */
        if (t == 7)        { *result = J("{\"feerate\":0.00000000,\"blocks\":7}");   return 1; }
        *result = J("{\"errors\":[\"Insufficient data or no feerate found\"],\"blocks\":0}"); return 1; }
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
    if (!strcmp(method, "decoderawtransaction")){
        /* the batch's decode: the "raw bytes" are a txid's characters, hex-encoded */
        char id[65] = ""; if (p0 && strlen(p0) == 128){ for (int b = 0; b < 64; b++){ unsigned v; sscanf(p0 + 2*b, "%2x", &v); id[b] = (char)v; } id[64] = 0; }
        /* a third argument: the real decode touches no pool, so this re-entry is not counted as a take */
        rj_val* a = rj_arr(); rj_arr_push(a, rj_str(id)); rj_arr_push(a, rj_num("1")); rj_arr_push(a, rj_str("decode"));
        int ok2 = rpc_dispatch("getrawtransaction", a, w, result, ec, em); rj_free(a); return ok2; }
    if (!strcmp(method, "getrawtransaction") && params && params->nitems < 3) g_pool_takes++;   /* mempool first: a pool-lock take */
    if (!strcmp(method, "getmempoolentry")) g_pool_takes++;
    if (!strcmp(method, "getrawtransaction")){
        if (p0 && !strcmp(p0, "7777777777777777777777777777777777777777777777777777777777777777")){   /* unconfirmed, spends the unconfirmed 0x44..:0 */
            const char* t = "{\"txid\":\"7777777777777777777777777777777777777777777777777777777777777777\",\"version\":2,\"locktime\":0,\"size\":110,\"weight\":440,\"vin\":[{\"txid\":\"4444444444444444444444444444444444444444444444444444444444444444\",\"vout\":0,\"scriptSig\":{\"hex\":\"\"},\"sequence\":0}],\"vout\":[{\"value\":0.029,\"n\":0,\"scriptPubKey\":{\"hex\":\"0014dd\",\"type\":\"witness_v0_keyhash\",\"address\":\"bc1qnext\"}}]}";
            *result = J(t); return 1; }
        if (p0 && !strcmp(p0, TX2)){
            if (p1 == 0){ *result = rj_str("0200aa"); return 1; }            if (g_big){ char* big = malloc(1300000); memset(big, 'a', 1200000); big[1200000] = 0;
                char* t = malloc(1400000); snprintf(t, 1400000, "{\"txid\":\"" TX2 "\",\"version\":2,\"locktime\":0,\"size\":1,\"weight\":4,\"fee\":0.00000001,\"blockhash\":\"" BH "\",\"vin\":[{\"txid\":\"" TX3 "\",\"vout\":0,\"scriptSig\":{\"hex\":\"\"},\"txinwitness\":[\"%s\"],\"sequence\":0}],\"vout\":[]}", big);
                *result = J(t); free(t); free(big); return 1; }
            const char* t = "{\"txid\":\"" TX2 "\",\"version\":2,\"locktime\":699999,\"size\":222,\"weight\":561,\"fee\":0.00000377,\"blockhash\":\"" BH "\",\"confirmations\":3,\"blocktime\":1631000000,\"vin\":[{\"txid\":\"" TX3 "\",\"vout\":1,\"scriptSig\":{\"hex\":\"\"},\"txinwitness\":[\"3044aa\"],\"sequence\":4294967293,\"prevout\":{\"generated\":false,\"height\":699990,\"value\":0.03612294,\"scriptPubKey\":{\"hex\":\"00146ffe291a\",\"type\":\"witness_v0_keyhash\",\"address\":\"bc1qprev\"}}}],\"vout\":[{\"value\":0.03611917,\"n\":0,\"scriptPubKey\":{\"hex\":\"76a914aa88ac\",\"type\":\"pubkeyhash\",\"address\":\"1test\"}},{\"value\":0,\"n\":1,\"scriptPubKey\":{\"hex\":\"6a04deadbeef\",\"type\":\"nulldata\"}}]}";
            *result = rj_parse(t, strlen(t)); return 1; }
        if (p0 && !strcmp(p0, "5555555555555555555555555555555555555555555555555555555555555555") && g_mp_on){   /* the parent, confirmed: its output 0 pays A 700 sats */
            const char* t = "{\"txid\":\"5555555555555555555555555555555555555555555555555555555555555555\",\"version\":2,\"locktime\":0,\"size\":100,\"weight\":400,\"blockhash\":\"" BH "\",\"confirmations\":1,\"vin\":[{\"coinbase\":\"00\",\"sequence\":0}],\"vout\":[{\"value\":0.00000700,\"n\":0,\"scriptPubKey\":{\"hex\":\"00141111111111111111111111111111111111111111\",\"type\":\"witness_v0_keyhash\",\"address\":\"bc1qaddrA\"}}]}";
            *result = J(t); return 1; }
        if (p0 && (!strcmp(p0, TX3) || !strcmp(p0, "5555555555555555555555555555555555555555555555555555555555555555"))){
            /* a confirmed tx used by the address routes (TX3 at 700000, 0x55.. at 700001) */
            static char t[1200]; snprintf(t, sizeof t, "{\"txid\":\"%s\",\"version\":2,\"locktime\":0,\"size\":100,\"weight\":400,\"fee\":0.00000100,\"blockhash\":\"" BH "\",\"confirmations\":1,\"vin\":[{\"txid\":\"" TX2 "\",\"vout\":0,\"scriptSig\":{\"hex\":\"\"},\"sequence\":0,\"prevout\":{\"generated\":false,\"height\":700000,\"value\":0.03611917,\"scriptPubKey\":{\"hex\":\"0014aa\",\"type\":\"witness_v0_keyhash\",\"address\":\"bc1qaddrA\"}}}],\"vout\":[{\"value\":0.036,\"n\":0,\"scriptPubKey\":{\"hex\":\"0014bb\",\"type\":\"witness_v0_keyhash\",\"address\":\"bc1qother\"}}]}", p0);
            *result = J(t); return 1; }
        if (p0 && !strcmp(p0, "6666666666666666666666666666666666666666666666666666666666666666")){   /* the mempool tx: pays A (P2WPKH 0x11..) 900 sats, spends 0x55:0 */
            const char* t = "{\"txid\":\"6666666666666666666666666666666666666666666666666666666666666666\",\"version\":2,\"locktime\":0,\"size\":110,\"weight\":440,\"vin\":[{\"txid\":\"5555555555555555555555555555555555555555555555555555555555555555\",\"vout\":0,\"scriptSig\":{\"hex\":\"\"},\"sequence\":0}],\"vout\":[{\"value\":0.00000900,\"n\":0,\"scriptPubKey\":{\"hex\":\"00141111111111111111111111111111111111111111\",\"type\":\"witness_v0_keyhash\",\"address\":\"bc1qaddrA\"}}]}";
            *result = J(t); return 1; }
        if (p0 && !strcmp(p0, "4444444444444444444444444444444444444444444444444444444444444444")){   /* an unconfirmed tx: no prevout, no fee, no blockhash */
            const char* t = "{\"txid\":\"4444444444444444444444444444444444444444444444444444444444444444\",\"version\":2,\"locktime\":0,\"size\":110,\"weight\":440,\"vin\":[{\"txid\":\"" TX2 "\",\"vout\":0,\"scriptSig\":{\"hex\":\"\"},\"sequence\":0}],\"vout\":[{\"value\":0.03,\"n\":0,\"scriptPubKey\":{\"hex\":\"0014cc\",\"type\":\"witness_v0_keyhash\",\"address\":\"bc1qout\"}}]}";
            *result = rj_parse(t, strlen(t)); return 1; }
        *ec = -5; *em = "No such mempool or blockchain transaction"; return 0; }
    if (!strcmp(method, "getmempoolentry")){ *result = J("{\"vsize\":110,\"fees\":{\"base\":0.00000500}}"); return 1; }
    if (!strcmp(method, "gettxout")){ g_calls_gettxout++;
        if (p0 && !strcmp(p0, TX2) && p1 == 0){ *result = J("{\"value\":0.03611917,\"scriptPubKey\":{\"hex\":\"76a914aa88ac\",\"type\":\"pubkeyhash\",\"address\":\"1test\"}}"); return 1; }
        *result = rj_null(); return 1; }
    if (!strcmp(method, "gettxspendingprevout")){ if (!g_spender_index){ *ec = -1; *em = "txospenderindex is unavailable"; return 0; }
        /* echo every outpoint asked; TX2:0 is spent by 0x44.., the rest unspent */
        const rj_val* list = params->items[0]; rj_val* arr = rj_arr();
        for (size_t i = 0; list && list->typ == RJ_ARR && i < list->nitems; i++){
            rj_val* o = rj_obj(); const char* tx = S(list->items[i], "txid"); const char* vo = S(list->items[i], "vout");
            rj_obj_set(o, "txid", rj_str(tx ? tx : "")); rj_obj_set(o, "vout", rj_num(vo ? vo : "0"));
            if (tx && !strcmp(tx, TX2) && vo && !strcmp(vo, "0")){ rj_obj_set(o, "spendingtxid", rj_str("4444444444444444444444444444444444444444444444444444444444444444")); rj_obj_set(o, "spendingvin", rj_num("0")); }
            rj_arr_push(arr, o);
        }
        *result = arr; return 1; }
    if (!strcmp(method, "getrawmempool") && g_mp_on){ *result = J("[\"6666666666666666666666666666666666666666666666666666666666666666\"]"); return 1; }
    if (!strcmp(method, "getrawmempool")){ if (params->items[0]->str[0] == '1'){
            /* frozen, as rpc_node's verbose getrawmempool hands its entries
             * out since 2026-10-06 (rj_freeze): /mempool/recent reads into it */
            rj_val* o = rj_obj(); rj_mark mk = rj_arena_mark();
            rj_obj_set(o, "4444444444444444444444444444444444444444444444444444444444444444",
                       rj_freeze(J("{\"vsize\":110,\"fees\":{\"base\":0.000005}}"), mk));
            *result = o; return 1; }
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

    esplora_set_exec_lock(tlock, tunlock);
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
      ok(t3 && !G(t3, "fee") && G(t3, "vin"), "a tx whose prevouts Core's JSON lacks has NO fee key: 0 would claim it paid nothing (2026-09-08)");
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
    g_calls_gettxout = 0;
    { rj_val* t = GET("/tx/4444444444444444444444444444444444444444444444444444444444444444");
      ok(t && G(G(t, "status"), "confirmed")->str[0] == '0' && streq(S(t, "fee"), "500"), "an unconfirmed tx: status unconfirmed, fee from getmempoolentry");
      rj_val* pv = G(G(t, "vin")->items[0], "prevout"); ok(pv && streq(S(pv, "value"), "3611917") && streq(S(pv, "scriptpubkey_address"), "1test"), "...its prevout filled from the previous transaction's vout");
      ok(g_calls_gettxout == 0, "...without a single gettxout (that call crosses to the download worker and starved production's RPC)");
      rj_free(t); }
    { rj_val* m = GET("/mempool/txids"); ok(m && m->nitems == 1, "GET /mempool/txids"); rj_free(m); }
    { rj_val* m = GET("/mempool"); ok(m && streq(S(m, "count"), "1") && streq(S(m, "vsize"), "110") && streq(S(m, "total_fee"), "500"), "GET /mempool -> count, vsize, total_fee in sats"); rj_free(m); }
    { rj_val* m = GET("/mempool/recent"); ok(m && m->nitems == 1 && streq(S(m->items[0], "fee"), "500"), "GET /mempool/recent"); rj_free(m); }
    { rj_val* m = GET("/internal/mempool/txs?max_txs=5"); ok(m && m->nitems == 1 && streq(S(m->items[0], "txid"), "4444444444444444444444444444444444444444444444444444444444444444"), "GET /internal/mempool/txs -> full transactions"); rj_free(m); }
    { rj_val* m = POST("/internal/txs", "[\"" TX2 "\",\"" TX1 "\"]"); ok(m && m->nitems == 1 && streq(S(m->items[0], "txid"), TX2), "POST /internal/txs -> the known ones"); rj_free(m); }
    { rj_val* m = POST("/internal/txs/outspends/by-txid", "[\"" TX2 "\"]"); ok(m && m->nitems == 1 && m->items[0]->nitems == 2, "POST /internal/txs/outspends/by-txid"); rj_free(m); }
    POST("/tx", "0200aa\n"); ok(g_status == 200 && streq(g_out, "4444444444444444444444444444444444444444444444444444444444444444"), "POST /tx broadcasts and returns the txid");
    POST("/tx", "bad"); ok(g_status == 400, "POST /tx with a rejected tx -> 400 with the node's reason");
    GET("/address/bc1qtest"); ok(g_status == 400, "GET /address/<unknown to the decoder> -> 400");
    /* ---- the address routes (stage 2) ---- */
    GET("/address/bc1qaddrA"); ok(g_status == 501, "without the history index: 501 naming the builder");
    GET("/address/notanaddress"); ok(g_status == 400, "an invalid address: 400");
    write_base();
    { rj_val* a = GET("/address/bc1qaddrA"); rj_val* cs = G(a, "chain_stats");
      ok(a && streq(S(a, "address"), "bc1qaddrA") && streq(S(cs, "funded_txo_count"), "1") && streq(S(cs, "funded_txo_sum"), "3611917") && streq(S(cs, "spent_txo_count"), "1") && streq(S(cs, "spent_txo_sum"), "3611917") && streq(S(cs, "tx_count"), "2"),
         "GET /address: chain_stats from the base (1 funded, 1 spent, 2 transactions)");
      ok(a && G(a, "mempool_stats") && streq(S(G(a, "mempool_stats"), "tx_count"), "0"), "...mempool_stats present, zero (this cut)"); rj_free(a); }
    { rj_val* t = GET("/address/bc1qaddrA/txs");
      ok(t && t->typ == RJ_ARR && t->nitems == 2 && streq(S(t->items[0], "txid"), TX3) && streq(S(t->items[1], "txid"), TX2), "GET /address/txs: newest first (TX3 the spend, then TX2 the fund), txids resolved through getblock");
      rj_free(t); }
    { rj_val* t = GET("/address/bc1qaddrA/txs/chain/" TX3); ok(t && t->nitems == 1 && streq(S(t->items[0], "txid"), TX2), "GET /address/txs/chain/:lastSeen pages after it"); rj_free(t); }
    { rj_val* t = GET("/address/bc1qaddrA/txs/mempool"); ok(t && t->typ == RJ_ARR && t->nitems == 0, "GET /address/txs/mempool: empty in this cut"); rj_free(t); }
    { rj_val* u = GET("/address/bc1qaddrA/utxo"); ok(u && u->typ == RJ_ARR && u->nitems == 0, "GET /address/utxo: the base's one funding (TX2:0) is spent per the spender index -> empty"); rj_free(u); }
    g_tail_on = 1;
    { rj_val* a = GET("/address/bc1qaddrA"); rj_val* cs = G(a, "chain_stats");
      ok(a && streq(S(cs, "funded_txo_count"), "2") && streq(S(cs, "funded_txo_sum"), "3612617") && streq(S(cs, "spent_txo_count"), "2") && streq(S(cs, "tx_count"), "4"), "with the tail journal: the ADD, DEL and TOUCH above the base count in (2 funded, 2 spent, 4 txs)"); rj_free(a); }
    { rj_val* t = GET("/address/bc1qaddrA/txs"); ok(t && t->nitems >= 3 && streq(S(t->items[0], "txid"), "4444444444444444444444444444444444444444444444444444444444444444"), "...the newest transaction is the tail's spender (0x44.., height 700002)"); rj_free(t); }
    { rj_val* u = GET("/address/bc1qaddrA/utxo"); ok(u && u->typ == RJ_ARR && u->nitems == 0, "...utxo with the tail: its ADD (0x55:0) is cancelled by its DEL; still empty"); rj_free(u); }
    { g_tail_add_only = 1; rj_val* u = GET("/address/bc1qaddrA/utxo"); g_tail_add_only = 0;
      ok(u && u->nitems == 1 && streq(S(u->items[0], "txid"), "5555555555555555555555555555555555555555555555555555555555555555") && streq(S(u->items[0], "value"), "700") && streq(S(G(u->items[0], "status"), "block_height"), "700001"), "...a tail ADD with no DEL: one utxo, 700 sats at 700001"); rj_free(u); }
    g_tail_on = 0; unlink(AH_FILE);
    /* the mempool, by address: 0x66.. pays A 900 sats and spends A's unconfirmed-tail output 0x55:0 (700 sats) */
    write_base(); g_tail_add_only = 1; g_mp_on = 1;
    { rj_val* a = GET("/address/bc1qaddrA"); rj_val* ms = G(a, "mempool_stats");
      ok(a && streq(S(ms, "funded_txo_count"), "1") && streq(S(ms, "funded_txo_sum"), "900") && streq(S(ms, "spent_txo_count"), "1") && streq(S(ms, "spent_txo_sum"), "700") && streq(S(ms, "tx_count"), "1"), "mempool_stats: one funding (900), one spend (700), one transaction"); rj_free(a); }
    { rj_val* t = GET("/address/bc1qaddrA/txs/mempool"); ok(t && t->nitems == 1 && streq(S(t->items[0], "txid"), "6666666666666666666666666666666666666666666666666666666666666666"), "GET /address/txs/mempool lists the unconfirmed transaction"); rj_free(t); }
    { rj_val* t = GET("/address/bc1qaddrA/txs"); ok(t && t->nitems >= 2 && streq(S(t->items[0], "txid"), "6666666666666666666666666666666666666666666666666666666666666666") && G(G(t->items[0], "status"), "confirmed")->str[0] == '0', "GET /address/txs: the unconfirmed transaction comes first"); rj_free(t); }
    { rj_val* u = GET("/address/bc1qaddrA/utxo");
      ok(u && u->nitems == 1 && streq(S(u->items[0], "txid"), "6666666666666666666666666666666666666666666666666666666666666666") && streq(S(u->items[0], "value"), "900") && G(G(u->items[0], "status"), "confirmed")->str[0] == '0', "GET /address/utxo: the output spent in the mempool is gone, the new unconfirmed output is listed as unconfirmed"); rj_free(u); }
    g_mp_on = 0; g_tail_add_only = 0; unlink(AH_FILE);
    GET("/scripthash/aa"); ok(g_status == 501, "scripthash routes: 501 (the index is keyed by address)");
    GET("/nothing/here"); ok(g_status == 404, "an unknown route -> 404");
    ok(g_locks > 20 && g_locks == g_unlocks, "the execution lock was taken and released around every dispatch, not once per request");
    /* a response over 1 MiB: the writer reports the needed length, the reply must grow (found live: garbage after the first MiB) */
    { g_big = 1; rj_val* m = POST("/internal/txs", "[\"" TX2 "\"]"); g_big = 0;
      ok(m && m->nitems == 1 && g_outlen > (1u << 20) && g_out[g_outlen - 1] == ']', "a >1 MiB response is complete and well-formed"); rj_free(m); }
    /* ---- /fee-estimates ---------------------------------------------------
     * The last route mempool.space's esplora client called that this facade
     * answered 404 for. Esplora's shape is a FLAT MAP of confirmation target
     * to feerate in sat/vB; Core reports BTC/kvB, so the conversion is x100000
     * and it is done as string arithmetic, never a double.
     *
     * The rule that matters is the OMISSION: a target the estimator cannot
     * answer is left out, not sent as zero. A caller that fell back to a zero
     * feerate would build a transaction the network will not relay, so a
     * missing key is the safe answer and a zero is a dangerous one. */
    { rj_val* f = GET("/fee-estimates");
      ok(f && f->typ == RJ_OBJ, "/fee-estimates answers a JSON object");
      /* 0.000125 BTC/kvB = 12500 sat/kvB = 12.5 sat/vB */
      ok(f && S(f, "1") && !strcmp(S(f, "1"), "12.5"), "target 1: BTC/kvB converted to sat/vB");
      ok(f && S(f, "2") && !strcmp(S(f, "2"), "10.1"), "target 2");
      ok(f && S(f, "6") && !strcmp(S(f, "6"), "2.0"),  "target 6");
      ok(f && S(f, "144") && !strcmp(S(f, "144"), "1.0"), "the long target");
      ok(f && !rj_obj_get(f, "7"),   "a target answering ZERO is OMITTED (the value check, not the missing-field one)");
      ok(f && !rj_obj_get(f, "8"),   "a target with no answer at all is omitted too");
      ok(f && !rj_obj_get(f, "1008"), "...and so is the longest one");
      rj_free(f); }

    /* ---- POST /internal/mempool/txs batched (2026-10-01) ----
     * The same request through the per-transaction path and the batched one:
     * byte-identical JSON, and the pool-lock takes fall from 3 per transaction
     * (getrawtransaction, getmempoolentry, one per input's prevout) to one per
     * slice for the transactions and one for their parents. 0x77.. spends the
     * unconfirmed 0x44..:0 (a parent in the pool); 0x44.. and 0x66.. spend
     * confirmed parents (resolved by block hash, no pool lock). */
    { const char* body = "[\"4444444444444444444444444444444444444444444444444444444444444444\",\"6666666666666666666666666666666666666666666666666666666666666666\",\"7777777777777777777777777777777777777777777777777777777777777777\"]";
      g_mp_on = 1;
      g_batch_on = 0; g_pool_takes = 0;
      rj_val* a = POST("/internal/mempool/txs", body); char* sa = g_out ? strndup(g_out, g_outlen) : 0; int takes_old = g_pool_takes;
      g_batch_on = 1; g_pool_takes = 0; g_idx_calls = g_idx_unlocked = 0; g_many_calls = 0;
      rj_val* b = POST("/internal/mempool/txs", body); char* sb = g_out ? strndup(g_out, g_outlen) : 0; int takes_new = g_pool_takes;
      ok(a && b && a->nitems == 3 && b->nitems == 3, "POST /internal/mempool/txs: all three transactions, both paths");
      ok(sa && sb && !strcmp(sa, sb), "...the batched reply is byte-identical to the per-transaction one (fee, prevouts from pool and index)");
      if (sa && sb && strcmp(sa, sb)) printf("      per-tx: %.300s\n      batch : %.300s\n", sa, sb);
      ok(takes_old == 9 && takes_new == 2, "...pool-lock takes: 9 per-transaction (3 x 3) -> 2 batched (one slice of txs, one of parents)");
      if (!(takes_old == 9 && takes_new == 2)) printf("      takes per-tx %d, batched %d\n", takes_old, takes_new);
      ok(g_idx_calls > 0 && g_many_calls == 1 && g_idx_unlocked == 0, "...the txid-index lookups ran as ONE lane batch with no execution lock held (2026-10-05: the lane guards irs_refresh, not the exclusive lock)");
      if (!(g_idx_calls > 0 && g_many_calls == 1 && g_idx_unlocked == 0)) printf("      index lookups %d in %d batch call(s), with the exec lock held %d\n", g_idx_calls, g_many_calls, g_idx_unlocked);
      rj_val* v7 = (b && b->nitems == 3) ? rj_obj_get(b->items[2], "vin") : 0;
      rj_val* p7 = (v7 && v7->nitems) ? v7->items[0] : 0;
      ok(p7 && rj_obj_get(p7, "prevout") && !strcmp(S(rj_obj_get(p7, "prevout"), "value"), "3000000"), "...0x77..'s prevout came from its unconfirmed parent in the pool (3,000,000 sat)");
      rj_free(a); rj_free(b); free(sa); free(sb);
      g_batch_on = 0; g_mp_on = 0; }

    free(g_out);
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
