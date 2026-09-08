/* tests/test_rpc_esplora_stress.c -- the address routes against a large
 * mempool and a large address, under the sanitizers.
 *
 * 2026-09-08: the first address request on production (the genesis
 * address, a real 8,400-transaction mempool) crashed the daemon (SIGSEGV,
 * 71 s in). The routes had only ever seen a three-transaction fixture.
 * This harness fakes rpc_dispatch at production scale so the fault is
 * found offline. Build with -fsanitize=address,undefined. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include "../rpc_esplora.h"
/* weak: the watched-to-fail build links the OLD facade, which has no refresher entry point */
void esplora_mp_refresh(const rpc_wallet* w, long budget) __attribute__((weak));
#include "../rpc_json.h"
#include "../daemon/addr_hist_fmt.h"
#include "../daemon/addr_index_fmt.h"
static long MP_N = 9000, BASE_EVENTS = 60000, TX_PER_BLOCK = 3;
static const unsigned char KEY_A[20] = {0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11};
int wallet_validate_address(const char* addr, int* type, unsigned char* ver, unsigned char h160[20], unsigned char prog[32]){
    (void)ver; (void)prog; if (!strcmp(addr, "bc1qaddrA")){ *type = 2; memcpy(h160, KEY_A, 20); return 1; } return 0; }
long axt_read_events(int type, const unsigned char hash[32], long min_height,
                     int (*cb)(void*, int, const unsigned char*, unsigned, unsigned long long, unsigned), void* ctx){
    (void)type; (void)hash; (void)min_height; (void)cb; (void)ctx; return 0; }
static rj_val* J(const char* s){ return rj_parse(s, strlen(s)); }
/* confirmed txid <- (height, pos): 56 hex digits of height, 8 of pos; mempool txid: "ffff" + 60 hex digits of index */
static void conf_txid(char out[65], long h, long pos){ snprintf(out, 65, "%056lx%08lx", h, pos); }
static void mp_txid(char out[65], long i){ snprintf(out, 65, "ffff%060lx", i); }
static long g_calls = 0;
int rpc_dispatch(const char* method, const rj_val* params, const rpc_wallet* w, rj_val** result, long* ec, const char** em){
    (void)w; g_calls++;
    const char* p0 = params && params->typ == RJ_ARR && params->nitems ? params->items[0]->str : 0;
    long p1 = params && params->nitems > 1 && params->items[1]->str ? strtol(params->items[1]->str, 0, 10) : -1;
    if (!strcmp(method, "getblockchaininfo")){ char b[256]; snprintf(b, sizeof b, "{\"blocks\":%ld,\"bestblockhash\":\"%064lx\"}", BASE_EVENTS, BASE_EVENTS); *result = J(b); return 1; }
    if (!strcmp(method, "getblockhash")){ char b[80]; snprintf(b, sizeof b, "%064lx", p0 ? strtol(p0, 0, 10) : 0); *result = rj_str(b); return 1; }
    if (!strcmp(method, "getblock")){
        long h = p0 ? strtol(p0, 0, 16) : 0;
        if (p1 == 0){ *result = rj_str("0102"); return 1; }
        char* b = malloc(4096); int o = snprintf(b, 4096, "{\"hash\":\"%s\",\"height\":%ld,\"time\":1631000000,\"tx\":[", p0, h);
        for (long t = 0; t < TX_PER_BLOCK; t++){ char id[65]; conf_txid(id, h, t); o += snprintf(b + o, 4096 - (size_t)o, "%s\"%s\"", t ? "," : "", id); }
        snprintf(b + o, 4096 - (size_t)o, "]}"); *result = J(b); free(b); return 1; }
    if (!strcmp(method, "getrawtransaction")){
        if (!p0 || strlen(p0) != 64){ *ec = -8; *em = "bad txid"; return 0; }
        if (p1 == 0){ *result = rj_str("0200aa"); return 1; }
        int mp = !strncmp(p0, "ffff", 4); long idx = mp ? strtol(p0 + 4, 0, 16) : 0;
        char parent[65]; if (mp && idx > 0 && (idx & 1)) mp_txid(parent, idx - 1); else conf_txid(parent, (idx % 40000) + 1, 1);
        char keyhex[41]; if (mp ? (idx % 10 == 0) : 1) for (int i = 0; i < 20; i++) snprintf(keyhex + 2 * i, 3, "%02x", KEY_A[i]); else snprintf(keyhex, 41, "%040lx", idx * 2654435761UL);
        char* b = malloc(4096);
        snprintf(b, 4096, "{\"txid\":\"%s\",\"version\":2,\"locktime\":0,\"size\":200,\"weight\":800,%s"
            "\"vin\":[{\"txid\":\"%s\",\"vout\":0,\"scriptSig\":{\"hex\":\"\"},\"sequence\":4294967295},{\"txid\":\"%s\",\"vout\":1,\"scriptSig\":{\"hex\":\"\"},\"sequence\":4294967295}],"
            "\"vout\":[{\"value\":0.00001000,\"n\":0,\"scriptPubKey\":{\"hex\":\"0014%s\",\"type\":\"witness_v0_keyhash\",\"address\":\"bc1qaddrA\"}},"
            "{\"value\":0.00002000,\"n\":1,\"scriptPubKey\":{\"hex\":\"0014%040lx\",\"type\":\"witness_v0_keyhash\",\"address\":\"bc1qother\"}}]}",
            p0, mp ? "" : "\"blockhash\":\"00\",\"confirmations\":5,", parent, parent, keyhex, idx + 7);
        *result = J(b); free(b); return 1; }
    if (!strcmp(method, "getrawmempool")){ rj_val* a = rj_arr(); for (long i = 0; i < MP_N; i++){ char id[65]; mp_txid(id, i); rj_arr_push(a, rj_str(id)); } *result = a; return 1; }
    if (!strcmp(method, "getmempoolentry")){ *result = J("{\"vsize\":110,\"fees\":{\"base\":0.00000500}}"); return 1; }
    if (!strcmp(method, "getmempoolinfo")){ *result = J("{\"size\":1,\"bytes\":110,\"total_fee\":0.000005}"); return 1; }
    if (!strcmp(method, "gettxspendingprevout")){ const rj_val* list = params->items[0]; rj_val* arr = rj_arr();
        for (size_t i = 0; list && list->typ == RJ_ARR && i < list->nitems; i++){ rj_val* o = rj_obj(); rj_obj_set(o, "txid", rj_str("")); rj_obj_set(o, "vout", rj_num("0")); rj_arr_push(arr, o); }
        *result = arr; return 1; }
    *ec = -32601; *em = "Method not found"; return 0;
}
static void write_base(void){
    FILE* f = fopen(AH_FILE, "wb"); ah_header hd; memset(&hd, 0, sizeof hd); hd.magic = AH_MAGIC; hd.version = AH_VERSION; hd.to_height = 900000; hd.body_off = AH_HDR_BYTES;
    unsigned char zero[AH_HDR_BYTES] = {0}; fwrite(zero, 1, AH_HDR_BYTES, f);
    ah_group_hdr g; g.type = 2; memset(g.hash, 0, 32); memcpy(g.hash, KEY_A, 20); g.n = (uint32_t)BASE_EVENTS; fwrite(&g, 1, AH_GROUP_HDR, f);
    for (long i = 0; i < BASE_EVENTS; i++){ ah_event e = { (i % 3 == 2) ? AH_SPEND : AH_FUND, (uint32_t)((i / 3) * 2 + 1), 1, (uint32_t)(i % 3), 1000 }; fwrite(&e, 1, AH_EVENT_BYTES, f); }
    hd.n_keys = 1; hd.n_events = (uint64_t)BASE_EVENTS; hd.body_len = AH_GROUP_HDR + (uint64_t)BASE_EVENTS * AH_EVENT_BYTES; hd.sparse_off = AH_HDR_BYTES + hd.body_len; hd.sparse_n = 1;
    ah_sparse sp; sp.type = 2; memcpy(sp.hash, g.hash, 32); sp.off = 0; fwrite(&sp, AH_SPARSE_BYTES, 1, f);
    fseek(f, 0, SEEK_SET); fwrite(&hd, 1, sizeof hd, f); fclose(f);
}
static char* g_out; static size_t g_outlen; static int g_status; static const char* g_ctype;
static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (double)t.tv_sec + t.tv_nsec / 1e9; }
static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c ? "ok " : "FAIL", w); if (!c) fails++; }
static long run(const char* path){
    free(g_out); g_out = 0; long c0 = g_calls; double t0 = now();
    esplora_handle("GET", 3, path, strlen(path), "", 0, 0, &g_out, &g_outlen, &g_status, &g_ctype);
    printf("  %-28s -> %d, %zu bytes, %ld rpc calls, %.2fs\n", path, g_status, g_outlen, g_calls - c0, now() - t0);
    return g_calls - c0;
}
static void* worker(void* a){ (void)a; for (int i = 0; i < 6; i++){ char* o = 0; size_t ol = 0; int st = 0; const char* ct = 0;
    esplora_handle("GET", 3, "/address/bc1qaddrA", 18, "", 0, 0, &o, &ol, &st, &ct); free(o); } return 0; }
int main(int argc, char** argv){
    if (argc > 1) MP_N = atol(argv[1]);
    if (argc > 2) BASE_EVENTS = atol(argv[2]);
    int threads = argc > 3 ? atoi(argv[3]) : 0;
    char td[] = "/tmp/bmc_esp_stress_XXXXXX"; if (!mkdtemp(td) || chdir(td) != 0){ perror("tmpdir"); return 1; }
    write_base();
    printf("---- rpc_esplora stress: mempool %ld txs, address %ld events ----\n", MP_N, BASE_EVENTS);
    if (threads > 0 || argc <= 3){ if (argc <= 3) threads = 4;
        /* production 14:13-14:14Z: two connections in the address route at
         * once, both refreshing the mempool cache; the cache is global */
        printf("  %d threads on /address at once ...\n", threads); fflush(stdout);
        pthread_t th[16]; for (int i = 0; i < threads && i < 16; i++) pthread_create(&th[i], 0, worker, 0);
        for (int i = 0; i < threads && i < 16; i++) pthread_join(th[i], 0);
        ok(1, "concurrent address requests survive (the cache is locked; 2026-09-08's double free)");
    }
    /* the cache is current after the threads (or after one inline slice per view) */
    if (esplora_mp_refresh) for (int i = 0; i < 30; i++) esplora_mp_refresh(0, 400);
    long c_stats = run("/address/bc1qaddrA");
    ok(g_status == 200 && c_stats <= 2, "stats: no txid is resolved -- at most 2 RPC calls for a 60,000-event address (was one getblock per block: 44,001)");
    long c_txs = run("/address/bc1qaddrA/txs");
    ok(g_status == 200 && c_txs <= 25 * 2 + 25 * 40, "txs: the first page resolves its own 25 transactions only");
    { rj_val* a = rj_parse(g_out, g_outlen); ok(a && a->typ == RJ_ARR && a->nitems >= 25, "txs: a full page of 25"); if (a) rj_free(a); }
    run("/address/bc1qaddrA/utxo");
    ok(g_status == 400 && strstr(g_out, "too many unspent transaction outputs") != 0, "utxo: more than 500 unspent outputs is Esplora's 400 'too many unspent transaction outputs'");
    long c_mp = run("/address/bc1qaddrA/txs/mempool");
    ok(g_status == 200, "txs/mempool answers from the cache");
    (void)c_mp;
    printf("%s (%d failure(s))\n", fails ? "FAILED" : "PASS", fails);
    return fails ? 1 : 0;
}
