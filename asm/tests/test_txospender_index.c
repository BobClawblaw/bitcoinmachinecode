/* tests/test_txospender_index.c -- the txo-spender index end to end
 * (Core's -txospenderindex): the offline builder's base file, the daemon's
 * incremental tail, the verifying reader in rpc_chain.c, and the
 * gettxspendingprevout RPC's index semantics (mempool_only default,
 * return_spending_tx, blockhash, and Core's error when the index is absent).
 *
 * A four-block synthetic archive: h0 coinbase; h1 spends (h0,0); h2 spends
 * (h1,0) and creates a second output; h3 spends (h2,1). The base is built
 * for [0,1] by the real tool; the tail then covers h2..h3. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"
#include "../rpc_commands.h"
#include "../rpc_json.h"
#include "../rpc_chain.h"
#include "../daemon/txosp_format.h"
typedef unsigned char u8;
extern long store_init(void* st);
extern long store_append(void* st, const unsigned char hash[32], const void* raw, long len);
extern int  store_rd_init(void* st);
extern int  tx_txid(void* out, const void* tx, unsigned long txlen, void* buf, unsigned long buflen);
extern void tsp_boot(void* store_buf);
extern int  tsp_active(void);
extern void tsp_on_block(void* store_buf, long h, const unsigned char* blk, long blen);
extern int  rpc_node_dispatch(const char* m, const rj_val* params, rj_val** res, long* ec, const char** em);
static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }
static void hexrev(char* o, const u8* b){ for (int i = 0; i < 32; i++) sprintf(o + 2*i, "%02x", b[31-i]); o[64] = 0; }
static const char* S(rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o, k) : NULL; return v ? v->str : NULL; }
static unsigned char store_buf[4096];
/* tx: version(tag) | nin inputs (prevout, empty scriptSig, seq) | nout outputs (value, OP_TRUE) | locktime */
static long mk_tx(u8* p, int tag, const u8* prev_txid, unsigned prev_vout, int nout){
    u8* s = p; *p++ = 1; *p++ = 0; *p++ = 0; *p++ = (u8)tag; *p++ = 1;
    if (prev_txid){ memcpy(p, prev_txid, 32); p += 32; *p++ = (u8)prev_vout; *p++ = (u8)(prev_vout >> 8); *p++ = 0; *p++ = 0; }
    else { memset(p, 0, 32); p += 32; *p++ = 0xff; *p++ = 0xff; *p++ = 0xff; *p++ = 0xff; }
    *p++ = 0; *p++ = 0xff; *p++ = 0xff; *p++ = 0xff; *p++ = 0xff;
    *p++ = (u8)nout; for (int i = 0; i < nout; i++){ memset(p, (u8)(0x40 + tag + i), 8); p += 8; *p++ = 1; *p++ = 0x51; }
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0; return p - s;
}
int main(void){
    char tool[4096]; if (!getcwd(tool, sizeof tool - 40)) return 1; strcat(tool, "/daemon/build_txospender_index");
    tt_isolate();
    memset(store_buf, 0, sizeof store_buf);
    ck("store_init", store_init(store_buf) == 1);
    static u8 blk[4][4096]; long blen[4]; u8 txid[4][32]; u8 hash[4][32]; static u8 scratch[8192];
    for (int h = 0; h < 4; h++){ memset(blk[h], 0xA0 + h, 80); blk[h][80] = 1; memset(hash[h], 0xB0 + h, 32); }
    long l0 = mk_tx(blk[0] + 81, 0, NULL, 0, 1); blen[0] = 81 + l0; tx_txid(txid[0], blk[0] + 81, l0, scratch, sizeof scratch);
    long l1 = mk_tx(blk[1] + 81, 1, txid[0], 0, 1); blen[1] = 81 + l1; tx_txid(txid[1], blk[1] + 81, l1, scratch, sizeof scratch);
    long l2 = mk_tx(blk[2] + 81, 2, txid[1], 0, 2); blen[2] = 81 + l2; tx_txid(txid[2], blk[2] + 81, l2, scratch, sizeof scratch);
    long l3 = mk_tx(blk[3] + 81, 3, txid[2], 1, 1); blen[3] = 81 + l3; tx_txid(txid[3], blk[3] + 81, l3, scratch, sizeof scratch);
    for (int h = 0; h < 2; h++) ck("store_append", store_append(store_buf, hash[h], blk[h], blen[h]) == h);
    store_rd_init(store_buf);
    ck("rpc_chain_open", rpc_chain_open(NULL) == 1);
    char t0d[65], t1d[65], t2d[65], t3d[65]; hexrev(t0d, txid[0]); hexrev(t1d, txid[1]); hexrev(t2d, txid[2]); hexrev(t3d, txid[3]);
    char pj[600]; rj_val* p; rj_val* r; long ec; const char* em;

    printf("== 1. no index yet ==\n");
    ck("index unavailable", !rpc_chain_txospender_available());
    tsp_boot(store_buf); ck("tail disabled without a base", !tsp_active());
    snprintf(pj, sizeof pj, "[[{\"txid\":\"%s\",\"vout\":0}]]", t0d); p = rj_parse(pj, strlen(pj)); r = NULL;
    ck("gettxspendingprevout defaults to mempool-only and answers (no spender known)", rpc_node_dispatch("gettxspendingprevout", p, &r, &ec, &em) && r && r->nitems == 1 && !S(r->items[0], "spendingtxid"));
    rj_free(p); rj_free(r);
    snprintf(pj, sizeof pj, "[[{\"txid\":\"%s\",\"vout\":0}],{\"mempool_only\":false}]", t0d); p = rj_parse(pj, strlen(pj)); r = NULL;
    ck("...mempool_only=false without the index -> Core's error", !rpc_node_dispatch("gettxspendingprevout", p, &r, &ec, &em) && ec == -1 && em && strstr(em, "txospenderindex is unavailable"));
    rj_free(p); if (r) rj_free(r);

    printf("== 2. base [0,1] built by the tool, tail covers h2..h3 ==\n");
    { char cmd[4300]; snprintf(cmd, sizeof cmd, "%s . 0 1 2>/dev/null", tool); ck("builder ran", system(cmd) == 0); }
    { struct stat sb; ck("txospender.dat has 1 record (h1 spends h0:0)", stat(TSP_BASE_FILE, &sb) == 0 && sb.st_size == TSP_HDR + 1 * TSP_REC + 1 * TSP_SPARSE); }
    ck("index available now", rpc_chain_txospender_available());
    for (int h = 2; h < 4; h++) ck("store_append", store_append(store_buf, hash[h], blk[h], blen[h]) == h);
    tsp_boot(store_buf); ck("tail active", tsp_active());
    { struct stat sb; ck("boot backfilled h2..h3 into the tail (2 records)", stat(TSP_TAIL_FILE, &sb) == 0 && sb.st_size == 2 * TSP_REC); }
    tsp_on_block(store_buf, 3, blk[3], blen[3]);
    { struct stat sb; ck("re-offered height appends nothing", stat(TSP_TAIL_FILE, &sb) == 0 && sb.st_size == 2 * TSP_REC); }

    printf("== 3. reader ==\n");
    u8 sp[32], bh[32]; long h = -1; static u8 txb[4096]; long tl = 0;
    ck("(h0,0) -> spent by tx1 at h1 (base)", rpc_chain_txospender_lookup(txid[0], 0, sp, &h, bh, txb, sizeof txb, &tl) && !memcmp(sp, txid[1], 32) && h == 1 && !memcmp(bh, hash[1], 32) && tl == l1 && !memcmp(txb, blk[1] + 81, l1));
    ck("(h1,0) -> spent by tx2 at h2 (tail)", rpc_chain_txospender_lookup(txid[1], 0, sp, &h, bh, NULL, 0, NULL) && !memcmp(sp, txid[2], 32) && h == 2);
    ck("(h2,1) -> spent by tx3 at h3 (tail)", rpc_chain_txospender_lookup(txid[2], 1, sp, &h, bh, NULL, 0, NULL) && !memcmp(sp, txid[3], 32) && h == 3);
    ck("(h2,0) is unspent", !rpc_chain_txospender_lookup(txid[2], 0, sp, &h, bh, NULL, 0, NULL));
    ck("(h3,0) is unspent", !rpc_chain_txospender_lookup(txid[3], 0, sp, &h, bh, NULL, 0, NULL));
    { u8 fake[32]; memcpy(fake, txid[0], 32); fake[20] ^= 1;   /* same 12-byte prefix, different txid: the verify step must reject it */
      ck("prefix collision is rejected by verification", !rpc_chain_txospender_lookup(fake, 0, sp, &h, bh, NULL, 0, NULL)); }

    printf("== 4. RPC with the index ==\n");
    snprintf(pj, sizeof pj, "[[{\"txid\":\"%s\",\"vout\":0},{\"txid\":\"%s\",\"vout\":1},{\"txid\":\"%s\",\"vout\":0}],{\"return_spending_tx\":true}]", t0d, t2d, t3d);
    p = rj_parse(pj, strlen(pj)); r = NULL;
    ck("gettxspendingprevout (index default: not mempool-only)", rpc_node_dispatch("gettxspendingprevout", p, &r, &ec, &em) && r && r->nitems == 3);
    if (r && r->nitems == 3){ char bh1[65]; hexrev(bh1, hash[1]);
        ck("...(h0,0): spendingtxid = tx1, blockhash = h1's hash, spendingtx present", S(r->items[0], "spendingtxid") && !strcmp(S(r->items[0], "spendingtxid"), t1d) && S(r->items[0], "blockhash") && !strcmp(S(r->items[0], "blockhash"), bh1) && S(r->items[0], "spendingtx"));
        ck("...(h2,1): spendingtxid = tx3", S(r->items[1], "spendingtxid") && !strcmp(S(r->items[1], "spendingtxid"), t3d));
        ck("...(h3,0): unspent -> no spendingtxid", !S(r->items[2], "spendingtxid")); }
    rj_free(p); if (r) rj_free(r);
    snprintf(pj, sizeof pj, "[[{\"txid\":\"%s\",\"vout\":0}],{\"mempool_only\":true}]", t0d); p = rj_parse(pj, strlen(pj)); r = NULL;
    ck("mempool_only=true ignores the index", rpc_node_dispatch("gettxspendingprevout", p, &r, &ec, &em) && r && !S(r->items[0], "spendingtxid"));
    rj_free(p); if (r) rj_free(r);
    { extern int rpc_chain_dispatch(const char* method, const rj_val* params, rj_val** res, long* ec, const char** em);
      p = rj_parse("[]", 2); r = NULL;
      int ok = rpc_chain_dispatch("getindexinfo", p, &r, &ec, &em);
      rj_val* ti = ok && r ? rj_obj_get(r, "txospenderindex") : NULL;
      ck("getindexinfo lists txospenderindex synced to the tip", ti && S(ti, "synced") && S(ti, "synced")[0] == '1' && S(ti, "best_block_height") && !strcmp(S(ti, "best_block_height"), "3"));
      rj_free(p); if (r) rj_free(r); }
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
