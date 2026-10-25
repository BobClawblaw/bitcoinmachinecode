/* tests/test_mempool_load_partial.c -- a mempool.dat that turns malformed
 * partway keeps the transactions read before the fault, as Core does.
 *
 * Core's LoadMempool (node/mempool_persist.cpp) admits each transaction as it
 * reads it; when a later read throws it logs "Failed to deserialize mempool
 * data on file ... Continuing anyway." and the ones already admitted stay.
 * rpc_node_mempool_load collected the whole file first and, on any error,
 * admitted nothing. The worker is a thread here: it answers each submission
 * on the shared status block (tx_submit_seq -> tx_submit_ack) with "accepted"
 * and records the tag of each transaction it was handed.
 *
 * The importmempool RPC (2026-10-25) answers as Core v31.1's does: -10 in
 * IBD, and -1 "Unable to import mempool file, see debug.log for details."
 * for a file it cannot read whole, the ones read before the fault kept. */
#include "../rpc_node.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include "test_tmpdir.h"
#include "../rpc_json.h"

typedef unsigned char u8;
extern long mempool_dump_write(const char* path, const u8* const* txs,
                               const unsigned long* lens, const long long* times,
                               const long long* deltas, long n,
                               const u8* extra_txids, const long long* extra_deltas,
                               long n_extra);
extern long rpc_node_mempool_load(const char* path);
extern void rpc_node_set_status_rw(node_status_t* st);

/* link stub: bitcoin_mempool_policy.c references it; nothing here reaches it */
long mempool_resolve_confirmed_utxo(void* u, const unsigned char* txid, unsigned long index,
                                    unsigned long long* val, const unsigned char** spk,
                                    unsigned long* spklen){
    (void)u; (void)txid; (void)index; (void)val; (void)spk; (void)spklen; return 0;
}

/* rpc_chain.c's IBD answer, which rpc_node.c takes weakly */
static int g_ibd;
int rpc_chain_in_ibd(void){ return g_ibd; }

static int fails = 0;
static void ck(const char* l, long got, long want){
    if (got == want) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, want); fails++; }
}

/* a minimal valid transaction tagged by its prevout (the shape
 * test_mempool_persist_wiring.c uses) */
static unsigned long mk_tx(u8* out, u8 tag){
    u8* p = out;
    p[0]=2;p[1]=0;p[2]=0;p[3]=0; p+=4;
    *p++ = 1;
    memset(p, tag, 32); p += 32;
    p[0]=0;p[1]=0;p[2]=0;p[3]=0; p+=4;
    *p++ = 0;
    p[0]=0xfd;p[1]=0xff;p[2]=0xff;p[3]=0xff; p+=4;
    *p++ = 1;
    for(int k=0;k<8;k++) *p++ = (u8)(k==0?0x40:0);
    *p++ = 22; *p++ = 0x00; *p++ = 0x14;
    for(int k=0;k<20;k++) *p++ = (u8)(k+tag);
    p[0]=0;p[1]=0;p[2]=0;p[3]=0; p+=4;
    return (unsigned long)(p - out);
}

static node_status_t* g_st;
static volatile int g_stop;
static int g_seen; static u8 g_tags[64];
static void* worker(void* a){
    (void)a;
    while (!g_stop){
        if (g_st->tx_submit_seq != g_st->tx_submit_ack){
            if (g_seen < 64) g_tags[g_seen] = g_st->tx_submit_buf[5];   /* the prevout's first byte: the tag */
            g_seen++;
            g_st->tx_submit_result = 1;
            __sync_synchronize();
            g_st->tx_submit_ack = g_st->tx_submit_seq;
        }
        usleep(50);
    }
    return 0;
}

static long load(const char* path, int* seen){
    g_seen = 0; memset(g_tags, 0, sizeof g_tags);
    long r = rpc_node_mempool_load(path);
    *seen = g_seen;
    return r;
}

int main(void){
    tt_isolate();
    setbuf(stdout, NULL);
    g_st = calloc(1, sizeof *g_st);
    if (!g_st){ printf("FAIL calloc\n"); return 1; }
    rpc_node_set_status_rw(g_st);
    pthread_t th; pthread_create(&th, 0, worker, 0);

    enum { N = 5 };
    static u8 tx[N][128]; const u8* txs[N]; unsigned long lens[N]; long long times[N], deltas[N];
    for (int i = 0; i < N; i++){ lens[i] = mk_tx(tx[i], (u8)(0x11 * (i + 1))); txs[i] = tx[i]; times[i] = 0; deltas[i] = 0; }
    if (mempool_dump_write("mempool.dat", txs, lens, times, deltas, N, 0, 0, 0) != N){ printf("FAIL write\n"); return 1; }

    int seen;
    ck("intact dump: all 5 loaded", load("mempool.dat", &seen), N);
    ck("intact dump: the worker was handed 5", seen, N);

    /* cut inside transaction 3: 0..2 are whole, 3 is torn. The v1 layout is
     * version(8) count(8), then each transaction followed by time(8) delta(8). */
    long cut = 16 + 3 * ((long)lens[0] + 16) + 5;
    if (truncate("mempool.dat", cut) != 0){ printf("FAIL truncate\n"); return 1; }
    ck("torn at transaction 3: the 3 read before it are loaded", load("mempool.dat", &seen), 3);
    ck("torn at transaction 3: the worker was handed exactly those 3", seen, 3);
    ck("torn at transaction 3: in file order, tags 0x11 0x22 0x33",
       g_tags[0] == 0x11 && g_tags[1] == 0x22 && g_tags[2] == 0x33, 1);

    /* nothing readable: still -1 (main reports it and starts empty) */
    if (truncate("mempool.dat", 16 + 5) != 0){ printf("FAIL truncate\n"); return 1; }
    ck("torn at transaction 0: nothing read, -1", load("mempool.dat", &seen), -1);
    ck("torn at transaction 0: the worker was handed nothing", seen, 0);
    ck("a missing file: -1", load("no-such-mempool.dat", &seen), -1);

    /* the RPC: rewrite the intact file, then tear it again */
    if (mempool_dump_write("mempool.dat", txs, lens, times, deltas, N, 0, 0, 0) != N){ printf("FAIL write\n"); return 1; }
    const char* pj = "[\"mempool.dat\"]";
    rj_val* params = rj_parse(pj, strlen(pj));
    rj_val* res; long ec; const char* em;
    g_ibd = 1; g_seen = 0; res = NULL; ec = 0; em = NULL;
    int ok = rpc_node_dispatch("importmempool", params, &res, &ec, &em);
    ck("importmempool in IBD: refused with -10", ok == 0 ? ec : 0, -10);
    ck("importmempool in IBD: Core's text",
       em && !strcmp(em, "Can only import the mempool after the block download and sync is done."), 1);
    ck("importmempool in IBD: the worker was handed nothing", g_seen, 0);
    g_ibd = 0; g_seen = 0; res = NULL;
    ok = rpc_node_dispatch("importmempool", params, &res, &ec, &em);
    ck("importmempool, intact dump: success", ok, 1);
    ck("importmempool, intact dump: all 5 handed over", g_seen, N);
    rj_free(res);
    if (truncate("mempool.dat", cut) != 0){ printf("FAIL truncate\n"); return 1; }
    g_seen = 0; res = NULL; ec = 0; em = NULL;
    ok = rpc_node_dispatch("importmempool", params, &res, &ec, &em);
    ck("importmempool, torn dump: -1", ok == 0 ? ec : 0, -1);
    ck("importmempool, torn dump: Core's text",
       em && !strcmp(em, "Unable to import mempool file, see debug.log for details."), 1);
    ck("importmempool, torn dump: the 3 read before the fault were still handed over", g_seen, 3);
    rj_free(params);

    g_stop = 1; pthread_join(th, 0);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
