/* tests/bench_mempool_scale.c -- MEM-12 (audit 2026-09-03): how much does the
 * policy layer's linear scanning actually cost?
 *
 * The audit's verdict is "CONFIRMED for complexity; timings PLAUSIBLE (not
 * measured)". find_node, find_outreg and find_claim are linear over up to a
 * million entries and are called per INPUT per accept; remove_node makes three
 * linear passes per removal; mpool_policy_block_connect calls find_claim over
 * every claim for every input of every transaction in a block. The claim is
 * that at a few hundred thousand entries each accept costs tens of
 * milliseconds and a block connect tens of seconds -- all under mp_lock, in
 * the download worker, blocking every accept in every process.
 *
 * This measures it rather than assuming it, because the fix -- hash-indexing
 * three tables whose removal is swap-with-last, inside a MAP_SHARED region --
 * is a large amount of delicate code, and the same "measure first" step is
 * what showed MEM-3's obvious fix would have cost +156 MB.
 *
 * Reports accepts/second and a block-connect time at several pool sizes, so
 * the growth curve is visible rather than a single number.
 *
 * Usage: ./bench_mempool_scale [max_entries]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

typedef unsigned char u8;
typedef unsigned long long u64;

extern void   mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern long   mpool_count(void* mp);
extern void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long   utxo_put(void* u, const u8 txid[32], unsigned index, u64 value, u64 h, u64 cb, const u8* spk, unsigned slen);
extern void   mpool_policy_init(void* pol, u64 relay, unsigned, unsigned, unsigned, unsigned, unsigned);
extern void   mpool_policy_set_acceptnonstd(void*, unsigned);
extern size_t mpool_policy_state_size(unsigned n);
extern void   mpool_policy_state_init(void* st, unsigned n);
extern long   mpool_policy_add(void* pol, void* st, void* mp, const u8* tx, unsigned long txlen, const u8 txid[32], void* utxo);
extern const char* mpool_policy_reason(void* pol);
extern int    tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
extern long   mpool_policy_block_connect(void* st, void* mp,
                                         const u8* block, unsigned long blen);

/* The policy layer calls mempool_resolve_confirmed_utxo rather than utxo_get
 * directly; this harness wants the plain single-table behaviour, same shim as
 * tests/test_mempool_policy.c. */
extern long utxo_get(void* u, const u8 txid[32], unsigned long index,
                     u64* value, unsigned long* height, unsigned long* is_coinbase,
                     const u8** script, unsigned long* slen);
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    unsigned long h_unused, cb_unused;
    return utxo_get(u, txid, index, value, &h_unused, &cb_unused, script, slen);
}

static double now_s(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec/1e9;
}

/* one-input one-output tx spending prev:0 */
static unsigned long mk(u8* o, const u8 prev[32], u64 outv, u8 spkbyte){
    unsigned long n = 0;
    o[n++]=2;o[n++]=0;o[n++]=0;o[n++]=0;
    o[n++]=1; memcpy(o+n, prev, 32); n+=32; memset(o+n,0,4); n+=4; o[n++]=0; memset(o+n,0xff,4); n+=4;
    o[n++]=1; for (int b=0;b<8;b++) o[n++]=(u8)(outv>>(8*b));
    o[n++]=22; o[n++]=0x00; o[n++]=0x14; memset(o+n, spkbyte, 20); n+=20;
    memset(o+n,0,4); n+=4;
    return n;
}
static void mk_prev(u8 p[32], unsigned i){ memset(p, 0x22, 32);
    p[0]=(u8)i; p[1]=(u8)(i>>8); p[2]=(u8)(i>>16); }

int main(int argc, char** argv){
    unsigned maxn = argc > 1 ? (unsigned)strtoul(argv[1], 0, 10) : 200000u;
    /* Block size, so the O(n) vs O(n*m) claim can be checked directly: with
     * per-transaction removal the block-connect column scales with BOTH the
     * pool and the block; with batch removal it should scale with the pool
     * only. */
    unsigned blk_tx = argc > 2 ? (unsigned)strtoul(argv[2], 0, 10) : 200u;
    if (blk_tx < 2) blk_tx = 2;
    if (blk_tx > 3000) blk_tx = 3000;

    static u8 pol[128];
    mpool_policy_init(pol, 0, 100000, 101000000, 100000, 101000000, 1);
    mpool_policy_set_acceptnonstd(pol, 1);

    unsigned cap = maxn + 1024;
    void* st = malloc(mpool_policy_state_size(cap));
    if (!st){ printf("SKIP: policy state alloc failed for cap=%u\n", cap); return 0; }
    mpool_policy_state_init(st, cap);

    unsigned long mpslots = 1; while (mpslots < (unsigned long)cap*2) mpslots <<= 1;
    void* mp = malloc(40 + mpslots*48 + 8);
    void* mblob = malloc((size_t)cap * 128 + (1u<<20));
    void* ux = malloc(40 + (size_t)mpslots*48 + 8);
    void* ublob = malloc((size_t)cap * 96 + (1u<<20));
    if (!mp || !mblob || !ux || !ublob){ printf("SKIP: fixture alloc failed\n"); return 0; }
    mpool_init(mp, mpslots, mblob, (size_t)cap * 128 + (1u<<20));
    utxo_init(ux, mpslots, ublob, (size_t)cap * 96 + (1u<<20));

    u8 spk1[2] = { 0x51, 0x00 };
    printf("MEM-12 scale: linear-scan cost in the policy layer\n");
    printf("(block size for the connect column: %u transactions)\n", blk_tx);
    printf("%10s %12s %12s %14s\n", "entries", "accepts/s", "us/accept", "blk-connect ms");

    unsigned next_report = 10000;
    double t_win = now_s(); unsigned win_start = 0;
    u8 tx[256]; u8 id[32]; u8 prev[32];

    for (unsigned i = 0; i < maxn; i++){
        mk_prev(prev, i);
        utxo_put(ux, prev, 0, 1000000ULL, 0, 0, spk1, 1);
        unsigned long n = mk(tx, prev, 900000ULL, (u8)(i & 0xff));
        /* The REAL txid, not a synthetic one: mpool_policy_block_connect
         * looks entries up by the txid it computes from the block's bytes,
         * so a synthetic id makes every lookup miss and the block-connect
         * column measures nothing. */
        { static u8 sc[4096]; tx_txid(id, tx, n, sc, sizeof sc); }
        if (mpool_policy_add(pol, st, mp, tx, n, id, ux) != 1){
            printf("  stopped at %u: %s\n", i, mpool_policy_reason(pol));
            maxn = i; break;
        }
        if (i + 1 == next_report){
            double dt = now_s() - t_win;
            unsigned did = i + 1 - win_start;
            double aps = did / dt, us = dt / did * 1e6;

            /* time a block connect over 200 of the resident transactions.
             * mpool_policy_block_connect takes a raw block, so one is
             * assembled: 80-byte header, tx count, coinbase, then 199 of the
             * transactions actually in the pool -- which is what makes the
             * find_claim / remove_confirmed work real. */
            unsigned ntx = blk_tx; if (ntx > i+1) ntx = i+1;
            static u8 blk[3000*128 + 256]; unsigned long bn = 0;
            memset(blk, 0, 80); bn = 80;
            if (ntx < 253) blk[bn++] = (u8)ntx;
            else { blk[bn++] = 0xfd; blk[bn++] = (u8)ntx; blk[bn++] = (u8)(ntx >> 8); }
            /* coinbase */
            blk[bn++]=2;blk[bn++]=0;blk[bn++]=0;blk[bn++]=0;
            blk[bn++]=1; memset(blk+bn,0,32); bn+=32; memset(blk+bn,0xff,4); bn+=4;
            blk[bn++]=1; blk[bn++]=0x51; memset(blk+bn,0xff,4); bn+=4;
            blk[bn++]=1; for (int b=0;b<8;b++) blk[bn++]=0;
            blk[bn++]=1; blk[bn++]=0x51; memset(blk+bn,0,4); bn+=4;
            for (unsigned k = 1; k < ntx; k++){
                unsigned src = i + 1 - k;
                mk_prev(prev, src);
                bn += mk(blk + bn, prev, 900000ULL, (u8)(src & 0xff));
            }
            double t0 = now_s();
            mpool_policy_block_connect(st, mp, blk, bn);
            double bc = (now_s() - t0) * 1000.0;

            printf("%10u %12.0f %12.1f %14.2f\n", i+1, aps, us, bc);
            fflush(stdout);
            t_win = now_s(); win_start = i + 1;
            next_report = next_report < 100000 ? next_report * 2 : next_report + 100000;
        }
    }
    printf("final pool: %ld entries\n", mpool_count(mp));
    return 0;
}
