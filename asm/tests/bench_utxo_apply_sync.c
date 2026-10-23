/* tests/bench_utxo_apply_sync.c -- the applier's sync cost per 1,000 blocks
 * (STO-A/STO-C, 2026-10-23). NOT a gate test: a benchmark.
 *
 * A synthetic chain shaped like a busy block -- NTX one-in two-out
 * transactions per block, every spend resolving the previous block's
 * output -- is written to an archive in the working directory, then applied
 * by utxo_live_catchup with the bulk memtable and the bulk checkpoint cadence
 * (what a sync does), or with a per-block checkpoint (the tip). The program
 * prints the wall clock of the catch-up and the durable prefixes taken; count
 * the syncs from outside:
 *
 *   tests/bench_utxo_apply_sync build <dir> <nblk> <ntx>
 *   strace -f -c -e trace=fsync,fdatasync tests/bench_utxo_apply_sync apply <dir> <ckpt>
 *
 * ckpt: -1 = the default cadence (bulk: 1,024 blocks or 60 s), 0 = per block.
 * build writes with the block store's per-block sync off and one fdatasync at
 * the end (the download committer's shape), so `apply` sees only the
 * applier's own syncs. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long long u64;
extern long store_init(void* st);
extern long store_reload(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void store_set_sync(int on);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  pow_check(const u8 hdr[80]);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
extern void sha256d(u8 out[32], const void* msg, long len);
extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_applied_height(void);
extern long utxo_live_count(void);
extern void utxo_live_close(void);
extern void utxo_live_test_force_sizing(int mode);
extern void utxo_live_test_set_ckpt_batch(long n);
extern unsigned long utxo_live_test_prefix_count(void) __attribute__((weak));   /* absent before STO-A */

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen; abort();
}

static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
static u8* put_cs(u8* q, u32 n){ if (n < 253){ *q++ = (u8)n; } else { *q++ = 0xfd; *q++ = (u8)n; *q++ = (u8)(n >> 8); } return q; }
static u8 g_scr[1 << 16];
static double now_s(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }

static void merkle(u8 root[32], u8 (*ids)[32], int n){
    static u8 lv[4096][32]; memcpy(lv, ids, (size_t)n * 32);
    while (n > 1){
        int m = 0;
        for (int i = 0; i < n; i += 2){ u8 pair[64]; memcpy(pair, lv[i], 32); memcpy(pair + 32, lv[i + 1 < n ? i + 1 : i], 32); sha256d(lv[m++], pair, 64); }
        n = m;
    }
    memcpy(root, lv[0], 32);
}
/* coinbase with `nout` OP_TRUE outputs sharing 50 BTC */
static long mk_coinbase(u8* q0, u32 tag, int nout){
    u8* q = q0;
    put32(q,1); q+=4; *q++ = 1; memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4; put32(q,0xffffffffu); q+=4;
    q = put_cs(q, (u32)nout);
    for (int i = 0; i < nout; i++){ put64(q, 5000000000ULL / (u64)nout); q+=8; *q++ = 1; *q++ = 0x51; }
    put32(q,0); q+=4;
    return q - q0;
}

static int build(int nblk, int ntx){
    static u8 st[4096]; store_init(st); store_reload(st); store_set_sync(0);
    static u8 blk[1 << 20], txs[1 << 20];
    static u8 ids[4096][32], prev_ids[4096][32];
    static u64 prev_val[4096];
    u8 prev[32]; memset(prev, 0, 32);
    int seed_h = 1, first_spend = 102;
    for (int h = 0; h < nblk; h++){
        int n = 0; u8* t = txs;
        long cbl = mk_coinbase(t, (u32)h, h == seed_h ? ntx : 1);
        tx_txid(ids[n++], t, (unsigned long)cbl, g_scr, sizeof g_scr); t += cbl;
        if (h == seed_h){ memcpy(prev_ids[0], ids[0], 32); for (int i = 0; i < ntx; i++) prev_val[i] = 5000000000ULL / (u64)ntx; }
        if (h >= first_spend){
            for (int i = 0; i < ntx; i++){
                u8* q = t;
                put32(q,1); q+=4; *q++ = 1;
                memcpy(q, h == first_spend ? prev_ids[0] : prev_ids[i + 1], 32); q+=32;
                put32(q, h == first_spend ? (u32)i : 0); q+=4; *q++ = 0; put32(q,0xffffffffu); q+=4;
                *q++ = 2; prev_val[i] -= 100;
                put64(q, prev_val[i]); q+=8; *q++ = 1; *q++ = 0x51;
                put64(q, 0); q+=8; *q++ = 1; *q++ = 0x51;
                put32(q,0); q+=4;
                tx_txid(ids[n++], t, (unsigned long)(q - t), g_scr, sizeof g_scr); t = q;
            }
            memcpy(prev_ids, ids, (size_t)n * 32);
        }
        u8 root[32]; merkle(root, ids, n);
        u8* o = blk;
        put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, root, 32); o+=32;
        put32(o, 1600000000u + (u32)h); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
        o = put_cs(o, (u32)n); memcpy(o, txs, (size_t)(t - txs)); o += t - txs;
        u32 nonce = 0; while (!pow_check(blk)) { nonce++; put32(blk + 76, nonce); }
        block_hash(prev, blk);
        if (store_append(st, prev, blk, o - blk) != h){ fprintf(stderr, "append %d failed\n", h); return 1; }
    }
    int bfd = *(int*)(st + 0), ifd = *(int*)(st + 8);
    if (bfd >= 0) fdatasync(bfd);
    if (ifd >= 0) fdatasync(ifd);
    printf("built %d blocks, %d spend tx each from height %d\n", nblk, ntx, first_spend);
    return 0;
}

static int apply(long ckpt){
    static u8 st[4096]; store_init(st); store_reload(st);
    utxo_live_test_force_sizing(ckpt == 0 ? 0 : 1);
    if (ckpt >= 0) utxo_live_test_set_ckpt_batch(ckpt);
    if (utxo_live_init(".") != 1){ fprintf(stderr, "init failed\n"); return 1; }
    long tip = *(int*)(st + 24);
    double t0 = now_s();
    long total = 0;
    while (utxo_live_applied_height() < tip){
        long r = utxo_live_catchup(st);
        if (r <= 0){ fprintf(stderr, "catchup -> %ld at %ld\n", r, utxo_live_applied_height()); return 1; }
        total += r;
    }
    double t1 = now_s();
    utxo_live_close();
    printf("applied %ld blocks to %ld in %.3f s (%.3f ms/block), live %ld, durable prefixes %ld\n",
           total, utxo_live_applied_height(), t1 - t0, (t1 - t0) * 1e3 / (double)total, utxo_live_count(),
           utxo_live_test_prefix_count ? (long)utxo_live_test_prefix_count() : -1L);
    return 0;
}

int main(int argc, char** argv){
    if (argc < 3){ fprintf(stderr, "usage: %s build <dir> <nblk> <ntx> | apply <dir> <ckpt>\n", argv[0]); return 2; }
    mkdir(argv[2], 0755);
    if (chdir(argv[2]) != 0){ perror("chdir"); return 2; }
    if (!strcmp(argv[1], "build") && argc == 5) return build(atoi(argv[3]), atoi(argv[4]));
    if (!strcmp(argv[1], "apply") && argc == 4) return apply(atol(argv[3]));
    return 2;
}
