/* tests/bench_utxo_put.c -- the applier's `put` phase, split, at production
 * sizing (plan B1, 2026-10-05). NOT a gate test: a benchmark.
 *
 * The logged pair of 2026-10-05 measured `put` at 7,812 s for the chain,
 * 2-3 us per spent input late in the chain -- far more than a hash insert.
 * This drives the same calls the applier makes (daemon/utxo_live.c Phase 5:
 * utxo_lsm_put per created output, undo_capture_and_del per spent input,
 * undo_commit + utxo_store_wal_drain per block) against a memtable of the
 * production size (2^25 slots), on one pinned core, and prints microseconds
 * per operation for each part: the insert, the prevout get inside the
 * capture, the undo record write, the tombstone del, and the block-end
 * commit + WAL drain. The split inside undo_capture_and_del comes from
 * undo_log.c's own counters (undo_split_ns), the same ones the daemon's
 * [bench] block line prints as put.get / put.undo / put.del.
 *
 *   phase A: NPUT outputs created in blocks of PERBLK (the set fills)
 *   phase B: NBLK blocks, each spending PERBLK random live outputs and
 *            creating PERBLK new ones -- the late-chain shape
 *
 * Usage: tests/bench_utxo_put [nput_millions] [nblk] [perblk] [flush_every_ops] [resolved]
 *   resolved=1: phase B captures with undo_capture_and_del_resolved -- the
 *   prevout handed in, as the applier does since plan B2 -- instead of the
 *   looking-up undo_capture_and_del. The before/after of B2 is the pair of
 *   runs with this 0 and 1.
 *   flush_every_ops > 0 flushes the memtable into runs during phase A, so
 *   phase B's spends resolve against RUNS (the production shape: a coin is
 *   usually older than the memtable); 0 (default) keeps everything in the
 *   memtable. Writes its WAL, runs and undo files in a private temp dir. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sched.h>
#include <sys/mman.h>
#include "test_tmpdir.h"

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned short u16; typedef unsigned long long u64;
extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], unsigned index, u64 value, unsigned long height, unsigned long is_coinbase, const u8* script, unsigned slen);
extern long utxo_store_wal_drain(void* st);
extern long undo_capture_and_del(void* lst, void* u, long height, const u8 txid[32], u32 index);
extern long undo_capture_and_del_resolved(void* lst, void* u, long height, const u8 txid[32], u32 index,
                                          u64 value, u32 utxo_height, u8 is_coinbase, const u8* script, u16 slen);
extern long undo_commit(long height);
extern void undo_set_split_timing(int on);
extern unsigned long long undo_split_ns(int k);

/* bitcoin_utxo_lsm.asm's state struct (168 bytes), as every caller mirrors it */
struct LST {
    long log_fd, idx_fd;
    u64 log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap;
    u64 next_run_no;
    void* tomb_hash_buf; u64 tomb_hash_mask;
};
#define SLOTS   (1ul << 25)                 /* production: dbcache=8192 -> bulk_slots=2^25 */
#define BLOB    (3ull << 30)
#define TOMB_CAP (32ull << 20)
#define MANIFEST_CAP 1024
/* the flush sorts one 128-byte descriptor per memtable entry in the scratch
 * (daemon/utxo_live.c sizes it slots*3): room for the entries + tombstones
 * between two flushes, plus the bloom and script areas */
#define SCRATCH_CAP(flush_every) ((u64)((flush_every) ? (flush_every) * 3 : 4096) * 128 + (4u << 20) + 65536)

static u64 now_ns(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (u64)t.tv_sec * 1000000000ull + (u64)t.tv_nsec; }
static u64 mix(u64 x){ x += 0x9E3779B97F4A7C15ull; x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull; x = (x ^ (x >> 27)) * 0x94D049BB133111EBull; return x ^ (x >> 31); }
static void key_of(u64 i, u8 out[32]){ for (int k = 0; k < 4; k++){ u64 v = mix(i * 4 + k + 1); memcpy(out + 8 * k, &v, 8); } }

int main(int argc, char** argv){
    u64 nput = (argc > 1 ? strtoull(argv[1], 0, 10) : 20) * 1000000ull;
    long nblk = argc > 2 ? atol(argv[2]) : 300;
    long perblk = argc > 3 ? atol(argv[3]) : 7000;
    u64 flush_every = argc > 4 ? strtoull(argv[4], 0, 10) : 0;
    int resolved = argc > 5 ? atoi(argv[5]) : 0;
    tt_isolate();
    { cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(3, &cs); if (sched_setaffinity(0, sizeof cs, &cs) != 0) fprintf(stderr, "(not pinned)\n"); }
    u64 scratch_cap = SCRATCH_CAP(flush_every);
    void* tomb = malloc(TOMB_CAP * 36); void* manifest = malloc(MANIFEST_CAP * 16);
    void* scratch = mmap(0, scratch_cap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    unsigned long usz = utxo_struct_size(SLOTS);
    void* ux = mmap(0, usz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    void* blob = mmap(0, BLOB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    u8* spent = calloc(nput / 8 + 1, 1);
    if (!tomb || !manifest || scratch == MAP_FAILED || ux == MAP_FAILED || blob == MAP_FAILED || !spent){ printf("alloc failed\n"); return 1; }
    struct LST lst; memset(&lst, 0, sizeof lst);
    lst.op_threshold = flush_every ? flush_every : (~0ull >> 1); lst.fill_threshold = ~0ull >> 1;   /* the flush is its own column */
    lst.tomb_buf = tomb; lst.tomb_cap = TOMB_CAP; lst.manifest_buf = manifest; lst.manifest_cap = MANIFEST_CAP;
    lst.scratch_buf = scratch; lst.scratch_cap = scratch_cap;
    if (utxo_lsm_init(&lst) != 1){ printf("lsm_init failed\n"); return 1; }
    utxo_init(ux, SLOTS, blob, BLOB);
    u8 spk[25] = { 0x76, 0xa9, 0x14 }; spk[23] = 0x88; spk[24] = 0xac;   /* a P2PKH-sized script */
    printf("bench_utxo_put: %llu outputs in, then %ld blocks x %ld spends + %ld creates; memtable 2^25 slots; flush every %llu ops%s\n",
           (unsigned long long)nput, nblk, perblk, perblk, (unsigned long long)flush_every, flush_every ? " (spends resolve against runs)" : " (never: all in the memtable)");
    printf("phase B capture: %s\n", resolved ? "undo_capture_and_del_resolved (the prevout handed in: plan B2)" : "undo_capture_and_del (looks the prevout up again)");

    /* ---- phase A: fill ---- */
    u64 tA0 = now_ns(), tdrain = 0; u8 key[32]; long h = 0;
    for (u64 i = 0; i < nput; i++){
        key_of(i, key); memcpy(spk + 3, key, 20);
        if (utxo_lsm_put(&lst, ux, key, 0, 50000 + (i & 0xffff), (unsigned long)h, 0, spk, 25) != 1){ printf("put %llu failed\n", (unsigned long long)i); return 1; }
        if ((i + 1) % (u64)perblk == 0){ u64 d0 = now_ns(); utxo_store_wal_drain(&lst); tdrain += now_ns() - d0; h++; }
    }
    u64 tA = now_ns() - tA0;
    printf("phase A: %llu run(s) on disk, %llu live\n", (unsigned long long)lst.manifest_n, (unsigned long long)lst.total_live);
    printf("phase A fill: put.ins %.3f us/op (incl. the buffered WAL append) | block-end WAL drain %.3f us/op (%.2f ms/block)\n",
           (double)(tA - tdrain) / 1e3 / (double)nput, (double)tdrain / 1e3 / (double)nput, (double)tdrain / 1e6 / (double)(nput / (u64)perblk));

    /* ---- phase B: the late-chain block ---- */
    undo_set_split_timing(1);
    u64 g0 = undo_split_ns(0), u0 = undo_split_ns(1), d0 = undo_split_ns(2);
    u64 tcap = 0, tins = 0, tcommit = 0, twal = 0, nspend = 0, ncreate = 0, rng = 12345;
    u64 next_i = nput;
    for (long b = 0; b < nblk; b++, h++){
        u64 c0 = now_ns();
        for (long s = 0; s < perblk; s++){
            u64 j; do { rng = mix(rng); j = rng % nput; } while (spent[j >> 3] & (1u << (j & 7)));
            spent[j >> 3] |= (u8)(1u << (j & 7));
            key_of(j, key);
            long cr;
            if (resolved){
                /* what phase A put for key j: the applier gets the same from Phase 1's ledger */
                memcpy(spk + 3, key, 20);
                cr = undo_capture_and_del_resolved(&lst, ux, h, key, 0, 50000 + (j & 0xffff), (u32)(j / (u64)perblk), 0, spk, 25);
            } else cr = undo_capture_and_del(&lst, ux, h, key, 0);
            if (cr != 1){ printf("capture+del of %llu failed at block %ld\n", (unsigned long long)j, h); return 1; }
            nspend++;
        }
        u64 c1 = now_ns(); tcap += c1 - c0;
        for (long s = 0; s < perblk; s++){
            key_of(next_i++, key); memcpy(spk + 3, key, 20);
            if (utxo_lsm_put(&lst, ux, key, 0, 60000 + (u64)s, (unsigned long)h, 0, spk, 25) != 1){ printf("put failed at block %ld\n", h); return 1; }
            ncreate++;
        }
        u64 c2 = now_ns(); tins += c2 - c1;
        if (undo_commit(h) != 1){ printf("commit failed at block %ld\n", h); return 1; }
        u64 c3 = now_ns(); tcommit += c3 - c2;
        utxo_store_wal_drain(&lst);
        twal += now_ns() - c3;
    }
    u64 gget = undo_split_ns(0) - g0, gundo = undo_split_ns(1) - u0, gdel = undo_split_ns(2) - d0;
    double ns = (double)nspend;
    printf("phase B, per spent input: put.get %.3f us | put.undo %.3f us | put.del %.3f us | capture total %.3f us (clock overhead %.3f us)\n",
           (double)gget / 1e3 / ns, (double)gundo / 1e3 / ns, (double)gdel / 1e3 / ns, (double)tcap / 1e3 / ns,
           ((double)tcap - (double)(gget + gundo + gdel)) / 1e3 / ns);
    printf("phase B, per created output: put.ins %.3f us\n", (double)tins / 1e3 / (double)ncreate);
    printf("phase B, per block: undo_commit %.3f ms | WAL drain %.3f ms | (%.3f + %.3f us per input)\n",
           (double)tcommit / 1e6 / (double)nblk, (double)twal / 1e6 / (double)nblk,
           (double)tcommit / 1e3 / ns, (double)twal / 1e3 / ns);
    double per_input = ((double)(gget + gundo + gdel) + (double)tins + (double)tcommit + (double)twal) / 1e3 / ns;
    printf("phase B, everything per spent input (one create per spend): %.3f us  [the pair's late-chain put was 2.0-3.1 us/input]\n", per_input);
    return 0;
}
