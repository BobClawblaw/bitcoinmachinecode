/* bench_lsm_flush_sort [N] [T] [cpu] -- time the SORT STEP of a UTXO memtable
 * flush in isolation, on one pinned core.
 *
 * mac_flush (bitcoin_utxo_lsm.asm) walks the memtable's live slots into
 * 64-byte descriptors (key36 + type + value/slen/height/cb + script ptr),
 * appends this generation's tombstones as DEL descriptors, then sorts the
 * whole array by key before writing the run. This tool rebuilds exactly that
 * descriptor array -- N descriptors in the flush's own build order: the live
 * entries in slot order, then T tombstones -- and times utxo_lsm_sort_desc on
 * it, restoring the unsorted input before every repetition.
 *
 * Defaults model a bulk-mode flush (UTXO_LIVE_BULK_SLOTS_LOG2 22 in
 * daemon/utxo_live.c: 2^22 slots, fill_threshold 3M): N = 4,000,000
 * descriptors of which T = 1,000,000 are tombstones, i.e. 3M live keys in a
 * 4M-slot table. Keys are uniform (splitmix64), as SHA256d outpoints are.
 *
 * Not a test: prints timings. The Makefile builds it; nothing runs it. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sched.h>

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_put(void* u, const u8 txid[32], unsigned long index, unsigned long long value,
                     unsigned long height, unsigned long is_coinbase, const u8* script, unsigned long slen);
extern void utxo_lsm_sort_desc(void* a, void* b, unsigned long n);
extern void utxo_lsm_set_sort_mode(long mode);   /* 0 = merge sort, 1 = radix */

static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }
static u64 sm_state = 0x9E3779B97F4A7C15ULL;
static u64 sm(void){ u64 z = (sm_state += 0x9E3779B97F4A7C15ULL); z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL; z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL; return z ^ (z >> 31); }
static void rnd_txid(u8 t[32]){ for (int k = 0; k < 4; k++){ u64 v = sm(); memcpy(t + 8*k, &v, 8); } }

static int cmp36(const u8* p, const u8* q){ return memcmp(p, q, 36); }

int main(int argc, char** argv){
    unsigned long N = argc > 1 ? strtoul(argv[1], 0, 10) : 4000000UL;
    unsigned long T = argc > 2 ? strtoul(argv[2], 0, 10) : N / 4;
    int cpu = argc > 3 ? atoi(argv[3]) : 2;
    if (T > N){ fprintf(stderr, "T > N\n"); return 1; }
    unsigned long live = N - T;
    { cpu_set_t one; CPU_ZERO(&one); CPU_SET(cpu, &one);
      if (sched_setaffinity(0, sizeof one, &one) != 0) perror("sched_setaffinity (continuing unpinned)"); }

    /* memtable: 2^22 slots (bulk mode), grown only if `live` would overfill it */
    unsigned long slots = 1UL << 22;
    while (live > slots * 3 / 4) slots <<= 1;
    unsigned long blob_cap = live * 64 + (1UL << 20);
    void* table = malloc((size_t)utxo_struct_size(slots)); void* blob = malloc(blob_cap);
    if (!table || !blob){ fprintf(stderr, "malloc\n"); return 1; }
    utxo_init(table, slots, blob, blob_cap);
    u8 spk[34]; memset(spk, 0x51, sizeof spk); spk[1] = 0x20;   /* P2TR-shaped, 34 bytes */
    double f0 = now();
    for (unsigned long i = 0; i < live; i++){
        u8 txid[32]; rnd_txid(txid);
        if (utxo_put(table, txid, (unsigned long)(sm() & 3), 1000 + i, 100 + (i % 50), 0, spk, 34) != 1){ fprintf(stderr, "put %lu failed\n", i); return 1; }
    }
    double fill_s = now() - f0;

    /* descriptors, built the way mac_flush builds them (see its slot walk) */
    u8* orig = malloc(N * 64); u8* a = malloc(N * 64); u8* b = malloc(N * 64);
    if (!orig || !a || !b){ fprintf(stderr, "malloc\n"); return 1; }
    memset(orig, 0, N * 64);
    unsigned long n = 0;
    u8* u = table; u64 mask = *(u64*)(u + 8); u8* blobbase = *(u8**)(u + 16);
    for (u64 s = 0; s <= mask; s++){
        u8* slot = u + 40 + s * 48;
        if (*(u32*)(slot + 40) == 0xFFFFFFFFu) continue;
        u8* d = orig + n * 64;
        memcpy(d, slot + 8, 32); *(u32*)(d + 32) = *(u32*)(slot + 40); d[36] = 1;
        u8* rec = blobbase + *(u64*)slot;
        memcpy(d + 40, rec, 8); *(u32*)(d + 50) = *(u32*)(rec + 8); d[54] = rec[12];
        *(uint16_t*)(d + 48) = (uint16_t)*(u64*)(rec + 16); *(u8**)(d + 56) = rec + 24;
        n++;
    }
    if (n != live){ fprintf(stderr, "walk found %lu live, expected %lu\n", n, live); return 1; }
    for (unsigned long i = 0; i < T; i++){ u8* d = orig + n * 64; rnd_txid(d); *(u32*)(d + 32) = (u32)(sm() & 3); d[36] = 2; n++; }

    printf("bench_lsm_flush_sort: N=%lu descriptors (%lu live + %lu tombstones), %lu slots, pinned cpu %d, fill %.2fs\n",
           N, live, T, slots, cpu, fill_s);
    static const char* const mode_name[2] = { "merge", "radix" };
    double best[2] = { 1e30, 1e30 };
    u8* ref = malloc(N * 64);
    if (!ref){ fprintf(stderr, "malloc\n"); return 1; }
    for (int mode = 0; mode < 2; mode++){
        utxo_lsm_set_sort_mode(mode);
        for (int rep = 0; rep < 3; rep++){
            memcpy(a, orig, N * 64); memset(b, 0, N * 64);
            double t0 = now(); utxo_lsm_sort_desc(a, b, N); double dt = now() - t0;
            unsigned long pushes = 0, bad = 0;
            for (unsigned long i = 0; i < N; i++){ pushes += a[i * 64 + 36] == 1; if (i && cmp36(a + (i - 1) * 64, a + i * 64) > 0) bad++; }
            if (bad || pushes != live){ printf("  %s rep %d: NOT SORTED (%lu inversions, %lu pushes)\n", mode_name[mode], rep, bad, pushes); return 1; }
            if (mode == 0 && rep == 0) memcpy(ref, a, N * 64);
            else if (memcmp(ref, a, N * 64) != 0){ printf("  %s rep %d: output differs from the merge sort's\n", mode_name[mode], rep); return 1; }
            printf("  %s rep %d: sort %.1f ms  (%.1f ns/key, %.0f MB/s of descriptors)\n", mode_name[mode], rep, dt * 1e3, dt * 1e9 / N, (double)N * 64 / dt / 1e6);
            if (dt < best[mode]) best[mode] = dt;
        }
    }
    printf("best: merge %.1f ms, radix %.1f ms for N=%lu (%.1f vs %.1f ns/key, %.2fx)\n",
           best[0] * 1e3, best[1] * 1e3, N, best[0] * 1e9 / N, best[1] * 1e9 / N, best[0] / best[1]);
    return 0;
}
