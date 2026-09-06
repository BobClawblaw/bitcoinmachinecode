/* tests/bench_utxo_probe.c -- what does one memtable probe cost at dbcache
 * scale, and where does the time go?
 *
 * WHY THIS EXISTS
 *   docs/audits/UTXO_CACHE_MODEL_SCOPE.md 4.1 sizes the bulk-mode memtable
 *   at 2^26..2^27 slots (3.2..6.4 GB of 48-byte slots). Before anyone
 *   spends assembly on a cache-line-aware probe (tags, SIMD tag compare,
 *   next-line prefetch) the program needs to know whether a utxo_get at that
 *   size is bound by the probe SEQUENCE (several dependent line misses, a
 *   tag would help) or by the FIRST line miss plus the blob record (nothing
 *   inside the slot helps; only issuing the address early does, which
 *   utxo_prefetch already does for the apply path).
 *
 * WHAT IT MEASURES, per (slots, load) pair -- default 2^16/2^22/2^26 at
 * 50% and 75%:
 *   - ns per utxo_get, hits and misses separately, in four shapes:
 *       dep        each get's key depends on the previous get's return
 *                  value, so the CPU cannot overlap probes: true latency.
 *       dep+pf     same chain, but utxo_prefetch was issued DIST gets
 *                  earlier for the key -- the daemon's STAGE A / STAGE B
 *                  shape (apply_block_inner walks every prevout a phase
 *                  before it looks any of them up).
 *       indep      a plain loop over independent keys: whatever
 *                  memory-level parallelism the core finds on its own.
 *       indep+pf   the loop with the same DIST-ahead prefetch.
 *       indep+pf+rec  the prefetch 2*DIST ahead, then DIST ahead a C walk
 *                  of the (now cached) slot that prefetches the BLOB RECORD
 *                  it points at: the two-phase shape a hit would need,
 *                  since blob_off is only known once the slot has arrived.
 *                  Modelled in C here to size the win; no assembly for it.
 *   - the probe-length histogram of the same query set, computed by a C
 *     mirror of the assembly's hash and walk (utxo_hash: FNV-1a over the
 *     first 8 txid bytes, XOR index, AND mask; linear probe, stride 48,
 *     wrap, stop at an empty slot). Every mirrored answer is checked
 *     against utxo_get's; a mismatch is a FAIL, so the histogram describes
 *     the probe the assembly actually made.
 *   - how many 64-byte lines the probe sequence touched, and how often the
 *     40 bytes a probe reads from the home slot (txid at +8, index at +40)
 *     straddle a line (48-byte slots at base+40: half of them do; the
 *     whole slot straddles three times in four).
 *   - how often the index field matched on a foreign slot, i.e. how often
 *     the 32-byte key compare ran and rejected (the case a hash tag would
 *     short-circuit). Prevout indexes are skewed towards 0 and 1 in real
 *     blocks, so the default index distribution is geometric (P(0)=1/2,
 *     P(1)=1/4, ...); --uniform-index gives the flat one for contrast.
 *
 *   The table is anonymous memory, 4 KiB pages, like the daemon's
 *   MAP_SHARED file mapping of utxo_lsm_table.map (file-backed mappings do
 *   not get transparent huge pages). --thp asks for MADV_HUGEPAGE so the
 *   TLB share of the cost can be read off the difference.
 *
 * Usage: bench_utxo_probe [--sizes 16,22,26] [--loads 50,75] [--queries LOG2]
 *                         [--cpu N] [--dist N] [--reps N] [--thp]
 *                         [--uniform-index] [--script-len N] [--pf-lines N]
 *   --pf-lines N uses utxo_prefetch_n(...,N) in place of utxo_prefetch
 *   (2 = the 2026-08-23 two-line hint; utxo_prefetch itself is 6).
 * Not part of `make test`: it needs ~6 GB and a quiet core. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sched.h>
#include <unistd.h>
#include <sys/mman.h>

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_put(void* u, const u8 txid[32], unsigned long index, u64 value,
                     unsigned long height, unsigned long is_coinbase,
                     const u8* script, unsigned long slen);
extern long utxo_get(void* u, const u8 txid[32], unsigned long index, u64* value,
                     unsigned long* height, unsigned long* is_coinbase,
                     const u8** script, unsigned long* slen);
extern long utxo_del(void* u, const u8 txid[32], unsigned long index);
extern void utxo_prefetch(void* u, const u8 txid[32], unsigned long index);
extern void utxo_prefetch_n(void* u, const u8 txid[32], unsigned long index, unsigned long lines);
extern long utxo_count(void* u);

/* ---- keys: deterministic from (set, i), no key array for the inserts ---- */
static u64 splitmix64(u64* s){
    u64 z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static int g_uniform_index = 0;
static long g_pf_lines = -1;   /* -1: utxo_prefetch; else utxo_prefetch_n(.., N) */
static void key_of(u64 set, u64 i, u8 txid[32], u32* index){
    u64 s = (set * 0xD1B54A32D192ED03ULL) ^ (i * 0x9E3779B97F4A7C15ULL);
    u64 w;
    for (int k = 0; k < 4; k++){ w = splitmix64(&s); memcpy(txid + 8*k, &w, 8); }
    w = splitmix64(&s);
    *index = g_uniform_index ? (u32)(w & 0xFFFF)
                             : (u32)__builtin_ctzll(w | (1ULL << 24));
}

/* ---- C mirror of bitcoin_utxo.asm's hash and probe walk ---- */
static u64 home_off(const u8* txid, u32 index, u64 mask){
    u32 h = 0x811c9dc5u;
    for (int k = 0; k < 8; k++){ h ^= txid[k]; h *= 16777619u; }
    return (((u64)h ^ (u64)index) & mask) * 48 + 40;
}
struct walk { int probes; int lines; int straddle; int keycmp; };
static long mirror_get(const u8* base, u64 mask, const u8* txid, u32 index, struct walk* w){
    u64 end = 40 + (mask + 1) * 48, home = home_off(txid, index, mask), off = home;
    u64 lo = (u64)-1, hi = 0, lo2 = (u64)-1, hi2 = 0; int wrapped = 0;
    w->probes = 0; w->keycmp = 0;
    w->straddle = ((home + 8) >> 6) != ((home + 47) >> 6);
    for (;;){
        w->probes++;
        const u8* s = base + off; u32 idx; memcpy(&idx, s + 40, 4);
        u64 a = off + 40, b = off + 43;
        int eq = 0;
        if (idx != 0xFFFFFFFFu && idx == index){ a = off + 8; eq = !memcmp(s + 8, txid, 32); if (!eq) w->keycmp++; }
        if (!wrapped){ if (a < lo) lo = a; if (b > hi) hi = b; } else { if (a < lo2) lo2 = a; if (b > hi2) hi2 = b; }
        if (idx == 0xFFFFFFFFu) break;
        if (eq){ w->lines = (int)((hi >> 6) - (lo >> 6) + 1) + (wrapped ? (int)((hi2 >> 6) - (lo2 >> 6) + 1) : 0); return 1; }
        off += 48; if (off >= end){ off = 40; wrapped = 1; }
        if (off == home) break;
    }
    w->lines = (int)((hi >> 6) - (lo >> 6) + 1) + (wrapped ? (int)((hi2 >> 6) - (lo2 >> 6) + 1) : 0);
    return 0;
}

struct q { u8 txid[32]; u32 index; u32 pad; };

static inline void pf(void* u, const struct q* p){
    if (g_pf_lines < 0) utxo_prefetch(u, p->txid, p->index); else utxo_prefetch_n(u, p->txid, p->index, (unsigned long)g_pf_lines);
}
/* phase two of the two-phase hint: the slot is cached now, so find it and
 * touch the record it points at (C mirror of the probe; blob base at u+16) */
static inline void pf_record(const u8* u, u64 mask, const struct q* p){
    u64 end = 40 + (mask + 1) * 48, home = home_off(p->txid, p->index, mask), off = home;
    const u8* blob; memcpy(&blob, u + 16, 8);
    for (;;){
        const u8* s = u + off; u32 idx; memcpy(&idx, s + 40, 4);
        if (idx == 0xFFFFFFFFu) return;
        if (idx == p->index && !memcmp(s + 8, p->txid, 32)){ u64 bo; memcpy(&bo, s, 8); __builtin_prefetch(blob + bo); return; }
        off += 48; if (off >= end) off = 40;
        if (off == home) return;
    }
}
static double now_ns(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec * 1e9 + ts.tv_nsec; }

/* mode: 0 dep, 1 dep+pf, 2 indep, 3 indep+pf, 4 indep+pf+rec */
static double time_gets(void* u, const struct q* qs, u64 Q, int mode, int dist, u64* found_out){
    u64 v = 0; unsigned long h, cb, sl; const u8* sp; u64 found = 0, qm = Q - 1;
    double t0 = now_ns();
    if (mode < 2){
        u64 j = 0;
        for (u64 i = 0; i < Q; i++){
            if (mode == 1) pf(u, &qs[(i + dist) & qm]);
            long r = utxo_get(u, qs[j].txid, qs[j].index, &v, &h, &cb, &sp, &sl);
            found += r;
            __asm__ volatile("" : "+r"(r));
            j = (j + 1 + (r >> 8)) & qm;      /* r>>8 is 0, but only the probe's result says so */
        }
    } else {
        for (u64 i = 0; i < Q; i++){
            if (mode >= 3) pf(u, &qs[(i + (mode == 4 ? 2 * dist : dist)) & qm]);
            if (mode == 4) pf_record((const u8*)u, ((const u64*)u)[1], &qs[(i + dist) & qm]);
            found += utxo_get(u, qs[i].txid, qs[i].index, &v, &h, &cb, &sp, &sl);
        }
    }
    double t1 = now_ns();
    *found_out = found;
    return (t1 - t0) / (double)Q;
}

static void* big_alloc(u64 bytes, int thp){
    void* p = mmap(0, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED){ perror("mmap"); exit(2); }
    if (thp) madvise(p, bytes, MADV_HUGEPAGE);
    return p;
}

#define NB 12
static const char* bname[NB] = {"1","2","3","4","5","6","7","8","9-16","17-32","33-64","65+"};
static int bucket(int n){ if (n <= 8) return n - 1; if (n <= 16) return 8; if (n <= 32) return 9; if (n <= 64) return 10; return 11; }

struct hist { u64 b[NB]; u64 n, probes, lines, straddle, keycmp, maxp; };
static void hist_add(struct hist* H, const struct walk* w){
    H->b[bucket(w->probes)]++; H->n++; H->probes += w->probes; H->lines += w->lines;
    H->straddle += w->straddle; H->keycmp += w->keycmp; if ((u64)w->probes > H->maxp) H->maxp = w->probes;
}
static void hist_print(const char* what, const struct hist* H){
    printf("    %-5s probes: mean %.2f max %lu | lines/probe-seq %.2f | home straddles line %.0f%% | foreign key compares/get %.3f\n",
           what, (double)H->probes / H->n, H->maxp, (double)H->lines / H->n,
           100.0 * H->straddle / H->n, (double)H->keycmp / H->n);
    printf("          hist:");
    for (int i = 0; i < NB; i++) if (H->b[i]) printf(" %s:%.1f%%", bname[i], 100.0 * H->b[i] / H->n);
    printf("\n");
}

static int run_one(int log2slots, int load_pct, int log2q, int dist, int reps, int thp, int slen, int* fails){
    u64 slots = 1ULL << log2slots, mask = slots - 1, n = slots * load_pct / 100, Q = 1ULL << log2q;
    u64 tsz = utxo_struct_size(slots), bsz = n * (24 + slen) + 4096;
    printf("== 2^%d slots (%.2f GB table), %d%% load = %lu entries, blob %.2f GB, %s pages ==\n",
           log2slots, tsz / 1e9, load_pct, n, bsz / 1e9, thp ? "THP-advised" : "4K");
    void* u = big_alloc(tsz, thp); void* blob = big_alloc(bsz, thp);
    utxo_init(u, slots, blob, bsz);
    u8 script[64]; for (int k = 0; k < 64; k++) script[k] = (u8)(0x76 + k);

    u8 txid[32]; u32 index;
    double t0 = now_ns();
    for (u64 i = 0; i < n; i++){
        key_of(1, i, txid, &index);
        long r = utxo_put(u, txid, index, i, (unsigned long)(i & 0xFFFFF), 0, script, slen);
        if (r != 1){ printf("FAIL put %lu -> %ld\n", i, r); (*fails)++; break; }
    }
    double put_ns = (now_ns() - t0) / (double)n;
    if ((u64)utxo_count(u) != n){ printf("FAIL count %ld != %lu\n", utxo_count(u), n); (*fails)++; }

    /* query sets: hits are random inserted keys, misses are fresh keys */
    struct q* hits = malloc(Q * sizeof *hits); struct q* miss = malloc(Q * sizeof *miss);
    u64 s = 0xC0FFEE ^ (u64)log2slots;
    for (u64 i = 0; i < Q; i++){
        key_of(1, splitmix64(&s) % n, hits[i].txid, &hits[i].index);
        key_of(2, i, miss[i].txid, &miss[i].index);
    }

    /* mirror walk: histogram + cross-check against the assembly */
    struct hist Hh, Hm; memset(&Hh, 0, sizeof Hh); memset(&Hm, 0, sizeof Hm);
    u64 mism = 0; u64 v; unsigned long h, cb, sl; const u8* sp;
    for (u64 i = 0; i < Q; i++){
        struct walk w;
        long m = mirror_get(u, mask, hits[i].txid, hits[i].index, &w);
        long a = utxo_get(u, hits[i].txid, hits[i].index, &v, &h, &cb, &sp, &sl);
        if (m != 1 || a != 1 || v >= n) mism++;
        hist_add(&Hh, &w);
        m = mirror_get(u, mask, miss[i].txid, miss[i].index, &w);
        a = utxo_get(u, miss[i].txid, miss[i].index, &v, &h, &cb, &sp, &sl);
        if (m != 0 || a != 0) mism++;
        hist_add(&Hm, &w);
    }
    if (mism){ printf("FAIL mirror walk disagrees with utxo_get on %lu queries\n", mism); (*fails)++; }

    printf("  put: %.1f ns/put (sequential inserts, includes first-touch page faults)\n", put_ns);
    static const char* mname[5] = {"dep", "dep+pf", "indep", "indep+pf", "indep+pf+rec"};
    printf("  %-12s %10s %10s\n", "ns/get", "hit", "miss");
    for (int mode = 0; mode < 5; mode++){
        double bh = 1e18, bm = 1e18; u64 f;
        for (int r = 0; r < reps; r++){
            double t = time_gets(u, hits, Q, mode, dist, &f); if (f != Q){ printf("FAIL hits found %lu/%lu\n", f, Q); (*fails)++; } if (t < bh) bh = t;
            t = time_gets(u, miss, Q, mode, dist, &f); if (f != 0){ printf("FAIL misses found %lu\n", f); (*fails)++; } if (t < bm) bm = t;
        }
        printf("  %-12s %10.1f %10.1f\n", mname[mode], bh, bm);
    }
    hist_print("hit", &Hh); hist_print("miss", &Hm);
    free(hits); free(miss); munmap(u, tsz); munmap(blob, bsz);
    return 0;
}

static int parse_list(const char* s, int* out, int max){
    int n = 0; while (*s && n < max){ out[n++] = atoi(s); const char* c = strchr(s, ','); if (!c) break; s = c + 1; } return n;
}

int main(int argc, char** argv){
    int sizes[8] = {16, 22, 26}, nsizes = 3, loads[8] = {50, 75}, nloads = 2;
    int log2q = 20, cpu = -1, dist = 16, reps = 3, thp = 0, slen = 25;
    for (int i = 1; i < argc; i++){
        if (!strcmp(argv[i], "--sizes") && i + 1 < argc) nsizes = parse_list(argv[++i], sizes, 8);
        else if (!strcmp(argv[i], "--loads") && i + 1 < argc) nloads = parse_list(argv[++i], loads, 8);
        else if (!strcmp(argv[i], "--queries") && i + 1 < argc) log2q = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cpu") && i + 1 < argc) cpu = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--dist") && i + 1 < argc) dist = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--reps") && i + 1 < argc) reps = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--script-len") && i + 1 < argc) slen = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--pf-lines") && i + 1 < argc) g_pf_lines = atol(argv[++i]);
        else if (!strcmp(argv[i], "--thp")) thp = 1;
        else if (!strcmp(argv[i], "--uniform-index")) g_uniform_index = 1;
        else { fprintf(stderr, "unknown arg %s\n", argv[i]); return 2; }
    }
    if (slen > 64) slen = 64;
    if (cpu < 0) cpu = (int)sysconf(_SC_NPROCESSORS_ONLN) - 2;
    { cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(cpu, &cs);
      if (sched_setaffinity(0, sizeof cs, &cs) != 0){ perror("sched_setaffinity"); return 2; } }
    printf("bench_utxo_probe: cpu %d, 2^%d queries per set, prefetch distance %d, %d reps (min reported), index %s, script %d B, prefetch %s\n",
           cpu, log2q, dist, reps, g_uniform_index ? "uniform" : "geometric", slen, g_pf_lines < 0 ? "utxo_prefetch" : "utxo_prefetch_n");
    int fails = 0;
    for (int a = 0; a < nsizes; a++) for (int b = 0; b < nloads; b++) run_one(sizes[a], loads[b], log2q, dist, reps, thp, slen, &fails);
    printf(fails ? "FAIL (%d)\n" : "OK\n", fails);
    return fails ? 1 : 0;
}
