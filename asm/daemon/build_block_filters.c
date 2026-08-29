/* daemon/build_block_filters.c -- backfill the BIP158 filter index over the
 * whole archive.
 *
 * WHY OFFLINE, AND WHY NOW: a block's filter needs its spent-prevout
 * scripts. Live blocks get them from undo data; HISTORY has no undo files
 * -- but since 2026-08-26 it has the TXID INDEX, which resolves any
 * outpoint to its creating transaction's bytes in the archive. That is
 * what makes a whole-chain filter backfill feasible at all: every input's
 * prevout script is one indexed lookup away.
 *
 * RESUMABLE by construction: bfi_open tells it how many records already
 * exist and it continues from there, so an interrupted multi-hour run
 * loses nothing. Never run this once the DAEMON has adopted the files
 * (see bfilter_index.c's writer-sequence contract).
 *
 * COST: ~2.4B prevout resolutions over the full chain. Two mitigations:
 * a small LRU of recently-resolved parent transactions (spends cluster:
 * consolidations drain many outputs of one parent), and the OS page cache
 * (spends skew heavily toward recent outputs, so the hot region of the
 * archive stays resident). Expect hours, not days -- and the progress
 * line says exactly where it is.
 *
 * Usage: build_block_filters <datadir> [to_height]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <pthread.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long u64;   /* matches txi_format.h uint64_t on x86-64 -- incident #49: no same-width type schisms */

#include "../block_filter.h"
#include "txi_format.h"

extern int  store_init(void* st);
extern int  store_reload(void* st);
extern int  store_rd_init(void* st);
extern long store_read_at(void* st, unsigned long h, void* out, long cap);
/* store_map_at hands back a pointer straight INTO the page cache: zero
 * copies, and zero syscalls once the file is mapped. That matters enormously
 * here -- resolving one prevout needs ~250 bytes of a parent transaction,
 * and store_read_at was copying the WHOLE parent block (up to 4MB) to get
 * them. At ~3,000 inputs per modern block that was tens of megabytes read
 * per block filtered, which is why this backfill was measured at 3.7
 * blocks/s and ~40 hours. The pointer is valid until the next map of a
 * different file, and parent_tx copies out of it immediately. */
extern const unsigned char* store_map_at(void* st, u64 h, u64 out[2]);
extern void store_map_init(void* st);
extern void store_map_random(int on);
extern int  tx_txid(void* out, const void* tx, unsigned long txlen, void* buf, unsigned long buflen);
extern void sha256d(u8 out[32], const void* msg, long long len);

extern long bfi_open(int rw);
extern int  bfi_create(void);
extern int  bfi_append(const u8* filter, unsigned long flen);
extern long bfi_count(void);

#define BLOCKBUF (8u << 20)
#define MAX_PREV 65536

/* ---- txid-index reader (base + tail), mirroring rpc_chain's ---- */
static const u8* g_txi; static u64 g_txi_n, g_txi_soff, g_txi_ns;
static const u8* g_tail; static u64 g_tail_sz;

static int txi_open_ro(void){
    int fd = open("txindex.dat", O_RDONLY);
    if (fd < 0) return 0;
    struct stat sb;
    if (fstat(fd, &sb) != 0){ close(fd); return 0; }
    void* m = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return 0;
    const u8* b = m;
    if (memcmp(b, TXI_MAGIC, 8)){ return 0; }
    for (int i = 0; i < 8; i++) g_txi_n    |= (u64)b[8+i]  << (8*i);
    for (int i = 0; i < 8; i++) g_txi_soff |= (u64)b[16+i] << (8*i);
    for (int i = 0; i < 8; i++) g_txi_ns   |= (u64)b[24+i] << (8*i);
    g_txi = b;
    fd = open(TXI_TAIL_FILE, O_RDONLY);
    if (fd >= 0){
        if (fstat(fd, &sb) == 0 && sb.st_size >= TXI_REC){
            u64 sz = (u64)sb.st_size - (u64)sb.st_size % TXI_REC;
            void* t = mmap(NULL, (size_t)sz, PROT_READ, MAP_SHARED, fd, 0);
            if (t != MAP_FAILED){ g_tail = t; g_tail_sz = sz; }
        }
        close(fd);
    }
    return 1;
}

/* ---- persistent archive mappings ---------------------------------------
 * store_map_at keeps ONE mapped block file per store state. Prevout parents
 * are scattered across the whole archive, so consecutive lookups almost never
 * land in the same file and that cache misses essentially every time: strace
 * over 20 blocks counted 33,432 munmap / 33,492 mmap / 33,406 open -- about
 * 1,670 full open+fstat+mmap+madvise+munmap+close cycles PER BLOCK, one per
 * prevout.
 *
 * The cost is not the syscalls, it is the lock. mmap and munmap take
 * mmap_lock for WRITE, so every resolver thread serialises against every
 * other one, and each munmap additionally shoots down TLBs across all cores.
 * That is why raising BFI_THREADS from 8 to 64 changed nothing -- the threads
 * were queueing on mmap_lock, not waiting on the device.
 *
 * So map each blk file ONCE and never unmap it. 8,414 files x 128MB is ~1TB
 * of address space and the VA budget is 128TB; resident memory is unchanged
 * because these are file pages the kernel reclaims on its own. After this the
 * fault path takes mmap_lock only for READ and the threads stop colliding. */
#define MAXBLKF 65536
static u8*   g_fbase[MAXBLKF];
static size_t g_flen[MAXBLKF];
static pthread_mutex_t g_fmu = PTHREAD_MUTEX_INITIALIZER;
static const u8* g_idxmap; static u64 g_idxlen;
static int g_map_random = 1;

/* map (or grow) blk<fno>.dat so that at least `need` bytes are addressable */
static const u8* blkfile(unsigned fno, u64 need){
    if (fno >= MAXBLKF) return NULL;
    u8* b = __atomic_load_n(&g_fbase[fno], __ATOMIC_ACQUIRE);
    if (b && need <= g_flen[fno]) return b;
    pthread_mutex_lock(&g_fmu);
    b = g_fbase[fno];
    if (!b || need > g_flen[fno]){
        char nm[24]; snprintf(nm, sizeof nm, "blk%05u.dat", fno);
        int fd = open(nm, O_RDONLY);
        if (fd >= 0){
            struct stat sb;
            if (fstat(fd, &sb) == 0 && (u64)sb.st_size >= need){
                void* m = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
                if (m != MAP_FAILED){
                    if (g_map_random) madvise(m, (size_t)sb.st_size, MADV_RANDOM);
                    /* the tip file grows while we run: replace, never unmap the
                     * old one -- another thread may still hold a pointer into it */
                    g_flen[fno] = (size_t)sb.st_size;
                    __atomic_store_n(&g_fbase[fno], (u8*)m, __ATOMIC_RELEASE);
                    b = m;
                }
            }
            close(fd);
        }
    }
    pthread_mutex_unlock(&g_fmu);
    return b;
}

/* height -> block payload, straight out of the persistent mapping.
 * index.dat: 48-byte positional records, [32..35] file_no u32,
 * [36..43] data_pos u64 (the [len][magic] frame), [44..47] data_size u32. */
static const u8* block_at(u64 h, u64* blen){
    if (!g_idxmap || (h + 1) * 48 > g_idxlen) return NULL;
    const u8* r = g_idxmap + h * 48;
    u32 fno = (u32)r[32] | ((u32)r[33]<<8) | ((u32)r[34]<<16) | ((u32)r[35]<<24);
    u64 pos = 0; for (int i = 0; i < 8; i++) pos |= (u64)r[36+i] << (8*i);
    u32 sz  = (u32)r[44] | ((u32)r[45]<<8) | ((u32)r[46]<<16) | ((u32)r[47]<<24);
    const u8* base = blkfile(fno, pos + 8 + sz);
    if (!base) return NULL;
    *blen = sz;
    return base + pos + 8;                 /* skip the [len][magic] frame */
}

static int idx_open_ro(void){
    int fd = open("index.dat", O_RDONLY);
    if (fd < 0) return 0;
    struct stat sb;
    if (fstat(fd, &sb) != 0 || sb.st_size < 48){ close(fd); return 0; }
    void* m = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return 0;
    g_idxmap = m; g_idxlen = (u64)sb.st_size;
    return 1;
}

static void* g_st;
static u8* g_blockbuf2;                     /* parent-tx block reads */
static u8* g_scratch;

/* ---- per-thread resolver context ----------------------------------------
 * Resolving a block's prevouts is thousands of INDEPENDENT random reads, so
 * it parallelises perfectly -- but only if nothing mutable is shared. Three
 * things were:
 *   - the store's mapping cache, which lives INSIDE the state passed to
 *     store_map_at (st+128), so each thread gets its own state;
 *   - the tx_txid scratch buffer;
 *   - the parent-tx LRU.
 * Each thread therefore carries its own. The txid index is mmap'd read-only
 * and shared freely. */
/* Parent-tx cache: DIRECT-MAPPED, not an LRU list.
 *
 * It was a 128-entry array scanned linearly on every lookup, and perf put
 * ~10% of the backfill's CPU in that scan. Enlarging it would have made
 * that worse, not better -- the scan is O(N).
 *
 * A txid is already a uniform hash, so its low bits are a perfectly good
 * index: one probe to look up, one store to insert, no eviction search. That
 * removes the scan AND makes capacity cheap, so the cache grows from 128 to
 * 4096 entries at the same time. A direct-mapped cache gives up some hit
 * rate to collisions relative to a true LRU of the same size, and wins it
 * straight back on capacity. */
#define LRU_N 4096                 /* power of two: indexed by txid low bits */
typedef struct {
    u8*  st;                       /* own store state -> own mapping cache */
    u8*  scratch;
    struct { u8 txid[32]; u8* tx; unsigned long len; } cache[LRU_N];
} rctx_t;

/* locate + verify a txid via the index; returns the tx bytes INSIDE
 * g_blockbuf2 (valid until the next call) and its length, or NULL. */
static const u8* txi_find(rctx_t* rc, const u8 txid_wire[32], unsigned long* txlen){
    const u8* recs = g_txi + TXI_HDR;
    const u8* sp   = g_txi + g_txi_soff;
    u64 lo = 0, hi = g_txi_ns ? g_txi_ns - 1 : 0, start = 0;
    while (g_txi_ns && lo <= hi){
        u64 mid = lo + (hi - lo) / 2;
        int c = memcmp(sp + mid * TXI_SPARSE, txid_wire, 8);
        if (c <= 0){
            u64 off = 0;
            for (int i = 0; i < 8; i++) off |= (u64)sp[mid*TXI_SPARSE + 8 + i] << (8*i);
            start = (off - TXI_HDR) / TXI_REC;
            lo = mid + 1;
        } else { if (mid == 0) break; hi = mid - 1; }
    }
    for (u64 i = start; i < g_txi_n; i++){
        const u8* r = recs + i * TXI_REC;
        int c = memcmp(r, txid_wire, 8);
        if (c < 0) continue;
        if (c > 0) break;
        u32 hh = 0, off = 0, ln = 0;
        for (int b = 0; b < 4; b++) hh  |= (u32)r[8+b]  << (8*b);
        for (int b = 0; b < 4; b++) off |= (u32)r[12+b] << (8*b);
        for (int b = 0; b < 4; b++) ln  |= (u32)r[16+b] << (8*b);
        u64 blen = 0;
        const u8* blk = block_at(hh, &blen);
        if (!blk) continue;
        if (blen < 81 || (u64)off + ln > blen || ln > BLOCKBUF) continue;
        u8 got[32];
        if (tx_txid(got, blk + off, ln, rc->scratch, BLOCKBUF) != 1) continue;
        if (memcmp(got, txid_wire, 32)) continue;
        *txlen = ln;
        return blk + off;
    }
    /* tail: unsorted scan */
    for (u64 o = 0; g_tail && o + TXI_REC <= g_tail_sz; o += TXI_REC){
        const u8* r = g_tail + o;
        if (memcmp(r, txid_wire, 8)) continue;
        u32 hh = 0, off = 0, ln = 0;
        for (int b = 0; b < 4; b++) hh  |= (u32)r[8+b]  << (8*b);
        for (int b = 0; b < 4; b++) off |= (u32)r[12+b] << (8*b);
        for (int b = 0; b < 4; b++) ln  |= (u32)r[16+b] << (8*b);
        u64 blen = 0;
        const u8* blk = block_at(hh, &blen);
        if (!blk) continue;
        if (blen < 81 || (u64)off + ln > blen || ln > BLOCKBUF) continue;
        u8 got[32];
        if (tx_txid(got, blk + off, ln, rc->scratch, BLOCKBUF) != 1) continue;
        if (memcmp(got, txid_wire, 32)) continue;
        *txlen = ln;
        return blk + off;
    }
    return NULL;
}


/* small LRU of resolved parent txs (consolidations drain one parent) */
static const u8* parent_tx(rctx_t* c, const u8 txid[32], unsigned long* len){
    /* the txid IS a hash, so its low bits index the cache directly */
    unsigned slot = ((unsigned)txid[0] | ((unsigned)txid[1] << 8) |
                     ((unsigned)txid[2] << 16)) & (LRU_N - 1);
    if (c->cache[slot].tx && !memcmp(c->cache[slot].txid, txid, 32)){
        *len = c->cache[slot].len;
        return c->cache[slot].tx;
    }
    unsigned long tl;
    const u8* t = txi_find(c, txid, &tl);
    if (!t) return NULL;
    /* the occupant of this slot loses -- one store, no search */
    u8* room = realloc(c->cache[slot].tx, tl);
    if (!room){ free(c->cache[slot].tx); c->cache[slot].tx = NULL; return NULL; }
    memcpy(room, t, tl);
    c->cache[slot].tx = room;
    memcpy(c->cache[slot].txid, txid, 32);
    c->cache[slot].len = tl;
    *len = tl;
    return room;
}

/* ---- parallel prevout resolution ----------------------------------------
 * Phase 1 walks the block and records every non-coinbase input's outpoint;
 * phase 2 resolves them across N threads; phase 3 assembles the scripts in
 * ORDER. Order matters only for reproducibility of the arena packing -- the
 * filter itself sorts its elements -- but keeping it makes the threaded
 * output byte-identical to the single-threaded output, which is how this is
 * verified. */
static int tx_output_spk_fwd(const u8* tx, unsigned long len, u32 index,
                             const u8** spk, unsigned long* slen);

typedef struct {
    const u8* op;                 /* 36-byte outpoint, inside blockbuf */
    u32  vout;
    unsigned long long txi;       /* tx index in the block, for the error */
    u8*  spk;                     /* resolved script, owned by this request */
    unsigned long spklen;
    int  ok;
} req_t;

typedef struct {
    rctx_t* ctx;
    req_t*  reqs;
    long    n;
    int     id, nthreads;
} worker_arg_t;

static void resolve_all(rctx_t* ctxs, int nthreads, req_t* reqs, long n);

/* ---- resolve one PARENT, not one input ----------------------------------
 * Two things were wrong with resolving each input independently.
 *
 * Inputs that spend the SAME parent transaction -- a consolidation draining
 * one funder, an exchange batch, any tx with several inputs from one payer --
 * each repeated the whole lookup: sparse binary search, record scan, archive
 * read, and a double-SHA256 over the parent to verify it. Only the per-thread
 * cache saved any of that.
 *
 * And the striping (i += nthreads) handed consecutive inputs to DIFFERENT
 * threads. Those are exactly the inputs most likely to share a parent, and
 * the caches are per-thread, so the one access pattern with real locality was
 * split across caches that cannot see each other.
 *
 * Grouping by txid fixes both at once: each distinct parent is located, read
 * and verified exactly once, and the members then differ only in which output
 * they take -- pure pointer arithmetic over bytes already in hand. */
static req_t* g_sortreqs;
static int cmp_by_txid(const void* a, const void* b){
    long ia = *(const long*)a, ib = *(const long*)b;
    int c = memcmp(g_sortreqs[ia].op, g_sortreqs[ib].op, 32);
    if (c) return c;
    return (ia > ib) - (ia < ib);            /* stable: keeps output order */
}
static long* g_order;                        /* req indices, sorted by txid */
static long* g_gstart;                       /* group i = order[gstart[i]..) */
static long  g_ngroups, g_ordercap;
static unsigned long long g_tot_inputs, g_tot_groups;   /* dedup accounting */

static void* resolve_worker(void* v){
    worker_arg_t* w = (worker_arg_t*)v;
    for (long g = w->id; g < g_ngroups; g += w->nthreads){
        long b = g_gstart[g], e = g_gstart[g+1];
        req_t* first = &w->reqs[g_order[b]];
        unsigned long ptl;
        const u8* ptx = parent_tx(w->ctx, first->op, &ptl);   /* ONCE per parent */
        if (!ptx) continue;
        for (long k = b; k < e; k++){
            req_t* r = &w->reqs[g_order[k]];
            const u8* spk; unsigned long slen;
            if (!tx_output_spk_fwd(ptx, ptl, r->vout, &spk, &slen)) continue;
            r->spk = malloc(slen ? slen : 1);
            if (!r->spk) continue;
            memcpy(r->spk, spk, slen);
            r->spklen = slen;
            r->ok = 1;
        }
    }
    return NULL;
}

/* Spread the requests over the threads and wait. Threads are created per
 * block: at ~13 blocks/s that is a few hundred pthread_create a second,
 * which is noise next to thousands of random reads, and it keeps the
 * lifetime rules trivial. */
static void resolve_all(rctx_t* ctxs, int nthreads, req_t* reqs, long n){
    if (n <= 0) return;
    /* group the requests by parent txid so each parent is resolved once */
    if (n + 1 > g_ordercap){
        long c = n + 1024;
        long* o = realloc(g_order, (size_t)c * sizeof *o);
        long* gs = realloc(g_gstart, (size_t)(c + 1) * sizeof *gs);
        if (!o || !gs){ free(o); free(gs); g_order = NULL; g_gstart = NULL; g_ordercap = 0; return; }
        g_order = o; g_gstart = gs; g_ordercap = c;
    }
    for (long i = 0; i < n; i++) g_order[i] = i;
    g_sortreqs = reqs;
    qsort(g_order, (size_t)n, sizeof *g_order, cmp_by_txid);
    g_ngroups = 0;
    for (long i = 0; i < n; ){
        g_gstart[g_ngroups++] = i;
        long j = i + 1;
        while (j < n && !memcmp(reqs[g_order[i]].op, reqs[g_order[j]].op, 32)) j++;
        i = j;
    }
    g_gstart[g_ngroups] = n;
    g_tot_inputs += (unsigned long long)n; g_tot_groups += (unsigned long long)g_ngroups;
    /* ALSO MEASURED AND REJECTED (2026-08-29): a two-phase resolve -- locate
     * every parent in the txid index first, sort those lookups into physical
     * (height, offset) order, then read the archive as a forward sweep. It is
     * the textbook fix for seek-bound random reads and it measured 3.32 blk/s
     * against 3.74 for this code at the same height (848k): 0.89x, WORSE.
     *
     * Two reasons, both visible in iostat:
     *   - Sorting cannot create adjacency here. A block has ~4,580 distinct
     *     parents scattered over a 1.13 TB archive, so even perfectly sorted
     *     the average gap between consecutive reads is ~246 MB. The seeks get
     *     ordered, not eliminated -- and on NVMe there is no rotational
     *     latency for that ordering to amortise. It is a spinning-disk
     *     optimisation applied to flash.
     *   - The barrier between phases COST concurrency: queue depth fell from
     *     ~7.3 to 1.41, because phase one must finish before phase two starts
     *     and the threads then drain unevenly.
     * The output was byte-identical, so it was correct -- just slower. Do not
     * retry without a device where seek ORDER actually matters.
     */
    /* MEASURED AND REJECTED (2026-08-29): batching madvise(WILLNEED) over every
     * distinct parent before the workers start does raise the queue depth
     * exactly as intended -- aqu-sz 7.5 -> ~500 -- and makes throughput WORSE.
     * Over 1000 blocks it ran 5.67 blk/s against 7.51 and 8.87 for the plain
     * build. The device delivers 12-17k reads/s whether the queue holds 7
     * requests or 533, so depth was never the constraint and the madvise
     * calls were pure added cost. Do not reintroduce this without a quiet
     * machine and a number that survives a drift control. */
    if (nthreads <= 1){
        worker_arg_t a = { &ctxs[0], reqs, n, 0, 1 };
        resolve_worker(&a);
        return;
    }
    pthread_t th[64];
    static worker_arg_t args[64];
    int started = 0;
    for (int i = 0; i < nthreads; i++){
        args[i] = (worker_arg_t){ &ctxs[i], reqs, n, i, nthreads };
        if (pthread_create(&th[i], NULL, resolve_worker, &args[i]) == 0) started++;
        else { /* fall back to doing this stripe inline rather than losing it */
               resolve_worker(&args[i]); }
    }
    for (int i = 0; i < started; i++) pthread_join(th[i], NULL);
}

/* output `index` of a raw tx: script ptr + len. 1 ok / 0 malformed. */
static int tx_output_spk_fwd(const u8* tx, unsigned long len, u32 index,
                             const u8** spk, unsigned long* slen);
static int tx_output_spk(const u8* tx, unsigned long len, u32 index,
                         const u8** spk, unsigned long* slen){
    const u8* p = tx + 4; const u8* end = tx + len;
    if (len < 10) return 0;
    if (p + 2 <= end && p[0] == 0x00 && p[1] == 0x01) p += 2;
    u64 cc, nin = txi_rd_varint(p, end, &cc); if (!cc || !nin) return 0;
    p += cc;
    for (u64 i = 0; i < nin; i++){
        if (p + 36 > end) return 0;
        p += 36;
        u64 sl = txi_rd_varint(p, end, &cc); if (!cc) return 0;
        p += cc;                       /* txi_rd_varint does NOT advance p */
        if ((u64)(end - p) < sl + 4) return 0;
        p += sl + 4;
    }
    u64 nout = txi_rd_varint(p, end, &cc); if (!cc || index >= nout) return 0;
    p += cc;
    for (u64 i = 0; i < nout; i++){
        if (p + 8 > end) return 0;
        p += 8;
        u64 sl = txi_rd_varint(p, end, &cc); if (!cc) return 0;
        p += cc;
        if ((u64)(end - p) < sl) return 0;
        if (i == index){ *spk = p; *slen = (unsigned long)sl; return 1; }
        p += sl;
    }
    return 0;
}

int main(int argc, char** argv){
    if (argc < 2){ fprintf(stderr, "usage: build_block_filters <datadir> [to_height]\n"); return 2; }
    if (chdir(argv[1])){ perror("chdir"); return 1; }
    long to_h = argc > 2 ? atol(argv[2]) : -1;

    static u8 store_buf[4096];
    if (store_init(store_buf) != 1){ fprintf(stderr, "store_init failed\n"); return 1; }
    store_reload(store_buf);
    store_rd_init(store_buf);
    g_st = store_buf;
    store_map_init(g_st);      /* the mapping cache txi_find reads through */
    /* MADV_RANDOM stays on for the ARCHIVE. The original reasoning counted
     * BYTES saved, which is the wrong axis for a latency-bound workload --
     * but measuring it the other way agreed anyway: off ran 92.68s against
     * 53.75s. Applying the same MADV_RANDOM to the TXID INDEX, by contrast,
     * was 2.2x SLOWER (67.26s vs 30.51s): a lookup there walks a <=256-record
     * run, so readahead amortises the next fault instead of wasting it. Two
     * mappings, opposite answers -- neither is guessable from byte counts. */
    store_map_random(1);
    if (!idx_open_ro()){ fprintf(stderr, "index.dat required\n"); return 1; }
    long tip = *(int*)(store_buf + 24);
    if (to_h < 0 || to_h > tip) to_h = tip;

    if (!txi_open_ro()){ fprintf(stderr, "txindex.dat required (build it first)\n"); return 1; }

    long n = bfi_open(1);
    if (n < 0){ if (!bfi_create()){ fprintf(stderr, "cannot create filter index files\n"); return 1; } n = 0; }
    fprintf(stderr, "[bfilter] resuming at height %ld, target %ld\n", n, to_h);

    /* one resolver context per thread: its own store state (hence its own
     * mapping cache), scratch and LRU. -j or BFI_THREADS picks the count. */
    int nthreads = 8;
    { const char* e = getenv("BFI_THREADS"); if (e && atoi(e) > 0) nthreads = atoi(e); }
    if (nthreads > 64) nthreads = 64;
    rctx_t* ctxs = calloc((size_t)nthreads, sizeof *ctxs);
    if (!ctxs){ fprintf(stderr, "oom\n"); return 1; }
    for (int i = 0; i < nthreads; i++){
        ctxs[i].st = malloc(4096);
        ctxs[i].scratch = malloc(BLOCKBUF);
        if (!ctxs[i].st || !ctxs[i].scratch){ fprintf(stderr, "oom\n"); return 1; }
        if (store_init(ctxs[i].st) != 1){ fprintf(stderr, "store_init failed\n"); return 1; }
        store_reload(ctxs[i].st);
        store_rd_init(ctxs[i].st);
        store_map_init(ctxs[i].st);
    }
    fprintf(stderr, "[bfilter] resolving prevouts on %d thread(s)\n", nthreads);
    static req_t reqs[MAX_PREV];

    u8* blockbuf = malloc(BLOCKBUF);
    g_blockbuf2 = malloc(BLOCKBUF);
    g_scratch = malloc(BLOCKBUF);
    static bf_script prev[MAX_PREV];
    static u8 prevcopy[MAX_PREV * 128]; /* most prevout spks are tiny; big ones malloc'd */
    static u8 filter[1u << 20];
    if (!blockbuf || !g_blockbuf2 || !g_scratch){ fprintf(stderr, "oom\n"); return 1; }

    time_t t0 = time(NULL);
    for (long h = n; h <= to_h; h++){
        long blen = store_read_at(g_st, (unsigned long)h, blockbuf, BLOCKBUF);
        if (blen < 81){ fprintf(stderr, "[bfilter] FATAL: block %ld unreadable (%ld)\n", h, blen); return 1; }
        /* collect every input's prevout script (coinbase skipped) */
        unsigned long np = 0, copyoff = 0;
        /* Prevout scripts too big for the inline arena. This was a FIXED
         * array of 64, and a block with more than 64 such scripts aborted
         * the whole backfill -- which is exactly what happened at height
         * 425,211 (large bare-multisig was common in 2016), and why the
         * mainnet filter index had been stuck there ever since. Nothing in
         * consensus caps this at 64, so neither does this. */
        u8** bigalloc = NULL; int nbig = 0, bigcap = 0;
        const u8* p = blockbuf + 80; const u8* end = blockbuf + blen;
        u64 cc, ntx = txi_rd_varint(p, end, &cc);
        if (!cc){ fprintf(stderr, "[bfilter] FATAL: block %ld malformed\n", h); return 1; }
        p += cc;
        int fatal = 0;

        /* ---- stage A: collect every non-coinbase outpoint (parse only,
         * no IO) so stage B can resolve them all at once, in parallel. */
        long nreq = 0;
        { const u8* q = p; u64 c2;
          for (u64 t = 0; t < ntx; t++){
              if (q + 4 > end){ fatal = 1; break; }
              q += 4;
              int sw = (q + 2 <= end && q[0] == 0x00 && q[1] == 0x01);
              if (sw) q += 2;
              u64 nin2 = txi_rd_varint(q, end, &c2); if (!c2){ fatal = 1; break; }
              q += c2;
              for (u64 i = 0; i < nin2; i++){
                  if (q + 36 > end){ fatal = 1; break; }
                  const u8* op2 = q;
                  q += 36;
                  u64 sl2 = txi_rd_varint(q, end, &c2); if (!c2){ fatal = 1; break; }
                  q += c2;
                  if ((u64)(end - q) < sl2 + 4){ fatal = 1; break; }
                  q += sl2 + 4;
                  if (t == 0) continue;
                  if (nreq >= MAX_PREV){ fprintf(stderr, "[bfilter] FATAL: h=%ld too many inputs\n", h); return 1; }
                  reqs[nreq].op = op2;
                  reqs[nreq].vout = (u32)(op2[32] | op2[33]<<8 | op2[34]<<16 | (u32)op2[35]<<24);
                  reqs[nreq].txi = (unsigned long long)t;
                  reqs[nreq].spk = NULL; reqs[nreq].spklen = 0; reqs[nreq].ok = 0;
                  nreq++;
              }
              if (fatal) break;
              u64 nout2 = txi_rd_varint(q, end, &c2); if (!c2){ fatal = 1; break; }
              q += c2;
              for (u64 i = 0; i < nout2; i++){
                  if (q + 8 > end){ fatal = 1; break; }
                  q += 8;
                  u64 osl = txi_rd_varint(q, end, &c2); if (!c2){ fatal = 1; break; }
                  q += c2;
                  if ((u64)(end - q) < osl){ fatal = 1; break; }
                  q += osl;
              }
              if (fatal) break;
              if (sw){
                  /* witness: one stack per input, each a vector of items */
                  for (u64 i = 0; i < nin2 && !fatal; i++){
                      u64 nit = txi_rd_varint(q, end, &c2); if (!c2){ fatal = 1; break; }
                      q += c2;
                      for (u64 k = 0; k < nit; k++){
                          u64 il = txi_rd_varint(q, end, &c2); if (!c2){ fatal = 1; break; }
                          q += c2;
                          if ((u64)(end - q) < il){ fatal = 1; break; }
                          q += il;
                      }
                  }
                  if (fatal) break;
              }
              if (q + 4 > end){ fatal = 1; break; }
              q += 4;                                   /* nLockTime */
          } }
        if (fatal){ fprintf(stderr, "[bfilter] FATAL: block %ld malformed (prepass)\n", h); return 1; }

        /* ---- stage B: resolve them across threads. Independent random
         * reads, so this is where the wall-clock actually goes. */
        resolve_all(ctxs, nthreads, reqs, nreq);
        long reqpos = 0;

        for (u64 t = 0; t < ntx && !fatal; t++){
            if (p + 4 > end){ fatal = 1; break; }
            p += 4;
            int segwit = (p + 2 <= end && p[0] == 0x00 && p[1] == 0x01);
            if (segwit) p += 2;
            u64 nin = txi_rd_varint(p, end, &cc); if (!cc){ fatal = 1; break; }
            p += cc;
            for (u64 i = 0; i < nin; i++){
                if (p + 36 > end){ fatal = 1; break; }
                const u8* op = p;
                p += 36;
                u64 sl = txi_rd_varint(p, end, &cc); if (!cc){ fatal = 1; break; }
                p += cc;
                if ((u64)(end - p) < sl + 4){ fatal = 1; break; }
                p += sl + 4;
                if (t == 0) continue;                       /* coinbase input */
                /* stage C: take the answer stage B already produced. The
                 * order matches because both walks visit inputs in the same
                 * order -- asserted, not assumed. */
                if (reqpos >= nreq || reqs[reqpos].op != op){
                    fprintf(stderr, "[bfilter] FATAL: h=%ld prepass/walk disagree at input %ld\n", h, reqpos);
                    return 1;
                }
                const u8* spk = reqs[reqpos].spk; unsigned long spklen = reqs[reqpos].spklen;
                int resolved = reqs[reqpos].ok;
                reqpos++;
                if (!resolved){
                    fprintf(stderr, "[bfilter] FATAL: h=%ld tx=%llu prevout unresolvable via txindex\n",
                            h, (unsigned long long)t);
                    return 1;                                /* NEVER emit a filter missing elements */
                }
                if (np >= MAX_PREV){ fprintf(stderr, "[bfilter] FATAL: h=%ld too many inputs\n", h); return 1; }
                if (spklen <= 128 && copyoff + spklen <= sizeof prevcopy){
                    memcpy(prevcopy + copyoff, spk, spklen);
                    prev[np].script = prevcopy + copyoff; prev[np].len = spklen;
                    copyoff += spklen;
                } else {
                    if (nbig == bigcap){
                        int nc = bigcap ? bigcap * 2 : 64;
                        u8** nb = realloc(bigalloc, (size_t)nc * sizeof *nb);
                        if (!nb){ fprintf(stderr, "[bfilter] FATAL: h=%ld oom growing prevout list\n", h);
                                  for (int i = 0; i < nbig; i++) free(bigalloc[i]);
                                  free(bigalloc); return 1; }
                        bigalloc = nb; bigcap = nc;
                    }
                    bigalloc[nbig] = malloc(spklen);
                    if (!bigalloc[nbig]){ fprintf(stderr, "[bfilter] FATAL: h=%ld oom\n", h);
                                          for (int i = 0; i < nbig; i++) free(bigalloc[i]);
                                          free(bigalloc); return 1; }
                    memcpy(bigalloc[nbig], spk, spklen);
                    prev[np].script = bigalloc[nbig]; prev[np].len = spklen;
                    nbig++;
                }
                np++;
            }
            if (fatal) break;
            u64 nout = txi_rd_varint(p, end, &cc); if (!cc){ fatal = 1; break; }
            p += cc;
            for (u64 i = 0; i < nout; i++){
                if (p + 8 > end){ fatal = 1; break; }
                p += 8;
                u64 sl = txi_rd_varint(p, end, &cc); if (!cc){ fatal = 1; break; }
                p += cc;
                if ((u64)(end - p) < sl){ fatal = 1; break; }
                p += sl;
            }
            if (fatal) break;
            if (segwit){
                for (u64 i = 0; i < nin; i++){
                    u64 items = txi_rd_varint(p, end, &cc); if (!cc){ fatal = 1; break; }
                    p += cc;
                    for (u64 k = 0; k < items; k++){
                        u64 il = txi_rd_varint(p, end, &cc);
                        if (!cc){ fatal = 1; break; }
                        p += cc;
                        if ((u64)(end - p) < il){ fatal = 1; break; }
                        p += il;
                    }
                    if (fatal) break;
                }
            }
            if (fatal) break;
            if (p + 4 > end){ fatal = 1; break; }
            p += 4;
        }
        if (fatal){ fprintf(stderr, "[bfilter] FATAL: block %ld malformed mid-walk\n", h); return 1; }

        u8 hash[32]; sha256d(hash, blockbuf, 80);
        long fl = bf_basic_build(blockbuf, (unsigned long)blen, hash, prev, np, filter, sizeof filter);
        for (int i = 0; i < nbig; i++) free(bigalloc[i]);
        if (fl <= 0){ fprintf(stderr, "[bfilter] FATAL: build failed at %ld\n", h); return 1; }
        if (!bfi_append(filter, (unsigned long)fl)){
            fprintf(stderr, "[bfilter] FATAL: append failed at %ld\n", h); return 1; }

        if (h % 5000 == 0)
            fprintf(stderr, "[bfilter] %ld/%ld (%llds elapsed)\n",
                    h, to_h, (long long)(time(NULL) - t0));
    }
    fprintf(stderr, "[bfilter] DONE: %ld filters, %llds\n", bfi_count(), (long long)(time(NULL) - t0));
    fprintf(stderr, "[bfilter] prevouts: %llu inputs -> %llu distinct parents (%.2fx dedup)\n", g_tot_inputs, g_tot_groups, g_tot_groups ? (double)g_tot_inputs/(double)g_tot_groups : 0.0);
    return 0;
}

static int tx_output_spk_fwd(const u8* tx, unsigned long len, u32 index,
                             const u8** spk, unsigned long* slen){
    return tx_output_spk(tx, len, index, spk, slen);
}
