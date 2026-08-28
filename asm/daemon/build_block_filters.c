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
#define LRU_N 128
typedef struct {
    u8*  st;                       /* own store state -> own mapping cache */
    u8*  scratch;
    struct { u8 txid[32]; u8* tx; unsigned long len; long stamp; } lru[LRU_N];
    long stamp;
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
        u64 mo[2];
        const u8* blk = store_map_at(rc->st, hh, mo);
        if (!blk) continue;
        u64 blen = mo[0];
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
        u64 mo[2];
        const u8* blk = store_map_at(rc->st, hh, mo);
        if (!blk) continue;
        u64 blen = mo[0];
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
    for (int i = 0; i < LRU_N; i++)
        if (c->lru[i].tx && !memcmp(c->lru[i].txid, txid, 32)){
            c->lru[i].stamp = ++c->stamp; *len = c->lru[i].len; return c->lru[i].tx; }
    unsigned long tl;
    const u8* t = txi_find(c, txid, &tl);
    if (!t) return NULL;
    int victim = 0;
    for (int i = 0; i < LRU_N; i++){
        if (!c->lru[i].tx){ victim = i; break; }
        if (c->lru[i].stamp < c->lru[victim].stamp) victim = i;
    }
    free(c->lru[victim].tx);
    c->lru[victim].tx = malloc(tl);
    if (!c->lru[victim].tx) return NULL;
    memcpy(c->lru[victim].tx, t, tl);
    memcpy(c->lru[victim].txid, txid, 32);
    c->lru[victim].len = tl; c->lru[victim].stamp = ++c->stamp;
    *len = tl;
    return c->lru[victim].tx;
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

static void* resolve_worker(void* v){
    worker_arg_t* w = (worker_arg_t*)v;
    for (long i = w->id; i < w->n; i += w->nthreads){
        req_t* r = &w->reqs[i];
        unsigned long ptl;
        const u8* ptx = parent_tx(w->ctx, r->op, &ptl);
        const u8* spk; unsigned long slen;
        if (!ptx || !tx_output_spk_fwd(ptx, ptl, r->vout, &spk, &slen)) continue;
        r->spk = malloc(slen ? slen : 1);
        if (!r->spk) continue;
        memcpy(r->spk, spk, slen);
        r->spklen = slen;
        r->ok = 1;
    }
    return NULL;
}

/* Spread the requests over the threads and wait. Threads are created per
 * block: at ~13 blocks/s that is a few hundred pthread_create a second,
 * which is noise next to thousands of random reads, and it keeps the
 * lifetime rules trivial. */
static void resolve_all(rctx_t* ctxs, int nthreads, req_t* reqs, long n){
    if (n <= 0) return;
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
    /* This workload reads ONE transaction out of a block picked at random
     * from the whole archive, so the kernel's readahead is pure waste --
     * measured at ~45KB pulled in per 250 bytes used. */
    store_map_random(1);
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
    return 0;
}

static int tx_output_spk_fwd(const u8* tx, unsigned long len, u32 index,
                             const u8** spk, unsigned long* slen){
    return tx_output_spk(tx, len, index, spk, slen);
}
