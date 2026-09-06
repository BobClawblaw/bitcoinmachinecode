/* daemon/coinstats_index.c -- the incrementally-maintained coinstats index.
 *
 * WHY: `gettxoutsetinfo` was a full O(set) walk (~6 minutes with MuHash)
 * that additionally demanded a quiesced datadir -- correct, and proven
 * byte-identical to Core at the parity capstone, but unusable as a routine
 * instrument. Core's coinstatsindex folds each connected block's coin
 * events into a running MuHash and running totals; this module does the
 * same, riding the live apply path's own coin events. The result: the RPC
 * answers instantly at any time, and the node carries a CONTINUOUS
 * cryptographic parity instrument -- our running muhash can be compared to
 * the oracle's `gettxoutsetinfo muhash <height>` at any shared height.
 *
 * TWO ACCUMULATORS, ONE ELEMENT SERIALIZER. bitcoin_muhash.asm is insert-
 * only by design (the snapshot walk never removes; no inverse machinery).
 * Removal here is Core's own trick from the other direction: keep a second
 * accumulator for removed elements and divide AT FINALIZE TIME --
 * digest = H(num * den^-1), with the inverse computed by Fermat
 * (den^(p-2), square-and-multiply over num3072_mul, ~4600 modmuls, tens of
 * milliseconds, paid only per RPC call / parity check, never per block).
 *
 * Both sides are utxo_stats_t objects fed through the PROVEN
 * utxo_stats_add (Core's exact compressed-coin serialization -- the
 * capstone's byte-identical muhash went through that code), so this module
 * never re-serializes a coin: inserts fold into the num side's stats,
 * removals into the den side's, and the reported txouts/amount/bogosize
 * are simply num.counters - den.counters.
 *
 * EVENT DISCIPLINE (why re-applied blocks cannot double-count): events fire
 * only on REAL state transitions -- a put that returns "duplicate" or a del
 * of an absent key fires nothing, which is exactly how a crash-resumed
 * block re-applies. The remaining torn window (state advanced in memory,
 * crash before the per-block persist) is detected at boot: a stored height
 * that does not match the applied height INVALIDATES the index, and it
 * re-seeds from a full walk. Persistence rides the same per-block
 * durability point as utxo_applied_height.dat (csi_commit is called from
 * persist_applied_height), tmp+fsync+rename like everything else here.
 *
 * REORGS stay incremental: the rewind path restores spent coins with full
 * fields (insert events) and deletes created coins get-first (remove
 * events), so a disconnect is just more events. The one path that
 * invalidates outright is the pre-BIP34 duplicate-coinbase overwrite --
 * unreachable at live heights, and a full replay re-seeds anyway.
 *
 * FILE (coinstats.dat): "BMCCSI1\0" | i64 height | u8 blockhash[32]
 *   | num utxo_stats_t counters (txouts,amount,bogosize: 3x u64)
 *   | den counters (3x u64) | num acc[384] | den acc[384] | sha256 of all
 *   the above. A bad checksum or magic reads as ABSENT (re-seed), never as
 *   a partially-trusted state.
 */
#include <stdio.h>
#include <time.h>
#include "log_ts.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include "../rpc_node.h"   /* node_status_t: the shared fold ring (csi_ring) */

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern void muhash_init(void* acc);
extern void muhash_finalize(unsigned char out[32], const void* acc);
extern void num3072_mul(void* a, const void* b);
extern void num3072_set_one(void* a);
extern void utxo_stats_init(void* st, unsigned long want_muhash, unsigned long excl_genesis);
extern void utxo_stats_add(void* st, const u8 key36[36], unsigned long value,
                           unsigned long code, const u8* script, unsigned long slen);
extern void sha256_full(unsigned char out[32], const void* data, unsigned long len);

#include "muhash_p2.inc.h"

/* ---- the fold worker (2026-09-06, UTXO_INLINE_BUILD_PERF_SCOPE.md lever 2)
 *
 * Steady state folded every coin event on the CONNECT THREAD: ~10k
 * elements x 1.66 us = ~17 ms per heavy block. Now the connect thread pushes
 * a compact record (outpoint, value, height|coinbase, script) onto the
 * MAP_SHARED sequenced ring in the status block (rpc_node.h csi_ring, a
 * sibling of ann_ring) and a FORKED fold worker drains it into the
 * accumulators -- which the worker alone owns from the fork on. The
 * per-block commit marker goes through the same ring, so the worker writes
 * coinstats.dat for height h only after folding everything pushed before
 * that marker, and then publishes h as the watermark (csi_folded_height)
 * the parent's gettxoutsetinfo gates on. MuHash is commutative, so the
 * order of records within a block is irrelevant; reorg removals (the undo
 * observer) push to the same ring in the same sequence and cancel exactly.
 *
 * ROLES BY PROCESS:
 *   connect process  g_ring_on=1: observers push; g_csi is STALE after the
 *                    fork (csi_read_live is for in-process/test use only);
 *   fold worker      g_in_worker=1: folds, persists, publishes the watermark;
 *   serve parent     g_st set pre-fork, no worker: csi_rpc_run reads the
 *                    file, gated on the watermark.
 * No status block (tests, tools) or no worker: everything stays inline,
 * exactly as before -- the negative control in test_coinstats_fold_ring.
 *
 * A LOST RECORD IS A WRONG DIGEST (unlike ann_ring's missed announcement),
 * so the producer waits for room up to a bound before it laps the worker,
 * and a lap the worker detects invalidates the index outright (counted in
 * csi_lapped; re-seeded at the next boot). */
#define CSI_K_ADD     1u
#define CSI_K_REMOVE  2u
#define CSI_K_CONT    3u   /* continuation of the previous record's script */
#define CSI_K_COMMIT  4u   /* body: i64 height */
#define CSI_K_INVAL   5u   /* body: reason (NUL-terminated) */
#define CSI_K_STOP    6u
#define CSI_SCRIPT_MAX 10000   /* MAX_SCRIPT_SIZE: anything longer never enters the set */

static node_status_t* g_st;              /* the pre-fork MAP_SHARED status block; NULL = inline */
static pid_t g_worker_pid;               /* connect process: the fold worker; 0 = none */
static int   g_ring_on;                  /* connect process: observers push instead of folding */
static int   g_in_worker;                /* this process IS the fold worker */
static long  g_push_wait_ms = 60000;     /* backpressure bound before the producer overruns */
static long  g_rpc_wait_ms  = 2000;      /* how long the RPC waits for the watermark */
static u64   g_push_overruns;

void csi_set_status(void* st){ g_st = (node_status_t*)st; }
int  csi_worker_pid(void){ return (int)g_worker_pid; }
int  csi_ring_on(void){ return g_ring_on; }
void csi_test_set_push_wait_ms(long ms){ g_push_wait_ms = ms; }
void csi_test_set_rpc_wait_ms(long ms){ g_rpc_wait_ms = ms; }
void csi_test_ring_pause(int on){ if (g_st) g_st->csi_pause = on; }
u64  csi_test_push_overruns(void){ return g_push_overruns; }

static void sleep_us(long us){ struct timespec ts; ts.tv_sec = us / 1000000; ts.tv_nsec = (us % 1000000) * 1000; nanosleep(&ts, 0); }
static long long mono_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000; }

/* The worker is a fork of a process with threads (tx_verify's pool, the
 * mempool reload thread): stdio's lock may be held at fork time, so the
 * worker never touches stdio -- one vsnprintf + write(2) per line. */
static void csi_logf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
static void csi_logf(const char* fmt, ...){
    va_list ap; va_start(ap, fmt);
    if (!g_in_worker){ log_vfprintf_at(NULL, 0, stderr, fmt, ap); va_end(ap); return; }
    char buf[1024]; int n = vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof buf) n = (int)sizeof buf;
    (void)!write(2, buf, (size_t)n);
}

/* utxo_stats_t layout (bitcoin_utxo_stats.asm): counters at 0/8/16, the
 * 384-byte accumulator at offset 96, struct comfortably inside 512 bytes.
 * Mirrored by offset exactly as every other cross-language struct here. */
#define ST_SIZE     512
#define ST_TXOUTS   0
#define ST_AMOUNT   8
#define ST_BOGO     16
#define ST_ACC      96

typedef struct {
    u8   num[ST_SIZE] __attribute__((aligned(16)));
    u8   den[ST_SIZE] __attribute__((aligned(16)));
    long height;              /* state corresponds to the set AT this height */
    u8   blockhash[32];
    int  valid;
} csi_t;

static csi_t g_csi;
/* Bulk catch-up (2026-09-06): set by csi_defer_to_caught_up while the connect
 * loop is bulk-sized. The observers are inert (g_csi.valid == 0, no file on
 * disk, so the RPC cannot serve a stale record) until utxo_live's caught-up
 * hook fires csi_on_caught_up, which seeds from a walk exactly as boot does.
 * On a fresh sync this replaces ~6.4 billion per-coin folds with one walk. */
static int g_csi_deferred;
/* Every element folded into either accumulator, by this process, from any
 * path (observer or seed walk). Test instrument: the bulk-mode property is
 * that this stays 0 across the whole catch-up and equals the set size after
 * the seed. */
static u64 g_csi_folds;
u64 csi_test_fold_count(void){ return g_csi_folds; }
#define CSI_FILE "coinstats.dat"
#define CSI_MAGIC "BMCCSI1"

static u64 st_get(const u8* st, int off){ u64 v; memcpy(&v, st+off, 8); return v; }

/* den^(p-2) mod p by square-and-multiply, using the asm's own modmul.
 * MSB-first over the little-endian exponent bytes. ~3072 squarings + ~3070
 * multiplies (the exponent is nearly all ones); tens of ms. */
static void num3072_inv(u8 out[384], const u8 in[384]){
    num3072_set_one(out);
    for (int byte = 383; byte >= 0; byte--){
        for (int bit = 7; bit >= 0; bit--){
            num3072_mul(out, out);
            if ((MUHASH_P_MINUS_2[byte] >> bit) & 1)
                num3072_mul(out, in);
        }
    }
}

static int csi_worker_dead(void);
static int ring_push(unsigned kind, const u8* key36, u64 value, u64 code,
                     const u8* script, unsigned long slen, const void* raw, unsigned rawlen);

/* this process's own state: drop it and the file */
static void csi_invalidate_local(const char* why){
    if (g_csi.valid)
        csi_logf("[coinstats] index INVALIDATED (%s) -- will re-seed\n", why ? why : "?");
    g_csi.valid = 0;
    unlink(CSI_FILE);
}

void csi_invalidate(const char* why){
    if (g_ring_on && g_worker_pid && !csi_worker_dead()){
        /* The worker owns the accumulators and the file: tell it, IN
         * SEQUENCE after any commit marker already pushed, and stop feeding.
         * Unlinking here would race the worker's tmp+rename of an earlier
         * marker and resurrect the file. */
        if (g_csi.valid){
            csi_logf("[coinstats] index INVALIDATED (%s) -- will re-seed\n", why ? why : "?");
            const char* r = why ? why : "?";
            ring_push(CSI_K_INVAL, 0, 0, 0, 0, 0, r, (unsigned)strlen(r) + 1);
        }
        g_csi.valid = 0;
        return;
    }
    csi_invalidate_local(why);
}

int csi_valid(void){ return g_csi.valid; }
long csi_height(void){ return g_csi.valid ? g_csi.height : -1; }
int csi_deferred(void){ return g_csi_deferred; }

/* one coin entered the live set */
void csi_on_add(const u8 txid[32], u32 index, u64 value, u64 height, u64 coinbase,
                const u8* script, unsigned long slen){
    if (!g_csi.valid) return;
    u8 key[36]; memcpy(key, txid, 32);
    for (int i = 0; i < 4; i++) key[32+i] = (u8)(index >> (8*i));
    if (g_ring_on){
        if (ring_push(CSI_K_ADD, key, value, (height << 1) | coinbase, script, slen, 0, 0) < 0)
            csi_invalidate("fold worker gone");
        return;
    }
    utxo_stats_add(g_csi.num, key, value, (height << 1) | coinbase, script, slen);
    g_csi_folds++;
}

/* one coin left the live set (spend, or a disconnected block's creation) */
void csi_on_remove(const u8 txid[32], u32 index, u64 value, u64 height, u64 coinbase,
                   const u8* script, unsigned long slen){
    if (!g_csi.valid) return;
    u8 key[36]; memcpy(key, txid, 32);
    for (int i = 0; i < 4; i++) key[32+i] = (u8)(index >> (8*i));
    if (g_ring_on){
        if (ring_push(CSI_K_REMOVE, key, value, (height << 1) | coinbase, script, slen, 0, 0) < 0)
            csi_invalidate("fold worker gone");
        return;
    }
    utxo_stats_add(g_csi.den, key, value, (height << 1) | coinbase, script, slen);
    g_csi_folds++;
}

/* ---- persistence --------------------------------------------------------- */
#define CSI_BODY (8 + 8 + 32 + 6*8 + 384 + 384)

static long csi_serialize(u8* buf){
    u8* p = buf;
    memcpy(p, CSI_MAGIC, 8); p += 8;
    memcpy(p, &g_csi.height, 8); p += 8;
    memcpy(p, g_csi.blockhash, 32); p += 32;
    u64 v;
    v = st_get(g_csi.num, ST_TXOUTS); memcpy(p, &v, 8); p += 8;
    v = st_get(g_csi.num, ST_AMOUNT); memcpy(p, &v, 8); p += 8;
    v = st_get(g_csi.num, ST_BOGO);   memcpy(p, &v, 8); p += 8;
    v = st_get(g_csi.den, ST_TXOUTS); memcpy(p, &v, 8); p += 8;
    v = st_get(g_csi.den, ST_AMOUNT); memcpy(p, &v, 8); p += 8;
    v = st_get(g_csi.den, ST_BOGO);   memcpy(p, &v, 8); p += 8;
    memcpy(p, g_csi.num + ST_ACC, 384); p += 384;
    memcpy(p, g_csi.den + ST_ACC, 384); p += 384;
    return p - buf;
}

/* Persist the state for `height`/`blockhash`. Called from the same per-block
 * durability point as utxo_applied_height.dat. Failure invalidates rather
 * than lying about coverage. */
static void csi_persist(long height){
    if (!g_csi.valid) return;
    g_csi.height = height;
    memset(g_csi.blockhash, 0, 32);   /* the RPC resolves height->hash itself */
    static u8 buf[CSI_BODY + 32];
    long n = csi_serialize(buf);
    sha256_full(buf + n, buf, (unsigned long)n);
    int fd = open(CSI_FILE ".tmp", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0){ csi_invalidate_local("persist open failed"); return; }
    if (write(fd, buf, (size_t)(n + 32)) != n + 32 || fsync(fd) != 0){
        close(fd); csi_invalidate_local("persist write failed"); return;
    }
    close(fd);
    if (rename(CSI_FILE ".tmp", CSI_FILE) != 0) csi_invalidate_local("persist rename failed");
}
void csi_commit(long height){
    if (!g_csi.valid) return;
    if (g_ring_on){
        /* a marker in sequence: the worker persists when it gets there and
         * then publishes the watermark; csi_pushed_height is what the RPC
         * compares that watermark against */
        long long h = height;
        if (ring_push(CSI_K_COMMIT, 0, 0, 0, 0, 0, &h, 8) < 0){ csi_invalidate("fold worker gone"); return; }
        g_st->csi_pushed_height = h;
        return;
    }
    csi_persist(height);
}

/* Load persisted state; returns the stored height, or -1 when absent/bad.
 * Counters land in the stats structs so the running arithmetic continues
 * exactly where it stopped. */
static long csi_load(void){
    int fd = open(CSI_FILE, O_RDONLY);
    if (fd < 0) return -1;
    static u8 buf[CSI_BODY + 32];
    long r = read(fd, buf, sizeof buf);
    close(fd);
    if (r != CSI_BODY + 32) return -1;
    u8 want[32];
    sha256_full(want, buf, CSI_BODY);
    if (memcmp(want, buf + CSI_BODY, 32) != 0) return -1;
    if (memcmp(buf, CSI_MAGIC, 8) != 0) return -1;
    const u8* p = buf + 8;
    long h; memcpy(&h, p, 8); p += 8;
    memcpy(g_csi.blockhash, p, 32); p += 32;
    utxo_stats_init(g_csi.num, 1 /* muhash */, 0 /* no genesis exclusion: live set */);
    utxo_stats_init(g_csi.den, 1, 0);
    memcpy(g_csi.num + ST_TXOUTS, p, 8); p += 8;
    memcpy(g_csi.num + ST_AMOUNT, p, 8); p += 8;
    memcpy(g_csi.num + ST_BOGO,   p, 8); p += 8;
    memcpy(g_csi.den + ST_TXOUTS, p, 8); p += 8;
    memcpy(g_csi.den + ST_AMOUNT, p, 8); p += 8;
    memcpy(g_csi.den + ST_BOGO,   p, 8); p += 8;
    memcpy(g_csi.num + ST_ACC, p, 384); p += 384;
    memcpy(g_csi.den + ST_ACC, p, 384); p += 384;
    g_csi.height = h;
    return h;
}

/* ---- seed ---------------------------------------------------------------- */
/* Seed by FULL WALK of the live set (the parity tool's own machinery: the
 * walk cb IS utxo_stats_add). Only correct on a quiesced set -- the caller
 * (worker boot, before catch-up starts) guarantees that. Minutes with
 * MuHash; paid only when no valid persisted state exists. */
extern long utxo_lsm_walk(void* lst, void* u, void* cb, void* ctx);

/* progress wrapper for the seed walk (2026-09-01, "coinstats not showing any
 * updates for a long time"): a full mainnet walk folds ~166M coins into the
 * muhash over several minutes -- say so every 20M. */
static struct { void* st; long n, next, total; time_t t0; } g_csi_walkprog;
static void csi_walk_add_prog(void* st, const u8 key36[36], unsigned long value,
                              unsigned long code, const u8* script, unsigned long slen){
    utxo_stats_add(st, key36, value, code, script, slen);
    g_csi_folds++;
    if (++g_csi_walkprog.n >= g_csi_walkprog.next){
        long secs = (long)(time(NULL) - g_csi_walkprog.t0); if (secs < 1) secs = 1;
        if (g_csi_walkprog.total > 0)
            fprintf(stderr, "[coinstats] seed walk: %ldM of ~%ldM coins (%.0f%%, %.1fM/s)\n",
                    g_csi_walkprog.n / 1000000, g_csi_walkprog.total / 1000000,
                    100.0 * (double)g_csi_walkprog.n / (double)g_csi_walkprog.total,
                    (double)g_csi_walkprog.n / 1e6 / (double)secs);
        else
            fprintf(stderr, "[coinstats] seed walk: %ldM coins (%.1fM/s)\n",
                    g_csi_walkprog.n / 1000000, (double)g_csi_walkprog.n / 1e6 / (double)secs);
        g_csi_walkprog.next += 20000000;
    }
}
extern long utxo_lsm_count(void* lst);
void csi_worker_stop(void);
int csi_seed_from_walk(void* lst, void* u, long height){
    if (g_worker_pid) csi_worker_stop();   /* the worker's accumulators are superseded by this walk */
    utxo_stats_init(g_csi.num, 1, 0);
    utxo_stats_init(g_csi.den, 1, 0);
    g_csi_walkprog.n = 0; g_csi_walkprog.next = 20000000; g_csi_walkprog.t0 = time(NULL);
    g_csi_walkprog.total = utxo_lsm_count(lst);
    fprintf(stderr, "[coinstats] seeding from a full walk at height %ld (~%ldM coins; one-time)\n",
            height, g_csi_walkprog.total > 0 ? g_csi_walkprog.total / 1000000 : -1);
    long n = utxo_lsm_walk(lst, u, (void*)csi_walk_add_prog, g_csi.num);
    if (n < 0){ fprintf(stderr, "[coinstats] seed walk failed\n"); g_csi.valid = 0; return 0; }
    g_csi.valid = 1;
    csi_commit(height);
    fprintf(stderr, "[coinstats] seeded: %ld coins, txouts=%llu at height %ld\n",
            n, (unsigned long long)st_get(g_csi.num, ST_TXOUTS), height);
    return g_csi.valid;
}

/* ---- bulk catch-up: defer, then seed at caught-up ------------------------
 * The worker calls csi_defer_to_caught_up at boot INSTEAD of csi_boot/seed
 * when utxo_live_bulk_mode() says the connect loop is far behind. Any
 * persisted state is dropped (it would only be maintained by the per-coin
 * folds this exists to skip, and a coinstats.dat that stops at the boot
 * height must not be served as if it were current). Reorgs during bulk mode
 * are not a concern: the walk happens after. */
void csi_defer_to_caught_up(void){
    if (g_csi.valid) csi_invalidate("bulk catch-up: per-coin folding is off until caught up");
    g_csi.valid = 0;
    unlink(CSI_FILE);
    g_csi_deferred = 1;
    if (g_st) g_st->csi_deferred = 1;   /* the parent's RPC refuses rather than walking */
    fprintf(stderr, "[coinstats] bulk catch-up: not folding per coin; the index seeds from a walk when the node is caught up\n");
}

/* utxo_live's caught-up hook (utxo_live_set_coinstats_caught_up): fires on
 * the same thread, between blocks, after the batch checkpoint -- the
 * quiescence csi_seed_from_walk needs, by the same construction as boot.
 * A no-op unless the index was deferred. */
int csi_worker_start(void);
void csi_on_caught_up(void* lst, void* u, long height){
    if (!g_csi_deferred) return;
    g_csi_deferred = 0;
    csi_seed_from_walk(lst, u, height);
    if (g_st) g_st->csi_deferred = 0;
    csi_worker_start();                    /* steady state from here: fold off the connect thread */
}

/* Boot: adopt the persisted state iff it matches the applied height exactly;
 * anything else re-seeds (the caller decides when to pay the walk). Returns
 * 1 = adopted, 0 = needs seed. */
int csi_boot(long applied_height){
    long h = csi_load();
    if (h >= 0 && h == applied_height){
        g_csi.valid = 1;
        fprintf(stderr, "[coinstats] adopted persisted state at height %ld\n", h);
        return 1;
    }
    if (h >= 0)
        fprintf(stderr, "[coinstats] persisted height %ld != applied %ld -- re-seed needed\n",
                h, applied_height);
    g_csi.valid = 0;
    return 0;
}

/* ---- read side ----------------------------------------------------------- */
/* Fill the caller's outputs from the running state; digest = H(num/den).
 * Also usable OUT-OF-PROCESS: csi_read_file loads coinstats.dat into the
 * same struct and finalizes, which is how the parent's RPC answers without
 * sharing memory with the worker. Returns 1 ok / 0 no valid state. */
static int csi_finalize_into(unsigned char digest[32], u64* txouts, u64* amount, u64* bogo){
    static u8 inv[384] __attribute__((aligned(16)));
    static u8 tmp[384] __attribute__((aligned(16)));
    num3072_inv(inv, g_csi.den + ST_ACC);
    memcpy(tmp, g_csi.num + ST_ACC, 384);
    num3072_mul(tmp, inv);
    muhash_finalize(digest, tmp);
    *txouts = st_get(g_csi.num, ST_TXOUTS) - st_get(g_csi.den, ST_TXOUTS);
    *amount = st_get(g_csi.num, ST_AMOUNT) - st_get(g_csi.den, ST_AMOUNT);
    *bogo   = st_get(g_csi.num, ST_BOGO)   - st_get(g_csi.den, ST_BOGO);
    return 1;
}

int csi_read_live(long* height, unsigned char digest[32], u64* txouts, u64* amount, u64* bogo){
    if (!g_csi.valid) return 0;
    *height = g_csi.height;
    return csi_finalize_into(digest, txouts, amount, bogo);
}

/* light height probe: read + checksum, no finalize. -1 = no valid state. */
long csi_file_height(void){
    csi_t save = g_csi;
    long h = csi_load();
    g_csi = save;
    return h;
}

/* Forward declaration: csi_rpc_run below calls csi_read_file, which is
 * DEFINED further down this file. Without this the call was implicit, so
 * none of its six pointer arguments was type-checked. */
int csi_read_file(long* height, unsigned char blockhash[32], unsigned char digest[32],
                  u64* txouts, u64* amount, u64* bogo);

/* RPC adapter: the same out-contract as the walk reader
 * (rpc_chain.c rpc_usi_out_t: height, txouts, bogosize, total_amount,
 * muhash[32], muhash_valid). Returns 1 served / 0 no-valid-index. */
long csi_rpc_run(int want_muhash, void* outv, char* msg, unsigned long mcap){
    struct { long height; unsigned long long txouts, bogosize, total_amount;
             unsigned char muhash[32]; int muhash_valid; } *o = outv;
#define MSG(...) do{ if (msg && mcap) snprintf(msg, mcap, __VA_ARGS__); }while(0)
    if (msg && mcap) msg[0] = 0;
    /* The watermark gate (2026-09-06). The file is written by the fold
     * worker only after it has folded everything before the commit marker
     * for that height, so a file behind csi_pushed_height is not stale --
     * it is a few milliseconds early. Wait a bounded time for the worker to
     * get there; refuse (-2: the caller does NOT fall back to the walk
     * reader) if it does not. Deferred (bulk catch-up): nothing to serve. */
    if (g_st){
        if (g_st->csi_deferred){
            MSG("coinstats index unavailable during bulk catch-up (it seeds from a walk when the node is caught up)");
            return -2;
        }
        long long pushed = g_st->csi_pushed_height, folded = g_st->csi_folded_height;
        if (folded < pushed){
            long long t0 = mono_ms();
            while ((folded = g_st->csi_folded_height) < (pushed = g_st->csi_pushed_height)){
                if (mono_ms() - t0 >= g_rpc_wait_ms){
                    MSG("coinstats index still folding (folded through height %lld, applied %lld) -- retry shortly", folded, pushed);
                    return -2;
                }
                sleep_us(2000);
            }
        }
    }
    long h; unsigned char digest[32]; u64 tx, amt, bg;
    if (!csi_read_file(&h, NULL, digest, &tx, &amt, &bg)){ MSG("no valid coinstats index state"); return 0; }
#undef MSG
    o->height = h; o->txouts = tx; o->total_amount = amt; o->bogosize = bg;
    if (want_muhash){
        /* PRESENTATION byte order: the raw finalize output is the exact
         * byte-reverse of what Core prints (the same trap utxo_setinfo.c
         * documents and reverses) -- the first live parity check against
         * the oracle read as a "total mismatch" that was really identical.
         * Reverse here so the RPC's hex compares directly. */
        for (int i = 0; i < 32; i++) o->muhash[i] = digest[31 - i];
        o->muhash_valid = 1;
    }
    else o->muhash_valid = 0;
    return 1;
}

/* out-of-process read: load the file fresh each call (one writer, atomic
 * rename; a torn read fails the checksum and reports "no state"). */
int csi_read_file(long* height, unsigned char blockhash[32], unsigned char digest[32],
                  u64* txouts, u64* amount, u64* bogo){
    csi_t save = g_csi;               /* don't disturb an in-process live state */
    long h = csi_load();
    int ok = 0;
    if (h >= 0){
        *height = h;
        if (blockhash) memcpy(blockhash, g_csi.blockhash, 32);
        ok = csi_finalize_into(digest, txouts, amount, bogo);
    }
    g_csi = save;
    return ok;
}

/* ---- the fold ring: producer side (connect process) --------------------- */
/* 0 = still running; otherwise dead (reaped here, or auto-reaped by the
 * download worker's SIGCHLD=SIG_IGN, in which case waitpid says ECHILD). */
static int csi_worker_dead(void){
    if (!g_worker_pid) return 1;
    int st; pid_t r = waitpid(g_worker_pid, &st, WNOHANG);
    if (r == 0) return 0;
    csi_logf("[coinstats] fold worker pid %d is gone (%s) -- the index cannot be maintained\n",
             (int)g_worker_pid, r < 0 ? "already reaped" : WIFSIGNALED(st) ? "signal" : "exited");
    g_worker_pid = 0; g_ring_on = 0;
    if (g_st) g_st->csi_worker_pid = 0;
    return 1;
}

/* Wait for n free slots. 1 = room; 0 = bound hit (the push proceeds and laps
 * the worker, which detects it and invalidates); -1 = the worker is gone. */
static int ring_wait_room(unsigned long n){
    node_status_t* st = g_st;
    if (st->csi_seq + n - st->csi_folded_seq <= RPC_CSI_RING) return 1;
    long long t0 = mono_ms(); long spins = 0;
    for (;;){
        if (st->csi_seq + n - st->csi_folded_seq <= RPC_CSI_RING) return 1;
        if ((++spins & 255) == 0 && csi_worker_dead()) return -1;
        if (mono_ms() - t0 >= g_push_wait_ms) return 0;
        sleep_us(50);
    }
}

static void slot_fill(u64 seq, unsigned kind, unsigned slen, const void* body, unsigned blen){
    volatile typeof(g_st->csi_ring[0])* e = &g_st->csi_ring[seq % RPC_CSI_RING];
    e->ready = 0;
    __sync_synchronize();
    e->kind = kind; e->slen = slen;
    if (blen) memcpy((void*)e->body, body, blen);
    __sync_synchronize();
    e->ready = seq + 1;
}

/* One record = one head slot (+ continuation slots for a script longer than
 * the inline part), all claimed with ONE atomic increment so they are
 * consecutive in sequence. Returns 1 pushed / -1 worker gone. */
static int ring_push(unsigned kind, const u8* key36, u64 value, u64 code,
                     const u8* script, unsigned long slen, const void* raw, unsigned rawlen){
    node_status_t* st = g_st;
    if (!st) return -1;
    unsigned long n = 1;
    if ((kind == CSI_K_ADD || kind == CSI_K_REMOVE) && slen > RPC_CSI_INLINE)
        n += (slen - RPC_CSI_INLINE + RPC_CSI_BODY - 1) / RPC_CSI_BODY;
    int room = ring_wait_room(n);
    if (room < 0) return -1;
    if (room == 0){ g_push_overruns++; st->csi_overrun++; }
    u64 seq = __sync_fetch_and_add(&st->csi_seq, (u64)n);
    if (kind == CSI_K_ADD || kind == CSI_K_REMOVE){
        u8 body[RPC_CSI_BODY];
        memcpy(body, key36, 36); memcpy(body + 36, &value, 8); memcpy(body + 44, &code, 8);
        unsigned long inl = slen < RPC_CSI_INLINE ? slen : RPC_CSI_INLINE;
        if (inl) memcpy(body + RPC_CSI_HDR, script, inl);
        slot_fill(seq, kind, (unsigned)slen, body, (unsigned)(RPC_CSI_HDR + inl));
        unsigned long off = inl;
        for (unsigned long i = 1; i < n; i++){
            unsigned long c = slen - off; if (c > RPC_CSI_BODY) c = RPC_CSI_BODY;
            slot_fill(seq + i, CSI_K_CONT, (unsigned)c, script + off, (unsigned)c);
            off += c;
        }
    } else slot_fill(seq, kind, 0, raw, rawlen);
    return 1;
}

/* ---- the fold worker ------------------------------------------------------ */
static volatile sig_atomic_t g_w_stop;
static void w_sig(int s){ (void)s; g_w_stop = 1; }

static void worker_run(u64 cursor, pid_t parent){
    node_status_t* st = g_st;
    g_in_worker = 1; g_ring_on = 0;
    g_csi_folds = 0;                            /* the worker's own count (the seed's stays with the parent) */
    signal(SIGTERM, w_sig); signal(SIGINT, w_sig); signal(SIGCHLD, SIG_DFL); signal(SIGPIPE, SIG_IGN);
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (getppid() != parent) g_w_stop = 1;      /* died between the fork and the prctl */
    static u8 script[CSI_SCRIPT_MAX + RPC_CSI_BODY];
    long long stalled_since = 0;
    int stop = 0;
    while (!stop){
        if (st->csi_pause){ sleep_us(1000); continue; }
        u64 head = st->csi_seq;
        if (head - cursor > RPC_CSI_RING){
            u64 lost = head - cursor - RPC_CSI_RING;
            st->csi_lapped += lost;
            cursor = head - RPC_CSI_RING;
            csi_logf("[coinstats] fold ring LAPPED: %llu record(s) overwritten before they were folded\n", (unsigned long long)lost);
            csi_invalidate_local("fold ring lapped");
        }
        int progressed = 0;
        while (cursor < head){
            volatile typeof(st->csi_ring[0])* e = &st->csi_ring[cursor % RPC_CSI_RING];
            if (e->ready != cursor + 1) break;                 /* claimed, not yet filled (or lapped: re-check above) */
            unsigned kind = e->kind, slen = e->slen;
            u8 body[RPC_CSI_BODY]; memcpy(body, (const void*)e->body, RPC_CSI_BODY);
            __sync_synchronize();
            if (e->ready != cursor + 1) break;                 /* overwritten under us */
            unsigned long n = 1;
            int coin = (kind == CSI_K_ADD || kind == CSI_K_REMOVE);
            if (coin && slen > CSI_SCRIPT_MAX){ csi_invalidate_local("fold ring: corrupt record"); slen = 0; coin = 0; }
            if (coin){
                unsigned long inl = slen < RPC_CSI_INLINE ? slen : RPC_CSI_INLINE;
                memcpy(script, body + RPC_CSI_HDR, inl);
                if (slen > RPC_CSI_INLINE){
                    n += (slen - RPC_CSI_INLINE + RPC_CSI_BODY - 1) / RPC_CSI_BODY;
                    if (head - cursor < n) break;              /* continuation not claimed yet */
                    unsigned long off = inl; int ok = 1;
                    for (unsigned long i = 1; i < n && ok; i++){
                        volatile typeof(st->csi_ring[0])* c = &st->csi_ring[(cursor + i) % RPC_CSI_RING];
                        if (c->ready != cursor + i + 1){ ok = 0; break; }
                        unsigned cl = c->slen;
                        if (c->kind != CSI_K_CONT || cl > RPC_CSI_BODY || off + cl > slen){ ok = -1; break; }
                        memcpy(script + off, (const void*)c->body, cl);
                        __sync_synchronize();
                        if (c->ready != cursor + i + 1){ ok = 0; break; }
                        off += cl;
                    }
                    if (ok <= 0){
                        if (ok < 0){ csi_invalidate_local("fold ring: torn continuation"); }
                        else break;                            /* not yet filled: come back */
                    }
                    if (ok > 0 && off != slen){ csi_invalidate_local("fold ring: short continuation"); ok = -1; }
                    if (ok < 0) coin = 0;
                }
            }
            if (coin && g_csi.valid){
                u64 value, code; memcpy(&value, body + 36, 8); memcpy(&code, body + 44, 8);
                utxo_stats_add(kind == CSI_K_ADD ? g_csi.num : g_csi.den, body, value, code, script, slen);
                g_csi_folds++; st->csi_folds = g_csi_folds;
            } else if (kind == CSI_K_COMMIT){
                long long h; memcpy(&h, body, 8);
                if (g_csi.valid) csi_persist((long)h);
                __sync_synchronize();
                st->csi_folded_height = h;                     /* the watermark: file (or its absence) is final for h */
            } else if (kind == CSI_K_INVAL){
                body[RPC_CSI_BODY - 1] = 0;
                csi_invalidate_local((const char*)body);
            } else if (kind == CSI_K_STOP){
                stop = 1;
            }
            cursor += n;
            st->csi_folded_seq = cursor;
            progressed = 1;
            if (stop) break;
        }
        if (!progressed){
            long long now = mono_ms();
            if (getppid() != parent) g_w_stop = 1;
            if (g_w_stop){
                if (st->csi_seq == cursor) break;              /* drained: nothing more can come */
                if (!stalled_since) stalled_since = now;
                else if (now - stalled_since > 2000) break;    /* a slot claimed by a dead producer: give up */
            }
            sleep_us(200);
        } else stalled_since = 0;
    }
    csi_logf("[coinstats] fold worker exiting: folded %llu element(s), watermark height %lld%s\n",
             (unsigned long long)g_csi_folds, (long long)st->csi_folded_height,
             g_csi.valid ? "" : " (index invalid)");
    _exit(0);
}

/* Fork the worker. Requires a status block and a VALID in-process state
 * (adopted or seeded) -- the child inherits it. 1 = running (this process
 * now pushes), 0 = inline folding continues (no block, fork failed, ...). */
int csi_worker_start(void){
    if (!g_st || g_worker_pid || g_in_worker || !g_csi.valid) return 0;
    node_status_t* st = g_st;
    u64 cursor = st->csi_seq;                 /* the child's start, fixed BEFORE the fork */
    st->csi_folded_seq = cursor;
    st->csi_folded_height = g_csi.height; st->csi_pushed_height = g_csi.height;
    st->csi_lapped = 0; st->csi_overrun = 0; st->csi_pause = 0; st->csi_folds = 0;
    g_w_stop = 0;
    pid_t parent = getpid();
    pid_t p = fork();
    if (p < 0){
        csi_logf("[coinstats] fork for the fold worker failed (%s) -- folding inline\n", strerror(errno));
        return 0;
    }
    if (p == 0) worker_run(cursor, parent);   /* never returns */
    g_worker_pid = p; g_ring_on = 1; st->csi_worker_pid = (int)p;
    csi_logf("[coinstats] fold worker pid %d started at height %ld: the connect thread pushes coin records, the worker folds\n",
             (int)p, g_csi.height);
    return 1;
}

/* Stop the worker: a STOP marker in sequence (everything pushed before it,
 * commit markers included, is folded and persisted first), then wait. The
 * connect process's own accumulators have been stale since the fork, so
 * they are marked invalid WITHOUT unlinking the worker's file. */
void csi_worker_stop(void){
    if (!g_worker_pid) return;
    pid_t p = g_worker_pid;
    if (!csi_worker_dead()){
        ring_push(CSI_K_STOP, 0, 0, 0, 0, 0, 0, 0);
        long long t0 = mono_ms();
        while (!csi_worker_dead()){
            if (mono_ms() - t0 > 15000){
                csi_logf("[coinstats] fold worker pid %d did not stop in 15 s -- killing it (the index re-seeds if its last commit is missing)\n", (int)p);
                kill(p, SIGKILL);
                int st; while (waitpid(p, &st, 0) < 0 && errno == EINTR) {}
                break;
            }
            sleep_us(1000);
        }
    }
    g_worker_pid = 0; g_ring_on = 0;
    if (g_st) g_st->csi_worker_pid = 0;
    g_csi.valid = 0;
}
