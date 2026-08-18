/* daemon/utxo_live.c -- the live serve daemon's real-time UTXO application.
 *
 * Single writer: this module is only ever driven by the download worker
 * process (serve_download_worker in main.c), which owns the sole live,
 * writable utxo_lsm_* instance. Inbound serve children get their own
 * READ-ONLY view via a separate utxo_lsm_reload() at connection start (see
 * the compat shim added in a later stage) -- this file only implements the
 * writer side.
 *
 * Progress is tracked via a PERSISTED applied-height file, not a per-call
 * before/after diff of the store's tip the way do_outbound_sync tracks its
 * OWN sync progress in main.c. That distinction matters: after Stage 0
 * (idxscan_append_locked), blocks can land in the shared archive via EITHER
 * this process's own node_sync calls OR a sibling inbound-serve child's
 * .do_block write -- a local before/after diff would only ever see the
 * former. Comparing the store's true on-disk tip against a durable applied-
 * height counter picks up either path correctly.
 *
 * Sized much smaller than build_utxo.c's batch-scale memtable (millions of
 * slots) -- see UTXO_LIVE_SLOTS_LOG2 below -- so that a per-inbound-
 * connection-fork utxo_lsm_reload() (a full current-generation WAL replay)
 * stays cheap, and so manifest_n growth between compactions stays small
 * (manifest_n directly bounds .do_tx's per-lookup disk-run scan cost for
 * every inbound child once that's wired up).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "utxo_walk.h"
#include "log_ts.h"

extern long store_reload(void* st);
extern long store_read_at(void* st, u64 height, void* buf, u64 cap);

extern int  tx_parse(void* info, const u8* tx, unsigned long txlen);
extern void tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);

extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_reload(void* lst, void* u);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index, u64 value, const u8* script, u32 slen);
extern long utxo_lsm_del(void* lst, void* u, const u8 txid[32], u32 index);
extern long utxo_lsm_count(void* lst);
extern long utxo_lsm_compact(void* lst);
extern void utxo_lsm_close(void* lst);

/* Must mirror bitcoin_utxo_lsm.asm's state struct exactly (152 bytes). */
struct lsm_state {
    long log_fd, idx_fd;
    u64 log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap;
    u64 next_run_no;
};
#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536

/* live-daemon memtable sizing -- see file header comment. 2^16 slots is a
 * few blocks' worth of live-traffic headroom at current mainnet tx volume
 * (thousands of ops/block), not build_utxo.c's batch-scale millions. */
#define UTXO_LIVE_SLOTS_LOG2    16
#define UTXO_LIVE_BLOB_BYTES    (64UL<<20)
#define UTXO_LIVE_MANIFEST_CAP  256
/* compact once manifest_n crosses this -- bounds .do_tx's per-lookup
 * disk-run scan cost, not just disk-space hygiene (see file header). */
#define UTXO_LIVE_COMPACT_THRESHOLD 12

static void* g_utxo_table = 0;
struct lsm_state g_utxo_lst;
static long  g_applied_height = -1;

static void* mmap_file(const char* path, u64 size){
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) { fprintf(stderr, "[utxo_live] open(%s) failed: %s\n", path, strerror(errno)); return 0; }
    if (ftruncate(fd, (off_t)size) != 0) { fprintf(stderr, "[utxo_live] ftruncate(%s,%lu) failed: %s\n", path, size, strerror(errno)); close(fd); return 0; }
    void* p = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd); /* mapping stays valid after close */
    if (p == MAP_FAILED) { fprintf(stderr, "[utxo_live] mmap(%s,%lu) failed: %s\n", path, size, strerror(errno)); return 0; }
    return p;
}

/* ---- persisted applied-height: crash-safe tmp+fsync+rename+dirfsync,
 * the same publish shape bitcoin_utxo_lsm.asm's own manifest already uses
 * (see its header comment / mac_flush's manifest-publish sequence). Only
 * ever written by this process (the single writer) after a batch of
 * puts/dels for a height range has already returned success -- so a crash
 * before the rename just means re-applying that range on next boot, which
 * is safe: utxo_lsm_put/del are themselves WAL-durable, and a duplicate
 * put / redundant tombstone are both already-defined non-error returns. ---- */
#define UTXO_APPLIED_HEIGHT_MAGIC 0x48504155u /* "UAPH" little-endian */

static long read_applied_height(void){
    int fd = open("utxo_applied_height.dat", O_RDONLY);
    if (fd < 0) return -1;
    u8 buf[12];
    long n = read(fd, buf, sizeof buf);
    close(fd);
    if (n != (long)sizeof buf) return -1;
    u32 magic; memcpy(&magic, buf, 4);
    if (magic != UTXO_APPLIED_HEIGHT_MAGIC) return -1;
    long h; memcpy(&h, buf+4, 8);
    return h;
}

static int persist_applied_height(long h){
    u8 buf[12];
    u32 magic = UTXO_APPLIED_HEIGHT_MAGIC;
    memcpy(buf, &magic, 4);
    memcpy(buf+4, &h, 8);
    int fd = open("utxo_applied_height.dat.tmp", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) { fprintf(stderr, "[utxo_live] open tmp height file failed: %s\n", strerror(errno)); return 0; }
    long wr = write(fd, buf, sizeof buf);
    if (wr != (long)sizeof buf) { fprintf(stderr, "[utxo_live] write height file failed\n"); close(fd); return 0; }
    if (fsync(fd) != 0) { fprintf(stderr, "[utxo_live] fsync height file failed: %s\n", strerror(errno)); close(fd); return 0; }
    close(fd);
    if (rename("utxo_applied_height.dat.tmp", "utxo_applied_height.dat") != 0) {
        fprintf(stderr, "[utxo_live] rename height file failed: %s\n", strerror(errno));
        return 0;
    }
    int dfd = open(".", O_RDONLY);
    if (dfd >= 0) { fsync(dfd); close(dfd); }
    return 1;
}

/* ---- per-block apply, reusing the shared walker from utxo_walk.h ---- */
typedef struct {
    const u8* txid;
    long fatal;
} apply_ctx_t;

static const u8 ZERO32[32] = {0};

static void live_on_input(void* ctxv, const u8 txid[32], u32 index){
    apply_ctx_t* ctx = (apply_ctx_t*)ctxv;
    if (index == 0xFFFFFFFFu && memcmp(txid, ZERO32, 32)==0) return; /* coinbase */
    long r = utxo_lsm_del(&g_utxo_lst, g_utxo_table, txid, index);
    if (r == -1) ctx->fatal = 1;
}

static void live_on_output(void* ctxv, u32 out_index, u64 value, const u8* script, u32 slen){
    apply_ctx_t* ctx = (apply_ctx_t*)ctxv;
    long r = utxo_lsm_put(&g_utxo_lst, g_utxo_table, ctx->txid, out_index, value, script, slen);
    if (r == -1 || r == 2) ctx->fatal = 1; /* -1 I/O error, 2 table full (undersized memtable) */
}

/* Apply every tx's puts/dels in one block. Returns 1 on a clean apply, 0 on
 * a parse inconsistency (caller logs/skips -- matches build_utxo.c's own
 * corrupt-block handling; the Stage 0 archive-write-race fix plus the
 * corruption repair already run make this an unexpected path in practice,
 * not a normal one). */
static int apply_block(const u8* blockbuf, u64 blocklen){
    if (blocklen < 81) return 0;
    const u8* p = blockbuf + 80;
    const u8* blkend = blockbuf + blocklen;
    u64 consumed;
    u64 ntx = utxo_walk_read_varint(p, blkend, &consumed);
    if (!consumed) return 0;
    p += consumed;

    static u8 txid_scratch[4<<20];
    apply_ctx_t ctx = { 0, 0 };
    for (u64 t=0; t<ntx && !ctx.fatal; t++){
        u8 info[64];
        int ok = tx_parse(info, p, (unsigned long)(blkend - p));
        if (!ok) return 0;
        u64 txlen; memcpy(&txlen, info, 8);
        u32 pn_in, pn_out; memcpy(&pn_in, info+12, 4); memcpy(&pn_out, info+16, 4);

        u8 txid[32];
        tx_txid(txid, p, txlen, txid_scratch, sizeof txid_scratch);
        ctx.txid = txid;

        u64 wnin=0, wnout=0;
        int wok = utxo_walk_tx_io(p, p+txlen, &ctx, live_on_input, live_on_output, &wnin, &wnout);
        if (!wok || ctx.fatal) return 0;
        if (wnin != pn_in || wnout != pn_out) return 0;
        p += txlen;
    }
    return ctx.fatal ? 0 : 1;
}

/* utxo_live_init(dir): open-or-init the live LSM UTXO instance in the
 * current directory (callers have already chdir'd to the daemon's data
 * dir, matching every other store in this codebase -- `dir` is only used
 * for the log line). Returns 1 on success, 0 on failure. */
int utxo_live_init(const char* dir){
    unsigned long slots = 1UL << UTXO_LIVE_SLOTS_LOG2;
    u64 blob_cap = UTXO_LIVE_BLOB_BYTES;
    u64 fill_threshold = (u64)slots * 3 / 4;
    u64 op_threshold    = (u64)slots * 2;
    u64 tomb_cap         = op_threshold;
    u64 desc_cap         = (u64)slots * 3; /* >= fill_threshold+tomb_cap, with margin */
    u64 scratch_cap       = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    u64 manifest_cap       = UTXO_LIVE_MANIFEST_CAP;

    long ustruct = utxo_struct_size(slots);
    g_utxo_table = mmap_file("utxo_lsm_table.map", (u64)ustruct);
    void* blob = mmap_file("utxo_lsm_blob.map", blob_cap);
    if (!g_utxo_table || !blob) { fprintf(stderr, "[utxo_live] mmap alloc failed\n"); return 0; }
    utxo_init(g_utxo_table, slots, blob, blob_cap);

    void* tomb_buf = malloc(tomb_cap*36);
    void* manifest_buf = malloc(manifest_cap*16); /* [gen:8][run_no:8] per entry */
    void* scratch_buf = malloc(scratch_cap);
    if (!tomb_buf || !manifest_buf || !scratch_buf) {
        fprintf(stderr, "[utxo_live] malloc failed (tomb=%p manifest=%p scratch=%p)\n", tomb_buf, manifest_buf, scratch_buf);
        return 0;
    }
    memset(&g_utxo_lst, 0, sizeof g_utxo_lst);
    g_utxo_lst.op_threshold = op_threshold;
    g_utxo_lst.fill_threshold = fill_threshold;
    g_utxo_lst.tomb_buf = tomb_buf; g_utxo_lst.tomb_cap = tomb_cap;
    g_utxo_lst.manifest_buf = manifest_buf; g_utxo_lst.manifest_cap = manifest_cap;
    g_utxo_lst.scratch_buf = scratch_buf; g_utxo_lst.scratch_cap = scratch_cap;

    /* Prior state can exist WITHOUT a manifest: utxo_manifest.dat is only
     * ever created at the first flush, but puts/dels before that point are
     * already WAL-durable in utxo.dat (bitcoin_utxo_store.asm's log file,
     * reused as the LSM's per-generation WAL). Checking manifest existence
     * alone would miss that WAL and silently start fresh -- confirmed via a
     * standalone smoke test (init, apply <1 flush-threshold worth of puts,
     * close, re-init: count came back 0 instead of the pre-close value,
     * exactly this bug) before this check was fixed to also look at
     * utxo.dat directly. */
    struct stat sb;
    int has_wal = (stat("utxo.dat", &sb) == 0 && sb.st_size > 0);
    int has_manifest = (stat("utxo_manifest.dat", &sb) == 0);
    int have_prior_state = has_wal || has_manifest;
    /* utxo_lsm_init(lst) -> 1 ok / -1 err, but utxo_lsm_reload(lst,u) ->
     * REPLAYED RECORD COUNT / -1 err (not literally 1) -- different
     * contracts, so they need different success checks. */
    long r = have_prior_state
        ? utxo_lsm_reload(&g_utxo_lst, g_utxo_table)
        : utxo_lsm_init(&g_utxo_lst);
    int ok = have_prior_state ? (r != -1) : (r == 1);
    if (!ok) { fprintf(stderr, "[utxo_live] utxo_lsm_%s failed\n", have_prior_state ? "reload" : "init"); return 0; }

    /* A reloaded manifest can already be at or near UTXO_LIVE_MANIFEST_CAP --
     * e.g. a batch-scale seed (build_utxo.c, much larger manifest_cap) can
     * leave exactly this many runs behind at its checkpoint, with zero
     * headroom left for the live daemon's own first flush. mac_flush's own
     * manifest-capacity guard (bitcoin_utxo_lsm.asm, right before any
     * sort/bloom/run-file work) refuses to add a run once manifest_n >=
     * manifest_cap, so utxo_lsm_put/del would return -1 (fatal, per
     * live_on_output/live_on_input) on literally the first op that crosses
     * op_threshold/fill_threshold -- and utxo_live_catchup only calls
     * utxo_lsm_compact() AFTER a successful (applied>0) batch, so a
     * catch-up call that fails on its very first block never gets a chance
     * to shrink the manifest on its own: full manifest -> fatal flush ->
     * catch-up aborts before any block succeeds -> compact() never runs ->
     * manifest stays full forever. Break that deadlock here, once, before
     * any block is applied: proactively compact down while there's still
     * more than one run to merge and we're above the same threshold normal
     * steady-state catch-up uses (UTXO_LIVE_COMPACT_THRESHOLD). Bounded by
     * manifest_cap iterations so a compact() that stops making progress
     * (e.g. every remaining run already merged) can't spin forever. */
    for (unsigned long guard = 0; g_utxo_lst.manifest_n >= UTXO_LIVE_COMPACT_THRESHOLD && guard < UTXO_LIVE_MANIFEST_CAP; guard++){
        u64 before = g_utxo_lst.manifest_n;
        if (before < 2) break;
        long cr = utxo_lsm_compact(&g_utxo_lst);
        fprintf(stderr, "[utxo_live] init: pre-catchup compact manifest_n=%lu -> %lu (result=%ld)\n",
                (unsigned long)before, (unsigned long)g_utxo_lst.manifest_n, cr);
        if (g_utxo_lst.manifest_n >= before) break; /* no progress -- stop rather than loop */
    }

    g_applied_height = read_applied_height();
    fprintf(stderr, "[utxo_live] init dir=%s slots=2^%d %s applied_height=%ld manifest_n=%lu live=%ld\n",
            dir, UTXO_LIVE_SLOTS_LOG2, have_prior_state ? "reload" : "fresh",
            g_applied_height, g_utxo_lst.manifest_n, utxo_lsm_count(&g_utxo_lst));
    return 1;
}

/* utxo_live_catchup(store_buf): compare the store's TRUE on-disk tip
 * (store_reload, not a stale cached field) against the persisted applied
 * height; if behind, walk the delta applying puts/dels per block, then
 * persist the new height. Safe to call repeatedly/frequently -- a no-op
 * read (store_reload + one height comparison) when already caught up.
 * Returns the number of newly-applied heights (>=0), or -1 on a fatal
 * error (I/O or memtable-capacity failure -- see live_on_output). */
long utxo_live_catchup(void* store_buf){
    store_reload(store_buf);
    long tip = *(int*)((char*)store_buf + 24);
    if (tip < 0 || tip <= g_applied_height) return 0;

    static u8 blockbuf[8<<20];
    long applied = 0;
    for (long h = g_applied_height + 1; h <= tip; h++){
        long len = store_read_at(store_buf, h, blockbuf, sizeof blockbuf);
        if (len < 81) {
            fprintf(stderr, "[utxo_live] WARNING: hole/short block at height %ld (len=%ld) -- stopping catch-up short\n", h, len);
            break;
        }
        if (!apply_block(blockbuf, (u64)len)) {
            fprintf(stderr, "[utxo_live] FATAL: apply_block failed at height %ld -- stopping catch-up\n", h);
            return -1;
        }
        g_applied_height = h;
        applied++;
    }
    if (applied > 0) {
        if (!persist_applied_height(g_applied_height)) {
            fprintf(stderr, "[utxo_live] WARNING: failed to persist applied height %ld (will re-apply from the prior persisted height on next boot -- safe, puts/dels are idempotent)\n", g_applied_height);
        }
        if (g_utxo_lst.manifest_n >= UTXO_LIVE_COMPACT_THRESHOLD) {
            long cr = utxo_lsm_compact(&g_utxo_lst);
            fprintf(stderr, "[utxo_live] compact manifest_n=%lu -> result=%ld\n", g_utxo_lst.manifest_n, cr);
        }
    }
    return applied;
}

long utxo_live_applied_height(void){ return g_applied_height; }
long utxo_live_count(void){ return utxo_lsm_count(&g_utxo_lst); }

void utxo_live_close(void){
    utxo_lsm_close(&g_utxo_lst);
}
