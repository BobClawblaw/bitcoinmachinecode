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

/* ---- STAGE B: per-block undo data (daemon/undo_log.c) --------------------
 * Stage A built these but deliberately left live_on_input untouched. They
 * are wired in below: every input the live daemon spends is now captured
 * (value + scriptPubKey, read out of the LSM immediately before the delete)
 * into undo_<height>.dat, which is what makes a later DISCONNECT of that
 * block possible at all. */
extern long undo_capture_and_del(void* lst, void* u, long height,
                                 const u8 txid[32], u32 index);
extern long undo_discard(long height);
extern long undo_prune_from(long from_height, long tip_height, long window, long max_scan);
/* utxo_walk.h supplies u8/u32/u64 but not u16 (undo records carry a u16
 * script length -- see daemon/undo_log.c's record format). */
typedef unsigned short u16;
typedef int (*undo_replay_cb)(void* ctx, const u8 txid[32], u32 index,
                              u64 value, const u8* script, u16 slen);
extern long undo_replay(long height, undo_replay_cb cb, void* ctx);

/* Rolling undo-data retention window. Stage A's own design note calls for
 * ~100-200 blocks; 200 is the top of that range, chosen because it is also
 * comfortably deeper than any reorg this node would apply automatically
 * (see REORG_MAX_DEPTH in daemon/reorg.c, which refuses to go deeper than
 * the undo data can actually support). */
#define UTXO_UNDO_WINDOW    200
/* Heights examined per prune sweep. Bounds the cold-start cost on a deep
 * store (a fresh boot starts the cursor at 0) without ever stalling the
 * download worker's loop; the cursor resumes on the next block. */
#define UTXO_UNDO_PRUNE_SCAN 20000

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
/* Height whose block is currently being applied -- the key undo records are
 * filed under. Set by apply_block_at before any walk begins. */
static long  g_apply_height = -1;
/* Undo capture master switch. ON by default: the whole point of Stage B is
 * that undo data accumulates during NORMAL operation so a reorg that shows
 * up later has something to disconnect with. Turned off only while
 * REconnecting is not a thing we do -- reconnect captures undo data too, so
 * this stays on there as well; the switch exists for one-shot batch tools
 * (daemon/build_utxo.c-style archive replays) that would otherwise write a
 * million undo files they will never read. */
static int   g_undo_enabled = 1;
/* Resumable prune cursor -- see undo_prune_from's own header comment for why
 * a plain undo_prune(tip,window) per block is not viable at mainnet depth. */
static long  g_undo_prune_cursor = 0;

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
    if (g_undo_enabled) {
        /* STAGE B: capture-then-delete. undo_capture_and_del is Stage A's own
         * intended shape for exactly this call site: utxo_lsm_get the prevout,
         * append (txid,index,value,script) to undo_<height>.dat, THEN
         * utxo_lsm_del. Its return contract is deliberately identical to the
         * bare utxo_lsm_del this replaces -- 1 deleted / 0 no-such-UTXO /
         * -1 error -- so the fatal condition below is unchanged. A 0 is NOT
         * fatal here for the same reason it was not before: an already-absent
         * prevout is how a re-applied (crash-resumed) block legitimately
         * reads back. */
        long r = undo_capture_and_del(&g_utxo_lst, g_utxo_table, g_apply_height, txid, index);
        if (r == -1) ctx->fatal = 1;
        return;
    }
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
static int apply_block_inner(const u8* blockbuf, u64 blocklen){
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

/* apply_block_at(buf, len, height): apply_block_inner, but with this block's
 * undo records filed under `height` and starting from a CLEAN undo file.
 *
 * The discard matters: a block that gets re-applied (crash-resumed catch-up
 * -- applied_height is only persisted after a whole batch, so the last block
 * of an interrupted batch is legitimately applied twice) would otherwise
 * have its second attempt's records O_APPENDed onto the first attempt's. A
 * later disconnect would then both restore duplicates AND see a record count
 * that no longer matches the block's real input count -- which the unapply
 * pre-flight gate below treats as corruption and refuses, turning a
 * survivable crash into a permanently un-disconnectable height. */
static int apply_block_at(const u8* blockbuf, u64 blocklen, long height){
    g_apply_height = height;
    if (g_undo_enabled && height >= 0) undo_discard(height);
    return apply_block_inner(blockbuf, blocklen);
}

/* ===========================================================================
 * STAGE B: DISCONNECT (the mirror image of apply_block).
 *
 * Unapplying block H must leave the UTXO set byte-identical to its state
 * before H was applied. Two steps, and THE ORDER IS LOAD-BEARING:
 *
 *   1. RESTORE every prevout H spent, from undo_<H>.dat (utxo_lsm_put with
 *      the exact value+scriptPubKey captured at spend time).
 *   2. THEN DELETE every output H created (utxo_lsm_del on each (txid,vout)).
 *
 * Doing it the other way round is wrong for outputs that were BOTH created
 * and spent inside H (tx B in block H spending tx A in block H -- extremely
 * common). Such an outpoint is in the undo log (it really was in the live
 * set at the moment B spent it, because apply walks tx-by-tx and A's outputs
 * land before B's inputs are processed), and it is also in H's created-output
 * set. Correct end state: ABSENT. "Delete created, then restore" leaves it
 * PRESENT -- a phantom spendable UTXO that never existed. "Restore, then
 * delete created" leaves it absent. Hence this order.
 *
 * (The one case this global ordering gets wrong is a pre-BIP30 duplicate
 * coinbase txid -- heights 91722/91880 on mainnet, where a block creates an
 * outpoint identical to one an EARLIER block created. Disconnecting the
 * later of those two would delete the earlier one's still-live output. Those
 * two heights are ~880k blocks below any tip this code will ever disconnect
 * -- the undo window is 200 blocks -- so it is documented, not handled.)
 * ======================================================================== */

/* ---- pre-flight integrity gate ----------------------------------------
 * Counts the block's non-coinbase inputs and the undo file's record count
 * and requires them to be EQUAL before any mutation happens. This is the
 * single most important safety check in the disconnect path: undo data that
 * is missing, truncated, pruned away, or left over from a different block at
 * the same height would otherwise produce a silently WRONG UTXO set -- the
 * one failure mode of a reorg that no later check would catch and that
 * corrupts real money state. Refusing to disconnect leaves the node on its
 * current chain, which is always a safe outcome.
 * Returns 1 = safe to unapply, 0 = refuse. */
typedef struct { long n_inputs; } count_ctx_t;

static void count_on_input(void* ctxv, const u8 txid[32], u32 index){
    if (index == 0xFFFFFFFFu && memcmp(txid, ZERO32, 32)==0) return; /* coinbase */
    ((count_ctx_t*)ctxv)->n_inputs++;
}

/* Walk a block's transactions, invoking the given input/output callbacks.
 * Shared by the counting pre-flight and the created-output deletion below so
 * the two can never drift on how a block is sliced. Returns 1 well-formed. */
static int walk_block_txs(const u8* blockbuf, u64 blocklen, void* ctx,
                          utxo_walk_input_cb icb, utxo_walk_output_cb ocb,
                          const u8** cur_txid_slot){
    if (blocklen < 81) return 0;
    const u8* p = blockbuf + 80;
    const u8* blkend = blockbuf + blocklen;
    u64 consumed;
    u64 ntx = utxo_walk_read_varint(p, blkend, &consumed);
    if (!consumed) return 0;
    p += consumed;

    static u8 txid_scratch2[4<<20];
    for (u64 t=0; t<ntx; t++){
        u8 info[64];
        if (!tx_parse(info, p, (unsigned long)(blkend - p))) return 0;
        u64 txlen; memcpy(&txlen, info, 8);
        u32 pn_in, pn_out; memcpy(&pn_in, info+12, 4); memcpy(&pn_out, info+16, 4);
        u8 txid[32];
        tx_txid(txid, p, txlen, txid_scratch2, sizeof txid_scratch2);
        if (cur_txid_slot) *cur_txid_slot = txid;
        u64 wnin=0, wnout=0;
        if (!utxo_walk_tx_io(p, p+txlen, ctx, icb, ocb, &wnin, &wnout)) return 0;
        if (wnin != pn_in || wnout != pn_out) return 0;
        p += txlen;
    }
    return 1;
}

static int undo_count_cb(void* ctx, const u8 txid[32], u32 index, u64 value,
                         const u8* script, u16 slen){
    (void)txid; (void)index; (void)value; (void)script; (void)slen;
    (*(long*)ctx)++;
    return 1;
}

int utxo_live_can_unapply(const void* blockbuf, u64 blocklen, long height){
    count_ctx_t cc = { 0 };
    if (!walk_block_txs((const u8*)blockbuf, blocklen, &cc, count_on_input, 0, 0)){
        fprintf(stderr, "[utxo_live] unapply pre-flight: height %ld block does not parse\n", height);
        return 0;
    }
    long nrec = 0;
    long r = undo_replay(height, undo_count_cb, &nrec);
    if (r < 0){
        fprintf(stderr, "[utxo_live] unapply pre-flight: height %ld undo file malformed\n", height);
        return 0;
    }
    if (nrec != cc.n_inputs){
        fprintf(stderr, "[utxo_live] unapply pre-flight REFUSED at height %ld: undo records=%ld but block spends %ld inputs (undo data missing, pruned, or stale)\n",
                height, nrec, cc.n_inputs);
        return 0;
    }
    return 1;
}

/* ---- the actual unapply ---- */
static int undo_restore_cb(void* ctx, const u8 txid[32], u32 index, u64 value,
                           const u8* script, u16 slen){
    int* fatal = (int*)ctx;
    long r = utxo_lsm_put(&g_utxo_lst, g_utxo_table, txid, index, value, script, (u32)slen);
    if (r == -1 || r == 2) { *fatal = 1; return 0; }
    return 1;
}

typedef struct { const u8* txid; int fatal; } del_created_ctx_t;

static void del_created_on_output(void* ctxv, u32 out_index, u64 value,
                                  const u8* script, u32 slen){
    del_created_ctx_t* c = (del_created_ctx_t*)ctxv;
    (void)value; (void)script; (void)slen;
    long r = utxo_lsm_del(&g_utxo_lst, g_utxo_table, c->txid, out_index);
    if (r == -1) c->fatal = 1;   /* 0 (already absent: spent inside this same
                                  * block, or by a descendant we already
                                  * unapplied) is expected, not an error */
}

/* utxo_live_unapply_block(buf, len, height) -> 1 clean / 0 failed.
 * Caller MUST have run utxo_live_can_unapply over the whole range first --
 * see the reorg driver, which pre-flights every height it intends to
 * disconnect BEFORE it mutates anything. */
int utxo_live_unapply_block(const void* blockbuf, u64 blocklen, long height){
    /* Undo capture must be OFF for the duration: the puts/dels below are the
     * reversal of a block's effects, not the application of one, and letting
     * them write undo records would corrupt the file for the height being
     * unapplied. */
    int saved = g_undo_enabled;
    g_undo_enabled = 0;

    int fatal = 0;
    long r = undo_replay(height, undo_restore_cb, &fatal);
    if (r < 0 || fatal){
        fprintf(stderr, "[utxo_live] unapply height %ld: undo replay failed (r=%ld fatal=%d)\n", height, r, fatal);
        g_undo_enabled = saved;
        return 0;
    }

    del_created_ctx_t dc = { 0, 0 };
    int ok = walk_block_txs((const u8*)blockbuf, blocklen, &dc, 0,
                            del_created_on_output, &dc.txid);
    g_undo_enabled = saved;
    if (!ok || dc.fatal){
        fprintf(stderr, "[utxo_live] unapply height %ld: created-output removal failed (ok=%d fatal=%d)\n", height, ok, dc.fatal);
        return 0;
    }
    /* This height is no longer on our chain -- drop its undo file so a block
     * later reconnected at the same height starts clean (undo_append_record
     * opens O_APPEND). */
    undo_discard(height);
    return 1;
}

/* Public apply entry for the reorg RECONNECT path: identical to what
 * catch-up does per block, including undo capture, so a reconnected block is
 * itself disconnectable afterwards. */
int utxo_live_apply_block(const void* blockbuf, u64 blocklen, long height){
    return apply_block_at((const u8*)blockbuf, blocklen, height);
}

/* Rewind the persisted applied-height counter after a disconnect, so a
 * subsequent utxo_live_catchup re-applies from the new fork tip rather than
 * believing heights that no longer exist are already applied. */
int utxo_live_rewind_to(long height){
    g_applied_height = height;
    return persist_applied_height(height);
}

void utxo_live_set_undo_enabled(int on){ g_undo_enabled = on; }

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
        if (!apply_block_at(blockbuf, (u64)len, h)) {
            fprintf(stderr, "[utxo_live] FATAL: apply_block failed at height %ld -- stopping catch-up\n", h);
            return -1;
        }
        g_applied_height = h;
        applied++;
    }
    if (applied > 0) {
        /* STAGE B: steady-state undo-data retention. Bounded and resumable
         * (see undo_prune_from) so this stays O(1) per catch-up call at
         * mainnet depth instead of re-sweeping from height 0 every time. */
        if (g_undo_enabled)
            g_undo_prune_cursor = undo_prune_from(g_undo_prune_cursor, g_applied_height,
                                                  UTXO_UNDO_WINDOW, UTXO_UNDO_PRUNE_SCAN);
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

/* Handles onto the ONE live writable LSM instance, so a caller that needs to
 * read the confirmed set (tests/test_reorg.c's expected-vs-actual UTXO diff,
 * and any in-process mempool prevout resolution) queries exactly the
 * instance this module writes to, rather than a second reloaded snapshot
 * that could lag it. */
void* utxo_live_table(void){ return g_utxo_table; }
void* utxo_live_lst(void){ return &g_utxo_lst; }

void utxo_live_close(void){
    utxo_lsm_close(&g_utxo_lst);
}
