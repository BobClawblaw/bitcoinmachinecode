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
#include "genesis_skip.h"
#include "chainparams.h"
#include "../script_flags_consts.h"   /* per-chain BIP34 activation heights
                                       * (VAL-1: coinbase height push) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "node_config.h"
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
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index, u64 value,
                         u64 height, u64 is_coinbase, const u8* script, u32 slen);
extern long utxo_lsm_del(void* lst, void* u, const u8 txid[32], u32 index);
/* A flush with no accompanying put/del -- see the asm's own header for why
 * this exists and who needs it (daemon catch-up completion). */
extern long utxo_lsm_flush(void* lst, void* u);
extern long utxo_lsm_count(void* lst);
/* returns the live entry count (or -1); NOT an int -- an implicit
 * declaration here truncated it to 32 bits. */
extern long utxo_lsm_walk(void* lst, void* u, void* cb, void* ctx);
extern long utxo_lsm_compact(void* lst);
extern long utxo_lsm_compact_range(void* lst, unsigned long lo, unsigned long k);
extern void utxo_lsm_close(void* lst);

/* ---- STAGE B: per-block undo data (daemon/undo_log.c) --------------------
 * Stage A built these but deliberately left live_on_input untouched. They
 * are wired in below: every input the live daemon spends is now captured
 * (value + scriptPubKey, read out of the LSM immediately before the delete)
 * into undo_<height>.dat, which is what makes a later DISCONNECT of that
 * block possible at all. */
extern long utxo_script_unspendable(const u8* script, unsigned long slen); /* bitcoin_utxo_stats.asm: Core's IsUnspendable() */
extern void utxo_prefetch(void* u, const u8 txid[32], unsigned long index); /* bitcoin_utxo.asm: warm the home slot, pure hint */
extern long undo_capture_and_del(void* lst, void* u, long height,
                                 const u8 txid[32], u32 index);
extern long undo_discard(long height);
extern long undo_prune_from(long from_height, long tip_height, long window, long max_scan);
/* utxo_walk.h supplies u8/u32/u64 but not u16 (undo records carry a u16
 * script length -- see daemon/undo_log.c's record format). */
typedef unsigned short u16;
typedef int (*undo_replay_cb)(void* ctx, const u8 txid[32], u32 index,
                              u64 value, u32 height, u8 is_coinbase,
                              const u8* script, u16 slen);
extern long undo_replay(long height, undo_replay_cb cb, void* ctx);
extern long undo_replay_tolerant(long height, undo_replay_cb cb, void* ctx, int* torn);

/* ---- STAGE D / CROSS-TX PARALLEL VERIFY (2026-08-19): per-input script
 * verification + coinbase maturity (daemon/tx_verify.c). Called ONCE per
 * block, for every non-coinbase tx at once (tx_verify_block_connect_all),
 * BEFORE any of the block's puts/dels are applied below -- exactly where
 * Core's ConnectBlock runs CheckInputs, ahead of UpdateCoins.
 *
 * A tx may spend an output created by an EARLIER tx in the SAME block;
 * since verification now runs before any of this block has been applied,
 * that can no longer resolve through the confirmed UTXO set the way the
 * old strictly-sequential verify-then-apply loop let it. build_block_index
 * below builds an in-block outpoint index BEFORE calling into tx_verify.c,
 * which consults it (via the exported bidx_get) ahead of falling back to
 * utxo_lsm_get. See tx_verify.c's own "CROSS-TRANSACTION PARALLEL
 * VERIFICATION" header comment for the full design rationale.
 *
 * Also builds/checks a whole-block duplicate-outpoint set (check_dup_
 * outpoints): the OLD interleaved loop caught an in-block double-spend only
 * as an accidental side effect (the second spender's utxo_lsm_get failed
 * once the first spender's output had already been deleted) -- that
 * detection disappears once verification runs before any apply, so this is
 * now an explicit check, run before verification, matching Core's own
 * CheckBlock (a whole-block structural check, not part of per-tx script
 * verification). */
typedef struct {
    const u8* ptr;
    u64 len;
    u8  txid[32];
    u32 pn_in;    /* tx_parse's own input count -- tx_verify.c reuses this
                    * to size its flat verify array without re-parsing */
} block_tx_t;
#include <stddef.h>
#include "block_witness.h"
#include "signet_block.h"
#include "bip30_consts.h"
/* block_witness.c reads only the (ptr, len) prefix of block_tx_t, by stride. */
_Static_assert(offsetof(block_tx_t, ptr) == 0 && offsetof(block_tx_t, len) == 8, "block_tx_t prefix must match bw_txref_t");
extern unsigned long long script_flags_for_block(unsigned long long height, const u8 hash32[32]);
extern int tx_verify_block_connect_all(const block_tx_t* txs, u64 ntx, long height,
                                       const u8 block_hash32[32], void* lst, void* u, void* bx,
                                       u64* fail_tx_index, const char** reason);
/* VAL-1 fees ledger (audit 2026-09-03): per-tx input sums (index = block tx
 * position) gathered by tx_verify_block_connect_all's Phase 1 resolve pass,
 * valid for the immediately preceding call. Returns NULL + n=0 if no call
 * has run. */
extern const u64* txvb_last_tx_in_sums(u64* n_out);
extern void block_hash(u8 out[32], const u8 hdr[80]);

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

/* Must mirror bitcoin_utxo_lsm.asm's state struct exactly (168 bytes). */
#include "lsm_state.h"
#include "lsm_manifest.h"
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
#define UTXO_LIVE_COMPACT_THRESHOLD 12   /* default for bmc.utxocompactthreshold */
long utxo_live_compact_threshold(void);

/* ---- BULK (far-behind) memtable sizing ---------------------------------
 * The steady-state sizing above is deliberately small so a per-inbound-child
 * utxo_lsm_reload() (a full current-generation WAL replay) stays cheap. That
 * is the right trade when we are a few blocks behind -- and badly wrong for a
 * from-scratch or long-gap replay, where it is quadratic: every flush is
 * ~49k entries, every 12th flush triggers utxo_lsm_compact, and compact
 * merges ALL runs into one, i.e. rewrites the ENTIRE UTXO set. Cost per
 * compaction grows with the set while the trigger cadence stays fixed.
 *
 * Measured in production on 2026-08-18: with a fixed ~590k UTXO ops between
 * compactions, wall time per compaction interval grew from ~2-4s at height
 * 125k to ~13.5s by 305k, still climbing -- 140 full-set rewrites in 21
 * minutes, and the set only ~2% of its eventual size.
 *
 * So: when we boot a long way behind, size the memtable like the batch tool
 * (daemon/build_utxo.c, whose documented production default is exactly
 * 2^22 / 1GB) and flush ~64x less often. Once caught up we downshift the
 * flush thresholds back to steady-state values (see utxo_live_catchup), which
 * restores the cheap-inbound-reload property the small sizing existed for.
 * Buffers stay allocated at bulk size -- lowering a threshold below the
 * capacity it was sized for is always safe; raising it would not be. */
#define UTXO_LIVE_BULK_SLOTS_LOG2 22
#define UTXO_LIVE_BULK_BLOB_BYTES (1024UL<<20)
#define UTXO_LIVE_BULK_GAP_BLOCKS 50000L
/* ...and independently: a current-generation WAL at least this large means the
 * RELOAD is batch-scale even when the remaining block gap is not. See
 * utxo_live_init. 256 MB is ~5x the biggest tail steady-state operation can
 * produce and ~1/7th of the one that wedged a restart on 2026-08-23. */
#define UTXO_LIVE_BULK_WAL_BYTES (256ULL<<20)

static void* g_utxo_table = 0;

struct lsm_state g_utxo_lst;
/* ---- compaction in the background ------------------------------------------
 * Compaction rewrites the whole live set -- 13 GB on production -- and used to
 * run inline in the apply path: a 3-5 minute stall every ~90 blocks, measured
 * 2026-08-31, invisible only because tip-following resumed afterwards. It
 * touches nothing the applier mutates (immutable runs in, one run out, then
 * the manifest), so it runs in a forked child now while apply continues.
 *
 * The one shared thing is the MANIFEST, and the protocol is:
 *   - the child merges with unlink AND publish deferred
 *     (utxo_lsm_set_defer_unlink/_publish): it writes its result manifest to
 *     utxo_manifest.child and leaves its input runs on disk. The parent still
 *     holds the old manifest and may open those runs by name; unlinking under
 *     it would turn a lookup into a false miss;
 *   - the parent keeps applying AND flushing meanwhile (a flush publishes the
 *     manifest itself; the run numbers/gens the child uses were reserved
 *     before it forked, so they cannot collide);
 *   - on exit the parent adopts (lsm_manifest_adopt_child): [child's entries]
 *     + [runs flushed since fork], live counter healed by the persisted
 *     base's movement (the file's count is RUNS-ONLY, the running one also
 *     has the WAL tail -- the inline compaction's own rule), publishes,
 *     bumps the reader-cache epoch, THEN unlinks the inputs;
 *   - mac_flush calls a hook first (utxo_lsm_set_flush_hook); the hook
 *     adopts a finished child promptly so a flush never has to wait.
 * Crash safety: a parent that dies mid-child leaves the manifest untouched
 * (inputs present, the child's output an orphan); a child that dies leaves
 * one orphan run. Orphans are swept at boot (lsm_manifest_sweep_orphans),
 * before any writer exists. Shutdown kills the child; the merge is redone.
 * that dies leaves the manifest untouched and one orphan output run. */
extern void utxo_lsm_set_defer_unlink(long on);
extern void utxo_lsm_set_defer_publish(long on);
extern void utxo_lsm_set_flush_hook(void (*fn)(void));
extern void lsm_mm_invalidate_all(void);
static pid_t   g_cmp_pid = 0;
static struct timespec g_cmp_t0;
static u64     g_cmp_inputs[64]; static int g_cmp_nin = 0;
static u64     g_cmp_n_before = 0;
static long    g_cmp_height = 0;
static void (*g_cmp_prev_sigchld)(int) = 0;
static int     g_cmp_fallbacks = 0;
static u64     g_cmp_old_base = ~0ULL;   /* persisted runs-only live count at fork time */
static int     g_cmp_is_full = 0;        /* the k inputs were the whole manifest at fork */
static u64     g_cmp_child_run = 0;      /* run_no reserved for the child's output */

static void unlink_run(u64 run_no){
    char n[64]; snprintf(n, sizeof n, "utxo_run_%06u.dat", (unsigned)run_no); unlink(n);
}
static int manifest_names(u64 run_no){
    const unsigned char* e = (const unsigned char*)g_utxo_lst.manifest_buf;
    for (u64 i = 0; i < g_utxo_lst.manifest_n; i++){ u64 r; memcpy(&r, e + i*16 + 8, 8); if (r == run_no) return 1; }
    return 0;
}
static void compact_adopt(int st){
    struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (t1.tv_sec - g_cmp_t0.tv_sec) + (t1.tv_nsec - g_cmp_t0.tv_nsec) / 1e9;
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0){
        u64 nbase = ~0ULL;
        if (lsm_manifest_adopt_child(&g_utxo_lst, g_cmp_inputs, g_cmp_nin, g_cmp_is_full, g_cmp_old_base, &nbase) != 0){
            /* keep the old manifest: its runs are all still on disk (unlink
             * was deferred), so this process stays consistent. The child's
             * output is an orphan; drop it now rather than at next boot. */
            unlink_run(g_cmp_child_run); unlink(LSM_MANIFEST_CHILD);
            fprintf(stderr, "[utxo_live] background compaction finished in %.1fs but its manifest did not reconcile with ours -- discarded (run %lu), old run set kept\n",
                    secs, (unsigned long)g_cmp_child_run);
        } else {
            lsm_mm_invalidate_all();
            int gone = 0;
            for (int i = 0; i < g_cmp_nin; i++) if (!manifest_names(g_cmp_inputs[i])){ unlink_run(g_cmp_inputs[i]); gone++; }
            long interim = (long)g_utxo_lst.manifest_n - ((long)g_cmp_n_before - g_cmp_nin + 1);   /* runs flushed since fork */
            fprintf(stderr, "[utxo_live] background compaction done in %.1fs: manifest_n %lu -> %lu (%d merged into run %lu, %ld flushed meanwhile), %d input run(s) unlinked (started at height %ld; apply never waited)\n",
                    secs, (unsigned long)g_cmp_n_before, (unsigned long)g_utxo_lst.manifest_n, g_cmp_nin, (unsigned long)g_cmp_child_run, interim, gone, g_cmp_height);
        }
    } else {
        unlink_run(g_cmp_child_run); unlink(LSM_MANIFEST_CHILD);
        fprintf(stderr, "[utxo_live] background compaction FAILED after %.1fs (%s %d) -- manifest unchanged, partial run %lu removed\n",
                secs, WIFSIGNALED(st) ? "signal" : "status", WIFSIGNALED(st) ? WTERMSIG(st) : WEXITSTATUS(st), (unsigned long)g_cmp_child_run);
    }
    g_cmp_pid = 0;
    if (g_cmp_prev_sigchld) signal(SIGCHLD, g_cmp_prev_sigchld);
}
static void compact_poll(void){
    if (!g_cmp_pid) return;
    int st; pid_t r = waitpid(g_cmp_pid, &st, WNOHANG);
    if (r == g_cmp_pid) compact_adopt(st);
}
/* mac_flush's gate: a flush is about to rewrite the manifest. It no longer
 * waits for anything -- run numbers are reserved, adoption reconciles -- it
 * just adopts a finished child first so the flush builds on the merged set. */
static void compact_flush_hook(void){ compact_poll(); }
/* Leveled: which runs to merge, by size ratio (lsm_compact_pick). Sizes come
 * from the run files themselves. Returns k, sets *lo. */
/* Byte budget for the mapped run files: 45% of MemTotal by default (the
 * memtable mapping, the flush scratch and the rest of the box need the
 * other half), overridable for tests. 0 = off. */
static u64 g_run_budget = ~0ULL;
u64 utxo_live_run_budget(void){
    if (g_run_budget != ~0ULL) return g_run_budget;
    u64 kb = 0; FILE* f = fopen("/proc/meminfo", "r");
    if (f){ char line[128]; while (fgets(line, sizeof line, f)) if (!strncmp(line, "MemTotal:", 9)){ kb = strtoull(line + 9, NULL, 10); break; } fclose(f); }
    /* 35%, not 45%: on the 63 GB box the worker itself holds ~16 GB of anonymous
     * flush scratch plus the file-backed memtable, and at 25.7 GB of runs (4 runs)
     * lookups were already faulting from disk (2026-09-01 18:09, 3-12 blk/s). */
    g_run_budget = kb ? kb * 1024 / 100 * 35 : 0;
    return g_run_budget;
}
void utxo_live_set_run_budget(unsigned long long bytes){ g_run_budget = bytes; }
static long compact_pick_now(long* lo){
    long n = (long)g_utxo_lst.manifest_n;
    if (n < 2) return 0;
    static u64 sizes[256];
    if (n > 256) n = 256;
    const unsigned char* e = (const unsigned char*)g_utxo_lst.manifest_buf;
    for (long i = 0; i < n; i++){
        u64 r; memcpy(&r, e + i*16 + 8, 8);
        char nm[64]; snprintf(nm, sizeof nm, "utxo_run_%06u.dat", (unsigned)r);
        struct stat sb; sizes[i] = stat(nm, &sb) == 0 ? (u64)sb.st_size : 0;
    }
    u64 budget = utxo_live_run_budget();
    long k = lsm_compact_pick_budget(sizes, n, utxo_live_compact_threshold(), 64, budget, lo);
    if (k && n < utxo_live_compact_threshold()){
        static long announced = -1; u64 total = 0; for (long i = 0; i < n; i++) total += sizes[i];
        if (announced != n){ announced = n;
            fprintf(stderr, "[utxo_live] run files total %.1f GB > budget %.1f GB (35%% of RAM) -- compacting %ld of %ld runs below the count threshold\n",
                    (double)total / 1e9, (double)budget / 1e9, k, n); }
    }
    return k;
}
static long g_cmp_lo = 0;
static int compact_start_async(long height, const char* why){
    if (g_cmp_pid) return 0;
    long lo = 0, k = compact_pick_now(&lo);
    if (k == 0) return 0;
    g_cmp_nin = (int)k; g_cmp_lo = lo;
    const unsigned char* e = (const unsigned char*)g_utxo_lst.manifest_buf;
    for (int i = 0; i < g_cmp_nin; i++) memcpy(&g_cmp_inputs[i], e + (lo + i)*16 + 8, 8);
    g_cmp_n_before = g_utxo_lst.manifest_n; g_cmp_height = height;
    g_cmp_old_base = lsm_manifest_persisted_live();
    /* SIGCHLD is SIG_IGN in the download worker (children auto-reap), which
     * would make waitpid lose the exit status; take it back for our child. */
    g_cmp_prev_sigchld = signal(SIGCHLD, SIG_DFL);
    pid_t p = fork();
    if (p < 0){
        signal(SIGCHLD, g_cmp_prev_sigchld);
        g_cmp_fallbacks++;
        fprintf(stderr, "[utxo_live] fork for background compaction failed (%s) -- compacting inline\n", strerror(errno));
        long cr = utxo_lsm_compact_range(&g_utxo_lst, (unsigned long)lo, (unsigned long)k);
        fprintf(stderr, "[utxo_live] %s compact at height %ld: manifest_n=%lu -> result=%ld\n", why, height, (unsigned long)g_utxo_lst.manifest_n, cr);
        return 1;
    }
    if (p == 0){
        /* child: no stdio (a parent thread may hold its lock at fork), no
         * atexit, nothing but the merge. */
        utxo_lsm_set_flush_hook(0);
        utxo_lsm_set_defer_unlink(1);
        utxo_lsm_set_defer_publish(1);
        long cr = utxo_lsm_compact_range(&g_utxo_lst, (unsigned long)lo, (unsigned long)k);
        _exit(cr > 0 ? 0 : 2);
    }
    /* reserve the child's output number and generation: it uses the values
     * it inherited; our next flush must skip them. */
    g_cmp_child_run = g_utxo_lst.next_run_no; g_utxo_lst.next_run_no++; g_utxo_lst.next_gen++;
    g_cmp_is_full = (lo == 0 && (u64)g_cmp_nin == g_utxo_lst.manifest_n);
    g_cmp_pid = p; clock_gettime(CLOCK_MONOTONIC, &g_cmp_t0);
    fprintf(stderr, "[utxo_live] compaction of %d run(s) [%ld..%ld) of %lu started in background pid %d (%s at height %ld; %s) -- apply continues\n",
            g_cmp_nin, lo, lo + k, (unsigned long)g_utxo_lst.manifest_n, (int)p, why, height,
            g_cmp_is_full ? "full merge" : lo == 0 ? "oldest runs" : "newest runs, tombstones kept");
    return 1;
}
/* For the daemon's shutdown path: a child mid-merge is killed, not awaited --
 * shutdown has a 90 s budget and the merge is redone next boot for free. */
void utxo_live_compact_shutdown(void){
    if (!g_cmp_pid) return;
    kill(g_cmp_pid, SIGKILL);
    int st; while (waitpid(g_cmp_pid, &st, 0) < 0 && errno == EINTR) {}
    fprintf(stderr, "[utxo_live] shutdown: killed background compaction pid %d (its partial run is an orphan)\n", (int)g_cmp_pid);
    g_cmp_pid = 0;
}
/* How many compactions have run in this process (for tests/status). */
int utxo_live_compaction_running(void){ return g_cmp_pid != 0; }
static long  g_applied_height = -1;
/* Height whose block is currently being applied -- the key undo records are
 * filed under. Set by apply_block_at before any walk begins. */
static long  g_apply_height = -1;
/* -assumevalid (2026-09-01): the height of the operator's assumed-valid block,
 * resolved from the archive index at init (-1 = none). While applying a block
 * at or below it, tx_verify's script EVALUATION is switched off -- everything
 * else (PoW, merkle, structure, every UTXO check) runs unchanged, exactly
 * Core's semantics. A submitblock dry run always evaluates scripts. */
extern void tx_verify_set_script_checks(int on);
static long g_assumevalid_height = -1;
static int  g_av_announced_end = 0;
extern const chainparams_t* g_chainp;
static void utxo_live_resolve_assumevalid(void){
    g_assumevalid_height = -1;
    unsigned char want[32];
    if (g_cfg.assumevalid_mode == 2) return;                       /* assumevalid=0 */
    if (g_cfg.assumevalid_mode == 1) memcpy(want, g_cfg.assumevalid, 32);
    else {                                                          /* the chain default, as Core ships it */
        if (!g_chainp || !g_chainp->assumevalid) return;
        const char* hx = g_chainp->assumevalid;
        for (int q = 0; q < 32; q++){
            int hi = hx[2*q], lo = hx[2*q+1];
            hi = hi>='0'&&hi<='9'?hi-'0':hi>='a'&&hi<='f'?hi-'a'+10:hi-'A'+10;
            lo = lo>='0'&&lo<='9'?lo-'0':lo>='a'&&lo<='f'?lo-'a'+10:lo-'A'+10;
            want[31-q] = (unsigned char)((hi<<4)|lo);
        }
    }
    FILE* f = fopen("index.dat", "rb"); if (!f) return;
    unsigned char rec[48]; long h = 0;
    while (fread(rec, 1, 48, f) == 48){ if (!memcmp(rec, want, 32)){ g_assumevalid_height = h; break; } h++; }
    fclose(f);
    if (g_assumevalid_height >= 0)
        fprintf(stderr, "[utxo_live] assumevalid: block found at height %ld -- script evaluation skipped through it, resumed above\n", g_assumevalid_height);
    else
        fprintf(stderr, "[utxo_live] assumevalid: block not in the archive -- every script is evaluated\n");
}



/* Mined-transaction callback: the serve worker registers a hook that removes
 * each just-CONFIRMED txid from the shared mempool, so getblocktemplate can
 * never offer an already-mined (now double-spending) transaction. Only the
 * reorg reconnect path did this before -- the normal apply path left mined
 * txs in the pool forever (found by the mining-polish template differential:
 * bmc's pool held 11 confirmed txs Core's had dropped). NULL (tools, tests,
 * catch-up-only processes) = no-op. */
static void (*g_mined_cb)(const unsigned char txid[32]) = 0;
void utxo_live_set_mined_cb(void (*cb)(const unsigned char[32])){ g_mined_cb = cb; }
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

/* TEST-ONLY crash injection (default disabled, -1). When armed (>=0),
 * utxo_live_catchup's per-block loop calls _exit(1) the instant `applied`
 * (this call's own count of newly-applied blocks) reaches the armed value --
 * immediately after that block's checkpoint persist, before anything else in
 * the loop or the function's own end-of-call bookkeeping. Simulates an
 * unclean process kill partway through a batch, for
 * tests/test_utxo_catchup_crash_resume.c to prove a restart never needs to
 * re-verify an already-durably-applied block. Production code never calls
 * the setter, so this is always a no-op (one integer compare) outside tests. */
static long g_test_crash_after_applied = -1;
void utxo_live_test_set_crash_after(long n){ g_test_crash_after_applied = n; }
#define UTXO_LIVE_TEST_CRASH_HOOK(applied_count) \
    do { if (g_test_crash_after_applied >= 0 && (applied_count) == g_test_crash_after_applied) _exit(1); } while (0)

/* TEST-ONLY crash injection, second generation (2026-08-22): the hook above
 * fires AFTER a block's checkpoint persist, i.e. at the one point in the
 * per-block cycle where a kill is harmless. The production failure that
 * motivated this file's crash-recovery path (see utxo_live_recover_partial_
 * block below) was a SIGKILL landing BEFORE the persist -- after the block's
 * spends were already durable in the WAL -- so the tests need to be able to
 * die there too, and mid-block. Two more arming points:
 *   UTXO_LIVE_CRASH_BEFORE_PERSIST n : _exit(1) right after the n-th block of
 *                                      this catch-up call has fully applied
 *                                      (all puts/dels in the WAL), before its
 *                                      checkpoint is written.
 *   UTXO_LIVE_CRASH_AFTER_INPUTS   n : _exit(1) right after the n-th
 *                                      non-coinbase input seen since init
 *                                      has been captured-and-deleted --
 *                                      i.e. partway through a block.
 * Always a no-op in production (one integer compare each). */
#define UTXO_LIVE_CRASH_BEFORE_PERSIST 1
#define UTXO_LIVE_CRASH_AFTER_INPUTS   2
static int  g_test_crash_mode = 0;
static long g_test_crash_n = -1;
static long g_test_input_count = 0;
void utxo_live_test_set_crash(int mode, long n){ g_test_crash_mode = mode; g_test_crash_n = n; }
#define UTXO_LIVE_TEST_CRASH_AT(mode_, count_) \
    do { if (g_test_crash_mode == (mode_) && (count_) == g_test_crash_n) _exit(1); } while (0)

/* Shutdown flag, registered by the process that owns the signal handler
 * (daemon/main.c's download worker: utxo_live_set_shutdown_flag(&g_shutdown_
 * requested)). utxo_live_catchup polls it after every block. Until
 * 2026-08-22 nothing in this file ever looked at the flag: a from-scratch
 * replay is one multi-hour utxo_live_catchup call, so SIGTERM just set a
 * bit nobody read, systemd's TimeoutStopSec (90s) expired on every single
 * stop/restart during bulk catch-up, and the worker was SIGKILLed mid-block
 * -- which is what created the checkpoint-lag window that the recovery path
 * below now also closes from the other side. A pointer rather than an
 * extern keeps this file free of main.c internals (tests register their own
 * flag). */
static const volatile sig_atomic_t* g_shutdown_flag = 0;
void utxo_live_set_shutdown_flag(const volatile sig_atomic_t* flag){ g_shutdown_flag = flag; }
static inline int shutdown_requested(void){ return g_shutdown_flag && *g_shutdown_flag; }

/* One-shot per process lifetime (reset by init/close): has the
 * partially-applied-block check run yet? */
static int g_recovery_checked = 0;
static long g_recovery_result = 0;   /* utxo_live_recover_partial_block's verdict, once */

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

/* ---- coinstats-index observers (daemon/coinstats_index.c) ---------------
 * Registered by the worker at boot; NULL everywhere else (tests, tools),
 * so no link set changes. add/remove fire only on REAL state transitions
 * (put returned 1 / del of a coin that existed) -- the property that makes
 * a crash-resumed re-apply a no-op stream and a partial-apply rollback an
 * exactly-cancelling one. invalidate fires on the paths whose events this
 * module cannot describe (pre-BIP34 coinbase overwrite, spends outside the
 * undo-capture path). */
typedef void (*csi_coin_fn)(const u8 txid[32], u32 index, u64 value, u64 height,
                            u64 coinbase, const u8* script, unsigned long slen);
static csi_coin_fn g_csi_add = 0, g_csi_rm = 0;
static void (*g_csi_inval)(const char*) = 0;
static void (*g_csi_commit)(long) = 0;   /* per-block durability point */
void utxo_live_set_coinstats(csi_coin_fn add, csi_coin_fn rm,
                             void (*inval)(const char*), void (*commit)(long)){
    g_csi_add = add; g_csi_rm = rm; g_csi_inval = inval; g_csi_commit = commit;
}

extern long utxo_store_wal_drain(void* st);
static int persist_applied_height(long h){
    /* the height claims every op through h is in the WAL: land the buffer first */
    if (utxo_store_wal_drain(&g_utxo_lst) != 0) return 0;
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
    /* the coinstats index persists at the SAME durability point, so its
     * stored height can only ever match or trail the applied height by a
     * crash window -- which boot detects and re-seeds */
    if (g_csi_commit) g_csi_commit(h);
    return 1;
}

/* ---- per-block apply, reusing the shared walker from utxo_walk.h ---- */
static long g_store_inconsistent = 0;   /* set when a spend found no coin the verifier had just resolved (incident 2026-09-01) */
static int  g_halted = 0;               /* UTXO tracking halted for the life of the process (see utxo_live_halted) */
typedef struct {
    const u8* txid;
    long fatal;
    int  is_coinbase;   /* Stage D: true for tx index 0 of the current block --
                          * Bitcoin's own rule (coinbase is always the first tx) */
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
        /* Incident 2026-09-01 (the 2,596 resurrected coins): a 0 here used to be
         * silently accepted as "already absent, re-applied block". That rationale
         * died when Stage D started verifying every prevout BEFORE the apply and
         * utxo_live_recover_partial_block took over crash-resumed blocks: by the
         * time we are here, Phase 1 resolved this exact outpoint a moment ago, so
         * an absent coin now can only mean the store answered two different
         * things to the same question. Under b3d47a9's bad sparse samples that
         * is precisely what happened -- the lookup inside undo_capture_and_del
         * missed for ~10-15% of the coins in a freshly flushed run, the spend was
         * skipped, and the coin came back from the run. The block fails instead
         * (rollback_partial_apply restores the spends already made from this
         * block's undo records), the failure is classified as a store error, and
         * the node retries from the checkpoint -- loudly, never silently. */
        if (r == 0) {
            fprintf(stderr, "[utxo_live] FATAL h=%ld: prevout resolved by verification is ABSENT at apply (store lookup inconsistency) -- failing the block\n",
                    g_apply_height);
            g_store_inconsistent = 1;
            g_halted = 1;          /* nothing below (rollback, retry, recovery) can trust a lookup now */
            ctx->fatal = 1;
        }
        g_test_input_count++;
        UTXO_LIVE_TEST_CRASH_AT(UTXO_LIVE_CRASH_AFTER_INPUTS, g_test_input_count);
        return;
    }
    if (g_csi_inval) g_csi_inval("spend outside undo capture (bulk mode)");
    long r = utxo_lsm_del(&g_utxo_lst, g_utxo_table, txid, index);
    if (r == -1) ctx->fatal = 1;
}

static void live_on_output(void* ctxv, u32 out_index, u64 value, const u8* script, u32 slen){
    apply_ctx_t* ctx = (apply_ctx_t*)ctxv;
    /* Core parity: AddCoin returns early for provably-unspendable scripts
     * (leading OP_RETURN, or script > MAX_SCRIPT_SIZE=10000) -- they NEVER
     * enter Core's chainstate, at any height. Until 2026-08-23 we stored
     * them (~252M of ~419M entries at tip 963,762), so live_utxo read
     * ~2.5x Core's txouts and the set was only comparable through the
     * stats-time filter. Filter shared with the differential tooling:
     * bitcoin_utxo_stats.asm's utxo_script_unspendable, which mirrors
     * Core's IsUnspendable() exactly. Spends can never miss (referencing
     * an unspendable output is consensus-invalid, so no valid block does),
     * and disconnect/rollback already tolerate the absent key
     * (del_created_on_output is get-first, "only delete what is there"). */
    if (utxo_script_unspendable(script, slen)) return;
    /* g_apply_height is already the right value here -- live_on_input uses
     * the same global for undo_capture_and_del above -- and g_apply_height
     * is always >= 0 by the time apply_block_inner runs (set by its sole
     * caller, apply_block_at). */
    long r = utxo_lsm_put(&g_utxo_lst, g_utxo_table, ctx->txid, out_index, value,
                          (u64)g_apply_height, (u64)ctx->is_coinbase, script, slen);

    /* r == 0 means "this outpoint already exists"; utxo_put's .dup path
     * declines the write and keeps the OLD record. For a coinbase output that
     * is wrong -- Core overwrites. src/coins.cpp, AddCoins:
     *
     *     bool overwrite = check_for_overwrite ? cache.HaveCoin(...) : fCoinbase;
     *     // Coinbase transactions can always be overwritten, in order to
     *     // correctly deal with the pre-BIP30 occurrences of duplicate
     *     // coinbase transactions.
     *
     * ConnectBlock calls AddCoins with check_for_overwrite defaulted false, so
     * on the connect path `overwrite` is exactly `fCoinbase`, at every height,
     * with no reference to BIP30 at all.
     *
     * Mainnet has two such duplicates: e3bf3d07...b468:0 (91,722 then 91,880)
     * and d5d27987...8599:0 (91,812 then 91,842). Core's chainstate ends up
     * holding the LATER height; ours held the earlier one. Nothing else in the
     * set differed: at height 963,000 the MuHash over 165,847,393 entries
     * matched Core byte for byte once exactly those two height fields were
     * corrected (LOG.md incident #29). Count, amount and bogosize are all
     * blind to a height field, so only the set hash could ever have seen it.
     *
     * It is not cosmetic: height feeds the 100-block coinbase-maturity rule,
     * so between heights 91,880 and 91,980 we would have accepted a spend Core
     * rejects as immature.
     *
     * del-then-put is the overwrite: the tombstone retires the old record and
     * the second put writes the new one, which is what the WAL replays in
     * order on reload. Live-count is unchanged (one del, one put) because the
     * outpoint exists both before and after. */
    if (r == 1 && g_csi_add)
        g_csi_add(ctx->txid, out_index, value, (u64)g_apply_height,
                  (u64)ctx->is_coinbase, script, slen);
    if (r == 0 && ctx->is_coinbase) {
        /* the OLD coin's fields are not in scope here, so this overwrite's
         * remove-event cannot be described -- pre-BIP34 heights only, which
         * a live-seeded index never replays */
        if (g_csi_inval) g_csi_inval("pre-BIP34 duplicate-coinbase overwrite");
        if (utxo_lsm_del(&g_utxo_lst, g_utxo_table, ctx->txid, out_index) < 0) {
            ctx->fatal = 1; return;
        }
        r = utxo_lsm_put(&g_utxo_lst, g_utxo_table, ctx->txid, out_index, value,
                         (u64)g_apply_height, (u64)ctx->is_coinbase, script, slen);
        fprintf(stderr, "[utxo_live] h=%ld: duplicate coinbase outpoint overwritten (Core: AddCoins overwrite=fCoinbase)\n",
                g_apply_height);
    } else if (r == 0) {
        if (g_csi_inval) g_csi_inval("non-coinbase duplicate outpoint");
        /* A NON-coinbase duplicate. Core does not tolerate this at all: its
         * AddCoin throws "Attempted to overwrite an unspent coin" when
         * possible_overwrite is false. BIP30 is what makes it unreachable, and
         * we now enforce BIP30 (incident #30) -- so reaching here means either
         * a height where Core also skips the check, or a bug. Loud, not fatal:
         * turning it fatal would be a new way to reject a block, and this has
         * never been observed. */
        fprintf(stderr, "[utxo_live] WARNING h=%ld: non-coinbase duplicate outpoint declined (Core's AddCoin would throw here)\n",
                g_apply_height);
    }
    if (r == -1 || r == 2) ctx->fatal = 1; /* -1 I/O error, 2 table full (undersized memtable) */
}

/* rollback_partial_apply(): undo whatever apply_block_inner already
 * committed for transactions 0..upto_t_inclusive of the CURRENT block
 * before failing partway through it, so a retry of this same height starts
 * from the true pre-block state instead of one where the first N
 * transactions' spends already landed. Without this, a retry re-walks from
 * tx 0 and its OWN first spend of an already-consumed input fails with a
 * confusing "missing/already-spent UTXO" that masks the real rejection
 * reason -- exactly what happened live at height 212613 on 2026-08-19 (the
 * OP_NOP1 bug's real error got buried under this artifact on every retry).
 * Forward-declared here; defined below once del_created_on_output and
 * undo_restore_cb exist (this file's existing STAGE B disconnect helpers,
 * reused as-is -- not reimplemented). */
static void rollback_partial_apply(const u8* blockbuf, u64 blocklen, u64 upto_t_inclusive);

/* ---- in-block index (2026-08-19, cross-tx parallel verify; made a
 * persistent/reused arena 2026-08-19 -- see below) --------------------------
 * Two open-addressed hash sets over the same 36-byte (txid+index) outpoint
 * key shape, same technique as bitcoin_utxo_lsm.asm's tomb_hash_buf
 * (mac_tomb_hash_probe):
 *   - bidx_t: outpoint -> the output that created it (value/script/height/
 *     is_coinbase), for resolving same-block chained spends. Consulted by
 *     tx_verify.c via bidx_get, exported below.
 *   - bspent_t: outpoint -> "already claimed by an earlier input in this
 *     block", for the explicit whole-block duplicate-outpoint check.
 *
 * ORIGINALLY malloc'd fresh and freed at the end of every single block
 * (bidx_init/bidx_free, bspent_init/bspent_free) -- profiling the live
 * daemon after deploying that version showed ~4 MILLION minor page faults
 * PER SECOND, with memset (called from calloc/realloc's own zero-fill, and
 * from the manual empty-sentinel refill loop below) as the single largest
 * userspace symbol, its entire call chain resolving into kernel page-fault
 * handler addresses -- fresh malloc/calloc at bulk-mode block rates was
 * handing out brand-new virtual pages that the kernel had to fault in and
 * zero on every touch, EVERY block, more expensive than the crypto work
 * this file exists to parallelize. Fixed the same way bitcoin_utxo_lsm.asm's
 * own tomb_hash_buf already is: one process-lifetime arena per structure,
 * grown (realloc) only when a block needs more than it currently has, never
 * freed -- reused, already-resident pages cost nothing to re-touch, so
 * re-filling the empty-sentinel/zero state on each block is now cheap
 * (still O(active table size), but a pure memory write with no page fault,
 * not a fresh OS allocation). */
static u64 next_pow2_u64(u64 n){
    if (n < 2) return 2;
    u64 p = 1;
    while (p < n) p <<= 1;
    return p;
}
static u64 outpoint_hash(const u8 key[36]){
    u64 h = 0x811c9dc5ULL;
    for (int i=0;i<8;i++){ h ^= key[i]; h = (h * 16777619ULL) & 0xffffffffULL; }
    u32 idx; memcpy(&idx, key+32, 4);
    h ^= idx;
    return h;
}
/* realloc()s *buf up to need_bytes if it isn't already that big, tracking
 * the arena's real capacity in *cap_bytes separately from whatever a
 * caller's CURRENT block only needs -- never shrinks, so a later smaller
 * block reuses the larger existing allocation untouched. */
static void* grow_arena(void** buf, u64* cap_bytes, u64 need_bytes){
    if (need_bytes > *cap_bytes){
        void* p = realloc(*buf, need_bytes);
        if (!p) return 0;
        *buf = p; *cap_bytes = need_bytes;
    }
    return *buf;
}

typedef struct {
    u64 value;
    const u8* spk;       /* points directly into blockbuf -- valid for the
                           * block's whole lifetime, no copy needed */
    u32 spklen;
    u32 creating_tx;     /* an input may only resolve against an output
                           * whose creating_tx is STRICTLY LESS than its own
                           * tx index -- a tx can never spend a later-in-
                           * block tx's not-yet-existing output, matching
                           * real consensus behavior (see bidx_get) */
    u8  is_coinbase;
} bidx_out_t;
typedef struct { u8 key[36]; u64 out_idx; } bidx_slot_t; /* out_idx==(u64)-1: empty */
typedef struct {
    bidx_slot_t* table; u64 table_cap; u64 mask;
    bidx_out_t*  outs;  u64 outs_cap;  u64 outs_n;
} bidx_t;

/* Resets bx for a new block, growing its two arenas only if this block's
 * sizing needs more than they already have. Only the ACTIVE tcap-sized
 * prefix of table gets refilled with the empty sentinel -- correct even
 * when the arena is larger (from an earlier, bigger block) than tcap,
 * since every lookup/insert masks its hash into exactly [0,tcap). */
static void bidx_reset(bidx_t* bx, u64 nout_hint){
    u64 tcap = next_pow2_u64((nout_hint ? nout_hint : 1) * 2);
    grow_arena((void**)&bx->table, &bx->table_cap, tcap * sizeof(bidx_slot_t));
    bx->mask = tcap - 1;
    for (u64 i=0;i<tcap;i++) bx->table[i].out_idx = (u64)-1;
    grow_arena((void**)&bx->outs, &bx->outs_cap, (nout_hint ? nout_hint : 1) * sizeof(bidx_out_t));
    bx->outs_n = 0;
}
static void bidx_insert(bidx_t* bx, const u8 key[36], u64 value, const u8* spk, u32 spklen,
                        u32 creating_tx, u8 is_coinbase){
    u64 idx = bx->outs_n++;
    bx->outs[idx].value = value; bx->outs[idx].spk = spk; bx->outs[idx].spklen = spklen;
    bx->outs[idx].creating_tx = creating_tx; bx->outs[idx].is_coinbase = is_coinbase;
    u64 h = outpoint_hash(key) & bx->mask;
    while (bx->table[h].out_idx != (u64)-1) h = (h+1) & bx->mask;
    memcpy(bx->table[h].key, key, 36);
    bx->table[h].out_idx = idx;
}

/* bidx_get: exported for tx_verify.c. Same argument/return shape as
 * utxo_lsm_get, plus the resolving tx's own 0-based block position. Returns
 * 1 hit / 0 miss (not resolvable in-block -- caller falls back to
 * utxo_lsm_get against the confirmed set). height is always this block's
 * own g_apply_height for an in-block-created output (relevant only for the
 * coinbase-maturity check: a coinbase can never be matured enough to spend
 * within the very block that created it, conf==0 < COINBASE_MATURITY,
 * correctly rejected downstream). */
long bidx_get(void* bxv, u32 caller_tx_index, const u8 txid[32], u32 index,
             u64* value, u64* height, u64* is_coinbase, const u8** script, unsigned long* slen){
    bidx_t* bx = (bidx_t*)bxv;
    u8 key[36]; memcpy(key, txid, 32); memcpy(key+32, &index, 4);
    u64 h = outpoint_hash(key) & bx->mask;
    while (bx->table[h].out_idx != (u64)-1){
        u64 oi = bx->table[h].out_idx;
        if (memcmp(bx->table[h].key, key, 36) == 0){
            if (bx->outs[oi].creating_tx >= caller_tx_index) return 0; /* forward/self reference: not resolvable in-block */
            *value = bx->outs[oi].value; *height = (u64)g_apply_height;
            *is_coinbase = bx->outs[oi].is_coinbase;
            *script = bx->outs[oi].spk; *slen = bx->outs[oi].spklen;
            return 1;
        }
        h = (h+1) & bx->mask;
    }
    return 0;
}

typedef struct { u8* used; u64 used_cap; u8* keys; u64 keys_cap; u64 mask; } bspent_t;
static void bspent_reset(bspent_t* bs, u64 nin_hint){
    u64 tcap = next_pow2_u64((nin_hint ? nin_hint : 1) * 2);
    grow_arena((void**)&bs->used, &bs->used_cap, tcap);
    memset(bs->used, 0, tcap);   /* active tcap-sized prefix only -- see bidx_reset */
    grow_arena((void**)&bs->keys, &bs->keys_cap, tcap * 36);
    bs->mask = tcap - 1;
}
/* Returns 1 the first time this exact outpoint is claimed, 0 if it was
 * already claimed earlier in this same block (an in-block double-spend). */
static int bspent_claim(bspent_t* bs, const u8 key[36]){
    u64 h = outpoint_hash(key) & bs->mask;
    while (bs->used[h]){
        if (memcmp(bs->keys + h*36, key, 36) == 0) return 0;
        h = (h+1) & bs->mask;
    }
    bs->used[h] = 1;
    memcpy(bs->keys + h*36, key, 36);
    return 1;
}

/* VAL-2 (audit 2026-09-03): Core's CAmount MAX_MONEY. Defined here (before
 * both the in-block index builder's value accumulators and the apply-path
 * helpers) so the file has ONE definition of the money ceiling. */
#define VAL_MAX_MONEY 2100000000000000ULL
typedef struct {
    bidx_t* bx; bspent_t* bs;
    const u8* txid; u32 tx_index;
    int dup_found;
    /* ---- VAL-1/VAL-2 accumulators (audit 2026-09-03) ----
     * ic is built fresh per transaction, so tx_out_sum is the per-tx running
     * output total (Core's txouttotal-toolarge checks exactly this running
     * sum). ptx_out points at a block-scope per-tx output-total array owned
     * by apply_block_inner -- the fees ledger's sum(out) side. */
    u64  tx_out_sum;
    int  money_bad;              /* output value or per-tx sum out of range */
    u64* ptx_out;
} idxbuild_ctx_t;

static void idxbuild_on_input(void* ctxv, const u8 txid[32], u32 index){
    idxbuild_ctx_t* c = (idxbuild_ctx_t*)ctxv;
    if (index == 0xFFFFFFFFu && memcmp(txid, ZERO32, 32)==0) return; /* coinbase's null prevout */
    u8 key[36]; memcpy(key, txid, 32); memcpy(key+32, &index, 4);
    if (!bspent_claim(c->bs, key)) c->dup_found = 1;
    /* Warm the memtable's home slot for this prevout NOW, a whole phase
     * before STAGE B's undo_capture_and_del and the verify workers'
     * prevout resolution probe it for real. utxo_get's probe is a chain of
     * dependent cache misses; issuing the address here overlaps that
     * latency with the rest of the index build. Pure hint -- no result can
     * change (see utxo_prefetch in bitcoin_utxo.asm). */
    utxo_prefetch(g_utxo_table, txid, index);
}
static void idxbuild_on_output(void* ctxv, u32 out_index, u64 value, const u8* script, u32 slen){
    idxbuild_ctx_t* c = (idxbuild_ctx_t*)ctxv;
    u8 key[36]; memcpy(key, c->txid, 32); memcpy(key+32, &out_index, 4);
    bidx_insert(c->bx, key, value, script, slen, c->tx_index, (u8)(c->tx_index==0));
    /* VAL-2 (audit 2026-09-03): Core's CheckTransaction runs MoneyRange on
     * every output value and on the running per-tx output total
     * (bad-txns-vout-negative / -vout-toolarge / -txouttotal-toolarge). A
     * u64 read of a signed CAmount puts "negative" values at >= 2^63, so
     * > MAX_MONEY rejects exactly what Core rejects on both arms. */
    if (value > VAL_MAX_MONEY) c->money_bad = 1;
    else {
        c->tx_out_sum += value;
        if (c->tx_out_sum > VAL_MAX_MONEY) c->money_bad = 1;
    }
    /* VAL-1 (fees ledger): block fees = sum over the NON-coinbase txs of
     * (sum(in) - sum(out)). sum(out) accumulates per tx here; sum(in) is
     * exported by tx_verify.c after Phase 1, which already resolved every
     * prevout's value for the script check. Overflow: value <= MAX_MONEY
     * and ptx_out[t] counts one tx's outputs -- a tx's own total cannot
     * exceed MAX_MONEY without money_bad already firing, and ntx x
     * MAX_MONEY still fits u64 for any ntx a 4 MB block can carry. */
    if (c->ptx_out) c->ptx_out[c->tx_index] += value;
}

/* Apply every tx's puts/dels in one block. Returns 1 on a clean apply, 0 on
 * a parse inconsistency (caller logs/skips -- matches build_utxo.c's own
 * corrupt-block handling; the Stage 0 archive-write-race fix plus the
 * corruption repair already run make this an unexpected path in practice,
 * not a normal one). Any failure ONCE THE LOOP HAS STARTED rolls back
 * whatever it already committed (see rollback_partial_apply) before
 * returning -- the two returns before the loop starts (malformed block
 * header) need no rollback since nothing has been applied yet. */
/* ========================================================================
 * BIP30 -- Core's "bad-txns-BIP30" gate (src/validation.cpp, ConnectBlock)
 *
 * A block may not create an outpoint (txid, vout) that already exists as an
 * UNSPENT coin. Until 2026-08-23 this daemon did not check it at all: the
 * rule had a shim (tests/bip30_shim.c) and a full differential against Core
 * (validation/bip30_diff.py), but the shim IMPLEMENTS the rule itself and is
 * not linked into bitcoind, so what passed was a reimplementation, not this
 * code path. See LOG.md incident #30.
 *
 * Core does NOT enforce it unconditionally, and getting that wrong in the
 * strict direction would false-REJECT real blocks. The gate is:
 *
 *     fEnforceBIP30 = !IsBIP30Repeat(pindex);
 *     pindexBIP34height = pindex->pprev->GetAncestor(BIP34Height);
 *     fEnforceBIP30 = fEnforceBIP30 &&
 *         (!pindexBIP34height ||
 *          !(pindexBIP34height->GetBlockHash() == params.BIP34Hash));
 *     if (fEnforceBIP30 || pindex->nHeight >= BIP34_IMPLIES_BIP30_LIMIT) { ... }
 *
 * which on mainnet means: enforce at heights <= 227,931; SKIP from 227,932
 * to 1,983,701 (BIP34 puts the height in the coinbase, so a duplicate
 * coinbase txid cannot recur); enforce again from 1,983,702. The two
 * grandfathered duplicate-coinbase blocks (91,842 and 91,880) are identified
 * by HASH, not height alone, and are skipped.
 *
 * `pprev->GetAncestor(H)` is NULL exactly when H > pprev->nHeight, i.e. when
 * this block's own height <= H -- that is the `height <= BIP34_HEIGHT` arm
 * below, and it is why the boundary is <= and not <.
 *
 * The BIP34-ancestor test is a real check, not an assumption that we are on
 * mainnet: if the block at BIP34Height is NOT BIP34Hash we are on some other
 * chain and Core keeps enforcing, so we must too. It is resolved once and
 * cached. If it cannot be resolved (no store handle, unreadable block) the
 * verdict is ENFORCE -- the safe direction, because over-enforcing can only
 * reject a block that does not exist on any real chain, whereas
 * under-enforcing is a false ACCEPT and a chain split.
 *
 * All constants come from validation/gen_bip30_consts.py, generated from
 * Core's own source. Never hand-transcribe a 64-hex-digit block hash --
 * same rule as asm/script_flags_consts.inc.
 * ====================================================================== */
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index, u64* value,
                         unsigned long* height, unsigned long* is_coinbase,
                         const u8** script, unsigned long* slen);

/* Set by utxo_live_catchup / utxo_live_recover_partial_block, which are the
 * only entry points that own a store handle (utxo_live_init deliberately
 * takes none -- see its comment). NULL is handled: the gate enforces. */
static void* g_bip30_store = 0;

/* Set ONLY by the BIP30 arm below. A differential harness needs to tell a
 * BIP30 rejection apart from every other reason apply_block_inner returns 0
 * -- otherwise a block refused for, say, a bad signature would be scored as a
 * BIP30 hit and the comparison against Core would be meaningless. Read and
 * cleared by utxo_live_test_took_bip30_reject. */
static int g_bip30_rejected = 0;

/* TEST-ONLY: force the gate to "skip", so a harness can exercise the
 * grandfathered path (heights 91,842 / 91,880) without forging a block whose
 * hash matches IsBIP30Repeat. Zero effect unless a test sets it. */
static int g_test_bip30_skip = 0;
void utxo_live_test_force_bip30_skip(int on){ g_test_bip30_skip = on; }

static int bip30_enforced(long height, const u8 hash32[32])
{
    if (g_test_bip30_skip) return 0;
    static const u8 REP0[32] = BIP30_REPEAT0_HASH;
    static const u8 REP1[32] = BIP30_REPEAT1_HASH;
    static const u8 B34 [32] = BIP30_BIP34_HASH;

    if (height == BIP30_REPEAT0_HEIGHT && memcmp(hash32, REP0, 32) == 0) return 0;
    if (height == BIP30_REPEAT1_HEIGHT && memcmp(hash32, REP1, 32) == 0) return 0;

    if (height >= BIP30_IMPLIES_LIMIT) return 1;
    if (height <= BIP30_BIP34_HEIGHT)  return 1;   /* no ancestor at BIP34Height */

    /* 0 = not yet resolved, 1 = ancestor is BIP34Hash (skip), -1 = it is not,
     * or could not be read (enforce). */
    static int anc = 0;
    if (anc == 0) {
        static u8 buf[1u<<20];      /* block 227,931 is ~215 KB */
        u8 h[32];
        long len = g_bip30_store
                 ? store_read_at(g_bip30_store, (u64)BIP30_BIP34_HEIGHT, buf, sizeof buf)
                 : -1;
        if (len >= 80) {
            block_hash(h, buf);
            anc = (memcmp(h, B34, 32) == 0) ? 1 : -1;
        } else {
            anc = -1;
        }
        fprintf(stderr, "[utxo_live] BIP30: ancestor at height %d %s -- %s the duplicate-outpoint check above that height\n",
                BIP30_BIP34_HEIGHT,
                anc == 1 ? "is BIP34Hash" :
                    (len >= 80 ? "is NOT BIP34Hash" : "could not be read"),
                anc == 1 ? "skipping" : "ENFORCING");
    }
    return anc == 1 ? 0 : 1;
}

/* Last reject reason from apply_block_inner, for submitblock's BIP22 result.
 * Reset on entry; only meaningful right after a 0 return. */
static const char* g_last_reject = "";
const char* utxo_live_last_reject(void){ return g_last_reject; }

/* ---- failure classification + honest recovery (incident 2026-09-01) ----
 * utxo_live_catchup() used to fail with a bare -1 and daemon/main.c treated
 * EVERY failure as "manifest full": compact in place, retry, and call the
 * retry's success proof that the failure was benign. On 2026-09-01 eight
 * consensus REJECTs ("input references a missing/already-spent UTXO", caused
 * by b3d47a9's sparse-index offsets) were "recovered" that way, and each
 * round silently lost the spends of the block applied just before the
 * failure: 2,596 spent coins resurrected, muhash parity broken from height
 * 539,017 to the tip. So:
 *   - every failure is CLASSIFIED (consensus reject / store error / other);
 *   - utxo_live_recovery_applicable() admits compaction ONLY for a store
 *     error with a genuinely full manifest -- the one condition compaction
 *     actually cures;
 *   - utxo_live_verify_after_recovery(count_before) walks the whole set and
 *     requires walk == counter == the pre-recovery count. A mismatch HALTS
 *     UTXO tracking for the life of the process (utxo_live_halted()); the
 *     operator drops and rebuilds. Continuing on an inconsistent set is how
 *     the damage became permanent last time. */
#define UTXO_FAIL_NONE   0
#define UTXO_FAIL_REJECT 1   /* verification refused the block: utxo_live_last_reject() names it */
#define UTXO_FAIL_STORE  2   /* a put/del/flush/WAL step returned an error */
#define UTXO_FAIL_OTHER  3   /* hole/short block, partial-block recovery failure */
static int  g_last_fail_kind = UTXO_FAIL_NONE;
long utxo_live_store_inconsistencies(void){ return g_store_inconsistent; }
static long g_last_fail_height = -1;
long utxo_live_last_fail_kind(void){ return g_last_fail_kind; }
long utxo_live_last_fail_height(void){ return g_last_fail_height; }
long utxo_live_halted(void){ return g_halted; }
const char* utxo_live_fail_kind_name(long k){
    return k == UTXO_FAIL_REJECT ? "consensus-reject" : k == UTXO_FAIL_STORE ? "store-error"
         : k == UTXO_FAIL_OTHER ? "archive/recovery" : "none";
}

/* Point query against the LIVE UTXO set, for the gettxout IPC (daemon/main.c).
 * The RPC server runs in the serve PARENT and has no handle on this state --
 * the download worker (this process) owns it. Called ONLY from the worker's
 * quiescent service point, where no put/del/flush is in flight: utxo_lsm_get
 * is thread-safe by itself but this module guarantees get() and flush() never
 * overlap by construction, and that guarantee is what keeps this sound.
 * Returns 1 found / 0 absent, and borrows the script from the LSM's own
 * per-thread buffer -- the caller must copy it before the next call. */
long utxo_live_lsm_get(const u8 txid_wire[32], unsigned int vout,
                       u64* value, unsigned long* height, unsigned long* is_coinbase,
                       const u8** script, unsigned long* slen){
    extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index, u64* value,
                             unsigned long* height, unsigned long* is_coinbase,
                             const u8** script, unsigned long* slen);
    if (!g_utxo_table) return 0;
    return utxo_lsm_get(&g_utxo_lst, g_utxo_table, txid_wire, (u32)vout,
                        value, height, is_coinbase, script, slen) == 1 ? 1 : 0;
}
/* Dry-run mode: run every verification phase (0 through 4) and STOP at the
 * Phase 5 boundary -- the first mutation -- returning 1. The whole point is
 * that this is the SAME code path a real apply takes, so a dry-run pass
 * guarantees the subsequent real apply of the same block against the same
 * state succeeds (single-threaded worker; nothing moves in between). */
static int g_dry_run = 0;

/* ---- nBits schedule enforcement (bad-diffbits) ---------------------------
 * Core's ContextualCheckBlockHeader: a block whose nBits differs from
 * GetNextWorkRequired(parent) is consensus-invalid. The rule engine is the
 * SHARED bitcoin_pow_rules.c -- the same implementation getblocktemplate
 * uses, proven against every header of the real mainnet chain (964,251
 * heights, 478 boundaries) and the real testnet4 chain (149,954 heights,
 * 101k min-difficulty blocks) by validation/pow_replay.c BEFORE being wired
 * here (LOG.md 2026-08-27).
 *
 * INJECTED, default OFF: the hermetic suites build synthetic chains whose
 * headers carry arbitrary nBits (test_reorg, test_cross_tx_verify, ...);
 * only the daemon -- which knows the selected chain -- registers the rules
 * (main.c, right after chainparams_select). Ancestor headers are read
 * straight from the block archive (g_bip30_store), 80 bytes per lookup via
 * the cached read fds; every apply path stores ancestors before applying,
 * and the submitblock dry-run's ancestors are the live chain. */
#include "../bitcoin_pow_rules.h"
extern int  store_get_at(void* st, u64 height, u64 out_meta[3]);
extern int  store_rd_fd(void* st, unsigned file_no);
static int  g_powr_enabled;
static int  g_powr_no_rt, g_powr_mindiff, g_powr_bip94;
static unsigned int g_powr_lim;
void utxo_live_set_pow_rules(int no_retarget, int allow_min_diff,
                             int enforce_bip94, unsigned int pow_limit_bits){
    g_powr_no_rt = no_retarget; g_powr_mindiff = allow_min_diff;
    g_powr_bip94 = enforce_bip94; g_powr_lim = pow_limit_bits;
    g_powr_enabled = 1;
}
static int powr_hdr_from_store(void* ctx, long h, u8 hdr[80]){
    u64 meta[3];
    if (!ctx || store_get_at(ctx, (u64)h, meta) != 1) return 0;
    int fd = store_rd_fd(ctx, (unsigned)meta[2]);
    if (fd < 0) return 0;
    /* +8 skips the [len][magic] frame header -- store_read_meta's own
     * pread does exactly this (bitcoin_store_fast.asm) */
    return pread(fd, hdr, 80, (off_t)meta[0] + 8) == 80 ? 1 : 0;
}

/* ========================================================================
 * VAL-1 / VAL-2 (audit 2026-09-03) -- CheckTransaction's value rules, the
 * coinbase consensus rules, and ConnectBlock's fees/subsidy cap. Until this
 * commit the connect path verified signatures and nothing else about VALUES:
 * a mined block could print money (no MAX_MONEY / MoneyRange / in>=out), a
 * coinbase could name a real outpoint and have Phase 5 delete that coin, and
 * the coinbase output total was never capped at subsidy + fees. Core's rules
 * ported here (CheckTransaction tx_check.cpp, CheckBlock/ContextualCheckBlock
 * /ConnectBlock validation.cpp):
 *
 *   - per-output value in [0, MAX_MONEY], per-tx output sum <= MAX_MONEY;
 *   - no duplicate inputs per tx (CVE-2018-17144; the whole-block
 *     duplicate-outpoint pass skips coinbase inputs, so per-tx it was
 *     unchecked);
 *   - only tx 0 may have a null prevout (bad-txns-prevout-null);
 *   - tx 0: exactly one input, null prevout, scriptSig 2..100 bytes,
 *     sequence ignored;
 *   - BIP34 (per-chain activation height): tx 0 scriptSig starts with the
 *     CScript height push;
 *   - per non-coinbase tx: input sum <= MAX_MONEY and in >= out
 *     (bad-txns-inputvalues-outofrange / bad-txns-in-belowout); the surplus
 *     accumulates as the block's fees;
 *   - coinbase outputs <= subsidy(height) + fees (bad-cb-amount), with
 *     Core's halvings>=64 -> 0 rule.
 *
 * The height/MTP-dependent contextual rules (finality, BIP68, time) are NOT
 * here -- they go in the accept-time gate where headers.dat is authoritative
 * (test harnesses mine year-2027-timestamped blocks into the store directly;
 * enforcing now+2h here would break every apply-path fixture for a rule that
 * is an admission rule in Core too).
 * ------------------------------------------------------------------------ */
static long val_bip34_height(void){
    switch (g_chainp ? g_chainp->id : CHAIN_MAIN){
        case CHAIN_REGTEST:  return SFC_R_HEIGHT_BIP34;
        case CHAIN_TESTNET4: return SFC_T_HEIGHT_BIP34;
        case CHAIN_SIGNET:   return SFC_S_HEIGHT_BIP34;
        default:             return SFC_HEIGHT_BIP34;
    }
}
static u64 val_subsidy(long height){
    if (!g_chainp || g_chainp->halving_interval <= 0) return 5000000000ULL;
    long halvings = height / g_chainp->halving_interval;
    if (halvings >= 64) return 0;                    /* Core's rule */
    return 5000000000ULL >> halvings;
}
/* Read a serialized tx's structural fields straight from its bytes (same
 * walk utxo_walk_tx_io does). Used by Phase 0.75, which needs the scriptSig
 * bounds and input shape that tx_parse's info struct does not carry.
 * (Duplicate inputs need no check here: the whole-block duplicate-outpoint
 * pass claims every non-null prevout via bspent_claim, which fires on a
 * same-tx repeat too -- the CVE-2018-17144 shape is already rejected.) */
typedef struct {
    const u8* in0_script; u64 in0_slen;
    int coinbase_shape;          /* exactly one input with the null prevout */
    int null_prevout;            /* any input after the first carries the
                                    null outpoint (Core: bad-txns-prevout-null) */
    int bad_shape;               /* truncated (a 0-input tx cannot even be
                                    walked by the merkle pass either) */
    u64 in_count;
    u32 locktime;                /* trailing 4 bytes (IsFinalTx, BIP68) */
    u32 version;                 /* BIP68's version>=2 gate */
    const u32* seqs; u32 nseqs;  /* per-input sequences (up to SEQ_CAP; a tx
                                    with more inputs reports nseqs=SEQ_CAP and
                                    the BIP68 pass treats the surplus as
                                    FINAL -- see the note in the pass) */
} val_txinfo_t;
#define VAL_SEQ_CAP 2048
static u32 g_val_seqs[VAL_SEQ_CAP];    /* single-buffer scratch: val_read_tx
                                        * has exactly one live consumer at a
                                        * time (all check loops finish one tx
                                        * before starting the next) */
static int val_read_tx(const u8* tx, u64 txlen, val_txinfo_t* vi){
    memset(vi, 0, sizeof *vi);
    const u8* p = tx; const u8* end = tx + txlen;
    if (p + 5 > end) { vi->bad_shape = 1; return 0; }
    memcpy(&vi->version, tx, 4);
    p += 4;                                        /* version */
    int segwit = (p + 2 <= end && p[0] == 0x00 && p[1] == 0x01);
    if (segwit) p += 2;                            /* segwit marker */
    u64 used;
    u64 nin = utxo_walk_read_varint(p, end, &used); if (!used){ vi->bad_shape=1; return 0; }
    p += used; vi->in_count = nin;
    if (nin == 0) { vi->bad_shape = 1; return 0; }
    vi->seqs = g_val_seqs;
    for (u64 i = 0; i < nin; i++){
        if (p + 36 > end) { vi->bad_shape = 1; return 0; }
        u32 idx; memcpy(&idx, p+32, 4);
        int is_null = (memcmp(p, ZERO32, 32) == 0) && idx == 0xFFFFFFFFu;
        if (i == 0) vi->coinbase_shape = is_null && nin == 1;
        /* ANY null prevout, at any input position. Core's CheckTransaction
         * checks every vin of a non-coinbase tx (a coinbase's own null input
         * is only ever legal as tx0's vin[0]); the Phase 0.15 loop rejects
         * null_prevout for every tx after the coinbase, whichever position
         * it sits in. */
        if (is_null) vi->null_prevout = 1;
        u64 sl = utxo_walk_read_varint(p + 36, end, &used);
        if (!used){ vi->bad_shape=1; return 0; }
        const u8* sp = p + 36 + used;
        p = sp + sl;
        if ((u64)(end - p) < 4){ vi->bad_shape=1; return 0; }
        if (i == 0){ vi->in0_script = sp; vi->in0_slen = sl; }
        if (vi->nseqs < VAL_SEQ_CAP){ memcpy(&g_val_seqs[vi->nseqs], p, 4); vi->nseqs++; }
        else vi->nseqs = VAL_SEQ_CAP;              /* truncation flag (see the
                                                    * BIP68 pass: surplus
                                                    * inputs default FINAL,
                                                    * never FALSE) */
        p += 4;                                    /* sequence */
    }
    /* segwit marker seen -> skip the witness sections (n_in stacks of
     * varint-count + varint-len items) before the trailing locktime.
     * tx_parse has ALREADY validated this exact structure (the tx passed
     * its walk to get here); this pass just locates the locktime, so a
     * decode disagreement is a bad_shape reject, never a skip. */
    if (segwit){
        for (u64 i = 0; i < nin; i++){
            u64 nitems = utxo_walk_read_varint(p, end, &used);
            if (!used){ vi->bad_shape=1; return 0; }
            p += used;
            for (u64 j = 0; j < nitems; j++){
                u64 il = utxo_walk_read_varint(p, end, &used);
                if (!used){ vi->bad_shape=1; return 0; }
                p += used;
                if ((u64)(end - p) < il){ vi->bad_shape=1; return 0; }
                p += il;
            }
        }
    }
    if ((u64)(end - p) < 4){ vi->bad_shape=1; return 0; }
    memcpy(&vi->locktime, p, 4);                   /* locktime */
    return 1;
}
/* CScript() << height, exactly Core's CScriptNum(h).serialize: OP_1..OP_16
 * for h<=16, else push-length + minimal little-endian bytes with the 0x00
 * sign pad. Returns the total byte length written to want. */
static int val_build_height_push(u64 h, u8* want){
    if (h >= 1 && h <= 16){ want[0] = (u8)(0x50 + (u8)h); return 1; }
    int n = 0; u64 vn = h;
    while (vn > 0){ want[1+n] = (u8)(vn & 0xff); vn >>= 8; n++; }
    if (want[1+n-1] & 0x80){ want[1+n] = 0; n++; }
    want[0] = (u8)n;
    return 1 + n;
}

static int apply_block_inner(const u8* blockbuf, u64 blocklen){
    g_last_reject = "";
    if (blocklen < 81) return 0;
    const u8* p = blockbuf + 80;
    const u8* blkend = blockbuf + blocklen;
    u64 consumed;
    u64 ntx = utxo_walk_read_varint(p, blkend, &consumed);
    if (!consumed) return 0;
    p += consumed;
    if (ntx == 0) return 1;   /* matches the old loop's own (never actually
                               * hit by real chain data) empty-block behavior */

    static u8 txid_scratch[4<<20];
    u8 blk_hash[32];
    block_hash(blk_hash, blockbuf);

    /* GENESIS: its coinbase output is NOT part of the UTXO set. Core never
     * writes it to the chainstate, which is why those 50 BTC are famously
     * unspendable -- the outpoint simply does not exist to be looked up.
     * Applying it would leave this node one UTXO richer than Core forever,
     * surfacing the first time our set is compared against `gettxoutsetinfo`
     * (the intended Stage D acceptance test). Genesis has no inputs and one
     * coinbase output, so there is nothing else here to do.
     *
     * Matched by HASH, not by height: the synthetic chains in
     * tests/test_cross_tx_verify.c and tests/test_utxo_checkpoint.c use
     * height 0 as an ordinary block whose outputs later get spent, and a
     * bare `height == 0` test silently dropped those (caught by both suites
     * failing, 2026-08-22). Only reachable at all because the archive now
     * stores real genesis at index 0 as of the same day. */
    if (bmc_is_genesis_block((long)g_apply_height, blk_hash)) return 1;
    /* a CUSTOM signet's genesis hash is derived from its challenge and is in
     * no static list; ask the active chain params too (real header type --
     * a hand-mirrored struct head is how offsets rot) */
    { if (g_apply_height == 0 && g_chainp && g_chainp->genesis_hash &&
          !memcmp(blk_hash, g_chainp->genesis_hash, 32)) return 1; }

    /* nBits schedule (see the block comment above apply_block_inner). The
     * check runs for the dry-run too -- submitblock and GBT proposal answer
     * Core's "bad-diffbits" without touching state. -1 (an ancestor header
     * unreadable) also rejects: refusing to evaluate is safer than accepting
     * unevaluated, and every legitimate path has its ancestors stored. */
    if (g_powr_enabled && g_apply_height >= 1){
        int pr = pow_check_bits(g_apply_height, blockbuf,
                                powr_hdr_from_store, g_bip30_store,
                                g_powr_no_rt, g_powr_mindiff,
                                g_powr_bip94, g_powr_lim);
        if (pr != 1){ g_last_reject = "bad-diffbits"; return 0; }
    }

    /* ---- Phase 0: parse every tx once (same tx_parse this loop always
     * used), building the tx array tx_verify.c also consumes. txs/pn_outs
     * are persistent, process-lifetime arenas (grown, never freed -- see
     * grow_arena's own comment above) instead of a fresh malloc/free every
     * block. A parse failure here means nothing has been applied yet -- no
     * rollback needed, unlike the old code's mid-loop parse failure. ---- */
    static block_tx_t* g_txs = 0; static u64 g_txs_cap = 0;
    static u32* g_pn_outs = 0;    static u64 g_pn_outs_cap = 0;
    block_tx_t* txs = grow_arena((void**)&g_txs, &g_txs_cap, ntx * sizeof(block_tx_t));
    u32* pn_outs = grow_arena((void**)&g_pn_outs, &g_pn_outs_cap, ntx * sizeof(u32));
    if (!txs || !pn_outs) return 0;
    const u8* q = p;
    u64 total_nin = 0, total_nout = 0;
    for (u64 t=0; t<ntx; t++){
        u8 info[64];
        int ok = tx_parse(info, q, (unsigned long)(blkend - q));
        if (!ok) return 0;
        u64 txlen; memcpy(&txlen, info, 8);
        u32 pn_in, pn_out; memcpy(&pn_in, info+12, 4); memcpy(&pn_out, info+16, 4);
        txs[t].ptr = q; txs[t].len = txlen; txs[t].pn_in = pn_in;
        pn_outs[t] = pn_out;
        tx_txid(txs[t].txid, q, txlen, txid_scratch, sizeof txid_scratch);
        total_nin += pn_in; total_nout += pn_out;
        q += txlen;
    }

    /* ---- Phase 0.15 (VAL-1/VAL-2, audit 2026-09-03): CheckTransaction's
     * structural coinbase rules + bad-txns-prevout-null. Context-free, so
     * it runs on the dry-run too -- submitblock answers Core's exact reasons
     * without touching state. tx_parse already bounded every read these
     * checks need (a tx whose input section is malformed never gets here);
     * val_read_tx re-walks for the fields info does not carry (scriptSig
     * extent, prevout nullness). ---- */
    {
        val_txinfo_t vi0, vix;
        if (!val_read_tx(txs[0].ptr, txs[0].len, &vi0) || !vi0.coinbase_shape){
            g_last_reject = "bad-cb-missing"; return 0;
        }
        for (u64 t=1; t<ntx; t++){
            if (!val_read_tx(txs[t].ptr, txs[t].len, &vix) || vix.null_prevout){
                g_last_reject = "bad-txns-prevout-null"; return 0;
            }
        }
        /* CheckBlock: coinbase scriptSig 2..100 bytes (pre-BIP34 history
         * included -- 2 is the floor even for the genesis-era free-form
         * extranonce blocks; Core checks size() < 2 || size() > 100). */
        if (vi0.in0_slen < 2 || vi0.in0_slen > 100){
            g_last_reject = "bad-cb-length"; return 0;
        }
        /* BIP34 (ContextualCheckBlock, per-chain activation height): the
         * scriptSig must START with the serialized block-height push. */
        if (g_apply_height >= val_bip34_height()){
            u8 want[8];
            int wlen = val_build_height_push((u64)g_apply_height, want);
            if (vi0.in0_slen < (u64)wlen || memcmp(vi0.in0_script, want, (size_t)wlen) != 0){
                g_last_reject = "bad-cb-height"; return 0;
            }
        }
    }

    /* ---- Phase 0.25: BIP141 witness commitment (Core CheckWitnessMalleation).
     * A whole-block structural check, like the merkle root: with segwit
     * active and a commitment in the coinbase, sha256d(witness-merkle-root ||
     * nonce) must match it; otherwise no tx may carry witness data. This is
     * the check that rejects a witness-STRIPPED block -- which is exactly
     * what the archive held for every block >= 481824 until 2026-08-22, and
     * what the tx merkle root can never notice. Segwit-active is read from
     * the flag schedule (NULLDUMMY bit == height >= SegwitHeight), the same
     * gate Core uses (DeploymentActiveAfter(prev, SEGWIT)), not the WITNESS
     * script flag, which is on from genesis. Nothing applied yet -- no
     * rollback. ---- */
    {
        unsigned long long bflags = script_flags_for_block((unsigned long long)g_apply_height, blk_hash);
        int segwit_active = (int)((bflags >> BW_SFC_BIT_NULLDUMMY) & 1ULL);
        const char* wreason = "?";
        long wr = block_check_witness_commitment(txs, ntx, sizeof(block_tx_t), segwit_active,
                                                 txid_scratch, sizeof txid_scratch, &wreason);
        if (wr != 1) {
            fprintf(stderr, "[utxo_live] REJECT h=%ld: %s\n", g_apply_height, wreason);
            g_last_reject = "bad-witness-merkle-match";
            return 0;
        }
    }

    /* ---- BIP325: on signet the block SIGNATURE replaces meaningful proof of
     * work, so this is the rule that makes a block expensive to produce.
     * Core checks it in CheckBlock (validation.cpp:3947). A no-op on every
     * other chain -- signet_check_block_chain returns 1 before touching
     * anything unless CHAIN_SIGNET is selected. ---- */
    {
        const char* sreason = "?";
        long sr = signet_check_block_chain(txs, ntx, sizeof(block_tx_t),
                                           blockbuf, &sreason);
        if (sr != 1) {
            fprintf(stderr, "[utxo_live] REJECT h=%ld: %s\n", g_apply_height, sreason);
            g_last_reject = "bad-signet-blksig";
            return 0;
        }
    }

    /* ---- Phase 0.3: BIP30. Core runs this in ConnectBlock BEFORE any
     * script verification, and so do we -- it is one UTXO lookup per created
     * output against a set we have already loaded, so failing here is far
     * cheaper than failing after a block's worth of signatures.
     *
     * EVERY transaction, coinbase included: the only two blocks this has
     * ever fired on are duplicate COINBASES, so a loop starting at t=1 would
     * check exactly the wrong thing. (tx_verify_block_connect_all starts at
     * t=1 because it verifies signatures, which a coinbase has none of --
     * which is why this check lives here and not there.)
     *
     * On mainnet the gate is off from height 227,932 to 1,983,701, so for a
     * node replaying the current chain this loop does not run at all. ---- */
    if (bip30_enforced(g_apply_height, blk_hash)) {
        for (u64 t=0; t<ntx; t++){
            for (u32 o=0; o<pn_outs[t]; o++){
                u64 v; unsigned long hh, cb, sl; const u8* sp;
                if (utxo_lsm_get(&g_utxo_lst, g_utxo_table, txs[t].txid, o,
                                 &v, &hh, &cb, &sp, &sl) == 1) {
                    fprintf(stderr, "[utxo_live] REJECT h=%ld tx=%lu: bad-txns-BIP30 "
                            "(tried to overwrite transaction: output %u already unspent)\n",
                            g_apply_height, (unsigned long)t, (unsigned)o);
                    g_bip30_rejected = 1;
                    g_last_reject = "bad-txns-BIP30";
                    return 0;
                }
            }
        }
    }

    /* ---- Phase 0 cont'd / Phase 0.5: in-block output index + whole-block
     * duplicate-outpoint check, in one pass over the already-parsed array.
     * See this file's own header comment above and tx_verify.c's for why.
     * bx/bs are also persistent, process-lifetime arenas -- reset (not
     * freed+reallocated) every block. ---- */
    static bidx_t bx = {0};
    static bspent_t bs = {0};
    bidx_reset(&bx, total_nout);
    bspent_reset(&bs, total_nin);
    /* VAL-1 fees ledger: per-tx output totals (sum(out) side; the sum(in)
     * side arrives from tx_verify.c's export). Persistent arena like bx/bs. */
    static u64* g_ptx_out = 0; static u64 g_ptx_out_cap = 0;
    u64* ptx_out = grow_arena((void**)&g_ptx_out, &g_ptx_out_cap, ntx * sizeof(u64));
    if (!ptx_out) return 0;
    memset(ptx_out, 0, ntx * sizeof(u64));
    int dup = 0;
    int money_bad = 0;
    for (u64 t=0; t<ntx && !dup; t++){
        idxbuild_ctx_t ic = { &bx, &bs, txs[t].txid, (u32)t, 0 };
        ic.ptx_out = ptx_out;
        u64 wnin=0, wnout=0;
        int wok = utxo_walk_tx_io(txs[t].ptr, txs[t].ptr+txs[t].len, &ic,
                                  idxbuild_on_input, idxbuild_on_output, &wnin, &wnout);
        if (!wok || wnin != txs[t].pn_in || wnout != pn_outs[t]) {
            /* utxo_walk_tx_io and tx_parse disagree on this tx's own shape
             * -- an internal consistency problem, same class of check the
             * old apply loop already made, just moved earlier (before any
             * verification/apply work happens, so still no rollback). */
            return 0;
        }
        if (ic.money_bad) money_bad = 1;   /* keep walking: dup detection
                                              still owes its reject string */
        dup = ic.dup_found;
    }
    if (dup) {
        fprintf(stderr, "[utxo_live] REJECT h=%ld: in-block double-spend (duplicate outpoint)\n", g_apply_height);
        g_last_reject = "bad-txns-inputs-duplicate";
        return 0;
    }
    if (money_bad) {
        fprintf(stderr, "[utxo_live] REJECT h=%ld: transaction output value out of range\n", g_apply_height);
        g_last_reject = "bad-txns-vout-toolarge";
        return 0;
    }

    /* ---- Phase 1-4 (tx_verify.c): verify every non-coinbase tx's
     * signatures, block-wide. Nothing applied yet -- a reject here needs no
     * rollback either. ---- */
    u64 fail_tx = 0; const char* reason = "?";
    if (!tx_verify_block_connect_all(txs, ntx, g_apply_height, blk_hash,
                                     &g_utxo_lst, g_utxo_table, &bx, &fail_tx, &reason)) {
        fprintf(stderr, "[utxo_live] REJECT h=%ld tx=%lu: %s\n", g_apply_height, (unsigned long)fail_tx, reason);
        g_last_reject = reason;    /* tx_verify's own string, verbatim */
        return 0;
    }

    /* ---- Phase 4.5 (VAL-1/VAL-2, audit 2026-09-03): ConnectBlock's value
     * ledger. fees = sum over the NON-coinbase txs of (in - out); every
     * per-tx in >= out and both sums within MAX_MONEY (Core's
     * bad-txns-in-belowout / -inputvalues-outofrange), and the coinbase's
     * outputs capped at subsidy + fees (bad-cb-amount). The per-tx input
     * sums come from tx_verify.c's Phase 1 (every prevout value it resolved
     * for the script check); the output sums from the Phase 0.5 walk. The
     * export array must match this block's ntx -- a shorter array means the
     * Phase-1 export could not be trusted, and refusing is the only safe
     * answer (same rule as every -1 header read in this module). ---- */
    {
        u64 in_n = 0;
        const u64* tx_in = txvb_last_tx_in_sums(&in_n);
        if (!tx_in || in_n < ntx){
            fprintf(stderr, "[utxo_live] REJECT h=%ld: internal: fee ledger export missing\n", g_apply_height);
            g_last_reject = "internal: fee ledger export missing";
            return 0;
        }
        u64 fees = 0;
        for (u64 t=1; t<ntx; t++){
            u64 in_t = tx_in[t], out_t = ptx_out[t];
            if (in_t > VAL_MAX_MONEY){ g_last_reject = "bad-txns-inputvalues-outofrange"; return 0; }
            if (in_t < out_t)       { g_last_reject = "bad-txns-in-belowout";        return 0; }
            fees += in_t - out_t;
            if (fees > VAL_MAX_MONEY)  { g_last_reject = "bad-txns-fee-outofrange";  return 0; }
        }
        u64 cap = val_subsidy(g_apply_height) + fees;
        if (ptx_out[0] > cap){
            fprintf(stderr, "[utxo_live] REJECT h=%ld: bad-cb-amount (cb out %llu > subsidy+fees %llu)\n",
                    g_apply_height, (unsigned long long)ptx_out[0], (unsigned long long)cap);
            g_last_reject = "bad-cb-amount";
            return 0;
        }
    }

    /* Dry-run stops HERE: every verification phase has passed and the next
     * line of the real path is the first put/del. */
    if (g_dry_run) return 1;

    /* ---- Phase 5: sequential apply, exactly as before, reusing the
     * already-parsed tx array instead of re-parsing. A failure HERE is the
     * only case that still needs rollback_partial_apply -- everything above
     * ran before any put/del happened. ---- */
    apply_ctx_t ctx = { 0, 0 };
    for (u64 t=0; t<ntx && !ctx.fatal; t++){
        ctx.txid = txs[t].txid;
        ctx.is_coinbase = (t == 0);
        u64 wnin=0, wnout=0;
        int wok = utxo_walk_tx_io(txs[t].ptr, txs[t].ptr+txs[t].len, &ctx, live_on_input, live_on_output, &wnin, &wnout);
        if (!wok || ctx.fatal) { rollback_partial_apply(blockbuf, blocklen, t); return 0; }
        if (wnin != txs[t].pn_in || wnout != pn_outs[t]) { rollback_partial_apply(blockbuf, blocklen, t); return 0; }
    }
    if (!ctx.fatal && g_mined_cb)
        for (u64 t=0; t<ntx; t++) g_mined_cb(txs[t].txid);
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
/* Reverse a ghost application of block h (undo_<h>.dat exists but its
 * checkpoint never landed). Defined below with the STAGE B disconnect
 * helpers it reuses. 1 rolled back / 0 failed. */
static int rollback_unapplied_block(const u8* blockbuf, u64 blocklen, long h);

/* Public dry-run for submitblock: verification phases only, no mutation, no
 * undo/ghost interaction. Caller must hold the same preconditions the apply
 * loop does (utxo_live_ok, single-threaded worker). 1 clean / 0 with
 * utxo_live_last_reject() set. */
long utxo_live_dryrun_block(const u8* blockbuf, u64 blocklen, long height){
    long saved = g_apply_height;
    g_apply_height = height;
    g_dry_run = 1;
    tx_verify_set_script_checks(1);           /* a proposal is never assumed valid */
    int r = apply_block_inner(blockbuf, blocklen);
    g_dry_run = 0;
    g_apply_height = saved;
    return r;
}

extern void undo_close_current(void);
static int apply_block_at_inner(const u8* blockbuf, u64 blocklen, long height);
/* Block boundary = WAL drain + undo file close (2026-09-01): the WAL is
 * buffered in the store (one write per block instead of one per record)
 * and the block's undo file stays open across its inputs. Both land here,
 * success or failure, so everything after this point -- the checkpoint, a
 * rollback, the next block's undo file -- sees a complete on-disk record. */
static int apply_block_at(const u8* blockbuf, u64 blocklen, long height){
    int r = apply_block_at_inner(blockbuf, blocklen, height);
    undo_close_current();
    if (utxo_store_wal_drain(&g_utxo_lst) != 0) {
        fprintf(stderr, "[utxo_live] FATAL: WAL drain failed after height %ld\n", height);
        g_last_fail_kind = UTXO_FAIL_STORE; g_last_fail_height = height;
        return 0;
    }
    if (!r) {
        /* apply_block_inner clears g_last_reject at entry and sets it on
         * every verification refusal; a failure with it still empty came
         * from the store (put/del -1, table full) -- see live_on_input/output. */
        g_last_fail_kind = g_last_reject[0] ? UTXO_FAIL_REJECT : UTXO_FAIL_STORE;
        g_last_fail_height = height;
    }
    return r;
}
static int apply_block_at_inner(const u8* blockbuf, u64 blocklen, long height){
    g_apply_height = height;
    { int on = (g_assumevalid_height < 0 || height > g_assumevalid_height);
      tx_verify_set_script_checks(on);
      if (on && g_assumevalid_height >= 0 && !g_av_announced_end){ g_av_announced_end = 1;
          fprintf(stderr, "[utxo_live] assumevalid: above height %ld -- script evaluation resumed\n", g_assumevalid_height); } }
    /* GHOST GUARD (closes the multi-block WAL-vs-checkpoint window, 2026-08-25):
     * an undo_<h>.dat here can only mean h was applied -- partially or fully --
     * by a previous process whose checkpoint never landed (a clean apply +
     * checkpoint keeps its undo file, but catch-up/reorg only ever hand us
     * h > the checkpointed height, and both the in-process failure rollback
     * and the disconnect path discard the file when they finish). The old
     * code blindly undo_discard()ed it "so a fresh apply starts clean" --
     * destroying the ONE piece of data that could reverse the ghost
     * application, right before the fresh apply rejected on the ghost's
     * already-spent inputs. Seen live 2026-08-24 at height 963915: boot
     * recovery healed applied+1 but the drift was multi-block, and the
     * DEGRADED retry loop could never recover because this discard had
     * already destroyed the later ghosts' undo data. Roll the ghost back
     * instead, then apply fresh; refuse to apply on rollback failure rather
     * than proceed on inconsistent state. */
    if (g_undo_enabled && height >= 0) {
        char upath[64]; struct stat usb;
        snprintf(upath, sizeof upath, "undo_%ld.dat", height);
        if (stat(upath, &usb) == 0 && !rollback_unapplied_block(blockbuf, blocklen, height))
            return 0;
    }
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
 * Shared by the counting pre-flight, the created-output deletion below, and
 * the partial-apply rollback further down, so all three can never drift on
 * how a block is sliced. max_tx bounds how many leading transactions get
 * walked -- pass (u64)-1 for "the whole block" (the two disconnect-path
 * callers below want that; partial-apply rollback wants only the
 * transactions it knows were actually touched). Returns 1 well-formed. */
static int walk_block_txs(const u8* blockbuf, u64 blocklen, void* ctx,
                          utxo_walk_input_cb icb, utxo_walk_output_cb ocb,
                          const u8** cur_txid_slot, u64 max_tx){
    if (blocklen < 81) return 0;
    const u8* p = blockbuf + 80;
    const u8* blkend = blockbuf + blocklen;
    u64 consumed;
    u64 ntx = utxo_walk_read_varint(p, blkend, &consumed);
    if (!consumed) return 0;
    p += consumed;

    static u8 txid_scratch2[4<<20];
    for (u64 t=0; t<ntx && t<max_tx; t++){
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
                         u32 height, u8 is_coinbase, const u8* script, u16 slen){
    (void)txid; (void)index; (void)value; (void)height; (void)is_coinbase; (void)script; (void)slen;
    (*(long*)ctx)++;
    return 1;
}

int utxo_live_can_unapply(const void* blockbuf, u64 blocklen, long height){
    count_ctx_t cc = { 0 };
    if (!walk_block_txs((const u8*)blockbuf, blocklen, &cc, count_on_input, 0, 0, (u64)-1)){
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

/* ---- the actual unapply ----
 * height/is_coinbase (2026-08-19, Stage D): restored straight from the undo
 * record -- the spent UTXO's OWN original creation height/coinbase-ness,
 * captured by undo_capture_and_del at spend time (see daemon/undo_log.c's
 * header comment). Getting this wrong would mean a reorg-restored coinbase
 * output silently loses correct maturity data. */
static int undo_restore_cb(void* ctx, const u8 txid[32], u32 index, u64 value,
                           u32 height, u8 is_coinbase, const u8* script, u16 slen){
    int* fatal = (int*)ctx;
    long r = utxo_lsm_put(&g_utxo_lst, g_utxo_table, txid, index, value,
                          (u64)height, (u64)is_coinbase, script, (u32)slen);
    if (r == -1 || r == 2) { *fatal = 1; return 0; }
    if (r == 1 && g_csi_add)
        g_csi_add(txid, index, value, (u64)height, (u64)is_coinbase, script, (unsigned long)slen);
    return 1;
}

typedef struct { const u8* txid; int fatal; } del_created_ctx_t;

extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index, u64* value,
                         unsigned long* height, unsigned long* is_coinbase,
                         const u8** script, unsigned long* slen);

static void del_created_on_output(void* ctxv, u32 out_index, u64 value,
                                  const u8* script, u32 slen){
    del_created_ctx_t* c = (del_created_ctx_t*)ctxv;
    (void)value; (void)script; (void)slen;
    /* Only delete what is actually there. utxo_lsm_del records a tombstone
     * and decrements the LSM's live counter UNCONDITIONALLY (it cannot know
     * whether the key exists in an older run without a lookup -- see the
     * CONTRACT CHANGE note in bitcoin_utxo_lsm.asm), so deleting an output
     * that was never created (a partial apply that died before that tx's
     * outputs landed) or already spent (same-block chain, or a descendant
     * already unapplied) left the count one too low each time. The set
     * itself was never wrong -- a tombstone over an absent key is a no-op
     * for lookups -- only the tally, which the heartbeat/logs report. Found
     * by tests/test_utxo_crash_recovery.c's count check (149 vs 151, 0 vs
     * 151) after its key-by-key comparison had already passed. One get per
     * created output, on rollback/unapply paths only. */
    u64 v=0; unsigned long hh=0, cb=0, sl=0; const u8* sc=0;
    if (g_store_inconsistent) {
        /* Incident 2026-09-01: the get above is the same lookup that just lied.
         * Gating the delete on it left 122 of a rolled-back block's outputs in
         * the set in the repro. Delete unconditionally: the tally may drift by
         * the absent keys, but the node is halting and the operator rebuilds. */
        static int said = 0;
        if (!said++) fprintf(stderr, "[utxo_live] rollback under a store inconsistency: deleting created outputs without a lookup (live counter may drift; rebuild pending)\n");
        if (utxo_lsm_del(&g_utxo_lst, g_utxo_table, c->txid, out_index) < 0) c->fatal = 1;
        return;
    }
    if (utxo_lsm_get(&g_utxo_lst, g_utxo_table, c->txid, out_index, &v, &hh, &cb, &sc, &sl) != 1) return;
    /* copy the script BEFORE the del: get()'s pointer is only valid until
     * the next LSM call, and the remove-event needs the exact bytes */
    static u8 scbuf[10000];
    unsigned long scn = sl <= sizeof scbuf ? sl : 0;
    if (scn) memcpy(scbuf, sc, scn);
    long r = utxo_lsm_del(&g_utxo_lst, g_utxo_table, c->txid, out_index);
    if (r == -1) c->fatal = 1;
    else if (r == 1 && g_csi_rm && scn == sl)
        g_csi_rm(c->txid, out_index, v, (u64)hh, (u64)cb, scbuf, sl);
}

/* rollback_partial_apply(blockbuf, blocklen, upto_t_inclusive): reverse
 * whatever apply_block_inner already committed for transactions
 * 0..upto_t_inclusive of the block CURRENTLY being applied at g_apply_height,
 * after it failed partway through. Deliberately NOT utxo_live_unapply_block:
 * that function's pre-flight gate (utxo_live_can_unapply) REQUIRES the undo
 * file's record count to equal the WHOLE block's declared input count --
 * exactly the mismatch a partial apply always produces, so it would refuse
 * every single time. This is the same restore-then-delete two-step (see the
 * STAGE B header comment above for why the order matters -- a same-block
 * spend chain needs the earlier tx's output back before its own declared
 * output gets deleted), just over a prefix of the block's transactions
 * instead of the whole thing, and reusing the disconnect path's own
 * undo_restore_cb / del_created_on_output callbacks unchanged.
 *
 * Both steps tolerate "never actually got that far": undo_replay only
 * restores whatever records this partial attempt genuinely wrote (a
 * verify-failure never reaches live_on_input, so no record exists for the
 * failing tx), and deleting a never-created output returns "already
 * absent" (0), not an error -- the same tolerance del_created_on_output
 * already relies on for the real disconnect path. */
/* rollback_unapplied_block(blockbuf, blocklen, h): reverse a GHOST
 * application of block h -- one that ran (partially or fully) in a previous
 * process without its checkpoint landing, leaving undo_<h>.dat behind. The
 * same restore-then-delete two-step as the disconnect path, with the
 * torn-tail-tolerant reader (a kill mid-undo-append leaves a torn record
 * whose delete never ran -- see utxo_live_recover_partial_block's header).
 * Discards the undo file on success so a fresh apply starts clean.
 * Returns 1 rolled back / 0 failed (undo file left in place). */
static int rollback_unapplied_block(const u8* blockbuf, u64 blocklen, long h){
    long saved_apply = g_apply_height;
    g_apply_height = h;
    int saved = g_undo_enabled;
    g_undo_enabled = 0;

    int fatal = 0, torn = 0;
    long r = undo_replay_tolerant(h, undo_restore_cb, &fatal, &torn);
    del_created_ctx_t dc = { 0, 0 };
    int ok = walk_block_txs(blockbuf, blocklen, &dc, 0, del_created_on_output, &dc.txid, (u64)-1);

    g_undo_enabled = saved;
    g_apply_height = saved_apply;

    if (r < 0 || fatal || !ok || dc.fatal) {
        fprintf(stderr, "[utxo_live] ghost-rollback FAILED at height %ld: restore r=%ld fatal=%d walk ok=%d del_fatal=%d -- state may be inconsistent\n",
                h, r, fatal, ok, dc.fatal);
        return 0;
    }
    undo_discard(h);
    fprintf(stderr, "[utxo_live] rolled back ghost application of block %ld (%ld prevout(s) restored%s) -- re-applying fresh\n",
            h, r, torn ? ", torn trailing undo record ignored" : "");
    return 1;
}

static void rollback_partial_apply(const u8* blockbuf, u64 blocklen, u64 upto_t_inclusive){
    long height = g_apply_height;
    int saved = g_undo_enabled;
    g_undo_enabled = 0;

    int fatal = 0;
    long r = undo_replay(height, undo_restore_cb, &fatal);
    if (r < 0 || fatal)
        fprintf(stderr, "[utxo_live] rollback h=%ld: undo replay failed (r=%ld fatal=%d) -- state may be inconsistent\n",
                height, r, fatal);

    del_created_ctx_t dc = { 0, 0 };
    int ok = walk_block_txs(blockbuf, blocklen, &dc, 0, del_created_on_output,
                            &dc.txid, upto_t_inclusive + 1);
    g_undo_enabled = saved;
    if (!ok || dc.fatal)
        fprintf(stderr, "[utxo_live] rollback h=%ld: created-output removal failed (ok=%d fatal=%d) -- state may be inconsistent\n",
                height, ok, dc.fatal);

    undo_discard(height);
    fprintf(stderr, "[utxo_live] rolled back partial apply at h=%ld (tx 0..%lu)\n", height, (unsigned long)upto_t_inclusive);
}

/* utxo_live_recover_partial_block(store_buf) -> 1 rolled back a partial
 * block / 0 nothing to do / -1 could not (block unreadable; undo file left in
 * place so the next call tries again).
 *
 * Boot-time repair for a process that died between "block N's puts/dels hit
 * the WAL" and "checkpoint N persisted". Per-block WAL durability plus a
 * per-block checkpoint (2fd4a14) closed the OLD unbounded window, but the
 * two writes are still sequential, and a SIGKILL/OOM/power-loss between them
 * leaves the reloaded set one block ahead of utxo_applied_height.dat. The
 * 2fd4a14 comment's "re-applying is safe, duplicate puts/dels are non-error"
 * was true of the storage layer and is false now that Stage D verifies a
 * block BEFORE applying it: tx_verify resolves every prevout first, finds
 * N's already spent, and rejects N as "missing/already-spent UTXO". That is
 * exactly what production did at height 318148 on 2026-08-22 after systemd
 * SIGKILLed a worker that was ignoring SIGTERM (now also fixed -- see
 * shutdown_requested -- but kill -9 and power loss remain).
 *
 * Detection: live_on_input appends to undo_<N>.dat BEFORE each delete
 * (undo_capture_and_del), and that file is only ever discarded by a
 * completed rollback/unapply. So "undo_<applied+1>.dat exists" means block
 * applied+1 started applying and its checkpoint never landed -- regardless
 * of whether it got all the way through. Repair is the same restore-then-
 * delete two-step rollback_partial_apply uses in-process, over the WHOLE
 * block (a never-created output deletes as "already absent", which is fine),
 * then catch-up re-applies N from a clean pre-block state.
 *
 * Flush in the middle of N: mac_flush can fire inside any utxo_lsm_put, so
 * some of N's ops may already be in an immutable run while the rest are in
 * the WAL. The rollback still works because the LSM is newest-wins: the
 * restoring put (memtable) shadows the run's tombstone, and the deleting
 * tombstone (memtable) shadows the run's put. tests/test_utxo_crash_recovery.c
 * forces exactly that layout and checks the result key-by-key against a
 * never-crashed reference.
 *
 * Torn tail: a kill between undo_append_record's two write()s (or a power
 * loss mid-write) can leave a header with a short/missing script. That
 * record's delete never happened (append precedes delete), so treating the
 * torn tail as end-of-file is exactly right -- undo_replay_tolerant does
 * that; the strict undo_replay used by the reorg pre-flight is untouched.
 *
 * Same-machine SIGKILL needs no fsync here: write() data that returned is
 * visible to the next process via the page cache. */
long utxo_live_recover_partial_block(void* store_buf){
    g_bip30_store = store_buf;   /* for BIP30's BIP34-ancestor test; see bip30_enforced */

    /* MULTI-BLOCK (2026-08-25): the drift is one block only when every
     * checkpoint persisted -- but the persist can fail (disk full, ENOSPC)
     * and the reorg reconnect's checkpoint failure also used to continue, so
     * the ghost run can be several blocks deep. Production hit exactly this
     * at height 963915 on 2026-08-24: boot recovery healed applied+1, then
     * catch-up rejected the NEXT ghost. Find the whole contiguous ghost run
     * and roll it back DESCENDING (disconnect is LIFO: a later block's undo
     * restores prevouts an earlier ghost created; deleting the earlier
     * ghost's outputs must come after). */
    long lo = g_applied_height + 1;
    long hi = lo - 1;
    for (long h = lo; ; h++){
        char upath[64]; snprintf(upath, sizeof upath, "undo_%ld.dat", h);
        struct stat sb;
        if (stat(upath, &sb) != 0) break;
        hi = h;
    }
    if (hi < lo) return 0;

    static u8 blockbuf[8<<20];
    long rolled = 0;
    for (long h = hi; h >= lo; h--){
        long len = store_read_at(store_buf, (u64)h, blockbuf, sizeof blockbuf);
        if (len < 81) {
            fprintf(stderr, "[utxo_live] RECOVERY: undo_%ld.dat exists (block %ld began applying before the last checkpoint) but block %ld is unreadable (len=%ld) -- cannot roll back, leaving it for retry\n",
                    h, h, h, len);
            return -1;
        }
        if (!rollback_unapplied_block(blockbuf, (u64)len, h)) {
            fprintf(stderr, "[utxo_live] RECOVERY FAILED at height %ld -- state may be inconsistent\n", h);
            return -1;
        }
        rolled++;
    }
    fprintf(stderr, "[utxo_live] RECOVERY: rolled back %ld ghost block(s) [%ld..%ld] (previous process died after their spends were durable but before their checkpoints); catch-up will re-apply them\n",
            rolled, lo, hi);
    return 1;
}
/* Boot hook (daemon/main.c): run the ghost-run repair BEFORE anything reads
 * the set as truth. The coinstats index adopts its persisted state at the
 * checkpoint height, or seeds itself from a walk -- both must see the
 * repaired set, and the rollback's own restore/delete callbacks notify the
 * index, which is right only if the index has not yet loaded. Catch-up used
 * to do this on its first call, after the index had already looked; with
 * batched checkpoints (below) a ghost run after a crash is the common case,
 * not a rarity. Idempotent; catch-up keeps its own check as the fallback. */
long utxo_live_recover_at_boot(void* store_buf){
    if (g_recovery_checked) return g_recovery_result;
    g_recovery_checked = 1;
    g_recovery_result = utxo_live_recover_partial_block(store_buf);
    return g_recovery_result;
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
                            del_created_on_output, &dc.txid, (u64)-1);
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

/* TEST-ONLY: drive one raw block through the full production apply path
 * (parse -> witness commitment -> tx_verify_block_connect_all on the real
 * verify-pool threads -> UTXO mutation) against whatever the LSM currently
 * holds. Used by tests/test_block_481827_pool_stack.c to reproduce the
 * 481827 verify-pool stack overflow (incident #13) and prove the fix. Not
 * called from any production path. */
int utxo_live_test_apply_block(const unsigned char* blk, unsigned long len, long height){
    return apply_block_at(blk, (u64)len, height);
}
/* TEST-ONLY: seed one prevout into the live LSM so a real historical block
 * can be applied against a synthetic UTXO view. */
int utxo_live_test_seed(const unsigned char txid[32], unsigned int index, unsigned long long value,
                        const unsigned char* spk, unsigned int spklen){
    return (int)utxo_lsm_put(&g_utxo_lst, g_utxo_table, txid, index, value, 0, 0, spk, spklen);
}
/* TEST-ONLY: the BIP30 enforcement gate, so its height/hash arithmetic can be
 * asserted directly instead of inferred from whether a block was rejected.
 * Returns 1 = enforce, 0 = skip. NOTE: with no store handle cached (which is
 * the case unless utxo_live_catchup ran) the BIP34-ancestor arm cannot be
 * resolved and the gate deliberately answers ENFORCE -- see bip30_enforced. */
int utxo_live_test_bip30_enforced(long height, const unsigned char hash32[32]){
    return bip30_enforced(height, hash32);
}
/* TEST-ONLY: 1 if the LAST apply_block failed the BIP30 check specifically.
 * Reading clears it. */
int utxo_live_test_took_bip30_reject(void){
    int v = g_bip30_rejected; g_bip30_rejected = 0; return v;
}


/* utxo_live_init(dir): open-or-init the live LSM UTXO instance in the
 * current directory (callers have already chdir'd to the daemon's data
 * dir, matching every other store in this codebase -- `dir` is only used
 * for the log line). Returns 1 on success, 0 on failure. */
/* Stored tip height straight off index.dat's size. Each index record is 48
 * bytes (the same layout anchor_locator/locator_build read positionally), so
 * the record count is the height count. Read this way rather than from a
 * store_buf because utxo_live_init deliberately takes no store handle -- and
 * we only need it to pick a memtable size. -1 when there is no usable index. */
static long utxo_live_index_tip(void){
    struct stat sb;
    if (stat("index.dat", &sb) != 0) return -1;
    if (sb.st_size < 48) return -1;
    return (long)(sb.st_size / 48) - 1;
}

/* Set while the memtable is bulk-sized, until catch-up downshifts it. */
static int g_bulk_mode = 0;

/* How many runs the manifest may hold before a compaction merges them.
 *
 * Until 2026-08-31 this was the UTXO_LIVE_COMPACT_THRESHOLD macro, and
 * bmc.utxocompactthreshold -- parsed by node_config.c and printed at every boot
 * as "compact_at=N" -- was never read by anything. An option that is accepted,
 * printed and inert is the exact failure this codebase has shipped repeatedly;
 * it is wired now.
 *
 * BULK MODE COMPACTS LESS OFTEN, by a factor of four. A compaction rewrites
 * the ENTIRE live set (one big run; the merge folds the new ones into it),
 * through three read syscalls and several write syscalls per record -- about
 * 50 MB/s whatever the disk. Measured on signet mid catch-up: 15 compactions
 * an hour, ~105 s each, 44% of wall-clock spent rewriting a 5 GB set instead
 * of applying blocks. Every run carries a Bloom filter, so a lookup that
 * misses costs one filter probe per extra run; while far behind that is far
 * cheaper than the rewrites. Steady state is unchanged. */
/* Test hook: g_bulk_mode is decided from the store at init, which a unit test
 * of the threshold arithmetic has no business setting up. */
void utxo_live_test_set_bulk_mode(int on){ g_bulk_mode = on; }

long utxo_live_compact_threshold(void){
    long t = g_cfg.utxo_compact_threshold > 0 ? g_cfg.utxo_compact_threshold
                                              : UTXO_LIVE_COMPACT_THRESHOLD;
    if (g_bulk_mode) t *= 4;
    if (t > 64) t = 64;   /* COMPACT_MAX_RUNS: a merge folds at most 64 runs */
    if (t < 2) t = 2;
    return t;
}

/* tx_verify.c's own parallel-verify dispatch: it must not fork() workers
 * while THIS process's memtable (and therefore its RSS) is bulk-sized and
 * still growing, since fork()'s copy-on-write cost scales with the parent's
 * resident size -- see txv_set_bulk_mode's own comment for the production
 * symptom that led to this. */
extern void txv_set_bulk_mode(int on);

int utxo_live_init(const char* dir){
    utxo_live_resolve_assumevalid();
    g_recovery_checked = 0;
    g_test_input_count = 0;
    /* Pick the memtable size from how far behind we actually are. */
    long boot_applied = read_applied_height();
    long boot_tip     = utxo_live_index_tip();
    long boot_gap     = (boot_tip >= 0) ? (boot_tip - boot_applied) : 0;
    g_bulk_mode = (boot_gap >= g_cfg.utxo_bulk_gap_blocks);

    /* ...and ALSO go bulk when the WAL tail we are about to replay is large,
     * regardless of how few blocks remain.
     *
     * The block gap alone answers "how much work is LEFT", not "how much work
     * is about to be REPLAYED", and reload replays the whole current WAL
     * generation before applying anything. Those diverge exactly once: right
     * after a long catch-up finishes, when the gap collapses to ~0 while the
     * WAL is at its largest. That is the one moment the old heuristic picked
     * the SMALL memtable for the BIGGEST replay.
     *
     * Measured 2026-08-23: the 963,000-block replay left a 1.83 GB tail; the
     * next restart had gap=750, chose 2^16 slots, filled the table, and
     * ground to a halt (LOG.md incident #32). Sizing from the tail turns that
     * restart into a normal one.
     *
     * The threshold is deliberately generous -- a WAL big enough to matter is
     * orders of magnitude past this -- and bulk sizing costs address space,
     * not resident memory, so over-selecting it is cheap and under-selecting
     * it is what wedges a restart. */
    {
        struct stat wb;
        if (!g_bulk_mode && stat("utxo.dat", &wb) == 0 &&
            (unsigned long long)wb.st_size >= UTXO_LIVE_BULK_WAL_BYTES) {
            fprintf(stderr, "[utxo_live] WAL tail is %lluMB -- bulk-sizing the memtable despite gap=%ld (see incident #32)\n",
                    (unsigned long long)(wb.st_size >> 20), boot_gap);
            g_bulk_mode = 1;
        }
    }
    txv_set_bulk_mode(g_bulk_mode);

    unsigned long slots = g_bulk_mode ? (1UL << g_cfg.utxo_bulk_slots_log2)
                                      : (1UL << UTXO_LIVE_SLOTS_LOG2);
    u64 blob_cap = g_bulk_mode ? ((u64)g_cfg.utxo_bulk_blob_mb << 20) : UTXO_LIVE_BLOB_BYTES;
    fprintf(stderr, "[utxo_live] sizing: %s (applied=%ld tip=%ld gap=%ld) slots=2^%d blob=%lluMB compact_at=%ld\n",
            g_bulk_mode ? "BULK -- far behind, batch-sized memtable" : "steady-state",
            boot_applied, boot_tip, boot_gap,
            g_bulk_mode ? g_cfg.utxo_bulk_slots_log2 : UTXO_LIVE_SLOTS_LOG2,
            (unsigned long long)(blob_cap >> 20), utxo_live_compact_threshold());
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
    utxo_lsm_set_flush_hook(compact_flush_hook);   /* see "compaction in the background" */

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
    for (unsigned long guard = 0; g_utxo_lst.manifest_n >= 2 && guard < UTXO_LIVE_MANIFEST_CAP; guard++) {
        /* count threshold OR byte budget (2026-09-01): compact_pick_now applies both */
        u64 before = g_utxo_lst.manifest_n;
        long lo = 0, k = compact_pick_now(&lo);
        if (k == 0) break;
        long cr = utxo_lsm_compact_range(&g_utxo_lst, (unsigned long)lo, (unsigned long)k);
        fprintf(stderr, "[utxo_live] init: pre-catchup compact manifest_n=%lu -> %lu (result=%ld)\n",
                (unsigned long)before, (unsigned long)g_utxo_lst.manifest_n, cr);
        if (g_utxo_lst.manifest_n >= before) break; /* no progress -- stop rather than loop */
    }

    g_applied_height = read_applied_height();
    /* reload succeeded: the in-memory manifest is the truth, so sweep run files
     * it does not name (publish-before-unlink crash leftovers, abandoned
     * background merges). Guarded: refuses unless file and memory agree. */
    { int sw = lsm_manifest_sweep_orphans(&g_utxo_lst);
      if (sw > 0) fprintf(stderr, "[utxo_live] init: swept %d orphan file(s) the manifest does not name\n", sw);
      else if (sw < 0) fprintf(stderr, "[utxo_live] init: orphan sweep skipped -- manifest file and memory disagree\n"); }
    fprintf(stderr, "[utxo_live] init dir=%s slots=2^%d %s applied_height=%ld manifest_n=%lu live=%ld\n",
            dir, g_bulk_mode ? g_cfg.utxo_bulk_slots_log2 : UTXO_LIVE_SLOTS_LOG2,
            have_prior_state ? "reload" : "fresh",
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
/* ---- checkpoint batching during catch-up (2026-08-31) ----------------------
 * persist_applied_height is tmp+fsync+rename+dirfsync plus the coinstats
 * commit: 1.9 ms per block on the production NVMe against a ~3 ms apply --
 * measured 2026-08-31, a third to a half of bulk catch-up. Far from the
 * archive tip the checkpoint now lands every UTXO_CKPT_BATCH_BLOCKS blocks or
 * 2 s, whichever first; within UTXO_CKPT_NEAR_TIP of the tip, and always at
 * the live tip, it stays per block. The crash window this opens is exactly
 * the multi-block ghost run utxo_live_recover_partial_block already heals
 * (descending rollback from the undo files), so the batch must stay well
 * inside UTXO_UNDO_WINDOW: every ghost needs its undo file. Loop exits and
 * utxo_live_close flush a pending checkpoint. Core's shape, for reference:
 * the UTXO batch and the best-block pointer are one atomic write, issued at
 * dbcache pressure, not per block. */
#define UTXO_CKPT_BATCH_BLOCKS 64      /* < UTXO_UNDO_WINDOW (200) */
#define UTXO_CKPT_BATCH_MS     2000
#define UTXO_CKPT_NEAR_TIP     64
static long      g_ckpt_since = 0;      /* applied blocks not yet covered by a checkpoint */
static long long g_ckpt_last_ms = 0;
static long      g_test_ckpt_batch = -1;   /* test knob: -1 default, 0 per-block, n = batch n even at the tip */
void utxo_live_test_set_ckpt_batch(long n){ g_test_ckpt_batch = n; }
static long long mono_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec*1000LL + t.tv_nsec/1000000; }
/* Pure so tests/test_utxo_ckpt_batch pins it without a chain. */
int utxo_live_ckpt_due(long h, long tip, long unpersisted, long long now_ms, long long last_ms, long forced){
    long batch = forced >= 0 ? forced : UTXO_CKPT_BATCH_BLOCKS;
    if (batch <= 0) return 1;
    if (forced < 0 && tip - h < UTXO_CKPT_NEAR_TIP) return 1;
    if (unpersisted >= batch) return 1;
    if (now_ms - last_ms >= UTXO_CKPT_BATCH_MS) return 1;
    return 0;
}
static int ckpt_now(void){
    if (!persist_applied_height(g_applied_height)) return 0;
    g_ckpt_since = 0; g_ckpt_last_ms = mono_ms();
    return 1;
}

long utxo_live_catchup(void* store_buf){
    g_bip30_store = store_buf;   /* for BIP30's BIP34-ancestor test; see bip30_enforced */
    store_reload(store_buf);
    long tip = *(int*)((char*)store_buf + 24);

    /* First call after init: if the previous process died between "block
     * N's puts/dels hit the WAL" and "checkpoint N persisted", the reloaded
     * set is one block AHEAD of g_applied_height and re-verifying N would
     * fail on its own already-spent inputs. Roll N back before touching
     * anything else (see utxo_live_recover_partial_block). Runs before the
     * tip check so a caught-up node still repairs itself. */
    if (!g_recovery_checked) {          /* normally already done by utxo_live_recover_at_boot */
        g_recovery_checked = 1;
        g_recovery_result = utxo_live_recover_partial_block(store_buf);
    }
    if (g_recovery_result < 0) { g_last_fail_kind = UTXO_FAIL_OTHER; g_last_fail_height = g_applied_height + 1; return -1; }
    if (g_halted) return -1;          /* utxo_live_verify_after_recovery() found the set inconsistent */
    if (tip < 0 || tip <= g_applied_height) return 0;
    g_last_fail_kind = UTXO_FAIL_NONE;

    static u8 blockbuf[8<<20];
    long applied = 0;
    time_t last_progress_log = 0;   /* 0 => the first block prints immediately (restart-visible) */
    /* rate + ETA on the progress tick (2026-09-01): instantaneous rate over
     * the last tick interval, session-average rate since this call began
     * (the ETA uses the average -- flush pauses make the instantaneous
     * figure swing 0..80 blk/s), ETA as DD:HH:MM:SS of the remaining gap. */
    long long cu_t0 = mono_ms(), cu_last_ms = cu_t0;
    long cu_h0 = g_applied_height, cu_last_h = g_applied_height;
    for (long h = g_applied_height + 1; h <= tip; h++){
        long len = store_read_at(store_buf, h, blockbuf, sizeof blockbuf);
        if (len < 81) {
            fprintf(stderr, "[utxo_live] WARNING: hole/short block at height %ld (len=%ld) -- stopping catch-up short\n", h, len);
            g_last_fail_kind = UTXO_FAIL_OTHER; g_last_fail_height = h;
            break;
        }
        if (!apply_block_at(blockbuf, (u64)len, h)) {
            fprintf(stderr, "[utxo_live] FATAL: apply_block failed at height %ld -- stopping catch-up\n", h);
            return -1;
        }
        /* Block h is now fully durable in the WAL but NOT yet checkpointed:
         * this is the window a SIGKILL landed in at height 318148 on
         * 2026-08-22. The test hook lets a test die exactly here. */
        UTXO_LIVE_TEST_CRASH_AT(UTXO_LIVE_CRASH_BEFORE_PERSIST, applied + 1);
        g_applied_height = h;
        applied++;

        /* Persist the checkpoint after EVERY block, not just at a compaction
         * or at the very end of the (potentially hours-long, for a
         * from-scratch replay) call. block h's puts/dels are ALREADY durable
         * at this point -- utxo_lsm_put/del write their WAL entries
         * synchronously, and any mac_flush they triggered along the way
         * publishes its run + manifest via its own independent crash-safe
         * rename, entirely decoupled from this height marker -- so an
         * unclean process death anytime after this line can never leave the
         * on-disk UTXO state further ahead than what utxo_applied_height.dat
         * says. Before this, that gap was real and unbounded: this file's
         * own header comment used to document a "REVERTED (2026-08-19)"
         * attempt at exactly this that was pulled after production reload
         * came back "missing" entries that were genuinely applied (even a
         * checkpointed height's own coinbase gone). That was misdiagnosed as
         * data loss in the flush/compact reconstruction path; it was in fact
         * this same gap in the other direction -- the reloaded LSM state was
         * correctly further ALONG than the stale checkpoint claimed, so
         * anything the stale checkpoint's height had created that a later,
         * already-durable-but-unpersisted block had since spent legitimately
         * looked "gone". Confirmed live in production 2026-08-21: a restart
         * landing after a mid-catchup compact's checkpoint (height 363896)
         * came back rejecting height 363897's very first spend as
         * "missing/already-spent" -- because that block (and however many
         * after it) had already been durably applied before the crash, just
         * never checkpointed. See tests/test_utxo_catchup_crash_resume.c.
         * fsync-per-block is not the throughput risk it looks like: bulk
         * catch-up is already far slower than one fsync per block (observed
         * production rate tops out around a few thousand blocks/sec even in
         * the cheap early-chain stretch, and drops to single digits/sec once
         * blocks carry real transaction volume), so this adds a small,
         * bounded fraction of total replay time in exchange for closing an
         * unbounded-drift crash window. */
        g_ckpt_since++;
        if (utxo_live_ckpt_due(h, tip, g_ckpt_since, mono_ms(), g_ckpt_last_ms, g_test_ckpt_batch) && !ckpt_now()) {
            /* STOP, don't continue (2026-08-25). The old comment claimed
             * continuing was "safe, puts/dels are idempotent" -- false since
             * Stage D verifies before applying: every un-checkpointed block
             * applied past this point re-verifies on the next boot against
             * its own already-durable spends and rejects. The ghost guard in
             * apply_block_at now heals that, but there is no reason to keep
             * growing an unbounded ghost run on a disk that cannot persist a
             * 12-byte checkpoint -- stop at the boundary and let the caller
             * retry/backoff. Block h itself IS durably applied; worst case on
             * a dead disk is a one-block ghost the guard rolls back. */
            fprintf(stderr, "[utxo_live] WARNING: failed to persist applied height %ld after block %ld -- stopping catch-up at this boundary (%ld block(s) applied this call)\n",
                    g_applied_height, h, applied);
            break;
        }
        UTXO_LIVE_TEST_CRASH_HOOK(applied);

        /* SIGTERM/SIGINT arrived: block h is applied AND checkpointed, so
         * this is a clean boundary. Stop here -- do not start the next block
         * and do not begin a compaction -- and return the count applied so
         * far like any other bounded call; the worker's own loop sees the
         * flag and exits. The end-of-call bookkeeping below still runs
         * (prune is bounded, the compacts are guarded). */
        if (shutdown_requested()) {
            fprintf(stderr, "[utxo_live] shutdown requested -- stopping catch-up cleanly after height %ld (%ld block(s) applied this call, checkpoint persisted)\n",
                    h, applied);
            break;
        }

        /* Progress heartbeat -- log-only, independent of the per-block
         * checkpoint above and the compaction below. Emit at most one line
         * per ~30 s of wall-clock, AND always on a round absolute-height
         * milestone. Absolute (h), not the session-relative `applied`, so the
         * same heights print across runs and the first line lands the moment
         * a resume starts applying -- not 20000 blocks later. The old
         * `applied % 20000` was both throughput-blind (interval swung with
         * block density) and restart-delayed (a resume went silent until it
         * had applied 20000 blocks, which masked whether it was progressing).
         * time(NULL) once per applied block is negligible against a block's
         * verify+apply cost. */
        {
            time_t now = time(NULL);
            if (now - last_progress_log >= 30 || h % 20000 == 0) {
                long long nowms = mono_ms();
                double inst = nowms > cu_last_ms ? (double)(h - cu_last_h) * 1000.0 / (double)(nowms - cu_last_ms) : 0.0;
                double avg  = nowms > cu_t0     ? (double)(h - cu_h0)     * 1000.0 / (double)(nowms - cu_t0)     : 0.0;
                long rem = tip - h, eta = avg > 0.0 ? (long)((double)rem / avg) : -1;
                char etabuf[32];
                if (eta >= 0) snprintf(etabuf, sizeof etabuf, "%02ld:%02ld:%02ld:%02ld", eta / 86400, (eta / 3600) % 24, (eta / 60) % 60, eta % 60);
                else          snprintf(etabuf, sizeof etabuf, "--:--:--:--");
                fprintf(stderr, "[utxo_live] catchup progress: height=%ld/%ld (%.1f%%) %.1f blk/s (avg %.1f) eta %s\n",
                        h, tip, tip > 0 ? 100.0 * (double)h / (double)tip : 0.0, inst, avg, etabuf);
                cu_last_ms = nowms; cu_last_h = h;
                last_progress_log = now;
            }
        }
        /* Compact periodically DURING a long catch-up, not just once at the
         * end. A from-scratch (or long-gap) replay flushes far more runs
         * than a steady-state catch-up call ever would, and the manifest
         * has a hard cap (UTXO_LIVE_MANIFEST_CAP) sized for steady-state
         * gaps, not a full historical replay. Without this, a long
         * catch-up deterministically walks into the cap and utxo_lsm_put/
         * del starts returning -1 (fatal, per live_on_output/live_on_input)
         * partway through -- observed in production: a from-scratch replay
         * (applied_height reset to -1) hit this wall at height 202134. */
        compact_poll();                                   /* adopt a finished background merge */
        compact_start_async(h, "mid-catchup");
    }
    /* Caught up while bulk-sized: drop the flush thresholds back to
     * steady-state so the current WAL generation stops growing to bulk size.
     * That is what keeps a per-inbound-child utxo_lsm_reload() cheap -- the
     * whole reason the steady-state memtable is small. We do NOT shrink the
     * allocations: the next put/del simply sees live-count over the new, lower
     * threshold and flushes naturally, which also resets the WAL. Lowering a
     * threshold under buffers sized for a bigger one is safe; the reverse
     * would not be. */
    if (g_ckpt_since && !ckpt_now())          /* loop exit of any kind: land the pending batch */
        fprintf(stderr, "[utxo_live] WARNING: failed to persist the batched checkpoint at height %ld\n", g_applied_height);
    if (g_bulk_mode && g_applied_height >= tip) {
        unsigned long ss = 1UL << UTXO_LIVE_SLOTS_LOG2;
        g_utxo_lst.fill_threshold = (u64)ss * 3 / 4;
        g_utxo_lst.op_threshold   = (u64)ss * 2;
        g_bulk_mode = 0;
        txv_set_bulk_mode(0);
        fprintf(stderr, "[utxo_live] caught up at height %ld -- downshifting to steady-state flush thresholds (fill=%llu op=%llu)\n",
                g_applied_height, (unsigned long long)g_utxo_lst.fill_threshold,
                (unsigned long long)g_utxo_lst.op_threshold);
        /* ...and FLUSH, rather than wait for the next put/del to notice the
         * lower threshold.
         *
         * The comment above used to end "the next put/del simply sees
         * live-count over the new, lower threshold and flushes naturally,
         * which also resets the WAL". True only if another block arrives.
         * Caught up on a quiet chain there IS no next put/del, so the current
         * WAL generation stays BULK-sized for as long as the node idles --
         * while the steady-state memtable this downshift just selected is
         * 2^16 slots, far too small to replay such a tail.
         *
         * A restart in that window reloads a batch-scale WAL into a
         * 65,536-slot open-addressed table and degenerates to a full-table
         * probe per record. Measured 2026-08-23 after the 963,000-block
         * replay completed: 100% CPU inside utxo_del's probe loop, no
         * progress after five minutes, and SIGTERM ignored because the reload
         * never reaches a shutdown check. daemon/flush_wal_tail.c exists
         * because build_utxo.c left exactly this kind of tail -- the live
         * path can leave one too, and nothing collected it.
         *
         * One flush per catch-up completion: a bounded cost, paid at the one
         * moment we know the WAL is at its largest and the node is idle. */
        if (g_utxo_lst.log_len > 0) {
            unsigned long long before_n   = (unsigned long long)g_utxo_lst.manifest_n;
            unsigned long long before_len = (unsigned long long)g_utxo_lst.log_len;
            long fr = utxo_lsm_flush(&g_utxo_lst, g_utxo_table);
            if (fr == 1 && g_utxo_lst.log_len == 0)
                fprintf(stderr, "[utxo_live] caught up: flushed the WAL tail (%llu bytes, manifest_n %llu -> %llu) so the next reload has nothing to replay\n",
                        before_len, before_n, (unsigned long long)g_utxo_lst.manifest_n);
            else
                fprintf(stderr, "[utxo_live] WARNING: catch-up WAL flush did not complete (r=%ld, log_len=%llu of %llu): a restart before the next block will replay that tail into a steady-state memtable and be very slow -- daemon/flush_wal_tail is the manual remedy\n",
                        fr, (unsigned long long)g_utxo_lst.log_len, before_len);
        }
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
        compact_poll();
        if (!shutdown_requested()) compact_start_async(g_applied_height, "post-catchup");
    }
    return applied;
}

/* utxo_live_recover(): try to unstick a catch-up that just failed, in place.
 *
 * The dominant catch-up failure is a FULL MANIFEST: once manifest_n reaches
 * manifest_cap, mac_flush refuses to add a run, so utxo_lsm_put/del start
 * returning -1 and every subsequent block fails. A compaction collapses the
 * runs and clears exactly that condition -- which means the failure is
 * usually recoverable without operator involvement, and the node has no
 * business giving up on UTXO tracking for its whole lifetime over it.
 *
 * Returns the number of compaction rounds that actually reduced manifest_n
 * (0 = nothing moved, so a retry will probably fail the same way). Bounded
 * by manifest_cap, and stops the moment a round stops making progress, so a
 * compact() that can no longer merge cannot spin here. */
long utxo_live_recover(void){
    long rounds = 0;
    for (unsigned long guard = 0; guard < UTXO_LIVE_MANIFEST_CAP; guard++){
        u64 before = g_utxo_lst.manifest_n;
        if (before < 2) break;
        long cr = utxo_lsm_compact(&g_utxo_lst);
        fprintf(stderr, "[utxo_live] recover: compact manifest_n=%lu -> %lu (result=%ld)\n",
                (unsigned long)before, (unsigned long)g_utxo_lst.manifest_n, cr);
        if (g_utxo_lst.manifest_n >= before) break;   /* no progress -- stop */
        rounds++;
    }
    return rounds;
}

/* Is compaction the right answer to the last failure? Only for a store
 * error with a full manifest (mac_flush refuses to add a run once manifest_n
 * reaches manifest_cap, and every later put/del fails). Anything else --
 * a consensus reject above all -- is NOT cured by merging runs, and merging
 * runs under a failure we do not understand is exactly what lost 2,596
 * spends on 2026-09-01. Logs its verdict either way so the operator sees
 * WHY the node did or did not compact. */
long utxo_live_recovery_applicable(void){
    unsigned long n = (unsigned long)g_utxo_lst.manifest_n, cap = (unsigned long)g_utxo_lst.manifest_cap;
    if (g_last_fail_kind == UTXO_FAIL_STORE && cap && n >= cap){
        fprintf(stderr, "[utxo_live] recovery applicable: store error at height %ld with a FULL manifest (%lu/%lu runs)\n",
                g_last_fail_height, n, cap);
        return 1;
    }
    fprintf(stderr, "[utxo_live] recovery REFUSED: failure at height %ld is %s (%s), manifest %lu/%lu -- compaction would not cure it\n",
            g_last_fail_height, utxo_live_fail_kind_name(g_last_fail_kind),
            g_last_fail_kind == UTXO_FAIL_REJECT ? g_last_reject : "-", n, cap);
    return 0;
}

/* After a recovery compaction: the set must be exactly what it was before
 * (the failed block was rolled back before recovery ran), by the ground-
 * truth walk, and the O(1) counter must agree. Any other outcome means the
 * merge changed the set -- halt, loudly, permanently for this process. */
long utxo_live_walk_count(void);
long utxo_live_verify_after_recovery(long count_before){
    if (g_halted){ fprintf(stderr, "[utxo_live] post-recovery check: already HALTED -- stays halted\n"); return 0; }
    long walk = utxo_live_walk_count();
    long counter = utxo_lsm_count(&g_utxo_lst);
    if (walk >= 0 && walk == count_before && counter == count_before){
        fprintf(stderr, "[utxo_live] post-recovery check OK: walk=%ld == counter=%ld == pre-recovery count\n", walk, counter);
        return 1;
    }
    g_halted = 1;
    fprintf(stderr, "[utxo_live] POST-RECOVERY CHECK FAILED: walk=%ld counter=%ld pre-recovery=%ld -- the compaction changed the set. "
                    "UTXO tracking HALTED for this process; operator: drop and rebuild the UTXO state (archive_drop_utxo_state), do not trust gettxoutsetinfo until then\n",
            walk, counter, count_before);
    return 0;
}

long utxo_live_applied_height(void){ return g_applied_height; }
/* TEST-ONLY: the live LSM handles, so a test can read a specific outpoint back
 * out of the real store rather than infer it from counts. */
void* utxo_live_test_lst(void){ return &g_utxo_lst; }
void* utxo_live_test_tbl(void){ return g_utxo_table; }
long utxo_live_count(void){ return utxo_lsm_count(&g_utxo_lst); }

/* GROUND-TRUTH live count: a full dedup walk (same primitive the setinfo
 * tool and the capstone used), vs utxo_lsm_count()'s O(1) incremental
 * counter. Added for incident #45 (the counter drifted +7,890,418 during
 * the ghost-heavy rebuild while the walk stayed Core-exact). O(set size) --
 * a diagnostic, never for the hot path. */
static void ulwc_cb(void* ctx, const u8 key36[36], u64 value, u64 code,
                    const u8* script, u64 slen){
    (void)key36; (void)value; (void)code; (void)script; (void)slen;
    (*(long*)ctx)++;
}
long utxo_live_walk_count(void){
    long n = 0;
    if (utxo_lsm_walk(&g_utxo_lst, g_utxo_table, (void*)ulwc_cb, &n) < 0) return -1;
    return n;
}

/* Test/ops knob: drop the flush thresholds live (the caught-up downshift in
 * utxo_live_catchup is the same operation). Incident #45's repro needs
 * flushes DURING a ghost/heal cycle, which production hit at bulk scale and
 * the default test-sized thresholds never reach. */
/* Test/ops: force a flush now (same call catch-up's own cadence makes). */
long utxo_live_flush(void){ return utxo_lsm_flush(&g_utxo_lst, g_utxo_table); }

void utxo_live_set_flush_thresholds(u64 fill, u64 op){
    g_utxo_lst.fill_threshold = fill;
    g_utxo_lst.op_threshold = op;
}

/* Handles onto the ONE live writable LSM instance, so a caller that needs to
 * read the confirmed set (tests/test_reorg.c's expected-vs-actual UTXO diff,
 * and any in-process mempool prevout resolution) queries exactly the
 * instance this module writes to, rather than a second reloaded snapshot
 * that could lag it. */
void* utxo_live_table(void){ return g_utxo_table; }
void* utxo_live_lst(void){ return &g_utxo_lst; }

/* Resolve one confirmed prevout against the LIVE writer state -- the
 * in-process mempool resolution the comment above promises. Matches
 * tx_accept.c's resolver contract (value/script/slen; height and coinbase
 * discarded there by its own stated contract). The returned script pointer
 * is valid until the next LSM operation, so callers must copy before
 * yielding -- mv_resolve does. Incident #48: the worker validated relayed
 * transactions against a SECOND, boot-latched LSM snapshot of the same
 * datadir this writer mutates in place; lookups went incoherent within
 * minutes (missing entries, garbage script lengths). utxo_setinfo's
 * quiescence discipline exists precisely because a live LSM cannot be
 * snapshot-read while written -- resolving against the writer itself is
 * the coherent (and cheaper) alternative. */
long utxo_live_resolve(const u8 txid[32], unsigned long index,
                       unsigned long long* value, unsigned long* height,
                       unsigned long* is_coinbase, const u8** script,
                       unsigned long* slen){
    if (!g_utxo_table) return 0;
    u64 v;
    if (utxo_lsm_get(&g_utxo_lst, g_utxo_table, txid, (u32)index,
                     &v, height, is_coinbase, script, slen) != 1) return 0;
    *value = (unsigned long long)v;
    return 1;
}

void utxo_live_close(void){
    if (g_ckpt_since) ckpt_now();            /* a clean close mid-batch persists */
    utxo_live_compact_shutdown();
    utxo_lsm_close(&g_utxo_lst);
    g_recovery_checked = 0;
}
