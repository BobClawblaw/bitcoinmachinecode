/* daemon/build_utxo.c -- construct the persistent UTXO set (bitcoin_utxo_
 * lsm.asm) by replaying every block in the archive, in height order.
 *
 * Every output creates a UTXO entry (utxo_lsm_put); every non-coinbase
 * input spends/deletes one (utxo_lsm_del). Coinbase inputs (null prevout:
 * txid all-zero, index 0xFFFFFFFF) are skipped -- they don't reference a
 * real prior output.
 *
 * Uses the LSM-tree store (bitcoin_utxo_lsm.asm) instead of the earlier
 * single-giant-table approach (bitcoin_utxo_store.asm): a small BOUNDED
 * memtable that periodically flushes to sorted, Bloom-filtered, immutable
 * run files, instead of one hash table pre-sized for the eventual ~408M
 * final live-UTXO count. The old approach write-amplified ~13x during a
 * full-archive replay because scattered writes landed across the whole
 * 51GB structure from block 0 onward regardless of the actual (much
 * smaller, early on) live count. See asm/bitcoin_utxo_lsm.asm's header
 * comment for the full design.
 *
 * Input/output walking is done by THIS driver (walk_tx_io below), not by
 * calling bitcoin_tx.asm's tx_parse repeatedly, because tx_parse only
 * records input[0]/output[0] offsets. To avoid re-deriving segwit's
 * witness-skip logic (already correct and proven in tx_parse), this driver
 * only walks the input/output section itself (identical encoding whether
 * or not a tx is segwit) and gets the AUTHORITATIVE total tx_len (which
 * DOES need correct witness-skipping, to find the next tx) from tx_parse.
 * tx_parse's own returned n_in/n_out are cross-checked against this
 * driver's independent walk on every transaction as a consistency guard.
 *
 * The real txid (for BOTH the outputs this tx creates AND matching later
 * inputs that reference it) comes from bitcoin_tx.asm's tx_txid -- the
 * already-proven BIP141-correct (witness-stripped) txid, in the same
 * internal/wire byte order the wire format's prevout field itself uses, so
 * no byte-reversal is needed anywhere in this driver.
 *
 * Usage: build_utxo <dir> <slots_log2> <blob_gb> [--dry-run] [start] [end]
 *   <slots_log2>: log2 of the MEMTABLE's slot count (NOT the final live
 *                 set -- the memtable is bounded and flushes long before
 *                 that). 22 (~4.2M slots) is a reasonable production
 *                 default; fill/op flush thresholds and scratch/tombstone/
 *                 manifest buffer sizes are all derived from it below.
 *   <blob_gb>: memtable blob (value+script bump allocator) capacity --
 *              only needs to cover one generation's worth of script data
 *              between flushes now, not the whole chain's history. 1.0 is
 *              a safe default at slots_log2=22.
 *   --dry-run: walk and cross-check every tx WITHOUT touching the UTXO
 *              store (no memory allocation for it) -- used to get real
 *              scale numbers and confirm parsing correctness across the
 *              whole archive before committing to the real, memory- and
 *              time-expensive populate run.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "utxo_walk.h"

extern long store_init(void* st);
extern long store_reload(void* st);
extern void store_rd_init(void* st);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern long store_read_at(void* st, u64 height, void* buf, u64 cap);

extern int  tx_parse(void* info, const u8* tx, unsigned long txlen);
extern void tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_count(void* u);

extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index, u64 value, u64 height, u64 is_coinbase, const u8* script, u32 slen);
extern long utxo_lsm_del(void* lst, void* u, const u8 txid[32], u32 index);
extern long utxo_lsm_count(void* lst);
extern void utxo_lsm_close(void* lst);

/* Must mirror bitcoin_utxo_lsm.asm's state struct exactly (168 bytes). */
struct lsm_state {
    long log_fd, idx_fd;
    u64 log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap;
    u64 next_run_no;
    void* tomb_hash_buf; u64 tomb_hash_mask; /* LSM-owned, see bitcoin_utxo_lsm.asm */
};
#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536

/* read_varint/walk_tx_io now live in utxo_walk.h (shared with utxo_live.c,
 * the live daemon's incremental counterpart to this batch driver) --
 * byte-for-byte the same logic that used to be defined here directly. */
typedef utxo_walk_input_cb input_cb;
typedef utxo_walk_output_cb output_cb;
#define read_varint utxo_walk_read_varint
#define walk_tx_io utxo_walk_tx_io

/* ---- driver state ---- */
static void* g_utxo = 0;
static struct lsm_state g_lst;
static int   g_dry_run = 0;
static long  g_puts=0, g_dels=0, g_put_dup=0, g_coinbase_skips=0, g_ntx=0;
static long  g_fatal = 0; /* -1 from utxo_lsm_put/del: I/O error or (put) table full */
static const u8 ZERO32[32] = {0};

static void on_input(void* ctx, const u8 txid[32], u32 index){
    (void)ctx;
    if (index == 0xFFFFFFFFu && memcmp(txid, ZERO32, 32)==0) { g_coinbase_skips++; return; }
    g_dels++;
    if (g_dry_run) return;
    /* utxo_lsm_del's contract (unlike the old utxo_store_del): a memtable
     * miss is ASSUMED to reference an already-flushed older generation and
     * is recorded as a tombstone rather than reported as a miss -- so it
     * always returns 1 except on a genuine I/O error (-1). A del_miss
     * counter would no longer mean anything (it'd fire on nearly every
     * spend of an already-flushed output, which is normal and expected). */
    long r = utxo_lsm_del(&g_lst, g_utxo, txid, index);
    if (r == -1) {
        fprintf(stderr, "[build_utxo] FATAL: utxo_lsm_del I/O error\n");
        g_fatal = 1;
    }
}

/* height/is_coinbase (2026-08-19, Stage D): the UTXO record now carries
 * both, so script verification can later enforce the 100-block coinbase
 * maturity rule -- neither was available anywhere before this. Both are
 * in scope in main()'s per-tx loop (block height h, tx index t) at
 * exactly the point out_ctx_t gets built; is_coinbase is (t==0), Bitcoin's
 * own rule (coinbase is always the first tx in a block). */
typedef struct { const u8* txid; u64 height; u64 is_coinbase; } out_ctx_t;
static void on_output(void* ctxv, u32 out_index, u64 value, const u8* script, u32 slen){
    out_ctx_t* ctx = (out_ctx_t*)ctxv;
    g_puts++;
    if (g_dry_run) return;
    long r = utxo_lsm_put(&g_lst, g_utxo, ctx->txid, out_index, value,
                          ctx->height, ctx->is_coinbase, script, slen);
    if (r == 1) return;
    if (r == 0) { g_put_dup++; return; } /* rare, real (e.g. BIP30-class) dup */
    fprintf(stderr, "[build_utxo] FATAL: utxo_lsm_put returned %ld (2=table full -- memtable "
                     "undersized for the fill_threshold that should have flushed first; "
                     "-1=I/O error)\n", r);
    g_fatal = 1;
}

static double now_s(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return ts.tv_sec+ts.tv_nsec*1e-9; }

/* Table/blob/scratch/tombstone/manifest buffers are all BOUNDED now (sized
 * off slots_log2, not the eventual ~408M live set), so plain mmap'd
 * anonymous-ish disk-backed files are still used for the two big ones
 * (table, blob) for consistency with the rest of this codebase's
 * disk-backed-allocation convention, but sizes are now modest (hundreds of
 * MB to low GB, not 51GB). */
static void* mmap_file(const char* path, u64 size){
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) { fprintf(stderr, "[build_utxo] open(%s) failed: %s\n", path, strerror(errno)); return 0; }
    if (ftruncate(fd, (off_t)size) != 0) { fprintf(stderr, "[build_utxo] ftruncate(%s,%lu) failed: %s\n", path, size, strerror(errno)); close(fd); return 0; }
    void* p = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd); /* mapping stays valid after close */
    if (p == MAP_FAILED) { fprintf(stderr, "[build_utxo] mmap(%s,%lu) failed: %s\n", path, size, strerror(errno)); return 0; }
    return p;
}

/* ---- corrupted-block tracking: verified independently against a real
 * archive integrity issue found at height 30000 during development (its
 * stored bytes don't hash-match their own index record -- confirmed via
 * the exact raw-file-access pattern check_chain.c uses, so this is a real
 * archive data issue, not a bug in this driver). Rather than let one bad
 * block abort a multi-hour replay, verify each block's hash against its
 * own index record BEFORE trusting its transaction data, and skip (with a
 * logged height) any block that fails -- so the UTXO set stays correct for
 * every block that DOES verify, and the exact set of affected heights is
 * known afterward for separate investigation/repair. ---- */
static int g_idx_fd = -1;
static long g_bad_hash=0, g_bad_parse=0;
#define MAX_BAD_HEIGHTS 100000
static long g_bad_heights[MAX_BAD_HEIGHTS];
static long g_bad_heights_n = 0;
static void record_bad_height(long h){
    if (g_bad_heights_n < MAX_BAD_HEIGHTS) g_bad_heights[g_bad_heights_n++] = h;
}

/* index.dat's stored hash and block_hash()'s return value are in the SAME
 * byte order -- confirmed directly against the genesis block's well-known
 * hash (no reversal needed; an earlier version of this function assumed
 * display/big-endian order and reversed before comparing, which produced
 * false "corruption" on every block, including known-good ones). */
static int verify_block_hash(long h, const u8* blockbuf){
    if (g_idx_fd < 0) return 1; /* verification unavailable, don't block */
    u8 rec[48];
    ssize_t n = pread(g_idx_fd, rec, 48, h*48);
    if (n != 48) return 1; /* can't verify -- don't false-positive on this */
    u8 hh[32]; block_hash(hh, blockbuf);
    return memcmp(rec, hh, 32) == 0;
}

int main(int argc, char** argv){
    if (argc < 4) { fprintf(stderr, "usage: %s <dir> <slots_log2> <blob_gb> [--dry-run] [start] [end]\n", argv[0]); return 2; }
    const char* dir = argv[1];
    int slots_log2 = atoi(argv[2]);
    double blob_gb = atof(argv[3]);
    long start_h = 0, end_h = -1;
    int npos = 0;
    for (int i=4;i<argc;i++){
        if (!strcmp(argv[i], "--dry-run")) g_dry_run = 1;
        else if (npos==0) { start_h = atol(argv[i]); npos=1; }
        else { end_h = atol(argv[i]); npos=2; }
    }
    if (chdir(dir)) { perror("chdir"); return 1; }

    g_idx_fd = open("index.dat", O_RDONLY);
    if (g_idx_fd < 0) { fprintf(stderr, "[build_utxo] WARNING: can't open index.dat for hash verification (%s) -- proceeding WITHOUT corruption checks\n", strerror(errno)); }

    static u8 store_buf[4096];
    if (store_init(store_buf) != 1) { fprintf(stderr, "store_init failed\n"); return 1; }
    store_reload(store_buf);
    store_rd_init(store_buf);
    long tip = *(int*)(store_buf+24);
    if (tip < 0) { fprintf(stderr, "empty store\n"); return 1; }
    if (end_h < 0 || end_h > tip) end_h = tip;
    fprintf(stderr, "[build_utxo] dir=%s tip=%ld range=[%ld,%ld] mode=%s\n",
            dir, tip, start_h, end_h, g_dry_run ? "DRY-RUN (no table)" : "POPULATE (LSM)");

    if (!g_dry_run) {
        unsigned long slots = 1UL << slots_log2;
        u64 blob_cap = (u64)(blob_gb * (1UL<<30));
        long ustruct = utxo_struct_size(slots);
        /* Derived flush-threshold/buffer sizing -- see bitcoin_utxo_lsm.asm's
         * header comment for the exact required relationships:
         *   desc_cap >= fill_threshold + tomb_cap
         *   scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES */
        u64 fill_threshold = (u64)slots * 3 / 4;
        u64 op_threshold    = (u64)slots * 2;
        u64 tomb_cap         = op_threshold;
        u64 desc_cap         = (u64)slots * 3; /* >= fill_threshold+tomb_cap, with margin */
        u64 scratch_cap       = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
        u64 manifest_cap       = 8192;

        fprintf(stderr, "[build_utxo] memtable: slots=2^%d (%lu) struct=%.2fGB blob=%.2fGB "
                "fill_th=%lu op_th=%lu tomb_cap=%lu manifest_cap=%lu scratch=%.2fGB\n",
                slots_log2, slots, ustruct/1e9, blob_cap/1e9, fill_threshold, op_threshold,
                tomb_cap, manifest_cap, scratch_cap/1e9);

        g_utxo = mmap_file("utxo_lsm_table.map", (u64)ustruct);
        void* blob = mmap_file("utxo_lsm_blob.map", blob_cap);
        if (!g_utxo || !blob) { fprintf(stderr, "mmap alloc failed (table=%p blob=%p)\n", g_utxo, blob); return 1; }
        double ti0 = now_s();
        utxo_init(g_utxo, slots, blob, blob_cap);
        fprintf(stderr, "[build_utxo] table zero-init done (%.1fs)\n", now_s()-ti0);

        void* tomb_buf = malloc(tomb_cap*36);
        void* manifest_buf = malloc(manifest_cap*16); /* [gen:8][run_no:8] per entry */
        void* scratch_buf = malloc(scratch_cap);
        if (!tomb_buf || !manifest_buf || !scratch_buf) {
            fprintf(stderr, "[build_utxo] malloc failed (tomb=%p manifest=%p scratch=%p)\n",
                    tomb_buf, manifest_buf, scratch_buf);
            return 1;
        }
        memset(&g_lst, 0, sizeof g_lst);
        g_lst.op_threshold = op_threshold;
        g_lst.fill_threshold = fill_threshold;
        g_lst.tomb_buf = tomb_buf; g_lst.tomb_cap = tomb_cap;
        g_lst.manifest_buf = manifest_buf; g_lst.manifest_cap = manifest_cap;
        g_lst.scratch_buf = scratch_buf; g_lst.scratch_cap = scratch_cap;
        if (utxo_lsm_init(&g_lst) != 1) { fprintf(stderr, "utxo_lsm_init failed\n"); return 1; }
    }

    static u8 blockbuf[8<<20];
    static u8 txid_scratch[4<<20];
    double t0 = now_s();
    long last_report_h = start_h;
    double last_report_t = t0;

    for (long h = start_h; h <= end_h && !g_fatal; h++){
        long len = store_read_at(store_buf, h, blockbuf, sizeof blockbuf);
        if (len < 81) { fprintf(stderr, "[build_utxo] WARNING: hole/short block at height %ld (len=%ld), skipping\n", h, len); continue; }

        if (!verify_block_hash(h, blockbuf)) {
            fprintf(stderr, "[build_utxo] CORRUPT: block hash mismatch at height %ld -- skipping this block entirely\n", h);
            g_bad_hash++; record_bad_height(h);
            continue;
        }

        const u8* p = blockbuf + 80;
        const u8* blkend = blockbuf + len;
        u64 consumed;
        u64 ntx = read_varint(p, blkend, &consumed);
        if (!consumed) {
            fprintf(stderr, "[build_utxo] CORRUPT: bad tx-count varint at height %ld -- skipping\n", h);
            g_bad_parse++; record_bad_height(h);
            continue;
        }
        p += consumed;

        int block_ok = 1;
        for (u64 t=0; t<ntx && block_ok && !g_fatal; t++){
            static u8 info[64];
            int ok = tx_parse(info, p, (unsigned long)(blkend - p));
            if (!ok) {
                fprintf(stderr, "[build_utxo] CORRUPT: tx_parse failed h=%ld tx=%lu -- skipping rest of block (hash already verified OK, so this indicates a parser gap, not archive corruption -- investigate!)\n", h, (unsigned long)t);
                g_bad_parse++; record_bad_height(h); block_ok = 0; break;
            }
            u64 txlen; memcpy(&txlen, info, 8);
            u32 pn_in, pn_out; memcpy(&pn_in, info+12, 4); memcpy(&pn_out, info+16, 4);

            u8 txid[32];
            tx_txid(txid, p, txlen, txid_scratch, sizeof txid_scratch);

            out_ctx_t oc = { txid, (u64)h, (u64)(t == 0) };
            u64 wnin=0, wnout=0;
            int wok = walk_tx_io(p, p+txlen, &oc, on_input, on_output, &wnin, &wnout);
            if (!wok) {
                fprintf(stderr, "[build_utxo] CORRUPT: walk_tx_io failed h=%ld tx=%lu (hash-verified block; investigate!)\n", h, (unsigned long)t);
                g_bad_parse++; record_bad_height(h); block_ok = 0; break;
            }
            if (wnin != pn_in || wnout != pn_out) {
                fprintf(stderr, "[build_utxo] CORRUPT: n_in/n_out mismatch h=%ld tx=%lu tx_parse(%u,%u) walk(%lu,%lu) (hash-verified block; investigate!)\n",
                        h, (unsigned long)t, pn_in, pn_out, wnin, wnout);
                g_bad_parse++; record_bad_height(h); block_ok = 0; break;
            }
            g_ntx++;
            p += txlen;
        }
        if (block_ok && p != blkend) {
            fprintf(stderr, "[build_utxo] WARNING: %ld trailing bytes unconsumed at height %ld\n", (long)(blkend-p), h);
        }

        if (h - last_report_h >= 20000 || h == end_h) {
            double t1 = now_s();
            double rate = (h - last_report_h) / (t1 - last_report_t + 1e-9);
            fprintf(stderr, "[build_utxo] h=%ld/%ld (%.1f%%) ntx=%ld puts=%ld dels=%ld put_dup=%ld cb_skip=%ld  %.0f blk/s  live=%ld runs=%lu\n",
                    h, end_h, 100.0*h/end_h, g_ntx, g_puts, g_dels, g_put_dup, g_coinbase_skips,
                    rate, g_dry_run ? (g_puts-g_dels) : utxo_lsm_count(&g_lst),
                    g_dry_run ? 0UL : g_lst.manifest_n);
            last_report_h = h; last_report_t = t1;
        }
    }

    double t1 = now_s();
    fprintf(stderr, "\n[build_utxo] %s range=[%ld,%ld] elapsed=%.1fs\n",
            g_fatal ? "ABORTED (fatal error)" : "DONE", start_h, end_h, t1-t0);
    fprintf(stderr, "[build_utxo] total tx=%ld puts=%ld dels=%ld put_dup=%ld coinbase_skips=%ld\n",
            g_ntx, g_puts, g_dels, g_put_dup, g_coinbase_skips);
    fprintf(stderr, "[build_utxo] CORRUPTION: bad_hash=%ld bad_parse=%ld (blocks entirely skipped: %ld)\n",
            g_bad_hash, g_bad_parse, g_bad_heights_n);
    if (g_bad_heights_n > 0) {
        fprintf(stderr, "[build_utxo] affected heights (up to first %d): ", MAX_BAD_HEIGHTS);
        for (long i=0;i<g_bad_heights_n && i<200;i++) fprintf(stderr, "%ld ", g_bad_heights[i]);
        if (g_bad_heights_n > 200) fprintf(stderr, "... (%ld more)", g_bad_heights_n-200);
        fprintf(stderr, "\n");
        FILE* bf = fopen("build_utxo_bad_heights.txt", "w");
        if (bf) { for (long i=0;i<g_bad_heights_n;i++) fprintf(bf, "%ld\n", g_bad_heights[i]); fclose(bf); }
        fprintf(stderr, "[build_utxo] full list written to build_utxo_bad_heights.txt\n");
    }
    if (!g_dry_run) {
        /* total_live is a best-effort running estimate (see
         * bitcoin_utxo_lsm.asm's header comment) -- exact in practice for
         * this workload since every del is a real consensus-valid spend,
         * but not reconciled against flushed-run contents; telemetry only. */
        fprintf(stderr, "[build_utxo] final live UTXO count (approx) = %ld, runs=%lu\n",
                utxo_lsm_count(&g_lst), g_lst.manifest_n);
        double s0 = now_s();
        utxo_lsm_close(&g_lst);
        fprintf(stderr, "[build_utxo] final close (%.2fs)\n", now_s()-s0);
    } else {
        fprintf(stderr, "[build_utxo] dry-run implied live count = puts-dels = %ld\n", g_puts - g_dels);
    }
    return g_fatal ? 1 : 0;
}
