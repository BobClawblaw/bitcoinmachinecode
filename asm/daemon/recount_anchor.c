/* daemon/recount_anchor.c -- one-time (reusable) re-anchor of the LSM's
 * persisted live count.
 *
 * WHY. The daemon always defers the boot recount (main.c sets
 * g_utxo_defer_recount for the whole process: a synchronous full walk would
 * block the boot), and mac_flush publishes the RUNNING tally into the
 * manifest header -- it never recomputes. So once the running tally drifts
 * from the true content count, every boot inherits the drift from the
 * persisted base and every flush re-publishes it: the count can never
 * self-heal. Observed 2026-09-05: the live store's tally ran ~215k above the
 * walked truth (a fossil of the pre-fix boots -- truncated 2^23 WAL replays,
 * zero-run manifest-cap boots, retry/rollback churn -- it entered before
 * h=964091 and, the deltas since being honest, stayed a constant offset).
 * The drift is display-only EXCEPT that gettxoutsetinfo's consistency guard
 * compares the running tally against the walk and refuses on mismatch.
 *
 * WHAT THIS TOOL DOES. With the daemon stopped:
 *   1. reload WITHOUT the defer flag. A non-empty WAL (the daemon's
 *      unflushed tail -- it always is, blocks apply between flushes) makes
 *      utxo_lsm_reload run mac_lsm_recount, which walks the actual content:
 *      total_live becomes TRUE.
 *      (If the WAL were empty the reload would trust the persisted base --
 *      the tool detects that via replayed==0 AND an unchanged-count sanity
 *      note, and still flushes; run it again after any daemon activity to
 *      get a recount pass.)
 *   2. utxo_lsm_flush: writes the memtable as a fresh run and publishes the
 *      RECOUNTED tally into the manifest header, truncating the WAL. Every
 *      later boot prints the honest count and gettxoutsetinfo's guard can
 *      pass.
 * The flush also carries the memtable's real pending ops (e.g. WAL-replayed
 * repairs) into durable runs, so the tool composes safely after
 * repair_bip30_heights.
 *
 * Usage: recount_anchor <datadir>
 * Mirrors flush_wal_tail.c's sizing (2^24 memtable, tomb_cap=slots*2).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

typedef uint8_t u8; typedef uint64_t u64;

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_reload(void* lst, void* u);
extern long utxo_lsm_flush(void* lst, void* u);
extern void utxo_lsm_close(void* lst);

struct lsm_state {
    long log_fd, idx_fd;
    u64 log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap;
    u64 next_run_no;
    void* tomb_hash_buf; u64 tomb_hash_mask;
};
#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536

static void* mmap_file(const char* path, u64 size){
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) { perror("open"); return 0; }
    if (ftruncate(fd, (off_t)size) != 0) { perror("ftruncate"); close(fd); return 0; }
    void* p = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) { perror("mmap"); return 0; }
    return p;
}

int main(int argc, char** argv){
    if (argc < 2) { fprintf(stderr, "usage: %s <datadir>\n", argv[0]); return 2; }
    if (chdir(argv[1])) { perror("chdir"); return 1; }

    int slots_log2 = 24;
    unsigned long slots = 1UL << slots_log2;
    u64 blob_cap = 2UL*1024*1024*1024;
    long ustruct = utxo_struct_size(slots);
    u64 tomb_cap = slots * 2;
    u64 desc_cap = slots * 3;
    u64 scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    u64 manifest_cap = 8192;

    void* u = mmap_file("utxo_lsm_recount_table.map", (u64)ustruct);
    void* blob = mmap_file("utxo_lsm_recount_blob.map", blob_cap);
    if (!u || !blob) return 1;
    utxo_init(u, slots, blob, blob_cap);

    void* tomb_buf = malloc(tomb_cap*36);
    void* manifest_buf = malloc(manifest_cap*16);
    void* scratch_buf = malloc(scratch_cap);
    if (!tomb_buf || !manifest_buf || !scratch_buf) { fprintf(stderr, "malloc failed\n"); return 1; }

    struct lsm_state lst;
    memset(&lst, 0, sizeof lst);
    lst.op_threshold = slots * 2;      /* production-like: the flush below is
                                        * the ONE flush this tool performs */
    lst.fill_threshold = slots * 3 / 4;
    lst.tomb_buf = tomb_buf; lst.tomb_cap = tomb_cap;
    lst.manifest_buf = manifest_buf; lst.manifest_cap = manifest_cap;
    lst.scratch_buf = scratch_buf; lst.scratch_cap = scratch_cap;

    /* This process NEVER sets g_utxo_defer_recount, so a non-empty WAL makes
     * utxo_lsm_reload recount from actual content. */
    long replayed = utxo_lsm_reload(&lst, u);
    if (replayed < 0) { fprintf(stderr, "FATAL: reload failed\n"); return 1; }
    fprintf(stderr, "reload ok: manifest_n=%lu replayed=%ld total_live=%lu%s\n",
            lst.manifest_n, replayed, lst.total_live,
            replayed > 0 ? " (recounted from content)" :
                           " (WAL empty -- base trusted; rerun after daemon activity for a recount)");

    long f = utxo_lsm_flush(&lst, u);
    if (f != 1){ fprintf(stderr, "FATAL: flush failed (%ld)\n", f); return 1; }
    fprintf(stderr, "flush ok: manifest_n=%lu total_live=%lu published to the manifest header; WAL reset\n",
            lst.manifest_n, lst.total_live);

    utxo_lsm_close(&lst);
    fprintf(stderr, "DONE\n");
    return 0;
}
