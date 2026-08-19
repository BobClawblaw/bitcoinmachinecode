/* daemon/flush_wal_tail.c -- one-time fix: the batch replay (build_utxo.c)
 * left a large unflushed WAL tail (its own memtable never crossed a flush
 * threshold before the process exited cleanly). Every subsequent
 * utxo_lsm_reload() -- including the live daemon's utxo_live.c, sized for
 * steady-state incremental traffic (2^16 slots), not this batch-scale
 * leftover -- has to replay that whole tail into memtable every single
 * time, which is exactly the pathological-slow scenario found earlier
 * today. Root-cause fix, not a per-caller workaround: reload the tail with
 * a properly-sized memtable, then force ONE flush so it becomes a durable
 * run and the WAL resets to empty. Every future reload (by any caller,
 * any memtable size) then has nothing to replay.
 *
 * Usage: flush_wal_tail <dir>
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
extern long utxo_lsm_del(void* lst, void* u, const u8 txid[32], unsigned index);
extern void utxo_lsm_close(void* lst);

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
    if (argc < 2) { fprintf(stderr, "usage: %s <dir>\n", argv[0]); return 2; }
    if (chdir(argv[1])) { perror("chdir"); return 1; }

    /* Large enough memtable to replay the real tail correctly (matches
     * build_migrate_compact.c's production sizing), but thresholds
     * deliberately tiny so the FIRST wrapper-layer op after reload forces
     * an immediate flush regardless of how big the replayed tail was --
     * reload's own WAL-tail replay bypasses utxo_lsm_put/del's threshold
     * bookkeeping entirely (it applies records via the raw in-memory
     * primitives, bitcoin_utxo.asm), so op_count stays 0 after reload no
     * matter how many records were replayed. */
    int slots_log2 = 22;
    unsigned long slots = 1UL << slots_log2;
    u64 blob_cap = 2UL*1024*1024*1024;
    long ustruct = utxo_struct_size(slots);
    u64 tomb_cap = slots * 2;   /* was 8192 -- far too small: reload's own WAL
                                 * tombstone-reconstruction pass silently
                                 * breaks out early once tomb_n hits tomb_cap
                                 * (bitcoin_utxo_lsm.asm .rl_wal_del, jae
                                 * .rl_wal_close), truncating op_count/tomb_n
                                 * well short of the real WAL tail's true
                                 * DEL-record count. Sized like production
                                 * fill/op thresholds elsewhere (slots*2). */
    u64 desc_cap = slots * 3;
    u64 scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    u64 manifest_cap = 8192;

    void* u = mmap_file("utxo_lsm_flushtail_table.map", (u64)ustruct);
    void* blob = mmap_file("utxo_lsm_flushtail_blob.map", blob_cap);
    if (!u || !blob) return 1;
    utxo_init(u, slots, blob, blob_cap);

    void* tomb_buf = malloc(tomb_cap*36);
    void* manifest_buf = malloc(manifest_cap*16);
    void* scratch_buf = malloc(scratch_cap);
    if (!tomb_buf || !manifest_buf || !scratch_buf) { fprintf(stderr, "malloc failed\n"); return 1; }

    struct lsm_state lst;
    memset(&lst, 0, sizeof lst);
    lst.op_threshold = 1;       /* force flush on the very next op */
    lst.fill_threshold = 1;
    lst.tomb_buf = tomb_buf; lst.tomb_cap = tomb_cap;
    lst.manifest_buf = manifest_buf; lst.manifest_cap = manifest_cap;
    lst.scratch_buf = scratch_buf; lst.scratch_cap = scratch_cap;

    long replayed = utxo_lsm_reload(&lst, u);
    if (replayed < 0) { fprintf(stderr, "FATAL: reload failed\n"); return 1; }
    fprintf(stderr, "reload ok: manifest_n=%lu replayed=%ld total_live=%lu op_count=%lu\n",
            lst.manifest_n, replayed, lst.total_live, lst.op_count);

    if (replayed == 0) {
        fprintf(stderr, "WAL tail already empty -- nothing to flush\n");
        utxo_lsm_close(&lst);
        return 0;
    }

    long before_manifest = lst.manifest_n;
    u8 dummy_txid[32]; memset(dummy_txid, 0xEE, 32); /* guaranteed nonexistent key */
    long r = utxo_lsm_del(&lst, u, dummy_txid, 0xFFFFFFFEu);
    /* utxo_lsm_del's error path is `mov eax, -1` (32-bit, bitcoin_utxo_lsm.asm
     * .ld_err) which zero-extends to rax=0xFFFFFFFF, NOT 64-bit -1 -- so
     * `r == -1` never matches here. Check against the success value (1)
     * instead, which is unambiguous regardless of the register-width quirk. */
    if (r != 1) { fprintf(stderr, "FATAL: dummy del failed (r=%ld)\n", r); return 1; }
    fprintf(stderr, "after forced flush: manifest_n=%lu (was %ld) log_len=%lu\n",
            lst.manifest_n, before_manifest, lst.log_len);

    if (lst.manifest_n <= (u64)before_manifest) {
        fprintf(stderr, "FATAL: manifest_n did not grow -- flush did not happen\n");
        return 1;
    }
    if (lst.log_len != 0) {
        fprintf(stderr, "WARNING: WAL not empty after flush (log_len=%lu) -- unexpected\n", lst.log_len);
    }

    utxo_lsm_close(&lst);
    fprintf(stderr, "DONE\n");
    return 0;
}
