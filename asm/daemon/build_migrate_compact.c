/* daemon/build_migrate_compact.c -- Stage 2 one-time migration: compact a
 * finished build_utxo.c replay down to a small manifest, upgrading every
 * surviving run to the sparse-indexed MAGIC_RUN2 format along the way
 * (both mac_flush and utxo_lsm_compact write through the same fixed
 * writer -- see bitcoin_utxo_lsm.asm's header comment). Pure manifest+
 * run-file surgery: utxo_lsm_compact never touches the memtable/table, so
 * this tool doesn't either, except as utxo_lsm_reload's required (but for
 * a cleanly-closed replay, essentially empty) WAL-tail replay target.
 *
 * Usage: build_migrate_compact <dir> <slots_log2> <blob_gb>
 *   Same sizing args as build_utxo.c -- reused here only so utxo_lsm_reload
 *   has correctly-sized buffers to replay into if there's any WAL tail.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

typedef uint8_t u8; typedef uint64_t u64;

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_reload(void* lst, void* u);
extern long utxo_lsm_compact(void* lst);
extern void utxo_lsm_close(void* lst);

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

static double now_s(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return ts.tv_sec+ts.tv_nsec*1e-9; }

static void* mmap_file(const char* path, u64 size){
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) { fprintf(stderr, "[migrate] open(%s) failed: %s\n", path, strerror(errno)); return 0; }
    if (ftruncate(fd, (off_t)size) != 0) { fprintf(stderr, "[migrate] ftruncate(%s,%lu) failed: %s\n", path, size, strerror(errno)); close(fd); return 0; }
    void* p = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) { fprintf(stderr, "[migrate] mmap(%s,%lu) failed: %s\n", path, size, strerror(errno)); return 0; }
    return p;
}

int main(int argc, char** argv){
    if (argc < 4) { fprintf(stderr, "usage: %s <dir> <slots_log2> <blob_gb> [--reload-only]\n", argv[0]); return 2; }
    const char* dir = argv[1];
    int slots_log2 = atoi(argv[2]);
    double blob_gb = atof(argv[3]);
    int reload_only = (argc >= 5 && !strcmp(argv[4], "--reload-only"));
    if (chdir(dir)) { perror("chdir"); return 1; }

    unsigned long slots = 1UL << slots_log2;
    u64 blob_cap = (u64)(blob_gb * (1UL<<30));
    long ustruct = utxo_struct_size(slots);
    u64 fill_threshold = (u64)slots * 3 / 4;
    u64 op_threshold    = (u64)slots * 2;
    u64 tomb_cap         = op_threshold;
    u64 desc_cap         = (u64)slots * 3;
    u64 scratch_cap       = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    u64 manifest_cap       = 8192;

    fprintf(stderr, "[migrate] dir=%s slots=2^%d blob=%.2fGB fill_th=%lu op_th=%lu "
            "tomb_cap=%lu manifest_cap=%lu scratch=%.2fGB\n",
            dir, slots_log2, blob_cap/1e9, fill_threshold, op_threshold,
            tomb_cap, manifest_cap, scratch_cap/1e9);

    void* u = mmap_file("utxo_lsm_migrate_table.map", (u64)ustruct);
    void* blob = mmap_file("utxo_lsm_migrate_blob.map", blob_cap);
    if (!u || !blob) { fprintf(stderr, "mmap alloc failed\n"); return 1; }
    utxo_init(u, slots, blob, blob_cap);

    void* tomb_buf = malloc(tomb_cap*36);
    void* manifest_buf = malloc(manifest_cap*16);
    void* scratch_buf = malloc(scratch_cap);
    if (!tomb_buf || !manifest_buf || !scratch_buf) { fprintf(stderr, "malloc failed\n"); return 1; }

    struct lsm_state lst;
    memset(&lst, 0, sizeof lst);
    lst.op_threshold = op_threshold;
    lst.fill_threshold = fill_threshold;
    lst.tomb_buf = tomb_buf; lst.tomb_cap = tomb_cap;
    lst.manifest_buf = manifest_buf; lst.manifest_cap = manifest_cap;
    lst.scratch_buf = scratch_buf; lst.scratch_cap = scratch_cap;

    double t0 = now_s();
    long replayed = utxo_lsm_reload(&lst, u);
    if (replayed < 0) { fprintf(stderr, "[migrate] FATAL: utxo_lsm_reload failed\n"); return 1; }
    fprintf(stderr, "[migrate] reload ok: manifest_n=%lu replayed_wal_ops=%ld (%.1fs)\n",
            lst.manifest_n, replayed, now_s()-t0);

    if (reload_only) {
        fprintf(stderr, "[migrate] --reload-only: stopping before any compaction\n");
        utxo_lsm_close(&lst);
        return 0;
    }

    if (lst.manifest_n <= 1) {
        fprintf(stderr, "[migrate] manifest_n already <=1 -- nothing to compact\n");
        utxo_lsm_close(&lst);
        return 0;
    }

    long pass = 0;
    while (lst.manifest_n > 1) {
        double ct0 = now_s();
        u64 before = lst.manifest_n;
        long r = utxo_lsm_compact(&lst);
        double dt = now_s() - ct0;
        if (r == -1) {
            fprintf(stderr, "[migrate] FATAL: utxo_lsm_compact returned -1 on pass %ld (manifest_n was %lu)\n", pass, before);
            utxo_lsm_close(&lst);
            return 1;
        }
        pass++;
        fprintf(stderr, "[migrate] pass %ld: manifest_n %lu -> %lu (%.1fs)\n", pass, before, lst.manifest_n, dt);
        if (r == 0) {
            /* "nothing to do" (manifest_n<2) -- loop condition already covers this, but
             * guard against an unexpected stall (r==0 while manifest_n>1 would spin forever) */
            if (lst.manifest_n > 1) {
                fprintf(stderr, "[migrate] FATAL: compact returned 0 (noop) but manifest_n=%lu>1 -- stalled\n", lst.manifest_n);
                utxo_lsm_close(&lst);
                return 1;
            }
            break;
        }
    }

    fprintf(stderr, "[migrate] DONE: manifest_n=%lu total_elapsed=%.1fs\n", lst.manifest_n, now_s()-t0);
    utxo_lsm_close(&lst);
    return 0;
}
