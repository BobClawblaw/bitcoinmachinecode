/* tests/test_lsm_manifest_cap.c -- utxo_lsm_reload must FAIL LOUDLY when a
 * store's manifest cannot be loaded, not silently proceed with zero runs.
 *
 * THE REGRESSION (2026-09-05, the 964001 DEGRADED class): the reload's
 * manifest loader compared the file's entry count against the CALLER's
 * manifest_cap and, on count > cap, jumped to a path that zeroed
 * manifest_n/next_gen/next_run_no and FELL THROUGH to the WAL replay --
 * returning a non-negative "replayed" count. A caller then owned a store
 * with ZERO runs registered: every utxo_lsm_get scanned nothing and missed,
 * which surfaced downstream as "input references a missing/already-spent
 * UTXO" at the first spend of the first block. Live instance: the v2
 * rebuilt store's 424-run manifest handed to the daemon whose
 * UTXO_LIVE_MANIFEST_CAP is 256 -- three boots, every lookup dead, and the
 * only tell was an "orphan sweep skipped -- manifest file and memory
 * disagree" line nobody had wired to an alarm.
 *
 * The fix returns -3 (distinct from -1 I/O and -2 WAL-tail-over-fill) on
 * every manifest-load failure: unreadable file, magic mismatch, short read,
 * or entry count over the caller's cap. utxo_live's UTX-2 check treats any
 * negative reload as fatal, so an over-cap store now refuses to boot with a
 * message naming the compaction remedy instead of silently going blind.
 *
 * This test pins BOTH directions:
 *   - a manifest over the caller's cap reloads -3 (was: silent zero);
 *   - the same store under a sufficient cap reloads fully (count intact).
 *
 * Usage: ./test_lsm_manifest_cap <tmpdir>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdint.h>

typedef uint8_t u8; typedef uint64_t u64;

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_reload(void* lst, void* u);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], unsigned index,
                         u64 value, unsigned long height, unsigned long is_coinbase,
                         const u8* script, unsigned long slen);
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

static int fails = 0, checks = 0;
static void ck(const char* w, long long got, long long want){
    checks++;
    if (got == want) printf("ok  : %-58s (%lld)\n", w, got);
    else { printf("FAIL: %-58s got %lld want %lld\n", w, got, want); fails++; }
}

#define NRUNS 300

static void* mmap_file(const char* path, u64 size){
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) { perror("open"); exit(1); }
    if (ftruncate(fd, (off_t)size) != 0) { perror("ftruncate"); exit(1); }
    void* p = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }
    return p;
}

int main(int argc, char** argv){
    if (argc < 2){ fprintf(stderr, "usage: %s <tmpdir>\n", argv[0]); return 2; }
    if (chdir(argv[1])){ perror("chdir"); return 1; }

    int slots_log2 = 16;             /* tiny memtable: one run per op */
    unsigned long slots = 1UL << slots_log2;
    u64 blob_cap = 64UL << 20;
    long ustruct = utxo_struct_size(slots);
    u64 tomb_cap = slots * 2;
    u64 desc_cap = slots * 3;
    u64 scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;

    void* u = mmap_file("cap_table.map", (u64)ustruct);
    void* blob = mmap_file("cap_blob.map", blob_cap);
    utxo_init(u, slots, blob, blob_cap);

    /* ---- phase 1: build NRUNS runs with a generous manifest cap -------- */
    {
        struct lsm_state lst; memset(&lst, 0, sizeof lst);
        lst.op_threshold = 1;        /* every op forces a flush -> one run each */
        lst.fill_threshold = 1;
        lst.tomb_buf = malloc(tomb_cap*36); lst.tomb_cap = tomb_cap;
        lst.manifest_buf = malloc(8192*16); lst.manifest_cap = 8192;
        lst.scratch_buf = malloc(scratch_cap); lst.scratch_cap = scratch_cap;

        long r = utxo_lsm_reload(&lst, u);
        ck("phase 1: fresh store reloads (replayed 0)", r, 0);

        u8 txid[32]; memset(txid, 0xAB, 32);
        for (int i = 0; i < NRUNS; i++){
            txid[0] = (u8)i;                         /* distinct keys */
            long p = utxo_lsm_put(&lst, u, txid, 0, 1000 + i, 100 + i, 0, 0, 0);
            if (p != 1){ ck("phase 1: put inserted", p, 1); break; }
        }
        ck("phase 1: manifest grew to NRUNS runs", (long)lst.manifest_n, NRUNS);
        ck("phase 1: live count", (long)lst.total_live, NRUNS);
        utxo_lsm_close(&lst);
    }

    /* ---- phase 2: reload with a cap BELOW the run count must FAIL ------- */
    {
        struct lsm_state lst; memset(&lst, 0, sizeof lst);
        lst.op_threshold = slots * 2;
        lst.fill_threshold = slots * 3 / 4;
        lst.tomb_buf = malloc(tomb_cap*36); lst.tomb_cap = tomb_cap;
        lst.manifest_buf = malloc(256*16); lst.manifest_cap = 256;   /* < NRUNS */
        lst.scratch_buf = malloc(scratch_cap); lst.scratch_cap = scratch_cap;

        long r = utxo_lsm_reload(&lst, u);
        ck("phase 2: over-cap manifest reload returns -3 (was: silent zero runs)", r, -3);
        ck("phase 2: no runs registered", (long)lst.manifest_n, 0);
    }

    /* ---- phase 3: the same store under a sufficient cap loads fully ----- */
    {
        struct lsm_state lst; memset(&lst, 0, sizeof lst);
        lst.op_threshold = slots * 2;
        lst.fill_threshold = slots * 3 / 4;
        lst.tomb_buf = malloc(tomb_cap*36); lst.tomb_cap = tomb_cap;
        lst.manifest_buf = malloc(8192*16); lst.manifest_cap = 8192;
        lst.scratch_buf = malloc(scratch_cap); lst.scratch_cap = scratch_cap;

        long r = utxo_lsm_reload(&lst, u);
        /* the WAL holds no unflushed ops (every put flushed), so the reload
         * trusts the persisted base instead of recounting: NRUNS live */
        ck("phase 3: sufficient cap reloads ok", r >= 0, 1);
        ck("phase 3: manifest_n intact", (long)lst.manifest_n, NRUNS);
        ck("phase 3: live count intact", (long)lst.total_live, NRUNS);
        utxo_lsm_close(&lst);
    }

    printf("\n%s (%d checks, %d failures)\n",
           fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
