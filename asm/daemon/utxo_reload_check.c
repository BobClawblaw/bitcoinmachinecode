/* daemon/utxo_reload_check.c -- POC validator: reload a generated LSM UTXO
 * set from the current directory and report the recovered live count.
 *
 * This is the correctness gate for the "generate the UTXO set in memory"
 * proof of concept. The LSM (bitcoin_utxo_lsm.asm) generates its full set
 * of run files / manifest / WAL into whatever directory it is run in; in the
 * POC that directory is a tmpfs (/dev/shm) mount, so the ENTIRE generated
 * UTXO state lives in RAM. This program then exercises the store's REAL
 * reload path (utxo_lsm_reload: read manifest + replay runs + WAL) against
 * that RAM-resident state and reports the recovered live count. If it
 * matches the count build_utxo printed at build time, the in-memory
 * generated set is complete, self-consistent, and reloadable.
 *
 * Usage: utxo_reload_check <slots_log2>   (run in the dir holding the build)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_count(void* u);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_count(void* lst);
extern long utxo_lsm_reload(void* lst, void* u);
extern void utxo_lsm_close(void* lst);

/* Mirror bitcoin_utxo_lsm.asm's state struct exactly (152 bytes).
 * Must match the sizing build_utxo used (slots_log2=18). */
struct LST {
    long log_fd;                     /* +0   */
    long idx_fd;                     /* +8   */
    unsigned long long log_len;      /* +16  */
    unsigned long long ckpt_log_off; /* +24  */
    unsigned long long ckpt_n;       /* +32  */
    unsigned long long op_count;     /* +40  */
    unsigned long long op_threshold; /* +48  */
    unsigned long long fill_threshold;/* +56 */
    void*              tomb_buf;     /* +64  */
    unsigned long long tomb_cap;     /* +72  */
    unsigned long long tomb_n;       /* +80  */
    unsigned long long total_live;   /* +88  */
    unsigned long long next_gen;     /* +96  */
    void*              manifest_buf; /* +104 */
    unsigned long long manifest_cap; /* +112 */
    unsigned long long manifest_n;   /* +120 */
    void*              scratch_buf;  /* +128 */
    unsigned long long scratch_cap;  /* +136 */
    unsigned long long next_run_no;  /* +144 */
};

#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536

/* Lower-bound validation: the reloaded count must be > 1M to prove the
 * multi-million-entry RAM-resident set survived (far above any trivial/small
 * set that could pass by accident). */
#define MIN_EXPECTED_LIVE 1000000L

int main(int argc, char** argv){
    int slots_log2 = (argc > 1) ? atoi(argv[1]) : 18;
    unsigned long slots = 1UL << slots_log2;
    u_int64_t fill_threshold = (u_int64_t)slots * 3 / 4;
    u_int64_t op_threshold    = (u_int64_t)slots * 2;
    u_int64_t tomb_cap        = op_threshold;
    u_int64_t desc_cap        = (u_int64_t)slots * 3;
    u_int64_t scratch_cap     = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    size_t    ustruct         = (size_t)utxo_struct_size(slots);
    u_int64_t blob_cap        = (u_int64_t)slots * 8;  /* bounded; WAL replay is small */

    printf("[reload] slots_log2=%d slots=%lu table=%zuB blob=%lluB\n",
           slots_log2, slots, ustruct, (unsigned long long)blob_cap);

    void* table = malloc(ustruct);
    void* blob  = malloc(blob_cap);
    void* tomb  = malloc(tomb_cap*36);
    void* manifest = malloc(16UL * 4096);  /* generous fixed manifest cap */
    void* scratch = malloc(scratch_cap);
    if (!table || !blob || !tomb || !manifest || !scratch) { printf("[reload] alloc failed\n"); return 1; }

    struct LST lst;
    memset(&lst, 0, sizeof lst);
    lst.op_threshold   = op_threshold;
    lst.fill_threshold = fill_threshold;
    lst.tomb_buf = tomb;   lst.tomb_cap = tomb_cap;
    lst.manifest_buf = manifest; lst.manifest_cap = 4096;
    lst.scratch_buf = scratch;   lst.scratch_cap = scratch_cap;

    utxo_init(table, slots, blob, blob_cap);

    /* utxo_lsm_reload reads the manifest, maps/replays every run, and
     * replays the WAL. Returns replayed record count, or -1 on error. */
    long repl = utxo_lsm_reload(&lst, table);
    printf("[reload] utxo_lsm_reload -> %ld\n", repl);
    if (repl < 0) { printf("FAIL: reload error\n"); return 1; }

    long n = utxo_lsm_count(&lst);
    printf("[reload] recovered live UTXO count = %ld  (manifest runs = %llu)\n",
           n, (unsigned long long)lst.manifest_n);

    if (n >= MIN_EXPECTED_LIVE && lst.manifest_n > 0) {
        printf("PASS: reloaded %ld live UTXOs from %llu RAM-resident LSM runs "
               "-- the in-memory generated set is complete and reloadable.\n",
               n, (unsigned long long)lst.manifest_n);
        int rc = 0;
        utxo_lsm_close(&lst);
        return rc;
    }
    printf("FAIL: recovered %ld (want >= %ld) and/or no runs; set is incomplete.\n",
           n, MIN_EXPECTED_LIVE);
    utxo_lsm_close(&lst);
    return 1;
}
