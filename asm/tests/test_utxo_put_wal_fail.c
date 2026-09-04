/* test_utxo_put_wal_fail.c -- UTX-3 (audit 2026-09-03): utxo_lsm_put must
 * report a failed WAL drain as a NEGATIVE value, not 0xFFFFFFFF.
 *
 * THE BUG. utxo_store_put returns a 64-bit -1 when the 1 MB WAL buffer has to
 * drain mid-block and the write fails (ENOSPC, EIO, a bad fd). utxo_lsm_put
 * copied that status through a 32-bit register (`mov r14d, eax` / `mov eax,
 * r14d`), which ZERO-extends: callers received 4294967295. daemon/utxo_live.c
 * tested `r == -1 || r == 2`, so neither matched, `ctx->fatal` was never set,
 * and the block kept going with the created output written to NEITHER the
 * memtable NOR the WAL. The block-boundary drain then retries the earlier
 * buffered bytes; if the disk has recovered it succeeds and the applied-height
 * checkpoint lands, making the missing coin permanent. That is a silent
 * divergence from Core's chainstate -- precisely the failure this store is
 * built to make impossible. utxo_lsm_del had the same defect and was fixed;
 * utxo_lsm_put was the sibling left behind.
 *
 * THE INJECTION. After a clean utxo_lsm_init, the WAL descriptor in the state
 * is replaced with a READ-ONLY fd. Nothing else changes. Buffered puts then
 * succeed until the 1 MB write buffer fills; the drain that follows calls
 * write() on a read-only fd, gets EBADF, and utxo_store_put fails. This
 * reproduces the audit's scratchpad repro (which used the same read-only-fd
 * trick and saw the drain fail after 16,644 puts) without needing a full disk.
 *
 * WHAT IS ASSERTED, and why it is phrased this way:
 *   1. some put in the run reports failure at all -- the drain really did fail;
 *   2. every failing put reports r < 0 -- the SIGN is the contract. Asserting
 *      `r == -1` specifically would pass on the buggy build the day someone
 *      widened the return again, so the test checks what callers check;
 *   3. no put ever returns 4294967295 -- naming the exact bug value, so a
 *      regression is reported as itself rather than as a generic mismatch.
 *
 * Usage: ./test_utxo_put_wal_fail
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

typedef unsigned long long u64;
typedef unsigned char u8;

struct lsm_state { long log_fd, idx_fd; u64 log_len, ckpt_log_off, ckpt_n; u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen; void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap; u64 next_run_no; void* tomb_hash_buf; u64 tomb_hash_mask; };

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8* txid, unsigned index, u64 value,
                         unsigned long height, unsigned long cb, const u8* script, unsigned slen);
extern void utxo_lsm_close(void* lst);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("ok  : %s\n", l); else { printf("FAIL: %s\n", l); fails++; } }

static void make_txid(u8* t, unsigned i){
    for (int j = 0; j < 32; j++) t[j] = (u8)(0x40 + j);
    t[0] = (u8)i; t[1] = (u8)(i >> 8); t[2] = (u8)(i >> 16);
}

int main(void){
    char tmpl[] = "/tmp/utxputXXXXXX"; char* dir = mkdtemp(tmpl);
    if (!dir || chdir(dir) != 0){ printf("FAIL: tmpdir\n"); return 1; }

    enum { SLOTS = 262144, TOMBS = 8192 };
    void* blob = malloc(64u << 20);
    void* u = malloc(utxo_struct_size(SLOTS));
    utxo_init(u, SLOTS, blob, 64u << 20);

    struct lsm_state lst; memset(&lst, 0, sizeof lst);
    lst.op_threshold  = 100000000ULL;      /* never flush on op count  */
    lst.fill_threshold = SLOTS;            /* never flush on fill      */
    lst.tomb_buf = malloc(TOMBS * 36); lst.tomb_cap = TOMBS;
    lst.manifest_buf = malloc(512 * 16); lst.manifest_cap = 512;
    lst.scratch_cap = (u64)(SLOTS + TOMBS) * 128 + 8 * 1024 * 1024 + 65536;
    lst.scratch_buf = malloc(lst.scratch_cap);
    ck("lsm_init", utxo_lsm_init(&lst) == 1);

    /* ---- the injection: a read-only WAL descriptor ---------------------- */
    int ro = open("utxo.dat", O_RDONLY);
    if (ro < 0){ printf("FAIL: cannot reopen WAL read-only\n"); return 1; }
    close((int)lst.log_fd);
    lst.log_fd = ro;

    u8 script[40]; for (int j = 0; j < 40; j++) script[j] = (u8)(0x80 + j);

    long nfail = 0, nbadwidth = 0, nneg = 0;
    long first_fail = -1;
    /* 40,000 puts is comfortably past the ~16.6k the audit measured for the
     * first 1 MB drain, so the drain is reached even if record sizes shift. */
    for (unsigned i = 0; i < 40000; i++){
        u8 t[32]; make_txid(t, i);
        long r = utxo_lsm_put(&lst, u, t, i & 3, 1000ULL + i, 100 + i, 0, script, 20 + (i % 20));
        if (r == 1 || r == 0 || r == 2) continue;          /* ok / dup / table full */
        if (first_fail < 0) first_fail = (long)i;
        nfail++;
        if (r < 0) nneg++;
        if ((unsigned long long)r == 4294967295ULL) nbadwidth++;
    }

    printf("      drained-and-failed puts: %ld (first at index %ld)\n", nfail, first_fail);
    ck("the read-only WAL really does make a drain fail", nfail > 0);
    ck("UTX-3 every failing put reports a NEGATIVE status", nfail > 0 && nneg == nfail);
    ck("UTX-3 no put ever returns 4294967295 (the zero-extended -1)", nbadwidth == 0);

    utxo_lsm_close(&lst);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
