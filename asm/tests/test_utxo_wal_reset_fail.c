/* tests/test_utxo_wal_reset_fail.c -- UTX-8 (audit 2026-09-03): a WAL reset
 * that FAILS must fail the flush, not be ignored.
 *
 * THE BUG. utxo_lsm_flush ends at .fl_finish_reset, which truncates the WAL
 * to zero and seeks back to its start. Both syscall results were discarded
 * and `log_len = 0` was written regardless. On EIO the old generation stays
 * in utxo.dat while new records are appended from offset 0 over it; a later
 * reload replays the new records and then keeps going into whatever stale
 * bytes follow -- a misparse, or, at an aligned boundary, stale PUSHes
 * applied on top of newer DELs. The chainstate diverges from Core's, which is
 * exactly what this store exists to prevent.
 *
 * THE INJECTION. Same trick as tests/test_utxo_put_wal_fail.c (UTX-3): after
 * a clean init the WAL descriptor in the state is replaced, here with the
 * write end of a PIPE. A pipe accepts write() -- so nothing earlier in the
 * flush changes behaviour -- but ftruncate() on it returns EINVAL and lseek()
 * returns ESPIPE, which is precisely the pair this fix now checks.
 *
 * WHAT IS ASSERTED:
 *   1. the flush REPORTS failure (negative), rather than claiming success;
 *   2. log_len is NOT cleared -- the caller still holds the state it had, so
 *      it can retry or halt instead of writing over a live WAL. This is the
 *      assertion that actually distinguishes the fix: the old code returned
 *      1 AND zeroed log_len, and a test that only checked the return value
 *      would still pass if the clearing were left in.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "test_tmpdir.h"

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
extern long utxo_lsm_flush(void* lst, void* u);
extern void utxo_lsm_close(void* lst);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("ok  : %s\n", l); else { printf("FAIL: %s\n", l); fails++; } }

int main(void){
    tt_isolate();

    enum { SLOTS = 262144, TOMBS = 8192 };
    void* blob = malloc(64u << 20);
    void* u = malloc(utxo_struct_size(SLOTS));
    if (!blob || !u){ printf("FAIL: malloc\n"); return 1; }
    utxo_init(u, SLOTS, blob, 64u << 20);

    struct lsm_state lst; memset(&lst, 0, sizeof lst);
    lst.op_threshold   = 100000000ULL;     /* never flush on op count */
    lst.fill_threshold = SLOTS;            /* never flush on fill     */
    lst.tomb_buf = malloc(TOMBS * 36); lst.tomb_cap = TOMBS;
    lst.manifest_buf = malloc(512 * 16); lst.manifest_cap = 512;
    lst.scratch_cap = (u64)(SLOTS + TOMBS) * 128 + 8 * 1024 * 1024 + 65536;
    lst.scratch_buf = malloc(lst.scratch_cap);
    if (!lst.tomb_buf || !lst.manifest_buf || !lst.scratch_buf){ printf("FAIL: malloc\n"); return 1; }
    ck("lsm_init", utxo_lsm_init(&lst) == 1);

    /* a few hundred live records, so the flush has real work to do */
    u8 script[40]; for (int j = 0; j < 40; j++) script[j] = (u8)(0x80 + j);
    for (unsigned i = 0; i < 512; i++){
        u8 t[32]; for (int j = 0; j < 32; j++) t[j] = (u8)(0x40 + j);
        t[0] = (u8)i; t[1] = (u8)(i >> 8);
        long r = utxo_lsm_put(&lst, u, t, i & 3, 1000ULL + i, 100 + i, 0, script, 20 + (i % 20));
        if (r < 0){ printf("FAIL: put %u returned %ld\n", i, r); return 1; }
    }

    u64 log_len_before = lst.log_len;
    ck("the WAL actually has bytes in it before the flush", log_len_before > 0);

    /* ---- the injection: a pipe as the WAL descriptor -------------------
     * writable, so nothing earlier in the flush behaves differently, but
     * ftruncate() gives EINVAL and lseek() gives ESPIPE -- exactly the pair
     * .fl_finish_reset now checks. */
    int pf[2];
    if (pipe(pf)){ printf("FAIL: pipe\n"); return 1; }
    long saved_fd = lst.log_fd;
    lst.log_fd = pf[1];

    long r = utxo_lsm_flush(&lst, u);
    ck("a flush whose WAL reset fails REPORTS failure", r < 0);
    if (r >= 0) printf("      got %ld, expected a negative status\n", r);

    ck("and log_len is NOT cleared (the state survives for a retry)",
       lst.log_len == log_len_before);
    if (lst.log_len != log_len_before)
        printf("      log_len went %llu -> %llu\n",
               (unsigned long long)log_len_before, (unsigned long long)lst.log_len);

    lst.log_fd = saved_fd;
    close(pf[0]); close(pf[1]);
    utxo_lsm_close(&lst);

    if (fails){ printf("\nTESTS FAILED (%d failures)\n", fails); return 1; }
    printf("\nALL TESTS PASSED (0 failures)\n");
    return 0;
}
