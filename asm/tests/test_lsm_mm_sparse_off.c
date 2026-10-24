/* test_lsm_mm_sparse_off.c -- ST2-8 (audit 2026-10-23): a run header's
 * sparse_off is validated against the file even when sparse_n is 0.
 *
 * THE BUG. utxo_lsm_mm.c parse_header bounds-checked the sparse index only
 * when sparse_n != 0, but lsm_run_lookup_mm ends its record scan at
 * rec_end = sparse_off whenever sparse_off is non-zero. A v2/v3 header with
 * sparse_n = 0 and a sparse_off past the end of the file therefore let the
 * scan run off the mapping: a lookup for a key above every record kept
 * stepping 37 bytes at a time through the page tail and on into whatever
 * lies beyond (SIGSEGV, or garbage parsed as records).
 *
 * The flush and the compaction always write sparse_off = the end of the
 * records (= the file length when there are no samples), so a valid run has
 * records_start <= sparse_off <= len; anything else is a corrupt header and
 * must take the asm fallback.
 *
 * WHAT IS ASSERTED (each lookup in a forked child, so a crash is a FAIL):
 *   control: a run with sparse_n = 0 and sparse_off = its length answers;
 *   sparse_off past the file end            -> LSM_MM_FALLBACK;
 *   sparse_off inside the header/bloom area -> LSM_MM_FALLBACK. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned long long u64;

#define LSM_MM_ABSENT    0
#define LSM_MM_TOMB      2
#define LSM_MM_FALLBACK (-2)
#define MAGIC_RUN3  0x33555255u

extern long lsm_run_lookup_mm(void *lst, u64 run_no, u64 gen, const u8 *txid, unsigned index,
                              u64 *out_value, u64 *out_height, u64 *out_is_coinbase,
                              const u8 **out_script, unsigned *out_slen);
extern void lsm_mm_invalidate_all(void);

static int fails = 0;
static void ck(const char* l, long g, long e){
    if (g == e) printf("ok  : %s (got %ld)\n", l, g);
    else { printf("FAIL: %s (got %ld exp %ld)\n", l, g, e); fails++; }
}

#define GEN 7
#define NREC 2
/* run file: URU3 header (44), no bloom, NREC tombstones with small keys */
static void write_run(unsigned run_no, u64 sparse_off){
    u8 buf[44 + NREC * 37]; memset(buf, 0, sizeof buf);
    uint32_t m = MAGIC_RUN3; memcpy(buf, &m, 4);
    u64 v = GEN;        memcpy(buf + 4, &v, 8);
    v = NREC;           memcpy(buf + 12, &v, 8);
    v = 0;              memcpy(buf + 20, &v, 8);      /* bloom_bits = 0: no filter */
    memcpy(buf + 28, &sparse_off, 8);
    v = 0;              memcpy(buf + 36, &v, 8);      /* sparse_n = 0 */
    for (int i = 0; i < NREC; i++){
        u8* r = buf + 44 + i * 37;
        r[0] = 0x01; r[1] = (u8)(i + 1);              /* keys 01 01 .. and 01 02 .. */
        r[36] = 2;                                     /* tombstone */
    }
    char nm[32]; snprintf(nm, sizeof nm, "utxo_run_%06u.dat", run_no);
    int fd = open(nm, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0 || write(fd, buf, sizeof buf) != (ssize_t)sizeof buf){ perror(nm); exit(2); }
    close(fd);
}

/* lookup in a child: returns the result, or 99 if the child died */
static long lookup(unsigned run_no, u8 first, u8 second){
    fflush(stdout);
    int pf[2]; if (pipe(pf)) return 98;
    pid_t p = fork();
    if (p == 0){
        close(pf[0]);
        u8 txid[32]; memset(txid, 0, 32); txid[0] = first; txid[1] = second;
        u64 val = 0, h = 0, cb = 0; const u8* sc = 0; unsigned sl = 0;
        long r = lsm_run_lookup_mm(0, run_no, GEN, txid, 0, &val, &h, &cb, &sc, &sl);
        if (write(pf[1], &r, sizeof r) != (ssize_t)sizeof r) _exit(3);
        _exit(0);
    }
    close(pf[1]);
    long r = 99; int st = 0;
    if (read(pf[0], &r, sizeof r) != (ssize_t)sizeof r) r = 99;
    close(pf[0]);
    waitpid(p, &st, 0);
    if (!WIFEXITED(st)){ printf("      (lookup child died, signal %d)\n", WIFSIGNALED(st) ? WTERMSIG(st) : 0); r = 99; }
    return r;
}

int main(void){
    tt_isolate();
    const u64 len = 44 + NREC * 37;

    write_run(1, len);
    ck("control: sparse_off = file length, a present key is found (tombstone)", lookup(1, 0x01, 0x02), LSM_MM_TOMB);
    ck("control: a key above every record is absent", lookup(1, 0xFF, 0xFF), LSM_MM_ABSENT);

    write_run(2, 1ULL << 40);
    ck("sparse_off past the end of the file falls back", lookup(2, 0xFF, 0xFF), LSM_MM_FALLBACK);

    write_run(3, 10);
    ck("sparse_off inside the header falls back", lookup(3, 0x01, 0x02), LSM_MM_FALLBACK);

    if (fails){ printf("\nTESTS FAILED (%d failures)\n", fails); return 1; }
    printf("\nALL TESTS PASSED (0 failures)\n");
    return 0;
}
