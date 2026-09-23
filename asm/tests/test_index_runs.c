/* test_index_runs.c -- the run set (daemon/index_runs.h) and the merger
 * (daemon/merge_index_runs.c), on hand-written run files in the txid
 * index's format: discovery of the legacy base plus run files, height
 * order, a torn file refused, a vanished file unmapped, and a merge whose
 * output is byte-for-byte what one build over the union range would have
 * written -- then the inputs are gone and the set sees one run. */
#include "../daemon/index_runs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "test_tmpdir.h"

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }

/* a txindex-format run: 20-byte records (prefix[8] | height | offset | len),
 * sorted by (prefix, height, offset); sparse every 256th (prefix[8] | u64 off) */
typedef struct { unsigned char prefix[8]; unsigned height, offset, len; } rec_t;
static int rec_cmp(const void* a, const void* b){
    const rec_t* x = a; const rec_t* y = b; int c = memcmp(x->prefix, y->prefix, 8); if (c) return c;
    if (x->height != y->height) return x->height < y->height ? -1 : 1;
    return x->offset < y->offset ? -1 : x->offset > y->offset ? 1 : 0;
}
static void put32(unsigned char* p, unsigned v){ for (int i = 0; i < 4; i++) p[i] = (unsigned char)(v >> (8*i)); }
static void put64(unsigned char* p, unsigned long long v){ for (int i = 0; i < 8; i++) p[i] = (unsigned char)(v >> (8*i)); }
static void write_run(const char* path, rec_t* r, long n, long from, long to, int torn){
    qsort(r, (size_t)n, sizeof *r, rec_cmp);
    FILE* f = fopen(path, "wb");
    unsigned char hdr[48] = {0}; fwrite(hdr, 1, 48, f);
    long nsparse = 0; unsigned char* sp = malloc((size_t)(n / 256 + 2) * 16);
    for (long i = 0; i < n; i++){
        if (i % 256 == 0){ memcpy(sp + nsparse * 16, r[i].prefix, 8); put64(sp + nsparse * 16 + 8, 48ULL + (unsigned long long)i * 20); nsparse++; }
        unsigned char rec[20]; memcpy(rec, r[i].prefix, 8); put32(rec + 8, r[i].height); put32(rec + 12, r[i].offset); put32(rec + 16, r[i].len);
        fwrite(rec, 1, 20, f);
    }
    fwrite(sp, 16, (size_t)nsparse, f); free(sp);
    memcpy(hdr, "BMCTXIDX", 8); put64(hdr + 8, (unsigned long long)(torn ? n + 1000 : n));
    put64(hdr + 16, 48ULL + (unsigned long long)n * 20); put64(hdr + 24, (unsigned long long)nsparse);
    put32(hdr + 32, (unsigned)from); put32(hdr + 36, (unsigned)to);
    fseek(f, 0, SEEK_SET); fwrite(hdr, 1, 48, f); fclose(f);
}
/* deterministic records for a height range: 3 per height, prefixes spread */
static long gen(rec_t* out, long from, long to){
    long n = 0;
    for (long h = from; h <= to; h++) for (int k = 0; k < 3; k++){
        rec_t r; unsigned long long x = (unsigned long long)h * 2654435761ULL + (unsigned long long)k * 40503ULL;
        for (int i = 0; i < 8; i++) r.prefix[i] = (unsigned char)(x >> (8*(7-i)) ^ (unsigned char)(h >> (i*3)));
        r.height = (unsigned)h; r.offset = (unsigned)(81 + k * 300); r.len = 250; out[n++] = r;
    }
    return n;
}

int main(void){
    tt_isolate();
    irunset_t s; irs_init(&s, "txindex", "BMCTXIDX", 20, 16);
    ck("no files: empty set, covered -1", irs_refresh(&s) == 0 && s.n == 0 && irs_covered_to(&s) == -1);

    static rec_t a[4096], b[4096], c[4096], all[12288];
    long na = gen(a, 0, 999), nb = gen(b, 1000, 1999), nc = gen(c, 2000, 2499);
    write_run("txindex.dat", a, na, 0, 999, 0);                     /* the legacy base */
    char n1[300], n2[300]; irs_run_name("txindex", 1000, 1999, n1, sizeof n1); irs_run_name("txindex", 2000, 2499, n2, sizeof n2);
    ck("run names are zero-padded so a listing sorts by height", !strcmp(n1, "txindex.r000001000-000001999.dat"));
    write_run(n2, c, nc, 2000, 2499, 0);
    write_run(n1, b, nb, 1000, 1999, 0);
    write_run("txindex.r000003000-000003999.dat", a, 10, 3000, 3999, 1);   /* torn: header claims more than the file holds */
    FILE* junk = fopen("txindex.r000004000-000004999.dat.tmp", "wb"); fputs("x", junk); fclose(junk);
    irs_dirty(&s);
    int ch = irs_refresh(&s);
    ck("refresh finds the base and the two runs, not the torn file, not the .tmp", ch == 1 && s.n == 3);
    ck("...sorted by height", s.n == 3 && s.r[0].from == 0 && s.r[1].from == 1000 && s.r[2].from == 2000);
    ck("...with their record counts", s.n == 3 && (long)s.r[0].n == na && (long)s.r[1].n == nb && (long)s.r[2].n == nc);
    ck("covered_to is the highest run", irs_covered_to(&s) == 2499 && irs_covered_from(&s) == 0);
    ck("a second refresh within the second is a no-op", irs_refresh(&s) == 0 && s.n == 3);

    /* one run vanishes: the set drops it on the next (dirtied) refresh */
    unlink(n2); irs_dirty(&s);
    ck("a vanished run is dropped", irs_refresh(&s) == 1 && s.n == 2 && irs_covered_to(&s) == 1999);
    write_run(n2, c, nc, 2000, 2499, 0); irs_dirty(&s); irs_refresh(&s);
    ck("...and found again when it is back", s.n == 3);

    /* the merger: one file, the union range, every record, builder order */
    unlink("txindex.r000003000-000003999.dat");
    irs_close_all(&s);
    pid_t p = fork();
    if (p == 0){ execl(tt_src("daemon/bmc_merge_index_runs"), "bmc_merge_index_runs", ".", "txindex", (char*)0); _exit(127); }
    int st = 0; waitpid(p, &st, 0);
    ck("merger exits 0", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    struct stat sb;
    ck("inputs are gone after the merge", stat("txindex.dat", &sb) != 0 && stat(n1, &sb) != 0 && stat(n2, &sb) != 0);
    irs_dirty(&s); irs_refresh(&s);
    ck("the set sees exactly one run covering [0,2499]", s.n == 1 && s.r[0].from == 0 && s.r[0].to == 2499);
    ck("...with every record", s.n == 1 && (long)s.r[0].n == na + nb + nc);
    /* byte-identical to a single build over the union: write one and compare */
    long nall = 0; memcpy(all, a, (size_t)na * sizeof *a); nall += na; memcpy(all + nall, b, (size_t)nb * sizeof *b); nall += nb; memcpy(all + nall, c, (size_t)nc * sizeof *c); nall += nc;
    write_run("expected.dat", all, nall, 0, 2499, 0);
    FILE* f1 = fopen("expected.dat", "rb"); FILE* f2 = fopen(s.n ? s.r[0].path : "none", "rb");
    int same = f1 && f2; long bytes = 0;
    while (same){ int x = fgetc(f1), y = fgetc(f2); if (x != y) same = 0; if (x == EOF) break; bytes++; }
    if (f1) fclose(f1);
    if (f2) fclose(f2);
    ck("the merged run is byte-identical to one build over the union range", same && bytes > 48);

    /* a second merge with one run is a no-op that exits 0 */
    irs_close_all(&s);
    p = fork(); if (p == 0){ execl(tt_src("daemon/bmc_merge_index_runs"), "bmc_merge_index_runs", ".", "txindex", (char*)0); _exit(127); }
    waitpid(p, &st, 0);
    ck("merging a single run is a no-op, exit 0", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    irs_dirty(&s); irs_refresh(&s);
    ck("...and the run is still there", s.n == 1 && (long)s.r[0].n == nall);

    printf(fails ? "\nFAILURES: %d\n" : "\nall good\n", fails);
    return fails ? 1 : 0;
}
