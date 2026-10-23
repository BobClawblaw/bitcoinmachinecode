/* P-HDRTREE: the fork-tree loader and its users (daemon/hdr_tree.c
 * hdrtree_open, hdrtree_best, hdrtree_add) over headers_forks.dat of
 * nondeterministic content and size <= FP_FSZ (3 records), plus one header
 * from a peer (hdrtree_add's input).
 * Environment: the file (fileio.h, appends discarded); block_hash and
 * chainwork_cmp (asm) as free functions of readable inputs.
 * Claims: memory safety, no leak beyond the table the module owns (freed by
 * the harness), the table never exceeds HDRTREE_MAX entries, hdrtree_best
 * returns a stored entry. */
#include <stdlib.h>
#include <string.h>
#include "nd.h"
#include "fileio.h"
void block_hash(unsigned char out[32], const unsigned char hdr[80]){ CHECK(__CPROVER_r_ok(hdr, 80), "block_hash input"); for (int i = 0; i < 32; i++) out[i] = nondet_uchar(); }
long chainwork_cmp(const unsigned char a[16], const unsigned char b[16]){ CHECK(__CPROVER_r_ok(a, 16) && __CPROVER_r_ok(b, 16), "chainwork_cmp inputs"); long r = nondet_long(); ASSUME(r >= -1 && r <= 1); return r; }
size_t fwrite(const void* p, size_t sz, size_t n, FILE* f){ (void)f; CHECK(__CPROVER_r_ok(p, sz * n), "fwrite source readable"); return n; }
int fflush(FILE* f){ (void)f; return 0; }
int fsync(int fd){ (void)fd; return 0; }
int fileno(FILE* f){ (void)f; return 3; }
int rename(const char* a, const char* b){ (void)a; (void)b; return 0; }
int unlink(const char* a){ (void)a; return 0; }
#include SRC
int main(void){
    fio_init();
    (void)hdrtree_open();
    CHECK(hdrtree_count() >= 0 && hdrtree_count() <= HDRTREE_MAX, "table within HDRTREE_MAX");
    unsigned char h[32]; long ht; unsigned char w[16];
    int b = hdrtree_best(h, &ht, w);
    if (b){ CHECK(hdrtree_has(h), "best is a stored entry"); }
    unsigned char hdr[80], work[16]; for (int i = 0; i < 80; i++) hdr[i] = nondet_uchar();
    int a = hdrtree_add(hdr, nondet_long(), work);
    CHECK(a >= -1 && a <= 1, "add result");
    if (nondet_int()) (void)hdrtree_prune_below(nondet_long());
    COVER(hdrtree_count() == 3, "two loaded and one added");
    free(g_e); free(g_f);
    return 0;
}
