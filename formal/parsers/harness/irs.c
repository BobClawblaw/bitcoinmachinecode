/* P-IRS: irs_open_run (daemon/index_runs.c), which maps one txindex /
 * txospender run file and validates its 48-byte header before the lookups in
 * rpc_chain.c (txi_lookup_locked, tsp_*) binary-search it. A run file of
 * nondeterministic content and size (any size: nothing loops over it).
 * Environment (stubs; trusted): open/fstat/close; mmap returns a mapping of
 * exactly st_size bytes; munmap checks it unmaps that mapping.
 * The formats are the two the node registers: (rec, sparse) = (20, 16)
 * txindex and (28, 24) txospender.
 * Claims:
 *   - memory safety of irs_open_run, no leaked mapping on refusal,
 *   - X-IRS-wrap (FP_CORE_STRICT): an accepted run's record array
 *     [48, 48 + n*rec) and sparse table [so, so + ns*sparse) lie inside the
 *     mapping, computed in exact (unbounded) arithmetic -- the guarantee the
 *     readers rely on when they index records by n and samples by nsparse. */
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "nd.h"
static size_t g_sz; static void* g_map; static int g_maps;
int open(const char* p, int fl, ...){ (void)p; (void)fl; return nondet_int() ? -1 : 7; }
int close(int fd){ (void)fd; return 0; }
int fstat(int fd, struct stat* sb){ (void)fd; if (nondet_int()) return -1; memset(sb, 0, sizeof *sb); sb->st_size = (off_t)g_sz; sb->st_ino = 42; return 0; }
void* mmap(void* a, size_t len, int prot, int fl, int fd, off_t off){ (void)a; (void)prot; (void)fl; (void)fd; (void)off;
    CHECK(len == g_sz, "maps the whole file"); if (nondet_int()) return MAP_FAILED; g_map = malloc(len); ASSUME(g_map != 0); g_maps++; return g_map; }
int munmap(void* a, size_t len){ CHECK(a == g_map && len == g_sz, "munmap of the mapping"); free(a); g_maps--; return 0; }
#include SRC
int main(void){
    g_sz = nondet_size(); ASSUME(g_sz <= ((size_t)1 << 40));
    irunset_t* s = malloc(sizeof *s); ASSUME(s != 0);
    if (nondet_int()) irs_init(s, "txindex", "BMCTXIDX", 20, 16); else irs_init(s, "txospender", "BMCTXOSP", 28, 24);
    irun_t r; memset(&r, 0, sizeof r); strcpy(r.path, "txindex.dat");
    int ok = irs_open_run(s, &r);
    if (!ok) CHECK(g_maps == 0, "no mapping kept on refusal");
    if (ok){
        CHECK(r.map == g_map && r.len == g_sz, "the run is the mapping");
#ifdef FP_CORE_STRICT
        /* exact arithmetic: 128-bit products cannot wrap for 64-bit factors <= 28 */
        unsigned __int128 rec_end = (unsigned __int128)48 + (unsigned __int128)r.n * (unsigned)s->rec;
        unsigned __int128 sp_end  = (unsigned __int128)r.sparse_off + (unsigned __int128)r.nsparse * (unsigned)s->sparse;
        CHECK(rec_end <= g_sz, "CORE: record array inside the mapping");
        CHECK(sp_end  <= g_sz, "CORE: sparse table inside the mapping");
#endif
        irs_close_run(&r);
    }
    CHECK(g_maps == 0, "mapping released");
    free(s);
    COVER(ok && r.n == 2, "a two-record run accepted");
    COVER(!ok && g_sz >= 48, "a torn run refused");
    return 0;
}
