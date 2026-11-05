/* confirm X-IRS-wrap on the compiled index_runs.c: a txindex run whose header
 * claims nsparse = 2^60 (16 * 2^60 wraps to 0 in the bound check) is accepted
 * by irs_open_run, so a reader binary-searching nsparse samples
 * (rpc_chain.c txi_lookup_locked: sp + mid*16, mid ~ 2^59) reads 2^63 bytes
 * past the mapping. Written to a scratch directory given as argv[1]. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "index_runs.h"
static void w64(unsigned char* p, unsigned long long v){ for (int i = 0; i < 8; i++) p[i] = (unsigned char)(v >> (8*i)); }
int main(int argc, char** argv){
    if (argc < 2 || chdir(argv[1]) != 0) return 2;
    unsigned char h[48 + 20]; memset(h, 0, sizeof h);
    memcpy(h, "BMCTXIDX", 8); w64(h + 8, 1); w64(h + 16, 48 + 20); w64(h + 24, 1ULL << 60);
    FILE* f = fopen("txindex.r000000000-000000010.dat", "wb"); fwrite(h, 1, sizeof h, f); fclose(f);
    irunset_t s; irs_init(&s, "txindex", "BMCTXIDX", 20, 16);
    irun_t r; memset(&r, 0, sizeof r); strcpy(r.path, "txindex.r000000000-000000010.dat");
    int ok = irs_open_run(&s, &r);
    printf("irs_open_run = %d: file %zu bytes, n=%llu sparse_off=%llu nsparse=%llu (sparse table claims %s bytes)\n",
           ok, r.len, r.n, r.sparse_off, r.nsparse, ok ? "2^64+" : "-");
    printf("%s\n", ok && r.nsparse == (1ULL << 60) ? "CONFIRMED: accepted a sparse table 2^60 entries long in a 68-byte file" : "not reproduced");
    if (ok) irs_close_run(&r);
    unlink("txindex.r000000000-000000010.dat");
    return ok ? 0 : 1;
}
