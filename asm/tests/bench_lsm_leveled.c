/* tests/bench_lsm_leveled.c -- A/B of the compaction POLICY (not a test).
 * Same workload twice in fresh directories: N puts through a 2^14-slot
 * memtable (a flush every ~12k ops), compacting whenever manifest_n >= 12.
 *   A: classic  -- utxo_lsm_compact: the oldest min(n,64) runs -> the base is
 *                  rewritten on every compaction.
 *   B: leveled  -- lsm_compact_pick + utxo_lsm_compact_range.
 * Reports compaction passes, bytes WRITTEN by compaction (sum of output run
 * sizes -- the write amplification), compaction wall time, and the number of
 * runs a lookup has to consult at the end. Usage: bench_lsm_leveled [N]. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"
#include "lsm_state.h"
#include "lsm_manifest.h"
typedef uint8_t u8; typedef uint32_t u32;
extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long long blob_cap);
extern int  utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index, unsigned long long value,
                         unsigned long long height, unsigned long long is_cb, const u8* script, unsigned long slen);
extern long utxo_lsm_compact(void* lst);
extern long utxo_lsm_compact_range(void* lst, unsigned long lo, unsigned long k);
extern void utxo_lsm_close(void* lst);
#define BLOOM_MAX_BYTES (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536
static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }
static uint64_t run_of(struct lsm_state* l, uint64_t i){ uint64_t r; memcpy(&r,(char*)l->manifest_buf+i*16+8,8); return r; }
static uint64_t fsize(uint64_t run_no){ char n[64]; snprintf(n,sizeof n,"utxo_run_%06u.dat",(unsigned)run_no); struct stat sb; return stat(n,&sb)==0?(uint64_t)sb.st_size:0; }
static void run(const char* label, int leveled, long N){
    mkdir(label, 0755); if (chdir(label) != 0){ perror("chdir"); exit(1); }
    unsigned long slots = 1UL<<14;
    void* table = malloc((size_t)utxo_struct_size(slots)); void* blob = malloc(64UL<<20);
    utxo_init(table, slots, blob, 64UL<<20);
    struct lsm_state lst; memset(&lst,0,sizeof lst);
    unsigned long long op_th = slots*2, tomb_cap = op_th, desc_cap = slots*3;
    lst.op_threshold = op_th; lst.fill_threshold = slots*3/4;
    lst.tomb_buf = malloc(tomb_cap*36); lst.tomb_cap = tomb_cap;
    lst.manifest_buf = malloc(256*16); lst.manifest_cap = 256;
    lst.scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES; lst.scratch_buf = malloc(lst.scratch_cap);
    if (utxo_lsm_init(&lst) != 1){ fprintf(stderr,"lsm init failed\n"); exit(1); }
    u8 spk[34]; memset(spk,0x51,34); spk[1]=0x20;
    double t0 = now(), tc = 0; long passes = 0; uint64_t written = 0, max_n = 0;
    for (long i = 0; i < N; i++){
        u8 txid[32]; memset(txid,0,32); memcpy(txid,&i,sizeof i); txid[31]=0x55;
        if (utxo_lsm_put(&lst, table, txid, (u32)(i&3), 1000+i, 100+(i%50), 0, spk, 34) != 1){ fprintf(stderr,"put failed\n"); exit(1); }
        if (lst.manifest_n > max_n) max_n = lst.manifest_n;
        if (lst.manifest_n >= 12){
            long lo = 0, k;
            if (leveled){ uint64_t sizes[256]; long n = (long)lst.manifest_n; for (long j = 0; j < n; j++) sizes[j] = fsize(run_of(&lst,(uint64_t)j)); k = lsm_compact_pick(sizes, n, 12, 64, &lo); if (!k) continue; }
            double c0 = now(); long cr = leveled ? utxo_lsm_compact_range(&lst, (unsigned long)lo, (unsigned long)k) : utxo_lsm_compact(&lst); tc += now() - c0;
            if (cr > 0){ passes++; written += fsize(run_of(&lst,(uint64_t)lo)); }
        }
    }
    double total = now() - t0;
    uint64_t on_disk = 0; for (uint64_t j = 0; j < lst.manifest_n; j++) on_disk += fsize(run_of(&lst,j));
    printf("%-8s N=%ld  compactions=%ld  bytes written by compaction=%.1f MB (%.1fx the %.1f MB live set)  compaction time=%.2fs of %.2fs total  runs at end=%llu (max %llu)\n",
           label, N, passes, written/1048576.0, on_disk ? (double)written/on_disk : 0.0, on_disk/1048576.0, tc, total, (unsigned long long)lst.manifest_n, (unsigned long long)max_n);
    utxo_lsm_close(&lst);
    if (chdir("..") != 0) exit(1);
}
int main(int argc, char** argv){
    long N = argc > 1 ? atol(argv[1]) : 1500000;
    tt_isolate();
    run("classic", 0, N);
    run("leveled", 1, N);
    return 0;
}
