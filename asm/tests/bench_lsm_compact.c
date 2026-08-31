/* bench_lsm_compact <N> -- time N puts through the REAL steady-state LSM
 * (2^16 memtable, flush every 2*slots ops, compact at 12 runs), so the cost
 * of flush+compaction over a growing set can be A/B'd between two builds of
 * bitcoin_utxo_lsm.o. Not a test: prints timings and the resulting run count.
 * Run in a throwaway dir (writes utxo.dat, runs, manifest in cwd). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
typedef uint8_t u8; typedef uint32_t u32;
extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long long blob_cap);
extern int  utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index, unsigned long long value,
                         unsigned long long height, unsigned long long is_cb, const u8* script, unsigned long slen);
extern long utxo_lsm_compact(void* lst);
extern void utxo_lsm_close(void* lst);
struct lsm_state {
    long log_fd, idx_fd; unsigned long long log_len, ckpt_log_off, ckpt_n;
    unsigned long long op_count, op_threshold, fill_threshold;
    void* tomb_buf; unsigned long long tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; unsigned long long manifest_cap, manifest_n;
    void* scratch_buf; unsigned long long scratch_cap; unsigned long long next_run_no;
    void* tomb_hash_buf; unsigned long long tomb_hash_mask;
};
#define BLOOM_MAX_BYTES (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536
static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }
int main(int argc, char** argv){
    long N = argc > 1 ? atol(argv[1]) : 2000000;
    unsigned long slots = 1UL<<16;
    void* table = malloc((size_t)utxo_struct_size(slots)); void* blob = malloc(64UL<<20);
    utxo_init(table, slots, blob, 64UL<<20);
    struct lsm_state lst; memset(&lst,0,sizeof lst);
    unsigned long long op_th = slots*2, tomb_cap = op_th, desc_cap = slots*3;
    lst.op_threshold = op_th; lst.fill_threshold = slots*3/4;
    lst.tomb_buf = malloc(tomb_cap*36); lst.tomb_cap = tomb_cap;
    lst.manifest_buf = malloc(256*16); lst.manifest_cap = 256;
    lst.scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES; lst.scratch_buf = malloc(lst.scratch_cap);
    if (utxo_lsm_init(&lst) != 1){ fprintf(stderr,"lsm init failed\n"); return 1; }
    u8 spk[34]; memset(spk, 0x51, sizeof spk); spk[1]=0x20;   /* P2TR-shaped, 34 bytes */
    double t0 = now(), tc = 0; long compactions = 0;
    for (long i = 0; i < N; i++){
        u8 txid[32]; memset(txid,0,32); memcpy(txid,&i,sizeof i); txid[31]=0x77;
        if (utxo_lsm_put(&lst, table, txid, (u32)(i&3), 1000+i, 100+(i%50), 0, spk, 34) != 1){ fprintf(stderr,"put %ld failed\n", i); return 1; }
        if (lst.manifest_n >= 12){ double c0=now(); utxo_lsm_compact(&lst); tc += now()-c0; compactions++; }
    }
    double c0=now(); while (lst.manifest_n > 1) { if (utxo_lsm_compact(&lst) <= 0) break; compactions++; } tc += now()-c0;
    double total = now()-t0;
    printf("N=%ld  total=%.1fs  compaction=%.1fs (%ld passes)  puts+flush=%.1fs  runs_left=%llu\n",
           N, total, tc, compactions, total-tc, (unsigned long long)lst.manifest_n);
    utxo_lsm_close(&lst);
    return 0;
}
