/* daemon/utxo_repair_del.c -- surgical repair for incident 2026-09-01: delete a
 * list of outpoints ("txid_display vout" per line) from the datadir's UTXO
 * store, offline (daemon stopped). Every key must be present (utxo_lsm_get
 * == 1) before anything is written; --apply performs the deletes and lands
 * the WAL (utxo_store_wal_drain). Without --apply it is a dry run. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
typedef struct { long log_fd, idx_fd; u64 log_len, ckpt_log_off, ckpt_n; u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen; void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap; u64 next_run_no; void* tomb_hash_buf; u64 tomb_hash_mask; } lsm_state_t;
extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_reload(void* lst, void* u);
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index, u64* value, unsigned long* height, unsigned long* coinbase, u8** script, unsigned long* slen);
extern long utxo_lsm_del(void* lst, void* u, const u8 txid[32], u32 index);
extern long utxo_lsm_count(void* lst);
extern long utxo_store_wal_drain(void* st);
extern void utxo_lsm_close(void* lst);
static u64 fsz(const char* p){ struct stat st; return stat(p, &st) == 0 ? (u64)st.st_size : 0; }
static void* xmap(u64 n){ void* m = mmap(0, n, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0); if (m == MAP_FAILED){ fprintf(stderr, "mmap failed\n"); exit(1); } return m; }
static int hexv(int c){ return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }
typedef struct { u8 txid[32]; u32 vout; } key_t_;
int main(int argc, char** argv){
    if (argc < 3){ fprintf(stderr, "usage: utxo_repair_del <datadir> <keys.txt> [--apply]\n"); return 2; }
    int apply = argc >= 4 && !strcmp(argv[3], "--apply");
    /* read keys first (before chdir) */
    FILE* kf = fopen(argv[2], "r"); if (!kf){ perror("keys"); return 2; }
    key_t_* keys = malloc(sizeof(key_t_) * 100000); long nk = 0; char line[256];
    while (fgets(line, sizeof line, kf)){
        if (strlen(line) < 66) continue;
        for (int i = 0; i < 32; i++){ int a = hexv(line[2*i]), b = hexv(line[2*i+1]); if (a < 0 || b < 0){ fprintf(stderr, "bad hex on line %ld\n", nk+1); return 2; }
            keys[nk].txid[31 - i] = (u8)(a * 16 + b); }           /* display order -> internal order */
        keys[nk].vout = (u32)strtoul(line + 65, 0, 10); nk++;
        if (nk >= 100000){ fprintf(stderr, "too many keys\n"); return 2; }
    }
    fclose(kf);
    if (chdir(argv[1]) != 0){ perror("chdir"); return 2; }
    u64 tsz = fsz("utxo_lsm_table.map");
    unsigned long slots = tsz > 48 ? (unsigned long)((tsz - 48) / 48) : (1UL << 16);
    u64 blob_cap = fsz("utxo_lsm_blob.map"); if (blob_cap < (64UL << 20)) blob_cap = 64UL << 20;
    fprintf(stderr, "[repair] datadir=%s keys=%ld slots=%lu blob=%luMB mode=%s\n", argv[1], nk, slots, (unsigned long)(blob_cap >> 20), apply ? "APPLY" : "dry-run");
    void* u = xmap(utxo_struct_size(slots)); void* blob = xmap(blob_cap);
    utxo_init(u, slots, blob, blob_cap);
    lsm_state_t lst; memset(&lst, 0, sizeof lst);
    lst.op_threshold = (u64)slots * 2; lst.fill_threshold = (u64)slots * 3 / 4;
    lst.tomb_buf = xmap((u64)slots * 2 * 36); lst.tomb_cap = (u64)slots * 2;
    lst.manifest_buf = xmap(4096 * 16); lst.manifest_cap = 4096;
    lst.scratch_buf = xmap(1UL << 20); lst.scratch_cap = 1UL << 20;
    long rep = utxo_lsm_reload(&lst, u);
    if (rep < 0){ fprintf(stderr, "[repair] reload failed\n"); return 1; }
    long c0 = utxo_lsm_count(&lst);
    fprintf(stderr, "[repair] reload ok: wal replayed %ld, manifest_n=%lu, live=%ld\n", rep, (unsigned long)lst.manifest_n, c0);
    /* phase 1: every key must be present */
    u64 sum = 0; long miss = 0, err = 0;
    for (long i = 0; i < nk; i++){
        u64 v = 0; unsigned long h = 0, cb = 0, sl = 0; u8* sc = 0;
        long g = utxo_lsm_get(&lst, u, keys[i].txid, keys[i].vout, &v, &h, &cb, &sc, &sl);
        if (g == 1) sum += v; else if (g == 0) miss++; else err++;
    }
    fprintf(stderr, "[repair] phase1: present=%ld missing=%ld error=%ld sum=%llu sat (%.8f BTC)\n", nk - miss - err, miss, err, (unsigned long long)sum, (double)sum / 1e8);
    if (miss || err){ fprintf(stderr, "[repair] ABORT: not every key is present -- nothing written\n"); utxo_lsm_close(&lst); return 3; }
    if (!apply){ fprintf(stderr, "[repair] dry run complete -- nothing written\n"); utxo_lsm_close(&lst); return 0; }
    /* phase 2: delete */
    long done = 0;
    for (long i = 0; i < nk; i++){
        long d = utxo_lsm_del(&lst, u, keys[i].txid, keys[i].vout);
        if (d != 1){ fprintf(stderr, "[repair] del failed at key %ld (r=%ld) after %ld deletes -- WAL NOT drained, state on disk = whatever landed\n", i, d, done); return 4; }
        done++;
    }
    if (utxo_store_wal_drain(&lst) != 0){ fprintf(stderr, "[repair] WAL drain failed\n"); return 5; }
    long c1 = utxo_lsm_count(&lst);
    fprintf(stderr, "[repair] phase2: deleted=%ld live %ld -> %ld (delta %ld), WAL drained\n", done, c0, c1, c1 - c0);
    /* phase 3: verify every key is now gone */
    long still = 0;
    for (long i = 0; i < nk; i++){
        u64 v = 0; unsigned long h = 0, cb = 0, sl = 0; u8* sc = 0;
        if (utxo_lsm_get(&lst, u, keys[i].txid, keys[i].vout, &v, &h, &cb, &sc, &sl) == 1) still++;
    }
    fprintf(stderr, "[repair] phase3: still present=%ld\n", still);
    utxo_lsm_close(&lst);
    return still ? 6 : 0;
}
