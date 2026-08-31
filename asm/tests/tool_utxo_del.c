/* tests/tool_utxo_del.c -- surgically DELETE one outpoint from a UTXO LSM
 * store (manual tool, not a test). Written for the 2026-08-31 signet repair:
 * the genesis coinbase had been applied (genesis_skip.h predated signet) and
 * had to leave the set. Appends an ordinary WAL tombstone, exactly what a
 * spend writes, so the daemon's next reload sees it; the coinstats index
 * file should be removed alongside so it re-seeds from the corrected walk.
 * Usage: tool_utxo_del <utxo-dir> <txid-display-hex> <vout>   (daemon STOPPED) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lsm_state.h"
typedef unsigned char u8; typedef unsigned int u32;
extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long long blob_cap);
extern int  utxo_lsm_init(void* lst);
extern long utxo_lsm_reload(void* lst, void* u);
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index, unsigned long long* v,
                         unsigned long* h, unsigned long* cb, const u8** s, unsigned long* sl);
extern long utxo_lsm_del(void* lst, void* u, const u8 txid[32], u32 index);
extern void utxo_lsm_close(void* lst);
#define BLOOM_MAX_BYTES (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536
int main(int argc, char** argv){
    if (argc != 4){ fprintf(stderr, "usage: %s <utxo-dir> <txid-hex> <vout>\n", argv[0]); return 2; }
    if (chdir(argv[1]) != 0){ perror("chdir"); return 2; }
    u8 txid[32];
    if (strlen(argv[2]) != 64){ fprintf(stderr, "txid must be 64 hex chars\n"); return 2; }
    for (int i = 0; i < 32; i++){ unsigned b; sscanf(argv[2] + i*2, "%2x", &b); txid[31-i] = (u8)b; }  /* display -> wire */
    u32 vout = (u32)atoi(argv[3]);
    unsigned long slots = 1UL<<16;
    void* table = malloc((size_t)utxo_struct_size(slots)); void* blob = malloc(64UL<<20);
    utxo_init(table, slots, blob, 64UL<<20);
    struct lsm_state lst; memset(&lst, 0, sizeof lst);
    unsigned long long op_th = slots*2, tomb_cap = op_th, desc_cap = slots*3;
    lst.op_threshold = op_th; lst.fill_threshold = slots*3/4;
    lst.tomb_buf = malloc(tomb_cap*36); lst.tomb_cap = tomb_cap;
    lst.manifest_buf = malloc(256*16); lst.manifest_cap = 256;
    lst.scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES; lst.scratch_buf = malloc(lst.scratch_cap);
    long r = utxo_lsm_reload(&lst, table);
    fprintf(stderr, "reload: %ld (WAL tail replayed), manifest_n=%llu total_live=%llu\n",
            r, (unsigned long long)lst.manifest_n, (unsigned long long)lst.total_live);
    if (r < 0) return 1;
    unsigned long long v; unsigned long h, cb, sl; const u8* sp;
    if (utxo_lsm_get(&lst, table, txid, vout, &v, &h, &cb, &sp, &sl) != 1){
        fprintf(stderr, "outpoint is NOT live in this store -- nothing to do\n"); return 1;
    }
    fprintf(stderr, "outpoint is live: value=%llu height=%lu coinbase=%lu -- deleting\n", v, h, cb);
    if (utxo_lsm_del(&lst, table, txid, vout) != 1){ fprintf(stderr, "del failed\n"); return 1; }
    if (utxo_lsm_get(&lst, table, txid, vout, &v, &h, &cb, &sp, &sl) == 1){ fprintf(stderr, "still live after del?!\n"); return 1; }
    utxo_lsm_close(&lst);
    fprintf(stderr, "deleted; total_live now %llu. Remove coinstats.dat so the index re-seeds.\n",
            (unsigned long long)lst.total_live);
    return 0;
}
