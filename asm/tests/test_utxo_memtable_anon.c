/* tests/test_utxo_memtable_anon.c -- plan B11 (2026-10-07): the live UTXO
 * memtable's table and blob are ANONYMOUS memory (huge-page eligible, never
 * written back), the files are kept at their sizes, and the table's first
 * page is the file's first page -- so the writer's live count, the first
 * qword of the table, is still what tx_accept.c reads from the file to
 * cross-check its tx-validation snapshot, and the tools still derive the
 * slot count and the blob cap from the file sizes.
 *
 * Pinned, with bmc.memtableanon=1 (the default):
 *   - utxo_live_init creates utxo_lsm_table.map at utxo_struct_size(slots)
 *     bytes and utxo_lsm_blob.map at the blob cap (the sizes the tools read);
 *   - a put through the raw memtable bumps the count, and the FILE's first
 *     qword shows it (the header page is shared);
 *   - /proc/self/maps shows the table's first page as a mapping of the file
 *     at offset 0 and the rest as anonymous memory named
 *     "utxo-memtable-table"; the blob as "utxo-memtable-blob".
 * And with bmc.memtableanon=0 the old shape: the whole table is a file
 * mapping and the count shows in the file as before.
 *
 * Watched to FAIL with the header-page mapping removed (anonymous table
 * without the MAP_FIXED file page): the file's first qword stays 0 after
 * the put. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"
#include "../daemon/node_config.h"

typedef unsigned char u8;
typedef unsigned long long u64;

extern long store_init(void* st);
extern int  utxo_live_init(const char* dir);
extern void utxo_live_close(void);
extern void* utxo_live_test_table(void);
extern void utxo_live_test_force_sizing(int);
extern long utxo_count(void* u);
extern long utxo_struct_size(unsigned long slots);
extern long utxo_put(void* u, const u8 txid[32], unsigned long index, u64 value,
                     unsigned long height, unsigned long is_coinbase, const u8* script, unsigned long slen);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u;(void)txid;(void)index;(void)value;(void)script;(void)slen;
    fprintf(stderr, "test_utxo_memtable_anon: unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
static void ckm(const char* l, int cond){
    if (cond) printf("PASS %s\n", l); else { printf("FAIL %s\n", l); failures++; }
}
static long fsize(const char* p){ struct stat st; return stat(p, &st) == 0 ? (long)st.st_size : -1; }
static u64 file_first_qword(const char* p){
    int fd = open(p, O_RDONLY); if (fd < 0) return (u64)-1;
    u64 v = 0; if (read(fd, &v, 8) != 8) v = (u64)-2; close(fd); return v;
}
/* the /proc/self/maps line that starts at address a: its path/name column (or "") */
static int maps_line_at(void* a, char* out, size_t cap){
    FILE* f = fopen("/proc/self/maps", "r"); if (!f) return 0;
    char line[512]; int found = 0;
    while (fgets(line, sizeof line, f)){
        unsigned long lo = 0, hi = 0; if (sscanf(line, "%lx-%lx", &lo, &hi) != 2) continue;
        if (lo == (unsigned long)a){ snprintf(out, cap, "%s", line); found = 1; break; }
    }
    fclose(f); return found;
}
static u8 store_buf[4096];

static void one_round(int anon){
    char sub[32]; snprintf(sub, sizeof sub, "anon%d", anon);
    tt_subdir(sub);
    g_cfg.memtable_anon = anon;
    memset(store_buf, 0, sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);
    void* u = utxo_live_test_table();
    ckm("the table pointer", u != NULL);
    unsigned long slots = ((unsigned long*)u)[1] + 1;          /* +8: mask = slots-1 */
    u64 blob_cap = ((u64*)u)[3];                                 /* +24 */
    printf("     memtableanon=%d slots=%lu blob_cap=%llu MB\n", anon, slots, blob_cap >> 20);
    ck("utxo_lsm_table.map is kept at utxo_struct_size(slots)", fsize("utxo_lsm_table.map"), utxo_struct_size(slots));
    ck("utxo_lsm_blob.map is kept at the blob cap", fsize("utxo_lsm_blob.map"), (long)blob_cap);
    ck("count 0 after init", utxo_count(u), 0);
    ck("the file's first qword is 0 after init", (long)file_first_qword("utxo_lsm_table.map"), 0);
    u8 txid[32]; memset(txid, 0x5a, sizeof txid); u8 spk[25]; memset(spk, 0x76, sizeof spk);
    ck("a raw put lands", utxo_put(u, txid, 0, 5000ULL, 100, 0, spk, sizeof spk), 1);
    ck("count 1 after the put", utxo_count(u), 1);
    ck("the FILE's first qword shows the count (the header page is shared)", (long)file_first_qword("utxo_lsm_table.map"), 1);
    char line[512];
    if (maps_line_at(u, line, sizeof line)){
        printf("     maps: %s", line);
        ckm("the table's first page is a mapping of utxo_lsm_table.map", strstr(line, "utxo_lsm_table.map") != NULL);
        unsigned long lo = 0, hi = 0; sscanf(line, "%lx-%lx", &lo, &hi);
        if (anon) ck("...of exactly one page (the header page)", (long)(hi - lo), 4096);
        else      ck("...of the whole table (file mappings, as before)", (long)(hi - lo), (utxo_struct_size(slots) + 4095) & ~4095L);
    } else ckm("a maps line at the table address", 0);
    if (anon){
        if (maps_line_at((char*)u + 4096, line, sizeof line)){
            printf("     maps: %s", line);
            ckm("the rest of the table is anonymous memory named utxo-memtable-table", strstr(line, "[anon:utxo-memtable-table]") != NULL);
        } else ckm("a maps line at table+4096", 0);
        void* blob = (void*)(uintptr_t)((u64*)u)[2];             /* +16 */
        if (maps_line_at(blob, line, sizeof line)){
            printf("     maps: %s", line);
            ckm("the blob is anonymous memory named utxo-memtable-blob", strstr(line, "[anon:utxo-memtable-blob]") != NULL);
        } else ckm("a maps line at the blob address", 0);
    }
    utxo_live_close();
}

int main(void){
    tt_isolate();
    utxo_live_test_force_sizing(0);                               /* the small steady-state memtable: the shape is the same, the test is quick */
    printf("-- bmc.memtableanon=1 (the default): anonymous table and blob, the header page shared\n");
    one_round(1);
    printf("\n-- bmc.memtableanon=0: file mappings, as before\n");
    one_round(0);
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
