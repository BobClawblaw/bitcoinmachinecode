/* daemon/utxo_dump_keys.c -- one line per live coin in the datadir's UTXO
 * set: "txid_display vout value height spendable". Read-only (reload_ro),
 * usable against a running node between writes. 2026-09-01, written to diff
 * the set against Core's dumptxoutset (muhash mismatch hunt). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
typedef uint8_t u8; typedef uint64_t u64;
typedef struct { long log_fd, idx_fd; u64 log_len, ckpt_log_off, ckpt_n; u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen; void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap; u64 next_run_no; void* tomb_hash_buf; u64 tomb_hash_mask; } lsm_state_t;
extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_reload_ro(void* lst, void* u);
extern long utxo_lsm_walk(void* lst, void* u, void* cb, void* ctx);
static u64 fsz(const char* p){ struct stat st; return stat(p, &st) == 0 ? (u64)st.st_size : 0; }
static void* xmap(u64 n){ void* m = mmap(0, n, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0); if (m == MAP_FAILED){ fprintf(stderr, "mmap failed\n"); exit(1); } return m; }
static long g_n;
static void emit(void* ctx, const u8 key36[36], unsigned long value, unsigned long code, const u8* script, unsigned long slen){
    (void)ctx;
    static const char* H = "0123456789abcdef";
    char line[128]; int o = 0;
    for (int i = 31; i >= 0; i--){ line[o++] = H[key36[i] >> 4]; line[o++] = H[key36[i] & 15]; }
    unsigned vout = (unsigned)key36[32] | ((unsigned)key36[33] << 8) | ((unsigned)key36[34] << 16) | ((unsigned)key36[35] << 24);
    int spendable = !(slen == 0 || (slen > 0 && script[0] == 0x6a) || slen > 10000);
    o += snprintf(line + o, sizeof line - o, " %u %lu %lu %d\n", vout, value, code >> 1, spendable);
    fwrite(line, 1, (size_t)o, stdout);
    if (++g_n % 20000000 == 0) fprintf(stderr, "[dump_keys] %ldM coins\n", g_n / 1000000);
}
int main(int argc, char** argv){
    if (argc < 2){ fprintf(stderr, "usage: utxo_dump_keys <datadir>\n"); return 2; }
    if (chdir(argv[1])){ perror("chdir"); return 1; }
    u64 tsz = fsz("utxo_lsm_table.map");
    unsigned long slots = tsz > 48 ? (unsigned long)((tsz - 48) / 48) : (1UL << 22);
    if (slots < (1UL << 20)) slots = 1UL << 20;
    u64 blob_cap = fsz("utxo_lsm_blob.map"); if (blob_cap < (256UL << 20)) blob_cap = 256UL << 20;
    void* u = xmap(utxo_struct_size(slots)); void* blob = xmap(blob_cap);
    utxo_init(u, slots, blob, blob_cap);
    lsm_state_t lst; memset(&lst, 0, sizeof lst);
    lst.op_threshold = (u64)slots * 2; lst.fill_threshold = (u64)slots * 3 / 4;
    lst.tomb_buf = xmap((u64)slots * 2 * 36); lst.tomb_cap = (u64)slots * 2;
    lst.manifest_buf = xmap(4096 * 16); lst.manifest_cap = 4096;
    lst.scratch_buf = xmap(1UL << 20); lst.scratch_cap = 1UL << 20;
    long rep = utxo_lsm_reload_ro(&lst, u);
    if (rep < 0){ fprintf(stderr, "reload_ro failed\n"); return 1; }
    long n = utxo_lsm_walk(&lst, u, (void*)emit, NULL);
    fprintf(stderr, "[dump_keys] done: %ld coins walked (wal replayed %ld)\n", n, rep);
    return n < 0 ? 1 : 0;
}
