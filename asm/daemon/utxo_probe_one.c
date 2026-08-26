/* daemon/utxo_probe_one.c -- diagnostic: resolve ONE outpoint against a
 * fresh read-only reload of a datadir's UTXO LSM, through BOTH read paths:
 *   1. utxo_lsm_get   (the point-lookup mempool validation uses)
 *   2. utxo_lsm_walk  (the full scan the muhash parity proof uses)
 * If the walk finds the coin and get() does not (or returns a different
 * script length), the point-lookup path is indicted; if neither finds it,
 * the set itself is. Written for incident #48's follow-up: mass mempool
 * rejects whose failing prevouts the oracle says are unspent.
 *
 * Usage: utxo_probe_one <datadir> <txid-display-hex> <vout>
 * (txid given in DISPLAY order, as RPC prints it; converted to wire here.)
 *
 * Read-only by the same discipline as utxo_setinfo (utxo_lsm_reload_ro);
 * run it in a quiet window -- it takes no quiescence fingerprint, so treat
 * a surprising result during heavy write activity with suspicion and rerun.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdint.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_reload_ro(void* lst, void* u);
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index, u64* value,
                         unsigned long* height, unsigned long* is_coinbase,
                         const u8** script, unsigned long* slen);
extern long utxo_lsm_walk(void* lst, void* u, void* cb, void* ctx);

typedef struct {
    u64 log_fd_, idx_fd_;
    u64 log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    u64 tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen;
    u64 manifest_buf; u64 manifest_cap, manifest_n;
    u64 scratch_buf; u64 scratch_cap;
    u64 next_run_no;
    u64 tomb_hash_buf; u64 tomb_hash_mask;
} lsm_state_t;

static u64 file_size_or(const char* p, u64 dflt){
    struct stat sb; return stat(p, &sb) == 0 ? (u64)sb.st_size : dflt;
}
static void* xmap(u64 len, const char* what){
    void* p = mmap(NULL, (size_t)len, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED){ fprintf(stderr, "mmap %s failed\n", what); exit(1); }
    return p;
}

static u8 g_want[36];              /* wire txid + LE vout */
typedef struct { long hits; } probe_ctx;
/* walk cb: cb(ctx, key36, value, (height<<1)|coinbase, script, slen) --
 * the utxo_stats_add contract (bitcoin_utxo_lsm.asm's walk header) */
static void probe_cb(void* ctxv, const u8 key[36], u64 value, u64 code,
                     const u8* script, unsigned long slen){
    probe_ctx* c = ctxv;
    if (memcmp(key, g_want, 36)) return;
    c->hits++;
    printf("[walk] FOUND value=%llu height=%llu coinbase=%llu slen=%lu spk=",
           (unsigned long long)value, (unsigned long long)(code >> 1),
           (unsigned long long)(code & 1), slen);
    for (unsigned long i = 0; i < slen && i < 64; i++) printf("%02x", script[i]);
    printf("\n");
}

#define MAX_PROBE 4096
static u8  g_keys[MAX_PROBE][36];
static int g_found[MAX_PROBE];
static int g_nkeys;

/* batch cb: mark every probed key the walk visits */
static void batch_cb(void* ctxv, const u8 key[36], u64 value, u64 code,
                     const u8* script, unsigned long slen){
    (void)ctxv; (void)value; (void)code; (void)script; (void)slen;
    for (int i = 0; i < g_nkeys; i++)
        if (!g_found[i] && !memcmp(key, g_keys[i], 36)) g_found[i] = 1;
}

int main(int argc, char** argv){
    int batch = 0;
    if (argc == 3){ batch = 1; }
    else if (argc != 4){
        fprintf(stderr, "usage: utxo_probe_one <datadir> <txid-display-hex> <vout>\n"
                        "       utxo_probe_one <datadir> <outpoints-file>   (lines: txid vout)\n");
        return 2;
    }
    if (batch){
        FILE* f = fopen(argv[2], "r");
        if (!f){ perror("outpoints file"); return 1; }
        char tx[80]; unsigned long vo;
        while (g_nkeys < MAX_PROBE && fscanf(f, "%64s %lu", tx, &vo) == 2){
            if (strlen(tx) != 64) continue;
            u8* k = g_keys[g_nkeys];
            for (int i = 0; i < 32; i++){
                unsigned b; sscanf(tx + 2*i, "%2x", &b);
                k[31 - i] = (u8)b;
            }
            for (int i = 0; i < 4; i++) k[32+i] = (u8)(vo >> (8*i));
            g_nkeys++;
        }
        fclose(f);
        fprintf(stderr, "[batch] %d outpoints loaded\n", g_nkeys);
    }
    if (chdir(argv[1])){ perror("chdir"); return 1; }
    u32 vout = 0;
    if (!batch){
        if (strlen(argv[2]) != 64){ fprintf(stderr, "txid must be 64 hex chars\n"); return 2; }
        for (int i = 0; i < 32; i++){
            unsigned b; sscanf(argv[2] + 2*i, "%2x", &b);
            g_want[31 - i] = (u8)b;                    /* display -> wire */
        }
        vout = (u32)atol(argv[3]);
        for (int i = 0; i < 4; i++) g_want[32+i] = (u8)(vout >> (8*i));
    }

    unsigned long slots;
    { u64 tsz = file_size_or("utxo_lsm_table.map", 0);
      slots = tsz > 48 ? (unsigned long)((tsz - 48) / 48) : (1UL << 22);
      if (slots < (1UL << 20)) slots = 1UL << 20; }
    u64 blob_cap = file_size_or("utxo_lsm_blob.map", 1UL << 30);
    if (blob_cap < (256UL << 20)) blob_cap = 256UL << 20;

    long ustruct = utxo_struct_size(slots);
    void* u = xmap((u64)ustruct, "memtable");
    void* blob = xmap(blob_cap, "blob");
    utxo_init(u, slots, blob, blob_cap);

    lsm_state_t lst; memset(&lst, 0, sizeof lst);
    u64 tomb_cap = (u64)slots * 2, manifest_cap = 4096;
    lst.op_threshold = (u64)slots * 2;
    lst.fill_threshold = (u64)slots * 3 / 4;
    lst.tomb_buf = (u64)(uintptr_t)xmap(tomb_cap * 36, "tomb");
    lst.tomb_cap = tomb_cap;
    lst.manifest_buf = (u64)(uintptr_t)xmap(manifest_cap * 16, "manifest");
    lst.manifest_cap = manifest_cap;
    lst.scratch_buf = (u64)(uintptr_t)xmap(8UL << 20, "scratch");
    lst.scratch_cap = 8UL << 20;

    long replayed = utxo_lsm_reload_ro(&lst, u);
    if (replayed < 0){ fprintf(stderr, "utxo_lsm_reload_ro failed\n"); return 1; }
    fprintf(stderr, "[reload] ok (wal replayed=%ld, manifest_n=%llu)\n",
            replayed, (unsigned long long)lst.manifest_n);

    if (batch){
        /* point lookups first, then one walk marking everything found */
        int get_hits = 0;
        for (int i = 0; i < g_nkeys; i++){
            u64 v; unsigned long hh, cb, sl; const u8* sc;
            u32 vo = (u32)(g_keys[i][32] | g_keys[i][33]<<8 | g_keys[i][34]<<16 | (u32)g_keys[i][35]<<24);
            if (utxo_lsm_get(&lst, u, g_keys[i], vo, &v, &hh, &cb, &sc, &sl) == 1){
                get_hits++;
                if (sl > 42){
                    printf("[get-slen-anomaly] ");
                    for (int b = 31; b >= 0; b--) printf("%02x", g_keys[i][b]);
                    printf(" %u slen=%lu\n", vo, sl);
                }
            }
            else {
                printf("[get-miss] ");
                for (int b = 31; b >= 0; b--) printf("%02x", g_keys[i][b]);
                printf(" %u\n", vo);
            }
        }
        printf("[get ] %d/%d found\n", get_hits, g_nkeys);
        long w = utxo_lsm_walk(&lst, u, (void*)batch_cb, NULL);
        int walk_hits = 0;
        for (int i = 0; i < g_nkeys; i++){
            if (g_found[i]){ walk_hits++; continue; }
            printf("[walk-miss] ");
            for (int b = 31; b >= 0; b--) printf("%02x", g_keys[i][b]);
            printf(" %u\n", (u32)(g_keys[i][32] | g_keys[i][33]<<8 | g_keys[i][34]<<16 | (u32)g_keys[i][35]<<24));
        }
        printf("[walk] %d/%d found (walked %ld)\n", walk_hits, g_nkeys, w);
        return 0;
    }

    /* path 1: the point lookup */
    u64 value; unsigned long height, coinbase, slen; const u8* script;
    long g = utxo_lsm_get(&lst, u, g_want, vout, &value, &height, &coinbase, &script, &slen);
    if (g == 1){
        printf("[get ] FOUND value=%llu height=%lu coinbase=%lu slen=%lu spk=",
               (unsigned long long)value, height, coinbase, slen);
        for (unsigned long i = 0; i < slen && i < 64; i++) printf("%02x", script[i]);
        printf("\n");
    } else {
        printf("[get ] NOT FOUND (rc=%ld)\n", g);
    }

    /* path 2: the full walk (ground truth of the parity proof) */
    probe_ctx c = {0};
    long w = utxo_lsm_walk(&lst, u, (void*)probe_cb, &c);
    if (w < 0){ fprintf(stderr, "walk failed\n"); return 1; }
    if (!c.hits) printf("[walk] NOT FOUND (walked %ld entries)\n", w);
    return 0;
}
