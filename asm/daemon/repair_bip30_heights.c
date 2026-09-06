/* daemon/repair_bip30_heights.c -- one-time fix for the BIP30 duplicate-
 * coinbase height bug found by the first full muhash parity check
 * (2026-09-05): build_utxo.c's on_output treated utxo_lsm_put's r==0
 * ("key already exists") as a benign no-op, so for the two duplicate
 * coinbases of the BIP30 era the SECOND block's coin -- the one Core's
 * chainstate actually holds, because a later coinbase overwrite REPLACES
 * the earlier coin with a new nHeight -- never landed. The store kept the
 * FIRST appearance's height:
 *
 *     d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599:0
 *       ours height=91812, Core height=91842   (50 BTC, P2PK, coinbase)
 *     e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468:0
 *       ours height=91722, Core height=91880   (50 BTC, P2PK, coinbase)
 *
 * Two coins, height byte only: count/total_amount/bogosize stayed Core-exact
 * while muhash diverged. This tool tombstones each stale coin and re-puts it
 * with the correct height and the exact script Core reports -- four WAL
 * records total. It does NOT flush: the daemon's next reload replays the
 * records into its memtable (new generation above the stale run entry), and
 * the next routine flush/compaction makes them durable. Del-then-put of the
 * same key is exactly the op sequence fuzz_lsm byte-compares against the
 * Python model, so no new store machinery is exercised.
 *
 * The tool asserts the stale state before touching anything (get must show
 * the stale height, else abort) -- running it twice cannot corrupt, but the
 * assert makes a surprise visible instead of silently "repairing" an
 * already-repaired store.
 *
 * Usage: repair_bip30_heights <datadir>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

typedef uint8_t u8; typedef uint64_t u64;

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_reload(void* lst, void* u);
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], unsigned index,
                         u64* value, unsigned long* height, unsigned long* is_coinbase,
                         const u8** script, unsigned long* slen);
extern long utxo_lsm_del(void* lst, void* u, const u8 txid[32], unsigned index);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], unsigned index,
                         u64 value, unsigned long height, unsigned long is_coinbase,
                         const u8* script, unsigned long slen);
extern void utxo_lsm_close(void* lst);

struct lsm_state {
    long log_fd, idx_fd;
    u64 log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap;
    u64 next_run_no;
    void* tomb_hash_buf; u64 tomb_hash_mask;
};
#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536

/* display-order txid hex -> wire order (the LSM key) */
static void wire_from_display(const char* hex, u8 out[32]){
    for (int i = 0; i < 32; i++){
        unsigned b; sscanf(hex + 2*i, "%2x", &b);
        out[31 - i] = (u8)b;
    }
}

typedef struct {
    const char* display;
    unsigned long stale_height;   /* what the (buggy) store holds today */
    unsigned long good_height;    /* what Core's chainstate holds */
    const char* spk_hex;          /* the coin's exact script, from Core */
} fix_t;

static const fix_t FIXES[] = {
    { "d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599",
      91812, 91842,
      "41046896ecfc449cb8560594eb7f413f199deb9b4e5d947a142e7dc7d2de0b811b8e20"
      "4833ea2a2fd9d4c7b153a8ca7661d0a0b7fc981df1f42f55d64b26b3da1e9cac" },
    { "e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468",
      91722, 91880,
      "4104124b212f5416598a92ccec88819105179dcb2550d571842601492718273fe0f217"
      "9a9695096bff94cd99dcccdea7cd9bd943bfca8fea649cac963411979a33e9ac" },
};

static void* mmap_file(const char* path, u64 size){
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) { perror("open"); return 0; }
    if (ftruncate(fd, (off_t)size) != 0) { perror("ftruncate"); close(fd); return 0; }
    void* p = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) { perror("mmap"); return 0; }
    return p;
}

int main(int argc, char** argv){
    if (argc < 2) { fprintf(stderr, "usage: %s <datadir>\n", argv[0]); return 2; }
    if (chdir(argv[1])) { perror("chdir"); return 1; }

    /* Same sizing as flush_wal_tail.c: large enough for any builder-scale
     * WAL tail, thresholds irrelevant (we must NOT flush here -- the whole
     * point is to leave exactly four WAL records for the daemon to replay). */
    int slots_log2 = 24;
    unsigned long slots = 1UL << slots_log2;
    u64 blob_cap = 2UL*1024*1024*1024;
    long ustruct = utxo_struct_size(slots);
    u64 tomb_cap = slots * 2;
    u64 desc_cap = slots * 3;
    u64 scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    u64 manifest_cap = 8192;

    void* u = mmap_file("utxo_lsm_repairbip30_table.map", (u64)ustruct);
    void* blob = mmap_file("utxo_lsm_repairbip30_blob.map", blob_cap);
    if (!u || !blob) return 1;
    utxo_init(u, slots, blob, blob_cap);

    void* tomb_buf = malloc(tomb_cap*36);
    void* manifest_buf = malloc(manifest_cap*16);
    void* scratch_buf = malloc(scratch_cap);
    if (!tomb_buf || !manifest_buf || !scratch_buf) { fprintf(stderr, "malloc failed\n"); return 1; }

    struct lsm_state lst;
    memset(&lst, 0, sizeof lst);
    lst.op_threshold = slots * 2;     /* production-like: no flush will fire */
    lst.fill_threshold = slots * 3 / 4;
    lst.tomb_buf = tomb_buf; lst.tomb_cap = tomb_cap;
    lst.manifest_buf = manifest_buf; lst.manifest_cap = manifest_cap;
    lst.scratch_buf = scratch_buf; lst.scratch_cap = scratch_cap;

    long replayed = utxo_lsm_reload(&lst, u);
    if (replayed < 0) { fprintf(stderr, "FATAL: reload failed\n"); return 1; }
    fprintf(stderr, "reload ok: manifest_n=%lu replayed=%ld total_live=%lu\n",
            lst.manifest_n, replayed, lst.total_live);

    int bad = 0;
    for (unsigned f = 0; f < sizeof FIXES / sizeof FIXES[0]; f++){
        u8 wire[32]; wire_from_display(FIXES[f].display, wire);
        u64 value = 0; unsigned long h = 0, cb = 0; const u8* sc = 0; unsigned long sl = 0;
        long g = utxo_lsm_get(&lst, u, wire, 0, &value, &h, &cb, &sc, &sl);
        if (g != 1){
            fprintf(stderr, "FATAL: %s:0 not FOUND (rc=%ld) -- refusing to touch anything\n",
                    FIXES[f].display, g);
            bad = 1; continue;
        }
        if (h != FIXES[f].stale_height || value != 5000000000ULL || !cb){
            fprintf(stderr, "FATAL: %s:0 unexpected state (height=%lu value=%llu cb=%lu) "
                            "-- expected the stale height %lu and the 50 BTC coinbase\n",
                    FIXES[f].display, h, (unsigned long long)value, cb, FIXES[f].stale_height);
            bad = 1; continue;
        }
    }
    if (bad) return 1;

    for (unsigned f = 0; f < sizeof FIXES / sizeof FIXES[0]; f++){
        u8 wire[32]; wire_from_display(FIXES[f].display, wire);
        u8 script[SCRIPT_MAX_BYTES]; unsigned long sl = 0;
        const char* p = FIXES[f].spk_hex;
        for (; *p && p[1]; p += 2){ unsigned b; sscanf(p, "%2x", &b); script[sl++] = (u8)b; }

        long d = utxo_lsm_del(&lst, u, wire, 0);
        if (d != 1){ fprintf(stderr, "FATAL: del %s returned %ld\n", FIXES[f].display, d); return 1; }
        long r = utxo_lsm_put(&lst, u, wire, 0, 5000000000ULL,
                              FIXES[f].good_height, 1, script, sl);
        if (r != 1){ fprintf(stderr, "FATAL: put %s returned %ld\n", FIXES[f].display, r); return 1; }
        fprintf(stderr, "repaired %s:0 height %lu -> %lu (script %lu B)\n",
                FIXES[f].display, FIXES[f].stale_height, FIXES[f].good_height, sl);
    }

    /* verify through the SAME handle before closing */
    for (unsigned f = 0; f < sizeof FIXES / sizeof FIXES[0]; f++){
        u8 wire[32]; wire_from_display(FIXES[f].display, wire);
        u64 value = 0; unsigned long h = 0, cb = 0; const u8* sc = 0; unsigned long sl = 0;
        long g = utxo_lsm_get(&lst, u, wire, 0, &value, &h, &cb, &sc, &sl);
        if (g != 1 || h != FIXES[f].good_height || value != 5000000000ULL || !cb){
            fprintf(stderr, "FATAL: post-repair verify failed for %s:0 (rc=%ld h=%lu)\n",
                    FIXES[f].display, g, h);
            return 1;
        }
    }
    fprintf(stderr, "post-repair verify ok (in-memory)\n");
    utxo_lsm_close(&lst);
    fprintf(stderr, "DONE -- 4 WAL records left for the daemon's next reload; no flush performed\n");
    return 0;
}
