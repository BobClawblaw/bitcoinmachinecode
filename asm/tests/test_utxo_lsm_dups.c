/* tests/test_utxo_lsm_dups.c -- one record per key, per run (2026-09-09).
 *
 * Bench run 18 invalidated a VALID mainnet block (963,311) because the point
 * lookup said one of its inputs, a coin created at 962,871, was spent. The
 * coin was in the set: the full walk found it. The run the background
 * compaction had just written held the key TWICE, a PUSH followed by a DEL,
 * and the sparse index happened to point at the DEL. Two defects behind it:
 *
 *   1. utxo_lsm_del appends to the generation's tombstone list every time
 *      it is called, so del K / put K / del K within one generation (a
 *      stale branch spends K, the unapply restores it, the replacement
 *      block spends it again) leaves K in the list twice, and the flush
 *      writes both: a run with two DEL records for one key.
 *   2. the k-way merge advances a matching input slot by ONE record after
 *      emitting a winner, so an input holding a key twice hands the key to
 *      the next iteration, which emits it again -- and once a PUSH from a
 *      newer run has been emitted, the stale DEL follows it into the output.
 *      11,362 duplicated keys in one 52M-record run on the bench.
 *
 * The walk takes the first record of a key and the point lookup takes
 * whichever one the sparse index lands on, so the two disagreed and
 * consensus rejected a valid block. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"
extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const unsigned char txid[32], unsigned index, unsigned long long value,
                         unsigned long height, unsigned long is_coinbase, const unsigned char* script, unsigned slen);
extern long utxo_lsm_del(void* lst, void* u, const unsigned char txid[32], unsigned index);
extern long utxo_lsm_flush(void* lst, void* u);
extern long utxo_lsm_get(void* lst, void* u, const unsigned char txid[32], unsigned index, unsigned long long* value,
                         unsigned long* height, unsigned long* is_coinbase, const unsigned char** script, unsigned long* slen);
extern long utxo_lsm_walk(void* lst, void* u, void* cb, void* ctx);
extern long utxo_lsm_compact_range(void* lst, unsigned long lo, unsigned long k);
extern void utxo_lsm_close(void* lst);
struct LST {
    long log_fd; long idx_fd; unsigned long long log_len, ckpt_log_off, ckpt_n, op_count, op_threshold, fill_threshold;
    void* tomb_buf; unsigned long long tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; unsigned long long manifest_cap, manifest_n;
    void* scratch_buf; unsigned long long scratch_cap, next_run_no;
    void* tomb_hash_buf; unsigned long long tomb_hash_mask;
};
#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536
#define SLOTS 256
#define TOMB_CAP 64
#define MANIFEST_CAP 4096
#define SCRATCH_CAP ((unsigned long long)128*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES)
static int fails = 0;
static void ck(const char* l, long g, long e){ if (g == e) printf("ok  : %s (got %ld)\n", l, g); else { printf("FAIL: %s (got %ld exp %ld)\n", l, g, e); fails++; } }
static void ckm(const char* l, int c){ ck(l, c, 1); }
static void setup_lst(struct LST* lst){
    memset(lst, 0, sizeof *lst);
    lst->op_threshold = 1000000; lst->fill_threshold = 200;      /* no automatic flushes: the test flushes */
    lst->tomb_buf = malloc(TOMB_CAP*36); lst->tomb_cap = TOMB_CAP;
    lst->manifest_buf = malloc(MANIFEST_CAP*16); lst->manifest_cap = MANIFEST_CAP;
    lst->scratch_buf = malloc(SCRATCH_CAP); lst->scratch_cap = SCRATCH_CAP;
}
static void* new_memtable(void){
    static unsigned char ux[40 + SLOTS*48 + 8]; static unsigned char blob[1<<20];
    utxo_init(ux, SLOTS, blob, sizeof blob); return ux;
}
static void txid_of(unsigned char* t, unsigned char lead){ memset(t, 0xab, 32); t[0] = lead; }

/* ---- a run file reader: the record kinds for one key, in file order ---- */
static int key_records(const char* path, const unsigned char key[36], int kinds[8], long* nrec_out){
    FILE* f = fopen(path, "rb"); if (!f) return -1;
    fseek(f, 0, SEEK_END); long len = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* m = malloc((size_t)len); if (fread(m, 1, (size_t)len, f) != (size_t)len){ fclose(f); free(m); return -1; }
    fclose(f);
    unsigned long long bits, sparse_off; memcpy(&bits, m + 20, 8); memcpy(&sparse_off, m + 28, 8);
    long p = 44 + (long)(bits >> 3), end = sparse_off ? (long)sparse_off : len, n = 0, hits = 0;
    while (p + 37 <= end){
        int kind = m[p+36];
        if (!memcmp(m + p, key, 36) && hits < 8) kinds[hits++] = kind;
        if (kind != 1) p += 37; else { unsigned slen = m[p+37+8] | (m[p+37+9] << 8); p += 37 + 15 + (long)slen; }
        n++;
    }
    free(m); if (nrec_out) *nrec_out = n; return (int)hits;
}
static unsigned long long manifest_run(struct LST* lst, int i){ unsigned long long r; memcpy(&r, (char*)lst->manifest_buf + i*16 + 8, 8); return r; }
static void run_path(char* out, unsigned long long run_no){ sprintf(out, "utxo_run_%06llu.dat", run_no); }

/* ---- a run file writer, for input shapes the fixed code can no longer produce ---- */
typedef struct { unsigned char key[36]; int kind; unsigned long long value; } rec_t;
static void mkrec(rec_t* r, unsigned char lead, unsigned index, int kind, unsigned long long value){
    memset(r, 0, sizeof *r); txid_of(r->key, lead); memcpy(r->key + 32, &index, 4); r->kind = kind; r->value = value;
}
static int rec_cmp(const void* a, const void* b){ return memcmp(a, b, 36); }
static void write_run(unsigned long long run_no, rec_t* recs, int n, int sparse_every_record){
    char path[64]; run_path(path, run_no); FILE* f = fopen(path, "wb");
    unsigned magic = 0x33555255u; unsigned long long gen = run_no, nrec = (unsigned long long)n, bloom_bits = 64, sparse_off = 0, sparse_n = 0;
    unsigned char bloom[8]; memset(bloom, 0xff, 8);
    unsigned long long offs[512]; long pos = 44 + 8;
    for (int i = 0; i < n; i++){ offs[i] = (unsigned long long)pos; pos += 37 + (recs[i].kind == 1 ? 15 + 1 : 0); }
    if (sparse_every_record){ sparse_off = (unsigned long long)pos; sparse_n = (unsigned long long)n; }
    fwrite(&magic, 4, 1, f); fwrite(&gen, 8, 1, f); fwrite(&nrec, 8, 1, f); fwrite(&bloom_bits, 8, 1, f); fwrite(&sparse_off, 8, 1, f); fwrite(&sparse_n, 8, 1, f);
    fwrite(bloom, 1, 8, f);
    for (int i = 0; i < n; i++){
        unsigned char kind = (unsigned char)recs[i].kind;
        fwrite(recs[i].key, 36, 1, f); fwrite(&kind, 1, 1, f);
        if (kind == 1){ unsigned short slen = 1; unsigned height = 5; unsigned char cb = 0, script = 0x51;
            fwrite(&recs[i].value, 8, 1, f); fwrite(&slen, 2, 1, f); fwrite(&height, 4, 1, f); fwrite(&cb, 1, 1, f); fwrite(&script, 1, 1, f); }
    }
    if (sparse_every_record) for (int i = 0; i < n; i++){ fwrite(recs[i].key, 36, 1, f); fwrite(&offs[i], 8, 1, f); }
    fclose(f);
}
static void inject_manifest(struct LST* lst, const unsigned long long* runs, int n){
    unsigned long long* m = lst->manifest_buf;
    for (int i = 0; i < n; i++){ m[2*i] = runs[i]; m[2*i+1] = runs[i]; }
    lst->manifest_n = (unsigned long long)n; lst->next_run_no = 900; lst->next_gen = 900;
}
typedef struct { const unsigned char* key; long hits; long total; } walk_ctx;
static void walk_cb(void* c, const unsigned char key[36], unsigned long long value, unsigned long long code, const unsigned char* script, unsigned long slen){
    (void)value; (void)code; (void)script; (void)slen; walk_ctx* w = c; w->total++; if (!memcmp(key, w->key, 36)) w->hits++;
}

int main(void){
    tt_isolate();
    unsigned char K[36], A[36]; unsigned index0 = 0;
    txid_of(K, 0x80); memcpy(K + 32, &index0, 4);
    txid_of(A, 0xf0); memcpy(A + 32, &index0, 4);
    unsigned char script[1] = {0x51};

    /* ================= case 1: del K / put K / del K in one generation ================= */
    printf("-- case 1: a key deleted twice in one generation is one tombstone, not two\n");
    mkdir("c1", 0755); ckm("chdir c1", chdir("c1") == 0);
    { struct LST lst; setup_lst(&lst); void* u = new_memtable();
      ck("init", utxo_lsm_init(&lst), 1);
      ck("put K", utxo_lsm_put(&lst, u, K, 0, 1000, 5, 0, script, 1), 1);
      ck("flush: K goes to a run", utxo_lsm_flush(&lst, u), 1);
      ck("del K (a stale block spends it: memtable miss, tombstone)", utxo_lsm_del(&lst, u, K, 0), 1);
      ck("put K (the unapply restores it)", utxo_lsm_put(&lst, u, K, 0, 1000, 5, 0, script, 1), 1);
      ck("del K (the replacement block spends it: memtable hit)", utxo_lsm_del(&lst, u, K, 0), 1);
      ck("the tombstone list holds K once", (long)lst.tomb_n, 1);
      ck("flush", utxo_lsm_flush(&lst, u), 1);
      ck("two runs", (long)lst.manifest_n, 2);
      char path[64]; run_path(path, manifest_run(&lst, 1)); int kinds[8] = {0}; long n = 0;
      int hits = key_records(path, K, kinds, &n);
      ck("the flushed run holds ONE record for K", hits, 1);
      ck("... a DEL", kinds[0], 2);
      unsigned long long v; unsigned long h, cb, sl; const unsigned char* sc;
      ck("get K: spent", utxo_lsm_get(&lst, u, K, 0, &v, &h, &cb, &sc, &sl), 0);
      /* the dedup is per generation: the flush reset the list, a new del of K is recorded again */
      ck("del K in the next generation", utxo_lsm_del(&lst, u, K, 0), 1);
      ck("... is recorded (the flush reset the tombstone hash)", (long)lst.tomb_n, 1);
      utxo_lsm_close(&lst); }
    ckm("chdir ..", chdir("..") == 0);

    /* ================= case 2: the merge collapses an input's duplicate ================= */
    printf("-- case 2: an input run holding a key twice does not duplicate it in the merge\n");
    mkdir("c2", 0755); ckm("chdir c2", chdir("c2") == 0);
    { struct LST lst; setup_lst(&lst); void* u = new_memtable();
      ck("init", utxo_lsm_init(&lst), 1);
      rec_t base[1]; mkrec(&base[0], 0xf0, 0, 1, 7);                          /* index 0: push A (below the batch) */
      rec_t dup[2]; mkrec(&dup[0], 0x80, 0, 2, 0); mkrec(&dup[1], 0x80, 0, 2, 0);   /* index 1: DEL K, DEL K (defect 1's output) */
      static rec_t newer[64]; for (int i = 0; i < 63; i++) mkrec(&newer[i], (unsigned char)(0x10 + i), 0, 1, 100 + (unsigned long long)i);
      mkrec(&newer[63], 0x80, 0, 1, 2000);                                      /* index 2: 63 fillers below K, then push K */
      qsort(newer, 64, sizeof(rec_t), rec_cmp);
      write_run(801, base, 1, 0); write_run(802, dup, 2, 0); write_run(803, newer, 64, 0);
      unsigned long long runs[3] = {801, 802, 803}; inject_manifest(&lst, runs, 3);
      ck("compact [1..3): the two newest runs, tombstones kept", utxo_lsm_compact_range(&lst, 1, 2), 1);
      ck("manifest: base + merged", (long)lst.manifest_n, 2);
      char path[64]; run_path(path, manifest_run(&lst, 1)); int kinds[8] = {0}; long n = 0;
      int hits = key_records(path, K, kinds, &n);
      ck("the merged run holds ONE record for K", hits, 1);
      ck("... the PUSH from the newest run", kinds[0], 1);
      ck("64 records in the merged run (63 fillers + K)", n, 64);
      unsigned long long v = 0; unsigned long h, cb, sl; const unsigned char* sc;
      ck("get K after the merge: live (the sparse sample at ordinal 64 was the stale DEL)", utxo_lsm_get(&lst, u, K, 0, &v, &h, &cb, &sc, &sl), 1);
      ck("get K value", (long)v, 2000);
      walk_ctx w = {K, 0, 0}; utxo_lsm_walk(&lst, u, (void*)walk_cb, &w);
      ck("the walk sees K once", w.hits, 1);
      ck("the walk sees 65 live coins (A + 63 fillers + K)", w.total, 65);
      utxo_lsm_close(&lst); }
    ckm("chdir ..", chdir("..") == 0);

    /* ================= case 3: a damaged run (PUSH K, DEL K) is repaired by the next merge ================= */
    printf("-- case 3: the bench's run shape -- PUSH then DEL for one key, sparse index on the DEL\n");
    mkdir("c3", 0755); ckm("chdir c3", chdir("c3") == 0);
    { struct LST lst; setup_lst(&lst); void* u = new_memtable();
      ck("init", utxo_lsm_init(&lst), 1);
      rec_t base[1]; mkrec(&base[0], 0xf0, 0, 1, 7);
      static rec_t damaged[65]; for (int i = 0; i < 63; i++) mkrec(&damaged[i], (unsigned char)(0x10 + i), 0, 1, 100 + (unsigned long long)i);
      mkrec(&damaged[63], 0x80, 0, 1, 3000); mkrec(&damaged[64], 0x80, 0, 2, 0);   /* sorted already: fillers, push K, del K */
      rec_t newest[1]; mkrec(&newest[0], 0xf8, 0, 1, 9);
      write_run(811, base, 1, 0); write_run(812, damaged, 65, 1); write_run(813, newest, 1, 0);
      unsigned long long runs[3] = {811, 812, 813}; inject_manifest(&lst, runs, 3);
      unsigned long long v = 0; unsigned long h, cb, sl; const unsigned char* sc;
      long g0 = utxo_lsm_get(&lst, u, K, 0, &v, &h, &cb, &sc, &sl);
      walk_ctx w0 = {K, 0, 0}; utxo_lsm_walk(&lst, u, (void*)walk_cb, &w0);
      printf("     before the merge: get says %s, the walk says %s (the bench's disagreement)\n", g0 == 1 ? "live" : "spent", w0.hits ? "live" : "spent");
      ck("compact [1..3)", utxo_lsm_compact_range(&lst, 1, 2), 1);
      char path[64]; run_path(path, manifest_run(&lst, 1)); int kinds[8] = {0}; long n = 0;
      int hits = key_records(path, K, kinds, &n);
      ck("the merged run holds ONE record for K", hits, 1);
      ck("... the first one, the PUSH (what the walk always reported)", kinds[0], 1);
      ck("get K after the merge: live", utxo_lsm_get(&lst, u, K, 0, &v, &h, &cb, &sc, &sl), 1);
      walk_ctx w = {K, 0, 0}; utxo_lsm_walk(&lst, u, (void*)walk_cb, &w);
      ck("the walk agrees", w.hits, 1);
      utxo_lsm_close(&lst); }
    ckm("chdir ..", chdir("..") == 0);

    printf("%s (%d failure(s))\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
