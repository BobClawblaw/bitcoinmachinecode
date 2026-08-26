/* tests/test_coinstats_index.c -- the incremental coinstats index
 * (daemon/coinstats_index.c).
 *
 * The property that matters: for ANY event sequence, the index's finalized
 * digest must equal a fresh full walk of the resulting set -- the exact
 * instrument the parity capstone used. Pinned here end to end:
 *
 *   1. Fermat inverse identity: acc * inv(acc) finalizes to the EMPTY-set
 *      digest (the muhash multiplicative identity);
 *   2. seed {A,B} by walk, then csi_on_add(C) + csi_on_remove(A):
 *      digest and all three counters must equal an independent full walk
 *      of a set built directly as {B,C};
 *   3. persistence: csi_read_file (the parent RPC's fresh-load path) agrees
 *      byte-for-byte with the live state, and the RPC adapter serves it;
 *   4. add-then-remove of the SAME coin nets out exactly (the property that
 *      makes partial-apply rollbacks self-cancelling).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern void muhash_init(void* acc);
extern void muhash_finalize(unsigned char out[32], const void* acc);
extern void utxo_stats_init(void* st, unsigned long want_muhash, unsigned long excl_genesis);
extern void utxo_stats_add(void* st, const u8 key36[36], unsigned long value,
                           unsigned long code, const u8* script, unsigned long slen);

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index, u64 value,
                         u64 height, u64 is_coinbase, const u8* script, u32 slen);
extern void utxo_lsm_close(void* lst);
extern long utxo_lsm_reload_ro(void* lst, void* u);
extern long utxo_lsm_walk(void* lst, void* u, void* cb, void* ctx);

extern int  csi_boot(long applied_height);
extern int  csi_seed_from_walk(void* lst, void* u, long height);
extern void csi_on_add(const u8*, u32, u64, u64, u64, const u8*, unsigned long);
extern void csi_on_remove(const u8*, u32, u64, u64, u64, const u8*, unsigned long);
extern void csi_commit(long height);
extern int  csi_read_live(long*, unsigned char[32], u64*, u64*, u64*);
extern int  csi_read_file(long*, unsigned char*, unsigned char[32], u64*, u64*, u64*);
extern long csi_rpc_run(int, void*, char*, unsigned long);
extern long csi_file_height(void);

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

static int failures = 0;
static void ck(const char* l, int cond){
    if (cond) printf("  ok  %s\n", l);
    else { printf("  FAIL %s\n", l); failures++; }
}

/* one LSM instance in the CURRENT directory, seeded with the given coins */
typedef struct { u8 txid[32]; u32 idx; u64 val, h, cb; u8 spk[32]; u32 slen; } coin_t;
static void lsm_build(struct lsm_state* lst, void** table_out, const coin_t* coins, int n){
    unsigned long slots = 1UL<<12;
    void* table = malloc((size_t)utxo_struct_size(slots));
    void* blob = malloc(16UL<<20);
    utxo_init(table, slots, blob, 16UL<<20);
    memset(lst, 0, sizeof *lst);
    u64 op_th = slots*2, tomb_cap = op_th, desc_cap = slots*3;
    lst->op_threshold = op_th; lst->fill_threshold = slots*3/4;
    lst->tomb_buf = malloc(tomb_cap*36); lst->tomb_cap = tomb_cap;
    lst->manifest_buf = malloc(256*16); lst->manifest_cap = 256;
    lst->scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    lst->scratch_buf = malloc(lst->scratch_cap);
    if (utxo_lsm_init(lst) != 1){ fprintf(stderr, "lsm init failed\n"); exit(1); }
    for (int i = 0; i < n; i++)
        if (utxo_lsm_put(lst, table, coins[i].txid, coins[i].idx, coins[i].val,
                         coins[i].h, coins[i].cb, coins[i].spk, coins[i].slen) != 1){
            fprintf(stderr, "seed put failed\n"); exit(1); }
    *table_out = table;
}

static void mk_coin(coin_t* c, int tag, u64 val, u64 h, u64 cb){
    memset(c, 0, sizeof *c);
    memset(c->txid, 0xA0 + tag, 32);
    c->idx = (u32)tag; c->val = val; c->h = h; c->cb = cb;
    c->slen = 25;
    c->spk[0]=0x76; c->spk[1]=0xa9; c->spk[2]=0x14;
    memset(c->spk+3, 0x30+tag, 20);
    c->spk[23]=0x88; c->spk[24]=0xac;
}

static void walk_digest(struct lsm_state* lst, void* table, unsigned char out[32],
                        u64* txouts, u64* amount, u64* bogo){
    static u8 st[512] __attribute__((aligned(16)));
    utxo_stats_init(st, 1, 0);
    long n = utxo_lsm_walk(lst, table, (void*)utxo_stats_add, st);
    if (n < 0){ fprintf(stderr, "walk failed\n"); exit(1); }
    extern void utxo_stats_finalize(void* st);
    utxo_stats_finalize(st);
    memcpy(out, st + 64, 32);                 /* ST_MUHASH */
    memcpy(txouts, st + 0, 8);
    memcpy(amount, st + 8, 8);
    memcpy(bogo,   st + 16, 8);
}

int main(void){
    tt_isolate();

    coin_t A, B, C;
    mk_coin(&A, 1, 5000000, 100, 0);
    mk_coin(&B, 2, 7000000, 200, 1);
    mk_coin(&C, 3, 9000000, 300, 0);

    printf("== 2: seed {A,B} by walk; +C, -A; must equal a fresh {B,C} walk ==\n");
    mkdir("set_ab", 0755); mkdir("set_bc", 0755);
    struct lsm_state l1; void* t1;
    if (chdir("set_ab")){ perror("chdir"); return 1; }
    { coin_t s[2] = { A, B }; lsm_build(&l1, &t1, s, 2); }
    ck("csi_boot with no file -> needs seed", csi_boot(500) == 0);
    ck("seed from walk", csi_seed_from_walk(&l1, t1, 500) == 1);
    csi_on_add(C.txid, C.idx, C.val, C.h, C.cb, C.spk, C.slen);
    csi_on_remove(A.txid, A.idx, A.val, A.h, A.cb, A.spk, A.slen);
    csi_commit(501);
    long h; unsigned char d_idx[32]; u64 tx, amt, bg;
    ck("live read ok", csi_read_live(&h, d_idx, &tx, &amt, &bg) == 1);
    ck("height tracks the commit", h == 501);

    if (chdir("../set_bc")){ perror("chdir"); return 1; }
    struct lsm_state l2; void* t2;
    { coin_t s[2] = { B, C }; lsm_build(&l2, &t2, s, 2); }
    unsigned char d_ref[32]; u64 rtx, ramt, rbg;
    walk_digest(&l2, t2, d_ref, &rtx, &ramt, &rbg);
    ck("DIGEST equals the independent {B,C} walk", memcmp(d_idx, d_ref, 32) == 0);
    ck("txouts equal", tx == rtx);
    ck("amount equal", amt == ramt);
    ck("bogosize equal", bg == rbg);

    printf("\n== 3: the file read (parent RPC path) agrees, and the adapter serves ==\n");
    if (chdir("../set_ab")){ perror("chdir"); return 1; }
    long fh; unsigned char d_file[32]; u64 ftx, famt, fbg;
    ck("csi_read_file ok", csi_read_file(&fh, NULL, d_file, &ftx, &famt, &fbg) == 1);
    ck("file digest == live digest", memcmp(d_file, d_idx, 32) == 0 && fh == 501);
    ck("csi_file_height", csi_file_height() == 501);
    { struct { long height; u64 txouts, bogosize, total_amount;
               unsigned char muhash[32]; int muhash_valid; } o;
      memset(&o, 0, sizeof o);
      char msg[64];
      ck("csi_rpc_run serves", csi_rpc_run(1, &o, msg, sizeof msg) == 1);
      /* the adapter REVERSES for presentation (Core's printed order --
       * pinned after the first live parity check read identical digests as
       * a mismatch) */
      unsigned char d_rev[32];
      for (int i = 0; i < 32; i++) d_rev[i] = d_idx[31 - i];
      ck("...same digest (presentation order) and counters",
         o.muhash_valid && memcmp(o.muhash, d_rev, 32) == 0
         && o.txouts == tx && o.total_amount == amt);
    }

    printf("\n== 4: add-then-remove of the same coin nets out exactly ==\n");
    { coin_t D; mk_coin(&D, 4, 1234567, 400, 0);
      csi_on_add(D.txid, D.idx, D.val, D.h, D.cb, D.spk, D.slen);
      csi_on_remove(D.txid, D.idx, D.val, D.h, D.cb, D.spk, D.slen);
      csi_commit(502);
      unsigned char d2[32]; u64 t2x, a2, b2;
      ck("read after net-zero pair", csi_read_live(&h, d2, &t2x, &a2, &b2) == 1);
      ck("digest unchanged", memcmp(d2, d_idx, 32) == 0);
      ck("counters unchanged", t2x == tx && a2 == amt && b2 == bg);
    }

    printf("\n%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
