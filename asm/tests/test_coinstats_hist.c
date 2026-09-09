/* tests/test_coinstats_hist.c -- the coinstats index's per-height rows and
 * gettxoutsetinfo's per-block accounting (daemon/coinstats_hist_fmt.h).
 *
 * A two-coin set is seeded at height 100 (the baseline row); blocks 101-103
 * are then committed through the inline fold path with a coinbase, a spend,
 * a new output and an OP_RETURN output. The rows must give Core's block_info
 * for each: prevout_spent, coinbase, new_outputs_ex_coinbase, the
 * unspendable script amount, and unclaimed_rewards = subsidy + prevout_spent
 * - new_outputs_ex_coinbase - coinbase - scripts (Core's formula per block),
 * with the set's counters and a digest at every height. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include "../daemon/coinstats_hist_fmt.h"
#include "test_tmpdir.h"
typedef unsigned char u8; typedef uint32_t u32; typedef uint64_t u64;
extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* t, unsigned long slots, void* blob, unsigned long blob_cap);
extern int  utxo_lsm_init(void* lst);
extern int  utxo_lsm_put(void* lst, void* t, const u8* txid, u32 idx, u64 val, u64 h, u64 cb, const u8* spk, u32 slen);
extern int  csi_seed_from_walk(void* lst, void* u, long height);
extern void csi_on_add(const u8*, u32, u64, u64, u64, const u8*, unsigned long);
extern void csi_on_remove(const u8*, u32, u64, u64, u64, const u8*, unsigned long);
extern void csi_commit(long height);
extern void csi_on_block(long height);
extern int  csi_hist_query(long h, int want_digest, csi_hist_out_t* o);
extern long csi_hist_first(void), csi_hist_last(void);
extern void csi_set_chain(long halving_interval, int mainnet);
extern u64  csi_subsidy_at(long h);
struct lsm_state { long log_fd, idx_fd; u64 log_len, ckpt_log_off, ckpt_n; u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen; void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap; u64 next_run_no; void* tomb_hash_buf; u64 tomb_hash_mask; };
#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536
static int failures = 0;
static void ck(const char* l, int cond){ if (cond) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); failures++; } }
typedef struct { u8 txid[32]; u32 idx; u64 val, h, cb; u8 spk[32]; u32 slen; } coin_t;
static void mk_coin(coin_t* c, int tag, u64 val, u64 h, u64 cb){
    memset(c, 0, sizeof *c); memset(c->txid, 0xA0 + tag, 32); c->idx = (u32)tag; c->val = val; c->h = h; c->cb = cb;
    c->slen = 25; c->spk[0]=0x76; c->spk[1]=0xa9; c->spk[2]=0x14; memset(c->spk+3, 0x30+tag, 20); c->spk[23]=0x88; c->spk[24]=0xac;
}
int main(void){
    char td[] = "/tmp/bmc_csh_XXXXXX"; if (!mkdtemp(td) || chdir(td) != 0){ perror("tmpdir"); return 1; }
    printf("---- coinstats per-height rows ----\n");
    /* the set at height 100: two P2PKH coins */
    static struct lsm_state lst; coin_t coins[2]; mk_coin(&coins[0], 1, 1000000000ULL, 90, 1); mk_coin(&coins[1], 2, 250000000ULL, 95, 0);
    unsigned long slots = 1UL<<12; void* table = malloc((size_t)utxo_struct_size(slots)); void* blob = malloc(16UL<<20); utxo_init(table, slots, blob, 16UL<<20);
    memset(&lst, 0, sizeof lst); u64 op_th = slots*2, tomb_cap = op_th, desc_cap = slots*3;
    lst.op_threshold = op_th; lst.fill_threshold = slots*3/4; lst.tomb_buf = malloc(tomb_cap*36); lst.tomb_cap = tomb_cap;
    lst.manifest_buf = malloc(256*16); lst.manifest_cap = 256; lst.scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES; lst.scratch_buf = malloc(lst.scratch_cap);
    if (utxo_lsm_init(&lst) != 1){ printf("lsm init failed\n"); return 1; }
    for (int i = 0; i < 2; i++) if (utxo_lsm_put(&lst, table, coins[i].txid, coins[i].idx, coins[i].val, coins[i].h, coins[i].cb, coins[i].spk, coins[i].slen) != 1){ printf("put failed\n"); return 1; }
    csi_set_chain(150, 0);                                     /* regtest: halving every 150 blocks, no BIP30 heights */
    ck("subsidy schedule: 50 BTC at 0, 25 at 150, 12.5 at 300, 0 past 64 halvings", csi_subsidy_at(0) == 5000000000ULL && csi_subsidy_at(149) == 5000000000ULL && csi_subsidy_at(150) == 2500000000ULL && csi_subsidy_at(300) == 1250000000ULL && csi_subsidy_at(150L*64) == 0);
    ck("seeded from the walk at height 100", csi_seed_from_walk(&lst, table, 100) == 1);
    ck("rows cover 100..100 after the seed", csi_hist_first() == 100 && csi_hist_last() == 100);
    csi_hist_out_t o;
    ck("the baseline row is readable: the set is 2 coins, 12.5 BTC", csi_hist_query(100, 1, &o) == -1 && o.txouts == 2 && o.amount == 1250000000ULL && o.digest_valid);
    /* block 101: a coinbase of 25.001 BTC (subsidy 25 at height 101? no: 50 -- height 101 < 150) claiming fee 0.001 from spending coin 2 (2.5 BTC) into 2.499 BTC */
    u8 cbtx[32]; memset(cbtx, 0x11, 32); u8 spk[25] = {0x76,0xa9,0x14}; memset(spk+3, 0x77, 20); spk[23]=0x88; spk[24]=0xac;
    csi_on_add(cbtx, 0, 5000000000ULL + 100000ULL, 101, 1, spk, 25);              /* coinbase: subsidy + fee */
    csi_on_remove(coins[1].txid, coins[1].idx, coins[1].val, coins[1].h, coins[1].cb, coins[1].spk, coins[1].slen);   /* spends 2.5 BTC */
    u8 tx2[32]; memset(tx2, 0x22, 32);
    csi_on_add(tx2, 0, 250000000ULL - 100000ULL, 101, 0, spk, 25);               /* 2.499 BTC to a new output */
    csi_on_block(101); csi_commit(101);
    ck("row 101: 3 coins (2 - 1 spent + 2 new), amount 10 + 50.001 + 2.499", csi_hist_query(101, 0, &o) == 1 && o.txouts == 3 && o.amount == 1000000000ULL + 5000100000ULL + 249900000ULL);
    ck("row 101 block_info: prevout_spent 2.5, coinbase 50.001, new_outputs_ex_coinbase 2.499", o.d_prevout == 250000000ULL && o.d_coinbase == 5000100000ULL && o.d_new_ex_cb == 249900000ULL);
    ck("row 101: scripts/genesis/bip30 0, unclaimed 0 (the coinbase claimed subsidy + fee exactly)", o.d_scripts == 0 && o.d_genesis == 0 && o.d_bip30 == 0 && o.d_unclaimed == 0 && o.subsidy == 5000000000ULL);
    /* block 102: the coinbase claims only 49 BTC (1 unclaimed) and pays 0.5 BTC into an OP_RETURN output */
    u8 cb2[32]; memset(cb2, 0x33, 32); u8 nulldata[10] = {0x6a, 0x08, 1,2,3,4,5,6,7,8};
    csi_on_add(cb2, 0, 4900000000ULL, 102, 1, spk, 25);
    csi_on_add(cb2, 1, 50000000ULL, 102, 1, nulldata, 10);                         /* unspendable: not in the set, counted as scripts */
    csi_on_block(102); csi_commit(102);
    ck("row 102: 4 coins (the OP_RETURN output is not a coin), amount +49", csi_hist_query(102, 0, &o) == 1 && o.txouts == 4 && o.amount == 1000000000ULL + 5000100000ULL + 249900000ULL + 4900000000ULL);
    ck("row 102 block_info: coinbase 49, scripts 0.5, unclaimed 50 - 49 - 0.5 = 0.5", o.d_coinbase == 4900000000ULL && o.d_scripts == 50000000ULL && o.d_unclaimed == 50000000ULL && o.d_prevout == 0 && o.d_new_ex_cb == 0);
    /* block 103: nothing but a full coinbase; the digest at each height is distinct and stable */
    u8 cb3[32]; memset(cb3, 0x44, 32); csi_on_add(cb3, 0, 5000000000ULL, 103, 1, spk, 25); csi_on_block(103); csi_commit(103);
    csi_hist_out_t a, b, c; csi_hist_query(101, 1, &a); csi_hist_query(102, 1, &b); csi_hist_query(103, 1, &c);
    ck("rows cover 100..103", csi_hist_first() == 100 && csi_hist_last() == 103);
    ck("digests: valid at every height, all distinct", a.digest_valid && b.digest_valid && c.digest_valid && memcmp(a.digest, b.digest, 32) && memcmp(b.digest, c.digest, 32) && memcmp(a.digest, c.digest, 32));
    csi_hist_out_t a2; csi_hist_query(101, 1, &a2);
    ck("a row read twice gives the same digest and counters", !memcmp(a.digest, a2.digest, 32) && a.txouts == a2.txouts && a.d_prevout == a2.d_prevout);
    ck("no row: height 104 (not committed) and height 50 (before the baseline) answer 0", csi_hist_query(104, 0, &o) == 0 && csi_hist_query(50, 0, &o) == 0);
    /* ---- 2026-09-08: the base beneath the tail, and the seam between them ---- */
    printf("---- the base beneath the tail ----\n");
    { extern int csi_hist_check(int, char*, unsigned long); extern long csi_hist_base_to(void); extern void sha256_full(u8*, const void*, long);
      /* a base to 101 built from the tail's own rows 100 and 101 (generation 0),
       * with rows 0..99 below them (copies of row 100 at their own heights) */
      csh_row_t r100, r101; int tf = open(CSH_FILE, O_RDONLY);
      ck("read the tail's rows 100 and 101", tf >= 0 && pread(tf, &r100, sizeof r100, CSH_HDR + 100 * CSH_REC) == (ssize_t)sizeof r100 && pread(tf, &r101, sizeof r101, CSH_HDR + 101 * CSH_REC) == (ssize_t)sizeof r101); close(tf);
      int bf = open(CSH_BASE_FILE, O_RDWR | O_CREAT | O_TRUNC, 0644); u8* sums = malloc(102 * 32);
      for (long h = 0; h <= 101; h++){ csh_row_t r = h == 101 ? r101 : r100; r.height = h; r.gen = 0; sha256_full(r.sum, &r, sizeof r - 32); (void)!pwrite(bf, &r, sizeof r, CSH_HDR + h * CSH_REC); memcpy(sums + h * 32, r.sum, 32); }
      csh_base_header_t bh; memset(&bh, 0, sizeof bh); bh.magic = CSH_BASE_MAGIC; bh.version = 1; bh.rec = CSH_REC; bh.complete = 1; bh.to_height = 101; bh.n_rows = 102; sha256_full(bh.sum, sums, 102 * 32);
      (void)!pwrite(bf, &bh, sizeof bh, 0); close(bf); free(sums);
      ck("the base is complete to 101 and coverage now starts at 0 (last still 103)", csi_hist_base_to() == 101 && csi_hist_first() == 0 && csi_hist_last() == 103);
      ck("a height below the tail answers from the base", csi_hist_query(50, 1, &o) == 1 && o.txouts == 2 && o.digest_valid);
      ck("height 101 answers from the base with the same block_info the tail gave", csi_hist_query(101, 0, &o) == 1 && o.d_prevout == 250000000ULL && o.d_coinbase == 5000100000ULL);
      ck("height 102, the first above the base, keeps its block_info (its predecessor comes from the tail, not the base's generation-0 copy)", csi_hist_query(102, 0, &o) == 1 && o.d_coinbase == 4900000000ULL && o.d_scripts == 50000000ULL);
      char why[200];
      ck("the seam check passes: base and tail agree at height 100", csi_hist_check(1, why, sizeof why) == 1);
      /* a base whose rows are intact but disagree with the live index at the seam */
      bf = open(CSH_BASE_FILE, O_RDWR); csh_row_t bad = r100; bad.gen = 0; bad.txouts += 1; sha256_full(bad.sum, &bad, sizeof bad - 32); (void)!pwrite(bf, &bad, sizeof bad, CSH_HDR + 100 * CSH_REC);
      sums = malloc(102 * 32); for (long h = 0; h <= 101; h++){ csh_row_t r; (void)!pread(bf, &r, sizeof r, CSH_HDR + h * CSH_REC); memcpy(sums + h * 32, r.sum, 32); }
      sha256_full(bh.sum, sums, 102 * 32); (void)!pwrite(bf, &bh, sizeof bh, 0); close(bf); free(sums);
      ck("a base that disagrees with the live index at the seam is quarantined, naming the height", csi_hist_check(1, why, sizeof why) == -1 && strstr(why, "disagrees") && strstr(why, "height 100") && access(CSH_BASE_FILE, F_OK) != 0);
      ck("coverage is the tail's again: 100..103", csi_hist_first() == 100 && csi_hist_last() == 103); }

    /* a re-seed starts a new generation: its baseline has no block_info, and a delta across generations is refused */
    ck("re-seeded at 103 (a new generation)", csi_seed_from_walk(&lst, table, 103) == 1);
    ck("the re-seed's row 103 is a baseline: -1 (no block_info across generations)", csi_hist_query(103, 0, &o) == -1);
    ck("row 102 (the old generation) still reads with its block_info", csi_hist_query(102, 0, &o) == 1 && o.d_scripts == 50000000ULL);
    /* mainnet: the BIP30 duplicate coinbases' subsidy is counted as bip30, and genesis at 0 */
    csi_set_chain(210000, 1);
    ck("mainnet subsidy: 6.25 BTC at 700,000, 3.125 at 840,000", csi_subsidy_at(700000) == 625000000ULL && csi_subsidy_at(840000) == 312500000ULL);
    { extern int csi_bip30_unspendable(long);
      /* Core's IsBIP30Unspendable: the ORIGINALS 91,722 and 91,812, not the duplicates 91,842 and 91,880
       * (2026-09-09: the history base named the duplicates and disagreed with Core's MuHash from 91,722 on) */
      ck("BIP30 unspendable coinbases are the originals, 91,722 and 91,812", csi_bip30_unspendable(91722) && csi_bip30_unspendable(91812));
      ck("... and not the duplicates at 91,842 and 91,880", !csi_bip30_unspendable(91842) && !csi_bip30_unspendable(91880));
      csi_set_chain(150, 0);
      ck("no BIP30 heights off mainnet", !csi_bip30_unspendable(91722) && !csi_bip30_unspendable(91812));
      csi_set_chain(210000, 1); }
    printf("%s (%d failure(s))\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
