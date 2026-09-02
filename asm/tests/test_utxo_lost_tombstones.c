/* tests/test_utxo_lost_tombstones.c -- incident 2026-09-01 at the DAEMON layer:
 * the regtest-shaped repro of the 2,596 resurrected coins, and the regression
 * test for the fix.
 *
 * Mechanism (found with this test, 2026-09-02): production replayed with undo
 * capture on (g_undo_enabled defaults to 1), so every spend went through
 * undo_capture_and_del = utxo_lsm_get THEN utxo_lsm_del. Under b3d47a9 a
 * memtable flush wrote runs whose sparse-index samples were short by the
 * buffered bytes; every lookup that landed in such a stride MISSED (~10-15% of
 * a run's coins with mainnet's 22-34-byte scripts). A flush lands in the middle
 * of a block; for the spends after that point whose coins had just gone into
 * the fresh run, the capture's lookup missed, returned 0, and live_on_input
 * treated 0 as "already absent -- a crash-resumed re-apply": the spend was
 * SKIPPED and the coin survived. Verification of the NEXT block then missed
 * too and rejected, the blind recovery compacted (correct offsets again) and
 * the retry passed -- so the damage was exactly the post-flush spends of the
 * block the flush landed in, at the lookup-miss rate: 491, 35, 389, 280, 395,
 * 408, 127, 471.
 *
 * Fixture: 32-transaction blocks, 2 spends + 6 outputs each (34-byte spendable
 * scripts -> 86-byte records, so the 1 MB drain lands mid-record), flush every
 * ~100 blocks, undo capture ON, and the old daemon/main.c recovery loop
 * (utxo_live_recover() + retry, no gate) at each failure.
 *   - tests/test_utxo_lost_tombstones      shipped LSM object: no rejects, exact.
 *   - tests/test_utxo_lost_tombstones_bad  tests/bitcoin_utxo_lsm_badsparse.o
 *     (the read-side fix compiled out) -DEXPECT_INCIDENT: the trigger must fire
 *     at every flush AND the set must stay exact anyway -- live_on_input now
 *     fails the block on an absent coin (store inconsistency) instead of
 *     skipping the spend. Before that fix this build reported
 *     "walk=65000 expected=64989 resurrected_spent=11 of 31904": +10 at the
 *     first flush, +1 at the second, exactly the production shape. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long store_init(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  pow_check(const u8 hdr[80]);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
extern void sha256d(u8 out[32], const void* msg, long len);

extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_count(void);
extern long utxo_live_walk_count(void);
extern void utxo_live_set_flush_thresholds(u64 fill, u64 op);
extern long utxo_live_applied_height(void);
extern long utxo_live_apply_block(const u8* blk, u64 len, long height);
extern void utxo_live_close(void);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u;(void)txid;(void)index;(void)value;(void)script;(void)slen;
    fprintf(stderr, "test_utxo_lost_tombstones: unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }

static u8 g_txid_scratch[1<<12];

/* Coinbase-only block, scriptPubKey OP_1, min difficulty (same shape as
 * test_utxo_catchup_crash_resume.c). Returns len; fills hash + cb txid. */
static long mk_and_mine(u8* raw, u8 hash[32], u8 cb_txid_out[32],
                        const u8 prev[32], u32 tag, u32 tstamp){
    u8 tx[80], txid[32];   /* 65-byte coinbase: 64 overflowed by one (see test_blk_dryrun.c) */
    u8* q = tx;
    put32(q,1); q+=4;
    *q++ = 1;
    memset(q,0,32); q+=32;
    put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4;
    put32(q,0xffffffffu); q+=4;
    *q++ = 1;
    put64(q, 50000000ULL); q+=8;
    *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long txlen = q - tx;
    if (!tx_txid(txid, tx, (unsigned long)txlen, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (coinbase)\n"); failures++;
    }
    if (cb_txid_out) memcpy(cb_txid_out, txid, 32);

    u8* o = raw;
    put32(o,1); o+=4;
    memcpy(o, prev, 32); o+=32;
    memcpy(o, txid, 32); o+=32;
    put32(o, tstamp); o+=4;
    put32(o, 0x207fffffu); o+=4;
    put32(o, 0); o+=4;
    *o++ = 1;
    memcpy(o, tx, (size_t)txlen); o += txlen;
    long len = o - raw;

    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

/* Coinbase + tx1 spending `spend_txid`:0 (empty scriptSig vs OP_1 -- valid),
 * creating one new OP_1 output. Fills tx1's txid so the NEXT block can chain
 * its spend onto this one. */

/* Block = coinbase + M transactions. Tx j (1..M) spends 1-2 inputs handed in by the
 * caller and creates KO outputs, each a 34-byte spendable script (OP_TRUE + 33 x OP_NOP):
 * 86-byte store records throughout, so the flush buffer's 1 MB drain lands mid-record
 * (a 53-byte record never straddles it; production's mixed 22-34-byte scripts do). With
 * ~200 records per block the memtable flush lands in the MIDDLE of a block, with spends
 * of fresh-run coins still to come in that block -- the production shape. */
enum { M = 32, KO = 6, MAXIN = 2 };
typedef struct { u8 txid[32]; u32 idx; u64 value; } inp_t;
static u8 g_blk[1 << 20];
static long mk_block_m(u8* raw, u8 hash[32], u8 (*txids_out)[32], u64* out0_val, const u8 prev[32],
                       const inp_t (*ins)[MAXIN], const int* nins, u32 tstamp){
    u8 cb[80], cb_txid[32]; u8* q = cb;
    put32(q,1); q+=4; *q++ = 1; memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tstamp); q+=4; put32(q,0xffffffffu); q+=4;
    *q++ = 1; put64(q, 50000000ULL); q+=8; *q++ = 1; *q++ = 0x51; put32(q,0); q+=4;
    long cblen = q - cb;
    if (!tx_txid(cb_txid, cb, (unsigned long)cblen, g_txid_scratch, sizeof g_txid_scratch)) { printf("FAIL tx_txid cb\n"); failures++; }
    u8* o = raw; put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; u8* root_at = o; o+=32; put32(o, tstamp); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
    *o++ = (u8)(M + 1); memcpy(o, cb, (size_t)cblen); o += cblen;
    static u8 leaves[M + 1][32]; memcpy(leaves[0], cb_txid, 32);
    for (int j = 1; j <= M; j++){
        u8* t = o; q = t;
        put32(q,1); q+=4; *q++ = (u8)nins[j];
        u64 in_sum = 0;
        for (int i = 0; i < nins[j]; i++){ memcpy(q, ins[j][i].txid, 32); q+=32; put32(q, ins[j][i].idx); q+=4; *q++ = 0; put32(q,0xffffffffu); q+=4; in_sum += ins[j][i].value; }
        *q++ = KO;
        u64 v0 = in_sum - (u64)(KO - 1) * 1000 - 1000; out0_val[j] = v0;
        for (int k = 0; k < KO; k++){ put64(q, k == 0 ? v0 : 1000ULL); q+=8; *q++ = 34; *q++ = 0x51; for (int z = 0; z < 33; z++) *q++ = 0x61; }
        put32(q,0); q+=4;
        long tl = q - t;
        if (!tx_txid(txids_out[j], t, (unsigned long)tl, g_txid_scratch, sizeof g_txid_scratch)) { printf("FAIL tx_txid tx%d\n", j); failures++; }
        memcpy(leaves[j], txids_out[j], 32);
        o = q;
    }
    /* merkle root over M+1 leaves (duplicate the last on odd levels, as Bitcoin does) */
    int n = M + 1; static u8 lvl[M + 2][32]; memcpy(lvl, leaves, (size_t)n * 32);
    while (n > 1){
        if (n & 1){ memcpy(lvl[n], lvl[n-1], 32); n++; }
        for (int i = 0; i < n / 2; i++){ u8 pair[64]; memcpy(pair, lvl[2*i], 32); memcpy(pair+32, lvl[2*i+1], 32); sha256d(lvl[i], pair, 64); }
        n /= 2;
    }
    memcpy(root_at, lvl[0], 32);
    long len = o - raw;
    u32 nonce = 0; while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}
extern long utxo_live_recover(void);
extern long utxo_live_last_fail_kind(void);
extern const char* utxo_live_last_reject(void);
extern long utxo_lsm_get(void* lst, void* u, const u8* txid, unsigned index, u64* value, unsigned long* height, unsigned long* cb, const u8** script, unsigned long* slen);
extern void* utxo_live_test_lst(void); extern void* utxo_live_test_tbl(void);
typedef struct { long log_fd, idx_fd; u64 log_len, ckpt_log_off, ckpt_n; u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen; void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap; u64 next_run_no; void* tomb_hash_buf; u64 tomb_hash_mask; } lsm_view_t;
static u8 store_buf[4096];
static u8 rawb[4096];
enum { NBLK = 700, MATURE = 200 };   /* coinbases 1..96 are spent at 200..202: all >= 100 deep */
static u8  cbid[MATURE][32];
static u8  txids[NBLK + 1][M + 1][32];
static u64 out0[NBLK + 1][M + 1];
static u8  spent[NBLK * M * MAXIN][32]; static u32 spent_idx[NBLK * M * MAXIN]; static long nspent = 0;
int main(void){
    tt_isolate();
    memset(store_buf,0,sizeof store_buf);
    if (store_init(store_buf)!=1){ printf("FAIL store_init\n"); return 1; }
    if (utxo_live_init(".")!=1){ printf("FAIL utxo_live_init\n"); return 1; }
    /* undo capture stays ON: production's replay ran with g_undo_enabled=1 (its default; main.c
     * never clears it), so every spend went through undo_capture_and_del = utxo_lsm_get THEN del */
    const long FILL = 20000;                       /* ~193 records/block -> a flush every ~100 blocks, 1.7 MB runs */
#ifdef EXPECT_INCIDENT
    printf("== object: badsparse (b3d47a9) through utxo_live, undo capture on -- expecting flush-time rejects and the loss ==\n");
#else
    printf("== object: shipped, through utxo_live, undo capture on -- expecting exactness ==\n");
#endif
    u8 prev[32]; memset(prev,0,32); u8 hash[32], t1[32];
    long rejects = 0, recoveries = 0, applied_total = 0, expected = 0, halted_at = -1, expected_at_halt = -1;
    for (long h = 0; h < MATURE; h++){
        long len = mk_and_mine(rawb, hash, t1, prev, (u32)h, 1600000000u + (u32)h);
        memcpy(cbid[h], t1, 32);
        if (store_append(store_buf, hash, rawb, len)!=h){ printf("FAIL append %ld\n", h); return 1; }
        memcpy(prev, hash, 32); expected += 1;
    }
    ck("mature prefix applied", utxo_live_catchup(store_buf), MATURE); applied_total += MATURE;
    extern void utxo_live_test_set_bulk_mode(int on); utxo_live_test_set_bulk_mode(1);
    lsm_view_t* lst = (lsm_view_t*)utxo_live_test_lst();
    unsigned long last_mn = (unsigned long)lst->manifest_n;
    static inp_t ins[M + 1][MAXIN]; static int nins[M + 1];
    for (long h = MATURE; h <= NBLK; h++){
        /* tx j: input 0 = out0 of tx j two blocks back (or a mature coinbase for the first three
         * blocks); input 1 = out1 of tx j five blocks back once that exists */
        for (int j = 1; j <= M; j++){
            int n = 0;
            if (h < MATURE + 3){ long c = (h - MATURE) * M + j; memcpy(ins[j][0].txid, cbid[c], 32); ins[j][0].idx = 0; ins[j][0].value = 50000000ULL; n = 1; }
            else { memcpy(ins[j][0].txid, txids[h-2][j], 32); ins[j][0].idx = 0; ins[j][0].value = out0[h-2][j]; n = 1; }
            if (h - 5 >= MATURE){ memcpy(ins[j][1].txid, txids[h-5][j], 32); ins[j][1].idx = 1; ins[j][1].value = 1000ULL; n = 2; }
            nins[j] = n;
        }
        long len = mk_block_m(g_blk, hash, txids[h], out0[h], prev, (const inp_t (*)[MAXIN])ins, nins, 1600000000u + (u32)h);
        if (store_append(store_buf, hash, g_blk, len)!=h){ printf("FAIL append %ld\n", h); return 1; }
        for (int j = 1; j <= M; j++) for (int i = 0; i < nins[j]; i++){ memcpy(spent[nspent], ins[j][i].txid, 32); spent_idx[nspent] = ins[j][i].idx; nspent++; }
        memcpy(prev, hash, 32);
        expected += 1; for (int j = 1; j <= M; j++) expected += KO - nins[j];
        utxo_live_set_flush_thresholds(FILL, 1u<<30);   /* the caught-up downshift resets these after every call */
        long ar = utxo_live_catchup(store_buf);
        extern long utxo_live_halted(void);
        if (ar < 0 && utxo_live_halted()){
            rejects++; halted_at = h; expected_at_halt = expected - (1 + KO*M - 2*M);   /* the failed block: 1 cb + 32*(6-2) */
            printf("  HALTED at height %ld (%s): walk=%ld count=%ld expected(before this block)=%ld\n", h, utxo_live_last_reject(), utxo_live_walk_count(), utxo_live_count(), expected_at_halt);
            break;
        }
        if (ar < 0){
            rejects++;
            printf("  round %ld: REJECT at height %ld kind=%ld (%s) manifest_n=%lu walk=%ld count=%ld expected(before)=%ld\n",
                   rejects, h, utxo_live_last_fail_kind(), utxo_live_last_reject(), (unsigned long)lst->manifest_n, utxo_live_walk_count(), utxo_live_count(), expected - (1 + KO*M - 0) );
            for (int attempt = 1; attempt <= 3 && ar < 0; attempt++){
                long r = utxo_live_recover(); recoveries += (r > 0);
                utxo_live_set_flush_thresholds(FILL, 1u<<30);
                ar = utxo_live_catchup(store_buf);
                printf("    attempt %d: recover rounds=%ld -> retry ar=%ld manifest_n=%lu walk=%ld count=%ld expected=%ld drift=%+ld\n",
                       attempt, r, ar, (unsigned long)lst->manifest_n, utxo_live_walk_count(), utxo_live_count(), expected, utxo_live_walk_count() - expected);
            }
            if (ar < 0){ printf("  FAIL retry still failing at %ld\n", h); failures++; break; }
        }
        applied_total += ar;
        if ((unsigned long)lst->manifest_n != last_mn){
            printf("  h=%ld manifest_n %lu -> %lu (walk=%ld count=%ld expected=%ld drift=%+ld)\n", h, last_mn, (unsigned long)lst->manifest_n, utxo_live_walk_count(), utxo_live_count(), expected, utxo_live_walk_count() - expected);
            last_mn = (unsigned long)lst->manifest_n;
        }
    }
    long walk = utxo_live_walk_count(), cnt = utxo_live_count();
    long res = 0;
    for (long i = 0; i < nspent; i++){ u64 v; unsigned long hh, cb, sl; const u8* sp;
        if (utxo_lsm_get(utxo_live_test_lst(), utxo_live_test_tbl(), spent[i], spent_idx[i], &v, &hh, &cb, &sp, &sl) == 1) res++; }
    printf("  final: applied=%ld rejects=%ld recoveries=%ld walk=%ld count=%ld expected=%ld resurrected_spent=%ld of %ld\n",
           applied_total, rejects, recoveries, walk, cnt, expected, res, nspent);
#ifndef EXPECT_INCIDENT
    ck("all blocks applied", applied_total, NBLK + 1);
#endif
#ifdef EXPECT_INCIDENT
    extern long utxo_live_store_inconsistencies(void);
    ck("TRIGGER: the flush-time lie reached the apply path (store-inconsistency counter > 0)", utxo_live_store_inconsistencies() > 0, 1);
    ck("FIX: UTXO tracking HALTED at the first lying lookup, nothing was skipped", halted_at > 0, 1);
    /* the set must be the exact pre-block state: the partial apply rolled back without trusting a lookup */
    ck("FIX: walk == the state before the failed block", walk, expected_at_halt);
    /* point lookups through the still-bad run lie (that is the whole incident), so make
     * them honest first: a compaction rewrites the run with correct offsets. The walk
     * above is already the ground truth; this just lets the key-by-key check run. */
    ck("compaction after the halt (correct offsets; the set is unchanged)", utxo_live_recover() >= 0, 1);
    ck("walk unchanged by the compaction", utxo_live_walk_count(), expected_at_halt);
    { long res_pre = 0;   /* spends of blocks before the halt: none may have come back */
      long n_pre = 0; for (long h2 = MATURE; h2 < halted_at; h2++) for (int j = 1; j <= M; j++) n_pre += (h2 < MATURE + 3) ? 1 : (h2 - 5 >= MATURE ? 2 : 1);
      for (long i = 0; i < n_pre && i < nspent; i++){ u64 v; unsigned long hh, cb, sl; const u8* sp;
          if (utxo_lsm_get(utxo_live_test_lst(), utxo_live_test_tbl(), spent[i], spent_idx[i], &v, &hh, &cb, &sp, &sl) == 1) res_pre++; }
      printf("  spends of the %ld blocks before the halt: %ld of %ld read back as live\n", halted_at - MATURE, res_pre, n_pre);
      ck("FIX: no spend before the halt was lost", res_pre, 0); }
    ck("a halted node refuses further catch-up", utxo_live_catchup(store_buf) < 0, 1);
#else
    ck("no rejects with the shipped object", rejects, 0);
    ck("walk exact", walk, expected);
    ck("counter exact", cnt, expected);
    ck("no spent coin resurrected", res, 0);
#endif
    utxo_live_close();
    printf("%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL PASS", failures);
    return failures ? 1 : 0;
}
