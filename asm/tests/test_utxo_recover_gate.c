/* test_utxo_recover_gate -- incident 2026-09-01: the download worker's
 * catch-up recovery is no longer blind.
 *
 * On 2026-09-01 eight consensus REJECTs ("input references a missing/
 * already-spent UTXO", b3d47a9's sparse-index offsets) were each answered
 * with utxo_live_recover() (a compaction) + retry, the retry passed, and
 * every round silently lost the spends of the block applied just before
 * the failure: 2,596 resurrected coins, muhash parity broken from 539,017.
 *
 * Contract under test (daemon/utxo_live.c):
 *   1. a consensus reject is classified as such; utxo_live_recovery_applicable()
 *      REFUSES compaction for it, and the set is untouched;
 *   2. a store error with a full manifest is the ONE case it admits; after
 *      utxo_live_recover(), utxo_live_verify_after_recovery(count_before)
 *      walks the set, finds it unchanged, and catch-up resumes;
 *   3. a post-recovery walk that disagrees with the pre-recovery count HALTS
 *      UTXO tracking: utxo_live_halted()==1 and every later catch-up is -1.
 * Synthetic regtest-style chain (mk_and_mine* from test_lsm_count_drift.c). */
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
    fprintf(stderr, "test_utxo_recover_gate: unexpected mempool_resolve_confirmed_utxo\n");
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
static long mk_and_mine_spend(u8* raw, u8 hash[32], u8 tx1_txid_out[32],
                              const u8 prev[32], const u8 spend_txid[32],
                              u32 tag, u32 tstamp){
    u8 cb[80], cb_txid[32];   /* 65-byte coinbase: 64 overflowed by one */
    u8* q = cb;
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
    long cblen = q - cb;
    if (!tx_txid(cb_txid, cb, (unsigned long)cblen, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (spend-block coinbase)\n"); failures++;
    }

    u8 tx1[128], tx1_txid[32];
    q = tx1;
    put32(q,1); q+=4;
    *q++ = 1;
    memcpy(q, spend_txid, 32); q+=32; put32(q,0); q+=4;
    *q++ = 0;
    put32(q,0xffffffffu); q+=4;
    *q++ = 1;
    put64(q, 40000000ULL); q+=8;
    *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long tx1len = q - tx1;
    if (!tx_txid(tx1_txid, tx1, (unsigned long)tx1len, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (tx1)\n"); failures++;
    }
    if (tx1_txid_out) memcpy(tx1_txid_out, tx1_txid, 32);

    u8 pair[64], root[32];
    memcpy(pair, cb_txid, 32); memcpy(pair+32, tx1_txid, 32);
    sha256d(root, pair, 64);

    u8* o = raw;
    put32(o,1); o+=4;
    memcpy(o, prev, 32); o+=32;
    memcpy(o, root, 32); o+=32;
    put32(o, tstamp); o+=4;
    put32(o, 0x207fffffu); o+=4;
    put32(o, 0); o+=4;
    *o++ = 2;
    memcpy(o, cb, (size_t)cblen); o += cblen;
    memcpy(o, tx1, (size_t)tx1len); o += tx1len;
    long len = o - raw;

    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}


typedef struct { long log_fd, idx_fd; u64 log_len, ckpt_log_off, ckpt_n; u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen; void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap; u64 next_run_no; void* tomb_hash_buf; u64 tomb_hash_mask; } lsm_view_t;
extern void* utxo_live_test_lst(void);
extern long  utxo_live_recover(void);
extern long  utxo_live_recovery_applicable(void);
extern long  utxo_live_verify_after_recovery(long count_before);
extern long  utxo_live_halted(void);
extern long  utxo_live_last_fail_kind(void);
extern long  utxo_live_last_fail_height(void);
extern const char* utxo_live_last_reject(void);

static u8 store_buf[4096];
static u8 raw[512];

int main(void){
    tt_isolate();
    memset(store_buf,0,sizeof store_buf);
    if (store_init(store_buf)!=1){ printf("FAIL store_init\n"); return 1; }
    if (utxo_live_init(".")!=1){ printf("FAIL utxo_live_init\n"); return 1; }
    utxo_live_set_flush_thresholds(64, 128);          /* several runs out of 150 blocks */
    lsm_view_t* lst = (lsm_view_t*)utxo_live_test_lst();

    /* ---- base chain: 150 coinbase-only blocks, flush-heavy ---- */
    long n1 = 150;
    u8 prev[32]; memset(prev,0,32);
    u8 height0_txid[32];
    for (long h=0; h<n1; h++){
        u8 hash[32], cbt[32];
        long len = mk_and_mine(raw, hash, cbt, prev, (u32)h, 1600000000u+(u32)h);
        if (h==0) memcpy(height0_txid, cbt, 32);
        if (store_append(store_buf, hash, raw, len)!=h){ printf("FAIL append %ld\n",h); failures++; }
        memcpy(prev, hash, 32);
    }
    ck("base catch-up applies 150", utxo_live_catchup(store_buf), n1);
    ck("no failure recorded after a clean catch-up", utxo_live_last_fail_kind(), 0);
    printf("manifest_n after base = %lu\n", (unsigned long)lst->manifest_n);
    if (lst->manifest_n < 2){ printf("FAIL fixture: need >=2 runs, have %lu\n", (unsigned long)lst->manifest_n); return 1; }

    /* ---- 2. store error with a FULL manifest: the one admitted case ---- */
    long next_h = n1;
    u8 chain_txid[32]; memcpy(chain_txid, height0_txid, 32);
    u64 saved_cap = lst->manifest_cap;
    lst->manifest_cap = lst->manifest_n;              /* "full": mac_flush must refuse the next run */
    utxo_live_set_flush_thresholds(1, 1);             /* the next put flushes */
    { u8 hash[32], t1[32];
      long len = mk_and_mine_spend(raw, hash, t1, prev, chain_txid, (u32)next_h, 1600001000u);
      if (store_append(store_buf, hash, raw, len) != next_h){ printf("FAIL append spend %ld\n", next_h); failures++; }
      memcpy(prev, hash, 32); memcpy(chain_txid, t1, 32); }
    long count_before = utxo_live_count();
    ck("catch-up fails under a full manifest", utxo_live_catchup(store_buf), -1);
    ck("classified as a STORE error (2)", utxo_live_last_fail_kind(), 2);
    ck("failure height is the block that could not apply", utxo_live_last_fail_height(), next_h);
    ck("applied height did not move", utxo_live_applied_height(), n1-1);
    ck("count unchanged after the rolled-back failure", utxo_live_count(), count_before);
    ck("recovery IS applicable (store error + full manifest)", utxo_live_recovery_applicable(), 1);
    lst->manifest_cap = saved_cap;                    /* let the compaction publish */
    utxo_live_set_flush_thresholds(64, 128);
    long rounds = utxo_live_recover();
    ck("recover() compacted at least one round", rounds > 0, 1);
    ck("post-recovery walk == pre-recovery count", utxo_live_verify_after_recovery(count_before), 1);
    ck("not halted", utxo_live_halted(), 0);
    ck("catch-up resumes and applies the pending block", utxo_live_catchup(store_buf), 1);
    ck("count == walk after resume", utxo_live_count(), utxo_live_walk_count());
    ck("net +1 for the spend block (1 coinbase + 1 out - 1 in)", utxo_live_walk_count(), n1 + 1);
    next_h++;

    /* ---- 1. consensus reject: NOT admitted, set untouched ---- */
    u8 bogus[32]; memset(bogus, 0xAB, 32);            /* no such outpoint */
    { u8 hash[32], t1[32];
      long len = mk_and_mine_spend(raw, hash, t1, prev, bogus, (u32)next_h, 1600002000u);
      if (store_append(store_buf, hash, raw, len) != next_h){ printf("FAIL append bogus %ld\n", next_h); failures++; }
      memcpy(prev, hash, 32); }
    long count_pre_reject = utxo_live_count();
    ck("catch-up rejects the block spending a missing outpoint", utxo_live_catchup(store_buf), -1);
    ck("classified as a consensus REJECT (1)", utxo_live_last_fail_kind(), 1);
    printf("reject reason: %s\n", utxo_live_last_reject());
    ck("reject reason is set", utxo_live_last_reject()[0] != 0, 1);
    ck("recovery REFUSED for a consensus reject", utxo_live_recovery_applicable(), 0);
    ck("count unchanged (block rolled back)", utxo_live_count(), count_pre_reject);
    ck("walk unchanged", utxo_live_walk_count(), count_pre_reject);
    ck("applied height stays below the bad block", utxo_live_applied_height(), next_h - 1);
    ck("still not halted (a reject is retried from the checkpoint, never compacted)", utxo_live_halted(), 0);
    ck("a second attempt fails the same way (deterministic)", utxo_live_catchup(store_buf), -1);
    ck("still a REJECT", utxo_live_last_fail_kind(), 1);
    { unsigned long n_before = (unsigned long)lst->manifest_n;
      ck("manifest untouched by the refused recovery", (long)lst->manifest_n, (long)n_before); }

    /* ---- 3. a post-recovery walk that disagrees HALTS tracking ---- */
    long truth = utxo_live_count();
    ck("verify with a wrong pre-recovery count fails", utxo_live_verify_after_recovery(truth + 7), 0);
    ck("halted", utxo_live_halted(), 1);
    ck("catch-up refuses to run while halted", utxo_live_catchup(store_buf), -1);
    ck("a correct count does not un-halt (halt is for the life of the process)", utxo_live_verify_after_recovery(truth), 0);
    ck("still halted", utxo_live_halted(), 1);

    utxo_live_close();
    printf("%s (%d failures)\n", failures ? "FAILED" : "ALL PASS", failures);
    return failures ? 1 : 0;
}
