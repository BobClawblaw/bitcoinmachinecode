/* tests/test_utxo_ckpt_batch.c -- checkpoint BATCHING during catch-up.
 *
 * Every applied block used to end with tmp+fsync+rename+dirfsync of the
 * height file plus the coinstats commit: ~1.9 ms on the production NVMe,
 * 50 ms on a HDD (measured 2026-08-31), against a ~3 ms apply. Far from the
 * tip the checkpoint now lands every UTXO_CKPT_BATCH_BLOCKS blocks (or 2 s),
 * so a kill mid-batch leaves up to that many GHOST blocks: durably applied,
 * never checkpointed. That is the multi-block ghost run boot recovery
 * already heals (utxo_live_recover_partial_block, descending rollback from
 * the undo files) -- this test proves the batch stays inside what recovery
 * can undo, end to end, with a real fork+_exit crash:
 *   1. utxo_live_ckpt_due(): the pure decision (pinned without a chain);
 *   2. a child applies 5 spend blocks under batching and dies before any
 *      checkpoint; the parent reopens, sees applied=149, rolls the 5 ghosts
 *      back and re-applies them -- final height, count and a spent-coin probe
 *      match a never-crashed application;
 *   3. a CLEAN close mid-batch persists the pending checkpoint. */
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
extern long utxo_live_applied_height(void);
extern void utxo_live_close(void);
extern void utxo_live_test_set_crash_after(long n);
extern void utxo_live_test_set_ckpt_batch(long n);
extern int  utxo_live_ckpt_due(long h, long tip, long unpersisted, long long now_ms, long long last_ms, long forced);
extern long utxo_live_resolve(const u8 txid[32], unsigned long index, unsigned long long* value, unsigned long* height,
                              unsigned long* is_coinbase, const u8** script, unsigned long* slen);

/* Never actually reached -- every prevout here is already confirmed on
 * chain, not mempool-chained -- but bitcoin_mempool_policy.c's object
 * resolves this extern, so link needs a definition. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_utxo_catchup_crash_resume: unexpected call to mempool_resolve_confirmed_utxo\n");
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

static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }

static u8 g_txid_scratch[1<<12];

/* Same shape as test_utxo_checkpoint.c / test_apply_block_rollback.c's own
 * mk_and_mine: one coinbase tx, scriptPubKey = OP_1, minimum difficulty. */
static long mk_and_mine(u8* raw, u8 hash[32], const u8 prev[32], u32 tag, u32 tstamp){
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

/* One coinbase (OP_1 payout) + tx1 (spends `spend_txid:0`, empty scriptSig
 * against OP_1 -- valid, creates one new OP_1 output). Both txs are entirely
 * ordinary and succeed. Merkle root over 2 leaves: sha256d(cb_txid||tx1_txid). */
static long mk_and_mine_spend(u8* raw, u8 hash[32], const u8 prev[32],
                              const u8 spend_txid[32], u32 tag, u32 tstamp){
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
    *q++ = 1;                        /* n_in */
    memcpy(q, spend_txid, 32); q+=32; put32(q,0); q+=4;   /* prevout */
    *q++ = 0;                        /* scriptSig len 0 -- valid vs OP_1 */
    put32(q,0xffffffffu); q+=4;      /* sequence */
    *q++ = 1;                        /* n_out */
    put64(q, 40000000ULL); q+=8;
    *q++ = 1; *q++ = 0x51;           /* scriptPubKey: OP_1 */
    put32(q,0); q+=4;                /* locktime */
    long tx1len = q - tx1;
    if (!tx_txid(tx1_txid, tx1, (unsigned long)tx1len, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (tx1)\n"); failures++;
    }

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
    *o++ = 2;                         /* n_tx */
    memcpy(o, cb, (size_t)cblen); o += cblen;
    memcpy(o, tx1, (size_t)tx1len); o += tx1len;
    long len = o - raw;

    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

static u8 store_buf[4096];

static u8 store_buf[4096];
int main(void){
    tt_isolate();
    printf("== 1. the decision ==\n");
    /* (h, tip, unpersisted, now, last, forced) */
    ckm("far behind, batch not full, fresh: not due",        !utxo_live_ckpt_due(1000, 100000, 10, 5000, 4000, -1));
    ckm("far behind, batch full: due",                        utxo_live_ckpt_due(1000, 100000, 64, 5000, 4000, -1));
    ckm("far behind, 2 s since last: due",                    utxo_live_ckpt_due(1000, 100000, 1, 6000, 4000, -1));
    ckm("within 64 of the tip: due every block",              utxo_live_ckpt_due(99950, 100000, 1, 5000, 4999, -1));
    ckm("at the tip: due",                                    utxo_live_ckpt_due(100000, 100000, 1, 5000, 4999, -1));
    ckm("forced 0 (per-block): due",                          utxo_live_ckpt_due(1000, 100000, 1, 5000, 4999, 0));
    ckm("forced 64 near the tip: still batching (test knob)", !utxo_live_ckpt_due(99999, 100000, 5, 5000, 4999, 64));
    ckm("forced 64, 64 unpersisted: due",                     utxo_live_ckpt_due(99999, 100000, 64, 5000, 4999, 64));

    printf("== 2. crash mid-batch: 5 ghost blocks ==\n");
    memset(store_buf,0,sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);
    long n1 = 150;
    u8 prev[32]; memset(prev,0,32);
    u8 cb_txid[8][32];
    for (long h=0; h<n1; h++){
        u8 raw[256], hash[32];
        long len = mk_and_mine(raw, hash, prev, 0x70000000u+(u32)h, 1900000000u+(u32)h);
        long r = store_append(store_buf, hash, raw, len);
        if (r != h) { printf("FAIL store_append h=%ld got=%ld\n", h, r); failures++; }
        if (h < 8) memcpy(cb_txid[h], raw+36, 32);      /* 1-tx block: merkle root == coinbase txid */
        memcpy(prev, hash, 32);
    }
    ck("clean chain applied", utxo_live_catchup(store_buf), n1);
    ck("checkpointed at 149", utxo_live_applied_height(), n1-1);
    ck("count 150", utxo_live_count(), n1);
    utxo_live_close();
    /* five spend blocks 150..154, each spending coinbase h (mature), net +1 */
    for (long k = 0; k < 5; k++){
        u8 raw[512], hash[32];
        long len = mk_and_mine_spend(raw, hash, prev, cb_txid[k], 0x80000000u+(u32)k, 1900100000u+(u32)k);
        long r = store_append(store_buf, hash, raw, len);
        if (r != n1+k) { printf("FAIL store_append spend %ld got=%ld\n", k, r); failures++; }
        memcpy(prev, hash, 32);
    }
    utxo_live_test_set_ckpt_batch(64);        /* batch even though we are at the tip */
    utxo_live_test_set_crash_after(5);        /* die after 5 applied, no checkpoint reached */
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0){
        if (utxo_live_init(".") != 1) _exit(2);
        long ar = utxo_live_catchup(store_buf);
        fprintf(stderr, "test_utxo_ckpt_batch: crash hook did not fire (ar=%ld)\n", ar);
        _exit(3);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) { perror("waitpid"); return 1; }
    ckm("child died via the crash hook after 5 blocks", WIFEXITED(status) && WEXITSTATUS(status)==1);
    utxo_live_test_set_crash_after(-1);
    int undo_present = 0; for (long h = 150; h < 155; h++){ char p[64]; snprintf(p,sizeof p,"undo_%ld.dat",h); if (access(p,F_OK)==0) undo_present++; }
    ck("all 5 ghosts left their undo files (recovery's evidence)", undo_present, 5);
    ck("reopen", utxo_live_init("."), 1);
    ck("checkpoint still 149: none of the 5 was persisted", utxo_live_applied_height(), n1-1);
    long re = utxo_live_catchup(store_buf);        /* rolls back 154..150, re-applies 150..154 */
    ck("recovery + re-apply applied 5", re, 5);
    ck("applied height 154", utxo_live_applied_height(), n1+4);
    ck("count 155 (each spend block nets +1)", utxo_live_count(), n1+5);
    { unsigned long long v; unsigned long hh, cb, sl; const u8* sc;
      ckm("coinbase 0 is SPENT after re-apply (no double-apply, no lost rollback)", utxo_live_resolve(cb_txid[0], 0, &v, &hh, &cb, &sc, &sl) != 1);
      ckm("coinbase 4 is SPENT (the last ghost's spend survived rollback + re-apply)", utxo_live_resolve(cb_txid[4], 0, &v, &hh, &cb, &sc, &sl) != 1);
      ckm("coinbase 7 (never spent) still resolves", utxo_live_resolve(cb_txid[7], 0, &v, &hh, &cb, &sc, &sl) == 1); }
    undo_present = 0; for (long h = 150; h < 155; h++){ char p[64]; snprintf(p,sizeof p,"undo_%ld.dat",h); if (access(p,F_OK)==0) undo_present++; }
    ck("re-applied blocks have fresh undo files", undo_present, 5);
    ck("nothing left to apply", utxo_live_catchup(store_buf), 0);

    printf("== 3. clean close mid-batch persists ==\n");
    for (long k = 0; k < 5; k++){
        u8 raw[256], hash[32];
        long len = mk_and_mine(raw, hash, prev, 0x71000000u+(u32)k, 1900200000u+(u32)k);
        long r = store_append(store_buf, hash, raw, len);
        if (r != n1+5+k) { printf("FAIL store_append h=%ld got=%ld\n", n1+5+k, r); failures++; }
        memcpy(prev, hash, 32);
    }
    ck("applied 5 more under batching", utxo_live_catchup(store_buf), 5);
    utxo_live_close();                          /* must flush the pending checkpoint */
    utxo_live_test_set_ckpt_batch(-1);
    ck("reopen", utxo_live_init("."), 1);
    ck("clean close persisted the batched checkpoint: 159", utxo_live_applied_height(), n1+9);
    ck("nothing to recover or apply", utxo_live_catchup(store_buf), 0);
    utxo_live_close();
    printf("\n%s (%d failure%s)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures, failures==1?"":"s");
    return failures ? 1 : 0;
}
