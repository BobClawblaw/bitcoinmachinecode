/* tests/test_utxo_catchup_crash_resume.c -- an unclean process death IN THE
 * MIDDLE of a utxo_live_catchup() call must not corrupt the resumed catch-up
 * on the next boot.
 *
 * Root cause this guards (found live in production 2026-08-21): before this
 * fix, utxo_live_catchup only ever persisted its resumable applied-height
 * checkpoint at a (rare, during bulk mode) compaction or once at the very
 * end of the whole call -- see the "REVERTED (2026-08-19)" history that used
 * to sit in daemon/utxo_live.c right where the per-block persist_applied_
 * height() call now lives. Every individual utxo_lsm_put/del is ALREADY
 * durable the instant it's called (synchronous WAL write, independent
 * crash-safe manifest publish on flush) -- so a process death any time after
 * a block finished applying left the on-disk UTXO state genuinely further
 * along than the persisted checkpoint claimed, by however many blocks (or
 * hours) had elapsed since the last compaction. On restart, catch-up trusted
 * the stale checkpoint and re-verified the next block from scratch --
 * whose inputs it had already, durably, spent in the crashed run -- and
 * rejected it as "input references a missing/already-spent UTXO", exactly
 * matching what happened live at height 363897 after a checkpoint taken at
 * height 363896's mid-catchup compact.
 *
 * (The 2026-08-19 session that first found a symptom of this had it
 * backwards: they saw a checkpointed height's own coinbase "gone" after a
 * reload and suspected the flush/compact reconstruction path was silently
 * losing data. It wasn't losing anything -- the reloaded state was correctly
 * AHEAD of the stale checkpoint, and something later in that already-applied
 * range had legitimately spent it.)
 *
 * Reproduction: apply a clean chain, then fork a child that applies exactly
 * ONE more block (a real spend) and calls _exit(1) via the TEST-ONLY crash
 * hook (utxo_live_test_set_crash_after) the instant that block's own
 * checkpoint would be persisted -- simulating a kill at that exact point.
 * The parent then does a real utxo_live_close()+utxo_live_init() (exactly
 * what a process restart does) and checks: (1) the persisted checkpoint
 * reflects the crashed child's fully-applied block, not the height before
 * it, and (2) resuming catch-up from there is a clean no-op, not a
 * REJECT/-1.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>

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
    u8 tx[64], txid[32];
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
    u8 cb[64], cb_txid[32];
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

int main(void){
    char tmpl[] = "/tmp/crashresumeXXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) { perror("mkdtemp"); return 1; }
    if (chdir(dir)) { perror("chdir"); return 1; }

    memset(store_buf,0,sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);

    /* Heights 0..149: ordinary coinbase-only chain. Height 0's coinbase is
     * what the spend block at height 150 will spend (conf=150, well past
     * COINBASE_MATURITY=100). */
    long n1 = 150;
    u8 prev[32]; memset(prev,0,32);
    u8 height0_txid[32];
    for (long h=0; h<n1; h++){
        u8 raw[256], hash[32];
        long len = mk_and_mine(raw, hash, prev, 0x70000000u+(u32)h, 1900000000u+(u32)h);
        long r = store_append(store_buf, hash, raw, len);
        if (r != h) { printf("FAIL store_append h=%ld got=%ld\n", h, r); failures++; }
        if (h==0){
            u8 blk_hdr[80]; memcpy(blk_hdr, raw, 80);
            memcpy(height0_txid, blk_hdr+36, 32);
        }
        memcpy(prev, hash, 32);
    }

    long applied1 = utxo_live_catchup(store_buf);
    ck("clean chain (0..149) catch-up applied exactly n1 blocks", applied1, n1);
    ck("applied_height after clean catch-up", utxo_live_applied_height(), n1-1);
    long count_before = utxo_live_count();
    ck("live UTXO count before the spend block", count_before, n1);

    /* Simulate a real process restart before the next block: close and
     * forget all in-process state. */
    utxo_live_close();

    /* Append height 150 -- a real, valid spend of height 0's coinbase. */
    {
        u8 raw[512], hash[32];
        long len = mk_and_mine_spend(raw, hash, prev, height0_txid, 0x80000000u, 1900100000u);
        long r = store_append(store_buf, hash, raw, len);
        if (r != n1) { printf("FAIL store_append (spend) got=%ld\n", r); failures++; }
    }

    /* Arm the crash hook (inherited by the child via fork's memory copy),
     * then fork a child that reopens from disk (a real restart) and applies
     * exactly this one new block before "crashing" right where its own
     * checkpoint persist already ran. */
    utxo_live_test_set_crash_after(1);
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0){
        if (utxo_live_init(".") != 1) _exit(2);
        long ar = utxo_live_catchup(store_buf);
        /* Should never get here -- the crash hook fires inside the call,
         * after applying exactly 1 block, before this returns. If it
         * returns normally instead, the hook didn't fire as expected;
         * surface that as a distinct exit code rather than a silent pass. */
        fprintf(stderr, "test_utxo_catchup_crash_resume: crash hook did not fire (ar=%ld)\n", ar);
        _exit(3);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) { perror("waitpid"); return 1; }
    ckm("crashed child terminated via the crash hook's _exit(1), not a real "
        "crash or an unfired hook", WIFEXITED(status) && WEXITSTATUS(status)==1);

    /* Real restart: fresh reload from whatever the crashed child left durably
     * on disk. */
    ck("utxo_live_init (post-crash reload)", utxo_live_init("."), 1);
    ck("checkpoint reflects the crashed child's fully-applied block, not the "
       "height before it", utxo_live_applied_height(), n1);
    ck("live UTXO count reflects the spend block's net effect (coinbase +1, "
       "height-0 spend -1, tx1 output +1)", utxo_live_count(), n1+1);

    long applied2 = utxo_live_catchup(store_buf);
    ck("resuming from the correct checkpoint is a clean no-op, not a "
       "re-verification of an already-applied block", applied2, 0);
    ck("applied_height unchanged by the no-op resume", utxo_live_applied_height(), n1);

    utxo_live_close();
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
