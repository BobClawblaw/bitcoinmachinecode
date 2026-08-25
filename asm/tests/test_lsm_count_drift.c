/* tests/test_lsm_count_drift.c -- incident #45 repro: utxo_lsm_count()'s
 * incremental counter vs the ground-truth dedup walk, through the EXACT
 * production shape that drifted +7,890,418: a LONG ghost run healed
 * block-by-block WITH FLUSHES FIRING MID-CYCLE (tiny thresholds stand in
 * for bulk scale; test_utxo_ghost_resume's 2-block heal never flushes,
 * which is why its count checks pass). Every phase asserts
 * utxo_live_count() == utxo_live_walk_count(); the walk is the same
 * primitive the parity capstone proved Core-exact. */
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
    fprintf(stderr, "test_lsm_count_drift: unexpected mempool_resolve_confirmed_utxo\n");
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

static u8 store_buf[4096];
static u8 raw[512];

static void ckdrift(const char* phase){
    long c = utxo_live_count(), w = utxo_live_walk_count();
    if (c == w) printf("PASS count==walk %s (both %ld)\n", phase, c);
    else { printf("FAIL count==walk %s: count=%ld walk=%ld drift=%+ld\n", phase, c, w, c-w); failures++; }
}

int main(void){
    tt_isolate();
    memset(store_buf,0,sizeof store_buf);
    if (store_init(store_buf)!=1){ printf("FAIL store_init\n"); return 1; }
    if (utxo_live_init(".")!=1){ printf("FAIL utxo_live_init\n"); return 1; }
    /* production ingredient: flushes fire DURING the cycle. ~64-entry fill
     * means several flushes across the run below. */
    utxo_live_set_flush_thresholds(64, 128);

    /* base chain 0..149: coinbase-only (mature funds for the spend chain) */
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
    ck("base catchup", utxo_live_catchup(store_buf), n1);
    ckdrift("after base catch-up (with flushes)");

    /* 120-block chained spend run: block N spends block N-1's tx output.
     * Appended AND ghost-applied (no checkpoints) -- the dead-process shape. */
    long nghost = 120;
    u8 chain_txid[32]; memcpy(chain_txid, height0_txid, 32);
    static u8 blks[120][512]; static long lens[120];
    for (long i=0; i<nghost; i++){
        u8 hash[32], t1[32];
        lens[i] = mk_and_mine_spend(blks[i], hash, t1, prev, chain_txid,
                                    (u32)(n1+i), 1600001000u+(u32)i);
        if (store_append(store_buf, hash, blks[i], lens[i]) != n1+i){ printf("FAIL append g%ld\n",i); failures++; }
        memcpy(prev, hash, 32);
        memcpy(chain_txid, t1, 32);
    }
    /* THE PRODUCTION CRASH SHAPE: the ghost run happens in a CHILD that
     * dies WITHOUT close/flush (_exit, the SIGKILL stand-in). Its puts/dels
     * are WAL-durable; its checkpoint never lands; the parent's reload then
     * faces exactly what the 07:05 rebuild boot faced -- a fat WAL tail over
     * the runs, and the counter restored as base + tail-pushes - tail-dels. */
    utxo_live_close();               /* parent hands the datadir to the child */
    { pid_t pid = fork();
      if (pid == 0){
          if (utxo_live_init(".") != 1) _exit(2);
          utxo_live_set_flush_thresholds(64, 128);
          for (long i=0; i<nghost; i++)
              if (utxo_live_apply_block(blks[i], (u64)lens[i], n1+i) != 1) _exit(3);
          _exit(0);                  /* NO close, NO flush -- the crash */
      }
      int st=-1; waitpid(pid, &st, 0);
      ck("child ghost-applied 120 blocks then died uncleanly",
         WIFEXITED(st) ? WEXITSTATUS(st) : -1, 0); }

    /* heal boot: reload (fat WAL tail) + recovery + catch-up re-apply */
    if (utxo_live_init(".")!=1){ printf("FAIL re-init\n"); return 1; }
    ck("checkpoint still at 149 (ghosts un-checkpointed)", utxo_live_applied_height(), n1-1);
    ckdrift("right after the crash-shaped reload (base + WAL tail)");
    utxo_live_set_flush_thresholds(64, 128);
    ck("heal catch-up applies the 120 ghosts", utxo_live_catchup(store_buf), nghost);
    ck("applied lands at the tip", utxo_live_applied_height(), n1+nghost-1);
    ckdrift("after the flush-heavy heal");

    /* the invariant the production heartbeat displays */
    ck("net live == height+1 (each block nets +1)", utxo_live_walk_count(), n1+nghost);

    /* ==== THE PRODUCTION MECHANISM (incident #45): a kill BETWEEN the
     * flush's manifest write and its WAL truncate. Simulated exactly at the
     * filesystem level: save the WAL, flush (folds it into a run + writes a
     * manifest whose persisted base INCLUDES it + truncates), then put the
     * saved WAL back -- the on-disk state a SIGKILL in that window leaves.
     * Reload then computes base + tail where the base already contains the
     * tail: the counter double-counts the tail's net; the WALK (and the
     * memtable, since replay is idempotent over the runs) stays correct. */
    extern long utxo_live_flush(void);
    { long more = 40;
      static u8 mblk[512];
      utxo_live_set_flush_thresholds(1u<<20, 1u<<21);   /* no auto-flush */
      for (long i=0; i<more; i++){
          u8 hash[32], t1[32];
          long ln = mk_and_mine_spend(mblk, hash, t1, prev, chain_txid,
                                      (u32)(n1+nghost+i), 1600002000u+(u32)i);
          if (store_append(store_buf, hash, mblk, ln) != n1+nghost+i){ printf("FAIL append m%ld\n",i); failures++; }
          memcpy(prev, hash, 32);
          memcpy(chain_txid, t1, 32);
      }
      ck("catch-up applies the 40 (WAL only, no flush)", utxo_live_catchup(store_buf), more);
      ckdrift("before the crash-window simulation");
      if (system("cp utxo.dat utxo.dat.pretrunc") != 0){ printf("FAIL wal save\n"); failures++; }
      ck("forced flush (manifest write + WAL truncate)", utxo_live_flush(), 1);
      utxo_live_close();
      if (system("cp utxo.dat.pretrunc utxo.dat") != 0){ printf("FAIL wal restore\n"); failures++; }
      if (utxo_live_init(".")!=1){ printf("FAIL crash-window re-init\n"); return 1; }
      long c = utxo_live_count(), w = utxo_live_walk_count();
      printf("crash-window reload: count=%ld walk=%ld drift=%+ld (net of the 40-block tail = +%ld)\n",
             c, w, c-w, more);
      ck("walk still exact after crash-window reload", w, n1+nghost+more);
      ck("INCIDENT #45: counter must equal the walk", c, w); }

    utxo_live_close();
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures ? 1 : 0;
}
