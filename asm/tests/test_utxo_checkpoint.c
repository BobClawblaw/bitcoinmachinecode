/* tests/test_utxo_checkpoint.c -- Stage D: a restart that lands BETWEEN two
 * separate, individually-COMPLETE utxo_live_catchup() calls must resume from
 * the persisted applied-height checkpoint instead of re-walking the whole
 * archive from -1. persist_applied_height() already runs at the end of any
 * call that applied at least one block (independent of compaction), so this
 * is safe today and is what this test locks in as a regression guard.
 *
 * NOT covered here, and NOT currently safe: a restart that lands WHILE a
 * single catch-up call is still in-flight, between two flush/compact events.
 * A periodic mid-loop checkpoint for that case was tried on 2026-08-19 and
 * reverted after it exposed a real data-loss bug in production -- reloading
 * from a checkpoint taken between flush/compact events came back missing
 * entries that had genuinely been applied (confirmed: even the exact
 * checkpointed height's own coinbase output was gone from the reloaded LSM
 * state, while older, already-flushed-to-run entries were intact). The
 * leading theory is a correctness bug in the flush/compact reconstruction
 * path itself, not a WAL-durability issue (WAL writes are synchronous and
 * already durable-enough for a same-machine restart). Do not add a periodic
 * mid-loop persist_applied_height() call back into utxo_live_catchup, or
 * extend this test to cover an in-flight restart, until that is root-caused.
 *
 * Drives a real, coinbase-only chain past 20000 heights in a single
 * complete catch-up call, simulates a process restart (utxo_live_close + a
 * fresh utxo_live_init from the same directory), and proves the resume
 * point comes back from the checkpoint, not from -1, with a follow-up
 * catch-up call applying only the blocks appended after the restart.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long store_init(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  pow_check(const u8 hdr[80]);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);

extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_count(void);
extern long utxo_live_applied_height(void);
extern void utxo_live_close(void);

/* Never actually reached -- this chain has no non-coinbase spends -- but
 * bitcoin_mempool_policy.c's object file resolves this extern, so link
 * needs a definition. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_utxo_checkpoint: unexpected call to mempool_resolve_confirmed_utxo\n");
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

/* Build+mine ONE coinbase-only block chaining off `prev` into `raw`
 * (caller-owned, >=256 bytes). Minimum-difficulty bits (0x207fffff, same
 * constant tests/test_reorg.c uses) so mining is instant. Single-tx block:
 * merkle root == that tx's own txid. */
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
        printf("FAIL tx_txid\n"); failures++;
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

static u8 store_buf[4096];

int main(void){
    tt_isolate();
    memset(store_buf,0,sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);

    /* Heights 0..19999 (20000 blocks) crosses exactly one periodic-
     * checkpoint tick (applied%20000==0, fires at h=19999) plus the
     * end-of-call persist -- both land on the same height here, which is
     * fine; the real point is proven by the post-restart re-init below. */
    long n1 = 20000;
    u8 prev[32]; memset(prev,0,32);
    for (long h=0; h<n1; h++){
        u8 raw[256], hash[32];
        long len = mk_and_mine(raw, hash, prev, 0x30000000u+(u32)h, 1700000000u+(u32)h);
        long r = store_append(store_buf, hash, raw, len);
        if (r != h) { printf("FAIL store_append h=%ld got=%ld\n", h, r); failures++; }
        memcpy(prev, hash, 32);
    }

    long applied1 = utxo_live_catchup(store_buf);
    ck("first catch-up applied exactly n1 blocks", applied1, n1);
    ck("applied_height after first catch-up", utxo_live_applied_height(), n1-1);
    long count1 = utxo_live_count();
    ck("live UTXO count after first catch-up", count1, n1);

    struct stat sb;
    ckm("checkpoint file exists after crossing the 20000-height cadence",
        stat("utxo_applied_height.dat", &sb) == 0);

    /* "Restart": drop all in-process state (mmaps, fds, g_applied_height)
     * and re-init from the SAME directory, exactly as a real process
     * restart would. */
    utxo_live_close();
    ck("utxo_live_init (post-restart reload)", utxo_live_init("."), 1);
    ck("resumed from the persisted checkpoint, not from -1",
       utxo_live_applied_height(), n1-1);
    ck("live UTXO count survived the restart intact", utxo_live_count(), count1);

    /* Extend the chain and catch up again -- must apply ONLY the new
     * blocks, not re-walk/re-apply the first 20000. */
    long n2 = 7;
    for (long i=0; i<n2; i++){
        long h = n1 + i;
        u8 raw[256], hash[32];
        long len = mk_and_mine(raw, hash, prev, 0x40000000u+(u32)i, 1700100000u+(u32)i);
        long r = store_append(store_buf, hash, raw, len);
        if (r != h) { printf("FAIL store_append h=%ld got=%ld\n", h, r); failures++; }
        memcpy(prev, hash, 32);
    }
    long applied2 = utxo_live_catchup(store_buf);
    ck("second catch-up (post-restart) applied ONLY the new blocks", applied2, n2);
    ck("applied_height after second catch-up", utxo_live_applied_height(), n1+n2-1);
    ck("live UTXO count after second catch-up", utxo_live_count(), n1+n2);

    utxo_live_close();
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
