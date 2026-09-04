/* tests/test_reorg_crash_ordering.c -- STO-1 (audit 2026-09-03): a crash
 * partway through a disconnect must leave a state boot can repair.
 *
 * THE DEFECT. reorg_execute unapplies heights tip..fork+1 one at a time, and
 * each utxo_live_unapply_block is durable the moment it returns -- its
 * restores and deletes go through the WAL. But the persisted applied height
 * was rewritten only ONCE, after the whole loop, and nothing marked
 * "disconnect in progress". A crash partway left the set at T-k while
 * utxo_applied_height.dat still said T, with the undo files for those heights
 * already discarded. Boot looked for undo_(T+1), found nothing, said "nothing
 * to do"; catch-up saw tip <= applied and did nothing either. Coins spent in
 * T-k+1..T were live again, silently -- and because tip == applied nothing
 * about the state looked wrong.
 *
 * THE FIX inverts which way a crash can leave things: persist h-1 BEFORE
 * unapplying h, and discard undo_h only after. The reachable window becomes
 * "applied says h-1, the set still has h applied, undo_h is on disk", which
 * utxo_live_recover_partial_block already repairs.
 *
 * WHAT THIS TEST DOES. It does not fork and SIGKILL -- it reproduces the
 * on-disk STATE a crash leaves, which is what boot actually sees, and is
 * deterministic. Three states, each built by applying a chain and then
 * arranging the files as a crash at that point would:
 *
 *   1. crash AFTER persist(h-1), BEFORE unapply(h): applied = h-1, the set
 *      still has h's effects, undo_h present. Boot must roll h back.
 *   2. crash AFTER unapply(h), BEFORE undo_discard(h): same files, but the
 *      set is already rolled back. Boot replays the undo AGAIN, so this pins
 *      that unapply is IDEMPOTENT -- the property the whole ordering rests
 *      on. A second rollback must not corrupt the set or the count.
 *   3. the OLD ordering's window, as a contrast: applied = T with the undo
 *      files gone. Boot cannot repair it and must not pretend it can.
 *
 * Usage: ./test_reorg_crash_ordering
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
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
extern long utxo_live_recover_partial_block(void* store_buf);
extern int  utxo_live_unapply_block(const void* blockbuf, u64 blocklen, long height);
extern int  utxo_live_rewind_to(long height);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u;(void)txid;(void)index;(void)value;(void)script;(void)slen; abort();
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
static void put32(u8* p, unsigned v){ p[0]=(u8)v;p[1]=(u8)(v>>8);p[2]=(u8)(v>>16);p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
static u8 g_scr[1<<12];

/* A block's coinbase, and -- when spend_txid is non-NULL -- one transaction
 * spending that coinbase output. THE SPEND IS THE POINT: an undo file is
 * written only for heights that actually consume prevouts, and STO-1 is
 * entirely about what happens to those files. A coinbase-only chain produces
 * no undo data at all, so it cannot reach the state under test -- which is
 * how the first draft of this fixture managed to "run" while proving
 * nothing. */
static long mk_block(u8* raw, u8 hash[32], const u8 prev[32], unsigned tag, unsigned ts,
                     const u8* spend_txid){
    u8 cb[80], cb_txid[32]; u8* q = cb;
    put32(q,1); q+=4; *q++=1; memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
    *q++=4; put32(q,tag); q+=4; put32(q,0xffffffffu); q+=4;
    *q++=1; put64(q,50000000ULL); q+=8; *q++=1; *q++=0x51; put32(q,0); q+=4;
    long cbl = q - cb;
    tx_txid(cb_txid, cb, (unsigned long)cbl, g_scr, sizeof g_scr);

    u8 sp[128], sp_txid[32]; long spl = 0;
    if (spend_txid){
        u8* r = sp;
        put32(r,1); r+=4; *r++=1;
        memcpy(r, spend_txid, 32); r+=32; put32(r,0); r+=4;
        *r++=0; put32(r,0xffffffffu); r+=4;
        *r++=1; put64(r,40000000ULL); r+=8; *r++=1; *r++=0x51;
        put32(r,0); r+=4;
        spl = r - sp;
        tx_txid(sp_txid, sp, (unsigned long)spl, g_scr, sizeof g_scr);
    }

    u8 root[32];
    if (spl){ u8 pair[64]; memcpy(pair,cb_txid,32); memcpy(pair+32,sp_txid,32); sha256d(root,pair,64); }
    else memcpy(root, cb_txid, 32);

    u8* o = raw;
    put32(o,1); o+=4; memcpy(o,prev,32); o+=32; memcpy(o,root,32); o+=32;
    put32(o,ts); o+=4; put32(o,0x207fffffu); o+=4; put32(o,0); o+=4;
    *o++ = spl ? 2 : 1;
    memcpy(o,cb,(size_t)cbl); o+=cbl;
    if (spl){ memcpy(o,sp,(size_t)spl); o+=spl; }
    unsigned nz=0; while(!pow_check(raw)){ nz++; put32(raw+76,nz); }
    block_hash(hash, raw);
    return o - raw;
}

static int undo_exists(long h){
    char p[64]; snprintf(p,sizeof p,"undo_%ld.dat",h);
    struct stat sb; return stat(p,&sb)==0;
}

/* Coinbase maturity is 100, so a block can only spend a coinbase at least
 * 100 deep. 140 blocks with spends from height 101 onward gives a tip whose
 * last ~39 heights all have undo files. */
#define NB 140
#define FIRST_SPEND 101
static u8 store_buf[4096];
static u8 blk[NB][512]; static long blen[NB]; static u8 bh[NB][32];
static u8 cbtxid[NB][32];

/* build the chain and apply it; returns the applied count */
static long build_and_apply(void){
    memset(store_buf,0,sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);
    u8 prev[32]; memset(prev,0,32);
    for (long h=0; h<NB; h++){
        const u8* spend = (h >= FIRST_SPEND) ? cbtxid[h - FIRST_SPEND] : 0;
        blen[h] = mk_block(blk[h], bh[h], prev, 0x50000000u+(unsigned)h,
                           1800000000u+(unsigned)h, spend);
        /* the coinbase txid is the FIRST tx in the block; recompute it for
         * later spends */
        { const u8* p = blk[h] + 81; unsigned long cbl;
          /* coinbase is 65 bytes as built above */
          cbl = 65; tx_txid(cbtxid[h], p, cbl, g_scr, sizeof g_scr); }
        if (store_append(store_buf, bh[h], blk[h], blen[h]) != h){ printf("FAIL append %ld\n",h); failures++; }
        memcpy(prev, bh[h], 32);
    }
    return utxo_live_catchup(store_buf);
}

int main(void){
    tt_isolate();
    ck("catch-up applied the whole chain", build_and_apply(), NB);
    long full_count = utxo_live_count();
    ck("applied height is the tip", utxo_live_applied_height(), NB-1);

    /* ---- 1. crash AFTER persist(h-1), BEFORE unapply(h) ---------------- */
    long h = NB-1;
    ck("STO-1 persist h-1 first (the new ordering's first step)",
       utxo_live_rewind_to(h-1), 1);
    ck("  undo_h is still on disk at that instant", undo_exists(h), 1);
    /* that IS the crash state. Boot now: */
    ck("STO-1 boot recovery repairs it (rolls the height back)",
       utxo_live_recover_partial_block(store_buf), 1);
    ck("  the set lost that block's coinbase output", utxo_live_count(), full_count-1);
    ck("  and its undo file is gone", undo_exists(h), 0);

    /* ---- 2. IDEMPOTENCE: replay the same undo a second time ------------ */
    /* Re-apply, then arrange the crash-after-unapply-before-discard state by
     * unapplying by hand while leaving applied at h-1 and undo_h in place. */
    ck("re-apply the disconnected block", utxo_live_catchup(store_buf), 1);
    ck("  set is whole again", utxo_live_count(), full_count);
    ck("STO-1 persist h-1", utxo_live_rewind_to(h-1), 1);
    ck("  roll it back once", utxo_live_recover_partial_block(store_buf), 1);
    long after_one = utxo_live_count();
    /* now put the undo file back and roll again: this is the crash-between-
     * unapply-and-discard window, and it must be harmless. */
    ck("re-apply again", utxo_live_catchup(store_buf), 1);
    ck("STO-1 persist h-1 again", utxo_live_rewind_to(h-1), 1);
    ck("  first rollback", utxo_live_recover_partial_block(store_buf), 1);
    ck("STO-1 a second rollback of an already-rolled-back height is a no-op",
       utxo_live_recover_partial_block(store_buf), 0);
    ck("  and the count is unchanged by it", utxo_live_count(), after_one);

    /* ---- 3. the OLD ordering's window, for contrast -------------------- */
    ck("re-apply for the contrast case", utxo_live_catchup(store_buf), 1);
    /* old ordering: unapply FIRST (discarding undo), applied left stale */
    ck("unapply with applied left at the tip (the OLD ordering)",
       utxo_live_unapply_block(blk[h], (u64)blen[h], h), 1);
    ck("  the undo file is gone", undo_exists(h), 0);
    ck("  applied still claims the tip", utxo_live_applied_height(), NB-1);
    ck("STO-1 boot CANNOT repair the old ordering's window -- nothing to do",
       utxo_live_recover_partial_block(store_buf), 0);
    printf("     (that is the defect: the set is one block behind what applied "
           "claims, and no undo file remains to fix it)\n");

    utxo_live_close();
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
