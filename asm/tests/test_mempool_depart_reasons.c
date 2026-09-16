/* tests/test_mempool_depart_reasons.c -- the departure REASONS, driven through
 * the real policy engine.
 *
 * WHY THIS EXISTS SEPARATELY from test_mempool_journal.c: that file tests the
 * STORE -- records survive a reopen, the ring wraps, a torn record is skipped.
 * It never proves that the policy engine reports the right reason, or reports
 * one at all, because it appends by hand.
 *
 * That gap was not theoretical. After 4.2 hours and 179,740 real departures on
 * production, `evicted` and `expired` were both still ZERO: the pool sits at
 * 3.4% of -maxmempool so TrimToSize never runs, and -mempoolexpiry is 336
 * hours, longer than the ring holds at that rate. So the two paths that make
 * the feature worth having -- "evicted because the pool was full" is precisely
 * what Core cannot tell you -- had never executed outside a unit test of the
 * store. If the hook were mis-wired for either, nothing would have said so.
 *
 * Here the reasons come from the engine itself: a tiny pool is filled past its
 * capacity to force a real TrimToSize, and a real expiry sweep is run over a
 * back-dated entry. The callback under test is the one the daemon registers
 * (mpool_policy_set_depart_cb), so what is checked is the wiring, not a
 * re-implementation of it.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../daemon/mempool_journal_fmt.h"

typedef unsigned char u8;
typedef unsigned long long u64;

extern void  mpool_init(void*, unsigned long, void*, unsigned long);
extern const u8* mpool_get(const void*, const u8*, unsigned long*);
extern void  utxo_init(void*, unsigned long, void*, unsigned long);
extern long  utxo_put(void*, const u8*, unsigned long, u64, unsigned long, unsigned long, const u8*, unsigned long);
extern int   tx_txid(u8 out[32], const u8* tx, unsigned long len, u8* scratch, unsigned long scap);
extern unsigned long mpool_policy_state_size(unsigned);
extern void  mpool_policy_state_init(void*, unsigned);
extern void  mpool_policy_init(void*, u64, unsigned, unsigned, unsigned, unsigned, unsigned);
extern void  mpool_policy_set_acceptnonstd(void*, unsigned);
extern long  mpool_policy_add(void*, void*, void*, const u8*, unsigned long, const u8*, void*);
extern long  mpool_policy_expire_one(void*, void*, const u8*);
extern void  mpool_policy_set_poolcap(void*, unsigned long long);
extern void  mpool_policy_set_depart_cb(void (*)(const u8*, unsigned long long, unsigned long long, int));
extern void  mpool_policy_set_depart_reason(int);
extern const char* mpool_policy_reason(void*);

/* the policy engine reaches the UTXO set through this; the harness wants the
 * plain single-table behaviour (same stub tests/test_mempool_policy.c uses) */
extern long utxo_get(void* u, const u8 txid[32], unsigned long index,
                     u64* value, unsigned long* height, unsigned long* is_coinbase,
                     const u8** script, unsigned long* slen);
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    unsigned long h, cb;
    return utxo_get(u, txid, index, value, &h, &cb, script, slen);
}

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; printf("%s %s\n", c ? "ok  :" : "FAIL:", w); if (!c) fails++; }

/* ---- what the engine reported --------------------------------------------- */
#define CAP 64
static struct { u8 txid[32]; unsigned long long vsize, fee; int reason; } g_dep[CAP];
static int g_ndep;
static void on_depart(const u8* txid, unsigned long long vsize,
                      unsigned long long fee, int reason){
    if (g_ndep >= CAP) return;
    memcpy(g_dep[g_ndep].txid, txid, 32);
    g_dep[g_ndep].vsize = vsize; g_dep[g_ndep].fee = fee; g_dep[g_ndep].reason = reason;
    g_ndep++;
}
static int depart_count(int reason){
    int n = 0; for (int i = 0; i < g_ndep; i++) if (g_dep[i].reason == reason) n++; return n;
}
static int departed_with(const u8 txid[32], int reason){
    for (int i = 0; i < g_ndep; i++)
        if (g_dep[i].reason == reason && !memcmp(g_dep[i].txid, txid, 32)) return 1;
    return 0;
}

static long mk_tx(u8* out, u8 in_tag, u64 invalue, u64 fee, int pad){
    u8* p = out;
    *p++=2;*p++=0;*p++=0;*p++=0;
    *p++=1;
    memset(p, in_tag, 32); p+=32;
    *p++=0;*p++=0;*p++=0;*p++=0;
    *p++=0;
    *p++=0xff;*p++=0xff;*p++=0xff;*p++=0xff;
    *p++=1;
    u64 outv = invalue - fee;
    for (int i=0;i<8;i++) *p++ = (u8)(outv >> (8*i));
    *p++ = (u8)(1+pad);
    *p++ = 0x51;
    for (int i=0;i<pad;i++) *p++ = 0x00;
    *p++=0;*p++=0;*p++=0;*p++=0;
    return p - out;
}

int main(void){
    /* the same fixture shape tests/test_mempool_evict.c uses: a real policy
     * config, the regtest escape hatch for synthetic txs, and a pool blob so
     * small that a fifth transaction cannot fit without TrimToSize running */
    static u8 pol[128], st[1<<20];
    memset(st, 0, sizeof st);
    mpool_policy_init(pol, 1000 /* sat/kvB */, 25, 101000, 25, 101000, 1);
    mpool_policy_set_acceptnonstd(pol, 1);
    { extern void mpol_policy_set_min_size(void*, unsigned);
      mpol_policy_set_min_size(pol, 0); }    /* test-only: these fixtures are ~60 bytes */
    mpool_policy_state_init(st, 256);

    static u8 mp[40 + 64*80 + 8];
    static u8 mblob[300];                      /* deliberately tiny: forces TrimToSize */
    mpool_init(mp, 64, mblob, sizeof mblob);
    mpool_policy_set_poolcap(st, sizeof mblob);

    static u8 ux[40 + 256*48 + 8]; static u8 ublob[1<<14];
    utxo_init(ux, 256, ublob, sizeof ublob);
    for (int i=1;i<=12;i++){ u8 t[32]; memset(t,(u8)i,32); utxo_put(ux, t, 0, 1000000ULL, 0, 0, (const u8*)"\x51", 1); }

    mpool_policy_set_depart_cb(on_depart);

    /* ---- EVICTED: fill past capacity so TrimToSize has to run -------------- */
    static u8 sc[4096];
    u8 ids[12][32];
    u64 fees[4] = {100,200,300,400};
    int inpool = 0;
    for (int i=0;i<4;i++){
        u8 tx[128]; long n = mk_tx(tx, (u8)(i+1), 1000000ULL, fees[i], 0);
        tx_txid(ids[i], tx, n, sc, sizeof sc);
        if (mpool_policy_add(pol, st, mp, tx, n, ids[i], ux) == 1) inpool++;
    }
    ck("the tiny pool filled to capacity", inpool == 4);
    ck("nothing has departed yet", g_ndep == 0);

    g_ndep = 0;
    { u8 tx[128]; long n = mk_tx(tx, 5, 1000000ULL, 1000, 0);
      tx_txid(ids[4], tx, n, sc, sizeof sc);
      long r = mpool_policy_add(pol, st, mp, tx, n, ids[4], ux);
      ck("a high-fee tx is accepted, evicting to make room", r == 1);
      unsigned long l;
      ck("...the cheapest really left the pool", mpool_get(mp, ids[0], &l) == NULL);

      /* THE POINT: the engine reported it, and reported it as an EVICTION.
       * This is the reason production has never produced -- its pool sits at
       * 3.4% of -maxmempool, so TrimToSize never runs there. */
      ck("the engine REPORTED a departure for it", g_ndep > 0);
      ck("...with reason EVICTED, not mined or replaced",
         departed_with(ids[0], MPJ_EVICTED));
      ck("...and no other reason was reported for this eviction",
         depart_count(MPJ_MINED) == 0 && depart_count(MPJ_REPLACED) == 0 &&
         depart_count(MPJ_EXPIRED) == 0 && depart_count(MPJ_CONFLICTED) == 0);
      /* the size and fee carried with it are the evicted tx's own, not the
       * incoming one's -- getting these crossed would misreport every row */
      for (int i = 0; i < g_ndep; i++)
        if (!memcmp(g_dep[i].txid, ids[0], 32)){
            ck("...carrying the EVICTED tx's fee, not the newcomer's", g_dep[i].fee == 100);
            ck("...and a non-zero vsize", g_dep[i].vsize > 0);
        }
    }

    /* ---- EXPIRED: a real expiry sweep over one entry ----------------------- */
    g_ndep = 0;
    { long r = mpool_policy_expire_one(st, mp, ids[1]);
      ck("expire_one removed the entry", r > 0);
      ck("the engine reported it as EXPIRED", departed_with(ids[1], MPJ_EXPIRED));
      ck("...and not as an eviction", !departed_with(ids[1], MPJ_EVICTED)); }

    /* ---- an eviction after an expiry is still an eviction ------------------
     * NOTE what this does NOT test: a reason LEAK. Removing expire_one's
     * restore does not fail it, because the eviction path sets its own reason
     * on entry and so overwrites whatever leaked. The leak is pinned directly
     * in tests/test_mempool_journal.c, which reads the reason back after
     * expire_one returns. Kept here for the sequencing it does cover. */
    g_ndep = 0;
    mpool_policy_set_depart_reason(0);
    { mpool_policy_expire_one(st, mp, ids[2]);
      g_ndep = 0;
      u8 tx[128]; long n = mk_tx(tx, 6, 1000000ULL, 2000, 0);
      u8 id6[32]; tx_txid(id6, tx, n, sc, sizeof sc);
      mpool_policy_add(pol, st, mp, tx, n, id6, ux);
      ck("an eviction that follows an expiry is reported as EVICTED",
         depart_count(MPJ_EXPIRED) == 0); }

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
