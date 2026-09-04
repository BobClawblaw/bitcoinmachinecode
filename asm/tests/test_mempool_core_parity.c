/* tests/test_mempool_core_parity.c -- the Core-parity mempool policy
 * semantics (bitcoin_mempool_policy.c, LOG.md 2026-08-27):
 *
 *   1. standardness with Core's exact reject strings (version, scriptsig
 *      size / push-only, scriptpubkey, dust at the 3000 sat/kvB discard
 *      rate, datacarrier budget, tx-size-small, coinbase);
 *   2. fee floors over VSIZE with Core's strings;
 *   3. TrimToSize by descendant PACKAGE: a cheap parent+child package is
 *      evicted TOGETHER (the old per-leaf logic took two rounds and only
 *      ever removed leaves), the floor lands at package-feerate +
 *      incrementalrelayfee (sat/kvB), and an incoming tx that IS the worst
 *      is refused as "mempool full";
 *   4. RBF, all Core rules: fullrbf ignores signaling; rule 3/4
 *      ("insufficient fee", increment priced at the replacement's OWN
 *      vsize); conflicts evicted WITH descendants and the descendants'
 *      fees counted; disjointness ("bad-txns-spends-conflicting-tx");
 *      no new unconfirmed inputs ("replacement-adds-unconfirmed");
 *      classic signaling of the REPLACED tx when fullrbf is off
 *      ("txn-mempool-conflict");
 *   5. block-connect reconciliation: a confirmed tx leaves ALONE (its
 *      child stays), a tx conflicting with a block spend leaves WITH its
 *      child, and the rolling floor decays after the block (white-box
 *      time poke at header offset +56, layout documented in the policy
 *      file);
 *   6. expiry removes the whole descendant package.
 */
#include <stdio.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned long long u64;

extern void   mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern const u8* mpool_get(void* mp, const u8 txid[32], unsigned long* len);
extern long   utxo_get(void* u, const u8 txid[32], unsigned long index, u64* value,
                       unsigned long* height, unsigned long* cb, const u8** script, unsigned long* slen);
extern void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long   utxo_put(void* u, const u8 txid[32], unsigned index, u64 value, u64 h, u64 cb, const u8* spk, unsigned slen);
extern void   mpool_policy_init(void* pol, u64 relay, unsigned, unsigned, unsigned, unsigned, unsigned);
extern void   mpool_policy_set_acceptnonstd(void*, unsigned);
extern void   mpool_policy_set_datacarrier(void*, u64);
extern void   mpool_policy_state_init(void* st, unsigned n);
extern long   mpool_policy_add(void* pol, void* st, void* mp, const u8* tx, unsigned long txlen, const u8 txid[32], void* utxo);
extern const char* mpool_policy_reason(void* pol);
extern u64    mpool_policy_min_fee(void* st);
extern long   mpool_policy_remove_package(void* st, void* mp, const u8 txid[32]);
extern long   mpool_policy_block_connect(void* st, void* mp, const u8* block, unsigned long blen);
extern long   mpool_policy_expire_one(void* st, void* mp, const u8 txid[32]);
extern int    tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    unsigned long h, cb; return utxo_get(u, txid, index, value, &h, &cb, script, slen);
}

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static void ckr(const char* l, void* pol, const char* want){
    const char* r = mpool_policy_reason(pol);
    if (r && strcmp(r, want) == 0) printf("  ok  %s [\"%s\"]\n", l, want);
    else { printf("  FAIL %s: reason \"%s\" != \"%s\"\n", l, r?r:"?", want); fails++; }
}

/* -------- general tx builder ---------------------------------------------
 * inputs: (tag,index,seq,scriptsig)  outputs: (value, spk bytes)           */
typedef struct { u8 tag; unsigned idx; unsigned seq;
                 const u8* ss; unsigned sslen;
                 const u8* previd; /* full 32-byte prev txid; overrides tag */ } txin_t;
typedef struct { u64 v; const u8* spk; unsigned spklen; } txout_t;
static long mk(u8* out, const txin_t* in, int nin, const txout_t* o, int nout){
    u8* p = out;
    *p++=2;*p++=0;*p++=0;*p++=0;
    *p++=(u8)nin;
    for (int i=0;i<nin;i++){
        if (in[i].previd) memcpy(p, in[i].previd, 32);
        else memset(p, in[i].tag, 32);
        p+=32;
        for (int k=0;k<4;k++) *p++ = (u8)(in[i].idx >> (8*k));
        *p++ = (u8)in[i].sslen;
        memcpy(p, in[i].ss, in[i].sslen); p += in[i].sslen;
        for (int k=0;k<4;k++) *p++ = (u8)(in[i].seq >> (8*k));
    }
    *p++=(u8)nout;
    for (int i=0;i<nout;i++){
        for (int k=0;k<8;k++) *p++ = (u8)(o[i].v >> (8*k));
        *p++=(u8)o[i].spklen;
        memcpy(p, o[i].spk, o[i].spklen); p += o[i].spklen;
    }
    *p++=0;*p++=0;*p++=0;*p++=0;
    return p - out;
}
/* standard P2WPKH spk (0x00 0x14 + 20 bytes) */
static u8 SPK_WPKH[22];
static u8 sc[1<<16];

int main(void){
    memset(SPK_WPKH, 0xab, sizeof SPK_WPKH); SPK_WPKH[0]=0x00; SPK_WPKH[1]=0x14;
    static u8 pol[192], st[1<<21];
    static u8 mp[40 + 256*48 + 8]; static u8 mblob[1<<16];
    static u8 ux[40 + 256*48 + 8]; static u8 ublob[1<<15];
    #define RESET(nonstd) do{ \
        memset(st,0,sizeof st); \
        mpool_policy_init(pol, 1000 /* sat/kvB: 1 sat/vB, as before */, 25, 101000, 25, 101000, 1); \
        if (nonstd) mpool_policy_set_acceptnonstd(pol, 1); \
        mpool_policy_state_init(st, 512); \
        mpool_init(mp, 256, mblob, sizeof mblob); \
        utxo_init(ux, 256, ublob, sizeof ublob); \
        for (int i=1;i<=12;i++){ u8 t[32]; memset(t,(u8)i,32); \
            utxo_put(ux, t, 0, 1000000ULL, 0, 0, SPK_WPKH, sizeof SPK_WPKH); } \
    } while(0)

    /* MEM-7's bloated replacement is ~6.4 kB; 8192 was too tight. */
    static u8 tx[65536]; u8 id[32]; long n, r;
    static const u8 EMPTY[1] = {0};

    printf("== 1: standardness, Core reject strings ==\n");
    RESET(0);
    { txin_t i0 = { .tag=1, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 };
      txout_t o0 = { .v=500000, .spk=SPK_WPKH, .spklen=22 };
      /* baseline standard tx accepted (fee 500,000 sat, ample) */
      n = mk(tx, &i0, 1, &o0, 1); tx_txid(id, tx, n, sc, sizeof sc);
      r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
      ck("standard P2WPKH-out tx accepted", r == 1);

      /* version 0 -> "version" */
      n = mk(tx, &(txin_t){ .tag=2, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &o0, 1);
      tx[0]=0; tx_txid(id, tx, n, sc, sizeof sc);
      r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
      ck("version 0 rejected", r == 0); ckr("...as", pol, "version");

      /* non-pushonly scriptsig -> "scriptsig-not-pushonly" */
      { static const u8 ss[1] = { 0x61 };   /* OP_NOP */
        n = mk(tx, &(txin_t){ .tag=2, .idx=0, .seq=0xffffffffu, .ss=ss, .sslen=1 }, 1, &o0, 1);
        tx_txid(id, tx, n, sc, sizeof sc);
        r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
        ck("OP_NOP scriptsig rejected", r == 0); ckr("...as", pol, "scriptsig-not-pushonly"); }

      /* nonstandard output script -> "scriptpubkey" */
      { static const u8 weird[3] = { 0x61, 0x61, 0x61 };
        txout_t ow = { .v=500000, .spk=weird, .spklen=3 };
        n = mk(tx, &(txin_t){ .tag=2, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &ow, 1);
        tx_txid(id, tx, n, sc, sizeof sc);
        r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
        ck("weird spk rejected", r == 0); ckr("...as", pol, "scriptpubkey"); }

      /* dust P2WPKH: threshold at 3000 sat/kvB is 294 sat -> 293 is dust */
      { txout_t od[2] = { { .v=293, .spk=SPK_WPKH, .spklen=22 },
                          { .v=400000, .spk=SPK_WPKH, .spklen=22 } };
        n = mk(tx, &(txin_t){ .tag=2, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, od, 2);
        tx_txid(id, tx, n, sc, sizeof sc);
        r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
        ck("293-sat P2WPKH output rejected", r == 0); ckr("...as", pol, "dust");
        od[0].v = 294;
        n = mk(tx, &(txin_t){ .tag=2, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, od, 2);
        tx_txid(id, tx, n, sc, sizeof sc);
        r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
        ck("294-sat P2WPKH output accepted (Core's exact threshold)", r == 1); }

      /* datacarrier budget: OP_RETURN past a 20-byte budget */
      { mpool_policy_set_datacarrier(pol, 20);
        static u8 nulldata[30]; nulldata[0]=0x6a; nulldata[1]=28; /* OP_RETURN push28 */
        txout_t on[2] = { { .v=0, .spk=nulldata, .spklen=30 },
                          { .v=400000, .spk=SPK_WPKH, .spklen=22 } };
        n = mk(tx, &(txin_t){ .tag=3, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, on, 2);
        tx_txid(id, tx, n, sc, sizeof sc);
        r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
        ck("30-byte OP_RETURN over a 20-byte budget rejected", r == 0);
        ckr("...as", pol, "datacarrier");
        mpool_policy_set_datacarrier(pol, 100000);
        r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
        ck("same tx accepted under the default budget", r == 1); }

      /* coinbase-shaped tx -> "coinbase" */
      { static u8 zero32[32];
        txin_t cb = { .previd=zero32, .idx=0xffffffffu, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 };
        n = mk(tx, &cb, 1, &o0, 1); tx_txid(id, tx, n, sc, sizeof sc);
        r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
        ck("coinbase rejected", r == 0); ckr("...as", pol, "coinbase"); }
    }

    printf("\n== 2: fee floors over vsize, Core strings ==\n");
    RESET(0);
    { /* exact vsize fee passes; one sat less fails with Core's string */
      txin_t i0 = { .tag=1, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 };
      txout_t o0 = { .v=0, .spk=SPK_WPKH, .spklen=22 };
      n = mk(tx, &i0, 1, &o0, 1);
      o0.v = 1000000 - (u64)n;         /* fee == vsize (non-witness: vsize==len) */
      n = mk(tx, &i0, 1, &o0, 1); tx_txid(id, tx, n, sc, sizeof sc);
      r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
      ck("fee == vsize*1 accepted at minrelay 1 sat/vB", r == 1);
      o0.v = 1000000 - (u64)n + 1;     /* fee = vsize-1 */
      txin_t i1 = { .tag=2, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 };
      n = mk(tx, &i1, 1, &o0, 1); tx_txid(id, tx, n, sc, sizeof sc);
      r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
      ck("fee == vsize-1 rejected", r == 0); ckr("...as", pol, "min relay fee not met"); }

    printf("\n== 3: package eviction (TrimToSize by descendant score) ==\n");
    { /* tiny blob: fits parent+child+standalone (~200B), not a 4th */
      static u8 tmblob[260];   /* fits three ~82B txs, not a fourth */
      memset(st,0,sizeof st);
      mpool_policy_init(pol, 1000 /* sat/kvB: 1 sat/vB, as before */, 25, 101000, 25, 101000, 1);
      mpool_policy_set_acceptnonstd(pol, 1);
      mpool_policy_state_init(st, 512);
      mpool_init(mp, 256, tmblob + 0, sizeof tmblob);   /* small pool */
      utxo_init(ux, 256, ublob, sizeof ublob);
      for (int i=1;i<=12;i++){ u8 t[32]; memset(t,(u8)i,32);
          utxo_put(ux, t, 0, 1000000ULL, 0, 0, SPK_WPKH, sizeof SPK_WPKH); }

      txout_t oS = { .v=0, .spk=SPK_WPKH, .spklen=22 };
      u8 pid[32], cid[32], sid[32], hid[32];
      /* parent: fee 100 */
      oS.v = 1000000-100;
      n = mk(tx, &(txin_t){ .tag=1, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(pid, tx, n, sc, sizeof sc);
      ck("parent (fee 100) in", mpool_policy_add(pol, st, mp, tx, n, pid, ux) == 1);
      /* child spends parent: fee 120 -> package (220 / ~132vB) ~ 1.67 sat/vB */
      oS.v = (1000000-100)-120;
      n = mk(tx, &(txin_t){ .previd=pid, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(cid, tx, n, sc, sizeof sc);
      ck("child (fee 120) in", mpool_policy_add(pol, st, mp, tx, n, cid, ux) == 1);
      /* standalone: fee 300 (~4.5 sat/vB own == package) */
      oS.v = 1000000-300;
      n = mk(tx, &(txin_t){ .tag=2, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(sid, tx, n, sc, sizeof sc);
      ck("standalone (fee 300) in", mpool_policy_add(pol, st, mp, tx, n, sid, ux) == 1);

      /* incoming fee 85 (~1.04 sat/vB, above minrelay): WORSE than the
       * worst package (~1.34) -> "mempool full", floor bumped, nothing
       * evicted */
      oS.v = 1000000-85;
      n = mk(tx, &(txin_t){ .tag=3, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(hid, tx, n, sc, sizeof sc);
      r = mpool_policy_add(pol, st, mp, tx, n, hid, ux);
      ck("worse-than-worst incoming refused", r == 0);
      ckr("...as", pol, "mempool full");
      { unsigned long l; ck("...and parent/child untouched",
            mpool_get(mp,pid,&l)!=NULL && mpool_get(mp,cid,&l)!=NULL); }
      u64 floor_after_reject = mpool_policy_min_fee(st);
      ck("floor bumped to worst-package rate + incremental (sat/kvB)",
         floor_after_reject >= 1600 && floor_after_reject <= 3800);

      /* incoming fee 5000: evicts the PARENT+CHILD PACKAGE together in ONE
       * admission (old leaf logic removed only the child first) */
      oS.v = 1000000-5000;
      n = mk(tx, &(txin_t){ .tag=4, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(hid, tx, n, sc, sizeof sc);
      r = mpool_policy_add(pol, st, mp, tx, n, hid, ux);
      ck("high-fee incoming accepted", r == 1);
      { unsigned long l;
        ck("parent evicted", mpool_get(mp,pid,&l) == NULL);
        ck("child evicted WITH it (package, not leaf)", mpool_get(mp,cid,&l) == NULL);
        ck("standalone survived (better score)", mpool_get(mp,sid,&l) != NULL);
        ck("incoming present", mpool_get(mp,hid,&l) != NULL); } }

    printf("\n== 4: RBF, Core rules ==\n");
    RESET(1);
    { txout_t oS = { .v=0, .spk=SPK_WPKH, .spklen=22 };
      u8 a1[32], p1[32], c1[32];
      /* fullrbf: a FINAL-sequence original is still replaceable */
      oS.v = 1000000-500;
      n = mk(tx, &(txin_t){ .tag=1, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(a1, tx, n, sc, sizeof sc);
      ck("original (seq final, fee 500) in", mpool_policy_add(pol, st, mp, tx, n, a1, ux) == 1);
      /* equal-fee replacement: rule 3 -> "insufficient fee" */
      { static const u8 ss1[1] = { 0x51 };
        oS.v = 1000000-500;
        n = mk(tx, &(txin_t){ .tag=1, .idx=0, .seq=0xffffffffu, .ss=ss1, .sslen=1 }, 1, &oS, 1);
        tx_txid(id, tx, n, sc, sizeof sc);
        r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
        ck("equal-fee replacement refused", r == 0); ckr("...as", pol, "insufficient fee"); }
      /* +30 sat on a ~67vB replacement: rule 4 (needs ~67) -> refused */
      { static const u8 ss1[1] = { 0x51 };
        oS.v = 1000000-530;
        n = mk(tx, &(txin_t){ .tag=1, .idx=0, .seq=0xffffffffu, .ss=ss1, .sslen=1 }, 1, &oS, 1);
        tx_txid(id, tx, n, sc, sizeof sc);
        r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
        ck("+30-sat bump on ~67vB refused (rule 4)", r == 0);
        ckr("...as", pol, "insufficient fee"); }
      /* proper bump: accepted despite final seq (fullrbf) */
      oS.v = 1000000-1500;
      n = mk(tx, &(txin_t){ .tag=1, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      { u8 rep[32]; tx_txid(rep, tx, n, sc, sizeof sc);
        r = mpool_policy_add(pol, st, mp, tx, n, rep, ux);
        ck("full-rbf replacement of a final-seq original accepted", r == 1);
        unsigned long l; ck("original evicted", mpool_get(mp, a1, &l) == NULL); }

      /* descendants: original P (fee 400) + child C (fee 400); replacement
       * paying 900 (> P but < P+C+incr) refused; 1500 accepted, C gone too */
      oS.v = 1000000-400;
      n = mk(tx, &(txin_t){ .tag=2, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(p1, tx, n, sc, sizeof sc);
      ck("P in", mpool_policy_add(pol, st, mp, tx, n, p1, ux) == 1);
      oS.v = (1000000-400)-400;
      n = mk(tx, &(txin_t){ .previd=p1, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(c1, tx, n, sc, sizeof sc);
      ck("C in", mpool_policy_add(pol, st, mp, tx, n, c1, ux) == 1);
      { static const u8 ss1[1] = { 0x51 };
        /* fees replaced = 800 (P 400 + C 400); the increment must cover the
         * replacement's OWN vsize (~83) at 1 sat/vB -> 850 is 50 short */
        oS.v = 1000000-850;
        n = mk(tx, &(txin_t){ .tag=2, .idx=0, .seq=0xffffffffu, .ss=ss1, .sslen=1 }, 1, &oS, 1);
        tx_txid(id, tx, n, sc, sizeof sc);
        r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
        ck("850 pays P+C but not the replacement's own vsize: refused", r == 0);
        ckr("...as", pol, "insufficient fee"); }
      oS.v = 1000000-1500;
      n = mk(tx, &(txin_t){ .tag=2, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(id, tx, n, sc, sizeof sc);
      r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
      ck("1500 covers P+C+increment: accepted", r == 1);
      { unsigned long l;
        ck("P evicted", mpool_get(mp, p1, &l) == NULL);
        ck("C evicted WITH P (descendant)", mpool_get(mp, c1, &l) == NULL); }

      /* ---- MEM-7 (audit 2026-09-03): PaysMoreThanConflicts ----
       *
       * Rules 3+4 above are ABSOLUTE-fee rules. On their own a replacement
       * that pays more in TOTAL but far less PER BYTE wins, which is worse
       * for a miner than what it evicted and is what Core's
       * PaysMoreThanConflicts (pre-v31) and feerate-diagram check (v31)
       * exist to refuse.
       *
       * The fixture is the audit's, scaled to this harness: a small original
       * at a high feerate, and a replacement bloated with outputs so that it
       * pays MORE in total -- clearing rules 3 and 4 -- at a much lower
       * feerate. If only the absolute rules were in force it would be
       * accepted and the original evicted. */
      { u8 sm[32];
        oS.v = 1000000 - 5000;                       /* fee 5000 over ~110 vB */
        n = mk(tx, &(txin_t){ .tag=9, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
        tx_txid(sm, tx, n, sc, sizeof sc);
        ck("MEM-7 small high-feerate original in", mpool_policy_add(pol, st, mp, tx, n, sm, ux) == 1);

        /* 200 outputs of 31 bytes each: ~6.3 kB of extra vsize. */
        enum { NBLOAT = 200 };
        static txout_t big[NBLOAT];
        /* fee 12,000: comfortably above the 1 sat/vB relay floor for ~6.4 kvB
         * (so the refusal below cannot be the floor), above the 5,000 it
         * replaces (so rules 3+4 pass), and ~1.9 sat/vB against the
         * original's ~45 (so only PaysMoreThanConflicts can refuse it). */
        big[0].v = 1000000 - 12000; big[0].spk = SPK_WPKH; big[0].spklen = 22;
        for (int q = 1; q < NBLOAT; q++){ big[q].v = 0; big[q].spk = SPK_WPKH; big[q].spklen = 22; }
        n = mk(tx, &(txin_t){ .tag=9, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, big, NBLOAT);
        tx_txid(id, tx, n, sc, sizeof sc);
        r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
        /* Rules 3+4 alone would let this through: it pays 12,000 against the
         * 5,000 it replaces, and the 7,000 increment covers its own ~6.4 kvB
         * at the incremental rate. */
        ck("MEM-7 a bigger-but-cheaper-per-byte replacement is REFUSED", r == 0);
        ckr("...as", pol, "insufficient fee");
        { unsigned long l;
          ck("MEM-7 the original was NOT evicted by the refused replacement",
             mpool_get(mp, sm, &l) != NULL); }

        /* Control: the same replacement at a feerate ABOVE the original is
         * accepted, so the new rule is not simply refusing large txs. */
        big[0].v = 1000000 - 400000;                 /* fee 400000 over ~6.4 kvB */
        n = mk(tx, &(txin_t){ .tag=9, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, big, NBLOAT);
        tx_txid(id, tx, n, sc, sizeof sc);
        r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
        ck("MEM-7 the same replacement at a HIGHER feerate is accepted", r == 1);
        { unsigned long l;
          ck("MEM-7 ...and then the original is evicted", mpool_get(mp, sm, &l) == NULL); } }

      /* disjointness: replacement double-spends U's prevout AND spends U's
       * own output -> "bad-txns-spends-conflicting-tx" */
      { u8 u1[32];
        oS.v = 1000000-600;
        n = mk(tx, &(txin_t){ .tag=3, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
        tx_txid(u1, tx, n, sc, sizeof sc);
        ck("U in", mpool_policy_add(pol, st, mp, tx, n, u1, ux) == 1);
        txin_t both[2] = {
            { .tag=3, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 },   /* conflicts with U */
            { .previd=u1, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 } /* spends U's output */
        };
        txout_t o2 = { .v=1000000-5000, .spk=SPK_WPKH, .spklen=22 };
        n = mk(tx, both, 2, &o2, 1); tx_txid(id, tx, n, sc, sizeof sc);
        r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
        ck("spend-of-conflicting-tx refused", r == 0);
        ckr("...as", pol, "bad-txns-spends-conflicting-tx"); }

      /* no new unconfirmed inputs: replacement adds a spend of ANOTHER
       * pool tx's output -> "replacement-adds-unconfirmed" */
      { u8 w1[32], v1[32];
        oS.v = 1000000-600;
        n = mk(tx, &(txin_t){ .tag=4, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
        tx_txid(w1, tx, n, sc, sizeof sc);
        ck("W in", mpool_policy_add(pol, st, mp, tx, n, w1, ux) == 1);
        oS.v = 1000000-600;
        n = mk(tx, &(txin_t){ .tag=5, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
        tx_txid(v1, tx, n, sc, sizeof sc);
        ck("V in (unrelated)", mpool_policy_add(pol, st, mp, tx, n, v1, ux) == 1);
        txin_t both[2] = {
            { .tag=4, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 },    /* conflicts with W */
            { .previd=v1, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 } /* NEW unconfirmed */
        };
        txout_t o2 = { .v=1000000-9000, .spk=SPK_WPKH, .spklen=22 };
        n = mk(tx, both, 2, &o2, 1); tx_txid(id, tx, n, sc, sizeof sc);
        r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
        ck("new-unconfirmed-input replacement refused", r == 0);
        ckr("...as", pol, "replacement-adds-unconfirmed"); }
    }

    printf("\n== 4b: classic signaling when fullrbf is OFF ==\n");
    RESET(1);
    { mpool_policy_init(pol, 1000 /* sat/kvB: 1 sat/vB, as before */, 25, 101000, 25, 101000, 0);   /* fullrbf OFF */
      mpool_policy_set_acceptnonstd(pol, 1);
      txout_t oS = { .v=1000000-500, .spk=SPK_WPKH, .spklen=22 };
      u8 f1[32], s1[32];
      /* final-seq original: NOT replaceable */
      n = mk(tx, &(txin_t){ .tag=1, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(f1, tx, n, sc, sizeof sc);
      ck("non-signaling original in", mpool_policy_add(pol, st, mp, tx, n, f1, ux) == 1);
      oS.v = 1000000-5000;
      n = mk(tx, &(txin_t){ .tag=1, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(id, tx, n, sc, sizeof sc);
      r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
      ck("its replacement refused", r == 0); ckr("...as", pol, "txn-mempool-conflict");
      /* signaling original (seq fffffffd): replaceable */
      oS.v = 1000000-500;
      n = mk(tx, &(txin_t){ .tag=2, .idx=0, .seq=0xfffffffdu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(s1, tx, n, sc, sizeof sc);
      ck("signaling original in", mpool_policy_add(pol, st, mp, tx, n, s1, ux) == 1);
      oS.v = 1000000-5000;
      n = mk(tx, &(txin_t){ .tag=2, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(id, tx, n, sc, sizeof sc);
      r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
      ck("its replacement accepted (signal checked on the REPLACED tx)", r == 1); }

    printf("\n== 5: block-connect reconciliation ==\n");
    RESET(1);
    { txout_t oS = { .v=1000000-500, .spk=SPK_WPKH, .spklen=22 };
      u8 A[32], Achild[32], B[32], Bchild[32];
      static u8 atx[256]; long alen;
      /* A confirmed by the block; A's child must SURVIVE. */
      alen = mk(atx, &(txin_t){ .tag=1, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(A, atx, alen, sc, sizeof sc);
      ck("A in", mpool_policy_add(pol, st, mp, atx, alen, A, ux) == 1);
      oS.v = (1000000-500)-500;
      n = mk(tx, &(txin_t){ .previd=A, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(Achild, tx, n, sc, sizeof sc);
      ck("A's child in", mpool_policy_add(pol, st, mp, tx, n, Achild, ux) == 1);
      /* B double-spends what the block spends; B and B's CHILD must go. */
      oS.v = 1000000-500;
      n = mk(tx, &(txin_t){ .tag=2, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(B, tx, n, sc, sizeof sc);
      ck("B in", mpool_policy_add(pol, st, mp, tx, n, B, ux) == 1);
      oS.v = (1000000-500)-500;
      n = mk(tx, &(txin_t){ .previd=B, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(Bchild, tx, n, sc, sizeof sc);
      ck("B's child in", mpool_policy_add(pol, st, mp, tx, n, Bchild, ux) == 1);

      /* build the block: header(80) + varint(3) + coinbase + A + a
       * DIFFERENT spend of coin tag2 (conflicts with B) */
      static u8 blk[4096]; long bl = 0;
      memset(blk, 0, 80); bl = 80;
      blk[bl++] = 3;
      { static u8 zero32[32];
        txout_t oc = { .v=5000000000ULL, .spk=SPK_WPKH, .spklen=22 };
        static const u8 ssc[1] = { 0x51 };
        txin_t cb = { .previd=zero32, .idx=0xffffffffu, .seq=0xffffffffu, .ss=ssc, .sslen=1 };
        bl += mk(blk+bl, &cb, 1, &oc, 1); }
      memcpy(blk+bl, atx, alen); bl += alen;
      { txout_t ob = { .v=1000000-700, .spk=SPK_WPKH, .spklen=22 };
        static const u8 ssb[2] = { 0x51, 0x51 };
        txin_t ib = { .tag=2, .idx=0, .seq=0xffffffffu, .ss=ssb, .sslen=2 };
        bl += mk(blk+bl, &ib, 1, &ob, 1); }

      long rm = mpool_policy_block_connect(st, mp, blk, (unsigned long)bl);
      ck("reconcile removed exactly A, B, B-child", rm == 3);
      { unsigned long l;
        ck("A gone (confirmed)", mpool_get(mp, A, &l) == NULL);
        ck("A's child SURVIVES", mpool_get(mp, Achild, &l) != NULL);
        ck("B gone (conflicted)", mpool_get(mp, B, &l) == NULL);
        ck("B's child gone WITH it", mpool_get(mp, Bchild, &l) == NULL); }

      /* rolling decay: bump the floor, then time-travel the last-update
       * stamp back 25h (white-box poke at st+56; layout documented in the
       * policy header) -- after a block the floor must have decayed by
       * about two half-lives, or to zero if below incremental/2. */
      { extern u64 mpool_policy_min_fee(void*);
        u64* fl   = (u64*)((char*)st+48);
        u64* last = (u64*)((char*)st+56);
        *fl = 40000;                       /* 40 sat/vB, sat/kvB units */
        *last = (u64)0;                    /* epoch: >> 25h ago */
        /* bit0 already set by block_connect above -> decay allowed */
        u64 after = mpool_policy_min_fee(st);
        ck("floor decayed after the block (epoch-old stamp)", after < 40000);
        ck("...to (well) under a quarter", after < 10000); } }

    printf("\n== 6: expiry takes the descendant package ==\n");
    RESET(1);
    { txout_t oS = { .v=1000000-500, .spk=SPK_WPKH, .spklen=22 };
      u8 P[32], C[32];
      n = mk(tx, &(txin_t){ .tag=1, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(P, tx, n, sc, sizeof sc);
      ck("P in", mpool_policy_add(pol, st, mp, tx, n, P, ux) == 1);
      oS.v = (1000000-500)-500;
      n = mk(tx, &(txin_t){ .previd=P, .idx=0, .seq=0xffffffffu, .ss=EMPTY, .sslen=0 }, 1, &oS, 1);
      tx_txid(C, tx, n, sc, sizeof sc);
      ck("C in", mpool_policy_add(pol, st, mp, tx, n, C, ux) == 1);
      long rm = mpool_policy_expire_one(st, mp, P);
      ck("expiring P removed 2 entries", rm == 2);
      { unsigned long l;
        ck("P gone", mpool_get(mp, P, &l) == NULL);
        ck("C gone with it", mpool_get(mp, C, &l) == NULL); } }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
