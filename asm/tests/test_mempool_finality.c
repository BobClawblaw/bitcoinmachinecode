/* tests/test_mempool_finality.c -- MEM-1 (audit 2026-09-03): the mempool
 * must reject non-final transactions, as Core's PreChecks does.
 *
 * THE DEFECT. bitcoin_mempool_policy.c's parse_tx read the sequences (for
 * BIP125 signalling only) and never decoded nLockTime at all -- the audit's
 * words: "the 4-byte nLockTime is never decoded on the admission path". So a
 * transaction with nLockTime = tip+500 passed every check, entered the shared
 * pool, was announced to every peer (Core peers reject it as non-final and
 * keep it in recent-rejects), and was selected by getblocktemplate. A miner
 * on that template produces a block Core rejects with bad-txns-nonfinal.
 *
 * WHAT IS ASSERTED. Core's PreChecks evaluates against the NEXT block's
 * height and the tip's median time past (BIP113), so the fixture sets that
 * context explicitly through mpool_policy_set_seqlocks and then drives real
 * transactions through mpool_policy_add:
 *
 *   height-based nLockTime in the future + non-final sequence -> "non-final"
 *   the SAME nLockTime with every sequence FINAL              -> accepted
 *   nLockTime 0 with a non-final sequence                     -> accepted
 *   time-based nLockTime past the tip MTP + non-final         -> "non-final"
 *   time-based nLockTime already elapsed                      -> accepted
 *   context not configured (next_height < 0)                  -> accepted
 *
 * Only two are rejections. A test that checked one of them alone would pass
 * against a rule that rejects every transaction carrying a non-final
 * sequence, which is most of the RBF-signalling traffic on the network -- so
 * the accepts are the load-bearing half.
 *
 * The last case pins the deliberate escape: with no chain context the rule is
 * SKIPPED rather than evaluated against a zero height, which would reject
 * everything. Every unit test in this suite that drives the policy layer with
 * synthetic transactions relies on that.
 *
 * Usage: ./test_mempool_finality
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned char u8;
typedef unsigned long long u64;

extern void   mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern const u8* mpool_get(void* mp, const u8 txid[32], unsigned long* len);
extern void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long   utxo_put(void* u, const u8 txid[32], unsigned long index, u64 value,
                       unsigned long height, unsigned long cb, const u8* script, unsigned long slen);
extern long   utxo_get(void* u, const u8 txid[32], unsigned long index, u64* value,
                       unsigned long* height, unsigned long* cb, const u8** script, unsigned long* slen);
extern void   mpool_policy_init(void* pol, u64 relay_fee_kvb, unsigned max_anc, unsigned max_anc_bytes,
                                unsigned max_desc, unsigned max_desc_bytes, unsigned rbf);
extern void   mpool_policy_set_acceptnonstd(void* pol, int on);
extern void   mpool_policy_state_init(void* st, unsigned long slots);
extern long   mpool_policy_add(void* pol, void* st, void* mp, const u8* tx, unsigned long txlen,
                               const u8 txid[32], void* utxo);
extern const char* mpool_policy_reason(void* pol);
extern int    tx_txid(u8 out[32], const u8* tx, unsigned long len, u8* scratch, unsigned long cap);
extern void   mpool_policy_set_seqlocks(long next_height, unsigned long tip_mtp, int csv_active,
                                        long (*height_fn)(const unsigned char*, unsigned long,
                                                          unsigned long long*));

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    unsigned long h, cb; return utxo_get(u, txid, index, value, &h, &cb, script, slen);
}

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("ok  : %s\n", l); else { printf("FAIL: %s\n", l); fails++; } }

static u8 sc[4096];
/* 1-in 1-out spending (prev:0), with a chosen nSequence and nLockTime */
static long mk(u8* out, const u8 prev[32], u64 invalue, u64 fee, unsigned seq, unsigned locktime){
    u8* p = out;
    *p++=2;*p++=0;*p++=0;*p++=0;
    *p++=1; memcpy(p, prev, 32); p+=32; *p++=0;*p++=0;*p++=0;*p++=0; *p++=0;
    for (int i=0;i<4;i++) *p++ = (u8)(seq >> (8*i));
    *p++=1; u64 o = invalue - fee; for (int i=0;i<8;i++) *p++ = (u8)(o >> (8*i));
    *p++=1; *p++=0x51;
    for (int i=0;i<4;i++) *p++ = (u8)(locktime >> (8*i));
    return p - out;
}

/* MEM-4 needs the CLAIMS table (one entry per INPUT) to fill while NODE slots
 * (one per transaction) remain -- that is the whole shape of the defect. A
 * 1-in fixture cannot express it: both tables fill together and the node-slot
 * check refuses first, which is exactly what the negative control caught in
 * the first draft of this section. So these transactions carry NIN inputs. */
#define MEM4_NIN 4
static long mk_multi(u8* out, unsigned first_coin, u64 fee, unsigned nin){
    u8* p = out;
    *p++=2;*p++=0;*p++=0;*p++=0;
    *p++=(u8)nin;
    for (unsigned k = 0; k < nin; k++){
        u8 coin[32]; memset(coin, (u8)(first_coin + k), 32);
        memcpy(p, coin, 32); p += 32;
        *p++=0;*p++=0;*p++=0;*p++=0;          /* prevout index 0 */
        *p++=0;                                /* empty scriptSig */
        *p++=0xff;*p++=0xff;*p++=0xff;*p++=0xff;
    }
    *p++=1;
    u64 o = (u64)nin * 1000000ULL - fee;
    for (int i=0;i<8;i++) *p++ = (u8)(o >> (8*i));
    *p++=1; *p++=0x51;
    *p++=0;*p++=0;*p++=0;*p++=0;
    return p - out;
}

#define TIP_HEIGHT 800000L
#define TIP_MTP    1700000000UL

static u8 pol[128];
static u8 st[1<<20];
static u8 mp[40 + 64*48 + 8], mblob[4096];
static u8 ux[40 + 256*48 + 8], ublob[1<<14];
static int g_coin = 0;

static void reset(void){
    memset(st,0,sizeof st);
    mpool_policy_init(pol, 1000, 25, 101000, 25, 101000, 1);
    mpool_policy_set_acceptnonstd(pol, 1);
    mpool_policy_state_init(st, 256);
    mpool_init(mp, 64, mblob, sizeof mblob);
    utxo_init(ux, 256, ublob, sizeof ublob);
    for (int i=1;i<=16;i++){ u8 t[32]; memset(t,(u8)i,32);
        utxo_put(ux, t, 0, 1000000ULL, 100, 0, (const u8*)"\x51", 1); }
    g_coin = 0;
}

/* returns 1 accepted, 0 rejected; fills why */
static long try_tx(unsigned seq, unsigned locktime, const char** why){
    u8 coin[32]; memset(coin, (u8)(++g_coin), 32);
    u8 tx[128]; long n = mk(tx, coin, 1000000ULL, 5000, seq, locktime);
    u8 id[32]; tx_txid(id, tx, (unsigned long)n, sc, sizeof sc);
    long r = mpool_policy_add(pol, st, mp, tx, (unsigned long)n, id, ux);
    *why = r == 1 ? "" : mpool_policy_reason(pol);
    return r;
}

int main(void){
    const char* why;

    printf("== chain context configured: next=%ld mtp=%lu ==\n", TIP_HEIGHT+1, TIP_MTP);
    reset();
    mpool_policy_set_seqlocks(TIP_HEIGHT + 1, TIP_MTP, 0, 0);

    long r = try_tx(0xfffffffeu, (unsigned)(TIP_HEIGHT + 500), &why);
    printf("      future height locktime + non-final seq -> %ld (%s)\n", r, why);
    ck("MEM-1 a height-locked future tx is rejected", r == 0);
    ck("MEM-1 ...with Core's reason \"non-final\"", r == 0 && !strcmp(why, "non-final"));

    r = try_tx(0xffffffffu, (unsigned)(TIP_HEIGHT + 500), &why);
    if (r != 1) printf("      (reason: %s)\n", why);
    ck("MEM-1 the same locktime with FINAL sequences is accepted", r == 1);

    r = try_tx(0xfffffffeu, 0u, &why);
    if (r != 1) printf("      (reason: %s)\n", why);
    ck("MEM-1 nLockTime 0 is final regardless of sequence", r == 1);

    r = try_tx(0xfffffffeu, (unsigned)(TIP_MTP + 10000), &why);
    printf("      future TIME locktime + non-final seq -> %ld (%s)\n", r, why);
    ck("MEM-1 a time-locked future tx is rejected", r == 0);
    ck("MEM-1 ...also as \"non-final\"", r == 0 && !strcmp(why, "non-final"));

    r = try_tx(0xfffffffeu, (unsigned)(TIP_MTP - 10000), &why);
    if (r != 1) printf("      (reason: %s)\n", why);
    ck("MEM-1 an elapsed time lock is accepted", r == 1);

    printf("\n== chain context NOT configured ==\n");
    reset();
    mpool_policy_set_seqlocks(-1, 0, 0, 0);
    r = try_tx(0xfffffffeu, (unsigned)(TIP_HEIGHT + 500), &why);
    if (r != 1) printf("      (reason: %s)\n", why);
    ck("MEM-1 with no chain context the rule is SKIPPED, not evaluated at zero", r == 1);

    printf("\n== MEM-4: a full claims table refuses rather than registering nothing ==\n");
    /* The claims and outreg tables hold one entry per INPUT and per OUTPUT but
     * are sized one slot per NODE. Both insertion loops used to test
     * `if (n < cap)` and silently do nothing when full. Claims overflowing is
     * the dangerous one: the transaction's inputs are never registered, so
     * find_claim misses them and a LATER transaction spending the same output
     * sees no conflict and is accepted. Two conflicting transactions in the
     * pool, both relayed, both eligible for a block template that does not
     * check conflicts.
     *
     * Driven here by sizing the policy state deliberately small, so the
     * tables fill while the pool still has room -- which is exactly the real
     * shape of the defect (a 300 MB pool fills the 1M-slot claims table at
     * ~400-500K transactions).
     *
     * What is asserted is the INVARIANT, not a count: every transaction the
     * pool accepted must have its inputs registered. A test that only counted
     * refusals would pass against a rule that refuses everything. */
    {
        static unsigned char st4[1<<20];
        memset(st4, 0, sizeof st4);
        mpool_policy_init(pol, 1000, 25, 101000, 25, 101000, 1);
        mpool_policy_set_acceptnonstd(pol, 1);
        mpool_policy_state_init(st4, 8);          /* eight node slots */
        mpool_init(mp, 64, mblob, sizeof mblob);
        utxo_init(ux, 256, ublob, sizeof ublob);
        for (int i = 1; i <= 32; i++){ u8 t[32]; memset(t, (u8)i, 32);
            utxo_put(ux, t, 0, 1000000ULL, 100, 0, (const u8*)"\x51", 1); }
        mpool_policy_set_seqlocks(-1, 0, 0, 0);

        long accepted = 0, refused_full = 0;
        for (int i = 0; i < 6; i++){
            unsigned first = 1u + (unsigned)i * MEM4_NIN;
            u8 tx[256]; long n = mk_multi(tx, first, 5000, MEM4_NIN);
            u8 id[32]; tx_txid(id, tx, (unsigned long)n, sc, sizeof sc);
            long r = mpool_policy_add(pol, st4, mp, tx, (unsigned long)n, id, ux);
            if (r == 1){ accepted++; continue; }
            if (!strcmp(mpool_policy_reason(pol), "mempool full")) refused_full++;
        }
        printf("      accepted=%ld refused-full=%ld (8 node slots, %d inputs each)\n",
               accepted, refused_full, MEM4_NIN);

        ck("MEM-4 the small table really did fill (some tx were refused)",
           refused_full > 0);
        /* the invariant: claims used never exceeds the table, and every
         * accepted transaction contributed its input */
        { unsigned int cap_ = *(unsigned int*)(st4 + 4);
          unsigned int nclm = *(unsigned int*)(st4 + 12);
          printf("      claims used=%u cap=%u accepted=%ld\n", nclm, cap_, accepted);
          ck("MEM-4 claims used never exceeds the table", nclm <= cap_);
          ck("MEM-4 every accepted transaction registered ALL its inputs "
             "(none admitted unregistered)", (long)nclm >= accepted * MEM4_NIN); }
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
