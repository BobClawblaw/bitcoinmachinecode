/* test_ephemeral_dust.c -- Core's ephemeral dust carve-out in the mempool
 * policy layer (bitcoin_mempool_policy.c).
 *
 * Dust is normally refused because it costs more to spend than it is worth
 * and then sits in the UTXO set forever. Core carves out one case: dust
 * created and swept inside the same package never reaches the UTXO set,
 * which is what makes a fee-bumping anchor output expressible at all.
 *
 * Two rules keep the carve-out safe and they only work as a pair -- a test
 * that checks one and not the other would pass on an implementation that is
 * still unsafe:
 *   1. a transaction carrying dust must pay ZERO fee, so no miner has an
 *      incentive to mine it alone and strand the dust;
 *   2. a child must sweep every dust output of its unconfirmed parents, so
 *      the parent can only be mined alongside the child that cleans up.
 * Drop rule 1 and stranding dust becomes profitable; drop rule 2 and the
 * dust survives in the UTXO set exactly as before.
 *
 * A 0-fee parent cannot clear the relay floor by itself, which is the whole
 * point -- so the accepting cases run with the PACKAGE fee context set, the
 * way a real submitpackage sets it.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void   mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern const unsigned char* mpool_get(void* mp, const unsigned char txid[32], unsigned long* out_len);
extern void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long blob_cap);
extern long   utxo_put(void* u, const unsigned char txid[32], unsigned long index,
                       unsigned long long value, unsigned long height,
                       unsigned long is_coinbase, const unsigned char* script, unsigned long slen);
extern long   utxo_get(void* u, const unsigned char txid[32], unsigned long index,
                       unsigned long long* value, unsigned long* height,
                       unsigned long* is_coinbase, const unsigned char** script, unsigned long* slen);
extern void   mpool_policy_state_init(void* st, unsigned n);
extern void   mpool_policy_init(void* pol, unsigned long long relay_fee_rate,
                                unsigned max_anc, unsigned max_anc_bytes,
                                unsigned max_desc, unsigned max_desc_bytes,
                                unsigned rbf_enabled);
extern void   mpool_policy_set_acceptnonstd(void*, unsigned);
extern long   mpool_policy_add(void* pol, void* st, void* mp,
                               const unsigned char* tx, unsigned long txlen,
                               const unsigned char txid[32], void* utxo);
extern const char* mpool_policy_reason(void* pol);
extern void   mpol_package_fee_context(unsigned long long fee, unsigned long long vsize);
extern int    tx_txid(unsigned char out[32], const unsigned char* tx,
                      unsigned long txlen, unsigned char* buf, unsigned long buflen);

long mempool_resolve_confirmed_utxo(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, const unsigned char** script, unsigned long* slen){
    unsigned long h, cb;
    return utxo_get(u, txid, index, value, &h, &cb, script, slen);
}

static int failures = 0, checks = 0;
static void ck(const char* l, int c){
    checks++;
    if (c) printf("  ok  %s\n", l);
    else { printf("  FAIL %s\n", l); failures++; }
}

/* P2WPKH dust threshold at Core's 3000 sat/kvB discard rate is 294 sat, so
 * 100 is dust and 50000 is not. */
#define DUSTY   100ull
#define SOLID   50000ull

static unsigned long mk_tx(unsigned char* out, unsigned ver,
                           const unsigned char prevs[][32], const unsigned* vouts, int n_in,
                           const unsigned long long* vals, int n_out, unsigned char tag){
    unsigned char* p = out;
    p[0]=(unsigned char)ver; p[1]=0; p[2]=0; p[3]=0; p+=4;
    *p++ = (unsigned char)n_in;
    for (int i=0;i<n_in;i++){
        memcpy(p, prevs[i], 32); p += 32;
        unsigned v = vouts[i];
        p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8);
        p[2]=(unsigned char)(v>>16); p[3]=(unsigned char)(v>>24); p += 4;
        *p++ = 0;
        p[0]=0xfd;p[1]=0xff;p[2]=0xff;p[3]=0xff; p += 4;
    }
    *p++ = (unsigned char)n_out;
    for (int i=0;i<n_out;i++){
        for (int k=0;k<8;k++) *p++ = (unsigned char)(vals[i] >> (8*k));
        *p++ = 22; *p++ = 0x00; *p++ = 0x14;
        for (int k=0;k<20;k++) *p++ = (unsigned char)(k + i + tag);
    }
    p[0]=0;p[1]=0;p[2]=0;p[3]=0; p += 4;
    return (unsigned long)(p - out);
}

static unsigned char pol[128];
static unsigned char stbuf[1<<20];
static unsigned char mp[40 + 4096*48 + 8];
static unsigned char mblob[4<<20];
static unsigned char ux[40 + 4096*48 + 8];
static unsigned char ublob[1<<16];
static unsigned char scratch[1<<20];
static unsigned long long FUND = 1000000ull;

static void world(int nonstd){
    memset(stbuf, 0, sizeof stbuf);
    mpool_policy_init(pol, 1000 /* sat/kvB: 1 sat/vB, as before */, 25, 101000, 25, 101000, 1);
    mpool_policy_set_acceptnonstd(pol, nonstd ? 1 : 0);
    mpool_policy_state_init(stbuf, 256);
    mpool_init(mp, 4096, mblob, sizeof mblob);
    utxo_init(ux, 4096, ublob, sizeof ublob);
    unsigned char t[32]; memset(t, 0xA0, 32);
    utxo_put(ux, t, 0, FUND, 0, 0, (const unsigned char*)"\x51", 1);
    mpol_package_fee_context(0, 0);
}
static long add(unsigned char* tx, unsigned long n, unsigned char id[32]){
    if (tx_txid(id, tx, n, scratch, sizeof scratch) != 1){ printf("tx_txid failed\n"); exit(2); }
    return mpool_policy_add(pol, stbuf, mp, tx, n, id, ux);
}
static int rejected_as(long rv, const char* want){
    const char* r = mpool_policy_reason(pol);
    return rv != 1 && r && !strcmp(r, want);
}

int main(void){
    static unsigned char A[8192], B[8192];
    unsigned char seed[32]; memset(seed, 0xA0, 32);
    unsigned char prevs[4][32]; unsigned vouts[4];
    unsigned long long vals[4];
    unsigned char ida[32], idb[32];
    unsigned long la, lb;

    printf("== rule 1: dust is only allowed on a ZERO-fee transaction ==\n");
    world(0);
    memcpy(prevs[0], seed, 32); vouts[0] = 0;
    /* pays a fee (outputs sum to less than the input), and carries dust */
    vals[0] = FUND - 10000ull; vals[1] = DUSTY;
    la = mk_tx(A, 3, prevs, vouts, 1, vals, 2, 1);
    ck("a fee-paying transaction with dust is refused", rejected_as(add(A, la, ida), "dust"));

    /* the same shape at exactly zero fee, inside a package -- accepted */
    world(0);
    vals[0] = FUND - DUSTY; vals[1] = DUSTY;      /* sums to the input: fee 0 */
    la = mk_tx(A, 3, prevs, vouts, 1, vals, 2, 1);
    mpol_package_fee_context(100000, 500);         /* as submitpackage sets it */
    ck("the same transaction at ZERO fee is accepted", add(A, la, ida) == 1);
    mpol_package_fee_context(0, 0);

    printf("\n== at most ONE dust output, even at zero fee ==\n");
    world(0);
    vals[0] = FUND - 2*DUSTY; vals[1] = DUSTY; vals[2] = DUSTY;
    la = mk_tx(A, 3, prevs, vouts, 1, vals, 3, 1);
    mpol_package_fee_context(100000, 500);
    ck("two dust outputs are refused", rejected_as(add(A, la, ida), "dust"));
    mpol_package_fee_context(0, 0);

    printf("\n== rule 2: the child must SWEEP the parent's dust ==\n");
    world(0);
    vals[0] = FUND - DUSTY; vals[1] = DUSTY;
    la = mk_tx(A, 3, prevs, vouts, 1, vals, 2, 1);
    mpol_package_fee_context(100000, 500);
    ck("0-fee dust parent accepted", add(A, la, ida) == 1);
    mpol_package_fee_context(0, 0);

    /* a child that spends only the SOLID output and leaves the dust behind:
     * exactly the transaction that would strand dust in the UTXO set */
    memcpy(prevs[0], ida, 32); vouts[0] = 0;
    vals[0] = FUND - DUSTY - 20000ull;
    lb = mk_tx(B, 3, prevs, vouts, 1, vals, 1, 2);
    ck("a child that ignores the parent's dust is refused",
       rejected_as(add(B, lb, idb), "missing-ephemeral-spends"));
    { unsigned long ml; ck("...and is not in the pool", mpool_get(mp, idb, &ml) == NULL); }

    /* the same child, now also spending the dust output: accepted */
    memcpy(prevs[0], ida, 32); vouts[0] = 0;
    memcpy(prevs[1], ida, 32); vouts[1] = 1;
    vals[0] = FUND - 20000ull;
    lb = mk_tx(B, 3, prevs, vouts, 2, vals, 1, 3);
    ck("a child that sweeps the dust is accepted", add(B, lb, idb) == 1);

    printf("\n== -acceptnonstdtxn turns the whole carve-out off ==\n");
    world(1);
    memcpy(prevs[0], seed, 32); vouts[0] = 0;
    vals[0] = FUND - 10000ull; vals[1] = DUSTY;
    la = mk_tx(A, 3, prevs, vouts, 1, vals, 2, 1);
    ck("a fee-paying transaction with dust is accepted under the escape hatch",
       add(A, la, ida) == 1);

    printf("\n%s (%d checks, %d failures)\n",
           failures ? "TESTS FAILED" : "ALL TESTS PASSED", checks, failures);
    return failures ? 1 : 0;
}
