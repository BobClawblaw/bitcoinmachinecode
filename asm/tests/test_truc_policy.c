/* test_truc_policy.c -- BIP431 TRUC (version=3) topology rules in the mempool
 * policy layer (bitcoin_mempool_policy.c).
 *
 * TRUC buys predictable fee-bumping by accepting a much tighter shape: one
 * unconfirmed ancestor, one unconfirmed descendant, a small child, and no
 * mixing with non-TRUC unconfirmed relatives. The rules that matter are the
 * ones that are easy to implement as "v3 transactions are limited", when in
 * fact half of them constrain NON-v3 transactions -- a v2 child may not
 * spend a v3 parent either, and getting that backwards leaves the pinning
 * hole TRUC exists to close.
 *
 * Everything here runs with standardness ON, because TRUC is policy: the
 * last case proves the -acceptnonstdtxn escape hatch turns it off, the same
 * way it turns off the rest of IsStandardTx.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern size_t mpool_struct_size(unsigned long slots);
extern void   mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern const unsigned char* mpool_get(void* mp, const unsigned char txid[32], unsigned long* out_len);
extern size_t utxo_struct_size(unsigned long slots);
extern void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long blob_cap);
extern long   utxo_put(void* u, const unsigned char txid[32], unsigned long index,
                       unsigned long long value, unsigned long height,
                       unsigned long is_coinbase, const unsigned char* script, unsigned long slen);
extern long   utxo_get(void* u, const unsigned char txid[32], unsigned long index,
                       unsigned long long* value, unsigned long* height,
                       unsigned long* is_coinbase, const unsigned char** script, unsigned long* slen);
extern size_t mpool_policy_state_size(unsigned n);
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

/* a standard-shaped tx: P2WPKH outputs, empty scriptSigs, chosen version */
static unsigned long mk_tx(unsigned char* out, unsigned ver,
                           const unsigned char prev[32], unsigned vout,
                           int n_out, unsigned long long val, unsigned char tag){
    unsigned char* p = out;
    p[0]=(unsigned char)ver; p[1]=0; p[2]=0; p[3]=0; p+=4;
    *p++ = 1;                                        /* one input */
    memcpy(p, prev, 32); p += 32;
    p[0]=(unsigned char)vout; p[1]=(unsigned char)(vout>>8);
    p[2]=(unsigned char)(vout>>16); p[3]=(unsigned char)(vout>>24); p += 4;
    *p++ = 0;                                        /* empty scriptSig */
    p[0]=0xfd;p[1]=0xff;p[2]=0xff;p[3]=0xff; p += 4; /* nSequence, signals RBF */
    if (n_out < 253) *p++ = (unsigned char)n_out;
    else { *p++ = 0xfd; *p++ = (unsigned char)n_out; *p++ = (unsigned char)(n_out>>8); }
    for (int i=0;i<n_out;i++){
        for (int k=0;k<8;k++) *p++ = (unsigned char)(val >> (8*k));
        *p++ = 22; *p++ = 0x00; *p++ = 0x14;
        for (int k=0;k<20;k++) *p++ = (unsigned char)(k + i + tag);
    }
    p[0]=0;p[1]=0;p[2]=0;p[3]=0; p += 4;             /* nLockTime */
    return (unsigned long)(p - out);
}

static unsigned char pol[128];
static unsigned char stbuf[1<<20];
static unsigned char mp[40 + 4096*48 + 8];
static unsigned char mblob[4<<20];
static unsigned char ux[40 + 4096*48 + 8];
static unsigned char ublob[1<<16];
static unsigned char scratch[1<<20];

/* a fresh world each case: TRUC is about mempool SHAPE, so cases must not
 * inherit each other's graphs */
static void world(int nonstd){
    memset(stbuf, 0, sizeof stbuf);
    /* Core's default ancestor/descendant limits, deliberately generous: a
     * rejection in these cases must come from TRUC, not from running into
     * the ordinary chain limits. */
    mpool_policy_init(pol, 1, 25, 101000, 25, 101000, 1);
    mpool_policy_set_acceptnonstd(pol, nonstd ? 1 : 0);
    mpool_policy_state_init(stbuf, 256);
    mpool_init(mp, 4096, mblob, sizeof mblob);
    utxo_init(ux, 4096, ublob, sizeof ublob);
    for (unsigned char c = 0xA0; c <= 0xA4; c++){
        unsigned char t[32]; memset(t, c, 32);
        utxo_put(ux, t, 0, 100000000ull, 0, 0, (const unsigned char*)"\x51", 1);
    }
}

static long add(unsigned char* tx, unsigned long n, unsigned char id[32]){
    if (tx_txid(id, tx, n, scratch, sizeof scratch) != 1){ printf("tx_txid failed\n"); exit(2); }
    return mpool_policy_add(pol, stbuf, mp, tx, n, id, ux);
}
static int is_truc_reject(long rv){
    const char* r = mpool_policy_reason(pol);
    return rv != 1 && r && !strcmp(r, "TRUC-violation");
}

int main(void){
    static unsigned char A[64<<10], B[64<<10], C[64<<10];
    unsigned char seed[32]; memset(seed, 0xA0, 32);
    unsigned char ida[32], idb[32], idc[32];
    unsigned long la, lb, lc;

    printf("== a TRUC parent and its single TRUC child ==\n");
    world(0);
    la = mk_tx(A, 3, seed, 0, 2, 1000000, 1);
    ck("v3 parent accepted", add(A, la, ida) == 1);
    lb = mk_tx(B, 3, ida, 0, 1, 900000, 2);
    ck("v3 child of a v3 parent accepted", add(B, lb, idb) == 1);

    printf("\n== the parent gets exactly ONE child ==\n");
    /* a second child, spending the parent's OTHER output: no input conflict
     * with the first child, so only the TRUC descendant rule can catch it */
    lc = mk_tx(C, 3, ida, 1, 1, 900000, 3);
    { long rv = add(C, lc, idc);
      ck("a second v3 child is refused", is_truc_reject(rv));
      unsigned long ml;
      ck("...and is not in the pool", mpool_get(mp, idc, &ml) == NULL); }

    printf("\n== TRUC and non-TRUC do not mix, in EITHER direction ==\n");
    world(0);
    la = mk_tx(A, 3, seed, 0, 2, 1000000, 1);
    ck("v3 parent accepted", add(A, la, ida) == 1);
    lb = mk_tx(B, 2, ida, 0, 1, 900000, 2);
    ck("a v2 child may NOT spend a v3 parent", is_truc_reject(add(B, lb, idb)));

    world(0);
    la = mk_tx(A, 2, seed, 0, 2, 1000000, 1);
    ck("v2 parent accepted", add(A, la, ida) == 1);
    lb = mk_tx(B, 3, ida, 0, 1, 900000, 2);
    ck("a v3 child may NOT spend a v2 parent", is_truc_reject(add(B, lb, idb)));

    printf("\n== one unconfirmed ancestor, not two ==\n");
    world(0);
    la = mk_tx(A, 3, seed, 0, 1, 1000000, 1);
    ck("v3 parent accepted", add(A, la, ida) == 1);
    lb = mk_tx(B, 3, ida, 0, 1, 900000, 2);
    ck("v3 child accepted", add(B, lb, idb) == 1);
    lc = mk_tx(C, 3, idb, 0, 1, 800000, 3);
    ck("a v3 GRANDchild is refused", is_truc_reject(add(C, lc, idc)));

    printf("\n== size caps: 10000 vB for a TRUC tx, 1000 vB for a TRUC child ==\n");
    world(0);
    /* ~31 bytes per P2WPKH output: 400 outputs is comfortably over 10000 vB */
    la = mk_tx(A, 3, seed, 0, 400, 100000, 1);
    ck("the fixture really is over 10000 vB", la > 10000);
    ck("an oversized v3 tx is refused", is_truc_reject(add(A, la, ida)));

    world(0);
    la = mk_tx(A, 3, seed, 0, 2, 1000000, 1);
    ck("v3 parent accepted", add(A, la, ida) == 1);
    /* 60 outputs: over the 1000 vB CHILD cap, well under the 10000 vB cap --
     * so only the child rule can reject it */
    lb = mk_tx(B, 3, ida, 0, 60, 10000, 2);
    ck("the fixture is between the two caps", lb > 1000 && lb < 10000);
    ck("an oversized v3 CHILD is refused", is_truc_reject(add(B, lb, idb)));

    printf("\n== a big v3 tx with no unconfirmed parent is fine ==\n");
    world(0);
    la = mk_tx(A, 3, seed, 0, 60, 100000, 1);
    ck("the fixture is over the child cap", la > 1000);
    ck("...but accepted, because it has no unconfirmed parent", add(A, la, ida) == 1);

    printf("\n== -acceptnonstdtxn turns TRUC off, like the rest of policy ==\n");
    world(1);
    la = mk_tx(A, 3, seed, 0, 2, 1000000, 1);
    ck("v3 parent accepted", add(A, la, ida) == 1);
    lb = mk_tx(B, 2, ida, 0, 1, 900000, 2);
    ck("a v2 child of a v3 parent is accepted under the escape hatch",
       add(B, lb, idb) == 1);

    printf("\n%s (%d checks, %d failures)\n",
           failures ? "TESTS FAILED" : "ALL TESTS PASSED", checks, failures);
    return failures ? 1 : 0;
}
