/* test_package_policy.c -- context-free package checks (Core
 * policy/packages.cpp IsWellFormedPackage), including the two rules that are
 * easy to get subtly wrong:
 *
 *   - a duplicate input WITHIN one transaction is NOT "conflict-in-package".
 *     Core batch-adds each transaction's inputs only after checking it,
 *     precisely so that case falls to CheckTransaction as the consensus error
 *     bad-txns-inputs-duplicate. Comparing inputs one at a time passes every
 *     obvious test and silently relabels a consensus failure as a policy one.
 *   - topology is checked against "this transaction and every later one", so
 *     a transaction spending ITSELF is caught as package-not-sorted.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern int mpol_package_well_formed(const unsigned char* const* txs,
                                    const unsigned long* lens, int n,
                                    unsigned char* txids_out,
                                    unsigned long long* vsize_out, const char** reason);
extern int tx_txid(unsigned char out[32], const unsigned char* tx,
                   unsigned long txlen, unsigned char* buf, unsigned long buflen);

/* bitcoin_mempool_policy.c's single-transaction path resolves prevouts
 * through this; the PACKAGE checks under test are context-free and never
 * reach it, so a stub that resolves nothing is the honest wiring -- if one of
 * them ever started needing chain state, this would fail loudly rather than
 * quietly consult a fake UTXO set. */
long mempool_resolve_confirmed_utxo(void* u, const unsigned char txid[32], unsigned long index,
                                    unsigned long long* value, unsigned long* height,
                                    unsigned long* is_coinbase,
                                    const unsigned char** script, unsigned long* slen){
    (void)u;(void)txid;(void)index;(void)value;(void)height;(void)is_coinbase;(void)script;(void)slen;
    return 0;
}

static int failures = 0;
static void ck(const char* l, int c){ if(c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); failures++; } }

/* minimal tx: version | n_in | (prevout,vout,0-len script,seq)* | n_out | (value,spk)* | locktime */
static unsigned long mk_tx(unsigned char* out, const unsigned char prevs[][32],
                           const unsigned int* vouts, int n_in, int n_out, unsigned long long val){
    unsigned char* p = out;
    p[0]=2;p[1]=0;p[2]=0;p[3]=0; p+=4;
    *p++ = (unsigned char)n_in;
    for(int i=0;i<n_in;i++){
        memcpy(p, prevs[i], 32); p+=32;
        unsigned int v = vouts[i];
        p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8); p[2]=(unsigned char)(v>>16); p[3]=(unsigned char)(v>>24); p+=4;
        *p++ = 0;                                   /* empty scriptSig */
        p[0]=0xfd;p[1]=0xff;p[2]=0xff;p[3]=0xff; p+=4;   /* sequence */
    }
    *p++ = (unsigned char)n_out;
    for(int i=0;i<n_out;i++){
        for(int k=0;k<8;k++) *p++ = (unsigned char)(val >> (8*k));
        *p++ = 22; *p++ = 0x00; *p++ = 0x14;
        for(int k=0;k<20;k++) *p++ = (unsigned char)(k+i);
    }
    p[0]=0;p[1]=0;p[2]=0;p[3]=0; p+=4;
    return (unsigned long)(p - out);
}

int main(void){
    static unsigned char a[4096], b[4096], c[4096];
    static unsigned char scratch[1<<20];
    unsigned char pv[8][32]; unsigned int vo[8];
    const char* why;

    memset(pv[0], 0x11, 32); vo[0] = 0;
    unsigned long la = mk_tx(a, pv, vo, 1, 2, 100000);

    unsigned char atxid[32];
    if(tx_txid(atxid, a, la, scratch, sizeof scratch) != 1){ printf("tx_txid failed\n"); return 2; }

    printf("---- package well-formedness ----\n");

    /* 1. a plain parent -> child pair is well formed */
    { memcpy(pv[0], atxid, 32); vo[0] = 0;
      unsigned long lb = mk_tx(b, pv, vo, 1, 1, 90000);
      const unsigned char* txs[2] = { a, b }; unsigned long ls[2] = { la, lb };
      ck("parent then child is well formed", mpol_package_well_formed(txs, ls, 2, NULL, NULL, &why) == 1); }

    /* 2. child BEFORE parent -> package-not-sorted */
    { memcpy(pv[0], atxid, 32); vo[0] = 0;
      unsigned long lb = mk_tx(b, pv, vo, 1, 1, 90000);
      const unsigned char* txs[2] = { b, a }; unsigned long ls[2] = { lb, la };
      int r = mpol_package_well_formed(txs, ls, 2, NULL, NULL, &why);
      ck("child before parent -> package-not-sorted", r == 0 && !strcmp(why, "package-not-sorted")); }

    /* 3. the same transaction twice -> package-contains-duplicates */
    { const unsigned char* txs[2] = { a, a }; unsigned long ls[2] = { la, la };
      int r = mpol_package_well_formed(txs, ls, 2, NULL, NULL, &why);
      ck("duplicate transaction -> package-contains-duplicates",
         r == 0 && !strcmp(why, "package-contains-duplicates")); }

    /* 4. two DIFFERENT transactions spending one outpoint -> conflict */
    { memset(pv[0], 0x11, 32); vo[0] = 0;
      unsigned long lc = mk_tx(c, pv, vo, 1, 1, 50000);   /* same input as `a`, different outputs */
      const unsigned char* txs[2] = { a, c }; unsigned long ls[2] = { la, lc };
      int r = mpol_package_well_formed(txs, ls, 2, NULL, NULL, &why);
      ck("two txs on one outpoint -> conflict-in-package",
         r == 0 && !strcmp(why, "conflict-in-package")); }

    /* 5. THE TRAP: one transaction spending the SAME outpoint twice is a
     *    CONSENSUS error (bad-txns-inputs-duplicate), not a package one.
     *    Core batch-adds per transaction so this never reaches the package
     *    conflict rule; a naive one-input-at-a-time check would relabel it. */
    { memset(pv[0], 0x22, 32); vo[0] = 3;
      memcpy(pv[1], pv[0], 32);  vo[1] = 3;              /* the same outpoint twice */
      unsigned long lc = mk_tx(c, pv, vo, 2, 1, 50000);
      const unsigned char* txs[1] = { c }; unsigned long ls[1] = { lc };
      int r = mpol_package_well_formed(txs, ls, 1, NULL, NULL, &why);
      ck("a tx with a duplicated input is NOT conflict-in-package",
         !(r == 0 && !strcmp(why, "conflict-in-package"))); }

    /* 6. over the count limit */
    { const unsigned char* txs[26]; unsigned long ls[26];
      for(int i=0;i<26;i++){ txs[i]=a; ls[i]=la; }
      int r = mpol_package_well_formed(txs, ls, 26, NULL, NULL, &why);
      ck("26 transactions -> package-too-many-transactions",
         r == 0 && !strcmp(why, "package-too-many-transactions")); }

    /* 7. txids are handed back so a caller need not re-walk the package */
    { const unsigned char* txs[1] = { a }; unsigned long ls[1] = { la };
      unsigned char out[32];
      int r = mpol_package_well_formed(txs, ls, 1, out, NULL, &why);
      ck("txids_out is filled with the real txid", r == 1 && !memcmp(out, atxid, 32)); }

    if(failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures ? 1 : 0;
}
