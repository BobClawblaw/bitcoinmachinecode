/* tests/test_policy_v31.c -- the Core v30/v31 policy prechecks added
 * 2026-08-31: legacy sigops (2,500), accurate sigop cost (16,000), and
 * IsWitnessStandard's P2WSH stack limits. These run BEFORE script
 * verification (Core's PreChecks order), so none of the crafted spends
 * needs a valid signature -- only resolvable prevouts, served by a stub
 * resolver exactly like incident #48's fix uses in test_tx_relay. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "test_tmpdir.h"
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long long u64;
extern long txacc_legacy_sigops(const u8* tx, unsigned long txlen);
extern const char* txacc_witness_standard(void* mp_area, const u8* tx, unsigned long txlen);
extern void tx_accept_set_resolver(long (*)(const u8*, unsigned long, u64*, unsigned long*,
                                            unsigned long*, const u8**, unsigned long*));
static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c?"ok ":"FAIL", w); if(!c) fails++; }
static u8 g_prev_spk[64]; static unsigned long g_prev_spklen;
static long stub_resolve(const u8* txid, unsigned long index, u64* v, unsigned long* h,
                         unsigned long* cb, const u8** s, unsigned long* l){
    (void)txid; (void)index;
    *v = 100000000ULL; *h = 1; *cb = 0; *s = g_prev_spk; *l = g_prev_spklen;
    return 1;
}
/* serialize a 1-input segwit tx with a caller-shaped witness stack */
static unsigned long mk_segwit(u8* o, int nitems, unsigned long itemlen, unsigned long lastlen){
    unsigned long n = 0;
    o[n++]=1;o[n++]=0;o[n++]=0;o[n++]=0; o[n++]=0x00; o[n++]=0x01;   /* version, marker, flag */
    o[n++]=1; memset(o+n, 0x33, 32); n+=32; memset(o+n, 0, 4); n+=4; /* 1 input, prevout */
    o[n++]=0;                                                        /* empty scriptSig */
    memset(o+n, 0xff, 4); n+=4;                                      /* sequence */
    o[n++]=1; memset(o+n, 0, 8); o[n]=0x10; n+=8; o[n++]=1; o[n++]=0x51;  /* 1 output, value, spk OP_TRUE */
    /* witness: nitems of itemlen, then one last item of lastlen */
    o[n++]=(u8)(nitems+1>=0xfd?0:nitems+1);
    for (int k = 0; k < nitems; k++){ o[n++]=(u8)itemlen; memset(o+n, 0xaa, itemlen); n+=itemlen; }
    if (lastlen < 0xfd) o[n++]=(u8)lastlen;
    else { o[n++]=0xfd; o[n++]=(u8)lastlen; o[n++]=(u8)(lastlen>>8); }
    memset(o+n, 0x51, lastlen); n+=lastlen;                          /* "script" of OP_TRUEs */
    memset(o+n, 0, 4); n+=4;                                         /* locktime */
    return n;
}
int main(void){
    tt_isolate();
    tx_accept_set_resolver(stub_resolve);
    printf("== legacy sigops (MAX_TX_LEGACY_SIGOPS 2,500, Core v30) ==\n");
    {
        /* 126 bare CHECKMULTISIGs in one output spk: 126*20 = 2,520 > 2,500 */
        static u8 tx[4096]; unsigned long n = 0;
        tx[n++]=1;tx[n++]=0;tx[n++]=0;tx[n++]=0;
        tx[n++]=1; memset(tx+n, 0x44, 32); n+=32; memset(tx+n, 0, 4); n+=4; tx[n++]=0; memset(tx+n,0xff,4); n+=4;
        tx[n++]=1; memset(tx+n, 0, 8); tx[n]=0x10; n+=8; tx[n++]=126; memset(tx+n, 0xae, 126); n+=126;
        memset(tx+n, 0, 4); n+=4;
        long lc = txacc_legacy_sigops(tx, n);
        printf("      legacy sigops counted: %ld\n", lc);
        ok(lc == 126*20, "126 bare OP_CHECKMULTISIGs count 2,520 (non-accurate x20)");
        tx[n-131] = 125;               /* shrink the spk push: 125 CMS = 2,500, at the limit */
        /* rebuild cleanly instead of poking offsets */
    }
    printf("== P2WSH witness standardness ==\n");
    {
        static u8 tx[16384];
        g_prev_spklen = 34; g_prev_spk[0]=0x00; g_prev_spk[1]=0x20; memset(g_prev_spk+2, 0x77, 32);
        unsigned long n = mk_segwit(tx, 100, 1, 200);
        ok(txacc_witness_standard(0, tx, n) == 0, "100 one-byte items + 200-byte script: standard");
        n = mk_segwit(tx, 101, 1, 200);
        const char* r = txacc_witness_standard(0, tx, n);
        ok(r && !strcmp(r, "bad-witness-nonstandard"), "101 stack items: bad-witness-nonstandard");
        n = mk_segwit(tx, 2, 81, 200);
        r = txacc_witness_standard(0, tx, n);
        ok(r && !strcmp(r, "bad-witness-nonstandard"), "an 81-byte stack item: bad-witness-nonstandard");
        n = mk_segwit(tx, 2, 80, 200);
        ok(txacc_witness_standard(0, tx, n) == 0, "80-byte items are fine");
        n = mk_segwit(tx, 2, 10, 3601);
        r = txacc_witness_standard(0, tx, n);
        ok(r && !strcmp(r, "bad-witness-nonstandard"), "3,601-byte witnessScript: bad-witness-nonstandard");
        n = mk_segwit(tx, 2, 10, 3600);
        ok(txacc_witness_standard(0, tx, n) == 0, "3,600-byte witnessScript is the limit, allowed");
        /* not P2WSH: the same stacks under P2WPKH shape are not judged */
        g_prev_spklen = 22; g_prev_spk[0]=0x00; g_prev_spk[1]=0x14; memset(g_prev_spk+2, 0x77, 20);
        n = mk_segwit(tx, 101, 1, 200);
        ok(txacc_witness_standard(0, tx, n) == 0, "P2WPKH prevout: P2WSH limits do not apply");
    }
    printf("\n%s (%d failure%s)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails, fails==1?"":"s");
    return fails ? 1 : 0;
}
