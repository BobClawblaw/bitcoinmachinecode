/* test_tapagg_diff.c -- bitcoin_tapagg.asm vs tx_verify.c's tapagg_build /
 * tapagg_verify.
 *
 * WHY THIS EXISTS
 *   Phase 2 slice 7. tapagg_build lays out the BIP341 aggregate-sighash
 *   arena -- outpoints, amounts, packed scriptPubKeys, and the stripped tx
 *   -- that EVERY taproot input's sighash commits to. One displaced byte is
 *   a wrong sighash for a whole transaction. The build differential
 *   therefore compares the descriptor fields AND the entire arena byte
 *   range on identical op streams (including the C-vs-asm dependency
 *   chains: the twin calls the slice-5/6 twins underneath).
 *
 *   tapagg_verify is a 12-argument marshal into the SAME C
 *   taproot_verify_input on both sides, so its differential drives a
 *   matrix of structurally distinct invalid shapes (empty witness, annex
 *   marker, key-path vs script-path lengths, wrong spk) where a transposed
 *   argument changes WHICH rejection fires -- plus rc/reason equality on
 *   every case. The accept path rides on the existing taproot fixtures
 *   (test_taproot_block_diff) and the pre-swap replay soak, as with every
 *   twin.
 *
 * Usage: ./test_tapagg_diff
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64;
typedef struct { u8* buf; u64 cap; u64 used; } bytepool_t;
typedef struct { u64 po_off, am_off, sp_off, ns_off, nslen, nin; } tapagg_t;
typedef void (*tapin_fn)(void* ctx, u64 k, const u8** outpoint, u64* value,
                         const u8** spk, u32* spklen);

extern int txv_test_tapagg_build(bytepool_t*, tapagg_t*, tapin_fn, void*,
                                 u64, const u8*, u64, const char**);
extern int txv_test_tapagg_verify(const bytepool_t*, const tapagg_t*, const u8*,
                                  const u8* const*, const u32*, u32, u64, const char**);
extern long tapagg_build_asm(bytepool_t*, tapagg_t*, tapin_fn, void*,
                             u64, const u8*, u64, const char**);
extern long tapagg_verify_asm(const bytepool_t*, const tapagg_t*, const u8*,
                              const u8* const*, const u32*, u32, u64, const char**);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk,
                                    unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr, "unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static long fails = 0, compared = 0;
static void fail(const char* what, long tag){
    if (fails < 25) printf("FAIL %s (case %ld)\n", what, tag);
    fails++;
}

/* the adapter: per-input records from plain arrays */
typedef struct { u8 op[36]; u64 v; u8 spk[300]; u32 sl; } inrec_t;
static void get_in(void* ctxv, u64 k, const u8** op, u64* v, const u8** spk, u32* sl){
    inrec_t* r = &((inrec_t*)ctxv)[k];
    *op = r->op; *v = r->v; *spk = r->spk; *sl = r->sl;
}

static u64 rs = 0x7a9a7a9aULL;
static u64 rnd(void){ rs ^= rs<<13; rs ^= rs>>7; rs ^= rs<<17; return rs; }

/* segwit tx with `nin` inputs for the strip stage */
static u64 build_tx(u8* o, int nin){
    u64 n = 0;
    o[n++]=2; o[n++]=0; o[n++]=0; o[n++]=0; o[n++]=0x00; o[n++]=0x01;
    o[n++]=(u8)nin;
    for (int i=0;i<nin;i++){
        for (int k=0;k<36;k++) o[n++]=(u8)(i*3+k);
        o[n++]=0; o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;
    }
    o[n++]=1; for (int k=0;k<8;k++) o[n++]=0; o[n++]=2; o[n++]=0x51; o[n++]=0x75;
    for (int i=0;i<nin;i++){ o[n++]=1; o[n++]=4; o[n++]=0xde;o[n++]=0xad;o[n++]=0xbe;o[n++]=0xef; }
    o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=0;
    return n;
}

int main(void){
    static inrec_t recs[64];
    static u8 tx[4096];
    bytepool_t pc, pa; memset(&pc,0,sizeof pc); memset(&pa,0,sizeof pa);
    long tag = 0;

    /* ---- build: several transactions appended to the same pools, sizes
     * crossing pool growth; then one oversized-spk reject ---- */
    for (int t = 0; t < 40; t++){
        u64 nin = 1 + rnd() % 8;
        for (u64 k = 0; k < nin; k++){
            for (int b=0;b<36;b++) recs[k].op[b] = (u8)(rnd());
            recs[k].v = rnd();
            recs[k].sl = (u32)(rnd() % 0xfd);        /* 0..0xfc, all legal */
            for (u32 b=0;b<recs[k].sl;b++) recs[k].spk[b] = (u8)(rnd());
        }
        u64 txn = build_tx(tx, (int)nin);
        tapagg_t dc, da; memset(&dc,0xee,sizeof dc); memset(&da,0xee,sizeof da);
        const char *rc_="", *ra_="";
        int  c = txv_test_tapagg_build(&pc, &dc, get_in, recs, nin, tx, txn, &rc_);
        long a = tapagg_build_asm(&pa, &da, get_in, recs, nin, tx, txn, &ra_);
        compared++;
        if (c != (int)a){ fail("build rc", tag); break; }
        if (!c){ if (strcmp(rc_, ra_)) fail("build reason", tag); continue; }
        if (memcmp(&dc, &da, sizeof dc)){ fail("descriptor fields", tag); break; }
        if (pc.used != pa.used){ fail("pool used", tag); break; }
        if (memcmp(pc.buf, pa.buf, pc.used)){ fail("arena bytes", tag); break; }
        tag++;
    }
    { /* sl == 0xfd rejects in the sizing pass, identically */
        recs[0].sl = 0xfd;
        tapagg_t dc, da; const char *rc_="", *ra_="";
        int  c = txv_test_tapagg_build(&pc, &dc, get_in, recs, 1, tx, build_tx(tx,1), &rc_);
        long a = tapagg_build_asm(&pa, &da, get_in, recs, 1, tx, build_tx(tx,1), &ra_);
        compared++;
        if (c != (int)a || c != 0 || strcmp(rc_, ra_)) fail("oversized-spk reject", ++tag);
        recs[0].sl = 30;
    }
    { /* malformed tx -> strip failure, identically (after arena writes) */
        tapagg_t dc, da; const char *rc_="", *ra_="";
        u64 txn = build_tx(tx, 1);
        tx[4] = 0x00; tx[5] = 0x01; tx[6] = 0x00;    /* nin=0 -> strip fails */
        int  c = txv_test_tapagg_build(&pc, &dc, get_in, recs, 1, tx, txn, &rc_);
        long a = tapagg_build_asm(&pa, &da, get_in, recs, 1, tx, txn, &ra_);
        compared++;
        if (c != (int)a || c != 0 || strcmp(rc_, ra_)) fail("strip-fail reject", ++tag);
    }

    /* ---- verify: same descriptor, structurally distinct invalid shapes;
     * both sides marshal into the same C verifier, so any argument
     * transposition changes rc or WHICH reason fires ---- */
    {
        u64 nin = 3;
        for (u64 k = 0; k < nin; k++){
            memset(recs[k].op, (int)(0x10+k), 36);
            recs[k].v = 50000 + k;
            recs[k].sl = 34; recs[k].spk[0]=0x51; recs[k].spk[1]=0x20;
            for (int b=0;b<32;b++) recs[k].spk[2+b]=(u8)(b+k);
        }
        u64 txn = build_tx(tx, (int)nin);
        tapagg_t dc, da; const char *r0="";
        if (txv_test_tapagg_build(&pc, &dc, get_in, recs, nin, tx, txn, &r0) != 1 ||
            tapagg_build_asm(&pa, &da, get_in, recs, nin, tx, txn, &r0) != 1){
            printf("FAIL verify-stage build\n"); fails++;
        } else {
            static u8 sig64[64], sig65[65], ctrl33[33], leaf[5] = {0x51,0,0,0,0};
            static u8 annex[3] = {0x50, 1, 2};
            memset(sig64, 0x11, 64); memset(sig65, 0x22, 65); memset(ctrl33, 0x33, 33);
            ctrl33[0] = 0xc0;
            struct { const u8* items[4]; u32 lens[4]; u32 n; const char* nm; } wshape[] = {
                { {sig64}, {64}, 1, "keypath-64" },
                { {sig65}, {65}, 1, "keypath-65" },
                { {sig64}, {63}, 1, "bad-sig-len" },
                { {sig64, annex}, {64, 3}, 2, "keypath+annex" },
                { {leaf, ctrl33}, {5, 33}, 2, "scriptpath" },
                { {sig64, leaf, ctrl33}, {64, 5, 33}, 3, "scriptpath+stack" },
                { {sig64}, {0}, 1, "empty-item" },
            };
            for (unsigned w = 0; w < sizeof wshape/sizeof wshape[0]; w++){
                for (u64 li = 0; li < nin; li++){
                    const char *rc_="", *ra_="";
                    int  c = txv_test_tapagg_verify(&pc, &dc, recs[li].spk,
                              wshape[w].items, wshape[w].lens, wshape[w].n, li, &rc_);
                    long a = tapagg_verify_asm(&pa, &da, recs[li].spk,
                              wshape[w].items, wshape[w].lens, wshape[w].n, li, &ra_);
                    compared++;
                    if (c != (int)a){ fail(wshape[w].nm, ++tag); continue; }
                    if (!c && strcmp(rc_, ra_)){ fail("verify reason", ++tag); }
                }
            }
        }
    }

    printf("compared %ld tapagg cases; %ld mismatch(es)\n", compared, fails);
    printf("%s (%ld failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
