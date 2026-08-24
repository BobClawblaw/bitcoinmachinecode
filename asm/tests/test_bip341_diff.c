/* test_bip341_diff.c -- bitcoin_bip341.asm vs bitcoin_taproot_sighash.c's
 * ts_agg_hashes / taproot_sighash.
 *
 * Phase 2 slice 13b, the taproot analogue of slice 12. Compares the four
 * aggregate hashes and the located spk-at-n_in, then the sighash's returned
 * LENGTH, the ENTIRE pre-poisoned preimage buffer byte-for-byte, and the
 * 32-byte TapSighash digest -- across every hash_type (valid AND the
 * invalid ones the 2026-08-22 consensus fix must keep rejecting), key path
 * vs script path, annex present/absent, SIGHASH_SINGLE both inside and
 * PAST the output count (BIP341 fails there; BIP143 would substitute a
 * zero hash), every input index, and a cap sweep landing mid-field.
 *
 * Usage: ./test_bip341_diff
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64;

typedef struct {
    const u8* tx; int64_t txlen; int64_t n_in; u8 hash_type;
    const u8* prevouts; const u8* amounts; const u8* spks;
    int64_t num_inputs; int ext_flag; const u8* tapleaf; u32 codesep_pos;
    const u8* annex; u64 annexlen;
} tapctx_t;
/* txview_t -- MUST match bitcoin_taproot_sighash.c exactly: `version` is a
 * plain int and there is no `inputs` field. (A first draft copied
 * bitcoin_segwit.c's swtx_t shape instead and drove the C oracle through
 * garbage offsets -- the crash was in the ORACLE, not the twin.) */
typedef struct {
    const u8* tx; int64_t txlen; const u8* end;
    int version; u32 locktime; int64_t nin, nout;
    const u32* in_off; const u32* out_off;
} txview_t;

extern long taproot_sighash(u8* out32, const tapctx_t* c, u8* pre, long cap);
extern long taproot_sighash_asm(u8* out32, const tapctx_t* c, u8* pre, long cap);
extern int  ts_tx_parse_export(void* t, u32* off);
extern int  ts_agg_hashes_export(const void* c, const void* t, u8 hp[32], u8 ha[32],
                                 u8 hs[32], u8 hq[32], const u8** sp, u64* sl);
extern long ts_agg_hashes_asm(const void* c, const void* t, u8 hp[32], u8 ha[32],
                              u8 hs[32], u8 hq[32], const u8** sp, u64* sl);

long mempool_resolve_confirmed_utxo(void* u, const u8 t[32], unsigned long i,
                                    unsigned long long* v, const u8** s, unsigned long* l){
    (void)u;(void)t;(void)i;(void)v;(void)s;(void)l; abort(); }

static long fails = 0, compared = 0;
static void fail(const char* w, long tag){
    if (fails < 25) printf("FAIL %s (case %ld)\n", w, tag);
    fails++;
}

#define PRECAP 8192
static u8 prec[PRECAP], prea[PRECAP];

static void diff_sig(const tapctx_t* c, long cap, long tag){
    u8 hc[32], ha[32];
    memset(prec, 0xE7, PRECAP); memset(prea, 0xE7, PRECAP);
    memset(hc, 0x33, 32); memset(ha, 0x44, 32);
    long rc_ = taproot_sighash(hc, c, prec, cap);
    long ra_ = taproot_sighash_asm(ha, c, prea, cap);
    compared++;
    if (rc_ != ra_){ fail("sighash rc", tag); return; }
    long span = cap > 0 ? (cap < PRECAP ? cap : PRECAP) : 0;
    if (span > 0 && memcmp(prec, prea, (size_t)span)){ fail("preimage bytes", tag); return; }
    if (rc_ > 0 && memcmp(hc, ha, 32)){ fail("digest", tag); return; }
}

static void diff_agg(const tapctx_t* c, const txview_t* t, long tag){
    u8 a1[32],a2[32],a3[32],a4[32], b1[32],b2[32],b3[32],b4[32];
    const u8 *sc = (const u8*)1, *sa = (const u8*)2; u64 lc = 7, la = 9;
    memset(a1,1,32); memset(a2,1,32); memset(a3,1,32); memset(a4,1,32);
    memset(b1,2,32); memset(b2,2,32); memset(b3,2,32); memset(b4,2,32);
    int  rc_ = ts_agg_hashes_export(c, t, a1, a2, a3, a4, &sc, &lc);
    long ra_ = ts_agg_hashes_asm(c, t, b1, b2, b3, b4, &sa, &la);
    compared++;
    if (rc_ != (int)ra_){ fail("agg rc", tag); return; }
    if (!rc_) return;
    if (memcmp(a1,b1,32)||memcmp(a2,b2,32)||memcmp(a3,b3,32)||memcmp(a4,b4,32)){
        fail("aggregate hashes", tag); return; }
    if (sc != sa || lc != la){ fail("spk_at_nin", tag); }
}

/* n-input / m-output tx (non-segwit serialization: BIP341 hashes the
 * stripped form, which is what callers pass) */
static u64 build(u8* o, int nin, int nout){
    u64 n = 0;
    o[n++]=2;o[n++]=0;o[n++]=0;o[n++]=0;
    o[n++]=(u8)nin;
    for (int i=0;i<nin;i++){
        for (int k=0;k<36;k++) o[n++]=(u8)(i*17+k+1);
        o[n++]=0;
        o[n++]=(u8)(0xa0+i); o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;
    }
    o[n++]=(u8)nout;
    for (int i=0;i<nout;i++){
        for (int k=0;k<8;k++) o[n++]=(u8)(i*3+k);
        o[n++]=4; o[n++]=0x51; o[n++]=0x52; o[n++]=0x53; o[n++]=(u8)i;
    }
    o[n++]=0x21;o[n++]=0x43;o[n++]=0x65;o[n++]=0x87;
    return n;
}

int main(void){
    static u8 tx[4096];
    static u8 prevouts[36*8], amounts[8*8], spks[8*40];
    static u8 tapleaf[32], annex[40];
    static u32 offtab[4096];
    for (unsigned i=0;i<sizeof prevouts;i++) prevouts[i]=(u8)(i*5+1);
    for (unsigned i=0;i<sizeof amounts;i++)  amounts[i]=(u8)(i*11+2);
    for (unsigned i=0;i<32;i++) tapleaf[i]=(u8)(i+0x40);
    annex[0]=0x50; for (int i=1;i<40;i++) annex[i]=(u8)(i*7);
    /* spks run: one single-byte compactsize + 34-byte spk per input */
    { u64 k = 0;
      for (int i=0;i<8;i++){ spks[k++]=34; spks[k++]=0x51; spks[k++]=0x20;
        for (int b=0;b<32;b++) spks[k++]=(u8)(i*13+b); } }

    u8 hts[] = { 0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83,
                 0x04, 0x05, 0x7f, 0x80, 0x84, 0xff };   /* last 6 must fail */
    long tag = 0;
    struct { int nin, nout; } shapes[] = { {1,1},{2,3},{3,1},{4,4},{5,2},{2,1} };

    for (unsigned s = 0; s < sizeof shapes/sizeof shapes[0]; s++){
        u64 n = build(tx, shapes[s].nin, shapes[s].nout);
        txview_t tv; tv.tx = tx; tv.txlen = (int64_t)n;
        int parsed = ts_tx_parse_export(&tv, offtab);
        for (int64_t i = 0; i < shapes[s].nin; i++){
            tapctx_t c;
            memset(&c, 0, sizeof c);
            c.tx = tx; c.txlen = (int64_t)n; c.n_in = i;
            c.prevouts = prevouts; c.amounts = amounts; c.spks = spks;
            c.num_inputs = shapes[s].nin;
            if (parsed) diff_agg(&c, &tv, ++tag);
            for (unsigned h = 0; h < sizeof hts/sizeof hts[0]; h++){
                c.hash_type = hts[h];
                /* key path */
                c.ext_flag = 0; c.tapleaf = NULL; c.codesep_pos = 0; c.annex = NULL; c.annexlen = 0;
                diff_sig(&c, PRECAP, ++tag);
                /* key path + annex */
                c.annex = annex; c.annexlen = 40;
                diff_sig(&c, PRECAP, ++tag);
                /* script path (ext_flag=1) with and without annex */
                c.ext_flag = 1; c.tapleaf = tapleaf; c.codesep_pos = 0xffffffffu;
                diff_sig(&c, PRECAP, ++tag);
                c.annex = NULL; c.annexlen = 0;
                diff_sig(&c, PRECAP, ++tag);
                c.codesep_pos = 3;
                diff_sig(&c, PRECAP, ++tag);
                /* script path with a NULL tapleaf must fail on both */
                c.tapleaf = NULL;
                diff_sig(&c, PRECAP, ++tag);
            }
            /* n_in out of range vs num_inputs / nin */
            { tapctx_t d; memset(&d,0,sizeof d);
              d.tx = tx; d.txlen = (int64_t)n; d.n_in = shapes[s].nin;
              d.hash_type = 1; d.prevouts = prevouts; d.amounts = amounts;
              d.spks = spks; d.num_inputs = shapes[s].nin;
              diff_sig(&d, PRECAP, ++tag);
              d.num_inputs = shapes[s].nin + 1;
              diff_sig(&d, PRECAP, ++tag); }
        }
        /* cap sweep on the first shape, key path, SIGHASH_ALL */
        if (s == 0){
            tapctx_t c; memset(&c,0,sizeof c);
            c.tx = tx; c.txlen = (int64_t)n; c.n_in = 0; c.hash_type = 1;
            c.prevouts = prevouts; c.amounts = amounts; c.spks = spks;
            c.num_inputs = 1;
            long need = taproot_sighash(prec, &c, prec, PRECAP);
            for (long cap = 0; cap <= need + 2; cap++) diff_sig(&c, cap, ++tag);
            /* and an ACP cap sweep, which takes the other branch */
            c.hash_type = 0x81;
            long need2 = taproot_sighash(prec, &c, prec, PRECAP);
            for (long cap = 0; cap <= need2 + 2; cap++) diff_sig(&c, cap, ++tag);
        }
    }

    printf("compared %ld bip341 cases; %ld mismatch(es)\n", compared, fails);
    printf("%s (%ld failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
