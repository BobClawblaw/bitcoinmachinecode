/* test_bip143_diff.c -- bitcoin_bip143.asm vs bitcoin_segwit.c's
 * swtx_parse / segwit_v0_sighash.
 *
 * Phase 2 slice 12. A displaced byte here is a silent WRONG SIGHASH for
 * every segwit v0 input in the chain, so the differential compares:
 *   - swtx_parse: every field of swtx_t and the whole in_off/out_off table;
 *   - segwit_v0_sighash: the returned preimage LENGTH, the ENTIRE preimage
 *     buffer byte-for-byte (pre-poisoned identically on both sides), and
 *     the 32-byte digest;
 * over the real bench block's segwit-shaped txs plus synthetic multi-input
 * / multi-output shapes, every hashtype (ALL/NONE/SINGLE x ANYONECANPAY,
 * plus undefined low bits), SINGLE with n_in >= nout, every input index,
 * per-byte truncation fuzz, and a cap sweep that lands mid-field.
 *
 * Usage: ./test_bip143_diff <block413567.raw>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64;
typedef struct {
    const u8* tx; int64_t txlen; const u8* end;
    int64_t version; u32 locktime;
    int64_t nin, nout;
    const u8* inputs; const u32* in_off; const u32* out_off;
} swtx_t;

extern int  swtx_parse_export(void* t, u32* off);
extern long swtx_parse_asm(void* t, u32* off);
extern long segwit_v0_sighash(u8 out32[32], const u8* tx, int64_t txlen, int64_t n_in,
                              u32 ht, u64 amount, const u8* sc, u64 scl, u8* pre, long cap);
extern long segwit_v0_sighash_asm(u8 out32[32], const u8* tx, int64_t txlen, int64_t n_in,
                                  u32 ht, u64 amount, const u8* sc, u64 scl, u8* pre, long cap);

long mempool_resolve_confirmed_utxo(void* u, const u8 t[32], unsigned long i,
                                    unsigned long long* v, const u8** s, unsigned long* l){
    (void)u;(void)t;(void)i;(void)v;(void)s;(void)l; abort(); }

static long fails = 0, compared = 0;
static void fail(const char* w, long tag){
    if (fails < 25) printf("FAIL %s (case %ld)\n", w, tag);
    fails++;
}

#define PRECAP (1<<16)
static u32 *offc, *offa;
static u8 *prec, *prea;

static void diff_parse(const u8* tx, u64 len, long tag){
    swtx_t tc, ta;
    memset(&tc, 0xcd, sizeof tc); memset(&ta, 0xcd, sizeof ta);
    tc.tx = tx; tc.txlen = (int64_t)len;
    ta.tx = tx; ta.txlen = (int64_t)len;
    memset(offc, 0xab, 4096*4); memset(offa, 0xab, 4096*4);
    int  c = swtx_parse_export(&tc, offc);
    long a = swtx_parse_asm(&ta, offa);
    compared++;
    if (c != (int)a){ fail("parse rc", tag); return; }
    if (!c) return;
    if (tc.version != ta.version || tc.locktime != ta.locktime){ fail("version/locktime", tag); return; }
    if (tc.nin != ta.nin || tc.nout != ta.nout){ fail("nin/nout", tag); return; }
    if (tc.end != ta.end || tc.inputs != ta.inputs){ fail("end/inputs", tag); return; }
    if (memcmp(tc.in_off, ta.in_off, (size_t)(tc.nin+1)*4)){ fail("in_off table", tag); return; }
    if (memcmp(tc.out_off, ta.out_off, (size_t)(tc.nout+1)*4)){ fail("out_off table", tag); return; }
}

static void diff_sig(const u8* tx, u64 len, int64_t n_in, u32 ht, u64 amount,
                     const u8* sc, u64 scl, long cap, long tag){
    static u8 hc[32], ha[32];
    memset(prec, 0xEE, PRECAP); memset(prea, 0xEE, PRECAP);
    memset(hc, 0x11, 32); memset(ha, 0x22, 32);
    long c = segwit_v0_sighash(hc, tx, (int64_t)len, n_in, ht, amount, sc, scl, prec, cap);
    long a = segwit_v0_sighash_asm(ha, tx, (int64_t)len, n_in, ht, amount, sc, scl, prea, cap);
    compared++;
    if (c != a){ fail("sighash rc", tag); return; }
    long span = cap > 0 ? (cap < PRECAP ? cap : PRECAP) : 0;
    if (span > 0 && memcmp(prec, prea, (size_t)span)){ fail("preimage bytes", tag); return; }
    if (c > 0 && memcmp(hc, ha, 32)){ fail("digest", tag); return; }
}

static u64 rd_cs_local(const u8** p, const u8* end, int* ok){
    if (*p >= end){ *ok = 0; return 0; }
    u8 f = **p;
    if (f < 0xfd){ (*p)++; return f; }
    int n = (f == 0xfd) ? 2 : (f == 0xfe) ? 4 : 8;
    if (*p + 1 + n > end){ *ok = 0; return 0; }
    u64 v = 0; for (int i = 0; i < n; i++) v |= (u64)(*p)[1+i] << (8*i);
    *p += 1 + n; return v;
}
static u64 tx_span(const u8* tx, const u8* end){
    const u8* p = tx; int ok = 1;
    if (p + 4 > end) return 0;
    p += 4;
    int sw = (p + 2 <= end && p[0] == 0 && p[1] == 1);
    if (sw) p += 2;
    u64 nin = rd_cs_local(&p, end, &ok); if (!ok) return 0;
    for (u64 i = 0; i < nin; i++){
        if (p + 36 > end) return 0;
        p += 36;
        u64 sl = rd_cs_local(&p, end, &ok); if (!ok) return 0;
        if ((u64)(end - p) < sl + 4) return 0;
        p += sl + 4;
    }
    u64 nout = rd_cs_local(&p, end, &ok); if (!ok) return 0;
    for (u64 i = 0; i < nout; i++){
        if (p + 8 > end) return 0;
        p += 8;
        u64 sl = rd_cs_local(&p, end, &ok); if (!ok) return 0;
        if ((u64)(end - p) < sl) return 0;
        p += sl;
    }
    if (sw){
        for (u64 i = 0; i < nin; i++){
            u64 ni = rd_cs_local(&p, end, &ok); if (!ok) return 0;
            for (u64 j = 0; j < ni; j++){
                u64 il = rd_cs_local(&p, end, &ok); if (!ok) return 0;
                if ((u64)(end - p) < il) return 0;
                p += il;
            }
        }
    }
    if (p + 4 > end) return 0;
    return (u64)(p + 4 - tx);
}

/* segwit tx builder: nin inputs, nout outputs, optional big output scripts */
static u64 build(u8* o, int nin, int nout, int witems, int bigout){
    u64 n = 0;
    o[n++]=2;o[n++]=0;o[n++]=0;o[n++]=0; o[n++]=0x00; o[n++]=0x01;
    o[n++]=(u8)nin;
    for (int i=0;i<nin;i++){
        for (int k=0;k<36;k++) o[n++]=(u8)(i*13+k+1);
        o[n++]=0;
        o[n++]=(u8)(0xf0+i); o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;
    }
    o[n++]=(u8)nout;
    for (int i=0;i<nout;i++){
        for (int k=0;k<8;k++) o[n++]=(u8)(i+k);
        if (bigout){ o[n++]=0xfd; o[n++]=0x2c; o[n++]=0x01; for (int k=0;k<300;k++) o[n++]=(u8)(k^i); }
        else { o[n++]=3; o[n++]=0x51; o[n++]=0x52; o[n++]=0x53; }
    }
    for (int i=0;i<nin;i++){
        o[n++]=(u8)witems;
        for (int j=0;j<witems;j++){ o[n++]=(u8)(j+2); for (int k=0;k<j+2;k++) o[n++]=(u8)(0x60+j); }
    }
    o[n++]=0x44;o[n++]=0x33;o[n++]=0x22;o[n++]=0x11;
    return n;
}

int main(int argc, char** argv){
    offc = malloc(4096*4); offa = malloc(4096*4);
    prec = malloc(PRECAP); prea = malloc(PRECAP);
    static u8 sc[64]; for (int i=0;i<64;i++) sc[i]=(u8)(i*7+3);
    u32 hts[] = { 1, 2, 3, 0, 4, 0x81, 0x82, 0x83, 0x80, 0x84 };
    long tag = 0, real = 0;

    if (argc > 1){
        FILE* f = fopen(argv[1], "rb");
        if (!f){ perror(argv[1]); return 1; }
        fseek(f,0,SEEK_END); long bl = ftell(f); fseek(f,0,SEEK_SET);
        u8* blk = malloc(bl);
        if (!blk || (long)fread(blk,1,bl,f) != bl) return 1;
        fclose(f);
        const u8* end = blk + bl; const u8* p = blk + 80; int ok = 1;
        u64 ntx = rd_cs_local(&p, end, &ok);
        for (u64 t = 0; ok && t < ntx; t++){
            u64 span = tx_span(p, end);
            if (!span) break;
            diff_parse(p, span, ++tag);
            for (unsigned h = 0; h < sizeof hts/sizeof hts[0]; h++)
                diff_sig(p, span, 0, hts[h], 123456789ULL, sc, 25, PRECAP, ++tag);
            if (t % 211 == 0)
                for (u64 cut = 0; cut < span; cut++){
                    diff_parse(p, cut, ++tag);
                    diff_sig(p, cut, 0, 1, 5000, sc, 25, PRECAP, ++tag);
                }
            p += span; real++;
        }
        free(blk);
    }

    static u8 tx[1<<16];
    struct { int nin, nout, wit, big; } shapes[] = {
        {1,1,1,0}, {1,3,2,0}, {3,1,1,0}, {4,4,3,0}, {2,5,1,1}, {6,2,2,1}, {1,1,0,0},
    };
    for (unsigned s = 0; s < sizeof shapes/sizeof shapes[0]; s++){
        u64 n = build(tx, shapes[s].nin, shapes[s].nout, shapes[s].wit, shapes[s].big);
        diff_parse(tx, n, ++tag);
        for (int64_t i = 0; i < shapes[s].nin + 1; i++)          /* +1: out of range */
            for (unsigned h = 0; h < sizeof hts/sizeof hts[0]; h++)
                diff_sig(tx, n, i, hts[h], 700000ULL + i, sc, 25, PRECAP, ++tag);
        /* scriptCode length variants incl. one crossing the 0xfd varint */
        u64 scls[] = { 0, 1, 25, 63 };
        for (unsigned k = 0; k < 4; k++)
            diff_sig(tx, n, 0, 1, 42, sc, scls[k], PRECAP, ++tag);
        /* truncation fuzz + cap sweep on the first two shapes */
        if (s < 2){
            for (u64 cut = 0; cut < n; cut++){
                diff_parse(tx, cut, ++tag);
                diff_sig(tx, cut, 0, 1, 9, sc, 25, PRECAP, ++tag);
            }
            long need = segwit_v0_sighash(prec, tx, (int64_t)n, 0, 1, 9, sc, 25, prec, PRECAP);
            for (long cap = 0; cap <= need + 2; cap++)
                diff_sig(tx, n, 0, 1, 9, sc, 25, cap, ++tag);
        }
    }

    printf("compared %ld bip143 cases (%ld real txs); %ld mismatch(es)\n", compared, real, fails);
    printf("%s (%ld failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
