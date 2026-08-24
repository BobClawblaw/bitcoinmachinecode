/* test_txvb_parse_diff.c -- txvb_parse_tx_asm vs tx_verify.c's txvb_parse_tx.
 *
 * WHY THIS EXISTS
 *   Phase 2 slice 4. txvb_parse_tx is the parser the LIVE daemon runs
 *   (tx_verify_block_connect_all's Phase 0); slice 1's txv_parse twin
 *   covered the single-tx path, which has been test-only since the
 *   connect-all rewrite. Same oracle pattern, same corpus discipline as
 *   test_txv_parse_diff, plus the block-path specifics: flat-entry
 *   bookkeeping (tx_index/local_idx/tx_ptr/tx_len), the tap_desc poison,
 *   and the sizing-cap bound that replaces TXV_MAX_INPUTS.
 *
 * Usage: ./test_txvb_parse_diff <block413567.raw>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64;

typedef struct { const u8** ptr; u32* len; u64 cap, used; } witpool_t;
typedef struct {
    u64 tx_index;
    u32 local_idx;
    const u8* tx_ptr; u64 tx_len;
    const u8* outpoint;
    const u8* scriptSig; u32 scriptSiglen;
    const u8** wit; u32* witlen; u32 nwit; u32 wit_off;
    const u8* wprog; u32 wproglen; u8 wrapped;
    u32 wprog_off;
    u64 value;
    u64 spk_off; u32 spklen;
    u64 tap_desc;
    u8  shape;
} txvb_in_t;

/* C oracle: hook drives the static txvb_parse_tx against g_wit_pool */
extern int   txv_test_parse_block(const u8* tx, u64 txlen, u64 tx_index, void* flat,
                                  u64 base, u64 cap, u64* out_nin, const char** reason);
extern void* txv_test_witpool(void);
/* asm twin: explicit pool */
extern long txvb_parse_tx_asm(const u8* tx, u64 txlen, u64 tx_index, txvb_in_t* flat,
                              u64 base, u64 cap, u64* out_nin, const char** reason,
                              witpool_t* wp);

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

#define CAP 4096
static txvb_in_t *fc, *fa;               /* separate flat arrays */
static witpool_t  wa;                    /* asm-side pool */

static void diff_one(const u8* tx, u64 len, u64 tx_index, u64 base, long tag){
    witpool_t* wc = (witpool_t*)txv_test_witpool();
    wc->used = 0; wa.used = 0;
    memset(fc, 0x5c, CAP * sizeof(txvb_in_t));
    memset(fa, 0x5c, CAP * sizeof(txvb_in_t));
    u64 nc = 0, na = 0;
    const char *rc_ = "", *ra_ = "";
    int  c = txv_test_parse_block(tx, len, tx_index, fc, base, CAP, &nc, &rc_);
    long a = txvb_parse_tx_asm(tx, len, tx_index, fa, base, CAP, &na, &ra_, &wa);
    compared++;
    if (c != (int)a){ fail("rc mismatch", tag); return; }
    if (!c){ if (strcmp(rc_, ra_)) fail("reason mismatch", tag); return; }
    if (nc != na){ fail("nin mismatch", tag); return; }
    if (wc->used != wa.used){ fail("pool used", tag); return; }
    for (u64 i = 0; i < nc; i++){
        txvb_in_t *ec = &fc[base+i], *ea = &fa[base+i];
        if (ec->tx_index != ea->tx_index)   { fail("tx_index", tag); return; }
        if (ec->local_idx != ea->local_idx) { fail("local_idx", tag); return; }
        if (ec->tx_ptr != ea->tx_ptr || ec->tx_len != ea->tx_len){ fail("tx_ptr/len", tag); return; }
        if (ec->outpoint != ea->outpoint)   { fail("outpoint", tag); return; }
        if (ec->scriptSig != ea->scriptSig || ec->scriptSiglen != ea->scriptSiglen){ fail("scriptSig", tag); return; }
        if (ec->nwit != ea->nwit)           { fail("nwit", tag); return; }
        if (ec->tap_desc != ea->tap_desc)   { fail("tap_desc poison", tag); return; }
        if (ec->nwit && ec->wit_off != ea->wit_off){ fail("wit_off", tag); return; }
        for (u32 j = 0; j < ec->nwit; j++){
            if (wc->ptr[ec->wit_off+j] != wa.ptr[ea->wit_off+j]){ fail("wit item ptr", tag); return; }
            if (wc->len[ec->wit_off+j] != wa.len[ea->wit_off+j]){ fail("wit item len", tag); return; }
        }
    }
}

/* independent minimal walker (copied from test_txv_parse_diff) */
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
    int segwit = (p + 2 <= end && p[0] == 0 && p[1] == 1);
    if (segwit) p += 2;
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
    if (segwit){
        for (u64 i = 0; i < nin; i++){
            u64 nit = rd_cs_local(&p, end, &ok); if (!ok) return 0;
            for (u64 j = 0; j < nit; j++){
                u64 il = rd_cs_local(&p, end, &ok); if (!ok) return 0;
                if ((u64)(end - p) < il) return 0;
                p += il;
            }
        }
    }
    if (p + 4 > end) return 0;
    return (u64)(p + 4 - tx);
}

static u64 build_segwit_tx(u8* o, int nin, int items){
    u64 n = 0;
    o[n++]=2; o[n++]=0; o[n++]=0; o[n++]=0; o[n++]=0x00; o[n++]=0x01;
    o[n++]=(u8)nin;
    for (int i=0;i<nin;i++){
        for (int k=0;k<36;k++) o[n++]=(u8)(i*11+k);
        o[n++]=0; o[n++]=0xff; o[n++]=0xff; o[n++]=0xff; o[n++]=0xff;
    }
    o[n++]=1; for (int k=0;k<8;k++) o[n++]=0; o[n++]=2; o[n++]=0x51; o[n++]=0x75;
    for (int i=0;i<nin;i++){
        o[n++]=(u8)items;
        for (int j=0;j<items;j++){ o[n++]=(u8)(j+2); for (int k=0;k<j+2;k++) o[n++]=(u8)(0x90+j); }
    }
    o[n++]=0; o[n++]=0; o[n++]=0; o[n++]=0;
    return n;
}

int main(int argc, char** argv){
    fc = calloc(CAP, sizeof(txvb_in_t));
    fa = calloc(CAP, sizeof(txvb_in_t));
    if (!fc || !fa){ fprintf(stderr, "oom\n"); return 1; }
    memset(&wa, 0, sizeof wa);
    long tag = 0, real_txs = 0;

    if (argc > 1){
        FILE* f = fopen(argv[1], "rb");
        if (!f){ perror(argv[1]); return 1; }
        fseek(f, 0, SEEK_END); long bl = ftell(f); fseek(f, 0, SEEK_SET);
        u8* blk = malloc(bl);
        if (!blk || (long)fread(blk, 1, bl, f) != bl) return 1;
        fclose(f);
        const u8* end = blk + bl; const u8* p = blk + 80; int ok = 1;
        u64 ntx = rd_cs_local(&p, end, &ok);
        for (u64 t = 0; ok && t < ntx; t++){
            u64 span = tx_span(p, end);
            if (!span){ fprintf(stderr, "corpus lost sync at %lu\n", t); return 1; }
            diff_one(p, span, t, (t % 7) * 3, ++tag);   /* varied base offsets */
            if (t % 131 == 0)
                for (u64 cut = 0; cut < span; cut++)
                    diff_one(p, cut, t, 0, ++tag);
            p += span; real_txs++;
        }
        free(blk);
    }

    /* synthetic segwit + block-path specifics */
    static u8 tx[1<<16];
    u64 n = build_segwit_tx(tx, 5, 3);
    diff_one(tx, n, 42, 100, ++tag);
    for (u64 cut = 0; cut < n; cut++) diff_one(tx, cut, 42, 0, ++tag);
    /* sizing-cap exceeded: base close to CAP */
    diff_one(tx, n, 7, CAP - 2, ++tag);
    diff_one(tx, n, 7, CAP, ++tag);

    printf("compared %ld block-parse cases (%ld real txs); %ld mismatch(es)\n",
           compared, real_txs, fails);
    printf("%s (%ld failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
