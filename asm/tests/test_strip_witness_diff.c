/* test_strip_witness_diff.c -- bitcoin_strip_witness.asm vs bitcoin_segwit.c.
 *
 * WHY THIS EXISTS
 *   Phase 2 slice 6. strip_witness feeds legacy sighash on mixed txs and
 *   BIP341's stripped-tx commitment: one divergent byte is a wrong sighash,
 *   silently. The twin must match the C on accepted outputs, on every
 *   reject, and on the PARTIAL BYTES left in the output buffer when a cap
 *   rejection lands mid-emit (observable state, same discipline as the
 *   pools' half-grown OOM shape).
 *
 * CORPUS
 *   - every tx of the real bench block, stripped with generous cap:
 *     rc + full output bytes compared;
 *   - synthetic segwit txs (multi-input, multi-item witness, 0xfd-length
 *     scriptSig so the varint re-encoding path is exercised);
 *   - non-canonical varints (0xfd-encoding of < 0xfd etc.) -> both reject;
 *   - per-byte truncation fuzz on samples;
 *   - CAP SWEEP: for chosen txs, every cap in 0..stripped_len+2, comparing
 *     rc and the ENTIRE buffer (pre-poisoned identically) -- pinning the
 *     partial-write behavior byte for byte.
 *
 * Usage: ./test_strip_witness_diff <block413567.raw>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64;

extern long strip_witness(const u8* tx, int64_t txlen, u8* out, long cap);
extern long strip_witness_asm(const u8* tx, int64_t txlen, u8* out, long cap);

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

#define OUTCAP (1<<20)
static u8 *oc, *oa;

static void diff_one(const u8* tx, u64 len, long cap, long tag){
    memset(oc, 0xCC, OUTCAP); memset(oa, 0xCC, OUTCAP);
    long c = strip_witness(tx, (int64_t)len, oc, cap);
    long a = strip_witness_asm(tx, (int64_t)len, oa, cap);
    compared++;
    if (c != a){ fail("rc mismatch", tag); return; }
    /* compare the whole buffer regardless of rc: partial writes must match */
    long span = cap > 0 ? (cap < OUTCAP ? cap : OUTCAP) : 0;
    if (c > 0 && c > span) span = c < OUTCAP ? c : OUTCAP;
    if (span > 0 && memcmp(oc, oa, (size_t)span) != 0) fail("output bytes", tag);
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

/* segwit tx with a 0xfd-form (300-byte) scriptSig: exercises varint
 * re-encoding and the emit-phase unsigned bound */
static u64 build_fat_tx(u8* o, int nin, int items){
    u64 n = 0;
    o[n++]=2; o[n++]=0; o[n++]=0; o[n++]=0; o[n++]=0x00; o[n++]=0x01;
    o[n++]=(u8)nin;
    for (int i=0;i<nin;i++){
        for (int k=0;k<36;k++) o[n++]=(u8)(i*5+k);
        o[n++]=0xfd; o[n++]=0x2c; o[n++]=0x01;          /* 300-byte scriptSig */
        for (int k=0;k<300;k++) o[n++]=(u8)(k^i);
        o[n++]=0xff; o[n++]=0xff; o[n++]=0xff; o[n++]=0xff;
    }
    o[n++]=2;
    for (int i=0;i<2;i++){ for (int k=0;k<8;k++) o[n++]=(u8)i; o[n++]=3; o[n++]=0x51; o[n++]=0x52; o[n++]=0x53; }
    for (int i=0;i<nin;i++){
        o[n++]=(u8)items;
        for (int j=0;j<items;j++){ o[n++]=(u8)(j+1); for (int k=0;k<j+1;k++) o[n++]=(u8)(0x70+j); }
    }
    o[n++]=9; o[n++]=0; o[n++]=0; o[n++]=0;
    return n;
}

int main(int argc, char** argv){
    oc = malloc(OUTCAP); oa = malloc(OUTCAP);
    if (!oc || !oa){ fprintf(stderr, "oom\n"); return 1; }
    long tag = 0, real_txs = 0;

    if (argc <= 1)
        /* BLD-2: the Makefile passes $(CORE_BENCH_BLOCK), which is a
         * $(wildcard) and so expands to nothing when Core's bench fixture is
         * not on this host. Say so, rather than quietly running only the
         * synthetic corpus and looking identical to a full run. */
        printf("SKIP real-block corpus: no path given (set CORE_BENCH_BLOCK to Core's block413567.raw)\n");
    if (argc > 1){
        FILE* f = fopen(argv[1], "rb");
        if (!f){
            /* BLD-2 (audit 2026-09-03): the real-block corpus is Core's own
             * bench fixture, which lives outside this repo. It used to be
             * passed as a literal path in the Makefile recipe, so on any host
             * without a Core checkout this exited 1, make aborted the recipe,
             * and the ~60 tests listed after it never ran at all -- while the
             * README presented `make test` as the full gate. SKIP loudly and
             * carry on with the synthetic corpus below, the way
             * test_taproot_block_diff already does for its own fixtures. */
            printf("SKIP real-block corpus: %s not present (Core bench fixture, optional)\n", argv[1]);
        } else {
        fseek(f, 0, SEEK_END); long bl = ftell(f); fseek(f, 0, SEEK_SET);
        u8* blk = malloc(bl);
        if (!blk || (long)fread(blk, 1, bl, f) != bl) return 1;
        fclose(f);
        const u8* end = blk + bl; const u8* p = blk + 80; int ok = 1;
        u64 ntx = rd_cs_local(&p, end, &ok);
        for (u64 t = 0; ok && t < ntx; t++){
            u64 span = tx_span(p, end);
            if (!span){ fprintf(stderr, "corpus lost sync at %lu\n", t); return 1; }
            diff_one(p, span, OUTCAP, ++tag);
            if (t % 149 == 0){
                for (u64 cut = 0; cut < span; cut++)
                    diff_one(p, cut, OUTCAP, ++tag);
                long need = strip_witness(p, (int64_t)span, oc, OUTCAP);
                for (long cap = 0; cap <= need + 2; cap++)
                    diff_one(p, span, cap, ++tag);
            }
            p += span; real_txs++;
        }
        free(blk);
            }
}

    static u8 tx[1<<16];
    /* fat segwit tx: full strip, truncation fuzz, and a full cap sweep */
    u64 n = build_fat_tx(tx, 3, 4);
    diff_one(tx, n, OUTCAP, ++tag);
    for (u64 cut = 0; cut < n; cut++) diff_one(tx, cut, OUTCAP, ++tag);
    { long need = strip_witness(tx, (int64_t)n, oc, OUTCAP);
      for (long cap = -2; cap <= need + 2; cap++) diff_one(tx, n, cap, ++tag); }

    /* non-canonical varints: 0xfd-encoding of a value < 0xfd -> reject */
    { u8 t[64]; u64 m = 0;
      t[m++]=1;t[m++]=0;t[m++]=0;t[m++]=0;
      t[m++]=0xfd; t[m++]=0x01; t[m++]=0x00;        /* nin = 1, non-canonical */
      for (int k=0;k<36;k++) t[m++]=7;
      t[m++]=0; t[m++]=0xff;t[m++]=0xff;t[m++]=0xff;t[m++]=0xff;
      t[m++]=1; for (int k=0;k<8;k++) t[m++]=0; t[m++]=1; t[m++]=0x51;
      t[m++]=0;t[m++]=0;t[m++]=0;t[m++]=0;
      diff_one(t, m, OUTCAP, ++tag); }
    /* nin == 0 */
    { u8 t[16] = {1,0,0,0, 0x00, 1,0,0,0,0,0,0,0,0, 0,0};
      diff_one(t, 16, OUTCAP, ++tag); }
    /* legacy passthrough (no witness): output == input bytes */
    { u8 t[64]; u64 m = 0;
      t[m++]=1;t[m++]=0;t[m++]=0;t[m++]=0;
      t[m++]=1;
      for (int k=0;k<36;k++) t[m++]=3;
      t[m++]=2; t[m++]=0x51; t[m++]=0x75;
      t[m++]=0xfe;t[m++]=0xff;t[m++]=0xff;t[m++]=0xff;
      t[m++]=1; for (int k=0;k<8;k++) t[m++]=0; t[m++]=1; t[m++]=0x6a;
      t[m++]=5;t[m++]=0;t[m++]=0;t[m++]=0;
      diff_one(t, m, OUTCAP, ++tag);
      long c = strip_witness(t, (int64_t)m, oc, OUTCAP);
      compared++;
      if (c != (long)m || memcmp(oc, t, m) != 0){ fail("legacy passthrough shape", tag); }
    }

    printf("compared %ld strip cases (%ld real txs); %ld mismatch(es)\n",
           compared, real_txs, fails);
    printf("%s (%ld failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
