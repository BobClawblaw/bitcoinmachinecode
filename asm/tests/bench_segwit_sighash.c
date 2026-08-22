/* bench_segwit_sighash.c -- CPU-time benchmark for BIP143 segwit-v0 sighashing.
 *
 * PERF_SCOPE.md section 7's live profile at height ~617,000 put read_cs at
 * 22.4% of all replay cycles, with sw_seq (5.9%) and sw_prevout (5.7%) behind
 * it -- 34% together, all three inside bitcoin_segwit.c, and all three there
 * because the BIP143 aggregate hashes walked the input list from the start
 * once per input. Incident #21's bound fix then cost a further 16% on exactly
 * this path (2.44 -> 2.84 ms/call on the shape below). Both numbers were
 * measured with a throwaway harness; this file makes the measurement a
 * standing, reproducible one so the next change to this path can be compared
 * against it rather than against a remembered figure.
 *
 * Shapes, and why these:
 *   big     1,372 inputs / 100 outputs -- the largest input count
 *           CHAIN_AHEAD_CENSUS.md found on the chain ahead of the replay, and
 *           the shape incident #21 reported its 2.44/2.54/2.84 ms figures on.
 *           This is where an O(n^2) shows up.
 *   mid     100 inputs / 5 outputs -- an ordinary consolidation.
 *   small1  1 input / 2 outputs, and
 *   small2  2 inputs / 2 outputs -- the overwhelmingly common shapes. An
 *           asymptotic win that pessimises these would be a bad trade, so
 *           they are measured too, and reported in microseconds because that
 *           is the scale they live at.
 *   manyout 2 inputs / 3,000 outputs -- an exchange batch payout, which is
 *           where the old hashOutputs walk was O(nin*nout + nout^2).
 *
 * Method: CLOCK_PROCESS_CPUTIME_ID (CPU time, not wall, so a loaded machine
 * does not inflate it), min of N runs reported alongside the median and the
 * max so the spread is visible. Iterations per run are chosen per shape so
 * every run is at least a few milliseconds.
 *
 * Usage: tests/bench_segwit_sighash [runs]     (default 15)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

extern long segwit_v0_sighash(uint8_t out32[32], const uint8_t* tx, int64_t txlen,
                              int64_t n_in, uint32_t nHashType, uint64_t amount,
                              const uint8_t* scriptCode, uint64_t scriptcode_len,
                              uint8_t* pre, long cap);

static int put_cs(uint8_t* d, uint64_t n){
    if (n < 0xfd){ d[0]=(uint8_t)n; return 1; }
    if (n <= 0xffff){ d[0]=0xfd; d[1]=(uint8_t)n; d[2]=(uint8_t)(n>>8); return 3; }
    d[0]=0xfe; for (int i=0;i<4;i++) d[1+i]=(uint8_t)(n>>(8*i)); return 5;
}

/* A synthetic but wire-exact segwit transaction: nin P2WPKH-style inputs
 * (empty scriptSig, one 72-byte witness item each) and nout P2WPKH outputs. */
static size_t build_tx(uint8_t* d, size_t nin, size_t nout, size_t spklen){
    size_t n = 0;
    d[n++]=2; d[n++]=0; d[n++]=0; d[n++]=0;              /* version */
    d[n++]=0x00; d[n++]=0x01;                            /* marker+flag */
    n += (size_t)put_cs(d+n, nin);
    for (size_t i=0;i<nin;i++){
        for (int b=0;b<32;b++) d[n++] = (uint8_t)((i*31 + b*13) & 0xff);
        d[n++]=(uint8_t)(i&0xff); d[n++]=0; d[n++]=0; d[n++]=0;   /* vout */
        d[n++]=0;                                        /* empty scriptSig */
        d[n++]=0xfe; d[n++]=0xff; d[n++]=0xff; d[n++]=0xff;       /* nSequence */
    }
    n += (size_t)put_cs(d+n, nout);
    for (size_t i=0;i<nout;i++){
        for (int b=0;b<8;b++) d[n++] = (uint8_t)((i>>(8*b)) & 0xff);
        n += (size_t)put_cs(d+n, spklen);
        for (size_t b=0;b<spklen;b++) d[n++] = (uint8_t)((b*7+3)&0xff);
    }
    for (size_t i=0;i<nin;i++){                          /* witness */
        d[n++]=1; d[n++]=72; for (int b=0;b<72;b++) d[n++]=(uint8_t)b;
    }
    d[n++]=0; d[n++]=0; d[n++]=0; d[n++]=0;              /* locktime */
    return n;
}

static double cpu_ms(void){
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}
static int cmpd(const void* a, const void* b){
    double x = *(const double*)a, y = *(const double*)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

static const uint8_t SC[25] = {
    0x76,0xa9,0x14, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19, 0x88,0xac };

static void run(const char* name, size_t nin, size_t nout, size_t spklen,
                int iters, int runs, uint8_t* pre, long precap){
    size_t cap = 64 + nin*(32+4+1+4+2+72) + nout*(8+9+spklen) + 16;
    uint8_t* tx = (uint8_t*)malloc(cap);
    size_t txlen = build_tx(tx, nin, nout, spklen);
    uint8_t h[32];
    /* correctness smoke + warm the per-thread scratch */
    if (segwit_v0_sighash(h, tx, (int64_t)txlen, 0, 1, 5000000000ULL,
                          SC, sizeof SC, pre, precap) <= 0){
        printf("%-8s FAILED to hash\n", name); free(tx); return;
    }
    double* t = (double*)malloc(sizeof(double)*runs);
    for (int r=0;r<runs;r++){
        double a = cpu_ms();
        for (int i=0;i<iters;i++)
            segwit_v0_sighash(h, tx, (int64_t)txlen, (int64_t)(i % nin), 1,
                              5000000000ULL, SC, sizeof SC, pre, precap);
        t[r] = (cpu_ms() - a) / iters;
    }
    qsort(t, (size_t)runs, sizeof(double), cmpd);
    const char* unit = t[0] >= 0.05 ? "ms" : "us";
    double k = t[0] >= 0.05 ? 1.0 : 1000.0;
    printf("%-8s %5zu in /%6zu out  tx=%8zu B   min %9.4f %s   med %9.4f   "
           "max %9.4f   (n=%d x %d iters)\n",
           name, nin, nout, txlen, t[0]*k, unit, t[runs/2]*k, t[runs-1]*k,
           runs, iters);
    free(t); free(tx);
}

int main(int argc, char** argv){
    int runs = argc > 1 ? atoi(argv[1]) : 15;
    if (runs < 3) runs = 3;
    long precap = 1 << 16;              /* the real consensus caller's cap
                                           (bitcoin_witness_v0.c) */
    uint8_t* pre = (uint8_t*)malloc((size_t)precap);
    printf("== BIP143 segwit-v0 sighash, CPU time per segwit_v0_sighash() call ==\n");
    run("small1",     1,     2, 22,  20000, runs, pre, precap);
    run("small2",     2,     2, 22,  20000, runs, pre, precap);
    run("mid",      100,     5, 22,   1000, runs, pre, precap);
    run("big",     1372,   100, 22,     20, runs, pre, precap);
    run("manyout",    2,  3000, 22,    200, runs, pre, precap);
    free(pre);
    return 0;
}
