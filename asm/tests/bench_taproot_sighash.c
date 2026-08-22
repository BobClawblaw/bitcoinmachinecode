/* bench_taproot_sighash.c -- CPU-time benchmark for BIP341/BIP342 taproot
 * sighashing, the taproot counterpart of tests/bench_segwit_sighash.c.
 *
 * Why: bitcoin_taproot_sighash.c carried the same shape PERF_SCOPE.md section
 * 7 found in bitcoin_segwit.c and fc4bd67 removed -- tx_seq() and
 * tx_outpoint() re-walked the input list from the start on every call, and
 * ser_txout()/ser_txout_len() re-walked the output list from the start on
 * every call (ser_txout_len twice, literally: the walk was run, thrown away,
 * and run again). BIP341's aggregate hashes call those once per input and
 * once per output, and taproot_sighash() is itself called once per input, so
 * a transaction paid O(nin^2 + nout^2) per call and O(nin^3 + nin*nout^2)
 * per transaction. This file makes the before/after a standing, reproducible
 * measurement rather than a remembered figure.
 *
 * Shapes, and why these -- deliberately the SAME five as
 * bench_segwit_sighash.c, so the two tables are directly comparable:
 *   small1  1 input / 2 outputs, and
 *   small2  2 inputs / 2 outputs -- the overwhelmingly common shapes. An
 *           asymptotic win that pessimises these is a bad trade on this
 *           chain, so they are measured first and reported in microseconds.
 *   mid     100 inputs / 5 outputs -- an ordinary consolidation.
 *   big     1,372 inputs / 100 outputs -- the largest input count
 *           CHAIN_AHEAD_CENSUS.md found on the chain ahead of the replay.
 *           This is where an O(nin^2) shows up.
 *   manyout 2 inputs / 3,000 outputs -- an exchange batch payout, where the
 *           old sha_outputs staging was O(nin*nout + nout^2).
 *
 * Both BIP341 spend paths are measured: ext_flag=0 (key-path) and ext_flag=1
 * (script-path / BIP342 tapscript, with a dummy 32-byte tapleaf). Taproot
 * usage goes script-path-heavy from roughly height 775,000, so the key-path
 * number alone would not describe the chain ahead.
 *
 * Two costs are reported per shape:
 *   us/call  -- one taproot_sighash() invocation, and
 *   tx total -- nin calls, i.e. what one whole transaction costs, because
 *               taproot_sighash() runs once per input (once per executed
 *               OP_CHECKSIG/OP_CHECKSIGADD) and that product is what a block
 *               actually pays.
 *
 * Method: CLOCK_PROCESS_CPUTIME_ID (CPU time, not wall, so a loaded machine
 * does not inflate it), min of N runs reported alongside the median and the
 * max so the spread is visible. Iterations per run are calibrated per shape
 * so every run is at least ~20 ms of work regardless of which build (old or
 * new) this source is linked against.
 *
 * Optional second argument: a real-block workload file (see
 * WORKLOAD FORMAT below) built by an external extractor from raw mainnet
 * blocks. Every taproot input in the workload is driven through
 * taproot_sighash() exactly once, which is what block validation does.
 *
 * Usage: tests/bench_taproot_sighash [runs] [workload-file]     (runs default 15)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* bitcoin_taproot_sighash.c API (copied verbatim from tests/test_taproot_sighash.c) */
typedef struct {
    const uint8_t* tx;   int64_t txlen;
    int64_t  n_in;
    uint8_t  hash_type;
    const uint8_t* prevouts;   /* 36 * num_inputs, contiguous */
    const uint8_t* amounts;    /* 8  * num_inputs, contiguous */
    const uint8_t* spks;       /* per input: 1-byte compactsize + scriptPubKey */
    int64_t  num_inputs;
    int      ext_flag;         /* 0 keypath, 1 scriptpath */
    const uint8_t* tapleaf;    /* 32 bytes or NULL */
    uint32_t codesep_pos;
    const uint8_t* annex;
    uint64_t annexlen;
} tapctx_t;
extern long taproot_sighash(uint8_t* out32, const tapctx_t* c, uint8_t* pre, long cap);

#define PRECAP 65536

static int put_cs(uint8_t* d, uint64_t n){
    if (n < 0xfd){ d[0]=(uint8_t)n; return 1; }
    if (n <= 0xffff){ d[0]=0xfd; d[1]=(uint8_t)n; d[2]=(uint8_t)(n>>8); return 3; }
    d[0]=0xfe; for (int i=0;i<4;i++) d[1+i]=(uint8_t)(n>>(8*i)); return 5;
}

/* A synthetic but wire-exact WITNESS-STRIPPED transaction, which is what the
 * daemon feeds this path (daemon/tx_verify.c calls strip_witness() before
 * taproot_verify_input()):
 *   version(4) || compactsize(nin)
 *   || per input { 36-byte outpoint || 0x00 empty scriptSig || 4-byte nSequence }
 *   || compactsize(nout)
 *   || per output { 8-byte value || compactsize(len) || scriptPubKey }
 *   || 4-byte locktime                                                     */
static size_t build_tx(uint8_t* d, size_t nin, size_t nout, size_t spklen){
    size_t n = 0;
    d[n++]=2; d[n++]=0; d[n++]=0; d[n++]=0;              /* version */
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
    d[n++]=0; d[n++]=0; d[n++]=0; d[n++]=0;              /* locktime */
    return n;
}

/* The three per-input arrays BIP341 hashes, built to match the transaction
 * EXACTLY: num_inputs == the transaction's input count, prevouts 36*n,
 * amounts 8*n, spks n entries of 1-byte-compactsize + 34-byte P2TR
 * scriptPubKey (0x51 0x20 || 32 bytes). The new code requires this
 * agreement; the old code did not check it. Spent outputs of taproot inputs
 * ARE P2TR, so 34 bytes is not an approximation here. */
typedef struct { uint8_t* prevouts; uint8_t* amounts; uint8_t* spks; } spent_t;

static void spent_build(spent_t* s, size_t nin){
    s->prevouts = (uint8_t*)malloc(nin*36);
    s->amounts  = (uint8_t*)malloc(nin*8);
    s->spks     = (uint8_t*)malloc(nin*35);
    for (size_t i=0;i<nin;i++){
        for (int b=0;b<32;b++) s->prevouts[i*36+b] = (uint8_t)((i*31 + b*13) & 0xff);
        s->prevouts[i*36+32]=(uint8_t)(i&0xff);
        s->prevouts[i*36+33]=0; s->prevouts[i*36+34]=0; s->prevouts[i*36+35]=0;
        uint64_t amt = 100000ULL + i*777ULL;
        for (int b=0;b<8;b++) s->amounts[i*8+b] = (uint8_t)(amt>>(8*b));
        s->spks[i*35+0] = 34; s->spks[i*35+1] = 0x51; s->spks[i*35+2] = 0x20;
        for (int b=0;b<32;b++) s->spks[i*35+3+b] = (uint8_t)((i*7 + b*11 + 5) & 0xff);
    }
}
static void spent_free(spent_t* s){ free(s->prevouts); free(s->amounts); free(s->spks); }

static const uint8_t TAPLEAF[32] = {
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
    0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf };

static double cpu_ms(void){
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}
static int cmpd(const void* a, const void* b){
    double x = *(const double*)a, y = *(const double*)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

static void ctx_init(tapctx_t* c, const uint8_t* tx, size_t txlen, size_t nin,
                     const spent_t* s, int ext_flag){
    c->tx = tx; c->txlen = (int64_t)txlen; c->n_in = 0;
    c->hash_type = 0x00;                 /* SIGHASH_DEFAULT: the common case */
    c->prevouts = s->prevouts; c->amounts = s->amounts; c->spks = s->spks;
    c->num_inputs = (int64_t)nin;
    c->ext_flag = ext_flag;
    c->tapleaf = ext_flag ? TAPLEAF : NULL;
    c->codesep_pos = 0xffffffffu;
    c->annex = NULL; c->annexlen = 0;
}

/* Calibrate an iteration count so a run is at least ~20 ms of work, so the
 * same source gives a usable run length whether it is linked against the old
 * (much slower on the large shapes) or the new implementation. */
static int calibrate(tapctx_t* c, size_t nin, uint8_t* pre){
    uint8_t h[32];
    int iters = 1;
    for (;;){
        double a = cpu_ms();
        for (int i=0;i<iters;i++){
            c->n_in = (int64_t)((size_t)i % nin);
            taproot_sighash(h, c, pre, PRECAP);
        }
        double d = cpu_ms() - a;
        if (d >= 20.0 || iters >= 400000) break;
        double f = d > 0.05 ? (25.0 / d) : 8.0;
        if (f > 8.0) f = 8.0;
        int next = (int)(iters * f) + 1;
        if (next <= iters) next = iters * 2;
        iters = next;
    }
    return iters;
}

static void run(const char* name, size_t nin, size_t nout, size_t spklen,
                int ext_flag, int runs, uint8_t* pre){
    size_t cap = 64 + nin*(32+4+1+4) + nout*(8+9+spklen) + 16;
    uint8_t* tx = (uint8_t*)malloc(cap);
    size_t txlen = build_tx(tx, nin, nout, spklen);
    spent_t s; spent_build(&s, nin);
    tapctx_t c; ctx_init(&c, tx, txlen, nin, &s, ext_flag);
    uint8_t h[32];

    /* Correctness smoke: a preimage length of 0 means the implementation
     * REFUSED this shape. Say so; never time a refusal. */
    long prelen = taproot_sighash(h, &c, pre, PRECAP);
    if (prelen <= 0){
        printf("%-8s %5zu in /%6zu out  tx=%9zu B   REFUSED (taproot_sighash returned %ld)\n",
               name, nin, nout, txlen, prelen);
        free(tx); spent_free(&s); return;
    }

    int iters = calibrate(&c, nin, pre);
    double* t = (double*)malloc(sizeof(double)*runs);
    for (int r=0;r<runs;r++){
        double a = cpu_ms();
        for (int i=0;i<iters;i++){
            c.n_in = (int64_t)((size_t)i % nin);
            taproot_sighash(h, &c, pre, PRECAP);
        }
        t[r] = (cpu_ms() - a) / iters;     /* ms per call */
    }
    qsort(t, (size_t)runs, sizeof(double), cmpd);
    double txmin = t[0] * (double)nin;     /* ms for a whole transaction */
    printf("%-8s %5zu in /%6zu out  tx=%9zu B  pre=%3ld B   "
           "min %10.4f us  med %10.4f  max %10.4f   |  tx total (%5zu calls) "
           "min %11.4f ms   (n=%d x %d iters)\n",
           name, nin, nout, txlen, prelen,
           t[0]*1000.0, t[runs/2]*1000.0, t[runs-1]*1000.0,
           nin, txmin, runs, iters);
    free(t); free(tx); spent_free(&s);
}

/* ---------------- real-block workload ----------------
 * WORKLOAD FORMAT (little-endian, packed, produced by an external extractor
 * that parses raw mainnet blocks):
 *     u32 magic = 0x54415057
 *     u32 ntx
 *     per tx:  u32 txlen; u8 tx[txlen]   (WITNESS-STRIPPED serialization)
 *              u32 nin                   (the transaction's input count)
 *              u32 ncalls
 *              per call: u32 in_index; u32 ext_flag
 * Every entry is one taproot input that a real block really contains, driven
 * through taproot_sighash() exactly once, in block order, with the real
 * transaction STRUCTURE (real input/output counts and real script sizes --
 * which is the whole of what the removed O(n^2) walked). */
typedef struct {
    uint8_t* tx; uint32_t txlen; uint32_t nin;
    uint32_t ncalls; uint32_t* idx; uint32_t* ext;
    spent_t s;
} wtx_t;

static int rdu32(FILE* f, uint32_t* v){ return fread(v, 4, 1, f) == 1; }

static void run_workload(const char* path, int runs, uint8_t* pre){
    FILE* f = fopen(path, "rb");
    if (!f){ printf("workload: cannot open %s\n", path); return; }
    uint32_t magic=0, ntx=0;
    if (!rdu32(f,&magic) || magic != 0x54415057u){ printf("workload: bad magic\n"); fclose(f); return; }
    if (!rdu32(f,&ntx)){ printf("workload: truncated\n"); fclose(f); return; }
    wtx_t* w = (wtx_t*)calloc(ntx, sizeof(wtx_t));
    uint64_t total_calls = 0;
    for (uint32_t i=0;i<ntx;i++){
        if (!rdu32(f,&w[i].txlen)){ printf("workload: truncated tx %u\n", i); fclose(f); return; }
        w[i].tx = (uint8_t*)malloc(w[i].txlen);
        if (fread(w[i].tx, 1, w[i].txlen, f) != w[i].txlen){ printf("workload: truncated body %u\n", i); fclose(f); return; }
        if (!rdu32(f,&w[i].nin) || !rdu32(f,&w[i].ncalls)){ printf("workload: truncated hdr %u\n", i); fclose(f); return; }
        w[i].idx = (uint32_t*)malloc(w[i].ncalls*4);
        w[i].ext = (uint32_t*)malloc(w[i].ncalls*4);
        for (uint32_t k=0;k<w[i].ncalls;k++){
            if (!rdu32(f,&w[i].idx[k]) || !rdu32(f,&w[i].ext[k])){ printf("workload: truncated calls %u\n", i); fclose(f); return; }
        }
        spent_build(&w[i].s, w[i].nin);
        total_calls += w[i].ncalls;
    }
    fclose(f);

    /* Verify every call really produces a preimage before any of it is timed. */
    uint8_t h[32];
    uint64_t refused = 0;
    for (uint32_t i=0;i<ntx;i++){
        tapctx_t c; ctx_init(&c, w[i].tx, w[i].txlen, w[i].nin, &w[i].s, 0);
        for (uint32_t k=0;k<w[i].ncalls;k++){
            c.n_in = (int64_t)w[i].idx[k]; c.ext_flag = (int)w[i].ext[k];
            c.tapleaf = c.ext_flag ? TAPLEAF : NULL;
            if (taproot_sighash(h, &c, pre, PRECAP) <= 0) refused++;
        }
    }
    printf("\n== real-block workload: %s ==\n", path);
    printf("   transactions %u   taproot sighash calls %llu   refused %llu\n",
           ntx, (unsigned long long)total_calls, (unsigned long long)refused);
    if (refused){
        printf("   NOT TIMED: %llu call(s) refused -- this build cannot do this workload\n",
               (unsigned long long)refused);
        return;
    }
    double* t = (double*)malloc(sizeof(double)*runs);
    for (int r=0;r<runs;r++){
        double a = cpu_ms();
        for (uint32_t i=0;i<ntx;i++){
            tapctx_t c; ctx_init(&c, w[i].tx, w[i].txlen, w[i].nin, &w[i].s, 0);
            for (uint32_t k=0;k<w[i].ncalls;k++){
                c.n_in = (int64_t)w[i].idx[k]; c.ext_flag = (int)w[i].ext[k];
                c.tapleaf = c.ext_flag ? TAPLEAF : NULL;
                taproot_sighash(h, &c, pre, PRECAP);
            }
        }
        t[r] = cpu_ms() - a;
    }
    qsort(t, (size_t)runs, sizeof(double), cmpd);
    printf("   total CPU  min %12.4f ms   med %12.4f   max %12.4f   (n=%d)\n",
           t[0], t[runs/2], t[runs-1], runs);
    printf("   per taproot input  min %10.4f us   med %10.4f   max %10.4f\n",
           t[0]*1000.0/(double)total_calls, t[runs/2]*1000.0/(double)total_calls,
           t[runs-1]*1000.0/(double)total_calls);
    free(t);
    for (uint32_t i=0;i<ntx;i++){ free(w[i].tx); free(w[i].idx); free(w[i].ext); spent_free(&w[i].s); }
    free(w);
}

int main(int argc, char** argv){
    int runs = argc > 1 ? atoi(argv[1]) : 15;
    if (runs < 3) runs = 3;
    uint8_t* pre = (uint8_t*)malloc(PRECAP);

    printf("== BIP341 taproot sighash, CPU time per taproot_sighash() call ==\n");
    printf("   SIGHASH_DEFAULT, 34-byte P2TR spent scriptPubKeys, 22-byte tx outputs\n");
    for (int ext = 0; ext <= 1; ext++){
        printf("\n-- %s (ext_flag=%d) --\n",
               ext ? "script-path / BIP342 tapscript" : "key-path", ext);
        run("small1",     1,     2, 22, ext, runs, pre);
        run("small2",     2,     2, 22, ext, runs, pre);
        run("mid",      100,     5, 22, ext, runs, pre);
        run("big",     1372,   100, 22, ext, runs, pre);
        run("manyout",    2,  3000, 22, ext, runs, pre);
    }

    if (argc > 2) run_workload(argv[2], runs, pre);
    free(pre);
    return 0;
}
