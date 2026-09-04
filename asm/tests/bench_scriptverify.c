/* bench_scriptverify.c -- CPU-time benchmark for the legacy/P2SH VerifyScript
 * driver's PER-CALL ARENA COST (bitcoin_scriptverify.c / _drv.asm).
 *
 * WHY THIS EXISTS. sv_verify_script runs a stack of MAX_STACK(1000) x
 * ELEM_SIZE(528) = 528,000-byte element records, and unconditionally:
 *
 *   :348  memset(main_e, 0, 528000)   every call
 *   :357  memcpy(copy_e, main_e, 528000)   every call with SV_P2SH set
 *   :378  memcpy(main_e, copy_e, 528000)   every actual P2SH redeem run
 *
 * i.e. ~1.5 MB of memory traffic per legacy P2SH input, to service a stack
 * that is realistically fewer than ten elements deep. PERF_SCOPE.md section
 * 11.2 item 3 and section 12.8 item 2 both still record the 6.9% in
 * memmove/memset/copy_bytes as "source unknown without a call-graph
 * profile"; section 11's table is __memmove_avx512 3.82% + __memset_avx512
 * 1.78% + copy_bytes.cb_loop 1.31% = 6.91%. This benchmark makes that cost
 * a standing, reproducible number so any change to the snapshot discipline
 * is compared against a measurement rather than against the arithmetic.
 *
 * WHAT IS AND IS NOT MEASURED. The shapes below are deliberately
 * CRYPTO-FREE -- no CHECKSIG, so no ecdsa_verify -- because the arena cost
 * is what is under test and a 120 us signature verification would bury it.
 * The per-input picture is then arithmetic the reader can do: PERF_SCOPE.md
 * section 1 measured this tree's ecdsa_verify at 120.9 us, so a legacy P2SH
 * input costs roughly one signature plus one of the p2sh_redeem figures
 * below.
 *
 * THIS BENCHMARK UNDERSTATES THE PRODUCTION COST, and the direction matters.
 * A tight loop keeps both 528,000-byte arenas (1.03 MB together) resident in
 * L2/L3. In the real connect path each call is separated by a signature
 * verification and several LSM UTXO lookups, so the arena is cold and every
 * touched line is a miss. Treat the numbers here as a floor.
 *
 * Shapes, and why these:
 *   nonp2sh      SV_P2SH clear -- isolates the :348 memset alone.
 *   p2sh_nonsh   SV_P2SH set, scriptPubKey is NOT a P2SH shape -- the :357
 *                snapshot happens, the :378 restore does not. This is every
 *                P2PKH/P2PK/bare-multisig input on a post-BIP16 chain, i.e.
 *                the overwhelmingly common case.
 *   p2sh_redeem  SV_P2SH set, a real P2SH redeem -- all three sites. The
 *                worst case, and the one worth quoting.
 *   deep         a 200-element stack under SV_P2SH, to show that the cost is
 *                flat in real stack depth (it is: the arena ops are sized by
 *                MAX_STACK, not by sp) -- which is the whole finding.
 *
 * Method mirrors bench_segwit_sighash.c: CLOCK_PROCESS_CPUTIME_ID (CPU time,
 * so a loaded box does not inflate it), min / median / max over N runs.
 *
 * Usage: tests/bench_scriptverify [runs]      (default 15)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

typedef unsigned char u8;
typedef unsigned long u64;

extern int sv_verify_script(const u8* ss, unsigned long ssl,
                            const u8* spk, unsigned long spl,
                            u64 flags, unsigned long nIn,
                            const u8* tx, unsigned long txlen,
                            u8* work, unsigned long workcap);
extern void hash160(u8 out[20], const void* in, long long len);

/* daemon/tx_verify.c is on the link line for sv_run_v's neighbours; this
 * symbol is the one it needs from the mempool side and never calls here. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk,
                                    unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr, "unexpected mempool_resolve_confirmed_utxo\n"); abort();
}

#define SV_P2SH        (1ULL<<0)
#define SV_SIGPUSHONLY (1ULL<<5)

static u8 work[1<<20];
/* A minimal wire-shaped tx. sv_get_locktime_context only walks as far as
 * input 0's nSequence; a malformed one leaves the CLTV/CSV context zeroed,
 * which none of these scripts consult. */
static u8 txb[64]; static u64 txl;

/* ---- script builders -------------------------------------------------- */
static u64 push(u8* d, u64 n, const u8* data, u64 len){
    if (len <= 75){ d[n++] = (u8)len; }
    else { d[n++] = 0x4c; d[n++] = (u8)len; }
    memcpy(d+n, data, len); return n + len;
}

typedef struct { const char* name; u8 ss[4096]; u64 ssl; u8 spk[64]; u64 spl;
                 u64 flags; long iters; int expect; } shape;

static shape shapes[4];

static void build(void){
    static u8 filler[32];
    for (int i=0;i<32;i++) filler[i] = (u8)(i*7+1);

    /* --- nonp2sh: scriptSig pushes 1, scriptPubKey is OP_1 (true). ------ */
    { shape* s = &shapes[0]; s->name = "nonp2sh";
      s->ssl = 0;
      s->spl = 0; s->spk[s->spl++] = 0x51;              /* OP_1 */
      s->flags = 0; s->iters = 20000; s->expect = 0; }

    /* --- p2sh_nonsh: P2SH flag on, spk is not a P2SH shape. ------------- */
    { shape* s = &shapes[1]; s->name = "p2sh_nonsh";
      s->ssl = 0; s->ssl = push(s->ss, s->ssl, filler, 32);
      s->spl = 0;
      s->spk[s->spl++] = 0x75;                          /* OP_DROP */
      s->spk[s->spl++] = 0x51;                          /* OP_1    */
      s->flags = SV_P2SH; s->iters = 20000; s->expect = 0; }

    /* --- p2sh_redeem: a real BIP16 redeem (redeemScript = OP_1). -------- */
    { shape* s = &shapes[2]; s->name = "p2sh_redeem";
      u8 redeem[1]; redeem[0] = 0x51;                   /* OP_1 */
      u8 h[20]; hash160(h, redeem, 1);
      s->ssl = 0; s->ssl = push(s->ss, s->ssl, redeem, 1);
      s->spl = 0;
      s->spk[s->spl++] = 0xa9;                          /* OP_HASH160 */
      s->spl = push(s->spk, s->spl, h, 20);
      s->spk[s->spl++] = 0x87;                          /* OP_EQUAL */
      s->flags = SV_P2SH; s->iters = 20000; s->expect = 0; }

    /* --- deep: 200 pushes left on the stack under P2SH. ----------------- */
    { shape* s = &shapes[3]; s->name = "deep200";
      s->ssl = 0;
      for (int i=0;i<200;i++) s->ssl = push(s->ss, s->ssl, filler, 8);
      s->spl = 0; s->spk[s->spl++] = 0x51;              /* OP_1 */
      s->flags = SV_P2SH; s->iters = 20000; s->expect = 0; }
}

static double now_cpu(void){
    struct timespec t; clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
    return (double)t.tv_sec + 1e-9*(double)t.tv_nsec;
}

static int cmpd(const void* a, const void* b){
    double x = *(const double*)a, y = *(const double*)b;
    return x<y ? -1 : x>y ? 1 : 0;
}

int main(int argc, char** argv){
    int runs = argc > 1 ? atoi(argv[1]) : 15;
    if (runs < 3) runs = 3;
    build();

    /* minimal tx: version(4) 1 input, null outpoint, empty scriptSig,
     * sequence, 0 outputs, locktime(4). */
    u64 n = 0;
    txb[n++]=1; txb[n++]=0; txb[n++]=0; txb[n++]=0;
    txb[n++]=1;                                   /* 1 input */
    memset(txb+n, 0, 32); n += 32;                /* prevout hash */
    txb[n++]=0xff; txb[n++]=0xff; txb[n++]=0xff; txb[n++]=0xff;
    txb[n++]=0;                                   /* empty scriptSig */
    txb[n++]=0xff; txb[n++]=0xff; txb[n++]=0xff; txb[n++]=0xff;
    txb[n++]=0;                                   /* 0 outputs */
    txb[n++]=0; txb[n++]=0; txb[n++]=0; txb[n++]=0;
    txl = n;

    printf("bench_scriptverify -- sv_verify_script arena cost, %d runs\n", runs);
    printf("(crypto-free shapes: what is measured is the 528,000-byte "
           "memset/memcpy discipline)\n\n");
    printf("%-12s %10s %10s %10s %10s\n", "shape", "us/call", "median", "max", "iters");

    double* t = malloc((size_t)runs * sizeof *t);
    int bad = 0;
    for (unsigned si = 0; si < sizeof shapes / sizeof shapes[0]; si++){
        shape* s = &shapes[si];
        /* correctness gate: a benchmark of a wrong answer is worthless */
        int r = sv_verify_script(s->ss, s->ssl, s->spk, s->spl, s->flags, 0,
                                 txb, txl, work, sizeof work);
        if (r != s->expect){
            printf("%-12s  SHAPE ERROR: sv_verify_script returned %d, want %d\n",
                   s->name, r, s->expect);
            bad = 1; continue;
        }
        for (int k = 0; k < runs; k++){
            double a = now_cpu();
            for (long i = 0; i < s->iters; i++)
                sv_verify_script(s->ss, s->ssl, s->spk, s->spl, s->flags, 0,
                                 txb, txl, work, sizeof work);
            t[k] = (now_cpu() - a) * 1e6 / (double)s->iters;
        }
        qsort(t, (size_t)runs, sizeof *t, cmpd);
        printf("%-12s %10.3f %10.3f %10.3f %10ld\n",
               s->name, t[0], t[runs/2], t[runs-1], s->iters);
    }
    free(t);
    if (bad) return 1;
    printf("\nFor scale: PERF_SCOPE.md section 1 measured this tree's "
           "ecdsa_verify at 120.9 us.\n");
    return 0;
}
