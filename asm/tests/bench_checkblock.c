/* bench_checkblock.c -- block-level consensus checking on mainnet block
 * 413,567, the same block Bitcoin Core's src/bench/checkblock.cpp uses, read
 * from Core's own data file so both sides see byte-identical input.
 *
 * Usage: bench_checkblock <path/to/block413567.raw> [rounds]
 *   Core ships that file at src/bench/data/block413567.raw (999,887 bytes,
 *   1,557 transactions). Passing a path rather than vendoring a 1 MB blob into
 *   this repo keeps the input provably the same bytes Core benchmarks.
 *
 * TWO ROWS, because Core has two and they measure different halves:
 *   parse      <- DeserializeBlockTest : walk every transaction in the block.
 *                 Core deserializes into CBlock/CTransaction objects (heap
 *                 allocation per tx, per input, per output). This repo does
 *                 not deserialize at all -- tx_parse walks the wire bytes in
 *                 place and records offsets. That is a genuine architectural
 *                 difference, not a like-for-like row, and BENCHMARKS.md says
 *                 so rather than presenting the ratio as a speedup.
 *   cons_verify <- CheckBlockTest      : the consensus check over a received
 *                 block.
 *
 * WHAT cons_verify DOES NOT DO THAT CheckBlock DOES -- read this before using
 * the ratio. Core's CheckBlock (validation.cpp) performs, in addition to PoW
 * and the merkle root:
 *   - merkle MUTATION detection (the CVE-2012-2459 duplicate-subtree guard),
 *   - block weight and serialized-size limits,
 *   - CheckTransaction on every tx: empty vin/vout, output value range and
 *     total-value overflow, duplicate inputs within a tx, null prevout on
 *     non-coinbase, coinbase scriptSig length bounds,
 *   - the legacy sigop count limit.
 * cons_verify (bitcoin_cons.asm) checks PoW, that every transaction parses
 * in-bounds, that the first transaction has n_in == 1, and that the merkle
 * root of the collected txids matches the header. Several of the remaining
 * checks do exist in this codebase but on other paths (bitcoin_sigops.asm,
 * the tx_verify block-connect path); they are simply not inside the function
 * being timed here. A "faster CheckBlock" claim would therefore be measuring
 * a smaller function, which is exactly the kind of comparison this suite
 * exists to refuse.
 *
 * MEASUREMENT: CLOCK_THREAD_CPUTIME_ID, min over N rounds, spread printed.
 * Core's nanobench reports a per-epoch min in its -output-csv, which is the
 * column scripts/bench_vs_core.sh reads, so both sides are compared min-to-min.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern int  cons_verify(const void* block, long len, void* scratch, unsigned cap_slots);

/* cons_verify returns with r13 clobbered -- its own frame is correct (it saves
 * only rbx, at rbp-8, and starts locals at rbp-0x10), so the damage comes from
 * something it calls. It is therefore invoked through tests/bench_abi_guard.S,
 * which restores the callee-saved set afterwards. Without the guard this
 * harness reported "tx walk covered 0 of 1557 txs": the clobber landed on a
 * pointer GCC was holding across the correctness-gate call, so the walk that
 * ran AFTER it started from garbage. That is exactly the failure mode this
 * guard exists to keep out of the numbers. The six push/pop pairs it costs are
 * ~1e-5 of a 380 us call. Reported, not fixed here -- see BENCHMARKS.md and
 * tests/bench_abi_audit.c. */
extern long bench_call_guarded(void* fn, const unsigned long args[6]);

static int cons_verify_guarded(const void* block, long len, void* scratch, unsigned cap_slots){
    unsigned long args[6] = { (unsigned long)block, (unsigned long)len,
                              (unsigned long)scratch, (unsigned long)cap_slots, 0, 0 };
    return (int)bench_call_guarded((void*)cons_verify, args);
}
extern int  tx_parse(void* info, const unsigned char* tx, unsigned long txlen);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);

/* tx_parse writes a 64-byte txinfo record (bitcoin_tx.asm's header documents
 * the layout: +0 u64 tx_len, +8 u32 version, +12 u32 n_in, +16 u32 n_out...).
 * It returns 1/0, NOT the length -- the length is read back from info+0. */
#define TXINFO_BYTES 64
#define SCRATCH_SLOTS (1u << 16)   /* 65,536 txid slots -- block 413567 has 1,557 */

static double cpu_s(void){
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}
static int cmpd(const void* a, const void* b){
    double x = *(const double*)a, y = *(const double*)b;
    return (x > y) - (x < y);
}

/* Read a compact-size (varint) at *p, advancing it. Returns the value, or
 * (unsigned long)-1 if it would run past `end`. */
static unsigned long read_varint(const unsigned char** p, const unsigned char* end){
    if (*p >= end) return (unsigned long)-1;
    unsigned char c = *(*p)++;
    if (c < 0xfd) return c;
    int n = (c == 0xfd) ? 2 : (c == 0xfe) ? 4 : 8;
    if (*p + n > end) return (unsigned long)-1;
    unsigned long v = 0;
    for (int i = 0; i < n; i++) v |= (unsigned long)(*p)[i] << (8*i);
    *p += n;
    return v;
}

int main(int argc, char** argv){
    if (argc < 2){
        fprintf(stderr, "usage: %s <block413567.raw> [rounds]\n", argv[0]);
        fprintf(stderr, "  Core ships it at src/bench/data/block413567.raw\n");
        return 2;
    }
    const char* path = argv[1];
    int rounds = (argc > 2) ? atoi(argv[2]) : 15;
    if (rounds < 3) rounds = 3;

    FILE* f = fopen(path, "rb");
    if (!f){ perror(path); return 1; }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* blk = malloc((size_t)len);
    if (!blk || fread(blk, 1, (size_t)len, f) != (size_t)len){ printf("read failed\n"); return 1; }
    fclose(f);

    unsigned char* scratch = malloc((size_t)SCRATCH_SLOTS * 32);
    if (!scratch){ printf("alloc failed\n"); return 1; }

    /* Correctness gate. cons_verify must ACCEPT this block; timing a reject
     * path would be measuring an early exit. Also count the transactions and
     * check the count against Core's own assertion (block.vtx.size() == 1557)
     * so a wrong or truncated file is caught rather than silently benchmarked. */
    const unsigned char* p = blk + 80;
    unsigned long ntx = read_varint(&p, blk + len);
    if (ntx != 1557){
        printf("FAIL: %s has %lu transactions, Core's checkblock.cpp asserts 1557 "
               "-- wrong or truncated file\n", path, ntx);
        return 1;
    }
    if (cons_verify_guarded(blk, len, scratch, SCRATCH_SLOTS) != 1){
        printf("FAIL: cons_verify rejected %s -- refusing to time the reject path\n", path);
        return 1;
    }

    printf("== block 413,567: %ld bytes, %lu transactions (Core's checkblock.cpp fixture) ==\n",
           len, ntx);
    printf("   CPU time (CLOCK_THREAD_CPUTIME_ID), min-of-%d rounds\n", rounds);

    double* t = malloc((size_t)rounds * sizeof(double));
    if (!t) return 1;

    /* Row 1: transaction walk only (tx_parse over every tx). */
    unsigned char info[TXINFO_BYTES];
    for (int r = 0; r < rounds; r++){
        double a = cpu_s();
        const unsigned char* q = blk + 80;
        unsigned long n = read_varint(&q, blk + len);
        unsigned long seen = 0;
        for (unsigned long i = 0; i < n; i++){
            if (tx_parse(info, q, (unsigned long)(blk + len - q)) != 1) break;
            unsigned long tl;
            memcpy(&tl, info, sizeof tl);           /* txinfo +0 = tx_len */
            if (tl == 0) break;
            q += tl; seen++;
        }
        t[r] = cpu_s() - a;
        if (seen != ntx){ printf("FAIL: tx walk covered %lu of %lu txs\n", seen, ntx); return 1; }
    }
    qsort(t, (size_t)rounds, sizeof(double), cmpd);
    printf("tx walk (tx_parse x%lu)   min %9.2f us   med %9.2f   max %9.2f   "
           "-> %6.2f ns/tx   [Core: DeserializeBlockTest -- NOT like-for-like, Core builds objects]\n",
           ntx, t[0]*1e6, t[rounds/2]*1e6, t[rounds-1]*1e6, t[0]*1e9/(double)ntx);

    /* Row 2: cons_verify (PoW + tx walk + txid collection + merkle root). */
    for (int r = 0; r < rounds; r++){
        double a = cpu_s();
        int ok = cons_verify_guarded(blk, len, scratch, SCRATCH_SLOTS);
        t[r] = cpu_s() - a;
        if (ok != 1){ printf("FAIL: cons_verify rejected on round %d\n", r); return 1; }
    }
    qsort(t, (size_t)rounds, sizeof(double), cmpd);
    printf("cons_verify              min %9.2f us   med %9.2f   max %9.2f   "
           "-> %6.2f ns/tx   [Core: CheckBlockTest -- Core does MORE, see header]\n",
           t[0]*1e6, t[rounds/2]*1e6, t[rounds-1]*1e6, t[0]*1e9/(double)ntx);

    free(t); free(scratch); free(blk);
    return 0;
}
