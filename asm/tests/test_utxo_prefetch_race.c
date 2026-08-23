/* test_utxo_prefetch_race.c -- utxo_prefetch under concurrent table churn.
 *
 * WHY THIS EXISTS
 *   utxo_prefetch (bitcoin_utxo.asm, 2026-08-23) is a pure cache hint issued
 *   by apply_block_inner's STAGE A walk, a phase before the real probes. Its
 *   contract is "no result can change". This test makes that measured rather
 *   than asserted, in both directions:
 *
 *     1. EQUIVALENCE: the same seeded put/del/get workload produces the same
 *        final table bytes and the same per-get answer stream with prefetch
 *        interleaved as without it.
 *     2. UNDER LOAD: N threads spam utxo_prefetch on random keys (present,
 *        absent, and tombstoned alike) against the SAME table while the main
 *        thread runs the workload. No crash, and the workload's answers still
 *        match the no-prefetch control. Prefetching a slot mid-write is the
 *        exact situation the daemon creates when STAGE A of the next block
 *        overlaps a compaction; a hint that could perturb bytes would corrupt
 *        the set silently.
 *
 * Usage: ./test_utxo_prefetch_race [threads] [ops]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

typedef uint8_t u8; typedef uint64_t u64;

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_put(void* u, const u8 txid[32], unsigned long index, u64 value,
                     u64 height, u64 is_coinbase, const u8* script, unsigned long slen);
extern long utxo_get(void* u, const u8 txid[32], unsigned long index, u64* value,
                     unsigned long* height, unsigned long* is_coinbase,
                     const u8** script, unsigned long* slen);
extern long utxo_del(void* u, const u8 txid[32], unsigned long index);
extern void utxo_prefetch(void* u, const u8 txid[32], unsigned long index);

#define SLOTS 4096
#define BLOB  (1u<<25)

static int NT = 8;
static long OPS = 200000;
static volatile int stop_spam = 0;

/* deterministic PRNG so both runs see the identical op stream */
static u64 rng_state;
static u64 rng(void){ rng_state ^= rng_state<<13; rng_state ^= rng_state>>7; rng_state ^= rng_state<<17; return rng_state; }
static void key_of(u64 r, u8 txid[32], unsigned long* idx){
    memset(txid, 0, 32);
    u64 k = r % 700;                       /* small keyspace -> plenty of hits, dels, re-puts */
    memcpy(txid, &k, 8); txid[31] = 0x77;
    *idx = (unsigned long)(r % 3);
}

typedef struct { void* u; unsigned long seed; } spam_arg_t;
static void* spammer(void* argv){
    spam_arg_t* a = (spam_arg_t*)argv;
    u64 s = a->seed; u8 txid[32]; unsigned long idx;
    while (!stop_spam){
        s ^= s<<13; s ^= s>>7; s ^= s<<17;
        key_of(s, txid, &idx);
        utxo_prefetch(a->u, txid, idx);
    }
    return 0;
}

/* Run the seeded workload against a fresh table. mode: 0 = plain control,
 * 1 = interleave a prefetch before every op (single-threaded equivalence),
 * 2 = concurrent spam threads (they are started by the caller).
 * Returns an order-sensitive checksum over every op's outcome. */
static u64 run_workload(void* u, int mode){
    rng_state = 0x5eed5eed5eed5eedULL;
    u64 sum = 1469598103934665603ULL;
    u8 txid[32], script[16]; unsigned long idx;
    memset(script, 0xab, sizeof script);
    for (long i = 0; i < OPS; i++){
        u64 r = rng();
        key_of(r, txid, &idx);
        if (mode == 1) utxo_prefetch(u, txid, idx);
        long rc;
        switch (r % 5){
        case 0: case 1:
            rc = utxo_put(u, txid, idx, r|1, i, 0, script, sizeof script); break;
        case 2:
            rc = utxo_del(u, txid, idx); break;
        default: {
            u64 v=0; unsigned long h=0, cb=0, sl=0; const u8* sp=0;
            rc = utxo_get(u, txid, idx, &v, &h, &cb, &sp, &sl);
            sum = (sum ^ v) * 1099511628211ULL;
            sum = (sum ^ h) * 1099511628211ULL;
            break;
        }
        }
        sum = (sum ^ (u64)rc) * 1099511628211ULL;
    }
    return sum;
}

/* Structural equality that survives different allocations: the struct header
 * embeds the blob BASE POINTER at +16 (differs per calloc), but slots hold
 * blob OFFSETS and the entry count / mask / blob fill are plain integers --
 * so compare n, mask, fill, the whole slot region, and blob CONTENT up to
 * fill (bitcoin_utxo.asm's layout comment is the contract here). */
static int tables_equal(const void* ua, const void* ba,
                        const void* ub, const void* bb, unsigned long usz){
    const u64* ha = (const u64*)ua; const u64* hb = (const u64*)ub;
    if (ha[0] != hb[0] || ha[1] != hb[1] || ha[4] != hb[4]) return 0;  /* n, mask, fill */
    if (memcmp((const u8*)ua + 40, (const u8*)ub + 40, usz - 40) != 0) return 0;
    return memcmp(ba, bb, ha[4]) == 0;                                  /* blob up to fill */
}

static int fails = 0;
static void ck(const char* what, int ok){
    printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) fails++;
}

int main(int argc, char** argv){
    if (argc > 1) NT = atoi(argv[1]);
    if (argc > 2) OPS = atol(argv[2]);

    unsigned long usz = utxo_struct_size(SLOTS);
    void *u0 = calloc(1, usz), *u1 = calloc(1, usz), *u2 = calloc(1, usz);
    void *b0 = calloc(1, BLOB), *b1 = calloc(1, BLOB), *b2 = calloc(1, BLOB);
    if (!u0||!u1||!u2||!b0||!b1||!b2){ fprintf(stderr, "oom\n"); return 1; }
    utxo_init(u0, SLOTS, b0, BLOB);
    utxo_init(u1, SLOTS, b1, BLOB);
    utxo_init(u2, SLOTS, b2, BLOB);

    u64 s0 = run_workload(u0, 0);                 /* control */
    u64 s1 = run_workload(u1, 1);                 /* interleaved prefetch */
    ck("interleaved prefetch: identical outcome stream", s0 == s1);
    ck("interleaved prefetch: identical final table state",
       tables_equal(u0, b0, u1, b1, usz));

    pthread_t th[64];
    spam_arg_t sa[64];
    if (NT > 64) NT = 64;
    for (int t = 0; t < NT; t++){ sa[t].u = u2; sa[t].seed = 0x1000 + t; pthread_create(&th[t], 0, spammer, &sa[t]); }
    u64 s2 = run_workload(u2, 2);                 /* under concurrent spam */
    stop_spam = 1;
    for (int t = 0; t < NT; t++) pthread_join(th[t], 0);
    ck("concurrent spam: identical outcome stream", s0 == s2);
    ck("concurrent spam: identical final table state",
       tables_equal(u0, b0, u2, b2, usz));

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
