/* test_utxo_hash_spread.c -- a transaction's outputs must not land in
 * neighbouring memtable slots (2026-10-10).
 *
 * utxo_hash was FNV-1a over the txid's first 8 bytes XOR the output index,
 * masked: index 0..n of one txid flips only the low bits, so the outputs sat
 * side by side and every multi-output transaction made a run of full slots.
 * Linear probing walks runs, and so does the delete's backward shift: the
 * diagnostic sync of 2026-10-10 measured 10.8 slots scanned per delete hit
 * over 575k-793k and 190 ns per delete in the memtable. The hash now
 * multiplies (txid bytes 0..7 ^ index) by an odd 64-bit constant and takes
 * the product's bits 32.. under the mask.
 *
 * Shape: 2^20 slots filled to 50% by 8,192 transactions of 64 outputs each.
 *   A. the mean length of the run of full slots holding a key, over every
 *      key: 5.08 with the fix, 328 with the old hash;
 *   B. the longest run: 40 with the fix, 1,728 with the old hash;
 *   C. every other transaction deleted (the backward shift, whose home-slot
 *      arithmetic is now inline in utxo_del), then every remaining output
 *      reads back with its value and every deleted one is absent;
 *   D. the deleted keys re-put and read back (the shift left no hole).
 *
 * Revert checks: the old utxo_hash (FNV ^ index & mask, the shift loop calling
 * it) fails A and B; the shift loop's inline home slot without its shr fails
 * C and D. 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8; typedef uint64_t u64;
extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_put(void* u, const u8 txid[32], unsigned long index, u64 value,
                     unsigned long height, unsigned long is_coinbase,
                     const u8* spk, unsigned long spklen);
extern long utxo_get(void* u, const u8 txid[32], unsigned long index, u64* value,
                     unsigned long* height, unsigned long* is_coinbase,
                     const u8** spk, unsigned long* slen);
extern long utxo_del(void* u, const u8 txid[32], unsigned long index);

#define SLOTS_LOG2 20
#define SLOTS      (1UL << SLOTS_LOG2)
#define NTX        8192
#define NOUT       64

static int fails = 0;
static void ck(const char* l, int ok, double got) {
    if (ok) printf("ok  : %-60s (got %.2f)\n", l, got);
    else { printf("FAIL: %-60s (got %.2f)\n", l, got); fails++; }
}
static u64 rs = 0x2545F4914F6CDD1DULL;
static u64 rnd(void){ rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static u8 txids[NTX][32];

/* slot i's index field is at u + 40 + i*48 + 40; 0xFFFFFFFF = empty */
static int occupied(const u8* u, u64 i){ uint32_t v; memcpy(&v, u + 40 + i * 48 + 40, 4); return v != 0xFFFFFFFFu; }

int main(void) {
    u8* u = malloc((size_t)utxo_struct_size(SLOTS));
    unsigned long cap = 64UL << 20; u8* blob = malloc(cap);
    if (!u || !blob) { printf("FAIL: no memory\n"); return 1; }
    utxo_init(u, SLOTS, blob, cap);
    for (int t = 0; t < NTX; t++) for (int b = 0; b < 32; b += 8) { u64 r = rnd(); memcpy(txids[t] + b, &r, 8); }
    static const u8 spk[1] = { 0x51 };
    for (int t = 0; t < NTX; t++) for (int o = 0; o < NOUT; o++)
        if (utxo_put(u, txids[t], o, (u64)t * NOUT + o + 1, t, 0, spk, 1) < 0) { printf("FAIL: put %d/%d\n", t, o); return 1; }

    /* A/B: run lengths. A key in a run of length L contributes L; the mean
     * over keys is sum(L^2)/sum(L). Start the scan just after an empty slot so
     * no run is split by the wrap. */
    u64 start = 0; while (occupied(u, start)) start++;
    double sum_l = 0, sum_l2 = 0; u64 longest = 0, run = 0;
    for (u64 k = 1; k <= SLOTS; k++) {
        u64 i = (start + k) & (SLOTS - 1);
        if (occupied(u, i)) run++;
        else { if (run) { sum_l += run; sum_l2 += (double)run * run; if (run > longest) longest = run; } run = 0; }
    }
    double mean_run = sum_l2 / sum_l;
    printf("      %0.f keys in %llu slots: mean run holding a key %.2f, longest %llu\n", sum_l, (unsigned long long)SLOTS, mean_run, (unsigned long long)longest);
    ck("A. mean run holding a key under 12 (old hash: 328)", mean_run < 12.0, mean_run);
    ck("B. longest run under 128 (old hash: 1,728)", longest < 128, (double)longest);

    /* C: delete every other transaction, then read everything */
    long bad = 0;
    for (int t = 0; t < NTX; t += 2) for (int o = 0; o < NOUT; o++)
        if (utxo_del(u, txids[t], o) != 1) bad++;
    ck("C. every delete of an even transaction's output hits", bad == 0, (double)bad);
    bad = 0;
    for (int t = 0; t < NTX; t++) for (int o = 0; o < NOUT; o++) {
        u64 v = 0; unsigned long h = 0, cb = 0, sl = 0; const u8* s = 0;
        long r = utxo_get(u, txids[t], o, &v, &h, &cb, &s, &sl);
        if (t & 1) { if (r != 1 || v != (u64)t * NOUT + o + 1 || h != (unsigned long)t) bad++; }
        else if (r != 0) bad++;
    }
    ck("C. odd transactions read back, even ones are absent", bad == 0, (double)bad);

    /* D: re-put the deleted keys and read everything back */
    for (int t = 0; t < NTX; t += 2) for (int o = 0; o < NOUT; o++)
        if (utxo_put(u, txids[t], o, (u64)t * NOUT + o + 1, t, 0, spk, 1) < 0) { printf("FAIL: re-put %d/%d\n", t, o); return 1; }
    bad = 0;
    for (int t = 0; t < NTX; t++) for (int o = 0; o < NOUT; o++) {
        u64 v = 0; unsigned long h = 0, cb = 0, sl = 0; const u8* s = 0;
        if (utxo_get(u, txids[t], o, &v, &h, &cb, &s, &sl) != 1 || v != (u64)t * NOUT + o + 1) bad++;
    }
    ck("D. after re-putting the deleted half, every key reads back", bad == 0, (double)bad);

    printf("%s\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED (0 failures)");
    return fails ? 1 : 0;
}
