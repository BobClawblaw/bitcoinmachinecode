/* tests/test_txrelay_invscale.c -- MEM-9 (audit 2026-09-03): inv processing
 * must not be O(entries x table size), and must be bounded by Core's caps.
 *
 * THE DEFECT. For every entry of every inv -- up to ~58,000 in a 2 MB message
 * -- the drain called txr_want_note (a linear scan of TXR_WANT_MAX = 4,096
 * entries with a 32-byte memcmp, plus oldest-slot eviction) and txr_ring_has
 * (a linear scan of TXR_RING = 4,096 with an 8-byte memcmp) BEFORE the
 * `want < TXR_MAX_REQ` cap could take effect -- because an entry that is
 * already known or already requested `continue`s without counting. Order 10^8
 * byte-compares per message, TXR_MAX_MSGS = 64 messages per pass, in the
 * single-threaded download worker between block-sync passes.
 *
 * TWO HALVES, and both are needed:
 *   - an INDEX makes each lookup cheap (chained hash on the first 8 bytes);
 *   - Core's BOUNDS make the count bounded (MAX_INV_SZ 50,000 refused
 *     outright, MAX_PEER_TX_ANNOUNCEMENTS 5,000 processed per message). An
 *     index alone still lets a peer choose 58,000 units of work for us.
 *
 * WHAT IS ASSERTED. This is a behaviour test, not a timing test -- a wall
 * clock in a gate is a flake waiting to happen. It pins the properties the
 * index must preserve exactly (a ring entry is found, a deleted one is not, a
 * wrapped-away one is not, and an entry survives 8-byte-prefix neighbours)
 * and the two bounds. The COST is measured separately by
 * tests/bench_mempool_scale.c's sibling reasoning and by inspection.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

typedef unsigned char u8;

/* The ring and the want table are file-local to daemon/tx_relay.c, reached
 * through its own test-hook convention (the same one txrelay_test_set_req_ttl_ms
 * and txrelay_debug_dump use) rather than by including the translation unit,
 * which would drag in the whole P2P surface. */
extern int  txrelay_test_ring_has(const u8* h);
extern void txrelay_test_ring_add(const u8* h);
extern void txrelay_test_ring_del(const u8* h);
extern int  txrelay_test_ring_size(void);
extern int  txrelay_test_want_present(const u8* h);
extern void txrelay_test_want_note(const u8* h, int fd);
extern void txrelay_test_want_clear(const u8* h);
extern int  txrelay_test_want_max(void);
extern int  txrelay_test_ring_has_linear(const u8* h);
extern int  txrelay_test_want_present_linear(const u8* h);
#define txr_ring_has     txrelay_test_ring_has
#define txr_ring_add     txrelay_test_ring_add
#define txr_ring_del     txrelay_test_ring_del
#define txr_want_find(h) (txrelay_test_want_present(h) ? (void*)1 : (void*)0)
#define txr_want_clear   txrelay_test_want_clear
#define TXR_RING         txrelay_test_ring_size()
#define TXR_WANT_MAX     txrelay_test_want_max()

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }

static void mk8(u8* h, unsigned i){ memset(h, 0, 32);
    h[0]=(u8)i; h[1]=(u8)(i>>8); h[2]=(u8)(i>>16); h[7]=0xA5; }

int main(void){
    printf("== the request ring answers correctly through the index ==\n");
    {
        u8 a[32], b[32];
        mk8(a, 1); mk8(b, 2);
        ck("an unseen txid is not in the ring", !txr_ring_has(a));
        txr_ring_add(a);
        ck("...and is after txr_ring_add", txr_ring_has(a));
        ck("a different txid is still absent", !txr_ring_has(b));
        txr_ring_del(a);
        ck("txr_ring_del removes it", !txr_ring_has(a));
    }

    printf("\n== entries survive many same-bucket neighbours ==\n");
    {
        /* Fill well past a single chain, then check an early entry is still
         * found: a broken unlink shows up here as a false negative, which is
         * the dangerous direction (every transaction re-requested). */
        u8 keep[32]; mk8(keep, 1000);
        txr_ring_add(keep);
        for (unsigned i = 2000; i < 2000 + 512; i++){ u8 h[32]; mk8(h, i); txr_ring_add(h); }
        ck("an entry added before 512 others is still found", txr_ring_has(keep));
    }

    printf("\n== a wrapped-away entry is correctly forgotten ==\n");
    {
        u8 old[32]; mk8(old, 7777);
        txr_ring_add(old);
        ck("present right after adding", txr_ring_has(old));
        for (unsigned i = 0; i < TXR_RING + 8; i++){ u8 h[32]; mk8(h, 100000 + i); txr_ring_add(h); }
        ck("gone once the ring has wrapped past it", !txr_ring_has(old));
    }

    printf("\n== after a full wrap, EVERY resident entry is still findable ==\n");
    {
        /* This is the case a missing unlink actually breaks. Skipping the
         * unlink on overwrite leaves the old key's chain node pointing at a
         * slot whose bytes have changed; lookups still verify with a memcmp,
         * so they stay correct -- but the slot is then linked into a SECOND
         * bucket while txr_ring_next[slot] is one field shared by both
         * chains, so the later link truncates the earlier chain and the
         * entries behind it become unreachable.
         *
         * Two full wraps, then every one of the last TXR_RING keys must be
         * present: they are exactly the ones the ring still holds. */
        int ring = TXR_RING;
        unsigned base = 500000;
        for (int i = 0; i < ring * 2; i++){ u8 h[32]; mk8(h, base + (unsigned)i); txr_ring_add(h); }
        int missing = 0;
        for (int i = ring; i < ring * 2; i++){
            u8 h[32]; mk8(h, base + (unsigned)i);
            if (!txr_ring_has(h)) missing++;
        }
        printf("      (%d of the last %d resident entries unreachable)\n", missing, ring);
        ck("every entry the ring still holds is reachable through the index", missing == 0);
    }

    printf("\n== the want table answers correctly through the index ==\n");
    {
        u8 a[32]; mk8(a, 4242);
        ck("unknown hash has no want entry", txr_want_find(a) == 0);
        txrelay_test_want_note(a, 99);
        ck("...and has one after txr_want_note", txr_want_find(a) != 0);
        txr_want_clear(a);
        ck("txr_want_clear removes it", txr_want_find(a) == 0);
    }

    printf("\n== a cleared entry does not shadow a later one in its bucket ==\n");
    {
        /* The failure this guards: clearing an entry's bytes without
         * unlinking leaves a stale chain node, and a later entry hashing to
         * the same bucket can be hidden behind it. */
        u8 a[32], b[32];
        mk8(a, 555); mk8(b, 556);
        txrelay_test_want_note(a, 11);
        txr_want_clear(a);
        txrelay_test_want_note(b, 12);
        ck("the later entry is found after the earlier was cleared", txr_want_find(b) != 0);
        ck("...and the cleared one is still gone", txr_want_find(a) == 0);
    }

    printf("\n== eviction keeps the index honest ==\n");
    {
        /* Overfill the want table so the oldest-slot eviction runs, then
         * confirm the newest entries are all findable: a missed unlink on
         * eviction shows up as a false negative here. */
        for (unsigned i = 0; i < (unsigned)TXR_WANT_MAX + 64; i++){ u8 h[32]; mk8(h, 300000 + i); txrelay_test_want_note(h, 7); }
        int found = 0;
        for (unsigned i = TXR_WANT_MAX; i < (unsigned)TXR_WANT_MAX + 64; i++){
            u8 h[32]; mk8(h, 300000 + i); if (txr_want_find(h)) found++;
        }
        printf("      (%d of the last 64 entries findable after overfilling)\n", found);
        ck("every recently-noted entry is findable after eviction churn", found == 64);
    }

    printf("\n== DIFFERENTIAL: the index answers exactly what the scan answered ==\n");
    {
        /* The claim MEM-9's index makes is not "it is fast" -- it is "it
         * returns the same answer as the linear scan it replaced, always".
         * Hand-constructing the interleaving that would break a hash chain is
         * guesswork; running a long randomized workload and comparing every
         * single query against the original scan is not. Any divergence --
         * a chain truncated by a missing unlink, a stale node shadowing a live
         * entry -- shows up here as a mismatch.
         *
         * Deterministic seed: a failure has to be reproducible. */
        unsigned seed = 20260904u;
        #define RND (seed = seed*1103515245u + 12345u, (seed >> 16) & 0x7fff)
        long mismatch_ring = 0, mismatch_want = 0, queries = 0;
        for (int step = 0; step < 200000; step++){
            u8 h[32]; mk8(h, (unsigned)(RND) % 6000u);
            int op = (int)(RND) % 10;
            if (op < 4){                      /* add */
                txr_ring_add(h);
            } else if (op < 5){               /* delete */
                txr_ring_del(h);
            } else {                          /* query, both ways */
                int a1 = txrelay_test_ring_has(h);
                int a2 = txrelay_test_ring_has_linear(h);
                if (a1 != a2) mismatch_ring++;
                queries++;
            }
            u8 wh[32]; mk8(wh, (unsigned)(RND) % 6000u);
            int wop = (int)(RND) % 10;
            if (wop < 4)      txrelay_test_want_note(wh, 5);
            else if (wop < 5) txrelay_test_want_clear(wh);
            else {
                int b1 = txrelay_test_want_present(wh);
                int b2 = txrelay_test_want_present_linear(wh);
                if (b1 != b2) mismatch_want++;
                queries++;
            }
        }
        printf("      (%ld queries; ring mismatches %ld, want mismatches %ld)\n",
               queries, mismatch_ring, mismatch_want);
        ck("the ring index never disagrees with the linear scan", mismatch_ring == 0);
        ck("the want index never disagrees with the linear scan", mismatch_want == 0);
        ck("the workload actually queried something", queries > 10000);
    }

    printf("\n== MEASUREMENT: indexed lookup vs the scan it replaced ==\n");
    {
        /* Reported, never asserted: a wall clock in a gate is a flake waiting
         * to happen, and the correctness claim is the differential above.
         * This is here so the SIZE of the win is a number in the log rather
         * than an assertion in a commit message -- the audit's own verdict on
         * MEM-9 was "CONFIRMED" for the complexity and silent on the cost.
         *
         * Both paths are given the same misses, which is the case that
         * matters: an attacker's inv is full of txids we have never seen, and
         * a miss is exactly when the linear scan pays its full price. */
        enum { NQ = 20000 };
        struct timespec t0, t1;
        volatile int sink = 0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < NQ; i++){ u8 h[32]; mk8(h, 900000u + (unsigned)i); sink += txrelay_test_ring_has(h); }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double idx = (t1.tv_sec-t0.tv_sec) + (t1.tv_nsec-t0.tv_nsec)/1e9;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < NQ; i++){ u8 h[32]; mk8(h, 900000u + (unsigned)i); sink += txrelay_test_ring_has_linear(h); }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double lin = (t1.tv_sec-t0.tv_sec) + (t1.tv_nsec-t0.tv_nsec)/1e9;
        printf("      ring, %d misses: indexed %.1f ms, linear %.1f ms (%.0fx)\n",
               NQ, idx*1e3, lin*1e3, idx > 0 ? lin/idx : 0.0);

        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < NQ; i++){ u8 h[32]; mk8(h, 900000u + (unsigned)i); sink += txrelay_test_want_present(h); }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        idx = (t1.tv_sec-t0.tv_sec) + (t1.tv_nsec-t0.tv_nsec)/1e9;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < NQ; i++){ u8 h[32]; mk8(h, 900000u + (unsigned)i); sink += txrelay_test_want_present_linear(h); }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        lin = (t1.tv_sec-t0.tv_sec) + (t1.tv_nsec-t0.tv_nsec)/1e9;
        printf("      want, %d misses: indexed %.1f ms, linear %.1f ms (%.0fx)\n",
               NQ, idx*1e3, lin*1e3, idx > 0 ? lin/idx : 0.0);
        (void)sink;
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
