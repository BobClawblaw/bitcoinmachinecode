/* tests/test_serve_rejects.c -- MEM-10 (audit 2026-09-03): the shared memory
 * of transactions we have already refused.
 *
 * THE DEFECT. bitcoin_serve.asm's .inv_txann asked "do we have it" and never
 * "did we already decide no". An inbound peer could announce the txid of a
 * valid-signature, policy-rejected transaction once per second, and every
 * announcement was fetched and fully re-verified -- thousands of ECDSA and
 * Schnorr checks each, in that connection's serve child, which also takes
 * mp_lock for the policy pass. The download worker has a 60-second request
 * ring; the inbound path had nothing.
 *
 * WHAT THIS PINS. The filter's semantics, which are what make it safe to
 * consult before a fetch:
 *
 *   - it answers yes only for something actually recorded;
 *   - it is SHARED, so a refusal recorded by one serve child is visible to
 *     the next -- the whole point of putting it in a MAP_SHARED region;
 *   - a block CLEARS it, because a block can make a previously-invalid
 *     transaction valid (its missing input just confirmed) and a stale "no"
 *     would stop us ever fetching it. Core resets m_recent_rejects the same
 *     way;
 *   - it is a CACHE: a collision or a wrapped-away entry costs one extra
 *     fetch, never a wrong verdict. Nothing here decides acceptance.
 *
 * The two things it must NOT record are checked at the call sites rather than
 * here, and are worth naming: a fee-only failure (-28, reconsiderable) stays
 * re-announceable because a CPFP child can overturn it, and a missing-input
 * failure (-25) becomes valid the moment the parent arrives.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned char u8;

extern unsigned long serve_rejects_size(void);
extern void serve_rejects_attach(void* region);
extern int  serve_reject_has(const u8 txid[32]);
extern void serve_reject_note(const u8 txid[32]);
extern void serve_rejects_clear(void);
extern long long serve_rejects_generation(void);

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }

static void mk(u8 t[32], unsigned i){
    memset(t, 0x77, 32);
    t[0]=(u8)i; t[1]=(u8)(i>>8); t[2]=(u8)(i>>16); t[3]=(u8)(i>>24);
}

int main(void){
    printf("== with no region attached, every call is a safe no-op ==\n");
    {
        u8 a[32]; mk(a, 1);
        serve_reject_note(a);                 /* must not crash */
        ck("an unattached filter never claims to know anything", serve_reject_has(a) == 0);
    }

    /* Attach a region the way daemon/mempool_cfg.c does pre-fork. */
    unsigned long sz = serve_rejects_size();
    void* region = malloc(sz);
    ck("filter size is sane", sz > 1024 && sz < (4u<<20));
    serve_rejects_attach(region);

    printf("\n== a recorded refusal is remembered ==\n");
    {
        u8 a[32], b[32]; mk(a, 100); mk(b, 101);
        ck("unknown txid is not refused", serve_reject_has(a) == 0);
        serve_reject_note(a);
        ck("...and is after being noted", serve_reject_has(a) == 1);
        ck("a different txid is unaffected", serve_reject_has(b) == 0);
    }

    printf("\n== a block CLEARS it (Core resets m_recent_rejects per block) ==\n");
    {
        u8 a[32]; mk(a, 200);
        serve_reject_note(a);
        ck("noted", serve_reject_has(a) == 1);
        long long g0 = serve_rejects_generation();
        serve_rejects_clear();
        ck("a block connect forgets it", serve_reject_has(a) == 0);
        ck("...and the generation advanced", serve_rejects_generation() == g0 + 1);
    }

    printf("\n== many refusals, and the recent ones are all remembered ==\n");
    {
        /* An attacker announcing thousands of distinct junk txids is exactly
         * the load this filter exists for, so it must not degrade into
         * forgetting everything. Direct-mapped, so some of the older ones are
         * evicted by collision -- that costs an extra fetch and nothing more,
         * which is why the assertion is on the most recent entries. */
        serve_rejects_clear();
        enum { N = 4000 };
        for (unsigned i = 0; i < N; i++){ u8 t[32]; mk(t, 900000 + i); serve_reject_note(t); }
        int remembered = 0;
        for (unsigned i = N - 200; i < N; i++){ u8 t[32]; mk(t, 900000 + i); remembered += serve_reject_has(t); }
        printf("      (%d of the last 200 refusals remembered after %d entries)\n", remembered, N);
        ck("the recent refusals survive a flood of them", remembered >= 190);
    }

    printf("\n== it is a cache, so a false NEGATIVE is the only failure mode ==\n");
    {
        /* Whatever it answers for something never recorded, it must never be
         * a yes -- a false positive would silently stop us fetching a
         * transaction we have no verdict on. */
        serve_rejects_clear();
        int false_yes = 0;
        for (unsigned i = 0; i < 20000; i++){ u8 t[32]; mk(t, 5000000 + i); if (serve_reject_has(t)) false_yes++; }
        ck("nothing unrecorded is ever reported as refused", false_yes == 0);
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
