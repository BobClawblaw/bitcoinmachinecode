/* tests/test_hdr_contextual.c -- VAL-5: ContextualCheckBlockHeader's non-PoW
 * rules, the half 141c786 deliberately left open.
 *
 * 141c786 made the boot header fetch PoW-gate every header before hst_append,
 * and VAL-11 added the nBits range checks. But Core also enforces a timestamp
 * FLOOR (the parent's median time past), a timestamp CEILING (2 hours ahead
 * of now), and MINIMUM BLOCK VERSIONS at BIP34/BIP66/BIP65 activation. None
 * of those existed, here or in reorg_analyze -- 141c786's own message says so,
 * because wiring the floor needed the parent's 11-header window, which did not
 * exist until val_mtp landed with VAL-4.
 *
 * Core, validation.cpp:
 *   block.GetBlockTime() <= pindexPrev->GetMedianTimePast()  -> "time-too-old"
 *   block.Time() > now + MAX_FUTURE_BLOCK_TIME (7200)        -> "time-too-new"
 *   nVersion < 2 && height >= BIP34Height                    -> "bad-version"
 *   nVersion < 3 && BIP66 active                             -> "bad-version"
 *   nVersion < 4 && BIP65 active                             -> "bad-version"
 *
 * EVERY RULE IS PINNED IN BOTH DIRECTIONS, and the accepts matter more than
 * the rejects here. A timestamp floor that used < instead of <= would accept
 * a header Core rejects; one that rejected at MTP+1 would reject most of the
 * chain. The boundaries are therefore checked one second either side, and the
 * version rules are checked at the version that is exactly sufficient as well
 * as the one that is one too low.
 *
 * The rules are header-only (daemon/hdrrules.h) so both the boot fetch and
 * the reorg path share one definition; this test includes that header and
 * links nothing, so it cannot drift from what the daemon runs.
 *
 * Usage: ./test_hdr_contextual
 */
#include <stdio.h>
#include <string.h>
#include "../daemon/hdrrules.h"

static int fails = 0, checks = 0;
static void ck(const char* w, int c){
    checks++;
    if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; }
}

/* build an 80-byte header with a chosen nVersion and nTime */
static void mk(unsigned char* h, unsigned int ver, unsigned int ntime){
    memset(h, 0, 80);
    memcpy(h, &ver, 4);
    memcpy(h + 68, &ntime, 4);
}

#define BIP34_H 227931L
#define F_NONE  0ULL
#define F_DERSIG (1ULL << HDR_SFC_BIT_DERSIG)
#define F_CLTV   (1ULL << HDR_SFC_BIT_CLTV)

int main(void){
    unsigned char h[80];
    const char* why;

    /* ---- timestamp FLOOR: strictly greater than the parent's MTP -------- */
    mk(h, 4, 1000000);
    ck("a timestamp one second above the parent MTP is accepted",
        hdr_contextual_ok(500000, h, 999999, 0, F_NONE, BIP34_H, &why));
    mk(h, 4, 1000000);
    why = "?";
    ck("a timestamp EQUAL to the parent MTP is time-too-old (Core uses <=)",
       !hdr_contextual_ok(500000, h, 1000000, 0, F_NONE, BIP34_H, &why) &&
       !strcmp(why, "time-too-old"));
    mk(h, 4, 999999);
    why = "?";
    ck("a timestamp below the parent MTP is time-too-old",
       !hdr_contextual_ok(500000, h, 1000000, 0, F_NONE, BIP34_H, &why) &&
       !strcmp(why, "time-too-old"));
    mk(h, 4, 5);
    ck("prev_mtp 0 disables the floor (genesis / unreadable window)",
        hdr_contextual_ok(500000, h, 0, 0, F_NONE, BIP34_H, &why));

    /* ---- timestamp CEILING: now + 2 hours ------------------------------- */
    mk(h, 4, 1000000 + 7200);
    ck("exactly now+7200 is accepted (Core rejects only ABOVE it)",
        hdr_contextual_ok(500000, h, 0, 1000000, F_NONE, BIP34_H, &why));
    mk(h, 4, 1000000 + 7201);
    why = "?";
    ck("now+7201 is time-too-new",
       !hdr_contextual_ok(500000, h, 0, 1000000, F_NONE, BIP34_H, &why) &&
       !strcmp(why, "time-too-new"));
    mk(h, 4, 4000000000u);
    ck("now 0 disables the ceiling (historical replay)",
        hdr_contextual_ok(500000, h, 0, 0, F_NONE, BIP34_H, &why));

    /* ---- BIP34: nVersion >= 2 at/after its height ----------------------- */
    mk(h, 1, 1000);
    ck("nVersion 1 is fine BELOW the BIP34 height",
        hdr_contextual_ok(BIP34_H - 1, h, 0, 0, F_NONE, BIP34_H, &why));
    mk(h, 1, 1000);
    why = "?";
    ck("nVersion 1 AT the BIP34 height is bad-version",
       !hdr_contextual_ok(BIP34_H, h, 0, 0, F_NONE, BIP34_H, &why) &&
       !strcmp(why, "bad-version"));
    mk(h, 2, 1000);
    ck("nVersion 2 at the BIP34 height is sufficient",
        hdr_contextual_ok(BIP34_H, h, 0, 0, F_NONE, BIP34_H, &why));

    /* ---- BIP66 / BIP65 keyed on the generated flag bits ----------------- */
    mk(h, 2, 1000);
    ck("nVersion 2 is fine while BIP66 is inactive",
        hdr_contextual_ok(400000, h, 0, 0, F_NONE, BIP34_H, &why));
    mk(h, 2, 1000);
    why = "?";
    ck("nVersion 2 with BIP66 active is bad-version",
       !hdr_contextual_ok(400000, h, 0, 0, F_DERSIG, BIP34_H, &why) &&
       !strcmp(why, "bad-version"));
    mk(h, 3, 1000);
    ck("nVersion 3 satisfies BIP66",
        hdr_contextual_ok(400000, h, 0, 0, F_DERSIG, BIP34_H, &why));
    mk(h, 3, 1000);
    why = "?";
    ck("nVersion 3 with BIP65 active is bad-version",
       !hdr_contextual_ok(400000, h, 0, 0, F_DERSIG|F_CLTV, BIP34_H, &why) &&
       !strcmp(why, "bad-version"));
    mk(h, 4, 1000);
    ck("nVersion 4 satisfies all three",
        hdr_contextual_ok(400000, h, 0, 0, F_DERSIG|F_CLTV, BIP34_H, &why));

    /* ---- a real mainnet-shaped header passes everything ------------------ */
    mk(h, 0x20000000u, 1700000000u);
    ck("a modern header (version 0x20000000) passes every rule",
        hdr_contextual_ok(800000, h, 1699999000u, 1700000000L,
                          F_DERSIG|F_CLTV, BIP34_H, &why));

    /* ---- CON-5 (audit 2026-10-23): nVersion is a SIGNED int32 ---------- */
    mk(h, 0x80000000u, 1000000);
    why = "?";
    ck("CON-5 nVersion 0x80000000 (negative) is bad-version once BIP34 is active",
       !hdr_contextual_ok(500000, h, 0, 0, F_NONE, BIP34_H, &why) && !strcmp(why, "bad-version"));
    mk(h, 0xffffffffu, 1000000);
    why = "?";
    ck("CON-5 nVersion 0xffffffff (-1) is bad-version under BIP65",
       !hdr_contextual_ok(500000, h, 0, 0, F_DERSIG | F_CLTV, BIP34_H, &why) && !strcmp(why, "bad-version"));
    mk(h, 0x7fffffffu, 1000000);
    ck("CON-5 nVersion 0x7fffffff (the largest positive) is accepted",
        hdr_contextual_ok(500000, h, 0, 0, F_DERSIG | F_CLTV, BIP34_H, &why));
    mk(h, 0x20000000u, 1000000);
    ck("CON-5 a BIP9 nVersion 0x20000000 is accepted",
        hdr_contextual_ok(500000, h, 0, 0, F_DERSIG | F_CLTV, BIP34_H, &why));
    mk(h, 0x80000000u, 1000000);
    ck("CON-5 a negative nVersion is still fine before BIP34 (Core: no floor yet)",
        hdr_contextual_ok(1000, h, 0, 0, F_NONE, BIP34_H, &why));

    /* ---- CON-8: BIP94 time-timewarp-attack (testnet4) ------------------- */
    {
        unsigned char ph[80];
        mk(ph, 4, 1000000);
        mk(h, 4, 1000000 - 601);
        why = "?";
        ck("CON-8 a retarget header 601 s before its parent is time-timewarp-attack under BIP94",
           !hdr_timewarp_ok(2016 * 40, h, ph, 1, &why) && !strcmp(why, "time-timewarp-attack"));
        mk(h, 4, 1000000 - 600);
        ck("CON-8 exactly 600 s before is accepted (Core: < prev - MAX_TIMEWARP)",
            hdr_timewarp_ok(2016 * 40, h, ph, 1, &why));
        mk(h, 4, 1000000 - 601);
        ck("CON-8 the same header off a retarget boundary is accepted",
            hdr_timewarp_ok(2016 * 40 + 1, h, ph, 1, &why));
        ck("CON-8 ...and on the boundary without BIP94 (mainnet) is accepted",
            hdr_timewarp_ok(2016 * 40, h, ph, 0, &why));
        mk(ph, 4, 400);
        mk(h, 4, 1);
        why = "?";
        ck("CON-8 times compare as int64: parent 400, header 1 is accepted (1 >= -200)",
            hdr_timewarp_ok(2016, h, ph, 1, &why));
    }

    printf("\n%s (%d checks, %d failures)\n",
           fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
