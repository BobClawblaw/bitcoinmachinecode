/* L4: ContextualCheckBlockHeader's time and version floors as bmc applies
 * them. Real code: asm/daemon/hdrrules.h hdr_contextual_ok (static inline,
 * copied verbatim into gen/). Reference: Core v31.1 validation.cpp
 * ContextualCheckBlockHeader:
 *   block.GetBlockTime() <= pindexPrev->GetMedianTimePast()   time-too-old
 *   block.Time() > NodeClock::now() + MAX_FUTURE_BLOCK_TIME   time-too-new
 *   nVersion < 2 && BIP34 active / < 3 && BIP66 / < 4 && BIP65  bad-version
 * with nVersion an int32_t (primitives/block.h) and nTime a uint32_t.
 *
 * "now": Core compares a whole-second block time with a sub-second clock.
 * For T, N integers and 0 <= f < 1, T > N + f + 7200 <=> T > N + 7200, so
 * bmc's integer `now` (time(NULL), the floor of the clock) gives the same
 * answer; the harness models Core with the floored clock on that basis.
 * Deployment activity is Core's DeploymentActiveAfter(pindexPrev, ...):
 * bmc passes script_flags_for_block(height) bits and the BIP34 height; the
 * harness takes the three activity booleans as free inputs and gives bmc the
 * encoding it expects (that the flags table equals Core's activation
 * heights is not verified here).
 *
 * Sentinels: prev_mtp == 0 and now == 0 disable the floor / ceiling in bmc
 * (documented: callers refuse rather than pass 0 on the live paths). The
 * equivalence is claimed for prev_mtp >= 1 and now >= 1.
 *
 * UNBOUNDED (no loops): all 2^32 versions and times, all MTPs, all clocks. */
#include <stdint.h>
#include <string.h>
#include "../lib/nondet.h"

#include "gen/hdrrules.h"

int main(void){
    unsigned char hdr[80];
    for (int i = 0; i < 80; i++) hdr[i] = nondet_u8();
    unsigned long prev_mtp = nondet_u32();           /* an MTP is a median of u32 times */
    long now = nondet_long();
    ASSUME(prev_mtp >= 1);
    ASSUME(now >= 1 && now <= (1L << 62));
    long height = nondet_long(), bip34_h = nondet_long();
    ASSUME(height >= 0 && height <= 0x7fffffffL && bip34_h >= 0 && bip34_h <= 0x7fffffffL);
    int a66 = nondet_int(), a65 = nondet_int();
    ASSUME((a66 == 0 || a66 == 1) && (a65 == 0 || a65 == 1));
    unsigned long long flags = nondet_u64();
    flags &= ~((1ULL << HDR_SFC_BIT_DERSIG) | (1ULL << HDR_SFC_BIT_CLTV));
    flags |= ((unsigned long long)a66 << HDR_SFC_BIT_DERSIG) | ((unsigned long long)a65 << HDR_SFC_BIT_CLTV);

    const char* why = 0;
    int b = hdr_contextual_ok(height, hdr, prev_mtp, now, flags, bip34_h, &why);

    int32_t nVersion; uint32_t nTime;
    memcpy(&nVersion, hdr, 4); memcpy(&nTime, hdr + 68, 4);
    int a34 = height >= bip34_h;
    int c = 1;
    if ((int64_t)nTime <= (int64_t)prev_mtp) c = 0;                         /* time-too-old */
    else if ((int64_t)nTime > (int64_t)now + 7200) c = 0;                   /* time-too-new */
    else if ((nVersion < 2 && a34) || (nVersion < 3 && a66) || (nVersion < 4 && a65)) c = 0;
    CHECK(b == c, "HDR: hdr_contextual_ok == Core's time-too-old / time-too-new / bad-version");
#ifdef REACH
    CHECK(!(c == 0 && nVersion < 0 && (int64_t)nTime > (int64_t)prev_mtp && (int64_t)nTime <= now + 7200),
          "REACH: a negative-version header rejected only by the version rule (must FAIL)");
    CHECK(!(c == 1), "REACH: an accepted header (must FAIL)");
#endif
    return 0;
}
