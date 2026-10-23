/* P6: BIP94 timewarp rule. bmc hdr_timewarp_ok (asm/daemon/hdrrules.h,
 * static inline, included as is via -DHDRRULES_H) == Core v31.1
 * validation.cpp ContextualCheckBlockHeader:
 *   if (consensusParams.enforce_BIP94 &&
 *       nHeight % DifficultyAdjustmentInterval() == 0 &&
 *       block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP)
 *       -> time-timewarp-attack
 * with nHeight = pindexPrev->nHeight + 1 (int, >= 1), GetBlockTime() the
 * uint32 nTime widened to int64, MAX_TIMEWARP = 600, interval 2016.
 * UNBOUNDED (no loops): every height Core can hold, all times, both flag
 * values. */
#include <stdint.h>
#include <string.h>
#include HDRRULES_H
unsigned char nondet_uchar(void); long nondet_long(void); int nondet_int(void);
int main(void){
    unsigned char hdr[80], prev[80];
    for (int i = 0; i < 80; i++){ hdr[i] = nondet_uchar(); prev[i] = nondet_uchar(); }
    long height = nondet_long();
    __CPROVER_assume(height >= 1 && height <= 0x7fffffffL);
    int bip94 = nondet_int(); __CPROVER_assume(bip94 == 0 || bip94 == 1);
    const char* why = 0;
    int b = hdr_timewarp_ok(height, hdr, prev, bip94, &why);
    uint32_t t, pt; memcpy(&t, hdr + 68, 4); memcpy(&pt, prev + 68, 4);
    int nHeight = (int)height;
    int c = !(bip94 && nHeight % 2016 == 0 && (int64_t)t < (int64_t)pt - 600);
    __CPROVER_assert(b == c, "P6 hdr_timewarp_ok == Core BIP94 timewarp rule");
#ifdef REACH
    __CPROVER_assert(c, "REACH: a timewarp rejection (must FAIL)");
    __CPROVER_assert(!(c && bip94 && nHeight % 2016 == 0 && (int64_t)t == (int64_t)pt - 600), "REACH: exactly at the 600 s bound accepted (must FAIL)");
#endif
    return 0;
}
