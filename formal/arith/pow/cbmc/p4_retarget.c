/* P4: bmc pow_retarget_bits (asm/bitcoin_pow_rules.c, the real file is
 * #included via -DBMC_POW_RULES_C) == Core v31.1 CalculateNextWorkRequired's
 * arithmetic (pow.cpp), for every int64 timespan and every base nBits that
 * is Core-valid on the chain chosen by -DCHAIN_BITS (DeriveTarget succeeds:
 * not negative, not overflowing, nonzero, <= powLimit). bmc is given the
 * compact powLimit it is configured with (chainparams pow_limit_bits); Core
 * gets its FULL consensus.powLimit (core_port.h core_pow_limit).
 *
 * Core side: core_port.h SetCompact / GetCompact (line-for-line ports,
 * cross-checked against an independent Python transcription by
 * check_core_port.py), with operator*=(uint32_t) and operator/= expressed on
 * a 256-bit CBMC bit-vector: both are exact mod-2^256 operations in Core
 * (operator*=(uint32_t) wraps; nActualTimespan converts to uint32_t for
 * that overload, the divisor to base_uint(uint64_t)), so the bit-vector
 * forms are the same functions; core_port.h's limb-loop versions of the
 * same two operators are what diff_pow and check_core_port.py exercise.
 *
 * -DMIN_BASE_LOG2=k additionally assumes the base target >= 2^k (k = 18
 * kept the new target >= 2^16, outside finding F1 before its fix); -DEXP=e fixes the
 * exponent. STATUS: OPEN -- this end-to-end harness did not close within
 * 15 min (mainnet, k = 18) nor 5 min with the exponent fixed, so run.sh does
 * not run it; P4 is covered by P2a + P3 + P4-LEM + P4-CAP and the
 * differential test (NOTES.md). Kept for anyone with a bigger time budget:
 *   cbmc p4_retarget.c -DBMC_POW_RULES_C='"<asm>/bitcoin_pow_rules.c"' \
 *        -DCHAIN_BITS=0x1d00ffffu -DMIN_BASE_LOG2=18 --unwind 41 \
 *        --unwinding-assertions --sat-solver cadical */
#include BMC_POW_RULES_C
#include "../core_port.h"

typedef unsigned __CPROVER_bitvector[256] bv256;
unsigned int nondet_uint(void);
long nondet_long(void);

static bv256 to_bv(const cu256* a){
    bv256 r = 0;
    for (int i = CP_WIDTH - 1; i >= 0; i--) r = (r << 32) | (bv256)a->pn[i];
    return r;
}
static cu256 from_bv(bv256 v){
    cu256 r;
    for (int i = 0; i < CP_WIDTH; i++){ r.pn[i] = (uint32_t)v; v >>= 32; }
    return r;
}
static uint32_t core_next(uint32_t base_bits, int64_t nActualTimespan, const cu256* bnPowLimit){
    const int64_t nPowTargetTimespan = 14 * 24 * 60 * 60;
    if (nActualTimespan < nPowTargetTimespan / 4) nActualTimespan = nPowTargetTimespan / 4;
    if (nActualTimespan > nPowTargetTimespan * 4) nActualTimespan = nPowTargetTimespan * 4;
    cu256 c = cu_set_compact(base_bits, 0, 0);
    bv256 bnNew = to_bv(&c);
    bnNew = bnNew * (bv256)(uint32_t)nActualTimespan;        /* operator*=(uint32_t), mod 2^256 */
    bnNew = bnNew / (bv256)(uint64_t)nPowTargetTimespan;     /* operator/= */
    if (bnNew > to_bv(bnPowLimit)) bnNew = to_bv(bnPowLimit);
    cu256 r = from_bv(bnNew);
    return cu_get_compact(&r, 0);
}

int main(void){
    u32 base = nondet_uint();
    long ts = nondet_long();
    int neg, ovf;
    cu256 bt = cu_set_compact(base, &neg, &ovf);
    cu256 lim = core_pow_limit(CHAIN_BITS);
    __CPROVER_assume(!neg && !ovf && !cu_iszero(&bt) && cu_cmp(&bt, &lim) <= 0);
#ifdef EXP
    __CPROVER_assume((base >> 24) == EXP);     /* one exponent per run */
#endif
#ifdef MIN_BASE_LOG2
    __CPROVER_assume(to_bv(&bt) >= ((bv256)1 << MIN_BASE_LOG2));
#endif
    u32 core = core_next(base, (int64_t)ts, &lim);
    u32 bmc  = pow_retarget_bits(base, ts, CHAIN_BITS);
    __CPROVER_assert(bmc == core, "P4 pow_retarget_bits == Core CalculateNextWorkRequired");
#ifdef REACH
    __CPROVER_assert(!(ts > 4838400 && core == CHAIN_BITS), "REACH: the powLimit cap is reached (must FAIL)");
    __CPROVER_assert(!(ts > 302400 && ts < 4838400 && core != base), "REACH: an unclamped retarget changes bits (must FAIL)");
#endif
    return 0;
}
