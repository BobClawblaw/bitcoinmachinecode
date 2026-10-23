/* P4s: the difficulty SCHEDULE. bmc pow_expected_bits (asm/bitcoin_pow_rules.c,
 * the real file #included) == Core v31.1 pow.cpp GetNextWorkRequired, with
 * the retarget ARITHMETIC factored out: goto-instrument --replace-calls
 * pow_retarget_bits:stub_retarget makes bmc's call record its (base_bits,
 * timespan) arguments and return a marker, and the Core side calls the same
 * stub where Core calls CalculateNextWorkRequired. P4 covers the arithmetic.
 *
 * Chain flags per run (-DMODE): 1 main (no min-diff, no BIP94), 2 testnet4
 * (min-diff + BIP94), 3 signet (as main, own powLimit), 4 regtest
 * (fPowNoRetargeting + fPowAllowMinDifficultyBlocks, Core's real regtest
 * flags; bmc passes no_retarget=1, allow_min_diff=1).
 * Header oracle: a free, CONSISTENT (memoised) nTime and nBits per height.
 * For regtest the oracle's nBits are pinned to powLimit for every ancestor:
 * the inductive invariant of any regtest chain either node accepts (genesis
 * carries 0x207fffff and every accepted block must carry the expected bits,
 * which both nodes then compute as powLimit -- the R-step assertion below
 * re-proves that step).
 *
 * BOUNDED: height = 2016*B + r with B free (2016*B < 2^40) and r in
 * [0, R], R = 3, so the min-difficulty walk-back runs at most R steps. */
#include BMC_POW_RULES_C
#include "../core_port.h"

unsigned int nondet_uint(void);
long nondet_long(void);
#ifndef R
#define R 3
#endif
#define MARK 0xdeadbeefu

#if MODE == 1
#define LIMIT 0x1d00ffffu
#define NO_RT 0
#define MIN_D 0
#define B94 0
#elif MODE == 2
#define LIMIT 0x1d00ffffu
#define NO_RT 0
#define MIN_D 1
#define B94 1
#elif MODE == 3
#define LIMIT 0x1e0377aeu
#define NO_RT 0
#define MIN_D 0
#define B94 0
#else
#define LIMIT 0x207fffffu
#define NO_RT 1
#define MIN_D 1
#define B94 0
#endif

/* the retarget stub */
static int st_calls; static u32 st_base; static long st_ts;
u32 stub_retarget(u32 base_bits, long ts, u32 lim){
    __CPROVER_assert(lim == LIMIT, "retarget gets the chain powLimit");
    st_calls++; st_base = base_bits; st_ts = ts; return MARK;
}

/* header oracle */
#define OQ 8
static long oq_h[OQ]; static u32 oq_t[OQ], oq_b[OQ]; static int oq_n;
static void oracle(long h, u32* t, u32* b){
    for (int i = 0; i < OQ; i++){ if (i >= oq_n) break; if (oq_h[i] == h){ *t = oq_t[i]; *b = oq_b[i]; return; } }
    __CPROVER_assert(oq_n < OQ, "oracle table large enough");
    oq_h[oq_n] = h; oq_t[oq_n] = nondet_uint(); oq_b[oq_n] = nondet_uint();
    __CPROVER_assume(oq_b[oq_n] != MARK);
#if MODE == 4
    __CPROVER_assume(oq_b[oq_n] == LIMIT);
#endif
    *t = oq_t[oq_n]; *b = oq_b[oq_n]; oq_n++;
}
static int get_hdr(void* ctx, long h, u8 hdr[80]){
    (void)ctx; u32 t, b; oracle(h, &t, &b);
    memset(hdr, 0, 80); memcpy(hdr + 68, &t, 4); memcpy(hdr + 72, &b, 4);
    return 1;
}

/* Core: GetNextWorkRequired + CalculateNextWorkRequired's prologue */
static u32 core_gnwr(long nHeightNext, int64_t blocktime){
    const long interval = 2016; const int64_t spacing = 600;
    long last = nHeightNext - 1; u32 last_t, last_b; oracle(last, &last_t, &last_b);
    u32 nProofOfWorkLimit = LIMIT;          /* UintToArith256(powLimit).GetCompact() */
    if ((last + 1) % interval != 0){
        if (MIN_D){
            if (blocktime > (int64_t)last_t + spacing * 2) return nProofOfWorkLimit;
            long h = last; u32 b = last_b, t;
            while (h > 0 /* pprev */ && h % interval != 0 && b == nProofOfWorkLimit){
                h--; oracle(h, &t, &b);
            }
            return b;
        }
        return last_b;
    }
    long first = last - (interval - 1);
    u32 first_t, first_b; oracle(first, &first_t, &first_b);
    /* CalculateNextWorkRequired */
    if (NO_RT) return last_b;
    int64_t nActualTimespan = (int64_t)last_t - (int64_t)first_t;
    u32 base = B94 ? first_b : last_b;
    return stub_retarget(base, (long)nActualTimespan, LIMIT);
}

int main(void){
    long B = nondet_long(), r = nondet_long();
    __CPROVER_assume(B >= 0 && B < (1L << 29) && r >= 0 && r <= R);
    long height = 2016 * B + r;
    __CPROVER_assume(height >= 1);
    long blocktime = (long)nondet_uint();
    oq_n = 0; st_calls = 0;
    u32 bmc = pow_expected_bits(height, blocktime, get_hdr, 0, NO_RT, MIN_D, B94, LIMIT);
    int bc = st_calls; u32 bb = st_base; long bt = st_ts;
    st_calls = 0;
    u32 core = core_gnwr(height, (int64_t)blocktime);
    __CPROVER_assert(bmc == core, "P4s pow_expected_bits == GetNextWorkRequired (schedule)");
    __CPROVER_assert(bc == st_calls && (!bc || (bb == st_base && bt == st_ts)),
                     "P4s retarget called iff Core retargets, with Core's base bits and timespan");
#ifdef REACH
    __CPROVER_assert(!(bc == 1), "REACH: a retarget boundary (must FAIL)");
#if MIN_D
    __CPROVER_assert(!(bc == 0 && core == LIMIT && r >= 2), "REACH: min-difficulty result off-boundary (must FAIL)");
#endif
#endif
    return 0;
}
