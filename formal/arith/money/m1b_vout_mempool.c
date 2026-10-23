/* M1b: the same CheckTransaction output rules on the MEMPOOL/relay parse,
 * asm/bitcoin_txval_modern.c (the per-output statements inside its tx
 * parser, cut verbatim into gen/m1b_step.inc: from `if (v > MV_MAX_MONEY)`
 * through `if (T->out_total > MV_MAX_MONEY) return 0;`). There a reject is
 * `return 0` out of the parser, which ends the walk exactly as Core's
 * `return state.Invalid(...)` does.
 *
 * UNBOUNDED by induction, relation R: !core_bad -> T->out_total == core_sum
 * in [0, MAX_MONEY]; STEP: bmc returns 0 iff Core rejects this output. The
 * BASE is `T->out_total = 0;` right before the loop (line checked by run.sh
 * with grep). */
#include <stdint.h>
#include "../lib/nondet.h"
#include "core_amount.h"

#include "gen/m1b_maxmoney.inc"
struct mv_tx { uint64_t out_total; };
static int mv_step(struct mv_tx* T, uint64_t v){
#include "gen/m1b_step.inc"
    return 1;
}

int main(void){
    struct mv_tx T;
    T.out_total = nondet_u64();
    CAmount core_sum = nondet_ll();
    ASSUME(core_sum >= 0 && core_sum <= CORE_MAX_MONEY && T.out_total == (uint64_t)core_sum);
    uint64_t wire = nondet_u64();

    int bmc_ok = mv_step(&T, wire);

    int core_bad = 0;
    CAmount nValue = (CAmount)wire;
    if (nValue < 0) core_bad = 1;
    else if (nValue > CORE_MAX_MONEY) core_bad = 1;
    else { core_sum += nValue; if (!core_MoneyRange(core_sum)) core_bad = 1; }

    CHECK(bmc_ok == !core_bad, "STEP: bmc continues iff Core continues");
    CHECK(core_bad || (T.out_total == (uint64_t)core_sum), "STEP: running totals stay equal");
#ifdef REACH
    CHECK(bmc_ok == 0, "REACH: an accepting step exists (must FAIL)");
#endif
    return 0;
}
