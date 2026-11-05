#!/usr/bin/env bash
# Money proofs (rule group 1). Exits 0 only if every proof holds, every
# REACH witness is found and every mutant is caught.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/../lib/runlib.sh"
"$here/gen.sh" || { echo "FAIL money gen"; exit 1; }
SC='--unwind 5 --unwindset strcmp.0:48 --unwinding-assertions'

cbmc_prove  M1  "$here" m1_vout_block.c
cbmc_reach  M1  "$here" m1_vout_block.c
cbmc_mutant M1a "$here" m1_vout_block.c gen/m1_on_output.inc 's/if \(value > VAL_MAX_MONEY\) c->money_bad = 1;/if (0) c->money_bad = 1;/'
cbmc_mutant M1b "$here" m1_vout_block.c gen/m1_on_output.inc 's/if \(c->tx_out_sum > VAL_MAX_MONEY\)/if (0)/'

cbmc_prove  M1m "$here" m1b_vout_mempool.c
cbmc_reach  M1m "$here" m1b_vout_mempool.c
cbmc_mutant M1m "$here" m1b_vout_mempool.c gen/m1b_step.inc 's/if \(T->out_total > MV_MAX_MONEY\) return 0;/;/'

for I in 210000 150; do
    cbmc_prove  M3-$I "$here" m3_subsidy.c -DINTERVAL=$I
    cbmc_reach  M3-$I "$here" m3_subsidy.c -DINTERVAL=$I
done
cbmc_mutant M3 "$here" m3_subsidy.c gen/m3_subsidy.inc 's/halvings >= 64/halvings >= 32/' -DINTERVAL=210000

for I in 210000 150; do
    cbmc_prove  M2-$I "$here" m2_ledger.c -DINTERVAL=$I $SC
done
cbmc_reach  M2 "$here" m2_ledger.c -DINTERVAL=210000 -DNTX=3 -DKIN=2 $SC
cbmc_mutant M2a "$here" m2_ledger.c gen/m2_ledger.inc 's/if \(in_t < out_t\)/if (in_t <= out_t)/' -DINTERVAL=210000 -DNTX=2 -DKIN=2 $SC
cbmc_mutant M2b "$here" m2_ledger.c gen/m2_ledger.inc 's/if \(ptx_out\[0\] > cap\)/if (ptx_out[0] > cap + 1)/' -DINTERVAL=210000 -DNTX=2 -DKIN=2 $SC
cbmc_mutant M2c "$here" m2_ledger.c gen/m2_ledger.inc 's/if \(fees > VAL_MAX_MONEY\)/if (0)/' -DINTERVAL=210000 -DNTX=3 -DKIN=2 $SC

z3_run M2-IND "$here/m2_ledger_induction.py"

# M4: the modelled lines must still be the product's
a=$here/../../../asm
grep -qE '^ +sub +rax, r8 +; - \(long\)uheight' "$a/bitcoin_txv_classify.asm" &&
grep -qE '^ +cmp +rax, COINBASE_MATURITY$' "$a/bitcoin_txv_classify.asm" &&
grep -qE '^ +jge +\.not_cb$' "$a/bitcoin_txv_classify.asm" &&
grep -qE '^%define COINBASE_MATURITY 100$' "$a/bitcoin_txv_classify.asm" &&
grep -qF 'long conf = height - (long)uheight;' "$a/daemon/tx_verify.c" &&
grep -qF 'if (conf < COINBASE_MATURITY)' "$a/daemon/tx_verify.c" ||
    { echo "FAIL  M4  modelled maturity lines changed"; FAILS=$((FAILS+1)); }
z3_run M4 "$here/m4_maturity.py"
echo "money: $FAILS failure(s)"
exit $((FAILS > 0))
