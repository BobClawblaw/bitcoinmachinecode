#!/usr/bin/env bash
# Time and lock proofs (rule group 3). Exits 0 only if every proof holds,
# every REACH witness is found and every mutant is caught.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/../lib/runlib.sh"
"$here/gen.sh" || { echo "FAIL locks gen"; exit 1; }
grep -q '#define VAL_SFC_BIT_CSV 10' "$here/../../../asm/daemon/utxo_live.c" || { echo "FAIL VAL_SFC_BIT_CSV moved"; exit 1; }
U12='--unwind 12 --unwinding-assertions --sat-solver cadical'
U9='--unwind 9 --unwinding-assertions --sat-solver cadical'

for W in 1 2 3 4 5 6 7 8; do cbmc_prove L1-w$W "$here" l1_mtp.c -DWIN=$W $U12; done
for W in 9 10 11;           do cbmc_prove L1-w$W "$here" l1_mtp.c -DWIN=$W -DRANKS $U12; done
cbmc_reach  L1 "$here" l1_mtp.c -DRANKS $U12
cbmc_mutant L1 "$here" l1_mtp.c gen/l1_mtp.inc 's/\*out = ts\[n \/ 2\];/*out = ts[(n - 1) \/ 2];/' -DWIN=4 $U12

cbmc_prove  L2 "$here" l2_isfinal.c
cbmc_reach  L2 "$here" l2_isfinal.c
cbmc_mutant L2 "$here" l2_isfinal.c gen/seqlocks.h 's/if \(\(long long\)locktime < cutoff\)/if ((long long)locktime <= cutoff)/'

cbmc_prove  L3 "$here" l3_bip68.c $U9
cbmc_reach  L3 "$here" l3_bip68.c -DNTX=2 $U9
cbmc_mutant L3a "$here" l3_bip68.c gen/l3_bip68.inc 's/int enforce = \(vib.version >= 2\);/int enforce = ((int)vib.version >= 2);/' -DNTX=2 $U9
cbmc_mutant L3b "$here" l3_bip68.c gen/seqlocks.h 's/<< VAL_SEQ_GRANULARITY\) - 1;/<< VAL_SEQ_GRANULARITY);/' -DNTX=2 $U9
cbmc_mutant L3c "$here" l3_bip68.c gen/seqlocks.h 's/if \(min_height >= \(long long\)height\) return 0;/if (min_height > (long long)height) return 0;/' -DNTX=2 $U9

cbmc_prove  L4 "$here" l4_hdrtime.c
cbmc_reach  L4 "$here" l4_hdrtime.c
cbmc_mutant L4a "$here" l4_hdrtime.c gen/hdrrules.h 's/    int32_t ver; unsigned int ntime;/    uint32_t ver; unsigned int ntime;/'
cbmc_mutant L4b "$here" l4_hdrtime.c gen/hdrrules.h 's/ntime <= prev_mtp\)/ntime < prev_mtp)/'
cbmc_mutant L4c "$here" l4_hdrtime.c gen/hdrrules.h 's/> now \+ HDR_MAX_FUTURE_BLOCK_TIME\)/> now + HDR_MAX_FUTURE_BLOCK_TIME + 1)/'
echo "locks: $FAILS failure(s)"
exit $((FAILS > 0))
