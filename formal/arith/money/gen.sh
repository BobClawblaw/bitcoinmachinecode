#!/usr/bin/env bash
# Cut the product code the money harnesses verify into money/gen/ (verbatim).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
wt=$(cd "$here/../../.." && pwd)
x="python3 $here/../lib/extract.py"
ul=$wt/asm/daemon/utxo_live.c
tm=$wt/asm/bitcoin_txval_modern.c
mkdir -p "$here/gen"
$x "$ul" lines '^#define VAL_MAX_MONEY ' '^#define VAL_MAX_MONEY '      > "$here/gen/m1_maxmoney.inc"
$x "$ul" typedef idxbuild_ctx_t                                     > "$here/gen/m1_ctx.inc"
$x "$ul" func idxbuild_on_output                                    > "$here/gen/m1_on_output.inc"
$x "$tm" lines '^#define MV_MAX_MONEY ' '^#define MV_MAX_MONEY '      > "$here/gen/m1b_maxmoney.inc"
$x "$tm" lines 'if \(v > MV_MAX_MONEY\) return 0;' 'if \(T->out_total > MV_MAX_MONEY\) return 0;' > "$here/gen/m1b_step.inc"
# M1b's BASE: the running total is zeroed right before the output loop
grep -q '^    T->out_total = 0;$' "$tm" || { echo "gen: M1b base line moved" >&2; exit 1; }
$x "$ul" func val_subsidy                                           > "$here/gen/m3_subsidy.inc"
$x "$ul" block 'const u64\* tx_in = txvb_last_tx_in_sums'           > "$here/gen/m2_ledger.inc"
