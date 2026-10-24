#!/usr/bin/env bash
# Cut the product code the locks harnesses verify into locks/gen/ (verbatim).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
wt=$(cd "$here/../../.." && pwd)
x="python3 $here/../lib/extract.py"
ul=$wt/asm/daemon/utxo_live.c
mkdir -p "$here/gen"
$x "$ul" func val_mtp                                               > "$here/gen/l1_mtp.inc"
$x "$ul" typedef val_txinfo_t                                       > "$here/gen/l_txinfo.inc"
$x "$ul" func val_is_final_tx                                       > "$here/gen/l2_isfinal_tx.inc"
$x "$ul" block 'long long min_height = -1, min_time = -1;'          > "$here/gen/l3_bip68.inc"
cp "$wt/asm/daemon/seqlocks.h" "$here/gen/seqlocks.h"
cp "$wt/asm/daemon/hdrrules.h" "$here/gen/hdrrules.h"
