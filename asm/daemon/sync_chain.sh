#!/usr/bin/env bash
# sync_chain.sh -- fill every archive hole, then immediately extend to the
# REAL chain tip, keeping NW workers continuously busy across both phases
# instead of leaving a gap where a finished job has to be noticed and
# relaunched by hand.
#
# No external oracle needed for "how far is the real tip": unified_ibd's own
# header phase (node_ibd_headers) already tracks the true chain length in
# headers.dat via our own P2P code. Passing a sentinel end_h far beyond any
# real height auto-clamps to that true tip, and once phase 1 leaves zero
# holes, unified_ibd's own resume logic sets start_h = current_tip+1
# automatically -- so phase 2 is just "download everything we don't have".
#
# Usage: sync_chain.sh <data_dir> [num_workers]
set -euo pipefail

DATA_DIR="${1:?usage: sync_chain.sh <data_dir> [num_workers]}"
NW="${2:-8}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL=999999999

echo "[sync] phase 1: backfill holes"
"$HERE/backfill_holes.sh" "$DATA_DIR" "$NW"

echo "[sync] phase 2: extend to real tip"
"$HERE/unified_ibd" "$DATA_DIR" "$NW" 0 "$SENTINEL"

echo "[sync] done; verifying:"
bash "$HERE/chainprogress.sh" "$DATA_DIR"
