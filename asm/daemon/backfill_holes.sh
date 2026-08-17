#!/usr/bin/env bash
# backfill_holes.sh -- drive ONE unified_ibd invocation over the whole
# current hole span in <data_dir>/index.dat, using ONLY our own P2P download
# path (unified_ibd.c) against real internet Bitcoin peers (no Bitcoin Core
# dependency). A single process now suffices: unified_ibd's worker chunks
# skip already-archived heights on their own (chunk_all_present), so workers
# stay busy across hole boundaries instead of the 8-way pool exiting and
# waiting on a fresh process (with its own ~20s peer re-probe) per hole.
# Re-run any time; hole_ranges.py recomputes from current state, so a
# partial/interrupted run just picks up whatever holes remain.
#
# Usage: backfill_holes.sh <data_dir> [num_workers]
set -euo pipefail

DATA_DIR="${1:?usage: backfill_holes.sh <data_dir> [num_workers]}"
NW="${2:-8}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

span="$(python3 "$HERE/hole_ranges.py" "$DATA_DIR" --span)"
if [ -z "$span" ]; then
    echo "[backfill] no holes"
else
    read -r start end <<< "$span"
    echo "[backfill] combined span [$start,$end], $NW workers"
    "$HERE/unified_ibd" "$DATA_DIR" "$NW" "$start" "$end"
fi

echo "[backfill] done; verifying:"
bash "$HERE/chainprogress.sh" "$DATA_DIR"
