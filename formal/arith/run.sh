#!/usr/bin/env bash
# Every arith proof group, one after the other (one solver at a time).
# Exits 0 only if every group's run.sh exits 0.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export LOGDIR=${LOGDIR:-$(mktemp -d)}
echo "logs: $LOGDIR"
rc=0; t0=$(date +%s)
for g in money locks pow limits scriptnum; do
    s=$(date +%s)
    echo "== $g"
    "$here/$g/run.sh" || rc=1
    echo "== $g: $(( $(date +%s) - s )) s"
done
echo "== total: $(( $(date +%s) - t0 )) s, $( [ $rc -eq 0 ] && echo ALL PASS || echo FAILURES )"
exit $rc
