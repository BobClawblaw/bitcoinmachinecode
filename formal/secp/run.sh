#!/bin/bash
# formal/secp/run.sh -- build, prove, differential-test and mutation-test the
# secp256k1 field/scalar arithmetic. Exits 0 only if every proof is PROVED,
# every differential vector matches and every mutant is caught.
#   FORMAL_TOOLS   default $HOME/.local/opt/formal (z3 venv)
#   SKIP_MUTANTS=1 skip the mutation stage (it rebuilds a scratch tree per mutant)
# Every solver/build runs through ./lim: systemd-run scope, MemoryMax=8G, no swap,
# nice 15, a timeout. One solver process at a time.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
FORMAL_TOOLS=${FORMAL_TOOLS:-$HOME/.local/opt/formal}
PY=$FORMAL_TOOLS/venv/bin/python
t0=$(date +%s)
rc=0
echo "== build"; bash "$HERE/build.sh" || { echo "BUILD FAILED"; exit 1; }
echo "== proofs";  ( cd "$HERE" && "$HERE/lim" 3600 "$PY" -u run_all.py ) || rc=1
echo "== differential tests"; ( cd "$HERE" && "$HERE/lim" 1800 "$PY" -u diff.py ) || rc=1
if [ "${SKIP_MUTANTS:-0}" != 1 ]; then
    echo "== mutants"; ( cd "$HERE" && "$HERE/lim" 7200 "$PY" -u mutate.py ) || rc=1
fi
echo "== total: $(( $(date +%s) - t0 )) s, $( [ $rc -eq 0 ] && echo ALL PASS || echo FAILURES )"
exit $rc
