# Shared by the run.sh scripts: each check is one line of output and one
# PASS/FAIL. A proof must report VERIFICATION SUCCESSFUL (CBMC) or "proved"
# (z3 scripts print that); a REACH or MUTANT run must report a failure, or
# the harness is treated as unable to fail and the run fails.
FORMAL_TOOLS=${FORMAL_TOOLS:-$HOME/.local/opt/formal}
CBMC=$FORMAL_TOOLS/cbmc/usr/bin/cbmc
PY=$FORMAL_TOOLS/venv/bin/python
export LD_LIBRARY_PATH=$FORMAL_TOOLS/cbmc/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
FAILS=0
LOGDIR=${LOGDIR:-$(mktemp -d)}

_lim(){ # every solver/build: memory-capped scope, no swap, niced (no fallback)
    systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 "$@"
}
_t0(){ date +%s.%N; }
_dt(){ echo "$(date +%s.%N) - $1" | bc | awk '{printf "%.2fs", $1}'; }

# cbmc_prove ID DIR HARNESS [cbmc flags...]  -> must be VERIFICATION SUCCESSFUL
cbmc_prove(){
    local id=$1 dir=$2 h=$3; shift 3
    local log=$LOGDIR/$id.prove.log t=$(_t0)
    ( cd "$dir" && _lim timeout 1800 "$CBMC" "$h" "$@" ) >"$log" 2>&1
    if grep -q '^VERIFICATION SUCCESSFUL' "$log"; then
        echo "PASS  $id  proof  $(_dt $t)  ($(grep -o '[0-9]* of [0-9]* failed' "$log" | tail -1))"
    else
        echo "FAIL  $id  proof  $(_dt $t)  see $log"; grep -E 'FAILURE|error' "$log" | head -5; FAILS=$((FAILS+1))
    fi
}
# cbmc_reach ID DIR HARNESS [flags]  -> compiled with -DREACH, must FAIL
cbmc_reach(){
    local id=$1 dir=$2 h=$3; shift 3
    local log=$LOGDIR/$id.reach.log t=$(_t0)
    ( cd "$dir" && _lim timeout 1800 "$CBMC" -DREACH "$h" "$@" ) >"$log" 2>&1
    if grep -q '^VERIFICATION FAILED' "$log" && ! grep -q 'REACH.*SUCCESS' "$log"; then
        echo "PASS  $id  reach  $(_dt $t)  (every REACH witness found: assumptions satisfiable)"
    else
        echo "FAIL  $id  reach  $(_dt $t)  a REACH assertion held: vacuous?  see $log"; FAILS=$((FAILS+1))
    fi
}
# cbmc_mutant ID DIR HARNESS FILE SED [flags]: copy DIR (and lib) to a
# scratch tree, apply SED to FILE (a gen/ cut of product code, or a model),
# require the SED to change the file, and require CBMC to FAIL.
cbmc_mutant(){
    local id=$1 dir=$2 h=$3 f=$4 sedx=$5; shift 5
    local log=$LOGDIR/$id.mutant.log t=$(_t0) tmp; tmp=$(mktemp -d)
    cp -r "$dir" "$tmp/sub"; cp -r "$dir/../lib" "$tmp/lib"
    cp "$tmp/sub/$f" "$tmp/orig"; sed -i -E "$sedx" "$tmp/sub/$f"
    if cmp -s "$tmp/orig" "$tmp/sub/$f"; then
        echo "FAIL  $id  mutant  sed did not change $f"; FAILS=$((FAILS+1)); rm -rf "$tmp"; return
    fi
    ( cd "$tmp/sub" && _lim timeout 1800 "$CBMC" "$h" "$@" ) >"$log" 2>&1
    if grep -q '^VERIFICATION FAILED' "$log"; then
        echo "PASS  $id  mutant  $(_dt $t)  [$sedx] -> $(grep -m1 'FAILURE' "$log" | sed 's/^ *//')"
    else
        echo "FAIL  $id  mutant  $(_dt $t)  mutation [$sedx] NOT detected  see $log"; FAILS=$((FAILS+1))
    fi
    rm -rf "$tmp"
}
# z3_run ID SCRIPT [args] -> the script prints lines "PROVED <name>" /
# "MUTANT-CAUGHT <name>" / "SAT-OK <name>" and exits 0 only if all hold.
z3_run(){
    local id=$1 s=$2; shift 2
    local log=$LOGDIR/$id.z3.log t=$(_t0)
    _lim timeout 1800 "$PY" "$s" "$@" >"$log" 2>&1; local rc=$?
    if [ $rc -eq 0 ]; then
        echo "PASS  $id  z3  $(_dt $t)  ($(grep -c -E '^(PROVED|MUTANT-CAUGHT|SAT-OK)' "$log") checks)"
    else
        echo "FAIL  $id  z3  $(_dt $t)  rc=$rc see $log"; tail -5 "$log"; FAILS=$((FAILS+1))
    fi
}
