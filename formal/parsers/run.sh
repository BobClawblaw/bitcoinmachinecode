#!/usr/bin/env bash
# formal/parsers/run.sh -- every CBMC proof, vacuity (cover) run and mutation
# for the untrusted-input parsers. Exits 0 only if every proof passes, every
# cover goal is reached and every mutant is caught.
#   ./run.sh            all
#   ./run.sh <regex>    only the entries whose name matches <regex> (bash =~)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
FORMAL_TOOLS="${FORMAL_TOOLS:-$HOME/.local/opt/formal}"
CBMC="$FORMAL_TOOLS/cbmc/usr/bin/cbmc"
export LD_LIBRARY_PATH="$FORMAL_TOOLS/cbmc/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
LOG="$HERE/logs"; mkdir -p "$LOG"
FILTER="${1:-}"
TIMEOUT="${FP_TIMEOUT:-1800}"       # seconds per CBMC run
CHECKS="--bounds-check --pointer-check --signed-overflow-check --unsigned-overflow-check \
--pointer-overflow-check --conversion-check --div-by-zero-check --memory-leak-check \
--float-overflow-check --nan-check --unwinding-assertions --object-bits 12"
A="$ROOT/asm"; D="$ROOT/asm/daemon"
fails=0; t_all=$(date +%s)

# memory cap + nice: the box is shared (FORMAL_RULES "Resources", and the
# 2026-10-23 rule after an uncapped run caused a global OOM): every CBMC run
# goes through systemd-run with an 8 GB cap and no swap, one at a time, and
# only while at least 25 GB is available. Without systemd-run, nothing runs.
MEMCAP="${FP_MEMCAP:-8G}"
avail_gb(){ free -g | awk '/^Mem:/{print $7}'; }
cap(){
  local tries=0
  while [ "$(avail_gb)" -lt 25 ]; do
    tries=$((tries+1)); [ $tries -gt 60 ] && { echo "run.sh: under 25 GB available for 30 min, giving up" >&2; return 99; }
    sleep 30
  done
  while pgrep -x cbmc >/dev/null; do sleep 5; done        # one CBMC process at a time

  flock "$LOG/.cbmc.lock" systemd-run --user --scope -q -p MemoryMax="$MEMCAP" -p MemorySwapMax=0 -- nice -n15 timeout "$TIMEOUT" "$@"
}
systemd-run --user --scope -q -p MemoryMax=64M -p MemorySwapMax=0 -- true || { echo "run.sh: systemd-run --user --scope is required" >&2; exit 2; }

# per-entry check set: "@nouov" drops --unsigned-overflow-check (defined
# wrap-around in C; the harness then asserts the consequences explicitly),
# "@noconv" drops --conversion-check where the code narrows on purpose; each
# such entry says why in proofs.sh
chk(){ local a="$1" c="$CHECKS"
  [[ "$a" == *"@nouov"* ]] && c="${c/--unsigned-overflow-check/}"
  [[ "$a" == *"@noconv"* ]] && c="${c/--conversion-check/}"
  echo "$c"; }
cleanargs(){ local a="${1//@nouov/}"; a="${a//@relwaive/}"; echo "${a//@noconv/}"; }
# "@relwaive": the code bounds-checks by forming a pointer past its object
# (`p + 36 > end`), undefined by the letter of C11 6.5.6p8 though never
# dereferenced; CBMC's --pointer-check reports each such relation. With this
# token an entry passes when every failed property is one of those relations
# (they are listed, counted, in the README) and nothing else failed.
verified(){ local log="$1" args="$2"
  grep -q "^VERIFICATION SUCCESSFUL" "$log" && return 0
  [[ "$args" == *"@relwaive"* ]] || return 1
  grep -q "^VERIFICATION FAILED" "$log" || return 1
  ! grep "FAILURE$" "$log" | grep -Ev "pointer (relation|arithmetic): pointer outside object bounds in p \+" | grep -q . ; }

want(){ [ -z "$FILTER" ] || [[ "$1" =~ $FILTER ]]; }

# proof NAME HARNESS SRC "CBMC ARGS"   -- must verify, and every cover goal must be hit
proof(){
  local name="$1" h="$HERE/harness/$2" src="$3" args="$4"
  want "$name" || return 0
  local t0=$(date +%s)
  cap "$CBMC" "$h" -I"$HERE/harness" -I"$(dirname "$src")" -DSRC="\"$src\"" $(chk "$args") $(cleanargs "$args") > "$LOG/$name.log" 2>&1
  local ok=0; verified "$LOG/$name.log" "$args" && ok=1
  local t1=$(date +%s)
  cap "$CBMC" "$h" -I"$HERE/harness" -I"$(dirname "$src")" -DSRC="\"$src\"" -DFP_COVER --cover cover --object-bits 12 $(cleanargs "$args") > "$LOG/$name.cover.log" 2>&1
  local cov; cov=$(grep -o '\*\* [0-9]* of [0-9]* covered' "$LOG/$name.cover.log" | tail -1)
  local covok=0; [[ "$cov" =~ \*\*\ ([0-9]+)\ of\ ([0-9]+)\ covered ]] && [ "${BASH_REMATCH[1]}" = "${BASH_REMATCH[2]}" ] && [ "${BASH_REMATCH[2]}" != 0 ] && covok=1
  local t2=$(date +%s)
  if [ $ok = 1 ] && [ $covok = 1 ]; then printf 'PASS   %-28s proof %4ss  cover %4ss  (%s)\n' "$name" $((t1-t0)) $((t2-t1)) "${cov#\*\* }"
  else printf 'FAIL   %-28s proof=%s cover=%s (%s)  see logs/%s.log\n' "$name" $ok $covok "$cov" "$name"; fails=$((fails+1)); fi
}

# proofm NAME HARNESS SRC "SED EXPR" "CBMC ARGS" -- a proof over a scratch copy
#   with a stated MODEL change (e.g. a limit lowered so its check is reachable
#   in bound); must verify and reach every cover goal
proofm(){
  local name="$1" h="$2" src="$3" sedx="$4" args="$5"
  want "$name" || return 0
  local tmp; tmp="$(mktemp -d)"; local m="$tmp/$(basename "$src")"
  sed -e "$sedx" "$src" > "$m"
  if cmp -s "$src" "$m"; then printf 'FAIL   %-28s the model change did not apply\n' "$name"; fails=$((fails+1)); rm -rf "$tmp"; return; fi
  # proof() takes the -I of the ORIGINAL dir so the copy's quoted includes resolve
  proof "$name" "$h" "$m" "-I$(dirname "$src") $args"
  rm -rf "$tmp"
}

# mutant NAME HARNESS SRC "SED EXPR" "EXPECTED PROPERTY TEXT" "CBMC ARGS"
#   applies SED EXPR to a scratch copy of SRC; CBMC must then report
#   VERIFICATION FAILED with a failing property whose line contains the text
mutant(){
  local name="$1" h="$HERE/harness/$2" src="$3" sedx="$4" expect="$5" args="$6"
  want "$name" || return 0
  local tmp; tmp="$(mktemp -d)"; local m="$tmp/$(basename "$src")"
  sed -e "$sedx" "$src" > "$m"
  if cmp -s "$src" "$m"; then printf 'FAIL   %-28s the mutation did not apply\n' "$name"; fails=$((fails+1)); rm -rf "$tmp"; return; fi
  local t0=$(date +%s)
  cap "$CBMC" "$h" -I"$HERE/harness" -I"$(dirname "$src")" -DSRC="\"$m\"" $(chk "$args") $(cleanargs "$args") > "$LOG/$name.log" 2>&1
  local t1=$(date +%s)
  if grep -q "^VERIFICATION FAILED" "$LOG/$name.log" && grep -F -- "$expect" "$LOG/$name.log" | grep "FAILURE" | grep -Evq "pointer (relation|arithmetic): pointer outside object bounds in p \+"; then
    printf 'CAUGHT %-28s %4ss  (%s)\n' "$name" $((t1-t0)) "$expect"
  else printf 'MISSED %-28s mutant not caught  see logs/%s.log\n' "$name" "$name"; fails=$((fails+1)); fi
  rm -rf "$tmp"
}

# mutanth NAME HARNESS SRC HDR "SED EXPR" "EXPECTED" "CBMC ARGS" -- as mutant,
#   for a header HDR the harness includes as <basename> ahead of SRC: the
#   mutated copy is put first on the include path
mutanth(){
  local name="$1" h="$HERE/harness/$2" src="$3" hdr="$4" sedx="$5" expect="$6" args="$7"
  want "$name" || return 0
  local tmp; tmp="$(mktemp -d)"; local m="$tmp/$(basename "$hdr")"
  sed -e "$sedx" "$hdr" > "$m"
  if cmp -s "$hdr" "$m"; then printf 'FAIL   %-28s the mutation did not apply\n' "$name"; fails=$((fails+1)); rm -rf "$tmp"; return; fi
  local t0=$(date +%s)
  cap "$CBMC" "$h" -I"$tmp" -I"$HERE/harness" -I"$(dirname "$src")" -DSRC="\"$src\"" $(chk "$args") $(cleanargs "$args") > "$LOG/$name.log" 2>&1
  local t1=$(date +%s)
  if grep -q "^VERIFICATION FAILED" "$LOG/$name.log" && grep -F -- "$expect" "$LOG/$name.log" | grep "FAILURE" | grep -Evq "pointer (relation|arithmetic): pointer outside object bounds in p \+"; then
    printf 'CAUGHT %-28s %4ss  (%s)\n' "$name" $((t1-t0)) "$expect"
  else printf 'MISSED %-28s mutant not caught  see logs/%s.log\n' "$name" "$name"; fails=$((fails+1)); fi
  rm -rf "$tmp"
}

# diverge NAME HARNESS SRC "EXPECTED PROPERTY TEXT" "CBMC ARGS"
#   the harness's FP_CORE_STRICT assertions (Core's rule) on the UNMODIFIED
#   source: CBMC must report the named property FAILED. Each such entry is a
#   finding confirmed on the compiled code by confirm/ (see README); the entry
#   fails the run if the code ever starts to satisfy Core's rule (then the
#   finding is fixed and the entry should become a proof).
diverge(){
  local name="$1" h="$HERE/harness/$2" src="$3" expect="$4" args="$5"
  want "$name" || return 0
  local t0=$(date +%s)
  cap "$CBMC" "$h" -I"$HERE/harness" -I"$(dirname "$src")" -DSRC="\"$src\"" -DFP_CORE_STRICT $(chk "$args") $(cleanargs "$args") --trace > "$LOG/$name.log" 2>&1
  local t1=$(date +%s)
  if grep -q "^VERIFICATION FAILED" "$LOG/$name.log" && grep -F -- "$expect" "$LOG/$name.log" | grep -q "FAILURE"; then
    printf 'FOUND  %-28s %4ss  (%s)\n' "$name" $((t1-t0)) "$expect"
  else printf 'GONE   %-28s the divergence no longer reproduces  see logs/%s.log\n' "$name" "$name"; fails=$((fails+1)); fi
}

. "$HERE/proofs.sh"

echo "total: $(( $(date +%s) - t_all ))s, failures: $fails"
[ $fails = 0 ]
