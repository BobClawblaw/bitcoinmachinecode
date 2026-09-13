#!/bin/bash
# test_ibd_harness.sh -- tests for the IBD benchmark harness's own readers.
#
# The node has had tests since the beginning. The harness that MEASURES it had
# none, and on 2026-09-12 that cost a full day: five harness defects, zero node
# defects, and a UTXO "corruption" that was a torn read. Two of the five did not
# fail loudly -- they reported success. This file exists so the next one fails
# here, in two seconds, instead of twenty hours into a run.
#
# The fixture is deliberately hostile in the ways the real log is: it carries a
# NUL byte (grep calls such a file binary and prints NOTHING without -a, counts
# included), the heartbeat tag is [dlc] rather than [dl], and it contains
# [reorg] lines that LOOK like failures and are not.
set -u
cd "$(dirname "$0")" || exit 2
. lib/ibd_harness_lib.sh

pass=0; fail=0
ck(){ if [ "$2" = "$3" ]; then echo "ok  : $1"; pass=$((pass+1));
      else echo "FAIL: $1"; echo "      want: [$3]"; echo "      got : [$2]"; fail=$((fail+1)); fi; }
ckc(){ if [ "$2" = "$3" ]; then echo "ok  : $1"; pass=$((pass+1));
       else echo "FAIL: $1 (want rc=$3 got rc=$2)"; fail=$((fail+1)); fi; }

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

# --- the fixture: a debug.log shaped like the real one -----------------------
printf '2026-09-11 16:53:02.676 [boot] logging to /x/data/main/debug.log\n' >  "$T/debug.log"
printf '2026-09-12 11:50:13.184 [dlc] == elapsed 18:55:13 | eta 00:00:00:52 | applied=966160 lag=0 ==\n' >> "$T/debug.log"
# a NUL byte, exactly as the real log carries. Without grep -a everything below
# this line is invisible and every reader returns empty.
printf 'some line with a NUL \000 in it\n' >> "$T/debug.log"
printf '2026-09-12 11:50:25.487 [dlc] == elapsed 18:55:25 | eta 00:00:00:00 | applied=966241 lag=287 ==\n' >> "$T/debug.log"
printf '2026-09-12 11:51:00.000 [dl] pool idle 7%%\n' >> "$T/debug.log"
printf '2026-09-12 11:52:00.000 [reorg] candidate REJECTED: lower work\n' >> "$T/debug.log"
printf '2026-09-12 11:52:01.000 [reorg] probe of 000000abc failed\n' >> "$T/debug.log"

# console.log as the daemon actually writes it: the banner, and nothing else.
printf '===== bmcbitcoind  LOG START: 2026-09-11 16:53:02 UTC\n=====   pid 1155550\n' > "$T/console.log"

echo "== readers =="
hb=$(ibd_heartbeat "$T/debug.log")
ck "heartbeat reads the LAST [dlc] elapsed line" \
   "$hb" "elapsed 18:55:25 | eta 00:00:00:00 | applied=966241 lag=287"

# The regression that cost three runs: reading console.log yields nothing at all.
ck "heartbeat from console.log is empty -- that file holds only the banner" \
   "$(ibd_heartbeat "$T/console.log")" ""

# The NUL-byte trap, pinned: the heartbeat above sits AFTER the NUL, so a reader
# without grep -a returns empty and this test is what catches its removal.
ck "a NUL byte earlier in the log does not hide later lines" \
   "$(ibd_heartbeat "$T/debug.log" | grep -c 'applied=966241')" "1"

ck "occupancy reads the pool idle share" "$(ibd_occupancy "$T/debug.log")" "pool idle 7%"

echo "== bad markers =="
ck "a clean log counts zero" "$(ibd_bad_markers "$T/debug.log")" "0"
printf '2026-09-12 11:53:00.000 [utxo] FATAL: store inconsistent\n' >> "$T/debug.log"
ck "a FATAL line is counted" "$(ibd_bad_markers "$T/debug.log")" "1"
ck "the bad-marker check on console.log finds nothing -- the defect that made it useless" \
   "$(ibd_bad_markers "$T/console.log")" "0"

echo "== capstone verdict =="
A=$(printf 'a%.0s' $(seq 1 64)); B=$(printf 'b%.0s' $(seq 1 64))
out=$(ibd_capstone_verdict "$A" "$A" 966496 966496); ckc "identical hashes at one height -> rc 0" "$?" "0"
ck  "...and it says PASS with the height" "$out" "PASS 966496"

out=$(ibd_capstone_verdict "$A" "$B" 966496 966496); ckc "different hashes -> rc 1" "$?" "1"

# The one that mattered most: empty == empty was read as agreement for months.
out=$(ibd_capstone_verdict "" "" 966496 966496); ckc "EMPTY vs EMPTY is a FAIL, not a pass" "$?" "1"
case "$out" in FAIL*no\ usable\ hash*) ck "...and it names the empty side" "yes" "yes";;
               *) ck "...and it names the empty side" "$out" "FAIL ... no usable hash";; esac

out=$(ibd_capstone_verdict "" "$A" 966496 966496); ckc "our side empty -> FAIL" "$?" "1"
out=$(ibd_capstone_verdict "$A" "" 966496 966496); ckc "oracle side empty -> FAIL" "$?" "1"
out=$(ibd_capstone_verdict "abc" "$A" 966496 966496); ckc "a short hash is refused, not compared" "$?" "1"
out=$(ibd_capstone_verdict "$A" "zz$(printf 'a%.0s' $(seq 1 62))" 966496 966496); ckc "a non-hex hash is refused" "$?" "1"

# Run 22's actual failure: same set, two different heights.
out=$(ibd_capstone_verdict "$A" "$A" 966496 966494); ckc "same hash at DIFFERENT heights -> FAIL" "$?" "1"
case "$out" in *"heights differ"*) ck "...and it says the heights differ" "yes" "yes";;
                *) ck "...and it says the heights differ" "$out" "FAIL heights differ";; esac

out=$(ibd_capstone_verdict "$A" "$A" "" 966496); ckc "a missing height is refused" "$?" "1"

echo "== launch guard =="
printf '#!/bin/bash\ntrue\n' > "$T/runner.sh"; chmod 644 "$T/runner.sh"
out=$(ibd_require_exec "$T/runner.sh"); ckc "mode 644 is refused before launch" "$?" "1"
chmod 755 "$T/runner.sh"
out=$(ibd_require_exec "$T/runner.sh"); ckc "mode 755 passes" "$?" "0"
out=$(ibd_require_exec "$T/nope.sh");   ckc "a missing program is refused" "$?" "1"

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ] || exit 1
echo "ALL HARNESS TESTS PASSED"
