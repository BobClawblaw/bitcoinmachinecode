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

echo "== the daemon's helpers (run 27: built without them) =="
# The daemon execs its index builders from its own directory and, without them,
# runs on and never builds those indexes. Run 27's harness built only the daemon
# and bmc_cli: its log said "builder ... not executable", then "missing beside
# the daemon" every five minutes, and nothing read either line.
mkdir -p "$T/bin"
for h in bmc_build_tx_index bmc_merge_index_runs; do printf '#!/bin/sh\n' > "$T/bin/$h"; chmod 755 "$T/bin/$h"; done
out=$(ibd_require_helpers "$T/bin" bmc_build_tx_index bmc_merge_index_runs); ckc "every helper present and executable -> rc 0" "$?" "0"
out=$(ibd_require_helpers "$T/bin" bmc_build_tx_index bmc_build_txospender_index bmc_merge_index_runs); ckc "one helper absent -> rc 1" "$?" "1"
ck "...and the refusal names it" "$out" "FAIL missing beside the daemon: bmc_build_txospender_index"
chmod 644 "$T/bin/bmc_merge_index_runs"
out=$(ibd_require_helpers "$T/bin" bmc_build_tx_index bmc_merge_index_runs); ckc "a helper at mode 644 counts as missing" "$?" "1"
out=$(ibd_require_helpers "$T/bin"); ckc "NO names (an empty print-runtime-helpers) is refused, not a pass" "$?" "1"
# the list itself comes from the Makefile, so the harness and the build cannot drift
rh=$(make -s --no-print-directory -C ../asm print-runtime-helpers 2>/dev/null)
case " $rh " in *" bmc_build_tx_index "*" bmc_merge_index_runs"*) ck "make print-runtime-helpers names the builders and the merger" "yes" "yes";;
                *) ck "make print-runtime-helpers names the builders and the merger" "$rh" "... bmc_build_tx_index ... bmc_merge_index_runs";; esac
printf '2026-09-18 19:10:00.000 [boot] config: datadir=/x\n' > "$T/helpers.log"
printf 'a NUL \000 here\n' >> "$T/helpers.log"
ibd_missing_helper "$T/helpers.log" >/dev/null; ckc "a log with no missing-helper line -> rc 1" "$?" "1"
ck "...and prints nothing" "$(ibd_missing_helper "$T/helpers.log")" ""
# run 27's two lines, verbatim, each on its own (after the NUL: grep -a matters)
L1='2026-09-18 19:17:11.522 [txindex] trail: builder /mnt/nvme8tb/bench/run27/src/asm/daemon/bmc_build_tx_index not executable -- the index cannot be built'
L2='2026-09-18 19:22:32.163 [trail] txindex: the txindex index needs a run and its builder is missing beside the daemon | txospender: not checked yet | addr_hist: not checked yet'
cp "$T/helpers.log" "$T/h1.log"; printf '%s\n' "$L1" >> "$T/h1.log"
out=$(ibd_missing_helper "$T/h1.log"); ckc "run 27's \"builder ... not executable\" line -> rc 0" "$?" "0"
ck "...and it is the line printed" "$out" "$L1"
cp "$T/helpers.log" "$T/h2.log"; printf '%s\n' "$L2" >> "$T/h2.log"
ibd_missing_helper "$T/h2.log" >/dev/null; ckc "run 27's \"missing beside the daemon\" status line alone -> rc 0" "$?" "0"
cp "$T/helpers.log" "$T/h3.log"; printf '2026-09-18 20:00:00.000 [txindex] trail: merger /x/bmc_merge_index_runs not executable\n' >> "$T/h3.log"
ibd_missing_helper "$T/h3.log" >/dev/null; ckc "the merger's line -> rc 0" "$?" "0"
cp "$T/helpers.log" "$T/h4.log"; printf '2026-09-18 20:00:00.000 [coinstats] repair: builder /x/bmc_build_coinstats_hist not executable -- cannot rebuild the history base\n' >> "$T/h4.log"
ibd_missing_helper "$T/h4.log" >/dev/null; ckc "the coinstats repair's line -> rc 0" "$?" "0"
cp "$T/helpers.log" "$T/h5.log"; printf '2026-09-18 20:00:00.000 [trail] txindex: idle, runs to 200000 | txospender: not configured | addr_hist: not configured\n' >> "$T/h5.log"
ibd_missing_helper "$T/h5.log" >/dev/null; ckc "a healthy [trail] status line is not a hit" "$?" "1"
# and the benchmark harness actually uses all three (static: running it would start a node)
ck "fresh_ibd_run.sh builds the runtime set (make runtime), not just the daemon" \
   "$(grep -c 'make -j8 runtime' ./fresh_ibd_run.sh)" "1"
ck "...refuses to launch without every helper" \
   "$(grep -c 'ibd_require_helpers src/asm/daemon' ./fresh_ibd_run.sh)" "1"
ck "...and fails on the daemon's own missing-helper line, early and on every tick" \
   "$(grep -c 'ibd_missing_helper' ./fresh_ibd_run.sh)" "2"

echo "== core-bench readers =="
J='{"blocks":740351,"headers":966753,"verificationprogress":0.5257,"chain":"main"}'
ck "a present field is read"            "$(bench_json_field "$J" blocks)" "740351"
ck "a float field is read verbatim"     "$(bench_json_field "$J" verificationprogress)" "0.5257"
# The defect this replaces: `|| echo 0` reported 0 for an absent field and for a
# dead RPC alike, so a stopped daemon looked like a node at height zero.
bench_json_field "$J" nosuchfield >/dev/null 2>&1; ckc "an ABSENT field is rc 1, not 0" "$?" "1"
ck  "...and prints nothing"             "$(bench_json_field "$J" nosuchfield 2>/dev/null)" ""
bench_json_field "" blocks >/dev/null 2>&1;         ckc "empty input (dead RPC) is rc 1" "$?" "1"
bench_json_field "not json" blocks >/dev/null 2>&1; ckc "unparseable input is rc 1" "$?" "1"
bench_json_field "[1,2]" blocks >/dev/null 2>&1;    ckc "a JSON array is rc 1, not a field read" "$?" "1"

echo "== core-bench tip test =="
bench_tip_reached 966752 966753 1.0;   ckc "at the tip with vbf 1.0 -> rc 0" "$?" "0"
bench_tip_reached 740351 966753 0.52;  ckc "mid-sync -> rc 1" "$?" "1"
bench_tip_reached 966752 966753 0.98;  ckc "height reached but vbf low -> rc 1" "$?" "1"
# The trap: ${theirs:-99999999} made a dead oracle mean "never at the tip", so a
# finished run waited forever and said nothing. Unreadable must be its own answer.
bench_tip_reached 966752 "" 1.0;       ckc "an unreadable ORACLE height is rc 2 (cannot tell)" "$?" "2"
bench_tip_reached "" 966753 1.0;       ckc "an unreadable OUR height is rc 2" "$?" "2"
bench_tip_reached 966752 966753 "";    ckc "an unreadable vbf is rc 2" "$?" "2"
bench_tip_reached 966752 966753 "abc"; ckc "a non-numeric vbf is rc 2" "$?" "2"

echo "== daemon log location and throughput =="
ck "the running log is <datadir>/<chain>/debug.log, not console.log" \
   "$(ibd_daemon_log /x/data)" "/x/data/main/debug.log"
ck "a non-default chain is honoured" "$(ibd_daemon_log /x/data signet)" "/x/data/signet/debug.log"
printf '2026-09-12 11:50:00.000 [dl] recv avg 10.8MB/s over 8 legs\n' >> "$T/debug.log"
ck "throughput reads the last avg line"        "$(ibd_throughput "$T/debug.log")" "avg 10.8MB/s"
# The sweep's defect: this string never appears in console.log at all.
ck "throughput from console.log is empty -- the sweep measured nothing" \
   "$(ibd_throughput "$T/console.log")" ""

echo "== every runnable harness carries its exec bit =="
# The fourth recurrence in one day: a bench runner rewritten to mode 644 so a
# queue announced a launch that never happened; a build artifact at 644 that
# read as 34 unrelated gate failures; and this very file, stripped by the script
# that wrote it.
#
# THE ROOT CAUSE, found 2026-09-13: this repo sets core.fileMode=false, so git
# IGNORES exec bits. `chmod +x` is invisible to git and never reaches a commit,
# and every fresh clone gets 644 again. This check found 15 harnesses in that
# state, fresh_ibd_run.sh and download_worker_sweep.sh among them. The fix is
# `git update-index --chmod=+x <file>`, which writes 100755 into the index
# whatever core.fileMode says -- chmod alone will not do it here.
missing=""
# lib/ is SOURCED, never run, so its exec bit is irrelevant -- only files a
# caller invokes directly are checked.
for f in ./*.sh; do
    [ -f "$f" ] || continue
    head -1 "$f" | grep -q '^#!' || continue      # only files meant to be run
    [ -x "$f" ] || missing="$missing $f"
done
ck "no #!-carrying harness is left non-executable" "$missing" ""

echo "== gettxoutsetinfo always names its hash type =="
# 2026-09-13: core_bench_attach.sh called `gettxoutsetinfo` with no hash type.
# Core's default is hash_serialized_3, whose response has NO "muhash" key, so
# the capstone read an empty value three times and failed a run whose UTXO set
# was in fact identical to the oracle's. Any caller that goes on to read
# r['muhash'] must ask for muhash.
# Only INVOCATIONS count: a ph/echo line that merely mentions the call by name
# is not a call. Match lines where it follows a CLI variable.
badhash=$(grep -nE '\$(CLI|ORACLE|C)[^|]*gettxoutsetinfo' \
          $(ls ./*.sh | grep -v test_ibd_harness) 2>/dev/null \
          | grep -v 'gettxoutsetinfo muhash' | grep -vc ':[[:space:]]*#' || true)
ck "every gettxoutsetinfo call names muhash" "$badhash" "0"

echo "== the retired sweep stays retired =="
# download_worker_sweep.sh answers a question this project should not act on
# (Core's download concurrency is fixed at 8) and cost an outage proving it.
# If someone revives it, this fails and they get the header instead of a LAN
# incident.
# CHECKED STATICALLY, NOT BY RUNNING IT. Verifying "it refuses to run" by
# running it means that the instant the guard is missing, the test STARTS THE
# SWEEP -- which is precisely what happened on 2026-09-14 while testing this
# very check, spawning daemons that had to be killed by hand. A test for a
# dangerous script must never invoke it.
ck "download_worker_sweep.sh still carries its refusal guard" \
   "$(grep -c 'SWEEP_I_HAVE_READ_THE_HEADER' ./download_worker_sweep.sh)" "2"
ck "...and the RETIRED banner is still in its header" \
   "$(grep -c 'RETIRED 2026-09-14. DO NOT RUN' ./download_worker_sweep.sh)" "1"
ck "...and its config still writes a maxconnections cap" \
   "$(grep -c 'maxconnections=\$MAXCONN' ./download_worker_sweep.sh)" "1"

echo "== every harness parses, and reads the right log =="
# A harness with a syntax error is found when someone launches a 20-hour run,
# not before. bash -n costs milliseconds.
broken=""
for f in ./*.sh; do bash -n "$f" 2>/dev/null || broken="$broken $f"; done
ck "no harness has a syntax error" "$broken" ""

# The NUL trap, enforced across the tree: any grep of a debug.log must pass -a,
# or a single NUL byte makes the file read as empty and the check silently
# passes. Three harnesses were in that state.
# This file is excluded: it DESCRIBES the pattern in prose, and a grep over the
# tree matches its own comment (the file:line prefix defeats a ^# filter).
nula=$(grep -nE "grep (-[a-zA-Z]*)?[a-zA-Z-]* *['\"]?[^|]*debug\.log" \
        $(ls ./*.sh | grep -v test_ibd_harness) 2>/dev/null \
        | grep -v 'grep -[a-zA-Z]*a' | grep -vc ':[[:space:]]*#' || true)
ck "every debug.log grep passes -a" "$nula" "0"

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ] || exit 1
echo "ALL HARNESS TESTS PASSED"
