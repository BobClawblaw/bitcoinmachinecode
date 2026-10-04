#!/bin/bash
# logged_pair_run.sh -- the fully logged IBD pair: Core v31.1 rerun #6 (logged),
# then bmc run 34 (logged, Core's download shape), then the stage report.
# Plan: worklog/2026-10-04-logged-ibd-runs-plan.md (s.4 "Order", steps 3).
#
# RUN IT ONLY AFTER CORE RERUN #5 HAS ENDED (the unlogged control) and with
# the box otherwise quiet. Never concurrent with another timed run. Launch from
# a plain shell, not from an agent's background task (the harness kills a
# background task's whole tree on its memory heuristic):
#
#   cd /storage/bitcoinmachinecode
#   SRCREF=<branch with bmc.benchlog + bmc.dlshape + the [ready] line> \
#     setsid nohup validation/logged_pair_run.sh \
#       > /srv/nvme8tb/bench/logged-pair.launch.log 2>&1 < /dev/null &
#
#   DRY_RUN=1 validation/logged_pair_run.sh   # every check, no change: each
#                                             # move/copy/start/stop/launch is
#                                             # logged as "DRY would ...", waits
#                                             # are skipped
#   STEP=c ...                                # resume at a step (a..g)
#
# THE STEPS. Each one checks free space on /srv/nvme8tb first. Nothing is ever
# deleted: a datadir in the way is MOVED aside (or the step refuses), and a
# replaced watcher script is moved aside, never overwritten in place.
#   a. prepare Core: rerun #5 must be over (its watch.log has IBD_END and its
#      bitcoind is gone); move its datadir aside to core31-rerun5-<start date>;
#      a fresh core31/ with config/core-bench/bitcoin.logged.conf; install this
#      tree's watcher (core_bench_watch.sh + lib, which has the READY step)
#      into core31-watch/, the path bitcoin-core-bench-watch.service runs.
#   b. start the Core unit (sudo -n systemctl start bitcoin-core-bench.service;
#      its ExecStartPre refuses a non-empty datadir and writes BENCH_START.txt;
#      it Wants= the watcher).
#   c. wait -- reading core31/watch.log only, never RPC -- for READY_INDEXES
#      (or a FAIL line, or bitcoind gone).
#   d. stop Core (sudo -n systemctl stop ...) and wait until its bitcoind exits.
#   e. launch the bmc harness: DEST=$BENCH/$RUN BENCHLOG=1 DLSHAPE=core
#      READY_WAIT=1 fresh_ibd_run.sh, built from SRCREF. The ref is checked
#      first for the three strings the run depends on (bmc.benchlog,
#      bmc.dlshape, "all indexes at height"): the daemon IGNORES unknown keys.
#   f. wait -- reading phase.log/RESULT only -- for the harness's RESULT, note
#      its READY line, then stop the idle daemon (SIGTERM, as the rerun #5
#      launcher did for run 33).
#   g. the report: validation/ibd_stage_report.py --core-dir --bmc-dir ->
#      $BENCH/logged-pair-report-<date>.md, with rerun #5's IBD end (the
#      unlogged control) written beside it for the logging overhead.
#
# Output: $BENCH/logged-pair.log (one line per action, UTC).
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
BENCH=${BENCH:-/srv/nvme8tb/bench}
CORE_DD=$BENCH/core31
WATCHDIR=$BENCH/core31-watch
RUN=${RUN:-run34}
BMC_DEST=$BENCH/$RUN
SRCREF=${SRCREF:-}
STEP=${STEP:-a}
DRY_RUN=${DRY_RUN:-0}
CONF=$REPO/config/core-bench/bitcoin.logged.conf
LOG=${PAIRLOG:-$BENCH/logged-pair.log}
# Free-space floors, KiB. Core with the three indexes took 916 GB in rerun #4,
# plus ~1.3 GB of log here; bmc run 33 took 1.2 TB.
CORE_MIN_KB=${CORE_MIN_KB:-1181116006}   # 1.1 TiB
BMC_MIN_KB=${BMC_MIN_KB:-1503238554}     # 1.4 TiB
POLL_S=${POLL_S:-120}

w(){ echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG"; }
die(){ w "ABORT: $*"; exit 1; }
run(){ if [ "$DRY_RUN" = 1 ]; then w "DRY would run: $*"; else "$@"; fi; }
free_kb(){ df --output=avail -k "$BENCH" | tail -1 | tr -d ' '; }
need_free(){ local f; f=$(free_kb)
    w "free on $BENCH: $((f/1024/1024)) GiB (step $1 needs $(( $2/1024/1024 )) GiB)"
    [ "$f" -ge "$2" ] || die "under the floor for step $1; free space (nothing here deletes anything)"; }
pid_alive(){ [ -s "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }
# Every process whose cwd or exe sits under a directory (the datadir is the
# daemon's cwd for bmc; Core is matched by its pid file).
procs_under(){ local n=0 p c; for p in /proc/[0-9]*; do
    c=$(readlink "$p/cwd" 2>/dev/null) || continue
    case "$c" in "$1"|"$1"/*) n=$((n+1));; esac; done; echo $n; }
at_or_after(){ [[ ! "$1" < "$STEP" ]]; }
case "$STEP" in [a-g]) ;; *) echo "STEP must be one of a..g, not '$STEP'" >&2; exit 2;; esac

mkdir -p "$BENCH" 2>/dev/null
w "START logged pair (step $STEP, dry=$DRY_RUN, repo $REPO @ $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null), core $CORE_DD, bmc $BMC_DEST, SRCREF='${SRCREF}')"
[ -n "$SRCREF" ] || die "SRCREF is required: the bmc branch carrying bmc.benchlog, bmc.dlshape and the [ready] line"
git -C "$REPO" rev-parse -q --verify "$SRCREF^{commit}" >/dev/null || die "SRCREF '$SRCREF' is not a commit in $REPO"
miss=""
for k in bmc.benchlog bmc.dlshape 'all indexes at height'; do
    git -C "$REPO" grep -qF "$k" "$SRCREF" -- asm/ 2>/dev/null || miss="$miss '$k'"
done
if [ -n "$miss" ]; then
    # A dry run rehearses the steps before the bmc branch has landed; a real
    # run refuses, because the daemon ignores unknown keys.
    [ "$DRY_RUN" = 1 ] || die "ref '$SRCREF' has no$miss under asm/ -- its daemon would ignore the setting or never print the line"
    w "DRY WARN ref '$SRCREF' has no$miss under asm/ -- a real run would ABORT here"
else
    w "SRCREF $SRCREF = $(git -C "$REPO" rev-parse --short "$SRCREF") carries bmc.benchlog, bmc.dlshape and the [ready] line"
fi
[ -r "$CONF" ] || die "no $CONF"

# ---- a. prepare Core ----
if at_or_after a; then
    need_free a "$CORE_MIN_KB"
    pid_alive "$CORE_DD/bitcoind.pid" && die "a bitcoind still runs from $CORE_DD (pid $(cat "$CORE_DD/bitcoind.pid")): rerun #5 is not over"
    [ "$(procs_under "$CORE_DD")" -eq 0 ] || die "a process still has its cwd under $CORE_DD"
    grep -aq ' IBD_END ' "$CORE_DD/watch.log" 2>/dev/null \
        || die "$CORE_DD/watch.log has no IBD_END: rerun #5 did not finish (look before moving anything)"
    w "rerun #5: $(grep -a ' IBD_END ' "$CORE_DD/watch.log" | tail -1)"
    sd=$(cut -c1-10 "$CORE_DD/BENCH_START.txt" 2>/dev/null | tr -d '-')
    ASIDE=$BENCH/core31-rerun5-${sd:-unknown}
    [ -e "$ASIDE" ] && die "$ASIDE already exists; not moving $CORE_DD onto it"
    run mv "$CORE_DD" "$ASIDE" || die "mv $CORE_DD $ASIDE failed"
    w "rerun #5 datadir moved aside: $ASIDE"
    run mkdir "$CORE_DD" || die "mkdir $CORE_DD failed"
    run cp "$CONF" "$CORE_DD/bitcoin.conf" || die "cp conf failed"
    w "fresh $CORE_DD with $(basename "$CONF") ($(grep -cE '^(debug|logtimemicros)=' "$CONF") logging line(s))"
    # The watcher: move the running copy aside, then rename the new one in
    # (a new inode; a bash still reading the old file keeps reading it).
    tsx=$(date -u +%Y%m%dT%H%M%SZ)
    for f in core_bench_watch.sh lib/ibd_harness_lib.sh; do
        [ -e "$WATCHDIR/$f" ] && { run mv "$WATCHDIR/$f" "$WATCHDIR/$f.pre-logged-$tsx" || die "mv aside $f failed"; }
        run cp "$REPO/validation/$f" "$WATCHDIR/$f.new" || die "cp $f failed"
        run mv "$WATCHDIR/$f.new" "$WATCHDIR/$f" || die "install $f failed"
    done
    [ "$DRY_RUN" = 1 ] || echo "watcher + lib from commit $(git -C "$REPO" rev-parse --short HEAD) on $tsx by logged_pair_run.sh: adds the READY step (READY_TIP, READY_INDEXES)" >> "$WATCHDIR/PROVENANCE"
    w "watcher installed in $WATCHDIR (previous copies kept as *.pre-logged-$tsx)"
fi

# ---- b. start Core ----
if at_or_after b; then
    need_free b "$CORE_MIN_KB"
    [ -e "$CORE_DD/blocks" ] && [ "$DRY_RUN" != 1 ] && die "$CORE_DD/blocks exists: not a fresh datadir"
    grep -q '^debug=bench' "$CORE_DD/bitcoin.conf" 2>/dev/null || [ "$DRY_RUN" = 1 ] \
        || die "$CORE_DD/bitcoin.conf is not the logged conf (no debug=bench)"
    run sudo -n systemctl start bitcoin-core-bench.service || die "systemctl start failed (journalctl -u bitcoin-core-bench)"
    [ "$DRY_RUN" = 1 ] || sleep 30
    [ "$DRY_RUN" = 1 ] || pid_alive "$CORE_DD/bitcoind.pid" || die "Core did not come up (journalctl -u bitcoin-core-bench)"
    w "Core rerun #6 (logged) started: BENCH_START $(cat "$CORE_DD/BENCH_START.txt" 2>/dev/null)"
fi

# ---- c. wait for READY_INDEXES (log only) ----
if at_or_after c; then
    need_free c 0
    if [ "$DRY_RUN" = 1 ]; then w "DRY would wait for READY_INDEXES in $CORE_DD/watch.log"
    else
        lowsaid=0
        until grep -aqE ' (READY_INDEXES|FAIL) ' "$CORE_DD/watch.log" 2>/dev/null; do
            pid_alive "$CORE_DD/bitcoind.pid" || { sleep 60; grep -aqE ' (READY_INDEXES|FAIL) ' "$CORE_DD/watch.log" 2>/dev/null && break; die "Core's bitcoind is gone and watch.log has no READY_INDEXES"; }
            f=$(free_kb); if [ "$f" -lt 52428800 ] && [ "$lowsaid" = 0 ]; then w "WARN under 50 GiB free on $BENCH during Core's run"; lowsaid=1; fi
            sleep "$POLL_S"
        done
        grep -aq ' FAIL ' "$CORE_DD/watch.log" && die "the watcher recorded a FAIL: $(grep -a ' FAIL ' "$CORE_DD/watch.log" | tail -1)"
        w "Core: $(grep -a ' IBD_END ' "$CORE_DD/watch.log" | tail -1 | cut -d' ' -f2-)"
        w "Core: $(grep -a ' READY_TIP ' "$CORE_DD/watch.log" | tail -1 | cut -d' ' -f2-)"
        w "Core: $(grep -a ' READY_INDEXES ' "$CORE_DD/watch.log" | tail -1 | cut -d' ' -f2-)"
    fi
fi

# ---- d. stop Core ----
if at_or_after d; then
    need_free d 0
    run sudo -n systemctl stop bitcoin-core-bench.service || die "systemctl stop failed"
    if [ "$DRY_RUN" != 1 ]; then
        for i in $(seq 1 180); do pid_alive "$CORE_DD/bitcoind.pid" || break; sleep 10; done
        pid_alive "$CORE_DD/bitcoind.pid" && die "Core's bitcoind still runs 30 min after stop; bmc NOT launched"
    fi
    w "Core stopped"
    [ "$DRY_RUN" = 1 ] || sleep 120   # let the device settle before the next timed run
fi

# ---- e. launch bmc ----
if at_or_after e; then
    need_free e "$BMC_MIN_KB"
    [ -e "$BMC_DEST/data" ] && die "$BMC_DEST/data exists: a run 34 already started there; move it aside by hand or set RUN="
    pid_alive "$CORE_DD/bitcoind.pid" && die "Core still runs: never concurrent"
    w "launching bmc $RUN: DEST=$BMC_DEST SRCREF=$SRCREF BENCHLOG=1 DLSHAPE=core READY_WAIT=1"
    if [ "$DRY_RUN" = 1 ]; then w "DRY would run: DEST=$BMC_DEST SRCREF=$SRCREF BENCHLOG=1 DLSHAPE=core READY_WAIT=1 setsid nohup $REPO/validation/fresh_ibd_run.sh > $BMC_DEST.launch.log &"
    else
        DEST=$BMC_DEST SRCREF=$SRCREF BENCHLOG=1 DLSHAPE=core READY_WAIT=1 \
            setsid nohup bash "$REPO/validation/fresh_ibd_run.sh" > "$BMC_DEST.launch.log" 2>&1 < /dev/null &
        sleep 120
        grep -aq ' FAIL' "$BMC_DEST/phase.log" 2>/dev/null && die "the harness failed at once: $(grep -a ' FAIL' "$BMC_DEST/phase.log" | head -1)"
        w "bmc harness launched ($(tail -1 "$BMC_DEST/phase.log" 2>/dev/null))"
    fi
fi

# ---- f. wait for the harness's RESULT (files only) ----
if at_or_after f; then
    need_free f 0
    if [ "$DRY_RUN" = 1 ]; then w "DRY would wait for $BMC_DEST/RESULT, then SIGTERM the idle daemon"
    else
        until [ -s "$BMC_DEST/RESULT" ]; do sleep "$POLL_S"; done
        w "bmc RESULT: $(cat "$BMC_DEST/RESULT")"
        w "bmc: $(grep -a ' IBD_END ' "$BMC_DEST/phase.log" | tail -1 | cut -d' ' -f2-)"
        r=$(grep -a ' READY ' "$BMC_DEST/phase.log" | tail -1 | cut -d' ' -f2-)
        w "bmc: ${r:-no READY line in phase.log -- see its WARN}"
        sleep 60
        if pid_alive "$BMC_DEST/daemon.pid"; then w "stopping the idle bmc daemon $(cat "$BMC_DEST/daemon.pid") (SIGTERM)"; kill -TERM "$(cat "$BMC_DEST/daemon.pid")"; fi
        for i in $(seq 1 180); do [ "$(procs_under "$BMC_DEST/data")" -eq 0 ] && break; sleep 10; done
        [ "$(procs_under "$BMC_DEST/data")" -eq 0 ] || w "WARN processes still run from $BMC_DEST/data after 30 min"
    fi
fi

# ---- g. the report ----
if at_or_after g; then
    REP=$BENCH/logged-pair-report-$(date -u +%Y%m%d).md
    [ -e "$REP" ] && REP=$BENCH/logged-pair-report-$(date -u +%Y%m%dT%H%M%SZ).md
    if [ "$DRY_RUN" = 1 ]; then w "DRY would run: python3 $REPO/validation/ibd_stage_report.py --core-dir $CORE_DD --bmc-dir $BMC_DEST > $REP"
    else
        python3 "$REPO/validation/ibd_stage_report.py" --core-dir "$CORE_DD" --bmc-dir "$BMC_DEST" > "$REP" 2>> "$LOG" \
            || die "the report failed (see $LOG)"
        C5=$(ls -d "$BENCH"/core31-rerun5-* 2>/dev/null | tail -1)
        {
            echo
            echo "## The logging-overhead control"
            echo
            echo "Core rerun #5 (same settings, default logging): $(grep -a ' IBD_END ' "$C5/watch.log" 2>/dev/null | tail -1 | cut -d' ' -f2-)"
            echo "Core rerun #6 (debug=bench, debug=coindb, logtimemicros): $(grep -a ' IBD_END ' "$CORE_DD/watch.log" | tail -1 | cut -d' ' -f2-)"
        } >> "$REP"
        w "report: $REP"
    fi
fi
w "DONE"
