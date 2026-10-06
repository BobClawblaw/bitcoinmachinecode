#!/bin/bash
# core_bench_run.sh -- ONE Core v31.1 logged IBD benchmark with the process
# sampler beside it (operator rule 2026-10-05: peak memory on every run, both
# sides; rerun #6's peak was lost because core31-watch/ had no
# proc_sampler.sh). The Core half of logged_pair_run.sh, on its own, for a
# box that is otherwise quiet. Never concurrent with another timed run.
# Launch from a plain shell, not an agent's background task:
#
#   cd /storage/bitcoinmachinecode
#   RERUN=7 setsid nohup validation/core_bench_run.sh \
#       > /srv/nvme8tb/bench/core-rerun7.launch.log 2>&1 < /dev/null &
#
#   DRY_RUN=1 validation/core_bench_run.sh     # every check, no change
#
# Steps (each checks free space first; nothing is deleted, a datadir in the
# way makes the script refuse):
#   a. refuse unless the box is quiet: no process with its cwd under $BENCH
#      and no bitcoind from $CORE_DD; $CORE_DD absent or empty; >= 1.1 TiB
#      free. A fresh $CORE_DD with config/core-bench/bitcoin.logged.conf
#      (debug=bench, debug=coindb, logtimemicros -- rerun #6's conf). This
#      tree's watcher, lib AND proc_sampler.sh go into $WATCHDIR, the path
#      bitcoin-core-bench-watch.service runs (previous copies moved aside).
#   b. systemctl start bitcoin-core-bench.service (ExecStartPre refuses a
#      non-empty datadir and writes BENCH_START.txt; it Wants= the watcher,
#      which starts the sampler: $CORE_DD/proc.log every 5 s).
#   c. wait -- reading $CORE_DD/watch.log only, never RPC -- for
#      READY_INDEXES (or a FAIL line, or bitcoind gone).
#   d. systemctl stop; wait until bitcoind exits; the sampler's MEM summary
#      is read from proc.log; the logs are copied to
#      $BENCH/core31-rerun$RERUN-<date>-logs/ and the datadir is MOVED to
#      $BENCH/core31-rerun$RERUN-<date>/ (the operator decides its deletion).
#
# Output: $BENCH/core-rerun$RERUN.log (one line per action, UTC).
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
BENCH=${BENCH:-/srv/nvme8tb/bench}
CORE_DD=$BENCH/core31
WATCHDIR=$BENCH/core31-watch
RERUN=${RERUN:-7}
STEP=${STEP:-a}
DRY_RUN=${DRY_RUN:-0}
CONF=$REPO/config/core-bench/bitcoin.logged.conf
LOG=${CORELOG:-$BENCH/core-rerun$RERUN.log}
CORE_MIN_KB=${CORE_MIN_KB:-1181116006}   # 1.1 TiB: rerun #4 took 916 GB with the three indexes
POLL_S=${POLL_S:-120}

w(){ echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG"; }
die(){ w "ABORT: $*"; exit 1; }
run(){ if [ "$DRY_RUN" = 1 ]; then w "DRY would run: $*"; else "$@"; fi; }
free_kb(){ df --output=avail -k "$BENCH" | tail -1 | tr -d ' '; }
need_free(){ local f; f=$(free_kb)
    w "free on $BENCH: $((f/1024/1024)) GiB (step $1 needs $(( $2/1024/1024 )) GiB)"
    [ "$f" -ge "$2" ] || die "under the floor for step $1; free space (nothing here deletes anything)"; }
pid_alive(){ [ -s "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }
procs_under(){ local n=0 p c; for p in /proc/[0-9]*; do
    c=$(readlink "$p/cwd" 2>/dev/null) || continue
    case "$c" in "$1"|"$1"/*) n=$((n+1));; esac; done; echo $n; }
at_or_after(){ [[ ! "$1" < "$STEP" ]]; }
case "$STEP" in [a-d]) ;; *) echo "STEP must be one of a..d, not '$STEP'" >&2; exit 2;; esac

mkdir -p "$BENCH" 2>/dev/null
w "START Core rerun #$RERUN (step $STEP, dry=$DRY_RUN, repo $REPO @ $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null), datadir $CORE_DD)"
[ -r "$CONF" ] || die "no $CONF"
for f in core_bench_watch.sh lib/ibd_harness_lib.sh proc_sampler.sh; do [ -r "$REPO/validation/$f" ] || die "no $REPO/validation/$f"; done
grep -q 'proc_sampler' "$REPO/validation/core_bench_watch.sh" || die "this tree's core_bench_watch.sh does not start the sampler"

# ---- a. prepare ----
if at_or_after a; then
    need_free a "$CORE_MIN_KB"
    pid_alive "$CORE_DD/bitcoind.pid" && die "a bitcoind still runs from $CORE_DD (pid $(cat "$CORE_DD/bitcoind.pid"))"
    systemctl is-active --quiet bitcoin-core-bench.service && die "bitcoin-core-bench.service is active"
    n=$(procs_under "$BENCH"); [ "$n" -eq 0 ] || die "$n process(es) have their cwd under $BENCH: the box is not quiet (a timed run, a harness, a smoke daemon?)"
    if [ -e "$CORE_DD" ]; then
        [ -z "$(ls -A "$CORE_DD" 2>/dev/null)" ] || die "$CORE_DD exists and is not empty: move it aside first (core31-rerun<N>-<date>)"
    else
        run mkdir "$CORE_DD" || die "mkdir $CORE_DD failed"
    fi
    run cp "$CONF" "$CORE_DD/bitcoin.conf" || die "cp conf failed"
    w "fresh $CORE_DD with $(basename "$CONF") ($(grep -cE '^(debug|logtimemicros)=' "$CONF") logging line(s))"
    tsx=$(date -u +%Y%m%dT%H%M%SZ)
    run mkdir -p "$WATCHDIR/lib"
    for f in core_bench_watch.sh lib/ibd_harness_lib.sh proc_sampler.sh; do
        if [ -e "$WATCHDIR/$f" ] && cmp -s "$WATCHDIR/$f" "$REPO/validation/$f"; then w "$f already current in $WATCHDIR"; continue; fi
        [ -e "$WATCHDIR/$f" ] && { run mv "$WATCHDIR/$f" "$WATCHDIR/$f.pre-rerun$RERUN-$tsx" || die "mv aside $f failed"; }
        run cp "$REPO/validation/$f" "$WATCHDIR/$f.new" || die "cp $f failed"
        run mv "$WATCHDIR/$f.new" "$WATCHDIR/$f" || die "install $f failed"
        w "$f installed in $WATCHDIR"
    done
    [ "$DRY_RUN" = 1 ] || echo "watcher + lib + proc_sampler from commit $(git -C "$REPO" rev-parse --short HEAD) on $tsx by core_bench_run.sh (rerun #$RERUN, sampled)" >> "$WATCHDIR/PROVENANCE"
fi

# ---- b. start ----
if at_or_after b; then
    need_free b "$CORE_MIN_KB"
    [ -e "$CORE_DD/blocks" ] && [ "$DRY_RUN" != 1 ] && die "$CORE_DD/blocks exists: not a fresh datadir"
    grep -q '^debug=bench' "$CORE_DD/bitcoin.conf" 2>/dev/null || [ "$DRY_RUN" = 1 ] || die "$CORE_DD/bitcoin.conf is not the logged conf (no debug=bench)"
    run sudo -n systemctl start bitcoin-core-bench.service || die "systemctl start failed (journalctl -u bitcoin-core-bench)"
    [ "$DRY_RUN" = 1 ] || sleep 30
    [ "$DRY_RUN" = 1 ] || pid_alive "$CORE_DD/bitcoind.pid" || die "Core did not come up (journalctl -u bitcoin-core-bench)"
    [ "$DRY_RUN" = 1 ] || grep -aq ' SAMPLER ' "$CORE_DD/watch.log" 2>/dev/null || w "WARN watch.log has no SAMPLER line yet (the watcher starts it; check in a minute: $CORE_DD/proc.log)"
    w "Core rerun #$RERUN (logged, sampled) started: BENCH_START $(cat "$CORE_DD/BENCH_START.txt" 2>/dev/null)"
fi

# ---- c. wait for READY_INDEXES (log only) ----
if at_or_after c; then
    if [ "$DRY_RUN" = 1 ]; then w "DRY would wait for READY_INDEXES in $CORE_DD/watch.log"
    else
        lowsaid=0
        until grep -aqE ' (READY_INDEXES|FAIL) ' "$CORE_DD/watch.log" 2>/dev/null; do
            pid_alive "$CORE_DD/bitcoind.pid" || { sleep 60; grep -aqE ' (READY_INDEXES|FAIL) ' "$CORE_DD/watch.log" 2>/dev/null && break; die "Core's bitcoind is gone and watch.log has no READY_INDEXES"; }
            f=$(free_kb); if [ "$f" -lt 52428800 ] && [ "$lowsaid" = 0 ]; then w "WARN under 50 GiB free on $BENCH during Core's run"; lowsaid=1; fi
            sleep "$POLL_S"
        done
        grep -aq ' FAIL ' "$CORE_DD/watch.log" && die "the watcher recorded a FAIL: $(grep -a ' FAIL ' "$CORE_DD/watch.log" | tail -1)"
        for k in IBD_END READY_TIP READY_INDEXES; do w "Core: $(grep -a " $k " "$CORE_DD/watch.log" | tail -1 | cut -d' ' -f2-)"; done
        grep -a ' MEM ' "$CORE_DD/watch.log" | tail -2 | while read -r l; do w "Core: $l"; done
    fi
fi

# ---- d. stop, keep the logs, move the datadir aside ----
if at_or_after d; then
    run sudo -n systemctl stop bitcoin-core-bench.service || die "systemctl stop failed"
    if [ "$DRY_RUN" != 1 ]; then
        for i in $(seq 1 180); do pid_alive "$CORE_DD/bitcoind.pid" || break; sleep 10; done
        pid_alive "$CORE_DD/bitcoind.pid" && die "Core's bitcoind still runs 30 min after stop"
        sleep 30
    fi
    sd=$(cut -c1-10 "$CORE_DD/BENCH_START.txt" 2>/dev/null | tr -d '-')
    LOGS=$BENCH/core31-rerun$RERUN-${sd:-unknown}-logs
    ASIDE=$BENCH/core31-rerun$RERUN-${sd:-unknown}
    [ -e "$LOGS" ] && die "$LOGS already exists"
    [ -e "$ASIDE" ] && die "$ASIDE already exists; not moving $CORE_DD onto it"
    run mkdir "$LOGS" || die "mkdir $LOGS failed"
    for f in debug.log watch.log proc.log BENCH_START.txt bitcoin.conf ready-getindexinfo.json; do
        [ -e "$CORE_DD/$f" ] && { run cp "$CORE_DD/$f" "$LOGS/" || die "cp $f failed"; }
    done
    w "logs copied to $LOGS"
    run mv "$CORE_DD" "$ASIDE" || die "mv $CORE_DD $ASIDE failed"
    w "datadir moved aside: $ASIDE (the operator decides its deletion; the stage report reads $LOGS)"
    w "END Core rerun #$RERUN: validation/ibd_stage_report.py --core-dir $LOGS --bmc-dir <run>"
fi
