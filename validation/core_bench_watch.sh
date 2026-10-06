#!/bin/bash
# core_bench_watch.sh DATADIR RPCPORT -- the Core side's equivalent of
# fresh_ibd_run.sh's monitor loop, WITHOUT any RPC to the node being timed.
#
# Operator rule (2026-09-19): nothing queries a timed node's RPC until its IBD is
# over. The first Core v31.1 baseline was polled every minute by a monitor, and
# Core's gettxoutsetinfo forces a UTXO cache flush on every call, so that
# baseline flushed its cache once a minute for 17 of its 19 h 40 m. During the
# timed span this watcher reads only the node's debug.log and the kernel's
# socket table:
#   - every 60 s it names any process connected to RPCPORT, and counts
#     connections that closed in the last minute (a poller that is in and out in
#     milliseconds is only visible that way);
#   - it records the IBD end from Core's own "Leaving InitialBlockDownload" line,
#     against BENCH_START.txt, which the unit writes the instant before bitcoind
#     starts;
#   - it notes the node disappearing before that line.
#
# THE READY STEP (2026-10-04, worklog/2026-10-04-logged-ibd-runs-plan.md s.3).
# Leaving IBD is not "ready to serve RPC with every index at the tip", which is
# the finish line bmc's "[ready] all indexes at height N" marks. Core logs no
# such line, so after IBD_END the watcher goes on:
#   1. READY_TIP: wait (log only, every 60 s) until the node's last UpdateTip
#      height reaches the ORACLE's tip. The oracle is asked with ITS OWN cli
#      (/storage/core-oracle, RPC 8335) -- the oracle is not the timed node,
#      so asking it costs the run nothing. The time recorded is the log's own
#      timestamp of the UpdateTip at that height.
#   2. READY_INDEXES: then, and only then, ONE getindexinfo to the timed node.
#      This is the first RPC the node receives, and it happens AFTER the timed
#      span ended (IBD_END and READY_TIP are already recorded from the log).
#      If an index is not yet at the READY_TIP height it retries, at most
#      once every 60 s, and records READY_INDEXES at the first answer where
#      every index is. Resolution: one retry interval.
#      "synced" alone is not enough: on a fresh datadir every index reports
#      synced=true from its first second (see core_index_unready in the lib).
# WATCH_READY=0 skips the ready step (exits at IBD_END, the old behaviour).
#
# Output: DATADIR/watch.log (and DATADIR/ready-getindexinfo.json, the last
# answer). It exits once READY_INDEXES (or a FAIL) is recorded. It is started
# with the node by bitcoin-core-bench-watch.service and stopped with it.
set -u
DD=${1:?datadir}; PORT=${2:?rpc port}
. "$(dirname "$0")/lib/ibd_harness_lib.sh"
OUT="$DD/watch.log"; LOG="$DD/debug.log"
WATCH_READY=${WATCH_READY:-1}
READY_MAX_S=${READY_MAX_S:-21600}   # give up on READY after 6 h past IBD_END
TICK=${WATCH_TICK_S:-60}            # the look interval; only a test shortens it
ORACLE=${ORACLE:-"/storage/bitcoin-core-v31.1/bin/bitcoin-cli -conf=/storage/core-oracle/bitcoin.conf -datadir=/storage/core-oracle"}
CORE_CLI=${CORE_CLI:-/storage/bitcoin-core-v31.1/bin/bitcoin-cli}
w(){ echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >> "$OUT"; }
hms(){ printf '%d h %d m %d s' $(($1/3600)) $(($1%3600/60)) $(($1%60)); }
listening(){ ss -ltnH "( sport = :$PORT )" 2>/dev/null | grep -q .; }
w "START watching $DD (rpc :$PORT); bench started $(cat "$DD/BENCH_START.txt" 2>/dev/null || echo '?'); ready step $( [ "$WATCH_READY" = 1 ] && echo on || echo off)"
# CPU time and peak memory beside the run (operator rule 2026-10-05: every
# run, both sides, the same way as bmc's harness). /proc only, plus systemd's
# own accounting for the unit -- neither is an RPC to the node.
SAMPLER="$(dirname "$0")/proc_sampler.sh"; CORE_EXE=${CORE_EXE:-/storage/bitcoin-core-v31.1/bin/bitcoind}
if [ -f "$SAMPLER" ]; then
    setsid nohup bash "$SAMPLER" --exe "$CORE_EXE" "$DD/proc.log" 5 > /dev/null 2>&1 < /dev/null &
    SAMPLER_PID=$!; trap 'kill "$SAMPLER_PID" 2>/dev/null' EXIT
    w "SAMPLER pid=$SAMPLER_PID $DD/proc.log every 5 s (cpu, rss, pss, peaks) for $CORE_EXE"
else w "WARN no $SAMPLER -- no CPU/memory sampling"; fi
mem_line(){ { [ -s "$DD/proc.log" ] && tail -1 "$DD/proc.log" | cut -d' ' -f2- || echo "no proc.log"; }
            echo "systemd MemoryPeak=$(systemctl show bitcoin-core-bench.service -p MemoryPeak --value 2>/dev/null) CPUUsageNSec=$(systemctl show bitcoin-core-bench.service -p CPUUsageNSec --value 2>/dev/null)"; }
seen=""; tw_said=0; off=0
while :; do
    for c in $(ibd_rpc_clients "$PORT"); do
        case " $seen " in *" $c "*) ;; *) seen="$seen $c"
            w "WARN rpc client during IBD: $c ($(tr '\0' ' ' < /proc/${c%%:*}/cmdline 2>/dev/null | cut -c1-120)) -- the run is being perturbed";; esac
    done
    tw=$(ibd_rpc_recent_closes "$PORT")
    if [ "${tw:-0}" -gt 0 ]; then
        [ "$tw_said" = 0 ] && w "WARN $tw connection(s) to the RPC port closed in the last minute during IBD -- something is polling the run"
        tw_said=1
    else tw_said=0; fi
    # Only the bytes written since the last look (plus a 4 KB overlap, so a
    # line split across two looks is still seen whole). Under debug=bench the
    # log grows to ~1.2 GB; grepping all of it every minute would make the
    # watcher a load on the run it is timing.
    size=$(stat -c %s "$LOG" 2>/dev/null || echo 0)
    [ "$size" -lt "$off" ] && off=0    # truncated or replaced: start over
    from=$(( off > 4096 ? off - 4096 : 0 ))
    end=$(tail -c +"$((from + 1))" "$LOG" 2>/dev/null | head -c "$((size - from))" \
          | grep -a -m1 'Leaving InitialBlockDownload' | cut -d' ' -f1)
    off=$size
    if [ -n "$end" ]; then
        start=$(cat "$DD/BENCH_START.txt" 2>/dev/null)
        el=$(( $(date -u -d "$end" +%s) - $(date -u -d "$start" +%s) ))
        w "IBD_END $end (from the log) elapsed=${el}s = $(hms "$el")"
        w "MEM at IBD_END: $(mem_line | tr '\n' ' ')"
        break
    fi
    # the node gone before its end line: the run is over and says so
    if ! listening; then
        sleep $(( TICK / 2 ))
        listening || { w "FAIL the node stopped listening on :$PORT before leaving IBD"; exit 1; }
    fi
    sleep "$TICK"
done
[ "$WATCH_READY" = 1 ] || exit 0

# ---- READY_TIP: the node's UpdateTip at the oracle's tip (log + oracle only) ----
T0=$(date -u -d "$(cat "$DD/BENCH_START.txt" 2>/dev/null)" +%s 2>/dev/null || echo 0)
GIVEUP=$(( $(date +%s) + READY_MAX_S ))
osaid=0
while :; do
    [ "$(date +%s)" -lt "$GIVEUP" ] || { w "FAIL READY_TIP not reached within ${READY_MAX_S}s of IBD_END"; exit 1; }
    if ! listening; then
        sleep $(( TICK / 2 ))
        listening || { w "FAIL the node stopped listening on :$PORT before READY_TIP"; exit 1; }
    fi
    ours=$(core_log_tip_height "$LOG")
    # shellcheck disable=SC2086  # ORACLE is a command line, one word per arg
    theirs=$($ORACLE getblockcount 2>/dev/null)
    case "$theirs" in ''|*[!0-9]*)
        [ "$osaid" = 0 ] && w "WARN the oracle did not answer getblockcount ('$theirs'); retrying every ${TICK} s"
        osaid=1; sleep "$TICK"; continue;; esac
    osaid=0
    case "$ours" in ''|*[!0-9]*) sleep "$TICK"; continue;; esac
    if [ "$ours" -ge "$theirs" ]; then
        tt=$(core_log_tip_time "$LOG" "$theirs")
        te=$(date -u -d "$tt" +%s 2>/dev/null || date +%s)
        READY_H=$theirs
        w "READY_TIP ${tt:-?} (from the log) height=$theirs node_log_tip=$ours oracle=$theirs elapsed=$((te - T0))s = $(hms $((te - T0)))"
        break
    fi
    sleep "$TICK"
done

# ---- READY_INDEXES: the first RPC to the node, after the timed span ----
TCLI=("$CORE_CLI" -conf="$DD/bitcoin.conf" -datadir="$DD" -rpcport="$PORT" -rpcclienttimeout=120)
n=0
while :; do
    [ "$(date +%s)" -lt "$GIVEUP" ] || { w "FAIL READY_INDEXES not reached within ${READY_MAX_S}s of IBD_END"; exit 1; }
    n=$((n + 1))
    ans=$("${TCLI[@]}" getindexinfo 2>&1); rc=$?
    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '%s\n' "$ans" > "$DD/ready-getindexinfo.json"
    w "GETINDEXINFO #$n rc=$rc $(printf '%s' "$ans" | tr -d ' \n' | cut -c1-600)"
    un=$(core_index_unready "$ans" "$READY_H"); r=$?
    case $r in
        0) te=$(date -u -d "$now" +%s)
           w "READY_INDEXES $now (getindexinfo #$n) every index at >= $READY_H elapsed=$((te - T0))s = $(hms $((te - T0)))"
           w "MEM at READY: $(mem_line | tr '\n' ' ')"
           exit 0;;
        1) w "WAIT index(es) below $READY_H: $un -- next getindexinfo in ${TICK} s";;
        *) w "WARN getindexinfo unreadable (rc=$rc) -- next try in ${TICK} s"
           listening || { w "FAIL the node stopped listening on :$PORT before READY_INDEXES"; exit 1; };;
    esac
    sleep "$TICK"
done
