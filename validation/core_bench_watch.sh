#!/bin/bash
# core_bench_watch.sh DATADIR RPCPORT -- the Core side's equivalent of
# fresh_ibd_run.sh's monitor loop, WITHOUT any RPC to the node being timed.
#
# Operator rule (2026-09-19): nothing queries a timed node's RPC until its IBD is
# over. The first Core v31.1 baseline was polled every minute by a monitor, and
# Core's gettxoutsetinfo forces a UTXO cache flush on every call, so that
# baseline flushed its cache once a minute for 17 of its 19 h 40 m. This watcher
# reads only the node's debug.log and the kernel's socket table:
#   - every 60 s it names any process connected to RPCPORT, and counts
#     connections that closed in the last minute (a poller that is in and out in
#     milliseconds is only visible that way);
#   - it records the IBD end from Core's own "Leaving InitialBlockDownload" line,
#     against BENCH_START.txt, which the unit writes the instant before bitcoind
#     starts;
#   - it notes the node disappearing before that line.
# Output: DATADIR/watch.log. It exits once the end is recorded. It is started
# with the node by bitcoin-core-bench-watch.service and stopped with it.
set -u
DD=${1:?datadir}; PORT=${2:?rpc port}
. "$(dirname "$0")/lib/ibd_harness_lib.sh"
OUT="$DD/watch.log"; LOG="$DD/debug.log"
w(){ echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >> "$OUT"; }
w "START watching $DD (rpc :$PORT); bench started $(cat "$DD/BENCH_START.txt" 2>/dev/null || echo '?')"
seen=""; tw_said=0
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
    end=$(grep -a -m1 'Leaving InitialBlockDownload' "$LOG" 2>/dev/null | cut -c1-20)
    if [ -n "$end" ]; then
        start=$(cat "$DD/BENCH_START.txt" 2>/dev/null)
        el=$(( $(date -u -d "$end" +%s) - $(date -u -d "$start" +%s) ))
        w "IBD_END $end (from the log) elapsed=${el}s = $((el/3600)) h $((el%3600/60)) m $((el%60)) s"
        exit 0
    fi
    # the node gone before its end line: the run is over and says so
    if ! ss -ltnH "( sport = :$PORT )" 2>/dev/null | grep -q .; then
        sleep 30
        ss -ltnH "( sport = :$PORT )" 2>/dev/null | grep -q . || { w "FAIL the node stopped listening on :$PORT before leaving IBD"; exit 1; }
    fi
    sleep 60
done
