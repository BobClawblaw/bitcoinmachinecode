#!/bin/bash
# ============================================================================
# RETIRED 2026-09-14. DO NOT RUN.
#
# This script is kept for its reasoning, not its use. It answers a question this
# project should not act on, and answering it cost a day and an outage.
#
# WHY IT IS RETIRED
#
# 1. The number is not ours to tune. Core's block-download concurrency is FIXED
#    at 8 (MAX_OUTBOUND_FULL_RELAY_CONNECTIONS, not configurable).
#    bmc.catchupworkers=8 exists to MATCH that. It is a parity decision, not a
#    performance one, and a Core-named behaviour carries Core's semantics.
#
# 2. Acting on the answer would break every benchmark. The IBD report says it
#    outright: earlier runs at 16 to 64 workers against Core's 8 "is not a
#    comparison of anything". Raising the count would make future Core
#    comparisons measure peer count rather than implementation.
#
# 3. The performance question is already answered in the only configuration we
#    can honestly benchmark. Run 23, at 8 workers, is the fastest of four runs
#    and beats an unhandicapped Core v31.1.
#
# 4. More download slots means more connections to strangers' nodes, for our
#    benefit. Core chose 8 deliberately.
#
# WHAT IT COST
#
# Four distinct failures, never once a complete result: it read its throughput
# from a file where the string never appears; $! captured a subshell so three of
# four arms died on a held port; empty arms were reported as "sweep done"; and
# the w=32 arm, with no maxconnections in its generated config, opened thousands
# of outbound connections across 35 processes and saturated the operator's LAN.
#
# WHAT IS WORTH KEEPING
#
# The pool_idle figure, 17-31% of worker wall-clock spent blocked before the
# first byte. That is a real observation about PEER SELECTION -- slots held by
# peers that cannot fill the pipe -- and it does not need a worker sweep. Measure
# it against the local oracle's sixteen loopback listeners, where no stranger's
# node is involved and nothing touches the LAN.
#
# If you are about to run this anyway, you need a reason better than curiosity,
# MAXCONN set, and the operator's agreement.
# ============================================================================
echo "download_worker_sweep.sh is RETIRED -- see the header. Refusing to run." >&2
echo "Set SWEEP_I_HAVE_READ_THE_HEADER=1 to override." >&2
[ "${SWEEP_I_HAVE_READ_THE_HEADER:-0}" = "1" ] || exit 2
# validation/download_worker_sweep.sh -- does adding download peers add throughput?
#
# WHY THIS EXISTS. bmc.catchupworkers has twice been set from an unmeasured
# number: 64 arrived as the size of the worker arrays, and 8 replaced it on a
# comparison of two runs a day apart with different peer sets, which the
# release note itself called "not a controlled A/B". The one measurement that
# settles it has never been run.
#
# It does not need a 20-hour sync. Throughput at a given worker count is
# readable in minutes, and the node now reports pool_idle_pct -- the share of
# worker wall-clock spent blocked in the socket read -- which says WHY a
# number is what it is:
#
#   idle LOW  + throughput flat as workers rise  -> a shared ceiling (the WAN)
#   idle LOW  + throughput rising                -> per-peer limited; add peers
#   idle HIGH                                    -> slots held by peers that
#                                                   cannot fill the pipe, so
#                                                   peer SELECTION is the lever,
#                                                   not peer count
#
# Each arm runs from the SAME fresh datadir state so the block sizes, and so
# the bytes per block, are identical across arms. Arms are short and the
# order is randomised, so a slow minute on the link does not land on one arm.
set -u
. "$(dirname "$0")/lib/ibd_harness_lib.sh"
BASE=${BASE:-/mnt/2tbssd/sweep}
SRC=${SRC:-/storage/bitcoinmachinecode}
# Arms are capped and the ceiling is deliberate: 8 is Core's own outbound
# full-relay count, and anything above MAXARM has to be asked for explicitly by
# someone who has decided the network load is acceptable.
ARMS=${ARMS:-"4 8 12 16"}
MAXARM=${MAXARM:-16}
MAXCONN=${MAXCONN:-24}
MINUTES=${MINUTES:-6}
PORT=${PORT:-8472}; RPCPORT=${RPCPORT:-8471}
CLI="$SRC/asm/daemon/bmc_cli"
ts(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
say(){ echo "$(ts) $*" | tee -a "$BASE/sweep.log"; }

# Refuse before a single socket is opened, not after.
for a in $ARMS; do
    case "$a" in ''|*[!0-9]*) echo "arm '$a' is not a number" >&2; exit 2;; esac
    if [ "$a" -gt "$MAXARM" ]; then
        echo "REFUSING: arm w=$a exceeds MAXARM=$MAXARM." >&2
        echo "  On 2026-09-14 a w=32 arm with no maxconnections opened thousands of" >&2
        echo "  outbound connections across 35 processes and saturated the LAN." >&2
        echo "  Raise MAXARM deliberately, with MAXCONN set, if you mean it." >&2
        exit 2
    fi
done
mkdir -p "$BASE"
say "=== download worker sweep: arms=[$ARMS] ${MINUTES}min each, commit=$(git -C "$SRC" rev-parse --short HEAD)"
say "link: $(ip -br link show enp14s0 2>/dev/null | awk '{print $1,$2}') $(sudo ethtool enp14s0 2>/dev/null | awk -F': ' '/Speed/{print $2}')"

# a randomised order, so a slow stretch of the link is not always the same arm
FAILED_ARMS=""; RESULTS=""
ORDER=$(for a in $ARMS; do echo "$RANDOM $a"; done | sort -n | awk '{print $2}')
say "randomised arm order: $(echo $ORDER | tr '\n' ' ')"

for W in $ORDER; do
    D="$BASE/w$W"
    rm -rf "$D" 2>/dev/null; mkdir -p "$D"
    cat > "$D/bitcoin.conf" <<CONF
port=$PORT
rpcport=$RPCPORT
dbcache=8192
bmc.bootcatchup=0
bmc.catchupworkers=$W
# 2026-09-14: THIS CAP IS NOT OPTIONAL. Without it, this config placed no bound
# on connections at all, and the w=32 arm opened thousands of outbound
# connections across 35 processes and saturated the operator's LAN. The arm's
# teardown never ran, so nothing bounded it until it was killed by hand.
# catchupworkers raises download concurrency; maxconnections is what keeps that
# from becoming a connection storm against the public network.
maxconnections=$MAXCONN
CONF
    say "--- arm w=$W : starting"
    # 2026-09-13: this was
    #   ( cd "$D" && "$BIN" serve "$D" >console.log 2>&1 & echo $! > pid )
    # where `&` backgrounds the whole `cd && cmd` LIST, so $! is the SUBSHELL's
    # pid, not the daemon's. The subshell exits at once, `kill -0` on it fails
    # immediately, and the arm logs "stopped" while the daemon and its forked
    # download workers keep running and holding the port. Arms 2, 3 and 4 then
    # died with "bind failed: Address already in use" and recorded nothing,
    # while the sweep still printed "sweep done". One usable arm out of four.
    #
    # setsid puts the daemon in its own process GROUP so the whole tree can be
    # signalled -- this node forks a worker per download slot, and killing only
    # the parent leaves them holding the listening socket.
    ( cd "$D" && setsid "$SRC/asm/daemon/bmcbitcoind" serve "$D" >"$D/console.log" 2>&1 & echo $! > "$D/pid" )
    sleep 2
    # the recorded pid is the daemon itself; record its group for the kill below
    DPID=$(cat "$D/pid" 2>/dev/null)
    ps -o pgid= -p "$DPID" 2>/dev/null | tr -d ' ' > "$D/pgid" || true
    sleep 90                                    # headers + the first chunks, before measuring
    T0=$(date +%s)
    sleep $((MINUTES*60))
    T1=$(date +%s)
    # the node's own figures, not a guess from the outside
    INFO=$("$CLI" -rpcport=$RPCPORT -datadir="$D" bmcgetdownloadinfo 2>/dev/null)
    IDLE=$(echo "$INFO" | sed -n 's/.*"pool_idle_pct": *\([-0-9]*\).*/\1/p' | head -1)
    BYTES=$(echo "$INFO" | sed -n 's/.*"bytes_total": *\([0-9]*\).*/\1/p' | head -1)
    HEIGHT=$("$CLI" -rpcport=$RPCPORT -datadir="$D" getblockcount 2>/dev/null)
    # the console's own recv average is the cross-check on bytes_total
    # 2026-09-13: this read $D/console.log, where "avg N MB/s" appears ZERO
    # times -- it is written to the daemon's running log. One archived debug.log
    # carries 5,916 of them. Every arm of this sweep would have recorded an
    # empty cross-check, and the sweep has never been run, so nobody saw it.
    RECV=$(ibd_throughput "$(ibd_daemon_log "$D")")
    say "arm w=$W : height=$HEIGHT bytes=$BYTES window=$((T1-T0))s console_avg=$RECV pool_idle=${IDLE}%"
    # An arm that produced nothing must SAY SO. The first run of this sweep
    # logged three arms as "height= bytes= console_avg= pool_idle=%" and still
    # finished with "sweep done" -- the daemon had failed to bind and the script
    # had no opinion about it. Empty fields are a failed arm, not a datapoint.
    if [ -z "${BYTES:-}" ] || [ -z "${HEIGHT:-}" ] || [ -z "${IDLE:-}" ]; then
        say "arm w=$W : FAILED -- no measurement (daemon up? port free? see $D/main/debug.log)"
        grep -aE 'bind failed|lsock failed|FATAL' "$(ibd_daemon_log "$D")" 2>/dev/null | tail -2 | while read -r l; do say "    $l"; done
        FAILED_ARMS="$FAILED_ARMS $W"
    else
        MBPS=$(python3 -c "print(f'{$BYTES/1048576/$((T1-T0)):.1f}')" 2>/dev/null)
        say "arm w=$W : ${MBPS} MB/s over the window, idle ${IDLE}%"
        RESULTS="$RESULTS $W:$MBPS:$IDLE"
    fi
    PID=$(cat "$D/pid" 2>/dev/null); PGID=$(cat "$D/pgid" 2>/dev/null)
    [ -n "${PGID:-}" ] && kill -TERM -"$PGID" 2>/dev/null    # the whole tree
    [ -n "${PID:-}"  ] && kill -TERM "$PID"   2>/dev/null
    # wait for it to close its files rather than racing the next arm's disk
    for i in $(seq 1 60); do kill -0 "$PID" 2>/dev/null || break; sleep 2; done
    # AND wait for the port to actually be free. Waiting on the pid alone is what
    # let the next arm start into a held socket: the forked workers outlive the
    # parent by a moment, and a listening socket they still hold is a bind
    # failure for the arm that follows.
    for i in $(seq 1 60); do
        ss -lnt 2>/dev/null | grep -qE ":$PORT\b" || break
        [ "$i" = 60 ] && say "WARN port $PORT still held after 120s; the next arm will fail to bind"
        sleep 2
    done
    say "arm w=$W : stopped"
done
say ""
say "=== sweep summary ==="
for r in $RESULTS; do
    w=${r%%:*}; rest=${r#*:}; mb=${rest%%:*}; id=${rest#*:}
    say "  w=$w  ${mb} MB/s  idle ${id}%"
done
if [ -n "$FAILED_ARMS" ]; then
    say "  FAILED ARMS:$FAILED_ARMS -- these produced NO measurement."
    say "  A sweep missing arms cannot answer the question it exists to answer."
    say "=== sweep INCOMPLETE ==="
    exit 1
fi
say "=== sweep done. Read the arms together: throughput AND pool_idle decide"
say "    which of the three readings above applies. One arm on its own says nothing."
