#!/bin/bash
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
BASE=${BASE:-/mnt/2tbssd/sweep}
SRC=${SRC:-/storage/bitcoinmachinecode}
ARMS=${ARMS:-"8 16 24 32"}
MINUTES=${MINUTES:-6}
PORT=${PORT:-8472}; RPCPORT=${RPCPORT:-8471}
CLI="$SRC/asm/daemon/bmc_cli"
ts(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
say(){ echo "$(ts) $*" | tee -a "$BASE/sweep.log"; }

mkdir -p "$BASE"
say "=== download worker sweep: arms=[$ARMS] ${MINUTES}min each, commit=$(git -C "$SRC" rev-parse --short HEAD)"
say "link: $(ip -br link show enp14s0 2>/dev/null | awk '{print $1,$2}') $(sudo ethtool enp14s0 2>/dev/null | awk -F': ' '/Speed/{print $2}')"

# a randomised order, so a slow stretch of the link is not always the same arm
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
CONF
    say "--- arm w=$W : starting"
    ( cd "$D" && "$SRC/asm/daemon/bmcbitcoind" serve "$D" >"$D/console.log" 2>&1 & echo $! > "$D/pid" )
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
    RECV=$(grep -oE 'avg [0-9.]+MB/s' "$D/console.log" | tail -1)
    say "arm w=$W : height=$HEIGHT bytes=$BYTES window=$((T1-T0))s console_avg=$RECV pool_idle=${IDLE}%"
    PID=$(cat "$D/pid" 2>/dev/null)
    [ -n "${PID:-}" ] && kill -TERM "$PID" 2>/dev/null
    # wait for it to close its files rather than racing the next arm's disk
    for i in $(seq 1 60); do kill -0 "$PID" 2>/dev/null || break; sleep 2; done
    say "arm w=$W : stopped"
done
say "=== sweep done. Read the arms together: throughput AND pool_idle decide"
say "    which of the three readings above applies. One arm on its own says nothing."
