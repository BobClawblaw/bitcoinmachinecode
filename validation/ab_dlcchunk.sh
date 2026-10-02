#!/bin/bash
# ab_dlcchunk.sh -- A/B of the parallel download's chunk size (bmc.dlcchunk)
# on the early chain, where run 31 lost most to run 30 (300,000 in 16:59
# against 9:40). Each arm is a fresh sync to STOP (default 300,000) with the
# fresh_ibd_run.sh configuration (PARITY=1), the same binary, one
# bmc.dlcchunk value; the arms run one after another, never together.
#
# The clock is the daemon's own log: the time from launch to the first
# "[utxo_live] catchup progress: height=" line at or past each 50,000 mark.
# No RPC is sent to an arm (never poll a benchmark node). An arm is stopped
# by its pid once the apply reaches STOP; since 2026-10-01 -stopatheight also
# shuts the node down there itself, as Core does, so an exit is read from the
# log (the final height) before it is called early.
#
#   BASE=/srv/nvme8tb/bench/ab-chunk SRCREF=<commit> ARMS="a40:40 b16:16" \
#     setsid nohup bash validation/ab_dlcchunk.sh > /dev/null 2>&1 < /dev/null &
#
# Results: $BASE/RESULTS (one row per arm), $BASE/<arm>/marks, the arm's
# datadir and console.log. $BASE/DONE is written last.
set -u
BASE=${BASE:-/srv/nvme8tb/bench/ab-chunk}
SRCREF=${SRCREF:-HEAD}
ARMS=${ARMS:-"a40:40 b16:16"}
STOP=${STOP:-300000}
ARM_TIMEOUT_S=${ARM_TIMEOUT_S:-3600}
P2P=${P2P:-8472}; RPC=${RPC:-8471}; ZMQPORT=${ZMQPORT:-28474}
REPO=${REPO:-/storage/bitcoinmachinecode}
ts(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
say(){ echo "$(ts) $*" | tee -a "$BASE/phase.log"; }

mkdir -p "$BASE" && cd "$BASE" || exit 2
rm -f DONE
say "START arms=[$ARMS] stop=$STOP srcref=$SRCREF"
[ -d src ] || git clone -q "$REPO" src
git -C src fetch -q "$REPO" "+refs/heads/*:refs/remotes/origin/*" 2>/dev/null
git -C src checkout -q --detach "$SRCREF" || { say "FAIL checkout $SRCREF"; echo FAIL > DONE; exit 1; }
COMMIT=$(git -C src rev-parse --short HEAD)
( cd src/asm && make -j8 runtime ) > build.log 2>&1 || { say "FAIL build (build.log)"; echo FAIL > DONE; exit 1; }
say "BUILD ok commit=$COMMIT"
[ -f RESULTS ] || echo "# arm chunk commit start_utc marks(height=elapsed_s...) stop_s" > RESULTS

for spec in $ARMS; do
    arm=${spec%%:*}; chunk=${spec##*:}
    D="$BASE/$arm"
    if [ -e "$D" ]; then say "SKIP $arm: $D exists (a fresh sync needs a fresh datadir; move it aside)"; continue; fi
    mkdir -p "$D/data"
    cp src/config/bitcoin.sample.conf "$D/data/bitcoin.conf" 2>/dev/null
    cat >> "$D/data/bitcoin.conf" <<CONF

# ab_dlcchunk arm $arm $(ts) -- fresh_ibd_run.sh's configuration (PARITY=1) plus the arm's chunk
port=$P2P
rpcport=$RPC
dbcache=8192
bmc.bootcatchup=0
coinstatsindex=1
txindex=1
blockfilterindex=1
maxconnections=48
zmqpubhashblock=tcp://127.0.0.1:$ZMQPORT
zmqpubrawblock=tcp://127.0.0.1:$ZMQPORT
zmqpubhashtx=tcp://127.0.0.1:$ZMQPORT
zmqpubrawtx=tcp://127.0.0.1:$ZMQPORT
stopatheight=$STOP
bmc.dlcchunk=$chunk
CONF
    LOG="$D/data/main/debug.log"
    T0=$(date +%s)
    setsid nohup "$BASE/src/asm/daemon/bmcbitcoind" serve "$D/data" > "$D/console.log" 2>&1 < /dev/null &
    pid=$!; echo "$pid" > "$D/daemon.pid"
    say "ARM $arm chunk=$chunk pid=$pid epoch=$T0"
    : > "$D/marks"; next=50000; reached=0
    while :; do
        sleep 5
        now=$(date +%s)
        alive=1; kill -0 "$pid" 2>/dev/null || alive=0
        if [ $((now - T0)) -ge "$ARM_TIMEOUT_S" ]; then say "ARM $arm: timeout at ${ARM_TIMEOUT_S}s"; break; fi
        h=0; [ -f "$LOG" ] && h=$(grep -a -o 'catchup progress: height=[0-9]*' "$LOG" | tail -1 | grep -o '[0-9]*$')
        h=${h:-0}
        # progress lines are periodic: the daemon's own stop line is the proof
        [ -f "$LOG" ] && grep -aq "stopatheight=$STOP reached" "$LOG" && h=$STOP
        # the node exits at STOP by itself now; earlier than that is a failure
        if [ "$alive" = 0 ] && [ "$h" -lt "$STOP" ]; then say "ARM $arm: daemon exited before $STOP (log height $h)"; break; fi
        while [ "$h" -ge "$next" ] && [ "$next" -le "$STOP" ]; do
            echo "$next=$((now - T0))" >> "$D/marks"; say "ARM $arm: $next at $((now - T0)) s (log height $h)"; next=$((next + 50000))
        done
        if [ "$h" -ge "$STOP" ]; then reached=1; break; fi
    done
    STOP_S=$(( $(date +%s) - T0 ))
    grep -a '\[dlc\] Core.s shape' "$LOG" | head -1 | tee -a "$D/shape.line" > /dev/null
    kill -TERM "$pid" 2>/dev/null
    w=0; while kill -0 "$pid" 2>/dev/null && [ "$w" -lt 300 ]; do sleep 2; w=$((w + 2)); done
    kill -0 "$pid" 2>/dev/null && say "ARM $arm: pid $pid still alive after 300 s of SIGTERM"
    echo "$arm $chunk $COMMIT $(date -u -d @"$T0" +%H:%M:%S) $(tr '\n' ' ' < "$D/marks")${reached:+ } $STOP_S" >> RESULTS
    say "ARM $arm done: reached=$reached stop_s=$STOP_S"
done
say "END"
echo OK > DONE
