#!/bin/bash
# validation/fresh_ibd_run.sh -- a fresh mainnet IBD benchmark that can EXPLAIN
# a muhash failure instead of merely reporting one.
#
# WHY THIS EXISTS. Run 22 (2026-09-10/11) synced 966,369 blocks in 20h08m with
# zero bad blocks, no gaps, a tip identical to the Core oracle by hash -- and a
# UTXO set whose muhash differed from Core's. Every aggregate matched exactly:
# txouts, bogosize, total_amount. Only the set hash differed. Production, built
# by reindex, matches Core on BOTH its walk and its index, so the code is sound
# and the fresh-sync path produced subtly wrong data.
#
# Two things made that finding cost twenty hours instead of minutes:
#
#   1. THE CHECK HAD NEVER RUN. Earlier runs' muhash comparison timed out, and
#      an empty result compared equal to an empty oracle value, so the harness
#      printed nothing and the run passed. Run 22 is the first time the
#      comparison actually completed. A check that cannot fail is not a check;
#      this one now refuses to render a verdict on anything that is not 64 hex
#      characters from BOTH sides.
#
#   2. THE ANSWER WAS A SINGLE BIT. "The set differs at the tip" does not say
#      which block broke it. With coinstatsindex on, the node records a muhash
#      for EVERY height as it syncs, so the first divergent height can be found
#      by bisection in seconds against the oracle's own index -- one block, then
#      one coin.
#
# The index costs sync time, so this run's wall clock is NOT comparable with
# run 22's or with Core's. That is deliberate: run 22 already settled the
# timing question, and correctness is now the open one.
set -u
DEST=${DEST:-/mnt/2tbssd/bmc-bench}
SRCREF=${SRCREF:-HEAD}
P2P=${P2P:-8462}; RPC=${RPC:-8461}
WORKERS=${WORKERS:-8}
ORACLE=${ORACLE:-"/storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli -conf=/storage/core-oracle/bitcoin.conf -datadir=/storage/core-oracle"}
PH="$DEST/phase.log"; PROG="$DEST/progress.log"
ts(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
ph(){ echo "$(ts) $*" | tee -a "$PH"; }

mkdir -p "$DEST" && cd "$DEST" || exit 2
: > "$PH"; : > "$PROG"; rm -f RESULT 2>/dev/null

ph "START host=$(hostname) kernel=$(uname -r) workers=$WORKERS"
[ -d src ] || git clone -q /storage/bitcoinmachinecode src
# Hard-reset to the REMOTE ref. `checkout <branch>` on an existing clone keeps
# whatever that branch pointed at when it was cloned, which silently built the
# previous commit on 2026-09-11 and put the wrong binary into a 20-hour run.
git -C src fetch -q origin "+refs/heads/*:refs/remotes/origin/*" 2>/dev/null
git -C src checkout -q --detach "origin/$SRCREF" 2>/dev/null || git -C src checkout -q --detach "$SRCREF" 2>/dev/null
COMMIT=$(git -C src rev-parse --short HEAD)
ph "SRC commit=$COMMIT ref=$SRCREF"
( cd src/asm && make -j8 daemon/bmcbitcoind ) > build.log 2>&1 || { ph "FAIL build"; echo FAIL > RESULT; exit 1; }
ph "BUILD ok"

mkdir -p data
cp src/config/bitcoin.sample.conf data/bitcoin.conf 2>/dev/null
cat >> data/bitcoin.conf <<CONF

# fresh IBD run $(ts)
port=$P2P
rpcport=$RPC
dbcache=8192
bmc.bootcatchup=0
bmc.catchupworkers=$WORKERS
# THE POINT OF THIS RUN: a per-height muhash record, so a set that diverges
# from Core names the block it diverged on instead of only the tip.
coinstatsindex=1
CONF
ph "CONF port=$P2P rpcport=$RPC dbcache=8192 workers=$WORKERS coinstatsindex=1"

T0=$(date +%s); echo "$T0" > epoch.start
setsid nohup nice -n 10 src/asm/daemon/bmcbitcoind serve "$DEST/data" > console.log 2>&1 < /dev/null &
echo $! > daemon.pid; sleep 8
kill -0 "$(cat daemon.pid)" 2>/dev/null || { ph "FAIL daemon exited at once"; echo FAIL > RESULT; exit 1; }
ph "DAEMON pid=$(cat daemon.pid) epoch=$T0"

CLI="src/asm/daemon/bmc_cli -rpcport=$RPC -datadir=$DEST/data"
while :; do
    sleep 300
    hb=$(grep '\[dl\] .*elapsed' console.log | tail -1 | sed 's/.*== //;s/ ==.*//')
    [ -z "$hb" ] && hb=$(grep '\[dl\] heartbeat' console.log | tail -1 | sed 's/.*heartbeat: //')
    bad=$(grep -E 'FATAL|REJECT|HALTED|SEGV' console.log | grep -vE '\[reorg\] (candidate REJECTED|probe of )' | grep -c .)
    du=$(du -sh data 2>/dev/null | cut -f1)
    # the 2026-09-11 occupancy figure: the share of worker wall-clock spent
    # blocked in the socket read. Recorded every tick so the sync's throughput
    # can be read against whether the peers were ever able to fill the pipe.
    idle=$(grep -oE 'pool idle [0-9]+%' console.log | tail -1)
    echo "$(ts) hb='$hb' disk=$du ${idle:+$idle} bad=$bad" >> "$PROG"
    [ "${bad:-0}" != "0" ] && { ph "FAIL bad markers"; echo FAIL > RESULT; exit 1; }
    ours=$($CLI getblockcount 2>/dev/null); theirs=$($ORACLE getblockcount 2>/dev/null)
    [ -z "$ours" ] || [ -z "$theirs" ] && continue
    [ "$ours" -ge $((theirs-1)) ] || continue

    ph "TIP reached: ours=$ours oracle=$theirs elapsed=$(( $(date +%s)-T0 ))s"
    sleep 180                      # let the engine settle and the index commit
    # Compare at a SETTLED height, well below the tip, so neither side is
    # hashing a set the network is still moving under it.
    H=$(( ours - 20 ))
    OM=$($CLI gettxoutsetinfo muhash "$H" 2>/dev/null | sed -n 's/.*"muhash": *"\([0-9a-f]*\)".*/\1/p' | head -1)
    CM=$($ORACLE gettxoutsetinfo muhash "$H" 2>/dev/null | sed -n 's/.*"muhash": *"\([0-9a-f]*\)".*/\1/p' | head -1)
    # THE GUARD THAT WAS MISSING: an empty answer is not a passing answer.
    case "$OM" in *[!0-9a-f]*|"") ph "FAIL muhash: our side returned no usable hash ('$OM')"; echo FAIL > RESULT; exit 1;; esac
    case "$CM" in *[!0-9a-f]*|"") ph "FAIL muhash: the oracle returned no usable hash ('$CM')"; echo FAIL > RESULT; exit 1;; esac
    [ ${#OM} -eq 64 ] && [ ${#CM} -eq 64 ] || { ph "FAIL muhash: a hash was not 64 hex chars (ours ${#OM}, oracle ${#CM})"; echo FAIL > RESULT; exit 1; }

    if [ "$OM" = "$CM" ]; then
        ph "PASS muhash identical at $H ($OM)"; echo "PASS $H" > RESULT; exit 0
    fi
    ph "FAIL muhash differs at $H: ours=$OM oracle=$CM"
    ph "BISECT: finding the first height whose set diverges"
    LO=1; HI=$H
    while [ $LO -lt $HI ]; do
        MID=$(( (LO+HI)/2 ))
        A=$($CLI gettxoutsetinfo muhash "$MID" 2>/dev/null | sed -n 's/.*"muhash": *"\([0-9a-f]*\)".*/\1/p' | head -1)
        B=$($ORACLE gettxoutsetinfo muhash "$MID" 2>/dev/null | sed -n 's/.*"muhash": *"\([0-9a-f]*\)".*/\1/p' | head -1)
        if [ ${#A} -ne 64 ] || [ ${#B} -ne 64 ]; then ph "BISECT stopped: no usable hash at $MID"; break; fi
        if [ "$A" = "$B" ]; then LO=$(( MID+1 )); else HI=$MID; fi
        ph "BISECT  height $MID  $( [ "$A" = "$B" ] && echo same || echo DIFFERS )  window [$LO,$HI]"
    done
    ph "BISECT first divergent height = $LO"
    ph "NEXT: diff that block's coins. getblock $LO, then gettxout each output on"
    ph "      both nodes; the aggregates matched in run 22, so look at the coin's"
    ph "      HEIGHT and COINBASE FLAG, which feed muhash but no aggregate."
    echo "FAIL first-divergent-height=$LO" > RESULT
    exit 1
done
