#!/bin/bash
# validation/fresh_install_ibd.sh -- the acceptance test: a FRESH clone from
# GitHub, built as the README says, started with a minimal configuration,
# synced from genesis UNATTENDED, then compared with Core's UTXO set hash.
#
#   validation/fresh_install_ibd.sh <dest-dir> [oracle-cli-cmd]
#
# Pass = no manual intervention, no FATAL / REJECT / HALTED in the log, and
# `gettxoutsetinfo muhash` identical to the oracle at the same height.
# Writes <dest>/phase.log (timestamps of every phase), <dest>/progress.log
# (a line every 10 min while syncing), <dest>/RESULT at the end.
set -u
DEST=${1:?dest dir}; ORACLE=${2:-"/storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli -conf=/storage/core-oracle/bitcoin.conf -datadir=/storage/core-oracle"}
# RESUME=1 restarts an interrupted run on the datadir it already built: the
# clone, the build and the configuration are left exactly as they were, the
# daemon is started again and the same watch resumes. Use it when something
# OUTSIDE the test stopped it (a host reboot, an OOM kill of another job) --
# never to paper over the daemon dying, which is a genuine failure.
RESUME=${RESUME:-0}
REPO=https://github.com/BobClawblaw/bitcoinmachinecode.git
P2P=8362; RPC=8361
mkdir -p "$DEST"; cd "$DEST" || exit 2
PH="$DEST/phase.log"; ts(){ date -u +%Y-%m-%dT%H:%M:%SZ; }; ph(){ echo "$(ts) $*" | tee -a "$PH"; }
ph "START dest=$DEST host=$(hostname) kernel=$(uname -r) nasm=$(nasm -v | head -1) gcc=$(gcc --version | head -1)"
if [ "$RESUME" = 1 ]; then
    [ -x src/asm/daemon/bitcoind ] || { ph "FAIL resume: no build at src/asm/daemon/bitcoind"; echo FAIL > RESULT; exit 2; }
    [ -f data/bitcoin.conf ] || { ph "FAIL resume: no data/bitcoin.conf"; echo FAIL > RESULT; exit 2; }
    if [ -f daemon.pid ] && kill -0 "$(cat daemon.pid)" 2>/dev/null; then ph "FAIL resume: daemon $(cat daemon.pid) is still running"; exit 2; fi
    ph "RESUME commit=$(git -C src rev-parse --short HEAD) datadir=$(du -sh data | cut -f1) -- clone/build/conf untouched"
else
# 1. clone -- from GitHub, not the local checkout: this is what a stranger gets
t0=$(date +%s); git clone -q "$REPO" src || { ph "FAIL clone"; echo FAIL > RESULT; exit 1; }
ph "CLONE done $(( $(date +%s)-t0 ))s commit=$(git -C src rev-parse --short HEAD)"
# 2. build -- exactly the README's target
t0=$(date +%s); ( cd src/asm && make -s daemon/bitcoind daemon/bitcoin_cli ) > build.log 2>&1 || { ph "FAIL build (see build.log)"; echo FAIL > RESULT; exit 1; }
ph "BUILD done $(( $(date +%s)-t0 ))s warnings=$(grep -c warning build.log)"
# 3. configuration -- the sample, plus the three things a second node on one box must set
mkdir -p data
# README: the daemon reads <datadir>/bitcoin.conf, then <datadir>/../config/bitcoin.conf.
# The quick start's `cp config/bitcoin.sample.conf config/bitcoin.conf` only
# works when the datadir is <repo>/data; ours is elsewhere, so the file goes
# to the first location. (Run 1 of this test put it in the repo and the daemon
# silently ran on compiled defaults -- the README now says so explicitly.)
cp src/config/bitcoin.sample.conf data/bitcoin.conf
cat >> data/bitcoin.conf <<CONF

# fresh-install acceptance test $(ts): a second node on the same box
port=$P2P
rpcport=$RPC
dbcache=8192
CONF
ph "CONF port=$P2P rpcport=$RPC dbcache=8192 (everything else = sample defaults)"
fi
# 4. start, unattended, low priority, its own console log; never as a unit
ph "START daemon"
if [ "$RESUME" = 1 ]; then setsid nohup nice -n 10 ionice -c3 src/asm/daemon/bitcoind serve "$DEST/data" >> console.log 2>&1 < /dev/null &
else setsid nohup nice -n 10 ionice -c3 src/asm/daemon/bitcoind serve "$DEST/data" > console.log 2>&1 < /dev/null & fi
echo $! > daemon.pid; sleep 5
kill -0 "$(cat daemon.pid)" 2>/dev/null || { ph "FAIL daemon exited at once (console.log)"; echo FAIL > RESULT; exit 1; }
grep -q "no config file" console.log && { ph "FAIL the daemon did not find the configuration (see console.log)"; kill "$(cat daemon.pid)"; echo FAIL > RESULT; exit 1; }
ph "DAEMON pid=$(cat daemon.pid) $(grep -m1 '\[config\] net' console.log | sed 's/.*net  : //')"
# 5. monitor until the tip, then judge
CLI="src/asm/daemon/bitcoin_cli -datadir=$DEST/data"
last_phase=""
while :; do
    sleep 600
    hb=$(grep '\[dl\] heartbeat' console.log | tail -1 | sed 's/.*heartbeat: //')
    # A lagging peer offering its own shorter chain makes the node log
    # "[reorg] candidate REJECTED ... (no action taken)". That is the node
    # being right, and it is routine on mainnet -- it must not fail the run.
    bad=$(grep -E 'FATAL|REJECT|HALTED|SEGV' console.log | grep -vE '\[reorg\] (candidate REJECTED|probe of )' | grep -c .)
    du=$(du -sh data 2>/dev/null | cut -f1); rss=$(ps -o rss= -p "$(cat daemon.pid)" 2>/dev/null | awk '{printf "%.1fG", $1/1048576}')
    for m in 'header' 'catch-up' 'bulk' '\[utxo_live\] init' 'coinstats\] adopted' 'keep-up'; do
        l=$(grep -m1 -E "$m" console.log | cut -c1-140); [ -n "$l" ] && ! grep -qF "$m" "$PH" && ph "PHASE first '$m': $l"
    done
    echo "$(ts) $hb disk=$du rss=$rss bad=$bad" >> progress.log
    if ! kill -0 "$(cat daemon.pid)" 2>/dev/null; then ph "FAIL daemon died (bad=$bad)"; echo FAIL > RESULT; exit 1; fi
    [ "$bad" != 0 ] && { ph "FAIL bad log markers: $(grep -E 'FATAL|REJECT|HALTED|SEGV' console.log | grep -vE '\[reorg\] (candidate REJECTED|probe of )' | head -2 | cut -c1-140)"; echo FAIL > RESULT; exit 1; }
    ours=$(echo "$hb" | grep -oE 'tip=[0-9]+' | cut -d= -f2); theirs=$($ORACLE getblockcount 2>/dev/null)
    [ -n "$ours" ] && [ -n "$theirs" ] && [ "$ours" -ge $((theirs-1)) ] && break
done
ph "TIP reached: ours=$ours oracle=$theirs -- comparing the UTXO set"
sleep 120
O=$($CLI gettxoutsetinfo muhash 2>/dev/null); H=$(echo "$O" | python3 -c "import sys,json; print(json.load(sys.stdin)['height'])")
OM=$(echo "$O" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['muhash'], r['txouts'])")
CM=$($ORACLE gettxoutsetinfo muhash "$H" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['muhash'], r['txouts'])")
ph "MUHASH h=$H ours=$OM oracle=$CM"
if [ "$OM" = "$CM" ]; then ph "PASS muhash identical at $H"; echo "PASS $H" > RESULT; else ph "FAIL muhash differs at $H"; echo FAIL > RESULT; fi
$CLI getblockchaininfo > rpc_getblockchaininfo.json 2>&1; $CLI getnetworkinfo > rpc_getnetworkinfo.json 2>&1
ph "END"
