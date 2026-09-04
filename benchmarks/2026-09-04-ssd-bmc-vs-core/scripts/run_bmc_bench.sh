#!/bin/bash
# run_bmc_bench.sh -- fresh mainnet IBD benchmark for bmc on /mnt/2tbssd.
# Mirrors validation/fresh_install_ibd.sh: same conf pattern, same monitor
# loop, same phase log / progress log / RESULT contract. Ports 8462/8461.
# Oracle = the live core-oracle node on this box.
set -u
DEST=/mnt/2tbssd/bmc-bench
cd "$DEST" || exit 2
PH=$DEST/phase.log; PROG=$DEST/progress.log
ORACLE="/storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli -conf=/storage/core-oracle/bitcoin.conf -datadir=/storage/core-oracle"
P2P=8462; RPC=8461
ts(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
ph(){ echo "$(ts) $*" | tee -a "$PH"; }

[ -f RESULT ] && grep -q PASS "$DEST/RESULT" && { ph "already PASS, refusing rerun"; exit 0; }

ph "START host=$(hostname) kernel=$(uname -r) commit=$(git -C src rev-parse --short HEAD)"
# configuration: sample + test overrides (README: daemon reads <datadir>/bitcoin.conf)
mkdir -p data
cp src/config/bitcoin.sample.conf data/bitcoin.conf
cat >> data/bitcoin.conf <<CONF

# bmc-bench on /mnt/2tbssd $(ts)
port=$P2P
rpcport=$RPC
dbcache=8192
CONF
ph "CONF port=$P2P rpcport=$RPC dbcache=8192"
T0=$(date +%s); echo "$T0" > epoch.start
ph "DAEMON start epoch=$T0"
setsid nohup nice -n 10 ionice -c3 src/asm/daemon/bitcoind serve "$DEST/data" > console.log 2>&1 < /dev/null &
echo $! > daemon.pid; sleep 5
kill -0 "$(cat daemon.pid)" 2>/dev/null || { ph "FAIL daemon exited at once"; echo FAIL > RESULT; exit 1; }
grep -q "no config file" console.log && { ph "FAIL daemon did not find config"; kill "$(cat daemon.pid)"; echo FAIL > RESULT; exit 1; }
ph "DAEMON pid=$(cat daemon.pid) $(grep -m1 '\[config\] net' console.log | sed 's/.*net  : //')"
CLI="src/asm/daemon/bitcoin_cli -datadir=$DEST/data"
while :; do
    sleep 600
    hb=$(grep '\[dl\] heartbeat' console.log | tail -1 | sed 's/.*heartbeat: //')
    bad=$(grep -E 'FATAL|REJECT|HALTED|SEGV' console.log | grep -vE '\[reorg\] (candidate REJECTED|probe of )' | grep -c .)
    du=$(du -sh data 2>/dev/null | cut -f1); rss=$(ps -o rss= -p "$(cat daemon.pid)" 2>/dev/null | awk '{printf "%.1fG", $1/1048576}')
    for m in 'header' 'catch-up' 'bulk' '\[utxo_live\] init' 'coinstats\] adopted' 'keep-up'; do
        l=$(grep -m1 -E "$m" console.log | cut -c1-140); [ -n "$l" ] && ! grep -qF "$m" "$PH" && ph "PHASE first '$m': $l elapsed=$(( $(date +%s)-T0 ))s"
    done
    echo "$(ts) $hb disk=$du rss=$rss bad=$bad" >> "$PROG"
    if ! kill -0 "$(cat daemon.pid)" 2>/dev/null; then ph "FAIL daemon died (bad=$bad)"; echo FAIL > RESULT; exit 1; fi
    [ "$bad" != 0 ] && { ph "FAIL bad log markers"; echo FAIL > RESULT; exit 1; }
    ours=$(echo "$hb" | grep -oE 'tip=[0-9]+' | cut -d= -f2); theirs=$($ORACLE getblockcount 2>/dev/null)
    [ -n "$ours" ] && [ -n "$theirs" ] && [ "$ours" -ge $((theirs-1)) ] && break
done
ph "TIP reached: ours=$ours oracle=$theirs elapsed=$(( $(date +%s)-T0 ))s -- comparing UTXO set"
sleep 120
O=$($CLI gettxoutsetinfo muhash 2>/dev/null)
H=$(echo "$O" | python3 -c "import sys,json; print(json.load(sys.stdin)['height'])")
OM=$(echo "$O" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['muhash'], r['txouts'])")
CM=$($ORACLE gettxoutsetinfo muhash "$H" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['muhash'], r['txouts'])")
ph "MUHASH h=$H ours=$OM oracle=$CM"
if [ "$OM" = "$CM" ]; then ph "PASS muhash identical at $H"; echo "PASS $H" > RESULT; else ph "FAIL muhash differs at $H"; echo FAIL > RESULT; fi
$CLI getblockchaininfo > rpc_getblockchaininfo.json 2>&1
$CLI getnetworkinfo > rpc_getnetworkinfo.json 2>&1
ph "END elapsed=$(( $(date +%s)-T0 ))s"
