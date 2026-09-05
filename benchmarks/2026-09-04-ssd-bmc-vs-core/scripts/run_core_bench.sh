#!/bin/bash
# run_core_bench.sh -- fresh mainnet IBD benchmark for Bitcoin Core v31.1 on
# /mnt/2tbssd. Phases timed: start -> RPC up -> headers -> blocks ->
# verificationprogress 1.0 (UTXO complete) -> muhash parity vs oracle.
# Oracle = core-oracle on this box. Ports 8563/8562.
set -u
DEST=/mnt/2tbssd/core-bench
cd "$DEST" || exit 2
PH=$DEST/phase.log; PROG=$DEST/progress.log
ORACLE="/storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli -conf=/storage/core-oracle/bitcoin.conf -datadir=/storage/core-oracle"
P2P=8563; RPC=8562
ts(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
ph(){ echo "$(ts) $*" | tee -a "$PH"; }
[ -f RESULT ] && grep -q PASS RESULT && { ph "already PASS, refusing rerun"; exit 0; }

mkdir -p data
cat > data/bitcoin.conf <<CONF
# core-bench on /mnt/2tbssd $(ts)
server=1
port=$P2P
rpcport=$RPC
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
dbcache=8192
par=8
maxconnections=64
CONF
BIN=$DEST/core/bin/bitcoind
CLI="$DEST/core/bin/bitcoin-cli -datadir=$DEST/data"
ph "START host=$(hostname) kernel=$(uname -r) version=$($BIN --version | head -1)"
T0=$(date +%s); echo "$T0" > epoch.start
ph "DAEMON start epoch=$T0"
setsid nohup nice -n 10 ionice -c3 "$BIN" -datadir="$DEST/data" > console.log 2>&1 < /dev/null &
echo $! > daemon.pid; sleep 5
kill -0 "$(cat daemon.pid)" 2>/dev/null || { ph "FAIL daemon exited at once (console.log)"; echo FAIL > RESULT; exit 1; }
ph "DAEMON pid=$(cat daemon.pid)"
# RPC readiness
while :; do
  if $CLI getblockcount >/dev/null 2>&1; then
    h=$($CLI getblockcount); ph "RPC_READY height=$h elapsed=$(( $(date +%s)-T0 ))s"; break
  fi
  kill -0 "$(cat daemon.pid)" 2>/dev/null || { ph "FAIL daemon died before RPC"; echo FAIL > RESULT; exit 1; }
  sleep 5
done
# inbound P2P readiness (stranger handshake with Core's own magic)
MAGIC=f9beb4d9
while :; do
  out=$(timeout 20 python3 /storage/bitcoinmachinecode/src/validation/p2p_inbound_probe.py 127.0.0.1 $P2P $MAGIC 2>&1)
  echo "$out" | grep -qiE 'verack' && { ph "P2P_INBOUND_OK elapsed=$(( $(date +%s)-T0 ))s"; break; }
  kill -0 "$(cat daemon.pid)" 2>/dev/null || { ph "daemon died during P2P probe"; echo FAIL > RESULT; exit 1; }
  sleep 60
done
while :; do
  sleep 600
  info=$($CLI getblockchaininfo 2>/dev/null)
  h=$(echo "$info" | python3 -c "import sys,json; print(json.load(sys.stdin).get('blocks',0))" 2>/dev/null || echo 0)
  vbf=$(echo "$info" | python3 -c "import sys,json; print(json.load(sys.stdin).get('verificationprogress',0))" 2>/dev/null || echo 0)
  headers=$(echo "$info" | python3 -c "import sys,json; print(json.load(sys.stdin).get('headers',0))" 2>/dev/null || echo 0)
  du=$(du -sh data 2>/dev/null | cut -f1); rss=$(ps -o rss= -p "$(cat daemon.pid)" 2>/dev/null | awk '{printf "%.1fG", $1/1048576}')
  theirs=$($ORACLE getblockcount 2>/dev/null)
  echo "$(ts) blocks=$h headers=$headers vbf=$vbf disk=$du rss=$rss oracle=$theirs" >> "$PROG"
  if ! kill -0 "$(cat daemon.pid)" 2>/dev/null; then ph "FAIL daemon died at blocks=$h"; echo FAIL > RESULT; exit 1; fi
  if [ "${h:-0}" -ge $(( ${theirs:-99999999} - 1 )) ] && [ -n "$theirs" ] && python3 -c "import sys; sys.exit(0 if float('$vbf')>0.9999 else 1)"; then
    ph "TIP reached: ours=$h oracle=$theirs vbf=$vbf elapsed=$(( $(date +%s)-T0 ))s"
    break
  fi
done
sleep 60
OM=$($CLI gettxoutsetinfo 2>/dev/null | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['muhash'], r['txouts'])" 2>/dev/null)
H=$($CLI getblockcount)
CM=$($ORACLE gettxoutsetinfo muhash "$H" 2>/dev/null | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['muhash'], r['txouts'])" 2>/dev/null)
ph "MUHASH h=$H ours=$OM oracle=$CM"
[ "$OM" = "$CM" ] && { ph "PASS muhash identical at $H"; echo "PASS $H" > RESULT; } || { ph "FAIL muhash differs"; echo FAIL > RESULT; }
$CLI getblockchaininfo > rpc_getblockchaininfo.json 2>&1
$CLI getnetworkinfo > rpc_getnetworkinfo.json 2>&1
ph "END elapsed=$(( $(date +%s)-T0 ))s"
