#!/bin/bash
# Monitor the fixed-binary bmc run (daemon relaunched manually; no monitor
# was alive). Same contract as run_fixed.sh: phase log, progress, TIP ->
# muhash parity vs the oracle.
set -u
BENCH=/mnt/2tbssd/bmc-bench
SRC=$BENCH/src
ORACLE="/storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli -conf=/storage/core-oracle/bitcoin.conf -datadir=/storage/core-oracle"
PH=$BENCH/phase.log
ts(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
ph(){ echo "$(ts) $*" | tee -a "$PH"; }
cd "$BENCH" || exit 2
rm -f RESULT
# fixed-run epoch = the manual relaunch at 03:56:0x (console.log start line)
T0=$(date -d "$(grep -m1 'LOG START' console.log | sed 's/.*LOG START: //;s/ UTC//')" +%s 2>/dev/null || stat -c %Y console.log)
ph "MONITOR attached pid=$(cat daemon.pid) epoch=$T0"
# RPC readiness probe (cookie appears once the serve parent binds it)
while :; do
  sleep 300
  kill -0 "$(cat daemon.pid)" 2>/dev/null || { ph "FAIL bmc daemon died (console tail: $(tail -1 console.log | cut -c1-80))"; echo FAIL > RESULT; exit 1; }
  bad=$(grep -E 'FATAL|HALTED|SEGV' console.log | grep -vc '\[reorg\]')
  hb=$(grep '\[dl\] heartbeat' console.log | tail -1 | sed 's/.*heartbeat: //')
  avg=$(grep '\[dlc\] -- average' console.log | tail -1 | sed 's/.*start: //')
  du=$(du -sh data 2>/dev/null | cut -f1); rss=$(ps -o rss= -p "$(cat daemon.pid)" | awk '{printf "%.1fG",$1/1048576}')
  echo "$(ts) hb='$hb' avg='$avg' disk=$du rss=$rss bad=$bad" >> progress.log
  [ "${bad:-0}" != "0" ] && { ph "FAIL bad markers"; echo FAIL > RESULT; exit 1; }
  for m in 'cookie authentication' 'utxo_live\] init' 'coinstats\] adopted' '\[dl\] heartbeat'; do
    l=$(grep -m1 -E "$m" console.log | cut -c1-140); [ -n "$l" ] && ! grep -qF "MON: $m" "$PH" && ph "MON: PHASE first '$m': $l elapsed=$(( $(date +%s)-T0 ))s"
  done
  if [ -n "$hb" ]; then
    ours=$(echo "$hb" | grep -oE 'tip=[0-9]+' | cut -d= -f2); theirs=$($ORACLE getblockcount 2>/dev/null)
    if [ -n "$ours" ] && [ -n "$theirs" ] && [ "$ours" -ge $((theirs-1)) ]; then
      ph "TIP reached: ours=$ours oracle=$theirs fixed-run-elapsed=$(( $(date +%s)-T0 ))s"
      sleep 120
      O=$($SRC/asm/daemon/bitcoin_cli -datadir=$BENCH/data gettxoutsetinfo muhash 2>/dev/null)
      H=$(echo "$O" | python3 -c "import sys,json; print(json.load(sys.stdin)['height'])" 2>/dev/null)
      OM=$(echo "$O" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['muhash'], r['txouts'])" 2>/dev/null)
      CM=$($ORACLE gettxoutsetinfo muhash "$H" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['muhash'], r['txouts'])" 2>/dev/null)
      ph "MUHASH h=$H ours=$OM oracle=$CM"
      if [ "$OM" = "$CM" ]; then ph "PASS muhash identical at $H"; echo "PASS $H" > RESULT
      else ph "FAIL muhash differs at $H"; echo FAIL > RESULT; fi
      $SRC/asm/daemon/bitcoin_cli -datadir=$BENCH/data getblockchaininfo > rpc_getblockchaininfo.json 2>&1
      $SRC/asm/daemon/bitcoin_cli -datadir=$BENCH/data getnetworkinfo > rpc_getnetworkinfo.json 2>&1
      # P2P inbound probe: stranger handshake + getheaders answer
      out=$(timeout 20 python3 $SRC/validation/p2p_inbound_probe.py 127.0.0.1 8462 f9beb4d9 2>&1 | tail -12)
      ph "P2P inbound probe: $(echo "$out" | grep -icE 'verack|headers') relevant replies"
      ph "MONITOR END elapsed=$(( $(date +%s)-T0 ))s"
      exit 0
    fi
  fi
done
