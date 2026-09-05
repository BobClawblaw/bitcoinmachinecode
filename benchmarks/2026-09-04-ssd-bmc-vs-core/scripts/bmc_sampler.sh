#!/bin/bash
# bmc log sampler: every 10 min record heartbeat/progress + RPC probe into progress.log
set -u
DEST=/mnt/2tbssd/bmc-bench
cd "$DEST" || exit 2
CLI="src/asm/daemon/bmc_cli -datadir=$DEST/data"
ts(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
while :; do
  sleep 600
  hb=$(grep '\[dl\] heartbeat' console.log 2>/dev/null | tail -1 | sed 's/.*heartbeat: //')
  dlc=$(grep '\[dlc\] -- average' console.log 2>/dev/null | tail -1 | sed 's/.*\[dlc\] //')
  rpc=$($CLI getblockcount 2>/dev/null | tr -d '\n')
  [ -z "$rpc" ] && rpc=no-cookie-yet
  du=$(du -sh data 2>/dev/null | cut -f1)
  rss=$(ps -o rss= -p "$(cat daemon.pid 2>/dev/null)" 2>/dev/null | awk '{printf "%.1fG", $1/1048576}')
  echo "$(ts) hb='$hb' rpc_height=$rpc disk=$du rss=$rss | $dlc" >> progress.log
  kill -0 "$(cat daemon.pid 2>/dev/null)" 2>/dev/null || { echo "$(ts) SAMPLER: daemon gone" >> progress.log; exit 0; }
done
