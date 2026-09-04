#!/bin/bash
# 15-min cadence: append a compact status tick to bench.log and push the
# benchmark repo (small delta only when logs actually changed).
set -u
BENCH=/mnt/2tbssd/bmc-bench
REPO=/mnt/2tbssd/bench-repo
ORACLE="/storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli -conf=/storage/core-oracle/bitcoin.conf -datadir=/storage/core-oracle"
ts(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
alive=$(pgrep -c -f "bitcoind serve /mnt" || true)
bmc_avg=$(grep '\[dlc\] -- average' $BENCH/console.log 2>/dev/null | tail -1 | sed 's/.*start: //')
bmc_prog=$(grep '== elapsed' $BENCH/console.log 2>/dev/null | tail -1 | sed -E 's/.*elapsed ([0-9:]+).*overall: ([0-9]+)\/([0-9]+).*/\1 stored \2\/\3/')
bmc_res=$(cat $BENCH/RESULT 2>/dev/null || echo pending)
core_prog=$(tail -1 /mnt/2tbssd/core-bench/progress.log 2>/dev/null)
core_res=$(cat /mnt/2tbssd/core-bench/RESULT 2>/dev/null || echo pending)
oracle=$($ORACLE getblockcount 2>/dev/null)
echo "$(ts) TICK bmc_alive=$alive result=$bmc_res prog='$bmc_prog' avg='$bmc_avg' | core result=$core_res prog='$core_prog' | oracle_tip=$oracle" >> /mnt/2tbssd/bench.log
# sync logs into the repo and push if changed
cp -f /mnt/2tbssd/bench.log $REPO/logs/bench.log
cp -f $BENCH/phase.log $BENCH/progress.log $BENCH/bisect.log $BENCH/floorhunt.log $REPO/logs/ 2>/dev/null
cp -f /mnt/2tbssd/core-bench/phase.log /mnt/2tbssd/core-bench/progress.log $REPO/logs/ 2>/dev/null
cd $REPO
if ! git diff --quiet || [ -n "$(git status --porcelain)" ]; then
  git add -A
  git -c user.name="BobClawblaw" -c user.email="BobClawblaw@users.noreply.github.com" commit -qm "tick: bmc=$bmc_res core=$core_res $(ts)" && git push -q origin master
fi
