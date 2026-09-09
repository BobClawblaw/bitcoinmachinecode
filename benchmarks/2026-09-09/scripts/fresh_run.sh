#!/bin/bash
# fresh_run.sh -- a fresh mainnet IBD benchmark for bmc on /mnt/2tbssd (run 19, 2026-09-09).
# Clones the repo at a pinned tag, builds, writes the conf, launches the daemon detached,
# then hands off to bench-repo/scripts/monitor_fixed.sh (phase log, progress, TIP -> muhash vs the oracle).
set -u
TAG=${1:-one-record-per-key-2026-09-09}
BENCH=/mnt/2tbssd/bmc-bench
ORACLE="/storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli -conf=/storage/core-oracle/bitcoin.conf -datadir=/storage/core-oracle"
ts(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
[ -e "$BENCH" ] && { echo "$BENCH exists; a fresh run needs it gone"; exit 2; }
$ORACLE getblockcount >/dev/null 2>&1 || { echo "the Core oracle does not answer; the monitor needs it"; exit 2; }
mkdir -p "$BENCH" && cd "$BENCH" || exit 2
PH=$BENCH/phase.log
ph(){ echo "$(ts) $*" | tee -a "$PH"; }
ph "INSTALL START tag=$TAG"
t0=$(date +%s)
git clone -q --branch "$TAG" https://github.com/BobClawblaw/bitcoinmachinecode.git src > install.log 2>&1 || { ph "FAIL clone"; echo FAIL > RESULT; exit 1; }
ph "CLONE done $(( $(date +%s)-t0 ))s commit=$(git -C src rev-parse --short HEAD)"
t0=$(date +%s)
( cd src/asm && make -j"$(nproc)" -s daemon/bmcbitcoind daemon/bmc_cli ) > build.log 2>&1 || { ph "FAIL build (see build.log)"; echo FAIL > RESULT; exit 1; }
ph "BUILD done $(( $(date +%s)-t0 ))s warnings=$(grep -ci warning build.log || true)"
mkdir -p data
cp src/config/bitcoin.sample.conf data/bitcoin.conf
cat >> data/bitcoin.conf <<CONF

# bmc-bench run 19 on /mnt/2tbssd $(ts), tag $TAG
port=8462
rpcport=8461
dbcache=8192
bmc.bootcatchup=0
printtoconsole=1
CONF
ph "CONF port=8462 rpcport=8461 dbcache=8192 bmc.bootcatchup=0"
T0=$(date +%s); echo "$T0" > epoch.start
ph "START host=$(hostname) kernel=$(uname -r) commit=$(git -C src rev-parse --short HEAD) tag=$TAG epoch=$T0"
setsid nohup nice -n 10 ionice -c3 src/asm/daemon/bmcbitcoind serve "$BENCH/data" > console.log 2>&1 < /dev/null &
echo $! > daemon.pid; sleep 5
kill -0 "$(cat daemon.pid)" 2>/dev/null || { ph "FAIL daemon exited at once: $(tail -2 console.log | cut -c1-120)"; echo FAIL > RESULT; exit 1; }
grep -q "no config file" console.log && { ph "FAIL daemon did not find config"; echo FAIL > RESULT; exit 1; }
ph "DAEMON pid=$(cat daemon.pid) $(grep -m1 '\[config\] net' console.log | sed 's/.*net  : //')"
exec bash /mnt/2tbssd/bench-repo/scripts/monitor_fixed.sh
