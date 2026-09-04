#!/bin/bash
# bmc-bench install phase: clone from GitHub + build, timed, logged.
# Usage: install_bmc.sh ; run in background.
set -u
D=/mnt/2tbssd/bmc-bench
LOG=$D/install.log
ts(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
log(){ echo "$(ts) $*" | tee -a "$LOG"; }
cd "$D" || exit 2
log "INSTALL START"
t0=$(date +%s)
git clone -q https://github.com/BobClawblaw/bitcoinmachinecode.git src >>"$LOG" 2>&1 \
  || { log "FAIL clone"; echo FAIL > RESULT; exit 1; }
log "CLONE done $(( $(date +%s)-t0 ))s commit=$(git -C src rev-parse --short HEAD)"
t0=$(date +%s)
( cd src/asm && make -j"$(nproc)" -s daemon/bitcoind daemon/bitcoin_cli ) >"$D/build.log" 2>&1 \
  || { log "FAIL build (see build.log)"; echo FAIL > RESULT; exit 1; }
log "BUILD done $(( $(date +%s)-t0 ))s warnings=$(grep -ci warning "$D/build.log" 2>/dev/null || echo 0)"
ls -la src/asm/daemon/bitcoind src/asm/daemon/bitcoin_cli >>"$LOG" 2>&1
log "INSTALL COMPLETE"
echo OK > RESULT
