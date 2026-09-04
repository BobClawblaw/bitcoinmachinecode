#!/bin/bash
# core-bench install phase: download Bitcoin Core v31.1 release binaries,
# verify checksum, install into /mnt/2tbssd/core-bench. Timed, logged.
# (v28.1 attempt was aborted per user correction at ~02:41Z; 31.1 is latest.)
set -u
D=/mnt/2tbssd/core-bench
LOG=$D/install.log
BASE=https://bitcoincore.org/bin/bitcoin-core-31.1
TAR=bitcoin-31.1-x86_64-linux-gnu.tar.gz
ts(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
log(){ echo "$(ts) $*" | tee -a "$LOG"; }
cd "$D" || exit 2
rm -f RESULT
log "INSTALL START (v31.1)"
t0=$(date +%s)
curl -sSfL -O "$BASE/$TAR" -O "$BASE/SHA256SUMS" >>"$LOG" 2>&1 \
  || { log "FAIL download"; echo FAIL > RESULT; exit 1; }
log "DOWNLOAD done $(( $(date +%s)-t0 ))s size=$(du -h $TAR | cut -f1)"
t0=$(date +%s)
grep "$TAR" SHA256SUMS | sha256sum -c - >>"$LOG" 2>&1 \
  || { log "FAIL checksum"; echo FAIL > RESULT; exit 1; }
log "CHECKSUM ok $(( $(date +%s)-t0 ))s"
t0=$(date +%s)
tar xzf "$TAR" >>"$LOG" 2>&1 || { log "FAIL extract"; echo FAIL > RESULT; exit 1; }
mv bitcoin-31.1 core >>"$LOG" 2>&1
log "EXTRACT done $(( $(date +%s)-t0 ))s"
core/bin/bitcoind --version >>"$LOG" 2>&1
log "INSTALL COMPLETE"
echo OK > RESULT
