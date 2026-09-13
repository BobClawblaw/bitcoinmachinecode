#!/bin/bash
# core_bench_attach.sh -- resume monitoring an ALREADY-RUNNING core-bench daemon.
#
# 2026-09-12: run_core_bench.sh wedged in its inbound-P2P readiness loop (it
# pointed at a probe path that does not exist), so the daemon synced for 1h30m
# with nothing recording progress, no tip check and no capstone. This picks the
# run up where the harness abandoned it. It does NOT start or stop the daemon.
set -u
DEST=/mnt/2tbssd/core-bench
cd "$DEST" || exit 2
PH=$DEST/phase.log; PROG=$DEST/progress.log
ORACLE="/storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli -conf=/storage/core-oracle/bitcoin.conf -datadir=/storage/core-oracle"
# rpcclienttimeout=0 means "wait forever". gettxoutsetinfo walks the whole UTXO
# set and can far exceed the 900s default; run 23's capstone reported an EMPTY
# hash and failed for exactly that class of reason. An empty answer must never
# be mistaken for a comparison.
CLI="$DEST/core/bin/bitcoin-cli -datadir=$DEST/data -rpcclienttimeout=0"
ts(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
ph(){ echo "$(ts) $*" | tee -a "$PH"; }
T0=$(cat epoch.start); PID=$(cat daemon.pid)
kill -0 "$PID" 2>/dev/null || { ph "ATTACH FAIL: daemon pid $PID is not running"; exit 1; }
ph "ATTACH monitoring pid=$PID from epoch=$T0 (elapsed already $(( $(date +%s)-T0 ))s)"

# 2026-09-13: this was `...get('$1',0) || echo 0`, which cannot tell "the node
# says 0" from "the RPC is dead" -- the same silent-success shape that made the
# IBD heartbeat log '' for three runs. bench_json_field returns rc 1 and prints
# nothing when the field is absent or the input unreadable, and the tip test
# below answers "cannot tell" separately from "not yet".
. "$(dirname "$0")/lib/ibd_harness_lib.sh"
jget(){ bench_json_field "$(cat)" "$1"; }

while :; do
  info=$($CLI getblockchaininfo 2>/dev/null)
  h=$(echo "$info" | jget blocks); vbf=$(echo "$info" | jget verificationprogress)
  headers=$(echo "$info" | jget headers)
  du=$(du -sh data 2>/dev/null | cut -f1)
  rss=$(ps -o rss= -p "$PID" 2>/dev/null | awk '{printf "%.1fG", $1/1048576}')
  theirs=$($ORACLE getblockcount 2>/dev/null)
  echo "$(ts) blocks=$h headers=$headers vbf=$vbf disk=$du rss=$rss oracle=$theirs elapsed=$(( $(date +%s)-T0 ))s" >> "$PROG"
  kill -0 "$PID" 2>/dev/null || { ph "FAIL daemon died at blocks=$h"; echo FAIL > RESULT; exit 1; }
  bench_tip_reached "$h" "$theirs" "$vbf"; tipres=$?
  if [ $tipres -eq 2 ]; then
      ph "WARN cannot tell whether the tip is reached (ours='$h' oracle='$theirs' vbf='$vbf') -- an unreadable side is not 'not yet'"
  fi
  if [ $tipres -eq 0 ]; then
    ph "TIP reached: ours=$h oracle=$theirs vbf=$vbf elapsed=$(( $(date +%s)-T0 ))s"
    break
  fi
  sleep 600
done

sleep 60
H=$($CLI getblockcount)
ph "CAPSTONE starting gettxoutsetinfo at h=$H (no client timeout; this walks the set)"
OM=""; for try in 1 2 3; do
  OM=$($CLI gettxoutsetinfo 2>>"$PH" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['muhash'], r['txouts'])" 2>/dev/null)
  [ -n "$OM" ] && break
  ph "CAPSTONE our side returned nothing (attempt $try/3); retrying in 120s"
  sleep 120
done
CM=$($ORACLE gettxoutsetinfo muhash "$H" 2>>"$PH" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['muhash'], r['txouts'])" 2>/dev/null)
ph "MUHASH h=$H ours=$OM oracle=$CM"
# An empty side is a harness failure, NOT a pass. Runs before 2026-09-11 compared
# empty to empty, called them equal, and reported nothing.
if [ -z "$OM" ] || [ -z "$CM" ]; then
  ph "FAIL muhash: a side returned no usable hash (ours='$OM' oracle='$CM')"; echo FAIL > RESULT
elif [ "$OM" = "$CM" ]; then
  ph "PASS muhash identical at $H"; echo "PASS $H" > RESULT
else
  ph "FAIL muhash differs at $H"; echo FAIL > RESULT
fi
$CLI getblockchaininfo > rpc_getblockchaininfo.json 2>&1
$CLI getnetworkinfo    > rpc_getnetworkinfo.json 2>&1
$CLI getpeerinfo       > rpc_getpeerinfo.json 2>&1
ph "END elapsed=$(( $(date +%s)-T0 ))s"
