#!/usr/bin/env bash
# validation/stopatheight_regtest_e2e.sh -- Core's -stopatheight, end to end
# against a real Bitcoin Core v31.1 on regtest.
#
# Core requests a clean shutdown once the connected tip reaches the height
# (KernelNotifications::blockTip, index.nHeight >= m_stop_at_height). bmc only
# clamped its download span, so it reached the height and kept running. This
# checks the behaviour, with Core as the reference on the same chain:
#   1. a fresh bmc with stopatheight=S syncs from Core (tip above S) and EXITS,
#      its connected tip at or above S (Core: "blocks after target height may
#      be processed during shutdown") and below Core's tip;
#   2. a fresh Core with -stopatheight=S does the same (the reference);
#   3. bmc restarted on that datadir with stopatheight below its tip exits at
#      startup -- measured on v31.1 2026-10-01: Core does, before any block;
#   4. without the option bmc stays up and syncs to Core's tip.
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-v31.1/bin}
ROOT=${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
BMC_BIN=${BMC_BIN:-$ROOT/asm/daemon/bmcbitcoind}
WORK=${WORK:-${CLAUDE_JOB_DIR:-/tmp}/tmp/stopatheight/e2e-$$}
# Core binds an onion listener on P2P+1 even with listenonion=0 and no bind=,
# so nothing may sit on a Core P2P port + 1
PB=${PORT_BASE:-21960}; CORE_P2P=$((PB+0)); CORE_RPC=$((PB+2)); BMC_P2P=$((PB+4)); BMC_RPC=$((PB+5)); REF_P2P=$((PB+6)); REF_RPC=$((PB+8))
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc; REF_DIR=$WORK/ref
STOP=${STOP:-25}; MINE=${MINE:-40}
FAILURES=0; PASSES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; PASSES=$((PASSES+1)); }
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
ref(){ "$CORE_BIN/bitcoin-cli" -datadir="$REF_DIR" -rpcport=$REF_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmc(){ curl -s -m 10 --user e2e:e2epw -H 'content-type:text/plain' --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$1\",\"params\":${2:-[]}}" http://127.0.0.1:$BMC_RPC/; }
bmch(){ bmc getblockcount | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"])' 2>/dev/null || echo -1; }
BMC_PID=""
bmc_stop(){ [ -n "$BMC_PID" ] && kill "$BMC_PID" 2>/dev/null; for i in $(seq 30); do [ -n "$BMC_PID" ] && kill -0 "$BMC_PID" 2>/dev/null || break; sleep 1; done; BMC_PID=""; }
cleanup(){ bmc_stop; core stop >/dev/null 2>&1; ref stop >/dev/null 2>&1; sleep 2; [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC $REF_P2P $REF_RPC; do ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }; done
mkdir -p "$CORE_DIR" "$BMC_DIR" "$REF_DIR"

cat > "$CORE_DIR/bitcoin.conf" <<EOC
regtest=1
[regtest]
port=$CORE_P2P
rpcport=$CORE_RPC
rpcuser=e2e
rpcpassword=e2epw
listen=1
listenonion=0
EOC
cat > "$REF_DIR/bitcoin.conf" <<EOC
regtest=1
[regtest]
port=$REF_P2P
rpcport=$REF_RPC
rpcuser=e2e
rpcpassword=e2epw
listenonion=0
connect=127.0.0.1:$CORE_P2P
EOC
write_bmc_conf(){   # $1 = extra line
cat > "$BMC_DIR/bitcoin.conf" <<EOC
chain=regtest
printtoconsole=1
# network-specific keys apply on regtest only inside [regtest] (Core's rule)
[regtest]
port=$BMC_P2P
rpcport=$BMC_RPC
rpcuser=e2e
rpcpassword=e2epw
connect=127.0.0.1:$CORE_P2P
listenonion=0
$1
EOC
}
# start bmc; $1 = log name. Sets BMC_PID (the serve process).
bmc_start(){
  ( cd "$ROOT/asm" && exec "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc-$1.log" 2>&1 ) &
  BMC_PID=$!
}
# wait up to $1 s for bmc to exit; sets RC to its exit status or "running".
# Not called as $(...): wait only reaps a child of THIS shell.
bmc_wait_exit(){
  local i
  for i in $(seq "$1"); do kill -0 "$BMC_PID" 2>/dev/null || break; sleep 1; done
  if kill -0 "$BMC_PID" 2>/dev/null; then RC=running; else wait "$BMC_PID" 2>/dev/null; RC=$?; fi
}

"$CORE_BIN/bitcoind" -datadir="$CORE_DIR" -daemon >/dev/null 2>&1
for i in $(seq 40); do core getblockcount >/dev/null 2>&1 && break; sleep 1; done
core getblockcount >/dev/null 2>&1 || { echo "core never came up"; exit 2; }
core generatetodescriptor "$MINE" 'raw(51)' >/dev/null
CT=$(core getblockcount)
echo "== Core at $CT; stopatheight=$STOP"

echo "== 1. a fresh bmc with stopatheight=$STOP exits once its tip reaches it"
write_bmc_conf "stopatheight=$STOP"
bmc_start fresh
bmc_wait_exit 120
if [ "$RC" = running ]; then
  fail "bmc still running 120 s after start (tip $(bmch), Core $CT)"; bmc_stop
else
  ok "bmc exited (status $RC)"
  [ "$RC" = 0 ] && ok "...with status 0, a clean shutdown" || fail "exit status $RC, not 0"
  grep -aq "stopatheight=$STOP reached" "$WORK/bmc-fresh.log" \
    && ok "it logged the reason: $(grep -a "stopatheight=$STOP reached" "$WORK/bmc-fresh.log" | head -1 | cut -c25-)" \
    || fail "no 'stopatheight=$STOP reached' line in the log"
  # the CONNECTED tip at exit (the last apply), which is what Core's rule is
  # about -- the shutdown line's tip= is the stored archive tip
  STIP=$(grep -a 'updating utxo: applied' "$WORK/bmc-fresh.log" | tail -1 | sed -n 's/.*now at height \([0-9]*\).*/\1/p')
  [ -n "$STIP" ] && [ "$STIP" -ge "$STOP" ] && [ "$STIP" -lt "$CT" ] \
    && ok "stopped at tip $STIP: at or above $STOP and short of Core's $CT" \
    || fail "stopped at tip '${STIP:-?}' (want $STOP <= tip < $CT)"
  # Core overshoots by what is in flight when the shutdown lands (one block
  # here); the leg passes stop at the height, so ours should be as tight
  [ -n "$STIP" ] && [ "$STIP" -le $((STOP + 2)) ] \
    && ok "no more than 2 blocks past the height (Core's own overshoot is ~1)" \
    || fail "stopped ${STIP:-?} -- more than 2 blocks past $STOP"
fi

echo "== 2. the reference: a fresh Core with -stopatheight=$STOP"
"$CORE_BIN/bitcoind" -datadir="$REF_DIR" -stopatheight="$STOP" -daemon >/dev/null 2>&1
for i in $(seq 120); do sleep 1; ref getblockcount >/dev/null 2>&1 || { [ $i -gt 3 ] && break; }; done
if ref getblockcount >/dev/null 2>&1; then fail "Core with -stopatheight still running after 120 s"; ref stop >/dev/null 2>&1
else
  RT=$(grep -a 'UpdateTip' "$REF_DIR/regtest/debug.log" | tail -1 | sed -n 's/.*height=\([0-9]*\).*/\1/p')
  ok "Core exited at tip ${RT:-?} (ours: ${STIP:-?})"
fi

echo "== 3. restarted with stopatheight below its tip: exits at startup, as Core does"
write_bmc_conf "stopatheight=10"
bmc_start restart
bmc_wait_exit 60
[ "$RC" != running ] && ok "bmc exited at startup (status $RC)" || { fail "bmc kept running with its tip past stopatheight=10"; bmc_stop; }
grep -aq 'stopatheight=10 reached' "$WORK/bmc-restart.log" && ok "...for that reason" || fail "no 'stopatheight=10 reached' line"

echo "== 4. without the option it stays up and syncs to Core's tip"
write_bmc_conf ""
bmc_start plain
for i in $(seq 90); do [ "$(bmch)" = "$CT" ] && break; sleep 1; done
[ "$(bmch)" = "$CT" ] && ok "bmc synced to $CT" || fail "bmc at $(bmch), Core $CT"
sleep 3; kill -0 "$BMC_PID" 2>/dev/null && ok "...and is still running" || fail "bmc exited without stopatheight"

echo
if [ "$FAILURES" -eq 0 ]; then echo "ALL PASS ($PASSES checks)"; exit 0; fi
echo "FAILURES: $FAILURES ($PASSES ok)"; exit 1
