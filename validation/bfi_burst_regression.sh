#!/usr/bin/env bash
# bfi_burst_regression.sh -- the adopt gate must judge the gap against the
# CHAIN TIP, not the height of the block being connected.
#
# The daemon replays a catch-up BURST by looping h from last_seen_tip+1. On a
# boot with no UTXO state that loop starts at h=1 while the store is already
# at the real tip. The gate used to compare h - n, which for a partially
# built index (n records, n > h) goes NEGATIVE and adopts at ANY real gap --
# then the gap close outruns the undo window and the index is CLOSED until
# build_block_filters is re-run. That is the worst case for an unattended
# overnight backfill, so it gets a regression test.
#
# Repro, deterministic (no timing race):
#   1. sync a chain, build a PARTIAL filter index (n records)
#   2. stop the node and delete its UTXO state, so the next boot replays
#      the whole chain as one burst starting at h=1 with h < n
#   3. boot: the gate must DECLINE (real gap >> 144), not adopt at "tip 1"
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-source/build/bin}
WT=${WT:-${TMPDIR:-/tmp}/bmc-wt-adoptgate}
BMC_BIN=${BMC_BIN:-$WT/asm/daemon/bitcoind}
BUILDER=${BUILDER:-$WT/asm/daemon/build_block_filters}
TXIBUILD=${TXIBUILD:-$WT/asm/daemon/build_tx_index}
WALLET_CLI=${WALLET_CLI:-$WT/asm/daemon/wallet_cli}
WORK=${TMPDIR:-/tmp}/bmc-bfi-burst-$$
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
CORE_P2P=19744; CORE_RPC=19760; BMC_P2P=19755; BMC_RPC=19746
FAILURES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; }
cleanup(){ for p in ${BMC_PIDS:-} ${CORE_PID:-}; do kill "$p" 2>/dev/null; done
           sleep 2; for p in ${BMC_PIDS:-}; do kill -9 "$p" 2>/dev/null; done
           [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmc(){ local m=$1; shift; local p=${1:-[]}
  curl -s --user e2e:e2epw -H 'content-type:text/plain' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":$p}" http://127.0.0.1:$BMC_RPC/; }
res(){ python3 -c "import sys,json;d=json.load(sys.stdin);sys.exit('RPC error') if d.get('error') else print(d['result'])"; }
bmch(){ bmc getblockcount | res 2>/dev/null || echo 0; }
idxcount(){ python3 -c "
import os;p='$BMC_DIR/regtest/bfilters.idx'
print((os.path.getsize(p)-48)//48 if os.path.exists(p) else -1)"; }
start_bmc(){ ( cd /storage/bitcoinmachinecode/asm && nohup "$BMC_BIN" serve "$BMC_DIR" >> "$1" 2>&1 & ); sleep 12
             BMC_PIDS=$(pgrep -f "serve $BMC_DIR" | tr '\n' ' '); }
stop_bmc(){ for p in $BMC_PIDS; do kill "$p" 2>/dev/null; done; sleep 3
            for p in $BMC_PIDS; do kill -9 "$p" 2>/dev/null; done; BMC_PIDS=""; sleep 1; }

echo "== setup =="
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do
  ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }
done
mkdir -p "$CORE_DIR" "$BMC_DIR/regtest"
printf 'regtest=1\n[regtest]\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=1\nlistenonion=0\nfallbackfee=0.0001\nblockfilterindex=1\n' \
  $CORE_P2P $CORE_RPC > "$CORE_DIR/bitcoin.conf"
printf 'chain=regtest\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nconnect=127.0.0.1:%s\n' \
  $BMC_P2P $BMC_RPC $CORE_P2P > "$BMC_DIR/bitcoin.conf"
"$CORE_BIN/bitcoind" -datadir="$CORE_DIR" -daemon >/dev/null 2>&1
for i in $(seq 30); do core getblockcount >/dev/null 2>&1 && break; sleep 1; done
CORE_PID=$(cat "$CORE_DIR/regtest/bitcoind.pid")
mkdir -p "$WORK/wgen/data"; ( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 )
cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat" || exit 2
core createwallet e2ecore >/dev/null 2>&1; CADDR=$(core -rpcwallet=e2ecore getnewaddress)
core -rpcwallet=e2ecore generatetoaddress 500 "$CADDR" >/dev/null
TIP=$(core getblockcount)
start_bmc "$WORK/bmc.log"
for i in $(seq 90); do [ "$(bmch)" = "$TIP" ] && break; sleep 2; done
[ "$(bmch)" = "$TIP" ] || { echo "bmc never synced to $TIP"; exit 2; }
for i in $(seq 60); do grep -q "now at height $TIP" "$WORK/bmc.log" && break; sleep 1; done
echo "  synced and drained to $TIP"

echo "== build a PARTIAL index, then force a from-scratch replay burst =="
"$TXIBUILD" "$BMC_DIR/regtest" >/dev/null 2>&1
"$BUILDER" "$BMC_DIR/regtest" $((TIP-300)) >"$WORK/build.log" 2>&1 || { echo "builder failed"; tail -3 "$WORK/build.log"; exit 2; }
N=$(idxcount); echo "  index has $N records; real tip $TIP (real gap $((TIP-N+1)))"
stop_bmc
# drop UTXO state ONLY -- the block archive stays, so the next boot has the
# full chain in the store but must replay it from height 1 as one burst.
rm -f "$BMC_DIR/regtest/utxo_applied_height.dat" "$BMC_DIR/regtest/utxo.dat" \
      "$BMC_DIR/regtest/utxo_manifest.dat" "$BMC_DIR/regtest/index.dat"
: > "$WORK/bmc2.log"
start_bmc "$WORK/bmc2.log"
for i in $(seq 90); do grep -q "now at height $TIP" "$WORK/bmc2.log" && break; sleep 2; done
sleep 3

echo "== the gate must have judged against the TIP, not h =="
if grep -qE "ADOPTED at [0-9]+ records \(tip (0|1|2|3|[1-9][0-9]?)\)" "$WORK/bmc2.log"; then
  fail "adopted during the burst against a low h: $(grep -m1 'ADOPTED at' "$WORK/bmc2.log" | sed 's/^.*\[bfilter\] //')"
elif grep -q "ADOPTED at" "$WORK/bmc2.log"; then
  ok "adopted, but against the real tip: $(grep -m1 'ADOPTED at' "$WORK/bmc2.log" | sed 's/^.*\[bfilter\] //')"
  fail "it should not have adopted at all -- real gap was $((TIP-N+1)) > 144"
else
  ok "declined through the whole burst: $(grep -m1 'waiting for the backfill' "$WORK/bmc2.log" | sed 's/^.*\[bfilter\] //')"
fi
if grep -q "gap close FAILED" "$WORK/bmc2.log"; then
  fail "index was CLOSED by a failed gap close -- $(grep -m1 'gap close FAILED' "$WORK/bmc2.log" | sed 's/^.*\[bfilter\] //')"
else
  ok "index never closed by a failed gap close"
fi
N2=$(idxcount)
[ "$N2" = "$N" ] && ok "partial index left intact at $N records (builder can still resume)" \
                 || fail "index changed $N -> $N2 during the burst"
echo
[ $FAILURES -eq 0 ] && echo "PASS: burst does not trigger premature adoption ($FAILURES failures)" || echo "FAILURES: $FAILURES"
exit $FAILURES
