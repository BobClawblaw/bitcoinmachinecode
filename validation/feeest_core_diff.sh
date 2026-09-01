#!/bin/bash
# validation/feeest_core_diff.sh -- fee estimation differential against Bitcoin Core.
#
# Runs a scratch regtest Core and this node (connected to Core over P2P, so
# both see the SAME transactions and the SAME blocks in the same order),
# feeds Core's wallet transactions at a fixed feerate schedule, mines each
# feerate class after its own delay with `generateblock` (explicit tx lists,
# so confirmation profiles are deterministic), and compares
# estimatesmartfee (economical + conservative) and estimaterawfee for a set
# of targets at several checkpoints. Core is the reference; any difference is
# printed as a FAIL with both JSON bodies.
#
# Usage: validation/feeest_core_diff.sh [rounds=60]     (KEEP=1 keeps the work dir)
set -u
ROUNDS=${1:-60}
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-source/build-zmq/bin}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BMC_BIN=${BMC_BIN:-$ROOT/asm/daemon/bitcoind}
WALLET_CLI=${WALLET_CLI:-$ROOT/asm/daemon/wallet_cli}
WORK=${WORK:-${CLAUDE_JOB_DIR:-/tmp}/tmp/fee/diff-$$}
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
CORE_P2P=19744; CORE_RPC=19760; BMC_P2P=19755; BMC_RPC=19746
FAILURES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; }
cleanup(){ core stop >/dev/null 2>&1; for p in ${BMC_PIDS:-} ${CORE_PID:-}; do kill "$p" 2>/dev/null; done
           sleep 2; for p in ${BMC_PIDS:-}; do kill -9 "$p" 2>/dev/null; done
           [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
corew(){ core -rpcwallet=fee "$@"; }
bmc(){ local m=$1; shift; local p=${1:-[]}
  curl -s --user e2e:e2epw -H 'content-type:text/plain' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":$p}" http://127.0.0.1:$BMC_RPC/; }
res(){ python3 -c "import sys,json;d=json.load(sys.stdin);sys.exit('RPC error: '+json.dumps(d['error'])) if d.get('error') else print(json.dumps(d['result']) if not isinstance(d['result'],(int,str)) else d['result'])"; }
bmch(){ bmc getblockcount | res 2>/dev/null || echo 0; }
bmc_pids(){ for p in /proc/[0-9]*; do [ "$(readlink $p/exe 2>/dev/null)" = "$BMC_BIN" ] || continue; grep -q -- "$BMC_DIR" $p/cmdline 2>/dev/null && echo ${p#/proc/}; done | tr '\n' ' '; }

echo "== setup (rounds=$ROUNDS) =="
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do
  ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }
done
mkdir -p "$CORE_DIR" "$BMC_DIR/regtest"
cat > "$CORE_DIR/bitcoin.conf" <<EOC
regtest=1
[regtest]
port=$CORE_P2P
rpcport=$CORE_RPC
rpcuser=e2e
rpcpassword=e2epw
listen=1
listenonion=0
fallbackfee=0.0001
dnsseed=0
EOC
cat > "$BMC_DIR/bitcoin.conf" <<EOC
chain=regtest
port=$BMC_P2P
rpcport=$BMC_RPC
rpcuser=e2e
rpcpassword=e2epw
connect=127.0.0.1:$CORE_P2P
EOC
"$CORE_BIN/bitcoind" -datadir="$CORE_DIR" -daemon >/dev/null 2>&1
for i in $(seq 30); do core getblockcount >/dev/null 2>&1 && break; sleep 1; done
CORE_PID=$(cat "$CORE_DIR/regtest/bitcoind.pid"); echo "  core up (pid $CORE_PID)"
mkdir -p "$WORK/wgen/data"; ( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 )
cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat" 2>/dev/null
( cd "$ROOT/asm" && nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 & )
for i in $(seq 30); do grep -q 'JSON-RPC server' "$WORK/bmc.log" && break; sleep 1; done
BMC_PIDS=$(bmc_pids)
grep -q 'JSON-RPC server' "$WORK/bmc.log" || { echo "bmc RPC never came up"; sed -n '1,40p' "$WORK/bmc.log"; exit 2; }
grep -q '\[feeest\] estimator' "$WORK/bmc.log" && ok "bmc up (pids $BMC_PIDS): $(grep -o '\[feeest\] estimator[^(]*' "$WORK/bmc.log" | head -1)" || fail "no [feeest] estimator line in the boot log"

echo "== mature coins on both nodes =="
core createwallet fee >/dev/null 2>&1
CADDR=$(corew getnewaddress)
corew generatetoaddress 200 "$CADDR" >/dev/null
TIP=$(core getblockcount)
for i in $(seq 90); do [ "$(bmch)" = "$TIP" ] && break; sleep 2; done
[ "$(bmch)" = "$TIP" ] || { echo "bmc never synced to $TIP (at $(bmch))"; exit 2; }
ok "both at height $TIP"

# feerate schedule (sat/vB -> confirmed after N blocks); every round sends one tx per class
python3 - "$WORK" <<'PY'
import json,sys
sched=[(40,1),(25,1),(15,2),(10,3),(6,4),(4,6),(2.5,9),(1.5,14)]
json.dump(sched,open(sys.argv[1]+'/sched.json','w'))
PY
declare -A DUE   # txid -> round due
wait_mempool_equal(){ for i in $(seq 60); do
    a=$(core getrawmempool | python3 -c 'import sys,json;print(",".join(sorted(json.load(sys.stdin))))')
    b=$(bmc getrawmempool | python3 -c 'import sys,json;d=json.load(sys.stdin);print(",".join(sorted(d["result"] or [])))' 2>/dev/null)
    [ "$a" = "$b" ] && return 0; sleep 1; done
    echo "  (mempools differ: core $(core getrawmempool | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))') vs bmc $(bmc getrawmempool | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["result"] or []))'))"; return 1; }
wait_tip(){ t=$(core getblockcount); for i in $(seq 60); do [ "$(bmch)" = "$t" ] && return 0; sleep 0.5; done; echo "  (bmc tip $(bmch) != core $t)"; return 1; }

compare(){ local tag=$1; local bad=0
  for n in 1 2 3 6 12 24 144; do
    for mode in economical conservative; do
      c=$(core estimatesmartfee $n $mode | python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin),sort_keys=True))')
      b=$(bmc estimatesmartfee "[$n, \"$mode\"]" | python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin)["result"],sort_keys=True))')
      if [ "$c" = "$b" ]; then ok "$tag estimatesmartfee $n $mode: $c"; else fail "$tag estimatesmartfee $n $mode"; echo "      core: $c"; echo "      bmc : $b"; bad=1; fi
    done
    c=$(core estimaterawfee $n | python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin),sort_keys=True))')
    b=$(bmc estimaterawfee "[$n]" | python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin)["result"],sort_keys=True))')
    if [ "$c" = "$b" ]; then ok "$tag estimaterawfee $n: identical ($(echo "$c" | wc -c) bytes)"; else fail "$tag estimaterawfee $n"; echo "      core: $c"; echo "      bmc : $b"; bad=1; fi
  done
  return $bad; }

echo "== $ROUNDS rounds: 8 txs per round, confirmed on the schedule =="
ADDR=$(corew getnewaddress)
for r in $(seq 1 $ROUNDS); do
  txids=""
  for pair in "40 1" "25 1" "15 2" "10 3" "6 4" "4 6" "2.5 9" "1.5 14"; do
    set -- $pair; fr=$1; delay=$2
    t=$(corew send "[{\"$ADDR\":0.001}]" null unset $fr | python3 -c 'import sys,json;print(json.load(sys.stdin)["txid"])' 2>/dev/null)
    [ -n "$t" ] || { fail "round $r: send at $fr sat/vB failed"; continue; }
    # hand the same bytes to our node directly (P2P relay from Core to an inbound
    # peer trickles over tens of seconds); the P2P copy then arrives as "known"
    hex=$(corew gettransaction $t | python3 -c 'import sys,json;print(json.load(sys.stdin)["hex"])')
    bmc sendrawtransaction "[\"$hex\"]" | grep -q "\"result\":\"$t\"" || fail "round $r: bmc sendrawtransaction of $t ($fr sat/vB): $(bmc sendrawtransaction "[\"$hex\"]" | cut -c1-160)"
    DUE[$t]=$((r+delay)); txids="$txids $t"
  done
  wait_mempool_equal || fail "round $r: mempools never matched before mining"
  due=""; for t in "${!DUE[@]}"; do [ "${DUE[$t]}" -le "$r" ] && due="$due \"$t\"" && unset DUE[$t]; done
  core generateblock "$CADDR" "[$(echo $due | sed 's/ /,/g')]" >/dev/null || fail "round $r: generateblock"
  wait_tip || fail "round $r: bmc did not connect the block"
  wait_mempool_equal || fail "round $r: mempools differ after the block"
  case $r in 10|20|40|60|80|100) echo "-- checkpoint round $r (height $(core getblockcount)) --"; compare "r$r";; esac
done
[ $((ROUNDS % 20)) -ne 0 ] && { echo "-- final (height $(core getblockcount)) --"; compare "final"; }

echo "== persistence: clean stop writes fee_estimates.dat; a restart seeds from it =="
for p in $BMC_PIDS; do kill -TERM $p 2>/dev/null; done
for i in $(seq 30); do [ -z "$(bmc_pids)" ] && break; sleep 1; done
grep -q '\[feeest\] shutdown' "$WORK/bmc.log" && ok "$(grep -o '\[feeest\] shutdown.*' "$WORK/bmc.log" | tail -1)" || fail "no [feeest] shutdown line"
[ -s "$BMC_DIR/regtest/fee_estimates.dat" ] && ok "fee_estimates.dat $(stat -c %s "$BMC_DIR/regtest/fee_estimates.dat") bytes" || fail "fee_estimates.dat missing"
before=$(bmc estimaterawfee "[6]" 2>/dev/null)
( cd "$ROOT/asm" && nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc2.log" 2>&1 & )
for i in $(seq 30); do grep -q 'JSON-RPC server' "$WORK/bmc2.log" && break; sleep 1; done
BMC_PIDS=$(bmc_pids)
grep -q 'seeded from fee_estimates.dat' "$WORK/bmc2.log" && ok "restart: $(grep -o '\[feeest\] estimator[^(]*' "$WORK/bmc2.log" | head -1)" || { fail "restart did not seed from fee_estimates.dat"; grep '\[feeest\]' "$WORK/bmc2.log" | head -3; }
after=$(bmc estimaterawfee "[6]" | python3 -c 'import sys,json;d=json.load(sys.stdin)["result"];print(d.get("long",{}).get("feerate"), d.get("long",{}).get("pass",{}).get("totalconfirmed"))')
ok "after restart estimaterawfee(6).long feerate/totalconfirmed = $after (long horizon carried over)"

echo
[ $FAILURES -eq 0 ] && echo "PASS: fee estimation identical to Bitcoin Core ($FAILURES failures)" || echo "FAILURES: $FAILURES"
exit $FAILURES
