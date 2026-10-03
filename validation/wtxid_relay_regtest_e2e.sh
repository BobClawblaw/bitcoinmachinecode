#!/usr/bin/env bash
# validation/wtxid_relay_regtest_e2e.sh -- BIP339 wtxid relay, end to end
# against real Bitcoin Core v31.1 nodes on regtest (2026-10-03).
#
# Core drops MSG_TX invs from a peer that negotiated wtxidrelay
# (net_processing: "Ignore INVs that don't match wtxidrelay setting"). bmc
# sent wtxidrelay but announced by txid, so none of its transactions reached a
# Core peer; on 2026-10-01 it stopped sending wtxidrelay. Now it sends it and
# announces MSG_WTX to a peer that negotiated it. Topology:
#
#     Core A (wallet, listens)  <-- outbound leg --  bmc  <-- inbound --  Core B
#
# B has connect= bmc only, so anything B learns came through bmc. Checks:
#   1. both legs negotiated wtxid relay (bmc's leg log line, wtxid=1; B's
#      inbound connection in bmc's log is checked through behaviour);
#   2. a tx submitted to bmc reaches Core A (bmc's outbound announcer) AND
#      Core B (bmc's inbound announcer, txann.c);
#   3. a tx submitted to Core A reaches bmc (A announces by wtxid, bmc asks by
#      wtxid) and then Core B -- so bmc both received and relayed it.
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-v31.1/bin}
ROOT=${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
BMC_BIN=${BMC_BIN:-$ROOT/asm/daemon/bmcbitcoind}
WORK=${WORK:-${CLAUDE_JOB_DIR:-/tmp}/tmp/wtxid-relay/e2e-$$}
# Core binds an onion listener on P2P+1 even with listenonion=0 and no bind=,
# so nothing may sit on a Core P2P port + 1
PB=${PORT_BASE:-22160}; A_P2P=$((PB+0)); A_RPC=$((PB+2)); BMC_P2P=$((PB+4)); BMC_RPC=$((PB+5)); B_P2P=$((PB+6)); B_RPC=$((PB+8))
A_DIR=$WORK/core-a; B_DIR=$WORK/core-b; BMC_DIR=$WORK/bmc
WAIT=${WAIT:-90}
FAILURES=0; PASSES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; PASSES=$((PASSES+1)); }
ca(){ "$CORE_BIN/bitcoin-cli" -datadir="$A_DIR" -rpcport=$A_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
caw(){ ca -rpcwallet=w "$@"; }
cb(){ "$CORE_BIN/bitcoin-cli" -datadir="$B_DIR" -rpcport=$B_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmc(){ curl -s -m 10 --user e2e:e2epw -H 'content-type:text/plain' --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$1\",\"params\":${2:-[]}}" http://127.0.0.1:$BMC_RPC/; }
res(){ python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["result"] if not d.get("error") else "ERR "+d["error"]["message"])' 2>/dev/null; }
BMC_PID=""
cleanup(){ [ -n "$BMC_PID" ] && kill "$BMC_PID" 2>/dev/null; for i in $(seq 30); do [ -n "$BMC_PID" ] && kill -0 "$BMC_PID" 2>/dev/null || break; sleep 1; done
           cb stop >/dev/null 2>&1; ca stop >/dev/null 2>&1; sleep 2; [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
for port in $A_P2P $A_RPC $BMC_P2P $BMC_RPC $B_P2P $B_RPC; do ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }; done
mkdir -p "$A_DIR" "$B_DIR" "$BMC_DIR"

printf 'regtest=1\n[regtest]\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=1\nlistenonion=0\ndebug=net\nfallbackfee=0.0002\n' $A_P2P $A_RPC > "$A_DIR/bitcoin.conf"
printf 'regtest=1\n[regtest]\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlistenonion=0\nconnect=127.0.0.1:%s\ndebug=net\n' $B_P2P $B_RPC $BMC_P2P > "$B_DIR/bitcoin.conf"
cat > "$BMC_DIR/bitcoin.conf" <<EOC
chain=regtest
printtoconsole=1
[regtest]
port=$BMC_P2P
rpcport=$BMC_RPC
rpcuser=e2e
rpcpassword=e2epw
listen=1
connect=127.0.0.1:$A_P2P
listenonion=0
EOC

"$CORE_BIN/bitcoind" -datadir="$A_DIR" -daemon >/dev/null 2>&1
for i in $(seq 40); do ca getblockcount >/dev/null 2>&1 && break; sleep 1; done
ca getblockcount >/dev/null 2>&1 || { echo "core A never came up"; exit 2; }
caw createwallet w >/dev/null 2>&1 || ca createwallet w >/dev/null
ADDR=$(caw getnewaddress)
caw generatetoaddress 120 "$ADDR" >/dev/null
echo "== Core A at $(ca getblockcount)"

( cd "$ROOT/asm" && exec "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 ) &
BMC_PID=$!
for i in $(seq 120); do [ "$(bmc getblockcount | res)" = "$(ca getblockcount)" ] && break; sleep 1; done
[ "$(bmc getblockcount | res)" = "$(ca getblockcount)" ] || { echo "bmc never synced (tip $(bmc getblockcount | res))"; tail -20 "$WORK/bmc.log"; exit 2; }
"$CORE_BIN/bitcoind" -datadir="$B_DIR" -daemon >/dev/null 2>&1
for i in $(seq 60); do [ "$(cb getblockcount 2>/dev/null)" = "$(ca getblockcount)" ] && break; sleep 1; done
[ "$(cb getblockcount 2>/dev/null)" = "$(ca getblockcount)" ] || { echo "core B never synced through bmc"; exit 2; }
echo "== bmc and Core B at $(cb getblockcount)"
# out of IBD everywhere before relaying: one more block, then wait
caw generatetoaddress 1 "$ADDR" >/dev/null
for i in $(seq 60); do [ "$(cb getblockcount)" = "$(ca getblockcount)" ] && break; sleep 1; done

echo "== 1. wtxid relay negotiated"
L=$(grep -a 'outbound [0-9]* = 127.0.0.1' "$WORK/bmc.log" | grep -a 'addrv2=' | tail -1)   # the leg line names the host without its port
case "$L" in *wtxid=1*) ok "bmc's leg to Core A: wtxid=1 ($(echo "$L" | grep -o 'addrv2=[0-9] wtxid=[0-9]'))";; *) fail "bmc's leg to Core A did not negotiate: ${L:-no leg line}";; esac
grep -aq 'sending wtxidrelay' "$A_DIR/regtest/debug.log" && grep -aq 'received: wtxidrelay' "$A_DIR/regtest/debug.log" \
  && ok "Core A's log: wtxidrelay sent and received" || fail "Core A's debug log does not show wtxidrelay both ways"
grep -aq 'received: wtxidrelay' "$B_DIR/regtest/debug.log" \
  && ok "Core B's log: bmc sent wtxidrelay on B's connection (bmc inbound)" || fail "Core B never received wtxidrelay from bmc"

in_mempool(){ "$@" getmempoolentry "$TXID" >/dev/null 2>&1; }
wait_for(){ # $1 label, rest: cli function
  local label=$1; shift; local t0=$(date +%s)
  for i in $(seq $WAIT); do in_mempool "$@" && { ok "$label (after $(( $(date +%s) - t0 )) s)"; return 0; }; sleep 1; done
  fail "$label: not in its mempool after $WAIT s"; return 1; }

echo "== 2. a tx submitted to bmc reaches Core A (outbound leg) and Core B (inbound)"
RAW=$(caw createrawtransaction "[]" "{\"$(caw getnewaddress)\":1.0}")
RAW=$(caw fundrawtransaction "$RAW" | python3 -c 'import sys,json;print(json.load(sys.stdin)["hex"])')
RAW=$(caw signrawtransactionwithwallet "$RAW" | python3 -c 'import sys,json;print(json.load(sys.stdin)["hex"])')
caw lockunspent false "$(caw decoderawtransaction "$RAW" | python3 -c 'import sys,json;print(json.dumps([{"txid":i["txid"],"vout":i["vout"]} for i in json.load(sys.stdin)["vin"]]))')" >/dev/null
TXID=$(bmc sendrawtransaction "[\"$RAW\"]" | res)
case "$TXID" in ERR*|"") fail "bmc refused the tx: $TXID";; *)
  echo "  submitted $TXID to bmc"
  wait_for "Core A has it -- bmc's outbound MSG_WTX was honoured" ca
  wait_for "Core B has it -- bmc's inbound announcement was honoured" cb ;; esac

echo "== 3. a tx submitted to Core A reaches bmc, then Core B"
TXID=$(caw sendtoaddress "$(caw getnewaddress)" 0.5)
echo "  submitted $TXID to Core A"
t0=$(date +%s); got=0
for i in $(seq $WAIT); do [ "$(bmc getmempoolentry "[\"$TXID\"]" | res | cut -c1-3)" != "ERR" ] && [ -n "$(bmc getmempoolentry "[\"$TXID\"]" | res)" ] && { got=1; break; }; sleep 1; done
[ $got = 1 ] && ok "bmc has it (after $(( $(date +%s) - t0 )) s) -- A announced by wtxid, bmc fetched it" || fail "bmc never got Core A's tx"
wait_for "Core B has it -- relayed onward by bmc" cb

echo
echo "$PASSES passed, $FAILURES failed"
[ $FAILURES = 0 ] && echo "ALL TESTS PASSED" || echo "TESTS FAILED"
exit $FAILURES
