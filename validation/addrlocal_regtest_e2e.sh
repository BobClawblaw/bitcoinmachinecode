#!/usr/bin/env bash
# addrlocal_regtest_e2e.sh -- getpeerinfo's addrlocal, last_block and
# last_transaction, proven against a REAL Bitcoin Core v31.1.
#
# addrlocal is OUR address as the peer's version message named it (its
# addr_recv). Core only fills addr_recv for a ROUTABLE peer
# (net_processing.cpp PushNodeVersion), so over loopback Core sends an empty
# address and prints no addrlocal itself. Asserted:
#   1. LOOPBACK, both directions with a real Core: the empty addr_recv Core
#      sends leaves our entry with no addrlocal -- what Core would print.
#   2. DIFFERENTIAL: version_addr_recv_peer.py sends the SAME version, with a
#      chosen addr_recv, to Core and to this node. Both must print the same
#      addrlocal: IPv4, compressed IPv6, and an invalid 0.0.0.0 (absent).
#   3. Every entry carries last_block and last_transaction, as Core's do.
# Until 2026-09-18 this node never printed addrlocal (0 of 11 peers on
# mainnet, Core 10 of 10) and omitted the two times at 0.
set -u
CORE_BIN=${CORE_BIN:-/mnt/nvme8tb/core-build/bitcoin-v31.1/build/bin}
BMC_BIN=${BMC_BIN:-/storage/bitcoinmachinecode/asm/daemon/bmcbitcoind}
PEER=${PEER:-/storage/bitcoinmachinecode/validation/version_addr_recv_peer.py}
WORK=${WORK:-/tmp/addrlocal-e2e-$$}
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
CORE_P2P=19944; CORE_RPC=19960; BMC_P2P=19955; BMC_RPC=19946
FAILURES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; }
cleanup(){ for p in ${PROBE_PIDS:-} ${BMC_PID:-} ${CORE_PID:-}; do kill "$p" 2>/dev/null; done
           sleep 2; [ -n "${BMC_PID:-}" ] && kill -9 "$BMC_PID" 2>/dev/null
           [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmc(){ curl -s --user e2e:e2epw -H 'content-type:text/plain' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$1\",\"params\":[]}" http://127.0.0.1:$BMC_RPC/ |
    python3 -c 'import sys,json; print(json.dumps(json.load(sys.stdin)["result"]))' 2>/dev/null; }
# field KEY of the first getpeerinfo entry matching SELECTOR on stdin:
#   out     -- the first outbound entry
#   in      -- the first inbound entry that is not the probe
#   probe   -- the inbound entry whose subver is the probe's
# (python: jq is not installed everywhere)
field(){ python3 -c '
import json,sys
sel, key = sys.argv[1], sys.argv[2]
for p in json.load(sys.stdin):
    probe = p.get("subver") == "/addrlocal-e2e/"
    if (sel == "out" and not p["inbound"]) or (sel == "in" and p["inbound"] and not probe) or (sel == "probe" and probe):
        print(p.get(key, "<absent>")); break
else: print("<no such peer>")' "$@"; }
# wait until SELECTOR has an entry on node $1 (core|bmc)
await(){ for i in $(seq 1 30); do [ "$($1 getpeerinfo 2>/dev/null | field $2 addr)" != "<no such peer>" ] && return 0; sleep 1; done; return 1; }

echo "== setup =="
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do
  ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }
done
mkdir -p "$CORE_DIR" "$BMC_DIR/regtest"
printf 'regtest=1\n[regtest]\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=1\nlistenonion=0\nbind=127.0.0.1\n' \
  $CORE_P2P $CORE_RPC > "$CORE_DIR/bitcoin.conf"
# the network keys go under [regtest]: outside the section the regtest node
# ignores them and comes up on 8333 with dnsseed on
printf 'chain=regtest\n[regtest]\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=1\nconnect=127.0.0.1:%s\n' \
  $BMC_P2P $BMC_RPC $CORE_P2P > "$BMC_DIR/bitcoin.conf"
"$CORE_BIN/bitcoind" -datadir="$CORE_DIR" >/dev/null 2>&1 & CORE_PID=$!
for i in $(seq 1 30); do core getblockcount >/dev/null 2>&1 && break; sleep 1; done
( cd /storage/bitcoinmachinecode/asm && exec "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.out" 2>&1 < /dev/null ) & BMC_PID=$!
for i in $(seq 1 60); do bmc getblockcount >/dev/null && [ -n "$(bmc getblockcount)" ] && break; sleep 1; done

echo "== 1. loopback with a real Core: an empty addr_recv means no addrlocal =="
await core in || { fail "Core never saw this node dial in"; tail -20 "$WORK/bmc.out"; exit 1; }
await bmc out || fail "this node lists no outbound entry for Core"
v=$(bmc getpeerinfo | field out addrlocal)
[ "$v" = "<absent>" ] && ok "outbound: no addrlocal, as Core prints none for an empty addr_recv" || fail "outbound addrlocal is '$v'"
echo "    (Core's own entry for us reads addrlocal=$(core getpeerinfo | field in addrlocal))"
core addnode "127.0.0.1:$BMC_P2P" onetry >/dev/null 2>&1
await bmc in || fail "Core's dial to this node never came up"
v=$(bmc getpeerinfo | field in addrlocal)
[ "$v" = "<absent>" ] && ok "inbound: no addrlocal, as Core prints none for an empty addr_recv" || fail "inbound addrlocal is '$v'"

echo "== 2. differential: the same version, with a chosen addr_recv, to Core and to this node =="
for case in "1.2.3.4 8333 1.2.3.4:8333" "2a01:4f8::1 8333 [2a01:4f8::1]:8333" "0.0.0.0 0 <absent>"; do
  set -- $case; A=$1; P=$2; WANT=$3
  python3 "$PEER" 127.0.0.1 $CORE_P2P fabfb5da "$A" "$P" 20 > "$WORK/probe_core.out" 2>&1 & PC=$!
  python3 "$PEER" 127.0.0.1 $BMC_P2P  fabfb5da "$A" "$P" 20 > "$WORK/probe_bmc.out"  2>&1 & PB=$!
  PROBE_PIDS="$PC $PB"
  await core probe && await bmc probe || fail "a probe never showed up ($(cat "$WORK"/probe_*.out | tr '\n' ' '))"
  C=$(core getpeerinfo | field probe addrlocal); B=$(bmc getpeerinfo | field probe addrlocal)
  [ "$C" = "$WANT" ] && [ "$B" = "$C" ] && ok "addr_recv $A port $P: Core '$C', this node '$B'" \
    || fail "addr_recv $A port $P: Core '$C', this node '$B', expected '$WANT'"
  kill $PC $PB 2>/dev/null; wait $PC $PB 2>/dev/null; PROBE_PIDS=""
  for i in $(seq 1 15); do [ "$(bmc getpeerinfo | field probe addr)" = "<no such peer>" ] && break; sleep 1; done
done

echo "== 3. last_block and last_transaction on every entry =="
bmc getpeerinfo > "$WORK/gpi.json"
python3 - "$WORK/gpi.json" <<'PY' && ok "every entry carries both, as integers" || fail "an entry lacks last_block or last_transaction"
import json,sys
peers=json.load(open(sys.argv[1]))
bad=[p["addr"] for p in peers if not all(isinstance(p.get(k), int) for k in ("last_block","last_transaction"))]
print("    %d entries, %d without both" % (len(peers), len(bad)))
sys.exit(1 if bad or not peers else 0)
PY

echo
[ $FAILURES = 0 ] && echo "ALL CHECKS PASSED" || echo "$FAILURES FAILURE(S)"
exit $([ $FAILURES = 0 ] && echo 0 || echo 1)
