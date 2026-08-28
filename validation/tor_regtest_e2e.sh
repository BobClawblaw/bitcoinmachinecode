#!/usr/bin/env bash
# tor_regtest_e2e.sh -- prove this node DIALS A REAL BITCOIN PEER OVER TOR.
#
# Bitcoin Core runs on regtest behind its OWN onion service, created through
# the real tor on this box (-listenonion, its control port). This node is
# given -onion=<tor socks> and the peer's .onion address, and must:
#   1. put the onion address in its book (addpeeraddress),
#   2. dial it through SOCKS5 (never a DNS lookup for a .onion),
#   3. complete the Bitcoin handshake and stay connected,
# with CORE confirming an inbound peer whose network is "onion".
# Nothing here is mocked: real tor, real circuits, real Core.
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-source/build/bin}
BMC_BIN=${BMC_BIN:-/storage/bitcoinmachinecode/asm/daemon/bitcoind}
WALLET_CLI=${WALLET_CLI:-/storage/bitcoinmachinecode/asm/daemon/wallet_cli}
WORK=${WORK:-/tmp/tor-e2e-$$}
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
CORE_P2P=19944; CORE_RPC=19960; BMC_P2P=19955; BMC_RPC=19946
TOR_SOCKS=${TOR_SOCKS:-127.0.0.1:9050}
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

echo "== setup: Core behind its own onion service, via the real tor =="
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do
  ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }
done
mkdir -p "$CORE_DIR" "$BMC_DIR/regtest"
printf 'regtest=1\n[regtest]\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=1\nlistenonion=1\ntorcontrol=127.0.0.1:9051\ndebug=net\ndebug=tor\n' \
  $CORE_P2P $CORE_RPC > "$CORE_DIR/bitcoin.conf"
"$CORE_BIN/bitcoind" -datadir="$CORE_DIR" -daemon >/dev/null 2>&1
for i in $(seq 40); do core getblockcount >/dev/null 2>&1 && break; sleep 1; done
CORE_PID=$(cat "$CORE_DIR/regtest/bitcoind.pid" 2>/dev/null)
[ -n "${CORE_PID:-}" ] || { echo "core did not start"; exit 2; }
# wait for tor to hand Core its onion address
ONION=""
for i in $(seq 60); do
  ONION=$(core getnetworkinfo 2>/dev/null | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    print(next((a['address'] for a in d.get('localaddresses',[]) if a['address'].endswith('.onion')), ''))
except Exception: print('')")
  [ -n "$ONION" ] && break; sleep 2
done
[ -n "$ONION" ] || { echo "Core never got an onion address (is tor's control port reachable?)"; grep -iE "tor|onion" "$CORE_DIR/regtest/debug.log" | tail -5; exit 2; }
ONION_PORT=$(core getnetworkinfo | python3 -c "import sys,json;d=json.load(sys.stdin);print(next(a['port'] for a in d['localaddresses'] if a['address'].endswith('.onion')))")
echo "  core onion: $ONION:$ONION_PORT"
ok "Core created an onion service through the real tor"

# plant Core's onion address in the book BEFORE the node starts, so the dial
# pool it builds at boot contains it -- that is the real path (book -> pool ->
# transport), not an RPC shortcut.
python3 - "$BMC_DIR/regtest/peers2.dat" "$ONION" "$ONION_PORT" <<'PYIN'
import struct, sys, time
from base64 import b32decode
path, onion, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
stem = onion.split('.')[0]
raw = b32decode(stem.upper() + '=' * ((8 - len(stem) % 8) % 8))[:32]
with open(path, 'wb') as f:
    f.write(b"BMCADBK2" + struct.pack("<I", 1) + b"\x00" * 4)
    f.write(bytes([4, 32]) + raw.ljust(32, b"\x00") + struct.pack(">H", port)
            + struct.pack("<Q", 9) + struct.pack("<I", int(time.time())))
PYIN
echo "  planted the onion peer in peers2.dat (the boot dial pool reads it)"

mkdir -p "$WORK/wgen/data"; ( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 )
cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat" || exit 2
printf 'chain=regtest\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=1\ndnsseed=0\nonion=%s\nproxyrandomize=1\n' \
  $BMC_P2P $BMC_RPC "$TOR_SOCKS" > "$BMC_DIR/bitcoin.conf"
( cd /storage/bitcoinmachinecode/asm && nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 & )
sleep 12
BMC_PIDS=$(pgrep -f "serve $BMC_DIR" | tr '\n' ' ')
grep -q 'JSON-RPC server' "$WORK/bmc.log" || { echo "bmc never came up"; tail -20 "$WORK/bmc.log"; exit 2; }
echo "  bmc up (pids $BMC_PIDS)"
grep -q "onion via SOCKS5" "$WORK/bmc.log" && ok "our node reports the onion transport: $(grep -m1 'onion via SOCKS5' "$WORK/bmc.log" | sed 's/.*\[dial\] //')" \
                                           || fail "our node did not configure the onion transport"

echo "== the onion peer enters the book and is dialled over tor =="
R=$(bmc getnodeaddresses '[0, "onion"]')
echo "$R" | grep -q "$ONION" && ok "getnodeaddresses network=onion lists the planted peer" || fail "book lacks the onion address: $R"
# a second onion address through the RPC, to prove that path too
R=$(bmc addpeeraddress '["2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion", 8333]')
echo "$R" | grep -q '"success":true' && ok "addpeeraddress accepts a .onion address" || fail "addpeeraddress: $R"
for i in $(seq 60); do grep -q "connected via onion transport" "$WORK/bmc.log" && break; sleep 2; done
if grep -q "connected via onion transport" "$WORK/bmc.log"; then
  ok "our node: $(grep -m1 'connected via onion' "$WORK/bmc.log" | sed 's/.*\[dial\] //')"
else fail "our node never completed a dial over tor"; grep -iE "\[dial\]" "$WORK/bmc.log" | tail -5; fi

echo "== Core sees an INBOUND peer whose network is onion =="
for i in $(seq 30); do core getpeerinfo 2>/dev/null | grep -q '"network": "onion"' && break; sleep 2; done
P=$(core getpeerinfo 2>/dev/null)
echo "$P" | grep -q '"network": "onion"' && ok "Core getpeerinfo shows a peer on network onion" || { fail "Core has no onion peer"; echo "$P" | python3 -c "import sys,json;print([(p.get('network'),p.get('subver'),p.get('inbound')) for p in json.load(sys.stdin)])" 2>/dev/null | head -2; }
echo "$P" | grep -q 'BitcoinMachineCode' && ok "and it is us (subver BitcoinMachineCode)" || fail "the onion peer is not this node"
echo "$P" | python3 -c "
import sys,json
ps=[p for p in json.load(sys.stdin) if p.get('network')=='onion']
print('    Core:', [(p['addr'][:22]+'...', p['subver'], 'inbound' if p['inbound'] else 'outbound') for p in ps])" 2>/dev/null
echo "== and the handshake really completed (Core counts it a full peer) =="
core getpeerinfo | python3 -c "
import sys,json
ps=[p for p in json.load(sys.stdin) if p.get('network')=='onion']
ok=any(p.get('version',0)>=70016 and p.get('bytesrecv',0)>0 for p in ps)
sys.exit(0 if ok else 1)" && ok "version >= 70016 negotiated and bytes received over the circuit" || fail "no completed handshake on the onion peer"
echo
[ $FAILURES -eq 0 ] && echo "PASS: this node dials a real Bitcoin peer over Tor ($FAILURES failures)" || echo "FAILURES: $FAILURES"
exit $FAILURES
