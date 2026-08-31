#!/usr/bin/env bash
# cjdns_regtest_e2e.sh -- prove the CJDNS transport with a REAL cjdns router.
#
# A CJDNS address IS an fc00::/8 IPv6 address on cjdns's tun interface, so
# this exercises the node's new IPv6 socket path end to end:
#   Bitcoin Core binds its regtest P2P port to OUR cjdns address; this node
#   is given that address with -cjdnsreachable and must dial it over the tun
#   and complete the Bitcoin handshake, with Core reporting the peer as
#   network "cjdns". It also checks the negative: WITHOUT -cjdnsreachable
#   the same peer is refused rather than dialled, as Core requires (it
#   cannot detect a cjdns interface either).
# Needs cjdroute running (its tun up) and IPv6 enabled on this host.
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-source/build/bin}
BMC_BIN=${BMC_BIN:-/storage/bitcoinmachinecode/asm/daemon/bitcoind}
WALLET_CLI=${WALLET_CLI:-/storage/bitcoinmachinecode/asm/daemon/wallet_cli}
WORK=${WORK:-/tmp/cjdns-e2e-$$}
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
CORE_P2P=19974; CORE_RPC=19980; BMC_P2P=19975; BMC_RPC=19976
FAILURES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; }
cleanup(){ for p in ${BMC_PIDS:-} ${CORE_PID:-}; do kill "$p" 2>/dev/null; done; sleep 2
           for p in ${BMC_PIDS:-}; do kill -9 "$p" 2>/dev/null; done
           [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmc(){ local m=$1; shift; local p=${1:-[]}
  curl -s --user e2e:e2epw -H 'content-type:text/plain' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":$p}" http://127.0.0.1:$BMC_RPC/; }

echo "== a real cjdns router with its tun up =="
# `ip -o` gives one line per address, so the interface and the address are
# read together -- a substring grep over the multi-line form picks fragments
# of unrelated addresses off other interfaces.
read -r IFACE CJCIDR <<<"$(ip -6 -o addr show 2>/dev/null | awk '$4 ~ /^fc/ {print $2, $4; exit}')"
CJ=${CJCIDR%%/*}
[ -n "$CJ" ] || { echo "no fc00::/8 address on any interface -- is cjdroute running?"; exit 2; }
ok "cjdns address $CJ on ${IFACE:-tun}"
ping6 -c1 -W3 "$CJ" >/dev/null 2>&1 && ok "it answers on the tun interface" || fail "the cjdns address does not respond"

echo "== Core listens for Bitcoin ON the cjdns address =="
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do
  ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }
done
mkdir -p "$CORE_DIR" "$BMC_DIR/regtest"
printf 'regtest=1\n[regtest]\nbind=[%s]:%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=1\nlistenonion=0\ncjdnsreachable=1\ndebug=net\n' \
  "$CJ" $CORE_P2P $CORE_RPC > "$CORE_DIR/bitcoin.conf"
"$CORE_BIN/bitcoind" -datadir="$CORE_DIR" -daemon >/dev/null 2>&1
for i in $(seq 40); do core getblockcount >/dev/null 2>&1 && break; sleep 1; done
CORE_PID=$(cat "$CORE_DIR/regtest/bitcoind.pid" 2>/dev/null)
[ -n "${CORE_PID:-}" ] || { echo "core did not start"; tail -5 "$CORE_DIR/regtest/debug.log" 2>/dev/null; exit 2; }
ss -ltn 2>/dev/null | grep -q "\[$CJ\]:$CORE_P2P" && ok "Core is listening on [$CJ]:$CORE_P2P" || { fail "Core did not bind the cjdns address"; ss -ltn | grep ":$CORE_P2P"; }

echo "== our node dials it over cjdns =="
mkdir -p "$WORK/wgen/data"; ( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 )
cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat" || exit 2
# plant the cjdns peer so the BOOT dial pool contains it (book -> pool -> transport)
python3 - "$BMC_DIR/regtest/peers2.dat" "$CJ" "$CORE_P2P" <<'PYIN'
import socket, struct, sys, time
path, addr, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
raw = socket.inet_pton(socket.AF_INET6, addr)
open(path, 'wb').write(b"BMCADBK2" + struct.pack("<I", 1) + b"\x00"*4 +
                       bytes([6, 16]) + raw.ljust(32, b"\x00") + struct.pack(">H", port) +
                       struct.pack("<Q", 9) + struct.pack("<I", int(time.time())))
PYIN
printf 'chain=regtest\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=1\ndnsseed=0\ncjdnsreachable=1\n' \
  $BMC_P2P $BMC_RPC > "$BMC_DIR/bitcoin.conf"
( cd /storage/bitcoinmachinecode/asm && nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 & )
sleep 12
BMC_PIDS=$(pgrep -f "serve $BMC_DIR" | tr '\n' ' ')
grep -q 'JSON-RPC server' "$WORK/bmc.log" || { echo "bmc never came up"; tail -20 "$WORK/bmc.log"; exit 2; }
grep -q "cjdns reachable" "$WORK/bmc.log" && ok "our node reports cjdns reachable over IPv6" || fail "our node did not enable cjdns"
grep -q "listening on IPv6" "$WORK/bmc.log" && ok "and it opened an IPv6 listener (cjdns peers can reach us too)" || fail "no IPv6 listener"
R=$(bmc getnodeaddresses '[0, "cjdns"]')
echo "$R" | grep -q "$CJ" && ok "getnodeaddresses network=cjdns lists the peer" || fail "book lacks the cjdns peer: $R"
for i in $(seq 45); do grep -q "connected via cjdns transport" "$WORK/bmc.log" && break; sleep 2; done
if grep -q "connected via cjdns transport" "$WORK/bmc.log"; then
  ok "our node: $(grep -m1 'connected via cjdns' "$WORK/bmc.log" | sed 's/.*\[dial\] //')"
else fail "our node never dialled the cjdns peer"; grep -E "\[dial\]" "$WORK/bmc.log" | tail -5; fi

echo "== Core sees the peer as network cjdns, handshake complete =="
for i in $(seq 30); do core getpeerinfo 2>/dev/null | grep -q '"network": "cjdns"' && break; sleep 2; done
P=$(core getpeerinfo 2>/dev/null)
echo "$P" | grep -q '"network": "cjdns"' && ok "Core getpeerinfo: network cjdns" || { fail "Core has no cjdns peer"; echo "$P" | python3 -c "import sys,json;print([(p.get('network'),p.get('subver')) for p in json.load(sys.stdin)])" 2>/dev/null | head -2; }
echo "$P" | grep -q 'BitcoinMachineCode' && ok "and it is us" || fail "the cjdns peer is not this node"
echo "$P" | python3 -c "
import sys,json
ps=[p for p in json.load(sys.stdin) if p.get('network')=='cjdns']
print('    Core:', [(p['addr'][:26]+'...', p['subver'], 'inbound' if p['inbound'] else 'outbound') for p in ps])
sys.exit(0 if any(p.get('version',0)>=70016 and p.get('bytesrecv',0)>0 for p in ps) else 1)" && ok "version >= 70016 and bytes received over cjdns" || fail "no completed handshake"

echo "== without -cjdnsreachable the same peer is REFUSED, not dialled =="
BMC2=$WORK/bmc2; mkdir -p "$BMC2/regtest"
cp "$WORK/wgen/data/bmcwallet.dat" "$BMC2/regtest/bmcwallet.dat"
cp "$BMC_DIR/regtest/peers2.dat" "$BMC2/regtest/peers2.dat"
printf 'chain=regtest\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=0\ndnsseed=0\n' \
  $((BMC_P2P+2)) $((BMC_RPC+2)) > "$BMC2/bitcoin.conf"
( cd /storage/bitcoinmachinecode/asm && nohup "$BMC_BIN" serve "$BMC2" > "$WORK/bmc2.log" 2>&1 & )
sleep 14
BMC_PIDS="$BMC_PIDS $(pgrep -f "serve $BMC2" | tr '\n' ' ')"
grep -q "connected via cjdns" "$WORK/bmc2.log" && fail "dialled a cjdns peer without -cjdnsreachable" \
                                               || ok "no -cjdnsreachable: the cjdns peer never enters the dial pool"
echo
[ $FAILURES -eq 0 ] && echo "PASS: this node speaks Bitcoin over CJDNS ($FAILURES failures)" || echo "FAILURES: $FAILURES"
exit $FAILURES
