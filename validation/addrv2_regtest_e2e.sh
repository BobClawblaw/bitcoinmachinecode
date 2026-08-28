#!/usr/bin/env bash
# addrv2_regtest_e2e.sh -- BIP155 addrv2 negotiation and the getaddr reply,
# proven against a REAL Bitcoin Core rather than against this node's own
# idea of the format.
#
# What it asserts, all read from Core's side (-debug=net) or from Core's
# addrman:
#   1. OUTBOUND: when this node dials Core, Core sees `sendaddrv2` from us
#      on that inbound peer -- before verack, or Core would disconnect.
#   2. INBOUND: when Core dials this node (addnode onetry), Core offers
#      sendaddrv2, sends getaddr, and receives an `addrv2` reply -- never a
#      legacy `addr` -- from a 3-record book we planted.
#   3. Core PARSED that reply: all three planted addresses appear in Core's
#      own getnodeaddresses. A byte-level mistake in our BIP155 encoding
#      would leave addrman empty (or Core disconnecting us), not "close".
#   4. validation/p2p_inbound_probe.py reports the same negotiation shape
#      for this node as for Core: sendaddrv2 accepted AND offered back.
# Until 2026-08-28 this node never offered sendaddrv2 in either role, and
# its getaddr handler had never answered anyone (bound register clobbered).
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-source/build/bin}
BMC_BIN=${BMC_BIN:-/storage/bitcoinmachinecode/asm/daemon/bitcoind}
WALLET_CLI=${WALLET_CLI:-/storage/bitcoinmachinecode/asm/daemon/wallet_cli}
PROBE=${PROBE:-/storage/bitcoinmachinecode/validation/p2p_inbound_probe.py}
WORK=${WORK:-/tmp/addrv2-e2e-$$}
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
CORE_P2P=19844; CORE_RPC=19860; BMC_P2P=19855; BMC_RPC=19846
REGTEST_MAGIC=fabfb5da
FAILURES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; }
cleanup(){ for p in ${BMC_PIDS:-} ${CORE_PID:-}; do kill "$p" 2>/dev/null; done
           sleep 2; for p in ${BMC_PIDS:-}; do kill -9 "$p" 2>/dev/null; done
           [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
CLOG=$CORE_DIR/regtest/debug.log

echo "== setup =="
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do
  ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }
done
mkdir -p "$CORE_DIR" "$BMC_DIR/regtest"
printf 'regtest=1\n[regtest]\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=1\nlistenonion=0\ndebug=net\n' \
  $CORE_P2P $CORE_RPC > "$CORE_DIR/bitcoin.conf"
printf 'chain=regtest\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=1\nconnect=127.0.0.1:%s\n' \
  $BMC_P2P $BMC_RPC $CORE_P2P > "$BMC_DIR/bitcoin.conf"
# the book this node will answer getaddr from: three routable IPv4s with
# NODE_NETWORK set (Core drops addresses without it) and fresh timestamps
# (Core's getnodeaddresses hides "terrible" entries older than 30 days)
python3 - "$BMC_DIR/regtest/peers.dat" <<'PY'
import struct, sys, time, socket
now = int(time.time())
recs = [("5.6.7.8", 8333, 9), ("9.10.11.12", 8333, 1), ("200.1.2.3", 8334, 0x409)]
with open(sys.argv[1], "wb") as f:
    for ip, port, svc in recs:
        f.write(socket.inet_aton(ip) + struct.pack(">H", port) + struct.pack("<Q", svc) + struct.pack("<I", now))
PY
"$CORE_BIN/bitcoind" -datadir="$CORE_DIR" -daemon >/dev/null 2>&1
for i in $(seq 30); do core getblockcount >/dev/null 2>&1 && break; sleep 1; done
CORE_PID=$(cat "$CORE_DIR/regtest/bitcoind.pid"); echo "  core up (pid $CORE_PID, debug=net)"
mkdir -p "$WORK/wgen/data"; ( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 )
cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat" || exit 2
( cd /storage/bitcoinmachinecode/asm && nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 & )
sleep 12
BMC_PIDS=$(pgrep -f "serve $BMC_DIR" | tr '\n' ' ')
grep -q 'JSON-RPC server' "$WORK/bmc.log" || { echo "bmc never came up"; tail -20 "$WORK/bmc.log"; exit 2; }
echo "  bmc up (pids $BMC_PIDS)"

echo "== 1. OUTBOUND: this node dialled Core; Core must have seen our sendaddrv2 pre-verack =="
for i in $(seq 20); do grep -q "received: sendaddrv2" "$CLOG" && break; sleep 1; done
if grep -q "received: sendaddrv2 (0 bytes) peer=" "$CLOG"; then
  ok "Core: $(grep -m1 'received: sendaddrv2' "$CLOG" | sed 's/^.*received:/received:/')"
else fail "Core never logged receiving sendaddrv2 from our outbound connection"; grep -m3 "peer=0" "$CLOG"; fi
grep -q "sendaddrv2 received after verack" "$CLOG" && fail "Core says our sendaddrv2 came AFTER verack (protocol violation)" \
                                                 || ok "not flagged as after-verack"
IN_PEER=$(grep -m1 "received: sendaddrv2" "$CLOG" | sed 's/.*peer=\([0-9]*\).*/\1/')

echo "== 2. INBOUND: Core dials this node, sends getaddr, must get addrv2 (never addr) =="
core addnode "127.0.0.1:$BMC_P2P" onetry >/dev/null 2>&1
for i in $(seq 30); do grep -qE "received: addrv2 \([0-9]+ bytes\) peer=" "$CLOG" && break; sleep 1; done
# the peer id Core assigned to ITS outbound connection to us is the one on
# the addrv2 line (Core also sends sendaddrv2 to peer 0, our inbound leg)
OUT_PEER=$(grep -m1 "received: addrv2" "$CLOG" | sed 's/.*peer=\([0-9]*\).*/\1/')
if grep -qE "received: addrv2 \(42 bytes\) peer=" "$CLOG"; then
  ok "Core: $(grep -m1 'received: addrv2' "$CLOG" | sed 's/^.*received:/received:/')  (42 bytes = Core's own msg_addrv2 size for these 3 records)"
elif grep -qE "received: addrv2" "$CLOG"; then
  fail "Core received addrv2 but not 42 bytes: $(grep -m1 'received: addrv2' "$CLOG")"
else fail "Core never received an addrv2 reply to its getaddr"; grep -E "sending getaddr|received: addr" "$CLOG" | head -4; fi
if [ -n "${OUT_PEER:-}" ] && grep -qE "received: addr \([0-9]+ bytes\) peer=${OUT_PEER}\b" "$CLOG"; then
  fail "Core received a LEGACY addr from peer=$OUT_PEER, which negotiated addrv2"
else ok "no legacy addr sent to the addrv2 peer (peer=${OUT_PEER:-?})"; fi
grep -q "sending getaddr" "$CLOG" && ok "Core did send getaddr (the reply was solicited, as Core requires for >10 addrs)" || fail "Core never sent getaddr"

echo "== 3. Core PARSED the reply: the planted addresses are in Core's addrman =="
sleep 1
ADDRS=$(core getnodeaddresses 0 2>/dev/null)
for ip in 5.6.7.8 9.10.11.12 200.1.2.3; do
  echo "$ADDRS" | grep -q "\"address\": \"$ip\"" && ok "getnodeaddresses has $ip" || fail "getnodeaddresses lacks $ip"
done
echo "$ADDRS" | grep -q "\"port\": 8334" && ok "port 8334 (big-endian on the wire) parsed" || fail "port 8334 not parsed"
echo "$ADDRS" | grep -q "\"services\": 1033" && ok "services 0x409 (3-byte CompactSize) parsed as 1033" || fail "services 0x409 not parsed"

echo "== 4. the inbound probe reports the same negotiation shape as Core =="
P_BMC=$(python3 "$PROBE" 127.0.0.1 $BMC_P2P $REGTEST_MAGIC --wait=1.5 2>/dev/null)
P_CORE=$(python3 "$PROBE" 127.0.0.1 $CORE_P2P $REGTEST_MAGIC --wait=1.5 2>/dev/null)
L_BMC=$(echo "$P_BMC" | grep -E "^\s*sendaddrv2 "); L_CORE=$(echo "$P_CORE" | grep -E "^\s*sendaddrv2 ")
echo "    bmc : $L_BMC"; echo "    core: $L_CORE"
echo "$L_BMC" | grep -q "peer offers it too: True" && ok "this node offers sendaddrv2 back" || fail "this node does not offer sendaddrv2"
[ "$(echo "$L_BMC" | sed 's/ *$//')" = "$(echo "$L_CORE" | sed 's/ *$//')" ] && ok "probe line identical to Core's" || fail "probe line differs from Core's"
for late in sendaddrv2_late wtxidrelay_late; do
  LB=$(echo "$P_BMC" | grep -E "^\s*$late "); LC=$(echo "$P_CORE" | grep -E "^\s*$late ")
  echo "    bmc : $LB"; echo "    core: $LC"
  echo "$LB" | grep -q "<disconnected>" && ok "$late: this node disconnects (Core: '... received after verack')" || fail "$late: this node did not disconnect: $LB"
  [ "$(echo "$LB" | sed 's/ *$//')" = "$(echo "$LC" | sed 's/ *$//')" ] && ok "$late: probe line identical to Core's" || fail "$late: differs from Core: $LC"
done
G_BMC=$(echo "$P_BMC" | grep -E "^\s*getaddr "); echo "    bmc : $G_BMC"
# anchored on the REPLY column: the probe's own line starts with "getaddr",
# so a bare grep for "addr" matched even "(silence)" (review, 2026-08-28)
echo "$G_BMC" | grep -qE "getaddr +-> *(addr|addrv2)\b" && ok "getaddr answered (addr)" || fail "getaddr unanswered: $G_BMC"

echo
[ $FAILURES -eq 0 ] && echo "PASS: addrv2 negotiation proven against Core ($FAILURES failures)" || echo "FAILURES: $FAILURES"
exit $FAILURES
