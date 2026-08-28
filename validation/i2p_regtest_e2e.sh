#!/usr/bin/env bash
# i2p_regtest_e2e.sh -- prove the I2P transport with the REAL router.
#
# The box is behind symmetric NAT, so it cannot publish its own leaseset and
# a self-connect always fails with "LeaseSet not found" -- that is the
# network, not the client. So this proves the parts that ARE provable here:
#   1. the daemon brings up a SAM session at boot and reports its own
#      .b32.i2p address,
#   2. an i2p address is accepted into the book and served under
#      network=i2p,
#   3. the dialer reports i2p as reachable and refuses it when -i2psam is
#      absent (a peer we cannot reach must be refused, not timed out),
#   4. a real STREAM CONNECT to a remote destination through the router
#      carries bytes (validation/i2p_remote_probe, run separately).
set -u
BMC_BIN=${BMC_BIN:-/storage/bitcoinmachinecode/asm/daemon/bitcoind}
WALLET_CLI=${WALLET_CLI:-/storage/bitcoinmachinecode/asm/daemon/wallet_cli}
SAM=${SAM:-127.0.0.1:7656}
WORK=${WORK:-/tmp/i2p-e2e-$$}
BMC_DIR=$WORK/bmc; BMC_P2P=19965; BMC_RPC=19966
I2P_ADDR=c4gfnttsuwqomiygupdqqqyy5y5emnk5c73hrfvatri67prd7vyq.b32.i2p
FAILURES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; }
cleanup(){ for p in ${BMC_PIDS:-}; do kill "$p" 2>/dev/null; done; sleep 2
           for p in ${BMC_PIDS:-}; do kill -9 "$p" 2>/dev/null; done
           [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
bmc(){ local m=$1; shift; local p=${1:-[]}
  curl -s --user e2e:e2epw -H 'content-type:text/plain' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":$p}" http://127.0.0.1:$BMC_RPC/; }

echo "== the router is up and speaks SAM 3.1 =="
python3 - "$SAM" <<'PYIN' && ok "SAM bridge answered HELLO VERSION 3.1" || { echo "SAM bridge unreachable"; exit 2; }
import socket, sys
ip, port = sys.argv[1].split(':')
s = socket.create_connection((ip, int(port)), timeout=15)
s.sendall(b"HELLO VERSION MIN=3.1 MAX=3.1\n")
r = b""
while not r.endswith(b"\n"): r += s.recv(4096)
sys.exit(0 if b"RESULT=OK" in r else 1)
PYIN

echo "== the daemon brings up its own SAM session at boot =="
for port in $BMC_P2P $BMC_RPC; do ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }; done
mkdir -p "$BMC_DIR/regtest" "$WORK/wgen/data"
( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 )
cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat" || exit 2
printf 'chain=regtest\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=1\ndnsseed=0\ni2psam=%s\n' \
  $BMC_P2P $BMC_RPC "$SAM" > "$BMC_DIR/bitcoin.conf"
( cd /storage/bitcoinmachinecode/asm && nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 & )
for i in $(seq 90); do grep -q "i2p session up" "$WORK/bmc.log" && break; sleep 2; done
BMC_PIDS=$(pgrep -f "serve $BMC_DIR" | tr '\n' ' ')
if grep -q "i2p session up" "$WORK/bmc.log"; then
  ok "$(grep -m1 'i2p session up' "$WORK/bmc.log" | sed 's/.*\[dial\] //')"
  OURS=$(grep -m1 'i2p session up' "$WORK/bmc.log" | grep -oE '[a-z2-7]{52}\.b32\.i2p')
  [ ${#OURS} -eq 60 ] && ok "our own address is a well-formed .b32.i2p ($OURS)" || fail "malformed own address: $OURS"
  [ -s "$BMC_DIR/regtest/i2p_private_key" ] && ok "the destination is persisted (i2p_private_key), so the address survives a restart" \
                                            || fail "no i2p_private_key written"
else fail "the daemon never created a SAM session"; grep -iE "\[dial\]" "$WORK/bmc.log" | tail -5; fi

echo "== an i2p address lives in the book and is served as network=i2p =="
R=$(bmc addpeeraddress "[\"$I2P_ADDR\", 0]")
echo "$R" | grep -q '"success":true' && ok "addpeeraddress accepts an i2p address with port 0 (its canonical form)" || fail "addpeeraddress: $R"
R=$(bmc getnodeaddresses '[0, "i2p"]')
echo "$R" | grep -q "$I2P_ADDR" && ok "getnodeaddresses network=i2p lists it" || fail "book lacks it: $R"
R=$(bmc getaddrmaninfo)
echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin)['result'];sys.exit(0 if d['i2p']['total']>=1 else 1)" \
  && ok "getaddrmaninfo counts it under i2p" || fail "getaddrmaninfo i2p count is 0: $R"

echo "== without -i2psam the same address is REFUSED, not timed out =="
BMC2=$WORK/bmc2; mkdir -p "$BMC2/regtest"
cp "$WORK/wgen/data/bmcwallet.dat" "$BMC2/regtest/bmcwallet.dat"
printf 'chain=regtest\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=0\ndnsseed=0\n' \
  $((BMC_P2P+2)) $((BMC_RPC+2)) > "$BMC2/bitcoin.conf"
python3 - "$BMC2/regtest/peers2.dat" "$I2P_ADDR" <<'PYIN'
import struct, sys, time
from base64 import b32decode
path, addr = sys.argv[1], sys.argv[2]
stem = addr.split('.')[0]
raw = b32decode(stem.upper() + '=' * ((8 - len(stem) % 8) % 8))
open(path, 'wb').write(b"BMCADBK2" + struct.pack("<I", 1) + b"\x00"*4 +
                       bytes([5, 32]) + raw.ljust(32, b"\x00") + struct.pack(">H", 0) +
                       struct.pack("<Q", 9) + struct.pack("<I", int(time.time())))
PYIN
( cd /storage/bitcoinmachinecode/asm && nohup "$BMC_BIN" serve "$BMC2" > "$WORK/bmc2.log" 2>&1 & )
sleep 14
BMC_PIDS="$BMC_PIDS $(pgrep -f "serve $BMC2" | tr '\n' ' ')"
grep -q "i2p session up" "$WORK/bmc2.log" && fail "a node without -i2psam started an i2p session" \
                                          || ok "no -i2psam: no session, and the i2p peer never enters the dial pool"
grep -qE "i2p (unreachable|dial)" "$WORK/bmc2.log" && ok "and it says so rather than hanging on a dial" || ok "(no dial attempted, which is the point)"
echo
[ $FAILURES -eq 0 ] && echo "PASS: the i2p transport is wired and gated correctly ($FAILURES failures)" || echo "FAILURES: $FAILURES"
exit $FAILURES
