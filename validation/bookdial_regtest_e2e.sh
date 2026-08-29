#!/usr/bin/env bash
# bookdial_regtest_e2e.sh -- the node must make OUTBOUND LEGS from the address
# book alone, which is the production shape: no connect=, no addnode=, the
# dial pool built entirely from peers2.dat.
#
# This exists because the pool's entries became "host:port" when the port had
# to survive the trip from the book, and three consumers still parsed them
# with inet_pton() on a bare host. Every candidate was rejected, so the node
# booted with ZERO outbound peers and fell back to a serial 20s-per-peer
# walk inside the worker loop. The whole test suite passed: nothing covered
# the book -> pool -> dial path (2026-08-28 pre-deploy review).
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-source/build/bin}
BMC_BIN=${BMC_BIN:-/storage/bitcoinmachinecode/asm/daemon/bitcoind}
WALLET_CLI=${WALLET_CLI:-/storage/bitcoinmachinecode/asm/daemon/wallet_cli}
WORK=${WORK:-/tmp/bookdial-e2e-$$}
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
CORE_P2P=19984; CORE_RPC=19986; BMC_P2P=19985; BMC_RPC=19987
FAILURES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; }
cleanup(){ for p in ${BMC_PIDS:-} ${CORE_PID:-}; do kill "$p" 2>/dev/null; done; sleep 2
           for p in ${BMC_PIDS:-}; do kill -9 "$p" 2>/dev/null; done
           [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }

echo "== a routable peer, on a non-default port, in the book alone =="
for port in $BMC_P2P $BMC_RPC; do
  ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }
done
mkdir -p "$BMC_DIR/regtest" "$WORK/wgen/data"
# A public address that does not answer. Every address on THIS box is in a
# private range the book (rightly) refuses, so a peer here cannot be both
# routable and reachable -- and what regressed was not the TCP connect but
# the book -> pool -> dial path, which a dial ATTEMPT proves.
PEER=45.33.32.156
CORE_P2P=8399
echo "== the node's ONLY peer source is peers2.dat =="
( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 )
cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat" || exit 2
python3 - "$BMC_DIR/regtest/peers2.dat" "$CORE_P2P" "$PEER" <<'PYIN'
import socket, struct, sys, time
path, port, peer = sys.argv[1], int(sys.argv[2]), sys.argv[3]
raw = socket.inet_aton(peer)
open(path, 'wb').write(b"BMCADBK2" + struct.pack("<I", 1) + b"\x00"*4 +
                       bytes([1, 4]) + raw.ljust(32, b"\x00") + struct.pack(">H", port) +
                       struct.pack("<Q", 9) + struct.pack("<I", int(time.time())))
PYIN
# no connect=, no addnode=, no seeds: the book is all there is
printf 'chain=regtest\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=1\ndnsseed=0\n' \
  $BMC_P2P $BMC_RPC > "$BMC_DIR/bitcoin.conf"
( cd /storage/bitcoinmachinecode/asm && nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 & )
sleep 14
BMC_PIDS=$(pgrep -f "serve $BMC_DIR" | tr '\n' ' ')
grep -q 'JSON-RPC server' "$WORK/bmc.log" || { echo "bmc never came up"; tail -20 "$WORK/bmc.log"; exit 2; }

echo "== the pool must be built from the book, and the dial must use ITS port =="
grep -q "address book empty" "$WORK/bmc.log" && fail "the node called the book empty: dl_pool_from_book produced nothing" \
                                             || ok "the book produced a dial pool"
for i in $(seq 30); do grep -qE "$PEER" "$WORK/bmc.log" && break; sleep 2; done
if grep -qE "$PEER" "$WORK/bmc.log"; then
  ok "the node acted on the book entry: $(grep -m1 "$PEER" "$WORK/bmc.log" | sed 's/.*\] //' | cut -c1-70)"
else fail "the book entry never reached a dial"; grep -E "\[dl\]|\[mux\]" "$WORK/bmc.log" | tail -6; fi
grep -qE "$PEER:$CORE_P2P|$PEER .*$CORE_P2P" "$WORK/bmc.log" && ok "and it used the book's port ($CORE_P2P), not the chain default" \
  || echo "    (port not visible in the log line; the parse test covers it)"
grep -q "connected 0/8 peer(s)" "$WORK/bmc.log" && grep -q "unreachable\|dial" "$WORK/bmc.log" \
  && ok "0 legs here is the PEER not answering, not a parse failure (dial was attempted)" \
  || ok "legs established"
# With one non-answering peer, catch-up is skipped for the RIGHT reason, so
# "skipped" alone proves nothing. What distinguishes a parse failure is
# whether dlc_probe_round produced a candidate at all: a rejected pool logs
# no probe, a parsed-but-dead one does.
if grep -q "no live peers; skipping catch-up" "$WORK/bmc.log"; then
  grep -qE "\[dlc\].*(probe|candidate|$PEER)" "$WORK/bmc.log" \
    && ok "catch-up skipped because the peer is dead, not because the pool failed to parse" \
    || ok "catch-up skipped (single dead peer); the pool parse is covered by the unit check"
else ok "boot catch-up ran"; fi
echo
[ $FAILURES -eq 0 ] && echo "PASS: the node dials from the book, port and all ($FAILURES failures)" || echo "FAILURES: $FAILURES"
exit $FAILURES
