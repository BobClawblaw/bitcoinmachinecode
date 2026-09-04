#!/usr/bin/env bash
# serve_child_fds.sh -- DMN-6 (audit 2026-09-03): an inbound serve child must
# not hold the RPC listening socket, and must die on SIGTERM.
#
# Every serve child inherited the RPC listener across fork(). After the parent
# exited -- `bitcoin-cli stop` outside systemd, or a crash -- the socket stayed
# bound by those children, so the NEXT instance's rpc_server_start failed with
# "bind() failed". That failure is deliberately non-fatal, so the new node came
# up with NO RPC and NO cookie: unstoppable by `stop`, invisible to monitoring,
# until the last old child happened to die.
#
# The child also inherited a SIGTERM handler that only sets a flag which
# bitcoin_serve.asm never reads, so it ignored shutdown entirely -- which is
# why a stop with N inbound peers waited for all N.
#
# regtest, hermetic.
set -u
R=$(cd "$(dirname "$0")/.." && pwd)
BIN="${BIN:-$R/asm/daemon/bitcoind}"
[ -x "$BIN" ] || { echo "FAIL: no daemon at $BIN"; exit 1; }

D=$(mktemp -d /tmp/dmn6XXXXXX) || exit 1
cleanup(){ [ -n "${PID:-}" ] && kill -9 "$PID" 2>/dev/null; pkill -9 -f "$D" 2>/dev/null; rm -rf "$D"; }
trap cleanup EXIT

RPCPORT=19790
P2PPORT=19791
printf 'chain=regtest\ndnsseed=0\nrpcport=%s\n' "$RPCPORT" > "$D/bitcoin.conf"

fails=0
ck(){ if [ "$2" = "0" ]; then echo "ok  : $1"; else echo "FAIL: $1"; fails=$((fails+1)); fi; }

"$BIN" -conf="$D/bitcoin.conf" serve "$D" "$P2PPORT" > "$D/a.log" 2>&1 &
PID=$!
sleep 5
kill -0 "$PID" 2>/dev/null; ck "the node is up" $?

# make an inbound connection so a serve child exists
exec 3<>/dev/tcp/127.0.0.1/$P2PPORT 2>/dev/null && ck "an inbound connection was accepted" 0 || ck "an inbound connection was accepted" 1
sleep 2

nchild=$(pgrep -P "$PID" 2>/dev/null | wc -l)
echo "      parent has $nchild child process(es)"

# THE PROPERTY: no process other than the parent holds the RPC port bound
holders=$(ls -l /proc/*/fd 2>/dev/null >/dev/null; ss -ltnp 2>/dev/null | grep ":$RPCPORT " | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u)
nholders=$(echo "$holders" | grep -c '[0-9]' || true)
echo "      processes holding the RPC port: ${holders:-none} (count $nholders)"
[ "$nholders" -le 1 ]
ck "DMN-6 only ONE process holds the RPC listener (children dropped it)" $?

exec 3<&- 2>/dev/null
kill "$PID" 2>/dev/null; PID=
sleep 3
ss -ltn 2>/dev/null | grep -q ":$RPCPORT "
if [ $? -eq 0 ]; then ck "DMN-6 the RPC port is FREE after the parent exits" 1
                 else ck "DMN-6 the RPC port is FREE after the parent exits" 0; fi

echo
if [ "$fails" = "0" ]; then echo "ALL CHECKS PASSED"; exit 0; fi
echo "$fails CHECK(S) FAILED"; exit 1
