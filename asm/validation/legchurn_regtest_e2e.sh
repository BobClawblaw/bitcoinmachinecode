#!/bin/bash
# validation/legchurn_regtest_e2e.sh -- one outbound leg to a Core regtest node, HELD.
#
# Core runs with -debug=net, so its debug.log names the reason for any
# disconnect; bmc dials it as its only peer and Core mines a block with fresh
# transactions every 20 s for RUN_S seconds (default 150). PASS = the leg is
# installed once and never replaced, Core never logs a reset or a close from
# our side, and bmc follows every block. 2026-09-10 (snapshot aa): the pass
# moved into a helper child and the rotation's reorg probe, which ran AFTER
# the pass "returned nothing" (it now always returns nothing to the parent),
# probed the very socket the child was reading; the leg died every 30-70 s
# as "EOF on the first read" and Core logged "Connection reset by peer" --
# on the unfixed binary this script showed four resets in 150 s.
# Usage: validation/legchurn_regtest_e2e.sh   (RUN_S=n; KEEP=1 keeps the work dir; BMC_BIN overrides the binary)
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-source/build/bin}; BMC_BIN=${BMC_BIN:-/storage/bitcoinmachinecode/asm/daemon/bmcbitcoind}
WALLET_CLI=${WALLET_CLI:-/storage/bitcoinmachinecode/asm/daemon/bmc_wallet_cli}
WORK=${TMPDIR:-/tmp}/bmc-legchurn-e2e-$$; rm -rf "$WORK"; mkdir -p "$WORK/core" "$WORK/bmc/regtest"
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc; CORE_P2P=20974; CORE_RPC=20975; BMC_P2P=20976; BMC_RPC=20977; RUN_S=${RUN_S:-150}
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use (another run?)"; exit 2; }; done
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmc(){ local m=$1; shift; curl -s --user e2e:e2epw -H 'content-type:text/plain' --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":${1:-[]}}" http://127.0.0.1:$BMC_RPC/ | python3 -c "import sys,json; print(json.load(sys.stdin).get('result'))" 2>/dev/null; }
printf 'regtest=1\n[regtest]\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlistenonion=0\nfallbackfee=0.0001\ndebug=net\nlogips=1\nbind=127.0.0.1\n' $CORE_P2P $CORE_RPC > "$CORE_DIR/bitcoin.conf"
printf 'chain=regtest\nprinttoconsole=1\n[regtest]\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nconnect=127.0.0.1:%s\n' $BMC_P2P $BMC_RPC $CORE_P2P > "$BMC_DIR/bitcoin.conf"
"$CORE_BIN/bitcoind" -datadir="$CORE_DIR" -daemon >/dev/null 2>&1; sleep 3
mkdir -p "$WORK/wgen/data"; ( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 ); cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat"
core createwallet e2ecore >/dev/null 2>&1; CADDR=$(core -rpcwallet=e2ecore getnewaddress)
core -rpcwallet=e2ecore generatetoaddress 110 "$CADDR" >/dev/null
( setsid nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 < /dev/null & )
for i in $(seq 120); do grep -q 'JSON-RPC server' "$WORK/bmc.log" && break; sleep 1; done
T0=$(date +%s)
while [ $(( $(date +%s) - T0 )) -lt $RUN_S ]; do
  for k in 1 2; do core -rpcwallet=e2ecore sendtoaddress "$(core -rpcwallet=e2ecore getnewaddress)" 0.5 >/dev/null 2>&1; done
  core -rpcwallet=e2ecore generatetoaddress 1 "$CADDR" >/dev/null; sleep 20
  echo "$(date -u +%T) core $(core getblockcount) bmc $(bmc getblockcount) peers=$(core getconnectioncount)"
done
CT=$(core getblockcount); BT=$(bmc getblockcount)
RESETS=$(grep -ac 'Connection reset by peer' "$CORE_DIR/regtest/debug.log")
INSTALLS=$(grep -acE 'filled outbound|leg replaced' "$WORK/bmc.log"); CLOSES=$(grep -ac 'connection closed' "$WORK/bmc.log")
echo "final: core $CT bmc $BT; Core saw $RESETS reset(s); bmc installed the leg $INSTALLS time(s), closed $CLOSES"
if [ "$RESETS" = 0 ] && [ "$INSTALLS" = 1 ] && [ "$CLOSES" = 0 ] && [ "$BT" = "$CT" ]; then echo "PASS: one leg, held for ${RUN_S}s through $((CT-110)) blocks"; RC=0
else echo "FAIL"; grep -aE 'disconnect|Misbehav' "$CORE_DIR/regtest/debug.log" | tail -4 | cut -c1-160; grep -aE 'connection closed|leg replaced' "$WORK/bmc.log" | tail -4 | cut -c1-160; RC=1; fi
for p in $(for q in /proc/[0-9]*; do grep -aqs "$WORK/bmc" $q/cmdline 2>/dev/null && [ "$(basename "$(readlink $q/exe 2>/dev/null)")" != "bash" ] && echo ${q#/proc/}; done); do kill $p 2>/dev/null; done
core stop >/dev/null 2>&1; sleep 2; [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; exit $RC
