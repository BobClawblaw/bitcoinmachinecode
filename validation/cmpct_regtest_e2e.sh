#!/bin/bash
# validation/cmpct_regtest_e2e.sh -- compact blocks received end to end, on regtest.
#
# One bmc leg to a Core regtest node, compact blocks on (there is no switch, as in Core):
# Core mines blocks carrying transactions this node has never seen, so every
# block needs a getblocktxn round trip. PASS = bmc follows Core to the same
# height; FAIL = it stalls. 2026-09-09: it stalled at the first such block on
# every build since the receive path landed (09-06) -- the sync drain matched
# the command name "block" by a 5-byte prefix, so the peer's `blocktxn` reply
# was verified as a block, failed, and the pass was thrown away (where=8).
# Usage: validation/cmpct_regtest_e2e.sh   (KEEP=1 keeps the work dir; BMC_BIN overrides the binary)
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-source/build/bin}; BMC_BIN=${BMC_BIN:-/storage/bitcoinmachinecode/asm/daemon/bmcbitcoind}
WALLET_CLI=${WALLET_CLI:-/storage/bitcoinmachinecode/asm/daemon/bmc_wallet_cli}
WORK=${TMPDIR:-/tmp}/bmc-cmpct-e2e-$$; rm -rf "$WORK"; mkdir -p "$WORK/core" "$WORK/bmc/regtest"
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc; CORE_P2P=19944; CORE_RPC=19960; BMC_P2P=19955; BMC_RPC=19946
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use (another run?)"; exit 2; }; done
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmc(){ local m=$1; shift; curl -s --user e2e:e2epw -H 'content-type:text/plain' --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":${1:-[]}}" http://127.0.0.1:$BMC_RPC/ | python3 -c "import sys,json; print(json.load(sys.stdin).get('result'))" 2>/dev/null; }
cat > "$CORE_DIR/bitcoin.conf" <<CONF
regtest=1
[regtest]
port=$CORE_P2P
rpcport=$CORE_RPC
rpcuser=e2e
rpcpassword=e2epw
listenonion=0
fallbackfee=0.0001
CONF
cat > "$BMC_DIR/bitcoin.conf" <<CONF
chain=regtest
printtoconsole=1
[regtest]
port=$BMC_P2P
rpcport=$BMC_RPC
rpcuser=e2e
rpcpassword=e2epw
connect=127.0.0.1:$CORE_P2P
CONF
"$CORE_BIN/bitcoind" -datadir="$CORE_DIR" -daemon >/dev/null 2>&1; sleep 3
mkdir -p "$WORK/wgen/data"; ( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 ); cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat"
( setsid nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 < /dev/null & )
for i in $(seq 120); do grep -q 'JSON-RPC server' "$WORK/bmc.log" && break; sleep 1; done
core createwallet e2ecore >/dev/null 2>&1; CADDR=$(core -rpcwallet=e2ecore getnewaddress)
core -rpcwallet=e2ecore generatetoaddress 110 "$CADDR" >/dev/null
for i in $(seq 60); do [ "$(bmc getblockcount)" = "110" ] && break; sleep 2; done; echo "$(date -u +%T) bmc at $(bmc getblockcount) of 110 (empty blocks)"
# blocks carrying transactions this node has never seen: each needs a getblocktxn round trip
for i in $(seq 6); do
  for k in 1 2 3; do core -rpcwallet=e2ecore sendtoaddress "$(core -rpcwallet=e2ecore getnewaddress)" 0.5 >/dev/null 2>&1; done
  core -rpcwallet=e2ecore generatetoaddress 1 "$CADDR" >/dev/null; sleep 8
  echo "$(date -u +%T) core $(core getblockcount) bmc $(bmc getblockcount)"
done
for i in $(seq 30); do [ "$(bmc getblockcount)" = "$(core getblockcount)" ] && break; sleep 2; done
CT=$(core getblockcount); BT=$(bmc getblockcount); echo "$(date -u +%T) final: core $CT bmc $BT"
grep -a '\[cmpct\] reconstructed' "$WORK/bmc.log" | tail -1 | cut -c1-160
if [ "$BT" = "$CT" ] && [ "$CT" -ge 116 ]; then echo "PASS: bmc followed Core through $((CT-110)) blocks that needed a getblocktxn round trip"; RC=0; else echo "FAIL: bmc at $BT, Core at $CT"; grep -aE 'closed ours|where=' "$WORK/bmc.log" | tail -4 | cut -c1-160; RC=1; fi
for p in $(for q in /proc/[0-9]*; do grep -aqs "$WORK/bmc" $q/cmdline 2>/dev/null && [ "$(basename "$(readlink $q/exe 2>/dev/null)")" != "bash" ] && echo ${q#/proc/}; done); do kill $p 2>/dev/null; done
core stop >/dev/null 2>&1; sleep 2; [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; exit $RC
