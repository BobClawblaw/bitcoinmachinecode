#!/bin/bash
# validation/tx_relay_regtest_e2e.sh -- transactions a Core peer relays reach
# this node's mempool, in BOTH directions, on regtest.
#
# One Core v31.1 regtest node, two bmc nodes:
#   bmc-out  dials Core (connect=127.0.0.1:<core>)  -- an OUTBOUND leg, worker-validated
#   bmc-in   is dialled by Core (addnode onetry)     -- an INBOUND leg, a serve child
# Core's wallet sends transactions; each bmc must hold every one of them in its
# mempool, and the block Core then mines must be rebuilt by bmc-out from its
# mempool (compact blocks) rather than fetched.
#
# 2026-09-19: both directions failed on every earlier build --
#   out: with connect= naming one host, the block-relay-only filler (which ran
#        before the full-relay top-up) took that host, so the only leg said
#        fRelay=0: Core getpeerinfo relaytxes=false, nothing relayed, and every
#        compact block had "0 from the mempool".
#   in:  the serve child validated against the UTXO snapshot built at boot,
#        which holds no coin newer than the process: Core sent the tx, bmc
#        logged "rejected: 3 missing-inputs", the mempool stayed empty.
# It also checks the block announcements bmc sends Core: every inv(MSG_BLOCK)
# carried the hash byte-reversed, and Core logged each as an unknown block
# ("got inv: block <reversed tip> new").
#
# Usage: validation/tx_relay_regtest_e2e.sh   (KEEP=1 keeps the work dir; CORE_BIN / BMC_BIN override)
set -u
CORE_BIN=${CORE_BIN:-/mnt/nvme8tb/core-build/bitcoin-v31.1/build/bin}; BMC_BIN=${BMC_BIN:-/storage/bitcoinmachinecode/asm/daemon/bmcbitcoind}
WORK=${TMPDIR:-/tmp}/bmc-txrelay-e2e-$$; rm -rf "$WORK"; mkdir -p "$WORK/core" "$WORK/bmcout/regtest" "$WORK/bmcin/regtest"
CORE_P2P=19410; CORE_RPC=19420; OUT_P2P=19430; OUT_RPC=19431; IN_P2P=19440; IN_RPC=19441   # Core also binds CORE_P2P+1 (onion)
for port in $CORE_P2P $((CORE_P2P+1)) $CORE_RPC $OUT_P2P $OUT_RPC $IN_P2P $IN_RPC; do ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use (another run?)"; exit 2; }; done
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$WORK/core" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmc(){ local port=$1 m=$2; shift 2; curl -s --user e2e:e2epw -H 'content-type:text/plain' --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":${1:-[]}}" http://127.0.0.1:$port/ | python3 -c "import sys,json; r=json.load(sys.stdin).get('result'); print(json.dumps(r) if isinstance(r,(list,dict)) else r)" 2>/dev/null; }
cat > "$WORK/core/bitcoin.conf" <<CONF
regtest=1
[regtest]
port=$CORE_P2P
rpcport=$CORE_RPC
rpcuser=e2e
rpcpassword=e2epw
listenonion=0
fallbackfee=0.0001
debug=net
CONF
cat > "$WORK/bmcout/bitcoin.conf" <<CONF
chain=regtest
printtoconsole=1
[regtest]
port=$OUT_P2P
rpcport=$OUT_RPC
rpcuser=e2e
rpcpassword=e2epw
connect=127.0.0.1:$CORE_P2P
CONF
cat > "$WORK/bmcin/bitcoin.conf" <<CONF
chain=regtest
printtoconsole=1
[regtest]
port=$IN_P2P
rpcport=$IN_RPC
rpcuser=e2e
rpcpassword=e2epw
listen=1
CONF
# bmc first, Core second: bmc-out's first dial finds nobody listening, so its
# leg comes from the background fillers -- the path where the block-relay-only
# filler used to win the only connect= host (a node whose Core restarts, or
# starts after it, lands here too)
for n in bmcout bmcin; do ( setsid nohup "$BMC_BIN" serve "$WORK/$n" > "$WORK/$n.log" 2>&1 < /dev/null & ); done
for i in $(seq 120); do grep -aq 'JSON-RPC server' "$WORK/bmcout.log" && grep -aq 'JSON-RPC server' "$WORK/bmcin.log" && break; sleep 1; done
"$CORE_BIN/bitcoind" -datadir="$WORK/core" -daemon >/dev/null 2>&1; sleep 3
core addnode 127.0.0.1:$IN_P2P onetry
core createwallet e2ecore >/dev/null 2>&1; CADDR=$(core -rpcwallet=e2ecore getnewaddress)
core -rpcwallet=e2ecore generatetoaddress 110 "$CADDR" >/dev/null
for i in $(seq 90); do [ "$(bmc $OUT_RPC getblockcount)" = "110" ] && [ "$(bmc $IN_RPC getblockcount)" = "110" ] && break; sleep 2; done
echo "$(date -u +%T) bmc-out at $(bmc $OUT_RPC getblockcount), bmc-in at $(bmc $IN_RPC getblockcount) of 110"
RC=0
# 1. the outbound leg asked for transactions (fRelay=1 in our version)
REL=$(core getpeerinfo | python3 -c "
import sys,json
for p in json.load(sys.stdin):
    if p['inbound'] and 'BitcoinMachineCode' in p['subver']: print(p['relaytxes'])")
if [ "$REL" = "True" ]; then echo "PASS: Core sees bmc-out's leg with relaytxes=true"; else echo "FAIL: Core sees bmc-out's leg with relaytxes=${REL:-<no leg>} (fRelay=0 on its only connect= leg)"; RC=1; fi
# 2. Core-relayed transactions reach both mempools
TXIDS=""; for k in 1 2 3; do TXIDS="$TXIDS $(core -rpcwallet=e2ecore sendtoaddress "$(core -rpcwallet=e2ecore getnewaddress)" 0.5)"; done
have_all(){ local pool; pool=$(bmc $1 getrawmempool); for t in $TXIDS; do case "$pool" in *"$t"*) ;; *) return 1;; esac; done; return 0; }
for i in $(seq 45); do have_all $OUT_RPC && have_all $IN_RPC && break; sleep 1; done
for side in "out $OUT_RPC" "in $IN_RPC"; do set -- $side
  if have_all $2; then echo "PASS: bmc-$1 holds all 3 Core-relayed transactions"; else echo "FAIL: bmc-$1 mempool $(bmc $2 getrawmempool) is missing some of:$TXIDS"; RC=1; fi
done
# 3. the next block is rebuilt from bmc-out's mempool
core -rpcwallet=e2ecore generatetoaddress 1 "$CADDR" >/dev/null
for i in $(seq 30); do [ "$(bmc $OUT_RPC getblockcount)" = "111" ] && break; sleep 1; done
CL=$(grep -a '\[cmpct\] block 111 ' "$WORK/bmcout.log" | tail -1)
FROM=$(echo "$CL" | sed -n 's/.*: \([0-9]*\) tx: \([0-9]*\) from the mempool.*/\2/p')
if [ "${FROM:-0}" -ge 3 ]; then echo "PASS: block 111 rebuilt with $FROM transaction(s) from bmc-out's mempool"; else echo "FAIL: block 111: ${CL:-no [cmpct] line}" | cut -c1-200; RC=1; fi
# 4. block announcements name blocks Core knows (the hash in wire order)
sleep 3
NEW=$(grep -a 'got inv: block .* new' "$WORK/core/regtest/debug.log" | head -1)
NINV=$(grep -ac 'got inv: block' "$WORK/core/regtest/debug.log")
if [ -z "$NEW" ]; then echo "PASS: $NINV block inv(s) from bmc, every one a block Core already has"; else echo "FAIL: Core logged a block inv from bmc as unknown: $NEW"; RC=1; fi
[ $RC = 0 ] && echo "ALL PASS" || { echo "FAILED"; grep -aE 'tx_accept\] last|txhandoff' "$WORK/bmcin.log" | tail -2 | cut -c1-200; }
for p in $(for q in /proc/[0-9]*; do grep -aqs "$WORK/bmc" $q/cmdline 2>/dev/null && [ "$(basename "$(readlink $q/exe 2>/dev/null)")" != "bash" ] && echo ${q#/proc/}; done); do kill $p 2>/dev/null; done
core stop >/dev/null 2>&1; sleep 2; [ "${KEEP:-0}" = 1 ] && echo "work dir kept: $WORK" || rm -rf "$WORK"; exit $RC
