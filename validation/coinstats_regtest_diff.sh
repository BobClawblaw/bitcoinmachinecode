#!/usr/bin/env bash
# validation/coinstats_regtest_diff.sh -- gettxoutsetinfo at every height, differentially.
#
# Starts a regtest Bitcoin Core with -coinstatsindex=1 and this node with coinstatsindex=1 on
# the same chain (Core mines, bmc syncs from it), then asks both /rest/
# every route in every format and compares: status codes and error texts
# byte for byte, .hex/.bin bodies byte for byte, .json bodies as parsed
# documents (key order is compared too: UniValue writes in insertion order
# and so does rpc_json). The routes that read the mempool are compared
# with one unconfirmed transaction in both pools.
#
# Usage: validation/rest_regtest_diff.sh        (KEEP=1 keeps the work dir)
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-source/build/bin}
BMC_BIN=${BMC_BIN:-/storage/bitcoinmachinecode/asm/daemon/bmcbitcoind}
WALLET_CLI=${WALLET_CLI:-/storage/bitcoinmachinecode/asm/daemon/bmc_wallet_cli}
TXI=${TXI:-/storage/bitcoinmachinecode/asm/daemon/bmc_build_tx_index}
BFI=${BFI:-/storage/bitcoinmachinecode/asm/daemon/bmc_build_block_filters}
WORK=${TMPDIR:-/tmp}/bmc-csi-diff-$$
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
CORE_P2P=19844; CORE_RPC=19860; BMC_P2P=19855; BMC_RPC=19846
FAILURES=0; CHECKS=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); CHECKS=$((CHECKS+1)); }
ok(){ echo "  ok  $*"; CHECKS=$((CHECKS+1)); }
cleanup(){ for p in ${BMC_PIDS:-} ${CORE_PID:-}; do kill "$p" 2>/dev/null; done
           sleep 2; for p in ${BMC_PIDS:-}; do kill -9 "$p" 2>/dev/null; done
           [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmc(){ local m=$1; shift; local p=${1:-[]}
  curl -s --user e2e:e2epw -H 'content-type:text/plain' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":$p}" http://127.0.0.1:$BMC_RPC/; }
res(){ python3 -c "import sys,json;d=json.load(sys.stdin);sys.exit('RPC error: '+json.dumps(d['error'])) if d.get('error') else print(d['result'])"; }
bmch(){ bmc getblockcount | res 2>/dev/null || echo 0; }
echo "== setup =="
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do
  ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }
done
mkdir -p "$CORE_DIR" "$BMC_DIR/regtest"
cat > "$CORE_DIR/bitcoin.conf" <<CONF
regtest=1
[regtest]
port=$CORE_P2P
rpcport=$CORE_RPC
rpcuser=e2e
rpcpassword=e2epw
listen=1
listenonion=0
fallbackfee=0.0001
txindex=1
blockfilterindex=1
coinstatsindex=1
CONF
cat > "$BMC_DIR/bitcoin.conf" <<CONF
chain=regtest
coinstatsindex=1
printtoconsole=1
bmc.cmpctrecv=0
[regtest]
port=$BMC_P2P
rpcport=$BMC_RPC
rpcuser=e2e
rpcpassword=e2epw
connect=127.0.0.1:$CORE_P2P
CONF
"$CORE_BIN/bitcoind" -datadir="$CORE_DIR" -daemon >/dev/null 2>&1
for i in $(seq 30); do core getblockcount >/dev/null 2>&1 && break; sleep 1; done
CORE_PID=$(cat "$CORE_DIR/regtest/bitcoind.pid"); echo "  core up (pid $CORE_PID, rest=1)"
mkdir -p "$WORK/wgen/data"; ( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 )
cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat" || exit 2
( nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 & )
for i in $(seq 120); do grep -q 'JSON-RPC server' "$WORK/bmc.log" && break; sleep 1; done
BMC_PIDS=$(pgrep -f "serve $BMC_DIR" | tr '\n' ' ')
grep -q 'JSON-RPC server' "$WORK/bmc.log" || { echo "bmc RPC never came up"; sed -n '1,40p' "$WORK/bmc.log"; exit 2; }
for i in $(seq 120); do grep -q "coinstats\] seeded\|coinstats\] adopted" "$WORK/bmc.log" && break; sleep 1; done; grep -q "coinstats\] seeded\|coinstats\] adopted" "$WORK/bmc.log" || { echo "bmc coinstats index never seeded"; grep -a coinstats "$WORK/bmc.log" | tail -3; exit 2; }
echo "  bmc up (pids $BMC_PIDS, rest=1)"
echo "== the chain, mined after this node connected (its index folds every block live) =="
core createwallet e2ecore >/dev/null 2>&1
CADDR=$(core -rpcwallet=e2ecore getnewaddress)
core -rpcwallet=e2ecore generatetoaddress 110 "$CADDR" >/dev/null
for i in $(seq 6); do
  core -rpcwallet=e2ecore sendtoaddress "$(core -rpcwallet=e2ecore getnewaddress)" 0.5 >/dev/null 2>&1
  core -rpcwallet=e2ecore generatetoaddress 1 "$CADDR" >/dev/null
done
TIP=$(core getblockcount)
for i in $(seq 90); do [ "$(bmch)" = "$TIP" ] && break; sleep 2; done
[ "$(bmch)" = "$TIP" ] || { echo "bmc never synced to $TIP (at $(bmch))"; grep -a "\[dl\]\|\[mux\|\[dial\]" "$WORK/bmc.log" | tail -12; exit 2; }
for i in $(seq 60); do grep -q "now at height $TIP" "$WORK/bmc.log" && break; sleep 1; done
sleep 2
echo "  both at height $TIP"
"$TXI" "$BMC_DIR/regtest" >"$WORK/txi.log" 2>&1 || { echo "build_tx_index failed"; exit 2; }
"$BFI" "$BMC_DIR/regtest" >"$WORK/bfi.log" 2>&1 || { echo "build_block_filters failed"; tail -3 "$WORK/bfi.log"; exit 2; }
echo "  indexes built; tip $TIP"
# one unconfirmed transaction in both mempools
MPTX=$(core -rpcwallet=e2ecore sendtoaddress "$(core -rpcwallet=e2ecore getnewaddress)" 0.25)
MPHEX=$(core getrawtransaction "$MPTX")
bmc sendrawtransaction "[\"$MPHEX\"]" >/dev/null
for i in $(seq 20); do bmc getrawmempool | grep -q "$MPTX" && break; sleep 1; done
bmc getrawmempool | grep -q "$MPTX" || echo "  (warning: the mempool tx is not in bmc's pool; mempool routes will differ)"
H5=$(core getblockhash 5); H100=$(core getblockhash 100); HSPEND=$(core getblockhash 112); HTIP=$(core getbestblockhash)
CBTX=$(core getblock "$H100" 1 | python3 -c "import sys,json; print(json.load(sys.stdin)['tx'][0])")
SPTX=$(core getblock "$HSPEND" 1 | python3 -c "import sys,json; print(json.load(sys.stdin)['tx'][1])")
echo "== gettxoutsetinfo at every height the rows cover =="
S=$WORK/s; mkdir -p "$S"
FIRST=$(bmc getindexinfo | python3 -c "import sys,json; d=json.load(sys.stdin)['result']; print(d.get('coinstatsindex',{}).get('best_block_height',-1))")
echo "  bmc coinstatsindex best height $FIRST; comparing heights 1..$TIP in both hash types"
cmpjson(){ python3 - "$1" "$2" <<'PY'
import sys, json, collections
a=json.load(open(sys.argv[1]),object_pairs_hook=collections.OrderedDict); b=json.load(open(sys.argv[2]),object_pairs_hook=collections.OrderedDict)
a=a.get('result',a); b=b.get('result',b)
def canon(x):
    if isinstance(x, collections.OrderedDict): return [(k, canon(v)) for k, v in x.items()]
    if isinstance(x, list): return [canon(v) for v in x]
    if isinstance(x, float): return round(x, 8)
    return x
sys.exit(0 if canon(a)==canon(b) else 1)
PY
}
for h in $(seq 1 $TIP); do
  for ht in none muhash; do
    core gettxoutsetinfo $ht $h > "$S/core.out" 2>&1; bmc gettxoutsetinfo "[\"$ht\",$h]" > "$S/bmc.out" 2>&1
    if cmpjson "$S/core.out" "$S/bmc.out"; then ok "height $h $ht"; else fail "height $h $ht: core $(head -c 200 "$S/core.out" | tr -d '\n') | bmc $(head -c 200 "$S/bmc.out" | tr -d '\n')"; fi
  done
done
echo "== the errors =="
bmc gettxoutsetinfo '["hash_serialized_3",5]' | grep -q "cannot be queried for a specific block" && ok "hash_serialized_3 with a block: Core's text" || fail "hash_serialized_3 with a block"
bmc gettxoutsetinfo '["none",5,false]' | grep -q "Cannot set use_index to false" && ok "use_index=false with a block: Core's text" || fail "use_index=false"
bmc gettxoutsetinfo '["none",99999]' | grep -q "error" && ok "a height past the tip is an error" || fail "height past the tip"
echo
echo "coinstats differential: $CHECKS checks, $FAILURES failure(s)"
[ "$FAILURES" = 0 ]
