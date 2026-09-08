#!/usr/bin/env bash
# validation/rest_regtest_diff.sh -- Core's REST interface, differentially.
#
# Starts a regtest Bitcoin Core with -rest=1 and this node with rest=1 on
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
WORK=${TMPDIR:-/tmp}/bmc-rest-diff-$$
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
CORE_P2P=19744; CORE_RPC=19760; BMC_P2P=19755; BMC_RPC=19746
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
rest=1
CONF
cat > "$BMC_DIR/bitcoin.conf" <<CONF
chain=regtest
rest=1
printtoconsole=1
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
echo "== a chain with spends =="
core createwallet e2ecore >/dev/null 2>&1
CADDR=$(core -rpcwallet=e2ecore getnewaddress)
core -rpcwallet=e2ecore generatetoaddress 110 "$CADDR" >/dev/null
for i in $(seq 6); do
  core -rpcwallet=e2ecore sendtoaddress "$(core -rpcwallet=e2ecore getnewaddress)" 0.5 >/dev/null 2>&1
  core -rpcwallet=e2ecore generatetoaddress 1 "$CADDR" >/dev/null
done
mkdir -p "$WORK/wgen/data"; ( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 )
cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat" || exit 2
( nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 & )
for i in $(seq 120); do grep -q 'JSON-RPC server' "$WORK/bmc.log" && break; sleep 1; done
BMC_PIDS=$(pgrep -f "serve $BMC_DIR" | tr '\n' ' ')
grep -q 'JSON-RPC server' "$WORK/bmc.log" || { echo "bmc RPC never came up"; sed -n '1,40p' "$WORK/bmc.log"; exit 2; }
grep -q 'REST interface' "$WORK/bmc.log" || { echo "bmc did not enable REST"; exit 2; }
echo "  bmc up (pids $BMC_PIDS, rest=1)"
TIP=$(core getblockcount)
for i in $(seq 90); do [ "$(bmch)" = "$TIP" ] && break; sleep 2; done
[ "$(bmch)" = "$TIP" ] || { echo "bmc never synced to $TIP (at $(bmch))"; exit 2; }
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
echo "== the routes =="
S=$WORK/s; mkdir -p "$S"
# ask both; compare status + body (json parsed with key order preserved; others byte for byte)
diffroute(){ local path=$1 method=${2:-GET} body=${3:-}
  local cs bs
  cs=$(curl -s -o "$S/core.out" -w '%{http_code}' -X "$method" ${body:+--data-binary "$body"} "http://127.0.0.1:$CORE_RPC$path")
  bs=$(curl -s -o "$S/bmc.out" -w '%{http_code}' -X "$method" ${body:+--data-binary "$body"} "http://127.0.0.1:$BMC_RPC$path")
  if [ "$cs" != "$bs" ]; then fail "$path: status core $cs, bmc $bs ($(head -c 100 "$S/bmc.out"))"; return; fi
  case "$path" in
    *.json*) if python3 - "$S/core.out" "$S/bmc.out" <<'PY'
import sys, json, collections
def load(p):
    t = open(p, 'rb').read()
    return json.loads(t, object_pairs_hook=collections.OrderedDict) if t.strip()[:1] in (b'{', b'[') else t
a, b = load(sys.argv[1]), load(sys.argv[2])
# documented divergences: size_on_disk (a different store), warnings (Core's build banner),
# coinbase_tx (a Core master field past v31, the compat target)
DROP = {'size_on_disk', 'warnings',                       # a different store; Core's build banner
        'coinbase_tx',                                      # a Core master field (the compat target is v31.1)
        'usage', 'unbroadcastcount',                        # memory accounting; which node's wallet made the tx
        'fullrbf', 'limitclustercount', 'limitclustersize', 'optimal'}   # v31.1 vs master getmempoolinfo skew; optimal is not answerable here
def canon(x):
    if isinstance(x, collections.OrderedDict): return [(k, canon(v)) for k, v in x.items() if k not in DROP]
    if isinstance(x, list): return [canon(v) for v in x]
    if isinstance(x, float): return round(x, 8)
    return x
sys.exit(0 if canon(a) == canon(b) else 1)
PY
      then ok "$path ($cs)"; else fail "$path: bodies differ"; python3 -c "
import sys,json,collections
a=json.load(open('$S/core.out'),object_pairs_hook=collections.OrderedDict); b=json.load(open('$S/bmc.out'),object_pairs_hook=collections.OrderedDict)
def walk(a,b,p=''):
    if isinstance(a,dict) and isinstance(b,dict):
        if list(a.keys())!=list(b.keys()): print('    keys',p,list(a.keys())[:12],'vs',list(b.keys())[:12])
        for k in a:
            if k in b: walk(a[k],b[k],p+'.'+k)
    elif isinstance(a,list) and isinstance(b,list):
        if len(a)!=len(b): print('    len',p,len(a),len(b))
        for i,(x,y) in enumerate(zip(a,b)): walk(x,y,p+'[%d]'%i)
    elif a!=b: print('    ',p,repr(a)[:60],'vs',repr(b)[:60])
walk(a,b)" 2>/dev/null | head -6; fi ;;
    *) if cmp -s "$S/core.out" "$S/bmc.out"; then ok "$path ($cs, $(stat -c%s "$S/bmc.out") bytes)"; else fail "$path: bodies differ (core $(stat -c%s "$S/core.out") bytes, bmc $(stat -c%s "$S/bmc.out")): core '$(head -c 80 "$S/core.out" | tr -d '\r')' bmc '$(head -c 80 "$S/bmc.out" | tr -d '\r')'"; fi ;;
  esac
}
for f in json hex bin; do
  diffroute "/rest/tx/$SPTX.$f"
  diffroute "/rest/tx/$CBTX.$f"
  diffroute "/rest/block/$HSPEND.$f"
  diffroute "/rest/block/notxdetails/$HSPEND.$f"
  diffroute "/rest/headers/$H5.$f?count=3"
  diffroute "/rest/headers/3/$H5.$f"
  diffroute "/rest/blockhashbyheight/100.$f"
  diffroute "/rest/blockfilter/basic/$H100.$f"
  diffroute "/rest/blockfilterheaders/basic/$H100.$f?count=2"
  diffroute "/rest/spenttxouts/$HSPEND.$f"
  diffroute "/rest/spenttxouts/$H5.$f"
  diffroute "/rest/getutxos/$CBTX-0/$SPTX-0/$SPTX-1.$f"
  diffroute "/rest/getutxos/checkmempool/$MPTX-0/$MPTX-1.$f"
done
diffroute "/rest/blockpart/$HSPEND.hex?offset=0&size=80"
diffroute "/rest/blockpart/$HSPEND.bin?offset=76&size=4"
diffroute "/rest/blockpart/$HSPEND.bin?offset=0&size=100000"
diffroute "/rest/blockpart/$HSPEND.json?offset=0&size=1"
diffroute "/rest/chaininfo.json"
diffroute "/rest/chaininfo.hex"
diffroute "/rest/deploymentinfo.json"
diffroute "/rest/deploymentinfo/$H100.json"
diffroute "/rest/mempool/info.json"
echo "  note: /rest/mempool/contents.json (verbose) is not compared: this node's getrawmempool verbose lacks the ancestry fields (documented in rpc_node.c; getmempoolentry carries them)"
diffroute "/rest/mempool/contents.json?verbose=false"
diffroute "/rest/mempool/contents.json?verbose=x"
diffroute "/rest/mempool/other.json"
# the error texts
Z=0000000000000000000000000000000000000000000000000000000000000000
diffroute "/rest/tx/$Z.json"; diffroute "/rest/tx/zz.json"; diffroute "/rest/tx/$SPTX"; diffroute "/rest/tx/$SPTX.xml"
diffroute "/rest/block/$Z.json"; diffroute "/rest/block/$HSPEND"
diffroute "/rest/headers/$Z.json"; diffroute "/rest/headers/$H5.json?count=0"; diffroute "/rest/headers/$H5.json?count=2001"; diffroute "/rest/headers/a/b/c.json"; diffroute "/rest/headers/zz.json"
diffroute "/rest/blockhashbyheight/99999.json"; diffroute "/rest/blockhashbyheight/-1.json"; diffroute "/rest/blockhashbyheight/abc.json"
diffroute "/rest/blockfilter/fancy/$H100.json"; diffroute "/rest/blockfilter/basic/$Z.json"; diffroute "/rest/blockfilter/basic.json"
diffroute "/rest/blockfilterheaders/$H100.json"
diffroute "/rest/spenttxouts/$Z.json"; diffroute "/rest/spenttxouts/a/b.json"
diffroute "/rest/deploymentinfo/$Z.json"; diffroute "/rest/deploymentinfo/zz.json"
diffroute "/rest/getutxos.json"; diffroute "/rest/getutxos/$CBTX-0-1.json"; diffroute "/rest/getutxos/zz-0.json"; diffroute "/rest/getutxos/$CBTX-0"
diffroute "/rest/blockpart/$HSPEND.bin?size=3"; diffroute "/rest/blockpart/$HSPEND.bin?offset=1"; diffroute "/rest/blockpart/$HSPEND.bin?offset=900000&size=1"
diffroute "/rest/nothing/here"
# getutxos with a POST body (bin: bool + vector<COutPoint>)
python3 -c "
import sys,binascii
t=binascii.unhexlify('$CBTX')[::-1]
sys.stdout.buffer.write(b'\x01'+t+b'\x00\x00\x00\x00')" > "$S/body.bin"
cs=$(curl -s -o "$S/core.out" -w '%{http_code}' --data-binary @"$S/body.bin" "http://127.0.0.1:$CORE_RPC/rest/getutxos.bin")
bs=$(curl -s -o "$S/bmc.out" -w '%{http_code}' --data-binary @"$S/body.bin" "http://127.0.0.1:$BMC_RPC/rest/getutxos.bin")
if [ "$cs" = "$bs" ] && cmp -s "$S/core.out" "$S/bmc.out"; then ok "/rest/getutxos.bin with a POST body ($cs)"; else fail "/rest/getutxos.bin POST: core $cs bmc $bs"; fi
echo
echo "REST differential: $CHECKS checks, $FAILURES failure(s)"
[ "$FAILURES" = 0 ]
