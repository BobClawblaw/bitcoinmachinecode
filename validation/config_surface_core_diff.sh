#!/bin/bash
# validation/config_surface_core_diff.sh -- 2026-09-01 config-surface options,
# side by side with Bitcoin Core on regtest. Same option, same observable.
#   run 1 (defaults):  initialblockdownload false after mining; the 1 sat/vB tx
#                      is in both templates; version 0x20000000; no UA comment
#   run 2 (options):   uacomment in subversion; addresstype=legacy addresses;
#                      maxtipage=1 -> IBD true; blockmintxfee=0.001 -> template
#                      empty; blockversion override; rpcwhitelist 403;
#                      rpccookieperms=group -> 0640; logtimestamps=0
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-source/build-zmq/bin}
ROOT=${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
BMC_BIN=${BMC_BIN:-$ROOT/asm/daemon/bitcoind}
WALLET_CLI=${WALLET_CLI:-$ROOT/asm/daemon/wallet_cli}
WORK=${WORK:-${CLAUDE_JOB_DIR:-/tmp}/tmp/cfg/diff-$$}
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
PB=${PORT_BASE:-20740}; CORE_P2P=$((PB+4)); CORE_RPC=$((PB+20)); BMC_P2P=$((PB+15)); BMC_RPC=$((PB+6))
FAILURES=0; PASSES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; PASSES=$((PASSES+1)); }
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmc(){ local m=$1; shift; local p=${1:-[]}
  curl -s --user e2e:e2epw -H 'content-type:text/plain' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":$p}" http://127.0.0.1:$BMC_RPC/; }
bmc_code(){ local m=$1; shift; local p=${1:-[]}
  curl -s -o /dev/null -w '%{http_code}' --user e2e:e2epw -H 'content-type:text/plain' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":$p}" http://127.0.0.1:$BMC_RPC/; }
core_code(){ local m=$1; shift; local p=${1:-[]}
  curl -s -o /dev/null -w '%{http_code}' --user e2e:e2epw -H 'content-type:text/plain' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":$p}" http://127.0.0.1:$CORE_RPC/; }
res(){ python3 -c "import sys,json;d=json.load(sys.stdin);sys.exit('RPC error: '+json.dumps(d['error'])) if d.get('error') else print(json.dumps(d['result']) if not isinstance(d['result'],str) else d['result'])"; }
jget(){ python3 -c "import sys,json;d=json.load(sys.stdin);print(eval(sys.argv[1]))" "$1"; }
bmch(){ bmc getblockcount | res 2>/dev/null || echo 0; }
BMC_PIDS=""
cleanup(){ stop_all; [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
stop_all(){ core stop >/dev/null 2>&1; CP=$(cat "$CORE_DIR/regtest/bitcoind.pid" 2>/dev/null); for p in $BMC_PIDS; do kill "$p" 2>/dev/null; done; sleep 3
            [ -n "$CP" ] && kill "$CP" 2>/dev/null; for i in $(seq 20); do [ -n "$CP" ] && kill -0 "$CP" 2>/dev/null || break; sleep 1; done
            for p in $BMC_PIDS; do kill -9 "$p" 2>/dev/null; done; BMC_PIDS=""; sleep 1; }
trap cleanup EXIT
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do
  ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }
done
mkdir -p "$CORE_DIR" "$BMC_DIR/regtest"

write_confs(){   # $1 = extra lines for both (Core names == our names)
cat > "$CORE_DIR/bitcoin.conf" <<EOC
regtest=1
[regtest]
port=$CORE_P2P
rpcport=$CORE_RPC
rpcuser=e2e
rpcpassword=e2epw
listen=1
listenonion=0
fallbackfee=0.0001
$1
${2:-}
EOC
cat > "$BMC_DIR/bitcoin.conf" <<EOC
chain=regtest
port=$BMC_P2P
rpcport=$BMC_RPC
rpcuser=e2e
rpcpassword=e2epw
connect=127.0.0.1:$CORE_P2P
fallbackfee=0.0001
$1
EOC
}
start_all(){
  "$CORE_BIN/bitcoind" -datadir="$CORE_DIR" -daemon >/dev/null 2>&1
  for i in $(seq 40); do core getblockcount >/dev/null 2>&1 && break; sleep 1; done
  core getblockcount >/dev/null 2>&1 || { echo "core never came up"; tail -5 "$CORE_DIR/regtest/debug.log"; exit 2; }
  ( cd "$ROOT/asm" && nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc-$RUN.log" 2>&1 & )
  for i in $(seq 40); do grep -q 'JSON-RPC server' "$WORK/bmc-$RUN.log" && break; sleep 1; done
  BMC_PIDS=$(pgrep -f "serve $BMC_DIR" | tr '\n' ' ')
  grep -q 'JSON-RPC server' "$WORK/bmc-$RUN.log" || { echo "bmc never came up"; sed -n '1,40p' "$WORK/bmc-$RUN.log"; exit 2; }
}

echo "== run 1: defaults =="
RUN=1
write_confs ""
mkdir -p "$WORK/wgen/data"; ( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 )
cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat" || exit 2
start_all
core createwallet e2ecore >/dev/null 2>&1
CADDR=$(core -rpcwallet=e2ecore getnewaddress)
core -rpcwallet=e2ecore generatetoaddress 120 "$CADDR" >/dev/null
TIP=$(core getblockcount)
for i in $(seq 60); do [ "$(bmch)" = "$TIP" ] && break; sleep 2; done
[ "$(bmch)" = "$TIP" ] || { echo "bmc never synced to $TIP (at $(bmch))"; exit 2; }
echo "  both at height $TIP"
C_IBD=$(core getblockchaininfo | jget "d['initialblockdownload']"); B_IBD=$(bmc getblockchaininfo | jget "d['result']['initialblockdownload']")
[ "$C_IBD" = "$B_IBD" ] && ok "maxtipage default: initialblockdownload core=$C_IBD bmc=$B_IBD" || fail "initialblockdownload core=$C_IBD bmc=$B_IBD"
C_UA=$(core getnetworkinfo | jget "d['subversion']"); B_UA=$(bmc getnetworkinfo | jget "d['result']['subversion']")
case "$B_UA" in *"("*) fail "bmc subversion carries a comment without uacomment: $B_UA";; *) ok "no uacomment: core=$C_UA bmc=$B_UA";; esac
# a 1 sat/vB transaction relayed to both mempools
TXID=$(core -rpcwallet=e2ecore -named sendtoaddress address="$(core -rpcwallet=e2ecore getnewaddress)" amount=0.1 fee_rate=1)
for i in $(seq 45); do [ "$(bmc getmempoolinfo | jget "d['result']['size']")" = 1 ] && break; sleep 1; done
# relay timing on a two-node regtest is not what this script measures: if the
# leg has not carried it yet, hand the same transaction to our mempool directly
if [ "$(bmc getmempoolinfo | jget "d['result']['size']")" != 1 ]; then
  RAW=$(core getrawtransaction "$TXID"); bmc sendrawtransaction "[\"$RAW\"]" >/dev/null; echo "  (tx submitted to bmc directly; relay had not carried it in 45 s)"
fi
B_MP=$(bmc getmempoolinfo | jget "d['result']['size']"); C_MP=$(core getmempoolinfo | jget "d['size']")
[ "$B_MP" = 1 ] && [ "$C_MP" = 1 ] && ok "the 1 sat/vB tx sits in both mempools" || fail "mempool sizes core=$C_MP bmc=$B_MP"
C_GBT=$(core getblocktemplate '{"rules":["segwit"]}'); B_GBT=$(bmc getblocktemplate '[{"rules":["segwit"]}]' | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)['result']))")
C_N=$(echo "$C_GBT" | jget "len(d['transactions'])"); B_N=$(echo "$B_GBT" | jget "len(d['transactions'])")
C_V=$(echo "$C_GBT" | jget "d['version']"); B_V=$(echo "$B_GBT" | jget "d['version']")
C_W=$(echo "$C_GBT" | jget "d['weightlimit']"); B_W=$(echo "$B_GBT" | jget "d['weightlimit']")
[ "$C_N" = "$B_N" ] && [ "$C_N" = 1 ] && ok "default blockmintxfee: the tx is in both templates (core=$C_N bmc=$B_N)" || fail "template tx count core=$C_N bmc=$B_N"
[ "$C_V" = "$B_V" ] && ok "default blockversion: template version core=$C_V bmc=$B_V" || fail "template version core=$C_V bmc=$B_V"
[ "$C_W" = "$B_W" ] && ok "weightlimit core=$C_W bmc=$B_W" || fail "weightlimit core=$C_W bmc=$B_W"
# Core writes no cookie once rpcpassword is set; ours always does. Core's
# documented modes are owner 0600 / group 0640 / all 0644 -- checked on ours.
B_CK=$(stat -c %a "$BMC_DIR/regtest/.cookie" 2>/dev/null)
[ "$B_CK" = 600 ] && ok "rpccookieperms default: bmc cookie mode $B_CK (Core: 0600; Core writes no cookie when rpcpassword is set)" || fail "bmc cookie mode $B_CK (want 600)"
[ "$(grep -cE '^20[0-9][0-9]-' "$WORK/bmc-1.log")" -gt 0 ] && ok "logtimestamps default: bmc log lines carry a timestamp" || fail "bmc log lines lack a timestamp"
stop_all

echo "== run 2: options =="
RUN=2
write_confs "uacomment=cfgdiff
addresstype=legacy
maxtipage=1
blockmintxfee=0.001
blockversion=536870913
rpcwhitelist=e2e:getblockcount,getblocktemplate,getblockchaininfo,getnetworkinfo,getnewaddress,createwalletdescriptor,getmempoolinfo,getpeerinfo,help,listwallets,loadwallet,stop,getrawtransaction,sendrawtransaction
rpccookieperms=group
logtimestamps=0" "wallet=e2ecore"
start_all
sleep 3
C_IBD=$(core getblockchaininfo | jget "d['initialblockdownload']"); B_IBD=$(bmc getblockchaininfo | jget "d['result']['initialblockdownload']")
[ "$C_IBD" = "$B_IBD" ] && [ "$C_IBD" = True ] && ok "maxtipage=1: initialblockdownload core=$C_IBD bmc=$B_IBD" || fail "maxtipage=1: initialblockdownload core=$C_IBD bmc=$B_IBD"
C_UA=$(core getnetworkinfo | jget "d['subversion']"); B_UA=$(bmc getnetworkinfo | jget "d['result']['subversion']")
case "$C_UA" in *"(cfgdiff)/") C_OK=1;; *) C_OK=0;; esac; case "$B_UA" in *"(cfgdiff)/") B_OK=1;; *) B_OK=0;; esac
[ $C_OK = 1 ] && [ $B_OK = 1 ] && ok "uacomment: core=$C_UA bmc=$B_UA" || fail "uacomment: core=$C_UA bmc=$B_UA"
# the UA on the wire, as the peer saw it: Core's getpeerinfo shows our subver
for i in $(seq 60); do [ "$(core getpeerinfo | python3 -c "import sys,json;print(len(json.load(sys.stdin)))")" -ge 1 ] && break; sleep 1; done
WIRE=$(core getpeerinfo | python3 -c "import sys,json;print(' '.join(p['subver'] for p in json.load(sys.stdin)))")
case "$WIRE" in *"(cfgdiff)/"*) ok "uacomment on the wire: Core sees our subver as $WIRE";; *) fail "Core sees our subver as '$WIRE'";; esac
core -rpcwallet=e2ecore createwalletdescriptor legacy >/dev/null 2>&1
bmc createwalletdescriptor '["legacy"]' >/dev/null 2>&1
C_A=$(core -rpcwallet=e2ecore getnewaddress); B_A=$(bmc getnewaddress | res)
case "$C_A" in m*|n*) C_OK=1;; *) C_OK=0;; esac; case "$B_A" in m*|n*) B_OK=1;; *) B_OK=0;; esac
[ $C_OK = 1 ] && [ $B_OK = 1 ] && ok "addresstype=legacy: getnewaddress core=$C_A bmc=$B_A" || fail "addresstype=legacy: core=$C_A bmc=$B_A"
for i in $(seq 45); do [ "$(bmc getmempoolinfo | jget "d['result']['size']")" = 1 ] && break; sleep 1; done
if [ "$(bmc getmempoolinfo | jget "d['result']['size']")" != 1 ]; then
  RAW=$(core getrawtransaction "$TXID"); bmc sendrawtransaction "[\"$RAW\"]" >/dev/null; echo "  (tx submitted to bmc directly after the restart)"
fi
C_GBT=$(core getblocktemplate '{"rules":["segwit"]}'); B_GBT=$(bmc getblocktemplate '[{"rules":["segwit"]}]' | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)['result']))")
C_N=$(echo "$C_GBT" | jget "len(d['transactions'])"); B_N=$(echo "$B_GBT" | jget "len(d['transactions'])")
C_V=$(echo "$C_GBT" | jget "d['version']"); B_V=$(echo "$B_GBT" | jget "d['version']")
B_MP=$(bmc getmempoolinfo | jget "d['result']['size']"); C_MP=$(core getmempoolinfo | jget "d['size']")
[ "$C_N" = "$B_N" ] && [ "$C_N" = 0 ] && ok "blockmintxfee=0.001: the 1 sat/vB tx is left out of both templates (mempools core=$C_MP bmc=$B_MP)" || fail "blockmintxfee: template tx count core=$C_N bmc=$B_N (mempools core=$C_MP bmc=$B_MP)"
[ "$C_V" = "$B_V" ] && [ "$C_V" = 536870913 ] && ok "blockversion=536870913: template version core=$C_V bmc=$B_V" || fail "blockversion: core=$C_V bmc=$B_V"
C_C=$(core_code getblockcount); B_C=$(bmc_code getblockcount); C_F=$(core_code getmininginfo); B_F=$(bmc_code getmininginfo)
[ "$C_C" = 200 ] && [ "$B_C" = 200 ] && [ "$C_F" = 403 ] && [ "$B_F" = 403 ] && ok "rpcwhitelist: listed method 200/200, unlisted 403/403 (core/bmc)" || fail "rpcwhitelist: listed core=$C_C bmc=$B_C unlisted core=$C_F bmc=$B_F"
B_CK=$(stat -c %a "$BMC_DIR/regtest/.cookie" 2>/dev/null)
[ "$B_CK" = 640 ] && ok "rpccookieperms=group: bmc cookie mode $B_CK (Core: 0640)" || fail "rpccookieperms=group: bmc cookie mode $B_CK (want 640)"
# the boot banner and the lines before the config is read keep their stamp; everything after must not
[ "$(tail -40 "$WORK/bmc-2.log" | grep -cE '^20[0-9][0-9]-')" = 0 ] && ok "logtimestamps=0: bmc log lines carry no timestamp (after the config is read)" || fail "logtimestamps=0: bmc log lines still carry a timestamp"
tail -3 "$CORE_DIR/regtest/debug.log" | grep -qE '^20[0-9][0-9]-' && fail "logtimestamps=0: core log lines still carry a timestamp" || ok "logtimestamps=0: core log lines carry no timestamp"
stop_all
echo; echo "config-surface Core differential: $PASSES ok, $FAILURES failed"
[ $FAILURES = 0 ]
