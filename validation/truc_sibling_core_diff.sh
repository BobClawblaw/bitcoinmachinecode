#!/usr/bin/env bash
# truc_sibling_core_diff.sh -- TRUC sibling eviction (BIP431), against a REAL
# regtest Bitcoin Core, because the rules were implemented by reading Core's
# source and that is a weaker claim than watching Core do it.
#
# The shape of the thing: a TRUC parent may have exactly one unconfirmed child.
# A SECOND child spends a different output of the parent, so it double-spends
# nothing and ordinary RBF cannot reach it -- only the TRUC descendant rule
# sees it. Core does not simply refuse: it offers the incumbent child up for
# eviction and lets the ordinary replacement arithmetic decide. Refusing
# outright is what this node used to do.
#
# Core is BOTH the transaction factory and the judge. It builds and signs
# every transaction, so nothing here depends on our signer, and each node then
# gets the SAME bytes over its own RPC. The two nodes are DISCONNECTED before
# any of it, or relay would carry a transaction from whichever node saw it
# first and neither verdict would be its own.
#
#   1. parent P (version 3) accepted by both
#   2. child A (version 3, spends P:0) accepted by both -- the incumbent
#   3. child B spending P:1 and paying the SAME as A: refused by both
#      (the arithmetic refuses it; the topology is no longer the reason)
#   4. child B' paying well over A: ACCEPTED by both, and A is gone from both
#      mempools -- the eviction itself
#   5. a third child paying less than the new incumbent: refused by both
#   6. the two mempools are identical, by txid set, after every step
#
# Usage: validation/truc_sibling_core_diff.sh [--keep]
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-source/build-zmq/bin}
ROOT=${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
BMC_BIN=${BMC_BIN:-$ROOT/asm/daemon/bitcoind}
WORK=${WORK:-/tmp/truc-diff-$$}
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
CORE_P2P=19644; CORE_RPC=19660; BMC_P2P=19655; BMC_RPC=19646
KEEP=0; [ "${1:-}" = "--keep" ] && KEEP=1
FAILURES=0; PASSES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){   echo "  ok  $*"; PASSES=$((PASSES+1)); }

cleanup(){
  [ $KEEP -eq 1 ] && { echo "(--keep: work dir $WORK)"; return; }
  # only the pids this script started -- never a pattern kill, which on this
  # box would also match the production daemon
  for p in ${BMC_PIDS:-} ${CORE_PID:-}; do kill "$p" 2>/dev/null; done
  sleep 2; for p in ${BMC_PIDS:-}; do kill -9 "$p" 2>/dev/null; done
  rm -rf "$WORK"
}
trap cleanup EXIT

core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
cw(){   core -rpcwallet=trucw "$@"; }
bmc(){  local m=$1; shift; local p=${1:-[]}
  curl -s --user e2e:e2epw -H 'content-type:text/plain' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"t\",\"method\":\"$m\",\"params\":$p}" \
    http://127.0.0.1:$BMC_RPC/; }
# result, or empty on error
bmcr(){ bmc "$@" | python3 -c "import sys,json
try: d=json.load(sys.stdin)
except Exception: print(''); raise SystemExit
print('' if d.get('error') else (d.get('result') if not isinstance(d.get('result'),(dict,list)) else json.dumps(d['result'])))"; }
# error message, or empty when it succeeded
bmce(){ bmc "$@" | python3 -c "import sys,json
try: d=json.load(sys.stdin)
except Exception: print('no-json'); raise SystemExit
e=d.get('error'); print((e.get('message') or '') if e else '')"; }

echo "== setup =="
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do
  ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port already in use"; exit 2; }
done
mkdir -p "$CORE_DIR" "$BMC_DIR"
cat > "$CORE_DIR/bitcoin.conf" <<EOF
regtest=1
[regtest]
port=$CORE_P2P
rpcport=$CORE_RPC
rpcuser=e2e
rpcpassword=e2epw
listen=1
listenonion=0
fallbackfee=0.0001
EOF
cat > "$BMC_DIR/bitcoin.conf" <<EOF
chain=regtest
port=$BMC_P2P
rpcport=$BMC_RPC
rpcuser=e2e
rpcpassword=e2epw
connect=127.0.0.1:$CORE_P2P
EOF

"$CORE_BIN/bitcoind" -datadir="$CORE_DIR" -daemon >/dev/null 2>&1
for i in $(seq 30); do core getblockcount >/dev/null 2>&1 && break; sleep 1; done
core getblockcount >/dev/null 2>&1 || { echo "core never came up"; exit 2; }
CORE_PID=$(cat "$CORE_DIR/regtest/bitcoind.pid")
core createwallet trucw >/dev/null 2>&1 || core loadwallet trucw >/dev/null 2>&1
echo "  core up (pid $CORE_PID)"

( cd "$ROOT/asm" && nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 & )
sleep 10
BMC_PIDS=$(pgrep -f "serve $BMC_DIR" | tr '\n' ' ')
for i in $(seq 30); do [ -n "$(bmcr getblockcount)" ] && break; sleep 1; done
[ -n "$(bmcr getblockcount)" ] || { echo "bmc RPC never came up; see $WORK/bmc.log"; exit 2; }
echo "  bmc up (pids $BMC_PIDS)"

echo "== fund and sync =="
ADDR=$(cw getnewaddress)
cw generatetoaddress 101 "$ADDR" >/dev/null
CORE_H=$(core getblockcount)
for i in $(seq 90); do
  BH=$(bmcr getblockcount); [ "$BH" = "$CORE_H" ] && break; sleep 2
done
[ "$(bmcr getblockcount)" = "$CORE_H" ] || { echo "bmc never synced to $CORE_H; see $WORK/bmc.log"; exit 2; }
echo "  both nodes at height $CORE_H"

# Sever the link. Relay would otherwise carry each transaction to the other
# node the moment one accepted it, and a node that learned a transaction from
# its peer has not given a verdict of its own.
bmcr setnetworkactive '[false]' >/dev/null 2>&1
core setnetworkactive false >/dev/null 2>&1
sleep 2
echo "  nodes disconnected (each verdict is now its own)"

# ---- transaction factory: Core builds and signs, we only set the version ----
# createrawtransaction emits version 2 and TRUC needs 3. The version is
# covered by the signature, so it has to be changed BEFORE signing.
mkv3(){ python3 -c "import sys; h=sys.argv[1]; print('03000000'+h[8:])" "$1"; }

# spend $1:$2 worth $3 BTC, paying $4 BTC to a fresh address -> signed hex
build(){ local ptxid=$1 pvout=$2 pspk=$3 pamt=$4 out=$5
  local addr raw
  addr=$(cw getnewaddress)
  raw=$(cw createrawtransaction "[{\"txid\":\"$ptxid\",\"vout\":$pvout}]" "[{\"$addr\":$out}]")
  raw=$(mkv3 "$raw")
  cw signrawtransactionwithwallet "$raw" \
     "[{\"txid\":\"$ptxid\",\"vout\":$pvout,\"scriptPubKey\":\"$pspk\",\"amount\":$pamt}]" \
     | python3 -c "import sys,json;d=json.load(sys.stdin);
sys.exit('sign failed: '+json.dumps(d.get('errors'))) if not d.get('complete') else None;print(d['hex'])"
}

# submit the same bytes to both, and report the pair of verdicts
both(){ local hex=$1 label=$2 expect=$3
  local cerr berr crc
  crc=$(core sendrawtransaction "$hex" 2>&1) || true
  case "$crc" in *error*|*Error*) cerr=$crc; crc="";; esac
  berr=$(bmce sendrawtransaction "[\"$hex\"]")
  local cacc=0 bacc=0
  [ -n "$crc" ] && cacc=1
  [ -z "$berr" ] && bacc=1
  if [ "$cacc" = "$bacc" ]; then
     if [ "$cacc" = "$expect" ]; then ok "$label: both nodes $( [ $cacc = 1 ] && echo accepted || echo refused )"
     else fail "$label: agreed, but on the WRONG verdict (both $( [ $cacc = 1 ] && echo accepted || echo refused ), expected $expect)"; fi
  else
     fail "$label: DISAGREE -- core=$( [ $cacc = 1 ] && echo accept || echo "reject(${cerr:-?})" ) bmc=$( [ $bacc = 1 ] && echo accept || echo "reject($berr)" )"
  fi
  [ "$cacc" = 0 ] && [ -n "${cerr:-}" ] && echo "        core said: $(echo "$cerr" | tr -d '\n' | cut -c1-120)"
  [ "$bacc" = 0 ] && [ -n "$berr" ] && echo "        bmc  said: $(echo "$berr" | cut -c1-120)"
}

# compare the two mempools as txid SETS
pools_match(){ local label=$1
  local c b
  c=$(core getrawmempool | python3 -c "import sys,json;print(' '.join(sorted(json.load(sys.stdin))))")
  b=$(bmcr getrawmempool | python3 -c "import sys,json;print(' '.join(sorted(json.load(sys.stdin))))")
  if [ "$c" = "$b" ]; then ok "$label: mempools identical ($(echo $c | wc -w) tx)"
  else fail "$label: mempools DIFFER
        core: $c
        bmc : $b"; fi
}

echo "== 1. a TRUC parent with two spendable outputs =="
COINBASE=$(cw listunspent 1 9999 | python3 -c "import sys,json
u=[x for x in json.load(sys.stdin) if x['amount']>=25]
sys.exit('no mature coinbase') if not u else None
x=u[0];print(x['txid'],x['vout'],x['scriptPubKey'],x['amount'])")
set -- $COINBASE; CB_TXID=$1; CB_VOUT=$2; CB_SPK=$3; CB_AMT=$4
A1=$(cw getnewaddress); A2=$(cw getnewaddress); ACHG=$(cw getnewaddress)
# a real change output: spending the whole ~50 BTC coinbase into two 1 BTC
# outputs with nothing else made the implicit fee ~48 BTC, which trips
# sendrawtransaction's own maxfeerate sanity check on BOTH nodes before TRUC
# is even reached.
CHGAMT=$(python3 -c "print(f'{$CB_AMT - 2.0 - 0.0001:.8f}')")
PRAW=$(cw createrawtransaction "[{\"txid\":\"$CB_TXID\",\"vout\":$CB_VOUT}]" \
        "[{\"$A1\":1.0},{\"$A2\":1.0},{\"$ACHG\":$CHGAMT}]")
PRAW=$(mkv3 "$PRAW")
PHEX=$(cw signrawtransactionwithwallet "$PRAW" \
        "[{\"txid\":\"$CB_TXID\",\"vout\":$CB_VOUT,\"scriptPubKey\":\"$CB_SPK\",\"amount\":$CB_AMT}]" \
        | python3 -c "import sys,json;d=json.load(sys.stdin);
sys.exit('parent sign failed') if not d.get('complete') else None;print(d['hex'])")
PTXID=$(core decoderawtransaction "$PHEX" | python3 -c "import sys,json;print(json.load(sys.stdin)['txid'])")
PVER=$(core decoderawtransaction "$PHEX" | python3 -c "import sys,json;print(json.load(sys.stdin)['version'])")
[ "$PVER" = "3" ] && ok "parent really is version 3" || fail "parent version is $PVER, not 3"
both "$PHEX" "parent P" 1
pools_match "after P"

# the parent's own outputs, for the children to spend
P0SPK=$(core decoderawtransaction "$PHEX" | python3 -c "import sys,json;print(json.load(sys.stdin)['vout'][0]['scriptPubKey']['hex'])")
P1SPK=$(core decoderawtransaction "$PHEX" | python3 -c "import sys,json;print(json.load(sys.stdin)['vout'][1]['scriptPubKey']['hex'])")

echo "== 2. child A: the one child a TRUC parent is allowed =="
AHEX=$(build "$PTXID" 0 "$P0SPK" 1.0 0.9999)          # fee 10000 sat
ATXID=$(core decoderawtransaction "$AHEX" | python3 -c "import sys,json;print(json.load(sys.stdin)['txid'])")
both "$AHEX" "child A" 1
pools_match "after A"

echo "== 3. a second child paying the SAME as A: refused by both =="
# no input conflict with A -- it spends the parent's OTHER output -- so plain
# RBF cannot reach it. It loses on the arithmetic, not on the topology.
B1HEX=$(build "$PTXID" 1 "$P1SPK" 1.0 0.9999)         # fee 10000 sat, equal to A
both "$B1HEX" "equal-paying sibling" 0
pools_match "after the refused sibling"

echo "== 4. a second child paying well over A: SIBLING EVICTION =="
B2HEX=$(build "$PTXID" 1 "$P1SPK" 1.0 0.999)          # fee 100000 sat
B2TXID=$(core decoderawtransaction "$B2HEX" | python3 -c "import sys,json;print(json.load(sys.stdin)['txid'])")
both "$B2HEX" "better-paying sibling" 1
pools_match "after the eviction"
CORE_HAS_A=$(core getrawmempool | grep -c "$ATXID" || true)
BMC_HAS_A=$(bmcr getrawmempool | grep -c "$ATXID" || true)
[ "$CORE_HAS_A" = "0" ] && ok "core evicted child A" || fail "core still holds child A"
[ "$BMC_HAS_A" = "0" ]  && ok "bmc evicted child A"  || fail "bmc still holds child A"
CORE_HAS_B=$(core getrawmempool | grep -c "$B2TXID" || true)
BMC_HAS_B=$(bmcr getrawmempool | grep -c "$B2TXID" || true)
[ "$CORE_HAS_B" = "1" ] && ok "core holds the new child" || fail "core lost the new child"
[ "$BMC_HAS_B" = "1" ]  && ok "bmc holds the new child"  || fail "bmc lost the new child"

echo "== 5. a third child must beat the NEW incumbent, not the old one =="
B3HEX=$(build "$PTXID" 0 "$P0SPK" 1.0 0.9995)         # fee 50000 sat < 100000
both "$B3HEX" "third child under the incumbent" 0
pools_match "after the third child"

echo
echo "$PASSES passed, $FAILURES failed"
[ $FAILURES -eq 0 ] || exit 1
