#!/usr/bin/env bash
# bumpfee_regtest_e2e.sh -- prove bumpfee/psbtbumpfee against a REAL chain and
# a real Bitcoin Core, because the hermetic suite can only reach the argument
# surface (missing txid -> -8, unknown txid -> -5). The parts that move money
# -- the fee arithmetic and the change/dust adjustment -- are only observable
# end to end, and the decisive check is not that OUR node likes the result but
# that CORE accepts our replacement as a valid RBF.
#
# What it asserts, all of it computed independently of the implementation:
#   1. the bumped fee equals Core's EstimateFeeRate formula, recomputed here
#      from the original's fee and vsize -- floor(old_fee*1000/vsize) + 1
#      + max(incrementalrelayfee, WALLET_INCREMENTAL_RELAY_FEE=5000), then
#      ceil(rate*vsize/1000).  NOTE the two roundings go in OPPOSITE
#      directions: Core's CFeeRate GetFeePerK evaluates DOWN (which is why it
#      then adds 1 sat/kvB) while GetFee rounds UP.  Getting the base rate
#      wrong by rounding it up too is a real bug this script would catch.
#   2. the change output shrank by EXACTLY the fee increase, and the payment
#      output is untouched.
#   3. the original is evicted from our mempool and the replacement is in it.
#   4. Bitcoin Core has the replacement in ITS mempool and not the original.
#   5. the replacement signals RBF (nSequence 0xfffffffd).
#
# Usage:  validation/bumpfee_regtest_e2e.sh [--keep]
#   --keep   leave both nodes running afterwards (for poking at state)
#
# Needs: a Bitcoin Core build at $CORE_BIN (scratch build, never the
# production install) and this repo's daemon/bitcoind already built.
set -u

CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-source/build/bin}
BMC_BIN=${BMC_BIN:-/storage/bitcoinmachinecode/asm/daemon/bitcoind}
WALLET_CLI=${WALLET_CLI:-/storage/bitcoinmachinecode/asm/daemon/wallet_cli}
WORK=${WORK:-/tmp/bumpfee-e2e-$$}
CORE_DIR=$WORK/core
BMC_DIR=$WORK/bmc
# Deliberately a NON-default regtest P2P port. Until 2026-08-27 this node
# honoured connect= only on a chain's default port and logged+ignored any
# other, so bmc never dialled and sat at tip=0 with peers=0/0; running this
# script on a non-default port is therefore also a regression test for that
# fix. (Core binds P2P+1 as its tor target, so leave the next port free.)
CORE_P2P=19444; CORE_RPC=19460
BMC_P2P=19555;  BMC_RPC=19446
KEEP=0; [ "${1:-}" = "--keep" ] && KEEP=1

fail(){ echo "FAIL: $*" >&2; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; }
FAILURES=0

cleanup(){
  [ $KEEP -eq 1 ] && { echo "(--keep: nodes left running, work dir $WORK)"; return; }
  # kill ONLY the pids this script started -- never a pattern kill, which on
  # this box would also match the production daemon and any benchmark run.
  for p in ${BMC_PIDS:-} ${CORE_PID:-}; do kill "$p" 2>/dev/null; done
  sleep 2
  for p in ${BMC_PIDS:-}; do kill -9 "$p" 2>/dev/null; done
  rm -rf "$WORK"
}
trap cleanup EXIT

core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC \
        -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmc(){ local m=$1; shift; local p=${1:-[]}
  curl -s --user e2e:e2epw -H 'content-type:text/plain' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":$p}" \
    http://127.0.0.1:$BMC_RPC/; }
jq_(){ python3 -c "import sys,json;d=json.load(sys.stdin);
e=d.get('error')
sys.exit('RPC error: '+json.dumps(e)) if e else None
print($1)"; }

echo "== setup =="
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do
  ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port already in use -- another regtest node is running"; exit 2; }
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
CORE_PID=$(cat "$CORE_DIR/regtest/bitcoind.pid")
echo "  core up (pid $CORE_PID)"

# a fresh wallet for this run -- never the production one. wallet_cli writes
# data/bmcwallet.dat relative to CWD, so give it a throwaway CWD.
mkdir -p "$WORK/wgen/data"
( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 )
[ -s "$WORK/wgen/data/bmcwallet.dat" ] || { echo "wallet_cli init produced no wallet (is $WALLET_CLI built?)"; exit 2; }
mkdir -p "$BMC_DIR/regtest"
cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat" || exit 2

( cd /storage/bitcoinmachinecode/asm && nohup "$BMC_BIN" serve "$BMC_DIR" \
    > "$WORK/bmc.log" 2>&1 & echo $! > "$WORK/bmc.pid" )
sleep 12
BMC_PIDS=$(pgrep -f "serve $BMC_DIR" | tr '\n' ' ')
grep -q 'JSON-RPC server' "$WORK/bmc.log" || { echo "bmc RPC never came up; see $WORK/bmc.log"; exit 2; }
echo "  bmc up (pids $BMC_PIDS)"

ADDR=$(bmc getnewaddress | jq_ "d['result']")
CHANGE=$(bmc getrawchangeaddress | jq_ "d['result']")
[ -n "$ADDR" ] && [ -n "$CHANGE" ] || { echo "wallet did not load (no seed); see $WORK/bmc.log"; exit 2; }
echo "  wallet receive=$ADDR change=$CHANGE"

echo "== fund: 101 blocks to the wallet, so a mature coinbase is spendable =="
core generatetoaddress 101 "$ADDR" >/dev/null
core createwallet e2ecore >/dev/null 2>&1
core -rpcwallet=e2ecore generatetoaddress 101 "$(core -rpcwallet=e2ecore getnewaddress)" >/dev/null
CORE_H=$(core getblockcount)
for i in $(seq 60); do
  BMC_H=$(bmc getblockcount | jq_ "d['result']" 2>/dev/null || echo 0)
  [ "$BMC_H" = "$CORE_H" ] && break
  sleep 2
done
[ "${BMC_H:-0}" = "$CORE_H" ] || { echo "bmc never synced to $CORE_H (stuck at ${BMC_H:-?}); see $WORK/bmc.log"; exit 2; }
echo "  both nodes at height $CORE_H"
bmc rescanblockchain '[0]' >/dev/null
sleep 2

# take the first mature coinbase straight from the scan records: this test is
# about bumpfee, not about coin selection (which reads the address index, an
# extension that is off by default).
read -r UTXO_TXID UTXO_VAL <<EOF
$(python3 - "$BMC_DIR/regtest/walletscan.dat" <<'PY'
import struct,sys
d=open(sys.argv[1],'rb').read()
assert d[:8]==b'BMCWSCN2', "unexpected scan format"
h,n=struct.unpack('<II',d[8:16]); body=d[16:]; S=86
for i in range(n):
    r=body[i*S:(i+1)*S]
    ht,=struct.unpack('<I',r[0:4]); val,=struct.unpack('<Q',r[40:48])
    kind=r[48]; branch=r[53]
    if kind==0 and branch==0 and ht<=h-100:      # mature coinbase
        print(r[4:36][::-1].hex(), val); break
else:
    sys.exit("no mature wallet coinbase in the scan records")
PY
)
EOF
[ -n "${UTXO_TXID:-}" ] || { echo "no spendable coin found"; exit 2; }
echo "  spending $UTXO_TXID ($UTXO_VAL sat)"

echo "== build + broadcast the ORIGINAL (fee 10000 sat, with change) =="
DEST=$(core -rpcwallet=e2ecore getnewaddress)
PAY=100000000                                   # 1 BTC to DEST
FEE0=10000
CH0=$((UTXO_VAL - PAY - FEE0))
PAY_BTC=$(python3 -c "print('%.8f'%($PAY/1e8))")
CH_BTC=$(python3 -c "print('%.8f'%($CH0/1e8))")
RAW=$(bmc createrawtransaction \
  "[[{\"txid\":\"$UTXO_TXID\",\"vout\":0,\"sequence\":4294967293}],{\"$DEST\":$PAY_BTC,\"$CHANGE\":$CH_BTC}]" \
  | jq_ "d['result']")
SIGNED=$(bmc signrawtransactionwithwallet "[\"$RAW\"]" | jq_ "d['result']['hex'] if d['result'].get('complete') else sys.exit('signing incomplete')")
ORIG=$(bmc sendrawtransaction "[\"$SIGNED\"]" | jq_ "d['result']")
echo "  original txid $ORIG"

VSIZE=$(bmc getmempoolentry "[\"$ORIG\"]" | jq_ "d['result']['vsize']")
OLDFEE=$(bmc getmempoolentry "[\"$ORIG\"]" | jq_ "round(d['result']['fees']['base']*1e8)")
INCR=$(bmc getmempoolinfo | jq_ "round(d['result']['incrementalrelayfee']*1e8)")
echo "  vsize=$VSIZE old_fee=$OLDFEE incrementalrelayfee=$INCR sat/kvB"

echo "== bumpfee =="
BUMP=$(bmc bumpfee "[\"$ORIG\"]")
echo "$BUMP" | grep -q '"error":null' || { echo "bumpfee failed: $BUMP"; exit 1; }
NEW=$(echo "$BUMP"    | jq_ "d['result']['txid']")
NEWFEE=$(echo "$BUMP" | jq_ "round(d['result']['fee']*1e8)")
echo "  replacement $NEW  fee=$NEWFEE sat"

echo "== assertions =="
# (1) Core's formula, recomputed here, independent of the implementation
EXPECT=$(python3 -c "
import math
old=$OLDFEE; vs=$VSIZE; incr=$INCR
base = old*1000//vs                       # CFeeRate(old,vsize).GetFeePerK() rounds DOWN
rate = base + 1 + max(incr, 5000)         # +1 sat/kvB, then max(node, wallet) increment
print(-(-rate*vs//1000))                  # GetFee() rounds UP
")
[ "$NEWFEE" = "$EXPECT" ] && ok "bumped fee == Core's formula ($NEWFEE sat)" \
                          || fail "fee $NEWFEE != expected $EXPECT"

# (2) the increase came out of change, and the payment is untouched.
# Wait for the replacement to REACH Core before asking it for the decoded tx:
# relay is asynchronous and fetching too early yields an empty file, which
# looks like an arithmetic failure when it is only a race in this script.
for i in $(seq 30); do
  core getrawtransaction "$NEW" true > "$WORK/new.json" 2>/dev/null && \
    [ -s "$WORK/new.json" ] && break
  sleep 1
done
[ -s "$WORK/new.json" ] || { fail "Core never saw the replacement (cannot check outputs)"; : > "$WORK/new.json"; }
python3 - "$WORK/new.json" "$CHANGE" "$DEST" "$CH0" "$PAY" "$OLDFEE" "$NEWFEE" <<'PY' && ok "change shrank by exactly the fee delta; payment untouched" || fail "output arithmetic"
import json,sys,os
if os.path.getsize(sys.argv[1])==0: sys.exit("no decoded replacement to check")
d=json.load(open(sys.argv[1])); change_addr,dest=sys.argv[2],sys.argv[3]
ch0,pay,oldfee,newfee=map(int,sys.argv[4:8])
outs={o["scriptPubKey"].get("address"):round(o["value"]*1e8) for o in d["vout"]}
assert outs.get(dest)==pay, f"payment changed: {outs.get(dest)} != {pay}"
assert outs.get(change_addr)==ch0-(newfee-oldfee), \
    f"change {outs.get(change_addr)} != {ch0}-{newfee-oldfee}"
assert d["vin"][0]["sequence"]==0xfffffffd, "replacement does not signal RBF"
PY

# (3) our mempool swapped them
bmc getmempoolentry "[\"$ORIG\"]" | grep -q '"error":null' \
  && fail "original still in our mempool" || ok "original evicted from our mempool"
bmc getmempoolentry "[\"$NEW\"]"  | grep -q '"error":null' \
  && ok "replacement is in our mempool" || fail "replacement missing from our mempool"

# (4) THE decisive one: Core accepted our replacement
sleep 3
CORE_POOL=$(core getrawmempool | tr -d ' \n')
echo "$CORE_POOL" | grep -q "$NEW"  && ok "Bitcoin Core accepted the replacement" \
                                    || fail "Core does not have the replacement: $CORE_POOL"
echo "$CORE_POOL" | grep -q "$ORIG" && fail "Core still holds the original" \
                                    || ok "Core dropped the original"

echo
[ $FAILURES -eq 0 ] && echo "ALL TESTS PASSED (0 failures)" || echo "FAILURES: $FAILURES"
exit $((FAILURES>0))
