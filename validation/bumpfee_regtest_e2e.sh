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
# format 3 adds a trailing is_coinbase byte; 2 is still readable
S = {b'BMCWSCN3':87, b'BMCWSCN2':86}.get(d[:8])
if not S: sys.exit("unexpected scan format %r" % d[:8])
h,n=struct.unpack('<II',d[8:16]); body=d[16:]
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

echo "== wallet view (getbalance/listunspent from the rescan, not the addrindex) =="
# Until 2026-08-27 these read the ADDRESS INDEX, an extension that is OFF by
# default, so a fully funded wallet reported 0.00000000 with an empty
# listunspent while walletscan.dat held every receive. They now answer from
# the scan records probed against the live UTXO set.
BAL=$(bmc getbalance | jq_ "round(float(d['result'])*1e8)")
NUTXO=$(bmc listunspent | jq_ "len(d['result'])")
[ "${BAL:-0}" -gt 0 ] 2>/dev/null && ok "getbalance reports the funded wallet ($BAL sat)" \
                                  || fail "getbalance is $BAL on a funded wallet"
[ "${NUTXO:-0}" -gt 0 ] 2>/dev/null && ok "listunspent returns the wallet coins ($NUTXO)" \
                                    || fail "listunspent empty on a funded wallet"

# the balance must equal the sum of the SPENDABLE entries listunspent reports
SUM=$(bmc listunspent | jq_ "sum(round(float(u['amount'])*1e8) for u in d['result'] if u['spendable'])")
[ "$BAL" = "$SUM" ] && ok "getbalance == sum of spendable listunspent entries" \
                    || fail "getbalance $BAL != spendable sum $SUM"

# a FRESH coinbase is immature: listed, not spendable, and not in the balance
core generatetoaddress 1 "$ADDR" >/dev/null
CORE_H2=$(core getblockcount)
for i in $(seq 30); do
  [ "$(bmc getblockcount | jq_ "d['result']")" = "$CORE_H2" ] && break; sleep 2
done
bmc rescanblockchain '[0]' >/dev/null; sleep 2
BAL2=$(bmc getbalance | jq_ "round(float(d['result'])*1e8)")
IMM=$(bmc listunspent | jq_ "sum(1 for u in d['result'] if not u['spendable'])")
IMMSAT=$(bmc listunspent | jq_ "sum(round(float(u['amount'])*1e8) for u in d['result'] if not u['spendable'])")
SUM2=$(bmc listunspent | jq_ "sum(round(float(u['amount'])*1e8) for u in d['result'] if u['spendable'])")
[ "$IMM" -ge 1 ] 2>/dev/null && ok "a fresh coinbase is listed but not spendable ($IMM immature)" \
                             || fail "immature coinbase not marked unspendable"
# NOT "the balance is unchanged" -- confirming the replacement legitimately
# moves it (a coinbase was spent, change came back). The invariant that
# actually proves exclusion is that the balance still equals the SPENDABLE
# total while a non-zero immature total sits outside it.
[ "${IMMSAT:-0}" -gt 0 ] 2>/dev/null && ok "the immature coinbase carries value ($IMMSAT sat)" \
                                     || fail "immature coin has no value to exclude"
[ "$BAL2" = "$SUM2" ] && ok "getbalance still excludes the immature coinbase ($BAL2 sat)" \
                      || fail "getbalance $BAL2 != spendable sum $SUM2"

echo "== gettxout via the download-worker IPC, diffed against Core =="
# The RPC lives in the serve parent and has no UTXO handle; it asks the worker
# over a socketpair. Before that existed it answered null for EVERY outpoint,
# which does not mean "unknown" -- it means "spent". Diffing against Core is
# the check that matters: same outpoint, same answer.
UTX=$(bmc listunspent | jq_ "next((u['txid'],u['vout']) for u in d['result'] if u['spendable'])" 2>/dev/null | tr -d "(),'" )
set -- $UTX; UT=$1; UV=$2
if [ -n "${UT:-}" ]; then
  OURS=$(bmc gettxout "[\"$UT\",$UV]" | jq_ "json.dumps([float(d['result']['value']), d['result']['scriptPubKey']['hex'], d['result']['coinbase']]) if d['result'] else 'null'")
  THEIRS=$(core gettxout "$UT" "$UV" | python3 -c "import sys,json;d=json.load(sys.stdin);print(json.dumps([float(d['value']),d['scriptPubKey']['hex'],d['coinbase']]) if d else 'null')")
  [ "$OURS" = "$THEIRS" ] && ok "gettxout on an unspent coin matches Core exactly" \
                          || fail "gettxout mismatch: ours=$OURS core=$THEIRS"
  [ "$OURS" != "null" ] && ok "gettxout returns the coin (not null) for an unspent outpoint" \
                        || fail "gettxout returned null for a coin listunspent reports"
else
  fail "no spendable coin to query"
fi

# a SPENT outpoint must be null from both -- the bump's original input was
# consumed by the replacement, which is now confirmed.
SPENT_OURS=$(bmc gettxout "[\"$UTXO_TXID\",0]" | jq_ "'null' if d['result'] is None else 'present'")
SPENT_CORE=$(core gettxout "$UTXO_TXID" 0 | python3 -c "
import sys,json
raw=sys.stdin.read().strip()
print('null' if not raw or json.loads(raw) is None else 'present')")
[ "$SPENT_OURS" = "null" ] && [ "$SPENT_CORE" = "null" ] \
  && ok "a spent outpoint is null from both nodes" \
  || fail "spent outpoint: ours=$SPENT_OURS core=$SPENT_CORE"

echo "== submitpackage: a child paying for a parent that cannot stand alone =="
# The whole point of package relay. The parent pays a fee BELOW the min relay
# floor, so it is refused on its own; the child pays enough for both, so the
# package clears the floor on its aggregate feerate. The standalone refusal is
# checked FIRST: without it, "the parent is in the mempool" proves nothing.
read -r P_TXID P_VAL <<PKGEOF
$(python3 - "$BMC_DIR/regtest/walletscan.dat" <<'PKGPY'
import struct,sys
d=open(sys.argv[1],'rb').read()
S = {b'BMCWSCN3':87, b'BMCWSCN2':86}.get(d[:8])
if not S: sys.exit("unexpected scan format")
h,n=struct.unpack('<II',d[8:16]); body=d[16:]
seen=0
for i in range(n):
    r=body[i*S:(i+1)*S]
    ht,=struct.unpack('<I',r[0:4]); val,=struct.unpack('<Q',r[40:48])
    kind=r[48]; branch=r[53]
    if kind==0 and branch==0 and ht<=h-100:
        seen+=1
        if seen==2:            # the bump test already spent the first
            print(r[4:36][::-1].hex(), val); break
else:
    sys.exit("no second mature coinbase")
PKGPY
)
PKGEOF
if [ -n "${P_TXID:-}" ]; then
  PKG_DEST=$(core -rpcwallet=e2ecore getnewaddress)
  P_CH=$((P_VAL - 100))                       # 100 sat on ~141 vB: below the floor
  P_CH_BTC=$(python3 -c "print('%.8f'%($P_CH/1e8))")
  PRAW=$(bmc createrawtransaction "[[{\"txid\":\"$P_TXID\",\"vout\":0,\"sequence\":4294967293}],{\"$CHANGE\":$P_CH_BTC}]" | jq_ "d['result']")
  PSIGNED=$(bmc signrawtransactionwithwallet "[\"$PRAW\"]" | jq_ "d['result']['hex'] if d['result'].get('complete') else sys.exit('parent signing incomplete')")

  ALONE=$(bmc sendrawtransaction "[\"$PSIGNED\"]" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('accepted' if d['error'] is None else d['error']['message'])")
  case "$ALONE" in
    *"fee not met"*) ok "the parent alone is refused: $ALONE" ;;
    *)               fail "parent alone was not fee-refused (got: $ALONE)" ;;
  esac

  PTXID=$(bmc decoderawtransaction "[\"$PSIGNED\"]" | jq_ "d['result']['txid']")
  C_VAL=$((P_CH - 20000))
  C_BTC=$(python3 -c "print('%.8f'%($C_VAL/1e8))")
  CRAW=$(bmc createrawtransaction "[[{\"txid\":\"$PTXID\",\"vout\":0,\"sequence\":4294967293}],{\"$PKG_DEST\":$C_BTC}]" | jq_ "d['result']")
  # The child's input exists ONLY inside this package -- it is in neither the
  # UTXO set nor the mempool -- so the signer is handed the prevout
  # explicitly. BIP143 commits to the value and scriptPubKey, and nothing on
  # chain can supply them yet.
  P_SPK=$(bmc decoderawtransaction "[\"$PSIGNED\"]" | jq_ "d['result']['vout'][0]['scriptPubKey']['hex']")
  P_AMT=$(python3 -c "print('%.8f'%($P_CH/1e8))")
  PREVTXS="[{\"txid\":\"$PTXID\",\"vout\":0,\"scriptPubKey\":\"$P_SPK\",\"amount\":$P_AMT}]"
  CSIGNED=$(bmc signrawtransactionwithwallet "[\"$CRAW\",$PREVTXS]" | jq_ "d['result']['hex'] if d['result'].get('complete') else sys.exit('child signing incomplete')")

  PKG=$(bmc submitpackage "[[\"$PSIGNED\",\"$CSIGNED\"]]")
  PMSG=$(echo "$PKG" | jq_ "d['result']['package_msg']")
  if [ "$PMSG" = "success" ]; then
    ok "submitpackage accepts the pair (package_msg=success)"
  else
    # print the per-transaction errors too: "transaction failed" alone does
    # not say WHICH member, and that is the only useful part.
    fail "submitpackage said: $PMSG -- $(echo "$PKG" | jq_ "'; '.join(k[:12]+': '+v.get('error','ok') for k,v in d['result']['tx-results'].items())")"
  fi
  NRES=$(echo "$PKG" | jq_ "len(d['result']['tx-results'])")
  [ "$NRES" = "2" ] && ok "tx-results has an entry per submitted wtxid" \
                    || fail "tx-results has $NRES entries, expected 2"
  HASEFF=$(echo "$PKG" | jq_ "1 if any('effective-feerate' in v.get('fees',{}) for v in d['result']['tx-results'].values()) else 0")
  [ "$HASEFF" = "1" ] && ok "fees carry Core's effective-feerate/effective-includes" \
                      || fail "effective-feerate missing from tx-results"

  INPOOL=$(bmc getmempoolentry "[\"$PTXID\"]" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('yes' if d['error'] is None else 'no')")
  [ "$INPOOL" = "yes" ] && ok "the below-floor parent is in the mempool via the package" \
                        || fail "parent not in the mempool after submitpackage"

  sleep 2
  CORE_PKG=$(core submitpackage "[\"$PSIGNED\",\"$CSIGNED\"]" 2>&1 | python3 -c "
import sys,json
raw=sys.stdin.read().strip()
try:    print(json.loads(raw).get('package_msg','?'))
except Exception: print(raw.splitlines()[0] if raw else 'no output')")
  case "$CORE_PKG" in
    success|*already*) ok "Bitcoin Core accepts the same package ($CORE_PKG)" ;;
    *)                 fail "Core rejected the package: $CORE_PKG" ;;
  esac
else
  fail "no second mature coinbase for the package test"
fi

echo
[ $FAILURES -eq 0 ] && echo "ALL TESTS PASSED (0 failures)" || echo "FAILURES: $FAILURES"
exit $((FAILURES>0))
