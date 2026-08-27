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

# (0) the bump must be REACHABLE afterwards. gettransaction answers from the
# wallet's send journal, and until 2026-08-27 nothing in the daemon ever wrote
# it -- only the wallet_cli tool did -- so a bump performed over RPC recorded a
# replaced-by linkage that no RPC could then read back. Both directions are
# checked: replaced_by_txid on the original is the one a caller actually asks
# for, and it is the one that needs the ORIGINAL to be journalled too.
RB=$(bmc gettransaction "[\"$ORIG\"]" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('ERR:'+json.dumps(d['error']) if d.get('error') else d['result'].get('replaced_by_txid','MISSING'))")
[ "$RB" = "$NEW" ] && ok "gettransaction(original).replaced_by_txid == the replacement" \
                   || fail "replaced_by_txid: got $RB, expected $NEW"
RP=$(bmc gettransaction "[\"$NEW\"]" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('ERR:'+json.dumps(d['error']) if d.get('error') else d['result'].get('replaces_txid','MISSING'))")
[ "$RP" = "$ORIG" ] && ok "gettransaction(replacement).replaces_txid == the original" \
                    || fail "replaces_txid: got $RP, expected $ORIG"

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

  # testmempoolaccept in PACKAGE mode, on both nodes, while neither has seen
  # the pair. This is the case that used to be impossible: the child spends a
  # parent that exists only inside the array, so validating the members
  # independently reports missing-inputs. Core is asked the same question and
  # the two answers are compared, not just ours checked for plausibility.
  TMA_OURS=$(bmc testmempoolaccept "[[\"$PSIGNED\",\"$CSIGNED\"]]" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if d.get('error'): sys.exit('RPC error: '+json.dumps(d['error']))
r=d['result']
print(len(r), ','.join(str(e.get('allowed')) for e in r),
      'eff' if all('effective-feerate' in e.get('fees',{}) for e in r) else 'noeff',
      'pkgerr' if any('package-error' in e for e in r) else 'nopkgerr')")
  TMA_CORE=$(core testmempoolaccept "[\"$PSIGNED\",\"$CSIGNED\"]" 2>/dev/null | python3 -c "
import sys,json
r=json.load(sys.stdin)
print(len(r), ','.join(str(e.get('allowed')) for e in r),
      'eff' if all('effective-feerate' in e.get('fees',{}) for e in r) else 'noeff',
      'pkgerr' if any('package-error' in e for e in r) else 'nopkgerr')")
  [ "$TMA_OURS" = "$TMA_CORE" ] \
    && ok "testmempoolaccept package mode agrees with Core: $TMA_OURS" \
    || fail "testmempoolaccept package mode: ours=[$TMA_OURS] core=[$TMA_CORE]"
  case "$TMA_OURS" in
    "2 True,True"*) ok "the child spending an in-array parent is allowed" ;;
    *)              fail "package mode did not allow the pair: $TMA_OURS" ;;
  esac

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
  # replaced-transactions: Core reports it ONCE at the top level, as the
  # union across the package's members. This package replaces nothing, so
  # both nodes must say so with an empty array -- present, not missing.
  REP_OURS=$(echo "$PKG" | jq_ "json.dumps(d['result'].get('replaced-transactions','MISSING'))")
  [ "$REP_OURS" = "[]" ] \
    && ok "replaced-transactions is an empty array on a non-replacing package" \
    || fail "replaced-transactions on a non-replacing package: $REP_OURS"

  # ...and now one that DOES replace: a second child spending the same parent
  # output, paying more. Both nodes must name the same displaced txid.
  CTXID=$(bmc decoderawtransaction "[\"$CSIGNED\"]" | jq_ "d['result']['txid']")
  C2_VAL=$((C_VAL - 30000))
  C2_BTC=$(python3 -c "print('%.8f'%($C2_VAL/1e8))")
  C2RAW=$(bmc createrawtransaction "[[{\"txid\":\"$PTXID\",\"vout\":0,\"sequence\":4294967293}],{\"$PKG_DEST\":$C2_BTC}]" | jq_ "d['result']")
  C2SIGNED=$(bmc signrawtransactionwithwallet "[\"$C2RAW\",$PREVTXS]" | jq_ "d['result']['hex'] if d['result'].get('complete') else sys.exit('replacement signing incomplete')")
  # The two nodes are peered, so a replacement submitted to one RELAYS to the
  # other within milliseconds -- and a node that already has the transaction
  # answers "already in mempool" and reports no replacements at all. Cut the
  # link first, so each node performs the replacement itself and reports on
  # its own work. (This bit the first run of this test: Core answered [] and
  # it looked like a disagreement about the field.)
  core disconnectnode "127.0.0.1:$BMC_P2P" >/dev/null 2>&1 \
    || core setban "127.0.0.1" add 600 >/dev/null 2>&1 || true
  sleep 1
  REP2_OURS=$(bmc submitpackage "[[\"$C2SIGNED\"]]" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if d.get('error'): sys.exit('RPC error: '+json.dumps(d['error']))
print(json.dumps(sorted(d['result'].get('replaced-transactions','MISSING'))))")
  REP2_CORE=$(core submitpackage "[\"$C2SIGNED\"]" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(json.dumps(sorted(d.get('replaced-transactions','MISSING'))))")
  core setban "127.0.0.1" remove >/dev/null 2>&1 || true
  [ "$REP2_OURS" = "[\"$CTXID\"]" ] \
    && ok "replaced-transactions names the displaced child" \
    || fail "replaced-transactions: got $REP2_OURS, expected [\"$CTXID\"]"
  [ "$REP2_OURS" = "$REP2_CORE" ] \
    && ok "...and Core reports exactly the same list" \
    || fail "replaced-transactions differs: ours=$REP2_OURS core=$REP2_CORE"
else
  fail "no second mature coinbase for the package test"
fi

echo "== exportwatchonlywallet -> restorewallet round trip =="
# Core promises the export "can be imported into another node using
# restorewallet", so the test is the ROUND TRIP, not that a file appeared.
# What must survive is the descriptor set: restore it under a new name and
# the restored wallet must list exactly what the original exported.
EXP="$WORK/watchonly-export.dat"
EF=$(bmc exportwatchonlywallet "[\"$EXP\"]" | jq_ "d['result']['exported_file']")
[ -s "$EF" ] && ok "exportwatchonlywallet wrote $EF ($(stat -c%s "$EF") bytes)" \
             || fail "no export file at ${EF:-<none>}"
SRC_DESCS=$(bmc listdescriptors | jq_ "json.dumps(sorted(e['desc'] for e in d['result']['descriptors']))")
# it must refuse to clobber -- an export that silently overwrote a wallet
# file would be the worst way to learn the path was wrong
CLOB=$(bmc exportwatchonlywallet "[\"$EXP\"]" | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(d['error']['message'] if d.get('error') else 'OVERWROTE')")
case "$CLOB" in
  *"will not overwrite"*) ok "a second export refuses to clobber the file" ;;
  *)                      fail "export clobbered an existing file: $CLOB" ;;
esac

RW=$(bmc restorewallet "[\"wo-restored\",\"$EXP\"]" | python3 -c "
import sys,json; d=json.load(sys.stdin)
print('ERR:'+d['error']['message'] if d.get('error') else d['result']['name'])")
[ "$RW" = "wo-restored" ] && ok "restorewallet installed the export as a wallet" \
                          || fail "restorewallet: $RW"
DST_DESCS=$(bmc listdescriptors | jq_ "json.dumps(sorted(e['desc'] for e in d['result']['descriptors']))")
[ "$SRC_DESCS" = "$DST_DESCS" ] \
  && ok "the restored watch-only wallet has exactly the exported descriptors" \
  || fail "descriptors differ: src=$SRC_DESCS dst=$DST_DESCS"
WO=$(bmc getwalletinfo | jq_ "str(d['result'].get('private_keys_enabled','?'))")
[ "$WO" = "False" ] && ok "...and it is watch-only (private_keys_enabled=false)" \
                    || fail "restored wallet reports private_keys_enabled=$WO"
# back to the wallet the rest of the script uses
bmc loadwallet "[\"\"]" >/dev/null 2>&1 || true

echo "== the OFFLINE utxo builder agrees with the live writer on genesis =="
# Core writes no chain's genesis coinbase to its chainstate. The live writer
# has skipped it since 2026-08-22; the offline batch builder did not, so a set
# built by the tool was one coin richer than one built by the node -- the two
# writers disagreed about what the UTXO set IS. A dry run over the regtest
# archive proves the skip on real blocks, without building a store.
BU=${BUILD_UTXO:-$(dirname "$BMC_BIN")/build_utxo}
if [ -x "$BU" ]; then
  BUOUT=$("$BU" "$BMC_DIR/regtest" 16 1 --dry-run 0 0 2>&1 | grep -E "genesis_skipped|total tx=")
  case "$BUOUT" in
    *genesis_skipped=1*) ok "build_utxo skips the genesis coinbase, as the live writer does" ;;
    *)                   fail "build_utxo did not skip genesis: $BUOUT" ;;
  esac
  case "$BUOUT" in
    *puts=0*) ok "...and wrote no UTXO for it" ;;
    *)        fail "build_utxo created a UTXO for genesis: $BUOUT" ;;
  esac
else
  fail "build_utxo not built at $BU"
fi

echo "== BIP431 TRUC (version=3) topology, asked of both nodes =="
# TRUC is pure policy, so testmempoolaccept answers it without touching
# either mempool -- and asking BOTH nodes the same question is the only way
# to know our reading of the rules matches the reference implementation's.
# createrawtransaction always emits version 2; the version is patched in the
# raw hex BEFORE signing, so the signature commits to the version we mean.
v3(){ python3 -c "import sys; h=sys.argv[1]; print('03000000'+h[8:])" "$1"; }

read -r T_TXID T_VAL <<TRUCEOF
$(python3 - "$BMC_DIR/regtest/walletscan.dat" <<'TRUCPY'
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
        if seen==3:            # coinbases 1 and 2 are spent by the tests above
            print(r[4:36][::-1].hex(), val); break
else:
    sys.exit("no third mature coinbase")
TRUCPY
)
TRUCEOF

if [ -n "${T_TXID:-}" ]; then
  TD=$(core -rpcwallet=e2ecore getnewaddress)
  # parent: two outputs, so a SECOND child is possible without an input
  # conflict -- that is what isolates the descendant rule from RBF
  PA=$(python3 -c "print('%.8f'%(($T_VAL//2 - 5000)/1e8))")
  TP_RAW=$(bmc createrawtransaction "[[{\"txid\":\"$T_TXID\",\"vout\":0,\"sequence\":4294967293}],{\"$CHANGE\":$PA,\"$TD\":$PA}]" | jq_ "d['result']")
  TP_SIGNED=$(bmc signrawtransactionwithwallet "[\"$(v3 "$TP_RAW")\"]" | jq_ "d['result']['hex'] if d['result'].get('complete') else sys.exit('v3 parent signing incomplete')")
  TP_TXID=$(bmc decoderawtransaction "[\"$TP_SIGNED\"]" | jq_ "d['result']['txid']")
  TP_VER=$(bmc decoderawtransaction "[\"$TP_SIGNED\"]" | jq_ "d['result']['version']")
  [ "$TP_VER" = "3" ] && ok "the parent really is version=3 after signing" \
                      || fail "parent version is $TP_VER, expected 3"
  TP_SPK=$(bmc decoderawtransaction "[\"$TP_SIGNED\"]" | jq_ "d['result']['vout'][0]['scriptPubKey']['hex']")
  TPREV="[{\"txid\":\"$TP_TXID\",\"vout\":0,\"scriptPubKey\":\"$TP_SPK\",\"amount\":$PA}]"

  CA=$(python3 -c "print('%.8f'%(($T_VAL//2 - 25000)/1e8))")
  TC_RAW=$(bmc createrawtransaction "[[{\"txid\":\"$TP_TXID\",\"vout\":0,\"sequence\":4294967293}],{\"$TD\":$CA}]" | jq_ "d['result']")
  TC3=$(bmc signrawtransactionwithwallet "[\"$(v3 "$TC_RAW")\",$TPREV]" | jq_ "d['result']['hex'] if d['result'].get('complete') else sys.exit('v3 child signing incomplete')")
  TC2=$(bmc signrawtransactionwithwallet "[\"$TC_RAW\",$TPREV]" | jq_ "d['result']['hex'] if d['result'].get('complete') else sys.exit('v2 child signing incomplete')")

  # One question, asked of both nodes, reduced to a comparable summary:
  # (allowed / reject-reason / package-error). The package-error is compared
  # on its leading TOKEN only -- Core's field is "TOKEN, debug detail" and the
  # detail names the offending txid and wtxid in prose. We carry the token
  # alone; that is a stated gap in a diagnostic string, not in the verdict.
  truc_ask(){   # $1..$n raw hex
    local arr="" c=""
    for h in "$@"; do arr="$arr$c\"$h\""; c=","; done
    local OURS CORE
    OURS=$(bmc testmempoolaccept "[[$arr]]" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if d.get('error'): sys.exit('RPC error: '+json.dumps(d['error']))
print(';'.join(str(e.get('allowed'))+'/'+str(e.get('reject-reason','-'))+'/'+str(e.get('package-error','-')).split(',')[0] for e in d['result']))")
    CORE=$(core testmempoolaccept "[$arr]" 2>/dev/null | python3 -c "
import sys,json
r=json.load(sys.stdin)
print(';'.join(str(e.get('allowed'))+'/'+str(e.get('reject-reason','-'))+'/'+str(e.get('package-error','-')).split(',')[0] for e in r))")
    echo "$OURS|$CORE"
  }

  R=$(truc_ask "$TP_SIGNED"); O=${R%%|*}; C=${R##*|}
  [ "$O" = "$C" ] && ok "a lone v3 parent: both nodes agree ($O)" \
                  || fail "lone v3 parent: ours=[$O] core=[$C]"

  R=$(truc_ask "$TP_SIGNED" "$TC3"); O=${R%%|*}; C=${R##*|}
  [ "$O" = "$C" ] && ok "v3 parent + v3 child: both nodes agree ($O)" \
                  || fail "v3 parent + v3 child: ours=[$O] core=[$C]"

  R=$(truc_ask "$TP_SIGNED" "$TC2"); O=${R%%|*}; C=${R##*|}
  [ "$O" = "$C" ] && ok "a v2 child of a v3 parent: both nodes agree ($O)" \
                  || fail "v2 child of a v3 parent: ours=[$O] core=[$C]"
  # Core rejects this as a PACKAGE, not per member: `allowed` is omitted on
  # every entry and the reason lands in package-error. Checking reject-reason
  # alone would look like a disagreement when there is none.
  case "$O" in
    *TRUC-violation*) ok "...and both name it a TRUC-violation, at package level" ;;
    *)                fail "a v2 child of a v3 parent was not rejected as TRUC: $O" ;;
  esac
else
  fail "no third mature coinbase for the TRUC test"
fi

echo "== mempool.dat: our dump read by Core, and Core's dump read by us =="
# Format interop, in both directions. A round trip through our own code
# proves only that we agree with ourselves.
SAVED=$(bmc savemempool | jq_ "d['result']['filename']")
if [ -n "${SAVED:-}" ] && [ -s "$SAVED" ]; then
  ok "savemempool wrote $(stat -c%s "$SAVED") bytes"
  OURN=$(python3 -c "
import struct,sys
d=open('$SAVED','rb').read()
v,=struct.unpack('<Q',d[0:8])
n,=struct.unpack('<Q',d[8:16]) if v==1 else (0,)
print(n)")
  [ "${OURN:-0}" -ge 1 ] && ok "our dump lists $OURN transactions" \
                         || fail "our dump lists no transactions"

  # CORE must be able to load it. importmempool is the read path Core would
  # use at startup, so this is the real compatibility question.
  cp "$SAVED" "$CORE_DIR/regtest/ours.dat"
  CORE_IMPORT=$(core importmempool "$CORE_DIR/regtest/ours.dat" 2>&1 | head -3)
  case "$CORE_IMPORT" in
    *error*|*Error*) fail "Core could not load our mempool.dat: $CORE_IMPORT" ;;
    *)               ok  "Bitcoin Core loaded our mempool.dat" ;;
  esac

  # and the other direction: Core writes, we read.
  CORE_SAVED=$(core savemempool | python3 -c "import sys,json;print(json.load(sys.stdin)['filename'])")
  if [ -s "$CORE_SAVED" ]; then
    ok "Core wrote its own dump ($(stat -c%s "$CORE_SAVED") bytes)"
    CV=$(python3 -c "
import struct
d=open('$CORE_SAVED','rb').read()
print(struct.unpack('<Q',d[0:8])[0])")
    ok "Core's dump is version $CV (we read 1 and 2)"
    IMP=$(bmc importmempool "[\"$CORE_SAVED\"]" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('ok' if d['error'] is None else d['error']['message'])")
    [ "$IMP" = "ok" ] && ok "we read Core's own mempool.dat (version $CV)" \
                      || fail "importmempool on Core's dump: $IMP"
  else
    fail "Core did not write a dump"
  fi
else
  fail "savemempool produced nothing"
fi

echo
[ $FAILURES -eq 0 ] && echo "ALL TESTS PASSED (0 failures)" || echo "FAILURES: $FAILURES"
exit $((FAILURES>0))
