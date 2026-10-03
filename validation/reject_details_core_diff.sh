#!/usr/bin/env bash
# validation/reject_details_core_diff.sh -- Core's reject details, byte for
# byte, against a real Bitcoin Core v31.1 on regtest (2026-10-03).
#
# Core's TxValidationState carries a reject REASON and a DEBUG message;
# ToString() is "reason, debug". sendrawtransaction's error, testmempoolaccept's
# reject-details and submitpackage's per-tx error print ToString();
# testmempoolaccept's reject-reason prints the reason alone. bmc printed the
# bare reason everywhere. Each case below builds ONE transaction with Core's
# wallet (never broadcast unless the case needs it in both pools), submits it
# to both nodes, and compares:
#   testmempoolaccept: reject-reason and reject-details
#   sendrawtransaction: the error message
# Cases: min relay fee (zero fee), bad-txns-in-belowout, RBF less fees, RBF not
# enough additional fees, premature coinbase spend, TRUC inheritance (a
# non-v3 child of a v3 parent), ephemeral dust with a fee, and an undecodable
# transaction (Core's decode-failure messages), and script failures -- a
# wrong signature on P2WPKH, P2PKH and a P2TR key path ("mempool-script-
# verify-flag-failed (<ScriptErrorString>)" with the input/prevout detail).
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-v31.1/bin}
ROOT=${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
BMC_BIN=${BMC_BIN:-$ROOT/asm/daemon/bmcbitcoind}
WORK=${WORK:-${CLAUDE_JOB_DIR:-/tmp}/tmp/reject-details/diff-$$}
# Core binds an onion listener on P2P+1 even with listenonion=0 and no bind=
PB=${PORT_BASE:-22260}; CORE_P2P=$((PB+0)); CORE_RPC=$((PB+2)); BMC_P2P=$((PB+4)); BMC_RPC=$((PB+5))
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
FAILURES=0; PASSES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; PASSES=$((PASSES+1)); }
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
cw(){ core -rpcwallet=w "$@"; }
bmc(){ curl -s -m 20 --user e2e:e2epw -H 'content-type:text/plain' --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$1\",\"params\":${2:-[]}}" http://127.0.0.1:$BMC_RPC/; }
js(){ python3 -c "import sys,json; d=json.load(sys.stdin); $1" 2>/dev/null; }
BMC_PID=""
cleanup(){ [ -n "$BMC_PID" ] && kill "$BMC_PID" 2>/dev/null; for i in $(seq 30); do [ -n "$BMC_PID" ] && kill -0 "$BMC_PID" 2>/dev/null || break; sleep 1; done
           core stop >/dev/null 2>&1; sleep 2; [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }; done
mkdir -p "$CORE_DIR" "$BMC_DIR"
printf 'regtest=1\n[regtest]\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=1\nlistenonion=0\nfallbackfee=0.0002\n' $CORE_P2P $CORE_RPC > "$CORE_DIR/bitcoin.conf"
cat > "$BMC_DIR/bitcoin.conf" <<EOC
chain=regtest
printtoconsole=1
[regtest]
port=$BMC_P2P
rpcport=$BMC_RPC
rpcuser=e2e
rpcpassword=e2epw
connect=127.0.0.1:$CORE_P2P
listenonion=0
EOC
"$CORE_BIN/bitcoind" -datadir="$CORE_DIR" -daemon >/dev/null 2>&1
for i in $(seq 40); do core getblockcount >/dev/null 2>&1 && break; sleep 1; done
core createwallet w >/dev/null
ADDR=$(cw getnewaddress)
cw generatetoaddress 150 "$ADDR" >/dev/null
( cd "$ROOT/asm" && exec "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 ) &
BMC_PID=$!
for i in $(seq 120); do [ "$(bmc getblockcount | js 'print(d["result"])')" = "$(core getblockcount)" ] && break; sleep 1; done
[ "$(bmc getblockcount | js 'print(d["result"])')" = "$(core getblockcount)" ] || { echo "bmc never synced"; tail -20 "$WORK/bmc.log"; exit 2; }
echo "== both at $(core getblockcount)"

# a confirmed wallet UTXO, not yet used by any case
utxo(){ cw listunspent 1 9999999 | python3 -c '
import sys,json
used=set(open(sys.argv[1]).read().split()) if len(sys.argv)>1 else set()
for u in json.load(sys.stdin):
    k="%s:%d"%(u["txid"],u["vout"])
    if k in used or not u.get("spendable") or u["amount"] < 1: continue
    print(u["txid"], u["vout"], "%.8f"%u["amount"]); break' "$WORK/used"; }
touch "$WORK/used"
take(){ read -r UT UV UA <<<"$(utxo)"; echo "$UT:$UV" >> "$WORK/used"; }
sign(){ cw signrawtransactionwithwallet "$1" | js 'print(d["hex"])'; }
amt(){ python3 -c "print('%.8f' % ($1))"; }

# compare one rejected tx on both nodes
compare(){ # $1 label, $2 hex
  local label=$1 hex=$2
  local c b
  c=$(core testmempoolaccept "[\"$hex\"]" | js 'e=d[0]; print(e.get("reject-reason","<allowed>")); print(e.get("reject-details","<none>"))')
  b=$(bmc testmempoolaccept "[[\"$hex\"]]" | js 'e=d["result"][0]; print(e.get("reject-reason","<allowed>")); print(e.get("reject-details","<none>"))')
  if [ "$c" = "$b" ]; then ok "$label: testmempoolaccept reason + details equal: $(echo "$c" | tail -1 | cut -c1-150)"
  else fail "$label: testmempoolaccept differs"; echo "      core: $(echo "$c" | tr '\n' '|')"; echo "      bmc : $(echo "$b" | tr '\n' '|')"; fi
  c=$(core sendrawtransaction "$hex" 2>&1 | sed -n 's/^error message://p;/^error message:/!{/^error code/!p}' | sed '/^$/d' | tail -1)
  b=$(bmc sendrawtransaction "[\"$hex\"]" | js 'print(d["error"]["message"] if d.get("error") else "<accepted>")')
  if [ "$c" = "$b" ]; then ok "$label: sendrawtransaction error equal"
  else fail "$label: sendrawtransaction differs"; echo "      core: $c"; echo "      bmc : $b"; fi
}

echo "== 1. min relay fee not met (zero fee)"
take; DEST=$(cw getnewaddress)
H=$(sign "$(cw createrawtransaction "[{\"txid\":\"$UT\",\"vout\":$UV}]" "{\"$DEST\":$UA}")")
compare "min relay fee" "$H"

echo "== 2. bad-txns-in-belowout"
take; DEST=$(cw getnewaddress)
H=$(sign "$(cw createrawtransaction "[{\"txid\":\"$UT\",\"vout\":$UV}]" "{\"$DEST\":$(amt "$UA + 1")}")")
compare "in-belowout" "$H"

echo "== 3/4. RBF: the original in both pools, then two weaker replacements"
take; DEST=$(cw getnewaddress)
ORIG=$(sign "$(cw createrawtransaction "[{\"txid\":\"$UT\",\"vout\":$UV}]" "{\"$DEST\":$(amt "$UA - 0.0001")}")")
OT=$(core sendrawtransaction "$ORIG")
for i in $(seq 60); do [ "$(bmc getmempoolentry "[\"$OT\"]" | js 'print("ok" if d.get("result") else "no")')" = ok ] && break; sleep 1; done
[ "$(bmc getmempoolentry "[\"$OT\"]" | js 'print("ok" if d.get("result") else "no")')" = ok ] || fail "the original never reached bmc's pool"
D2=$(cw getnewaddress)
H=$(sign "$(cw createrawtransaction "[{\"txid\":\"$UT\",\"vout\":$UV}]" "{\"$D2\":$(amt "$UA - 0.00005")}")")
compare "RBF less fees" "$H"
H=$(sign "$(cw createrawtransaction "[{\"txid\":\"$UT\",\"vout\":$UV}]" "{\"$D2\":$(amt "$UA - 0.0001")}")")
compare "RBF not enough additional fees" "$H"

echo "== 5. premature spend of a coinbase"
CB=$(cw generatetoaddress 1 "$ADDR" | js 'print(d[0])')
for i in $(seq 60); do [ "$(bmc getblockcount | js 'print(d["result"])')" = "$(core getblockcount)" ] && break; sleep 1; done
CBT=$(core getblock "$CB" 2 | js 'print(d["tx"][0]["txid"])')            # no txindex: the block, not getrawtransaction
CBA=$(core getblock "$CB" 2 | js 'print("%.8f" % d["tx"][0]["vout"][0]["value"])')
H=$(sign "$(cw createrawtransaction "[{\"txid\":\"$CBT\",\"vout\":0}]" "{\"$(cw getnewaddress)\":$(amt "$CBA - 0.001")}")")
compare "premature coinbase spend" "$H"

echo "== 6. TRUC: a version=2 child of a version=3 parent"
take; DEST=$(cw getnewaddress)
P3=$(sign "$(cw createrawtransaction "[{\"txid\":\"$UT\",\"vout\":$UV}]" "{\"$DEST\":$(amt "$UA - 0.0001")}" 0 false 3)")
P3T=$(core sendrawtransaction "$P3")
for i in $(seq 60); do [ "$(bmc getmempoolentry "[\"$P3T\"]" | js 'print("ok" if d.get("result") else "no")')" = ok ] && break; sleep 1; done
[ "$(bmc getmempoolentry "[\"$P3T\"]" | js 'print("ok" if d.get("result") else "no")')" = ok ] || fail "the v3 parent never reached bmc's pool"
H=$(sign "$(cw createrawtransaction "[{\"txid\":\"$P3T\",\"vout\":0}]" "{\"$(cw getnewaddress)\":$(amt "$UA - 0.0002")}" 0 false 2)")
compare "TRUC inheritance" "$H"

echo "== 7. ephemeral dust: a dust output and a non-zero fee"
take; DEST=$(cw getnewaddress)
# the dust: a 0-value P2WPKH output (a zero-value OP_RETURN is not dust)
H=$(sign "$(cw createrawtransaction "[{\"txid\":\"$UT\",\"vout\":$UV}]" "[{\"$DEST\":$(amt "$UA - 0.0001")},{\"$(cw getnewaddress)\":0}]")")
compare "ephemeral dust with a fee" "$H"

# a signature byte flipped: still well-formed, now wrong. $1 = address type
badsig(){ local at=$1 a txid vout amt raw hex sig bad
  a=$(cw getnewaddress "" "$at"); txid=$(cw sendtoaddress "$a" 1.5); cw generatetoaddress 1 "$ADDR" >/dev/null
  for i in $(seq 60); do [ "$(bmc getblockcount | js 'print(d["result"])')" = "$(core getblockcount)" ] && break; sleep 1; done
  vout=$(core getrawtransaction "$txid" true "$(cw gettransaction "$txid" | js 'print(d["blockhash"])')" | js "
for o in d['vout']:
    if o['scriptPubKey'].get('address')=='$a': print(o['n'])")
  raw=$(cw createrawtransaction "[{\"txid\":\"$txid\",\"vout\":$vout}]" "{\"$(cw getnewaddress)\":1.4999}")
  hex=$(sign "$raw")
  echo "$hex" | python3 -c "
import sys,json,subprocess
h=sys.stdin.read().strip()
d=json.loads(subprocess.check_output(sys.argv[1:]+['decoderawtransaction',h]))
vin=d['vin'][0]
sig=(vin.get('txinwitness') or [None])[0] if vin.get('txinwitness') else vin['scriptSig']['asm'].split()[0].split('[')[0]
# flip one nibble in the middle of the signature (inside R for DER, inside r for Schnorr)
k=len(sig)//3
bad=sig[:k]+('0' if sig[k]!='0' else '1')+sig[k+1:]
assert h.count(sig)==1, 'signature not unique in the hex'
print(h.replace(sig,bad))" "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw; }

echo "== 9. script failures: a wrong signature, three ways"
H=$(badsig bech32);  compare "P2WPKH wrong signature" "$H"
H=$(badsig legacy);  compare "P2PKH wrong signature" "$H"
H=$(badsig bech32m); compare "P2TR keypath wrong signature" "$H"

echo "== 8. an undecodable transaction"
c=$(core sendrawtransaction "00" 2>&1 | tail -1); b=$(bmc sendrawtransaction '["00"]' | js 'print(d["error"]["message"])')
[ "$c" = "$b" ] && ok "sendrawtransaction decode failure equal: $c" || { fail "sendrawtransaction decode failure differs"; echo "      core: $c"; echo "      bmc : $b"; }
BAD=0200000000
c=$(core testmempoolaccept "[\"$BAD\"]" 2>&1 | tail -1); b=$(bmc testmempoolaccept "[[\"$BAD\"]]" | js 'print(d["error"]["message"] if d.get("error") else "<no error>")')
[ "$c" = "$b" ] && ok "testmempoolaccept decode failure equal: $c" || { fail "testmempoolaccept decode failure differs"; echo "      core: $c"; echo "      bmc : $b"; }

echo
echo "$PASSES passed, $FAILURES failed"
[ $FAILURES = 0 ] && echo "ALL TESTS PASSED" || echo "TESTS FAILED"
exit $FAILURES
