#!/usr/bin/env bash
# validation/package_rbf_core_diff.sh -- package RBF (submitpackage replacing
# mempool transactions), bmc against Bitcoin Core v31.1 on regtest.
#
# Core's MemPoolAccept::PackageRBFChecks lets a 1-parent-1-child package
# replace mempool transactions that the parent ALONE could not: the parent
# conflicts and pays too little, the child pays for both. Its rules:
#   - the package is exactly 1 parent + 1 child, neither with mempool parents;
#   - the replaced set is under Core's limit (GetEntriesForConflicts);
#   - PaysForRBF over the package's total fee and vsize;
#   - package feerate > parent feerate (the child is not just paying anti-DoS);
#   - cluster limits; the feerate diagram improves.
# Both nodes get the same raw transactions with networking OFF (no relay
# between them), and every case compares Core's submitpackage answer with
# ours: package_msg, the per-member result, and replaced-transactions.
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-v31.1/bin}
ROOT=${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
BMC_BIN=${BMC_BIN:-$ROOT/asm/daemon/bmcbitcoind}
WORK=${WORK:-${CLAUDE_JOB_DIR:-/tmp}/tmp/pkgrbf/e2e-$$}
# Core binds an onion listener on P2P+1: keep that port free
PB=${PORT_BASE:-22040}; CORE_P2P=$((PB+0)); CORE_RPC=$((PB+2)); BMC_P2P=$((PB+4)); BMC_RPC=$((PB+5))
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
FAILURES=0; PASSES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; PASSES=$((PASSES+1)); }
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
cw(){ core -rpcwallet=w "$@"; }
bmc(){ curl -s -m 30 --user e2e:e2epw -H 'content-type:text/plain' --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$1\",\"params\":${2:-[]}}" http://127.0.0.1:$BMC_RPC/; }
bmch(){ bmc getblockcount | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"])' 2>/dev/null || echo -1; }
BMC_PID=""
cleanup(){ [ -n "$BMC_PID" ] && kill "$BMC_PID" 2>/dev/null; core stop >/dev/null 2>&1; sleep 2; [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }; done
mkdir -p "$CORE_DIR" "$BMC_DIR"
cat > "$CORE_DIR/bitcoin.conf" <<EOC
regtest=1
[regtest]
port=$CORE_P2P
rpcport=$CORE_RPC
rpcuser=e2e
rpcpassword=e2epw
listenonion=0
fallbackfee=0.0001
EOC
cat > "$BMC_DIR/bitcoin.conf" <<EOC
chain=regtest
printtoconsole=1
# network-specific keys apply on regtest only inside [regtest] (Core's rule)
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
core getblockcount >/dev/null 2>&1 || { echo "core never came up"; exit 2; }
core createwallet w >/dev/null
ADDR=$(cw getnewaddress "" bech32)
cw generatetoaddress 120 "$ADDR" >/dev/null
( cd "$ROOT/asm" && exec "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 ) & BMC_PID=$!
CT=$(core getblockcount)
for i in $(seq 90); do [ "$(bmch)" = "$CT" ] && break; sleep 1; done
[ "$(bmch)" = "$CT" ] || { echo "bmc never synced to $CT (at $(bmch))"; exit 2; }
core setnetworkactive false >/dev/null
for i in $(seq 20); do [ "$(core getconnectioncount)" = 0 ] && break; sleep 0.5; done
echo "== both at $CT, networking off: every transaction goes to each node by hand"

# coins: mature coinbase outputs of the Core wallet, one per case
mapfile -t COINS < <(cw listunspent 1 9999 | python3 -c "
import sys,json
for u in sorted(json.load(sys.stdin), key=lambda u:(u['txid'],u['vout'])):
    if abs(u['amount']-50)<1e-9: print(u['txid'],u['vout'],u['scriptPubKey'])")
[ "${#COINS[@]}" -ge 8 ] || { echo "not enough mature coins (${#COINS[@]})"; exit 2; }

# build + sign a tx: $1 = inputs json, $2 = outputs json, $3 = prevtxs json (optional)
mk(){ local raw; raw=$(cw createrawtransaction "$1" "$2") || return 1
      cw signrawtransactionwithwallet "$raw" "${3:-[]}" | python3 -c "
import sys,json; d=json.load(sys.stdin)
sys.exit('signing incomplete: '+json.dumps(d.get('errors'))) if not d['complete'] else print(d['hex'])"; }
btc(){ python3 -c "print('%.8f'%($1/1e8))"; }
txid(){ cw decoderawtransaction "$1" | python3 -c 'import sys,json;print(json.load(sys.stdin)["txid"])'; }
spk_of(){ cw decoderawtransaction "$1" | python3 -c "import sys,json;print(json.load(sys.stdin)['vout'][$2]['scriptPubKey']['hex'])"; }
send_both(){   # sendrawtransaction to both; both must accept (setup, not a case)
  local a b
  a=$(core sendrawtransaction "$1" 2>&1); b=$(bmc sendrawtransaction "[\"$1\"]" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["result"] if not d.get("error") else "ERR "+d["error"]["message"])')
  [ "$a" = "$b" ] || { echo "  setup: sendrawtransaction differs: core=$a bmc=$b"; return 1; }
}
# summarise a submitpackage answer: package_msg | per-member error-or-ok | sorted replaced
summ(){ python3 -c "
import sys,json
d=json.load(sys.stdin)
if isinstance(d,dict) and 'result' in d:
    if d.get('error'): print('RPCERR', d['error'].get('message')); sys.exit()
    d=d['result']
r=d.get('tx-results',{})
mem=[]
# a member's error is compared by its REASON (before the first ', '): Core
# appends a debug string (the replaced txid, amounts) that bmc's per-member
# reasons do not carry yet; package_msg is compared in full
for w in sorted(r):
    e=r[w]
    if e.get('error'): mem.append(e['error'].split(', ')[0]); continue
    f=e.get('fees',{})
    # which kind of valid: alone / in the package evaluation / already in the
    # mempool shows as the effective feerate and how many it includes
    mem.append('ok:%s:%s/%d'%(f.get('base'), f.get('effective-feerate','-'), len(f.get('effective-includes',[]))))
print(d.get('package_msg'),'|',','.join(mem),'|',','.join(sorted(d.get('replaced-transactions',[]))))"; }
compare(){   # $1 = name, $2 = parent hex, $3 = child hex, $4 = expected Core outcome (accept|reject)
  local C B
  C=$(core submitpackage "[\"$2\",\"$3\"]" 2>&1 | summ 2>&1)
  B=$(bmc submitpackage "[[\"$2\",\"$3\"]]" | summ 2>&1)
  echo "    core: $C"; echo "    bmc : $B"
  case "$4" in
    accept) case "$C" in success*) ;; *) fail "$1: Core did not accept -- the case is wrong, not bmc"; return;; esac ;;
    reject) case "$C" in success*) fail "$1: Core accepted -- the case is wrong, not bmc"; return;; esac ;;
  esac
  [ "$C" = "$B" ] && ok "$1: same answer as Core" || fail "$1: ours differs from Core"
}
# one case's transactions: coin index $1, A's fee $2, P's fee $3, C's fee $4
# A: coin -> ADDR (in both mempools); P: same coin -> ADDR (conflicts with A);
# C: spends P:0 -> ADDR
build_case(){
  read -r CTX CV CSPK <<< "${COINS[$1]}"
  local amt=5000000000
  A=$(mk "[{\"txid\":\"$CTX\",\"vout\":$CV,\"sequence\":4294967293}]" "[{\"$ADDR\":$(btc $((amt-$2)))}]") || return 1
  P=$(mk "[{\"txid\":\"$CTX\",\"vout\":$CV,\"sequence\":4294967293}]" "[{\"$ADDR\":$(btc $((amt-$3-1)))}]") || return 1
  local ptx pspk; ptx=$(txid "$P"); pspk=$(spk_of "$P" 0)
  local pamt=$((amt-$3-1))
  C=$(mk "[{\"txid\":\"$ptx\",\"vout\":0,\"sequence\":4294967293}]" "[{\"$ADDR\":$(btc $((pamt-$4)))}]" \
         "[{\"txid\":\"$ptx\",\"vout\":0,\"scriptPubKey\":\"$pspk\",\"amount\":$(btc $pamt)}]") || return 1
}

echo "== 0. sendrawtransaction of a transaction already in the mempool: Core returns its txid"
read -r DTX DV DSPK <<< "${COINS[5]}"
D=$(mk "[{\"txid\":\"$DTX\",\"vout\":$DV}]" "[{\"$ADDR\":$(btc $((5000000000-2000)))}]") && send_both "$D"
DC=$(core sendrawtransaction "$D" 2>&1)
DB=$(bmc sendrawtransaction "[\"$D\"]" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["result"] if not d.get("error") else "ERR %s %s"%(d["error"]["code"],d["error"]["message"]))')
echo "    core: $DC"; echo "    bmc : $DB"
[ "$DC" = "$DB" ] && ok "resubmitting a mempool transaction: same answer as Core (its txid)" \
                 || fail "resubmitting a mempool transaction: ours differs from Core"

echo "== 1. the parent alone cannot replace A; parent + child can (Core: package RBF)"
build_case 0 1000 500 20000 && send_both "$A" && compare "package RBF accepted" "$P" "$C" accept
P1=$P; C1=$C

echo "== 2. package feerate not above the parent's: the child pays only anti-DoS"
# P pays a lot on its own, C almost nothing: package feerate <= parent feerate
build_case 1 1000 5000 1 && send_both "$A" && compare "package feerate <= parent feerate" "$P" "$C" reject

echo "== 3. insufficient anti-DoS fees: the package pays less than A + incremental"
build_case 2 30000 500 1000 && send_both "$A" && compare "insufficient anti-DoS fees" "$P" "$C" reject

echo "== 4. the parent has a mempool ancestor: Core will not package-RBF"
read -r GTX GV GSPK <<< "${COINS[3]}"
G=$(mk "[{\"txid\":\"$GTX\",\"vout\":$GV}]" "[{\"$ADDR\":$(btc $((5000000000-1000)))}]") && send_both "$G"
GID=$(txid "$G"); GSPK0=$(spk_of "$G" 0)
read -r CTX CV CSPK <<< "${COINS[4]}"
A=$(mk "[{\"txid\":\"$CTX\",\"vout\":$CV,\"sequence\":4294967293}]" "[{\"$ADDR\":$(btc $((5000000000-1000)))}]") && send_both "$A"
# P spends coin 4 (conflicts with A) AND G:0 (a mempool parent)
P=$(mk "[{\"txid\":\"$CTX\",\"vout\":$CV,\"sequence\":4294967293},{\"txid\":\"$GID\",\"vout\":0,\"sequence\":4294967293}]" \
       "[{\"$ADDR\":$(btc $((5000000000+4999999000-600)))}]")
PID=$(txid "$P"); PSPK=$(spk_of "$P" 0); PAMT=$((5000000000+4999999000-600))
C=$(mk "[{\"txid\":\"$PID\",\"vout\":0,\"sequence\":4294967293}]" "[{\"$ADDR\":$(btc $((PAMT-30000)))}]" \
       "[{\"txid\":\"$PID\",\"vout\":0,\"scriptPubKey\":\"$PSPK\",\"amount\":$(btc $PAMT)}]")
compare "parent with a mempool ancestor" "$P" "$C" reject

echo "== 5. case 1's package again: both members already in the mempool (base fee only)"
compare "resubmitted package" "$P1" "$C1" accept

echo "== 6. two parents, one replacing: Core package-RBFs only 1-parent-1-child"
read -r XTX XV XSPK <<< "${COINS[6]}"
read -r YTX YV YSPK <<< "${COINS[7]}"
AX=$(mk "[{\"txid\":\"$XTX\",\"vout\":$XV,\"sequence\":4294967293}]" "[{\"$ADDR\":$(btc $((5000000000-1000)))}]") && send_both "$AX"
PX=$(mk "[{\"txid\":\"$XTX\",\"vout\":$XV,\"sequence\":4294967293}]" "[{\"$ADDR\":$(btc $((5000000000-500)))}]")
PY=$(mk "[{\"txid\":\"$YTX\",\"vout\":$YV,\"sequence\":4294967293}]" "[{\"$ADDR\":$(btc $((5000000000-50)))}]")
PXID=$(txid "$PX"); PYID=$(txid "$PY"); PXS=$(spk_of "$PX" 0); PYS=$(spk_of "$PY" 0)
CXY=$(mk "[{\"txid\":\"$PXID\",\"vout\":0,\"sequence\":4294967293},{\"txid\":\"$PYID\",\"vout\":0,\"sequence\":4294967293}]" \
         "[{\"$ADDR\":$(btc $((5000000000-500 + 5000000000-50 - 40000)))}]" \
         "[{\"txid\":\"$PXID\",\"vout\":0,\"scriptPubKey\":\"$PXS\",\"amount\":$(btc $((5000000000-500)))},{\"txid\":\"$PYID\",\"vout\":0,\"scriptPubKey\":\"$PYS\",\"amount\":$(btc $((5000000000-50)))}]")
C3=$(core submitpackage "[\"$PX\",\"$PY\",\"$CXY\"]" 2>&1 | summ 2>&1)
B3=$(bmc submitpackage "[[\"$PX\",\"$PY\",\"$CXY\"]]" | summ 2>&1)
echo "    core: $C3"; echo "    bmc : $B3"
case "$C3" in success*) fail "two-parent replacement: Core accepted -- the case is wrong";; *)
  [ "$C3" = "$B3" ] && ok "two-parent replacement: same answer as Core" || fail "two-parent replacement: ours differs from Core";; esac

echo
if [ "$FAILURES" -eq 0 ]; then echo "ALL PASS ($PASSES checks)"; exit 0; fi
echo "FAILURES: $FAILURES ($PASSES ok)"; exit 1
