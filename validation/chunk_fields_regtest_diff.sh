#!/bin/bash
# validation/chunk_fields_regtest_diff.sh -- chunkweight and fees.chunk, bmc
# against Bitcoin Core v31.1, on regtest. 2026-09-19.
#
# v31.1's entryToJSON reports every mempool entry's chunk (txgraph
# GetMainChunkFeerate): `chunkweight`, the chunk's sigops-adjusted weight, and
# `fees.chunk`, its summed modified fee in BTC. bmc's bulk getrawmempool
# omitted both for every member of a multi-transaction cluster. This builds the
# same clusters on both nodes from the SAME raw transactions (signed by Core's
# wallet, submitted to each node directly, parents first) and compares, per
# txid, both keys from getrawmempool true AND from getmempoolentry.
#
#   singleton  one tx, no relatives
#   cpfp       P (150 sat) <- C (20000)
#   chain3     A (5000) <- B (150) <- C (3000): [A] then [B,C]
#   diamond    D0 (2 outs, 300) <- D1 (150), D2 (5000) <- D3 (both, 1000)
#   equal      E1 <- E2, same fee and the same shape: equal feerates, no merge
#   fanout     F (150) <- K1 (4000), K2 (200), K3 (2500)
#   chain12    12 deep, fees varying 150..6000 (chunks split and merge)
#
# Usage: validation/chunk_fields_regtest_diff.sh  (KEEP=1 keeps the work dir;
#        BMC_BIN / CORE_BIN override the binaries)
set -u
CORE_BIN=${CORE_BIN:-/mnt/nvme8tb/core-build/bitcoin-v31.1/build/bin}
BMC_BIN=${BMC_BIN:-/storage/bitcoinmachinecode/asm/daemon/bmcbitcoind}
WALLET_CLI=${WALLET_CLI:-$(dirname "$BMC_BIN")/bmc_wallet_cli}
WORK=${TMPDIR:-/tmp}/bmc-chunk-diff-$$; rm -rf "$WORK"; mkdir -p "$WORK/core" "$WORK/bmc/regtest"
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc; CORE_P2P=19816; CORE_RPC=19826; BMC_P2P=19836; BMC_RPC=19846   # not adjacent: Core binds an onion target on P2P+1
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use (another run?)"; exit 2; }; done
"$CORE_BIN/bitcoin-cli" -version | head -1
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmcraw(){ local m=$1; shift; curl -s --user e2e:e2epw -H 'content-type:text/plain' --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":${1:-[]}}" http://127.0.0.1:$BMC_RPC/; }
bmc(){ bmcraw "$@" | python3 -c "import sys,json; r=json.load(sys.stdin).get('result'); print(r if not isinstance(r,(dict,list)) else json.dumps(r))" 2>/dev/null; }
cat > "$CORE_DIR/bitcoin.conf" <<CONF
regtest=1
[regtest]
port=$CORE_P2P
rpcport=$CORE_RPC
rpcuser=e2e
rpcpassword=e2epw
listenonion=0
fallbackfee=0.0001
CONF
cat > "$BMC_DIR/bitcoin.conf" <<CONF
chain=regtest
printtoconsole=1
[regtest]
port=$BMC_P2P
rpcport=$BMC_RPC
rpcuser=e2e
rpcpassword=e2epw
connect=127.0.0.1:$CORE_P2P
CONF
coreup(){ "$CORE_BIN/bitcoind" -datadir="$CORE_DIR" -daemon "$@" >/dev/null 2>&1
          for i in $(seq 60); do core getblockcount >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
coredown(){ core stop >/dev/null 2>&1; for i in $(seq 60); do core getblockcount >/dev/null 2>&1 || return 0; sleep 1; done; }
waitsync(){ for i in $(seq 90); do [ "$(bmc getblockcount)" = "$(core getblockcount)" ] && return 0; sleep 2; done; return 1; }
cleanup(){
  for p in $(for q in /proc/[0-9]*; do grep -aqs "$WORK/bmc" $q/cmdline 2>/dev/null && [ "$(basename "$(readlink $q/exe 2>/dev/null)")" != "bash" ] && echo ${q#/proc/}; done); do kill $p 2>/dev/null; done
  coredown; [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT

coreup || { echo "FAIL: Core did not start"; exit 1; }
mkdir -p "$WORK/wgen/data"; ( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 ); cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat"
( setsid nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 < /dev/null & )
for i in $(seq 120); do grep -aq 'JSON-RPC server' "$WORK/bmc.log" && break; sleep 1; done
core createwallet w >/dev/null 2>&1; ADDR=$(core -rpcwallet=w getnewaddress)
core -rpcwallet=w generatetoaddress 110 "$ADDR" >/dev/null

# 12 confirmed 1-BTC outputs to spend from, one per cluster root
AMTS=$(python3 -c "import json,sys; print(json.dumps({a:1 for a in sys.argv[1:]}))" $(for i in $(seq 12); do core -rpcwallet=w getnewaddress; done))
FUND=$(core -rpcwallet=w sendmany "" "$AMTS")
core -rpcwallet=w generatetoaddress 1 "$ADDR" >/dev/null
waitsync || { echo "FAIL: bmc at $(bmc getblockcount), Core at $(core getblockcount)"; exit 1; }
echo "$(date -u +%T) both at $(core getblockcount)"
ROOTS=($(core -rpcwallet=w gettransaction "$FUND" true true | python3 -c "
import sys,json; t=json.load(sys.stdin)['decoded']
print(' '.join(str(o['n']) for o in t['vout'] if abs(o['value']-1)<1e-12))"))
[ ${#ROOTS[@]} -ge 7 ] || { echo "FAIL: funding outputs ${ROOTS[*]}"; exit 1; }

# mk <inputs "txid:vout ..."> <outputs sat,sat,...> -> signed hex, submitted to
# Core then bmc; prints the txid. Outputs go to fresh wallet addresses.
: > "$WORK/txs.lst"   # name txid, one per line (mk runs in a subshell)
mk(){  # name, inputs, output sats
  local name=$1 ins=$2 outs=$3
  local ij oj
  ij=$(python3 -c "import json,sys; print(json.dumps([{'txid':x.split(':')[0],'vout':int(x.split(':')[1])} for x in sys.argv[1].split()]))" "$ins")
  oj="["; local first=1
  for s in ${outs//,/ }; do
    [ $first = 1 ] || oj="$oj,"; first=0
    oj="$oj{\"$(core -rpcwallet=w getnewaddress)\":$(python3 -c "print('%.8f' % ($s/1e8))")}"
  done; oj="$oj]"
  local raw hex id
  raw=$(core createrawtransaction "$ij" "$oj")
  hex=$(core -rpcwallet=w signrawtransactionwithwallet "$raw" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['hex'] if d['complete'] else '')")
  [ -n "$hex" ] || { echo "FAIL: could not sign $name" >&2; return 1; }
  id=$(core sendrawtransaction "$hex") || { echo "FAIL: Core refused $name" >&2; return 1; }
  local r; r=$(bmcraw sendrawtransaction "[\"$hex\"]")
  echo "$r" | grep -q "\"result\":\"$id\"" || echo "  bmc sendrawtransaction $name: $r" >&2
  printf "%s %s\n" "$name" "$id" >> "$WORK/txs.lst"
  echo "$id"
}
R(){ echo "$FUND:${ROOTS[$1]}"; }
# fees below are 1 BTC in minus the outputs; every tx pays >= 1 sat/vB
S1=$(mk singleton "$(R 0)" 99997000)
P=$(mk cpfp.P "$(R 1)" 99999850);  C=$(mk cpfp.C "$P:0" 99979850)
A=$(mk chain3.A "$(R 2)" 99995000); B=$(mk chain3.B "$A:0" 99994850); C3=$(mk chain3.C "$B:0" 99991850)
D0=$(mk diamond.D0 "$(R 3)" 49999850,49999850)
D1=$(mk diamond.D1 "$D0:0" 49999700); D2=$(mk diamond.D2 "$D0:1" 49994850)
D3=$(mk diamond.D3 "$D1:0 $D2:0" 99993550)
E1=$(mk equal.E1 "$(R 4)" 99990000); E2=$(mk equal.E2 "$E1:0" 99980000)
F=$(mk fanout.F "$(R 5)" 33333283,33333283,33333284)
K1=$(mk fanout.K1 "$F:0" 33329283); K2=$(mk fanout.K2 "$F:1" 33333083); K3=$(mk fanout.K3 "$F:2" 33330784)
prev="$(R 6)"; left=100000000
for i in $(seq 0 11); do fee=$(( 150 + ( (i * 7919) % 12 ) * 500 )); left=$((left - fee))
  id=$(mk chain12.$i "$prev" $left); prev="$id:0"; done

for i in $(seq 60); do [ "$(bmc getmempoolinfo | python3 -c 'import sys,json; print(json.load(sys.stdin)["size"])' 2>/dev/null)" = "$(core getmempoolinfo | python3 -c 'import sys,json; print(json.load(sys.stdin)["size"])')" ] && break; sleep 1; done
echo "$(date -u +%T) mempool: core $(core getmempoolinfo | python3 -c 'import sys,json; print(json.load(sys.stdin)["size"])') bmc $(bmc getmempoolinfo | python3 -c 'import sys,json; print(json.load(sys.stdin)["size"])' 2>/dev/null)"

core getrawmempool true > "$WORK/core_raw.json"
bmc getrawmempool '[true]' > "$WORK/bmc_raw.json"
: > "$WORK/entries.tsv"
while read -r nm id; do
  printf '%s\t%s\t%s\t%s\n' "$nm" "$id" "$(core getmempoolentry "$id" | tr -d '\n')" \
         "$(bmc getmempoolentry "[\"$id\"]")" >> "$WORK/entries.tsv"
done < "$WORK/txs.lst"
python3 - "$WORK" <<'PY'
import json, sys
w = sys.argv[1]
C = json.load(open(w + "/core_raw.json")); B = json.load(open(w + "/bmc_raw.json"))
bad = 0; n = 0
def pick(e):
    return (e.get("chunkweight"), None if e.get("fees", {}).get("chunk") is None else "%.8f" % e["fees"]["chunk"])
print("%-11s %-10s %-24s %-24s %s" % ("tx", "txid", "core cw / fees.chunk", "bmc bulk", "bmc entry"))
for line in open(w + "/entries.tsv"):
    name, txid, ce, be = line.rstrip("\n").split("\t")
    ce = json.loads(ce); be = json.loads(be) if be else {}
    c = pick(C.get(txid, {})); b = pick(B.get(txid, {})); ec = pick(ce); eb = pick(be)
    n += 1
    ok = (c == b == ec == eb) and c[0] is not None
    if not ok: bad += 1
    print("%-11s %s %-24s %-24s %-24s %s" % (name, txid[:10], "%s / %s" % c, "%s / %s" % b, "%s / %s" % eb, "same" if ok else "DIFF"))
missing = [t for t in B if "chunkweight" not in B[t]]
print("bmc bulk entries lacking chunkweight: %d of %d" % (len(missing), len(B)))
print("%d of %d txs agree on chunkweight and fees.chunk across Core bulk, Core entry, bmc bulk, bmc entry" % (n - bad, n))
sys.exit(1 if bad or missing or n == 0 else 0)
PY
RC=$?
[ $RC = 0 ] && echo "PASS: chunkweight and fees.chunk match v31.1 on every tx" || echo "FAIL: see DIFF lines above"
exit $RC
