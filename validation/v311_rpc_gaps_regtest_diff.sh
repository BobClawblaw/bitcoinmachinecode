#!/bin/bash
# validation/v311_rpc_gaps_regtest_diff.sh -- getdeploymentinfo and the
# mempool entry, bmc against Bitcoin Core v31.1, on regtest. 2026-09-18.
#
# Three gaps were found by diffing against v31.1 instead of the v31.99 dev
# oracle: taproot missing from getdeploymentinfo, bip125-replaceable missing
# from the mempool entry (with two v31.99-only vsize keys present), and
# getchainstates' two cache fields. This drives both nodes through the same
# chain and the same mempool and compares WHOLE documents.
#
#  deployments  Core mines 200 blocks that do NOT signal testdummy
#               (-blockversion), is restarted without it, and mines on to 600
#               signalling: testdummy goes DEFINED -> STARTED (144, with a
#               partial count that fails at 288) -> LOCKED_IN (432) -> ACTIVE
#               (576). getdeploymentinfo <hash> is compared at every boundary
#               and inside each period -- statistics and signalling included.
#  mempool      tx A (wallet default: signals BIP125), tx N (replaceable=false),
#               and C, a final child of A that inherits A's signalling. Every
#               entry is compared field for field except `time` (arrival
#               clocks differ), `height` (a documented gap here: 0) and
#               `unbroadcast` (printed; this node keeps no unbroadcast set).
#  chainstates  printed, not failed: the two cache fields are a declared
#               divergence (docs/CORE_DIVERGENCES.md).
#
# Usage: validation/v311_rpc_gaps_regtest_diff.sh  (KEEP=1 keeps the work dir;
#        BMC_BIN / CORE_BIN override the binaries)
set -u
CORE_BIN=${CORE_BIN:-/mnt/nvme8tb/core-build/bitcoin-v31.1/build/bin}
BMC_BIN=${BMC_BIN:-/storage/bitcoinmachinecode/asm/daemon/bmcbitcoind}
WALLET_CLI=${WALLET_CLI:-$(dirname "$BMC_BIN")/bmc_wallet_cli}
WORK=${TMPDIR:-/tmp}/bmc-v311-gaps-$$; rm -rf "$WORK"; mkdir -p "$WORK/core" "$WORK/bmc/regtest"
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc; CORE_P2P=19714; CORE_RPC=19724; BMC_P2P=19734; BMC_RPC=19744   # not adjacent: Core binds an onion target on P2P+1
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

coreup -blockversion=536870912 || { echo "FAIL: Core did not start"; exit 1; }   # 0x20000000: no bits
mkdir -p "$WORK/wgen/data"; ( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 ); cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat"
( setsid nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 < /dev/null & )
for i in $(seq 120); do grep -aq 'JSON-RPC server' "$WORK/bmc.log" && break; sleep 1; done
core createwallet w >/dev/null 2>&1; ADDR=$(core -rpcwallet=w getnewaddress)
core -rpcwallet=w generatetoaddress 200 "$ADDR" >/dev/null
coredown; coreup || { echo "FAIL: Core did not restart"; exit 1; }
core loadwallet w >/dev/null 2>&1
core -rpcwallet=w generatetoaddress 400 "$ADDR" >/dev/null
waitsync || { echo "FAIL: bmc at $(bmc getblockcount), Core at $(core getblockcount)"; exit 1; }
echo "$(date -u +%T) both at $(core getblockcount)"

RC=0
cmp_doc(){  # label, core json, bmc json, keys to drop at the top level
  python3 - "$1" "$2" "$3" "${4:-}" <<'PY'
import json, sys
label, c, b, drop = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4].split(",") if sys.argv[4] else []
try:
    C = json.loads(c, object_pairs_hook=list); B = json.loads(b, object_pairs_hook=list)
except Exception as e:
    print("DIFF %s: unparseable (%s)" % (label, e)); sys.exit(1)
def strip(d): return [kv for kv in d if kv[0] not in drop] if isinstance(d, list) else d
if strip(C) == strip(B):
    print("same %s" % label); sys.exit(0)
print("DIFF %s\n  core: %s\n  bmc : %s" % (label, json.dumps(strip(C))[:900], json.dumps(strip(B))[:900])); sys.exit(1)
PY
}
for h in 0 1 100 142 143 144 150 200 287 288 300 431 432 500 575 576 600; do
  bh=$(core getblockhash $h)
  cmp_doc "getdeploymentinfo @$h" "$(core getdeploymentinfo "$bh")" "$(bmc getdeploymentinfo "[\"$bh\"]")" || RC=1
done
cmp_doc "getdeploymentinfo (tip)" "$(core getdeploymentinfo)" "$(bmc getdeploymentinfo)" || RC=1

# --- the mempool: A signals, N does not, C is a final child of A ---
A=$(core -rpcwallet=w sendtoaddress "$(core -rpcwallet=w getnewaddress)" 1)
N=$(core -rpcwallet=w -named sendtoaddress address="$(core -rpcwallet=w getnewaddress)" amount=1 replaceable=false)
VOUT=$(core -rpcwallet=w gettransaction "$A" | python3 -c "import sys,json; t=json.load(sys.stdin); print([d['vout'] for d in t['details'] if d['category']=='receive' and abs(d['amount']-1)<1e-9][0])")
RAW=$(core createrawtransaction "[{\"txid\":\"$A\",\"vout\":$VOUT,\"sequence\":4294967295}]" "[{\"$(core -rpcwallet=w getnewaddress)\":0.999}]")
SIGNED=$(core -rpcwallet=w signrawtransactionwithwallet "$RAW" | python3 -c "import sys,json; print(json.load(sys.stdin)['hex'])")
C=$(core sendrawtransaction "$SIGNED")
# hand bmc the same three directly, parent first: relay from a regtest Core
# to its one outbound-only peer is not what this measures
for id in "$A" "$N" "$C"; do bmc sendrawtransaction "[\"$(core getrawtransaction "$id")\"]" >/dev/null; done
for i in $(seq 60); do [ "$(bmc getmempoolinfo | python3 -c 'import sys,json; print(json.load(sys.stdin)["size"])' 2>/dev/null)" = "$(core getmempoolinfo | python3 -c 'import sys,json; print(json.load(sys.stdin)["size"])')" ] && break; sleep 2; done
echo "$(date -u +%T) mempool: core $(core getmempoolinfo | python3 -c 'import sys,json; print(json.load(sys.stdin)["size"])') bmc $(bmc getmempoolinfo | python3 -c 'import sys,json; print(json.load(sys.stdin)["size"])' 2>/dev/null)"
for t in "A:$A" "N:$N" "C:$C"; do
  n=${t%%:*}; id=${t#*:}
  echo "  $n bip125-replaceable: core $(core getmempoolentry "$id" | python3 -c 'import sys,json; print(json.load(sys.stdin)["bip125-replaceable"])') bmc $(bmc getmempoolentry "[\"$id\"]" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("bip125-replaceable"))' 2>/dev/null)"
  # unbroadcast is dropped too, and printed: this node answers a constant
  # false (it keeps no unbroadcast set), where Core is true for a tx its
  # own RPC submitted until a peer asks for it. A known gap, not this batch's.
  echo "  $n unbroadcast: core $(core getmempoolentry "$id" | python3 -c 'import sys,json; print(json.load(sys.stdin)["unbroadcast"])') bmc $(bmc getmempoolentry "[\"$id\"]" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("unbroadcast"))' 2>/dev/null) (known gap)"
  cmp_doc "getmempoolentry $n" "$(core getmempoolentry "$id")" "$(bmc getmempoolentry "[\"$id\"]")" time,height,unbroadcast || RC=1
done
cmp_doc "getmempoolancestors C verbose (keys)" \
  "$(core getmempoolancestors "$C" true | python3 -c 'import sys,json; d=json.load(sys.stdin); print(json.dumps({k:[kk for kk in v] for k,v in d.items()}))')" \
  "$(bmc getmempoolancestors "[\"$C\", true]" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(json.dumps({k:[kk for kk in v] for k,v in d.items()}))')" || RC=1

echo "--- getchainstates (declared divergence: the two cache fields)"
echo "  core: $(core getchainstates | python3 -c 'import sys,json; print(sorted(json.load(sys.stdin)["chainstates"][0]))')"
echo "  bmc : $(bmc getchainstates | python3 -c 'import sys,json; print(sorted(json.load(sys.stdin)["chainstates"][0]))')"

[ $RC = 0 ] && echo "PASS: every compared document matches v31.1" || echo "FAIL: see DIFF lines above"
exit $RC
