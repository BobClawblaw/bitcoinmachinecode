#!/bin/bash
# validation/bench_fidelity_regtest_e2e.sh -- run 28's bench-fidelity fixes, end
# to end against Core v31.1 on regtest (2026-09-19).
#
# A. The downloader's bytes. Run 27 downloaded ~73 GB of blocks and reported
#    getnettotals.totalbytessent ~0: nothing counted what the parallel
#    downloader's sockets sent. Here bmc syncs BLOCKS blocks from one Core
#    regtest node through the parallel downloader, and Core -- whose only peer
#    is bmc -- is the referee: bmc's totalbytessent must match Core's
#    totalbytesrecv, and bmc's totalbytesrecv Core's totalbytessent, within
#    TOL_PCT. Before the fix the sent side reads a few KB (the relay leg only)
#    against Core's tens of KB.
#       BOOTCATCHUP=1 (default, 200 blocks): the boot catch-up downloads, before
#                     the shared status table exists
#       BOOTCATCHUP=0 BLOCKS=2200: the worker's far-behind trigger downloads --
#                     the benchmark harness's configuration (run 27's)
# B. Index gating. bmc runs with txindex=1 and NO txospenderindex line, as run
#    27 did; Core runs with txindex=1. getindexinfo must name the same indexes
#    on both sides, no txospender tail may exist in bmc's datadir, and
#    gettxspendingprevout with mempool_only=false must fail on both sides with
#    Core's words. Before the fix bmc listed txospenderindex and kept a tail.
# C. No "builder ... not executable" / "missing beside the daemon" line in
#    bmc's log: the txindex trail's builder sits beside the binary.
#
# Usage: validation/bench_fidelity_regtest_e2e.sh
#   BMC_BIN=<daemon> (default: this tree's asm/daemon/bmcbitcoind, built by
#   `make runtime` so the helpers sit beside it); KEEP=1 keeps the work dir.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
CORE_BIN=${CORE_BIN:-/mnt/nvme8tb/core-build/bitcoin-v31.1/build/bin}
BMC_BIN=${BMC_BIN:-$HERE/asm/daemon/bmcbitcoind}
BLOCKS=${BLOCKS:-200}; BOOTCATCHUP=${BOOTCATCHUP:-1}; TOL_PCT=${TOL_PCT:-2}
WORK=${TMPDIR:-/tmp}/bmc-fidelity-e2e-$$; rm -rf "$WORK"; mkdir -p "$WORK/core" "$WORK/bmc/regtest"
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
CORE_P2P=${CORE_P2P:-19411}; CORE_RPC=${CORE_RPC:-19431}; BMC_P2P=${BMC_P2P:-19417}; BMC_RPC=${BMC_RPC:-19437}   # spaced: Core binds its onion target at p2p+1
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use (another run?)"; exit 2; }; done
[ -x "$BMC_BIN" ] || { echo "no daemon at $BMC_BIN (make runtime)"; exit 2; }
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
# the whole JSON-RPC reply, so an error is visible as one
bmcraw(){ local m=$1; shift; curl -s --user e2e:e2epw -H 'content-type:text/plain' --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":${1:-[]}}" http://127.0.0.1:$BMC_RPC/; }
bmc(){ bmcraw "$@" | python3 -c "import sys,json; r=json.load(sys.stdin).get('result'); print(json.dumps(r) if isinstance(r,(dict,list)) else r)" 2>/dev/null; }
jf(){ python3 -c "import sys,json; d=json.loads(sys.argv[1]); print(d$2)" "$1" 2>/dev/null; }
RC=0; pass(){ echo "PASS: $*"; }; fail(){ echo "FAIL: $*"; RC=1; }

cat > "$CORE_DIR/bitcoin.conf" <<CONF
regtest=1
[regtest]
port=$CORE_P2P
rpcport=$CORE_RPC
rpcuser=e2e
rpcpassword=e2epw
listenonion=0
fallbackfee=0.0001
txindex=1
v2transport=0
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
bmc.bootcatchup=$BOOTCATCHUP
txindex=1
CONF
"$CORE_BIN/bitcoind" -datadir="$CORE_DIR" -daemon >/dev/null 2>&1
for i in $(seq 30); do core getblockcount >/dev/null 2>&1 && break; sleep 1; done
core createwallet e2ecore >/dev/null 2>&1; CADDR=$(core -rpcwallet=e2ecore getnewaddress)
core -rpcwallet=e2ecore generatetoaddress 101 "$CADDR" >/dev/null
# some spends, so the txid index has transactions and the spender index would have work
for k in 1 2 3 4 5; do core -rpcwallet=e2ecore sendtoaddress "$(core -rpcwallet=e2ecore getnewaddress)" 1.5 >/dev/null; done
SPENT_TXID=$(core -rpcwallet=e2ecore listtransactions "*" 1 | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['txid'])")
core -rpcwallet=e2ecore generatetoaddress $((BLOCKS-101)) "$CADDR" >/dev/null
CT=$(core getblockcount); echo "$(date -u +%T) core mined $CT blocks (bmc.bootcatchup=$BOOTCATCHUP)"

( setsid nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 < /dev/null & )
for i in $(seq 180); do [ "$(bmc getblockcount)" = "$CT" ] && break; sleep 1; done
BT=$(bmc getblockcount); echo "$(date -u +%T) bmc at $BT of $CT"
[ "$BT" = "$CT" ] && pass "bmc synced to Core's tip ($CT)" || fail "bmc at $BT, Core at $CT"
DLC=$(grep -ac '\[dlc\] span' "$WORK/bmc.log")
[ "${DLC:-0}" -ge 1 ] && pass "the parallel downloader fetched the span ($(grep -a '\[dlc\] span' "$WORK/bmc.log" | head -1 | sed 's/.*\[dlc\] //'))" \
                      || fail "the parallel downloader never ran -- this run does not test defect A"
sleep 5                                              # let the leg go quiet before reading both sides

echo "== A. bytes: bmc's count against Core's =="
BN=$(bmc getnettotals); CN=$(core getnettotals)
BS=$(jf "$BN" "['totalbytessent']"); BR=$(jf "$BN" "['totalbytesrecv']")
CS=$(jf "$CN" "['totalbytessent']"); CR=$(jf "$CN" "['totalbytesrecv']")
echo "     bmc  getnettotals: sent $BS recv $BR"
echo "     core getnettotals: sent $CS recv $CR   (Core's only peer is bmc)"
echo "     core getpeerinfo (bmc's connections still open):"
core getpeerinfo | python3 -c "
import sys,json
for p in json.load(sys.stdin): print('       id %s %s inbound=%s bytesrecv %s bytessent %s' % (p['id'], p['addr'], p['inbound'], p['bytesrecv'], p['bytessent']))"
echo "     bmc getpeerinfo:"
bmc getpeerinfo | python3 -c "
import sys,json
for p in json.loads(sys.stdin.read() or '[]'): print('       %s bytessent %s bytesrecv %s  sent_per_msg %s' % (p.get('addr'), p.get('bytessent'), p.get('bytesrecv'), json.dumps(p.get('bytessent_per_msg',{}))))"
within(){ python3 -c "import sys; a,b,t=float(sys.argv[1]),float(sys.argv[2]),float(sys.argv[3]); sys.exit(0 if b>0 and abs(a-b)*100.0/b<=t else 1)" "$1" "$2" "$TOL_PCT"; }
pct(){ python3 -c "import sys; a,b=float(sys.argv[1]),float(sys.argv[2]); print('%+.2f%%' % ((a-b)*100.0/b if b else 0))" "$1" "$2"; }
within "$BS" "$CR" && pass "bmc totalbytessent $BS vs Core totalbytesrecv $CR ($(pct "$BS" "$CR"), within ${TOL_PCT}%)" \
                   || fail "bmc totalbytessent $BS vs Core totalbytesrecv $CR ($(pct "$BS" "$CR"), outside ${TOL_PCT}%)"
within "$BR" "$CS" && pass "bmc totalbytesrecv $BR vs Core totalbytessent $CS ($(pct "$BR" "$CS"), within ${TOL_PCT}%)" \
                   || fail "bmc totalbytesrecv $BR vs Core totalbytessent $CS ($(pct "$BR" "$CS"), outside ${TOL_PCT}%)"

echo "== B. index gating: txindex=1, txospenderindex absent =="
BI=$(bmc getindexinfo); CI=$(core getindexinfo)
BK=$(python3 -c "import sys,json; print(' '.join(sorted(json.loads(sys.argv[1]).keys())))" "$BI" 2>/dev/null)
CK=$(python3 -c "import sys,json; print(' '.join(sorted(json.loads(sys.argv[1]).keys())))" "$CI" 2>/dev/null)
echo "     bmc  getindexinfo: $BI"
echo "     core getindexinfo: $CI"
[ "$BK" = "$CK" ] && pass "getindexinfo names the same indexes on both sides: [$BK]" || fail "getindexinfo: bmc [$BK], Core [$CK]"
case " $BK " in *" txospenderindex "*) fail "bmc lists txospenderindex, which nobody configured";; *) pass "bmc does not list txospenderindex";; esac
TAILS=$(ls "$BMC_DIR/regtest" | grep -E '^txospender' | tr '\n' ' ')
[ -z "$TAILS" ] && pass "no txospender file in bmc's datadir" || fail "txospender files exist: $TAILS"
[ -f "$BMC_DIR/regtest/txindex.tail" ] && pass "the configured txindex keeps its tail (txindex.tail)" || fail "txindex=1 but no txindex.tail"
Q="[[{\"txid\":\"$SPENT_TXID\",\"vout\":0}],{\"mempool_only\":false}]"
BE=$(bmcraw gettxspendingprevout "$Q" | python3 -c "import sys,json; e=json.load(sys.stdin).get('error') or {}; print('%s %s' % (e.get('code'), e.get('message')))")
# bitcoin-cli prints "error code: N", then "error message:" and the text on the line(s) after
CE=$(core gettxspendingprevout "[{\"txid\":\"$SPENT_TXID\",\"vout\":0}]" '{"mempool_only":false}' 2>&1 | python3 -c "
import sys
code, msg, m = '', [], False
for l in sys.stdin.read().split('\n'):
    if l.startswith('error code: '): code = l[12:]
    elif l.startswith('error message:'): m = True
    elif m and l: msg.append(l)
print('%s %s' % (code, ' '.join(msg)))")
echo "     bmc : $BE"
echo "     core: $CE"
[ "$BE" = "$CE" ] && pass "gettxspendingprevout mempool_only=false without the index: bmc answers Core's error" || fail "gettxspendingprevout: bmc [$BE], Core [$CE]"
BH=$(bmc getrawtransaction "[\"$SPENT_TXID\"]"); CH=$(core getrawtransaction "$SPENT_TXID")
[ -n "$BH" ] && [ "$BH" = "$CH" ] && pass "getrawtransaction by txid (txindex=1) matches Core" || fail "getrawtransaction by txid: bmc [${BH:0:40}] Core [${CH:0:40}]"

echo "== C. the index builders sit beside the daemon =="
ML=$(grep -aE '(builder|merger) [^ ]+ not executable|missing beside the daemon' "$WORK/bmc.log" | head -1)
[ -z "$ML" ] && pass "no missing-helper line in bmc's log" || fail "bmc says: $ML"

for p in $(for q in /proc/[0-9]*; do grep -aqs "$WORK/bmc" $q/cmdline 2>/dev/null && [ "$(basename "$(readlink $q/exe 2>/dev/null)")" != "bash" ] && echo ${q#/proc/}; done); do kill $p 2>/dev/null; done
core stop >/dev/null 2>&1; sleep 2; [ "${KEEP:-0}" = 1 ] && echo "kept $WORK" || rm -rf "$WORK"
[ $RC = 0 ] && echo "ALL PASS" || echo "FAILED"
exit $RC
