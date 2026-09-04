#!/usr/bin/env bash
# bfi_adopt_proof.sh -- prove the LAZY ADOPTION path of the block-filter index
# on regtest, because tonight's 8-hour mainnet backfill is worthless if the
# daemon then refuses to adopt the files it produced.
#
# What it asserts:
#   1. with the index MORE than BFI_ADOPT_GAP(144) behind the tip, the live
#      daemon leaves the files alone and says so.
#   2. with the index WITHIN 144, the daemon ADOPTS on the next connected
#      block -- no restart, no downtime.
#   3. after adopting it CLOSES the residual gap from undo data, reaching the
#      tip exactly.
#   4. it then MAINTAINS the index as new blocks arrive.
#   5. every filter it produced -- backfilled, gap-closed and live-appended --
#      is byte-identical to Bitcoin Core's for the same block.
# (5) is the one that matters: 1-4 only prove it wrote something.
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-source/build/bin}
BMC_BIN=${BMC_BIN:-/storage/bitcoinmachinecode/asm/daemon/bitcoind}
BUILDER=${BUILDER:-/storage/bitcoinmachinecode/asm/daemon/build_block_filters}
WALLET_CLI=${WALLET_CLI:-/storage/bitcoinmachinecode/asm/daemon/wallet_cli}
WORK=${TMPDIR:-/tmp}/bmc-bfi-proof-$$
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
CORE_P2P=19644; CORE_RPC=19660; BMC_P2P=19655; BMC_RPC=19646
FAILURES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; }
cleanup(){ for p in ${BMC_PIDS:-} ${CORE_PID:-}; do kill "$p" 2>/dev/null; done
           sleep 2; for p in ${BMC_PIDS:-}; do kill -9 "$p" 2>/dev/null; done
           [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmc(){ local m=$1; shift; local p=${1:-[]}
  curl -s --user e2e:e2epw -H 'content-type:text/plain' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":$p}" http://127.0.0.1:$BMC_RPC/; }
res(){ python3 -c "import sys,json;d=json.load(sys.stdin);sys.exit('RPC error: '+json.dumps(d['error'])) if d.get('error') else print(d['result'])"; }
idxcount(){ python3 -c "
import os,sys
p='$BMC_DIR/regtest/bfilters.idx'
print((os.path.getsize(p)-48)//48 if os.path.exists(p) else -1)"; }
bmch(){ bmc getblockcount | res 2>/dev/null || echo 0; }

echo "== setup =="
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do
  ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }
done
mkdir -p "$CORE_DIR" "$BMC_DIR/regtest"
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
blockfilterindex=1
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
CORE_PID=$(cat "$CORE_DIR/regtest/bitcoind.pid"); echo "  core up (pid $CORE_PID, blockfilterindex=1)"
mkdir -p "$WORK/wgen/data"; ( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 )
cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat" || exit 2
( cd /storage/bitcoinmachinecode/asm && nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc.log" 2>&1 & )
sleep 12
BMC_PIDS=$(pgrep -f "serve $BMC_DIR" | tr '\n' ' ')
grep -q 'JSON-RPC server' "$WORK/bmc.log" || { echo "bmc RPC never came up"; sed -n '1,40p' "$WORK/bmc.log"; exit 2; }
echo "  bmc up (pids $BMC_PIDS)"

echo "== a chain with real SPENDS, so undo records are not trivial =="
core createwallet e2ecore >/dev/null 2>&1
CADDR=$(core -rpcwallet=e2ecore getnewaddress)
core -rpcwallet=e2ecore generatetoaddress 200 "$CADDR" >/dev/null
for i in $(seq 12); do
  core -rpcwallet=e2ecore sendtoaddress "$(core -rpcwallet=e2ecore getnewaddress)" 0.5 >/dev/null 2>&1
  core -rpcwallet=e2ecore generatetoaddress 1 "$CADDR" >/dev/null
done
core -rpcwallet=e2ecore generatetoaddress 60 "$CADDR" >/dev/null
TIP=$(core getblockcount)
for i in $(seq 90); do [ "$(bmch)" = "$TIP" ] && break; sleep 2; done
[ "$(bmch)" = "$TIP" ] || { echo "bmc never synced to $TIP (at $(bmch))"; exit 2; }
echo "  both nodes at height $TIP (with $(core getblockcount) blocks, 12 spend blocks)"
# The daemon connects a catch-up BURST by looping h from last_seen_tip+1, so
# during initial sync bfi_on_block sees h=1 while the tip is already 272. The
# adopt gate compares against h, not the tip, so a builder finishing mid-burst
# is judged against h=1 and adopts at ANY gap. Harmless (the append is guarded
# by g_n == h, so nothing is written out of order) but it destroys this test's
# premise, so wait for the burst to drain before touching the index.
for i in $(seq 60); do grep -q "now at height $TIP" "$WORK/bmc.log" && break; sleep 1; done
sleep 3
grep -q "now at height $TIP" "$WORK/bmc.log" || { echo "utxo catch-up never reached $TIP"; exit 2; }
echo "  utxo catch-up drained to $TIP (burst over -- the adopt gate now sees the real tip)"

# the filter builder resolves prevouts THROUGH the txid index, so that index
# has to exist first -- exactly the ordering the mainnet backfill depends on.
echo "== txid index (the filter builder resolves prevouts through it) =="
/storage/bitcoinmachinecode/asm/daemon/build_tx_index "$BMC_DIR/regtest" >"$WORK/txi.log" 2>&1 \
  || { echo "build_tx_index failed"; tail -5 "$WORK/txi.log"; exit 2; }
echo "  txindex.dat $(stat -c%s "$BMC_DIR/regtest/txindex.dat" 2>/dev/null || echo 0) bytes"

echo "== 1. index MORE than 144 behind: daemon must NOT adopt =="
FAR=$((TIP-200))
"$BUILDER" "$BMC_DIR/regtest" $FAR >"$WORK/build1.log" 2>&1 || { echo "builder failed"; tail -5 "$WORK/build1.log"; exit 2; }
N1=$(idxcount); echo "  built to $N1 (tip $TIP, gap $((TIP-N1)))"
[ "$N1" -ge $((FAR-1)) ] || fail "builder stopped short at $N1, wanted ~$FAR"
core -rpcwallet=e2ecore generatetoaddress 1 "$CADDR" >/dev/null; TIP=$((TIP+1))
for i in $(seq 30); do [ "$(bmch)" = "$TIP" ] && break; sleep 1; done
sleep 3
if grep -q "waiting for the backfill to close in" "$WORK/bmc.log"; then
  ok "daemon declined to adopt at a $((TIP-N1))-block gap (and said so)"
else
  fail "no 'waiting for the backfill' log at a $((TIP-N1))-block gap"; grep -i bfilter "$WORK/bmc.log" | tail -5
fi
[ "$(idxcount)" = "$N1" ] || fail "index moved ($N1 -> $(idxcount)) while un-adopted -- the builder was raced"
ok "index untouched while un-adopted ($N1 records)"

echo "== 2+3. close to within 144: daemon must ADOPT and close the gap from undo =="
NEAR=$((TIP-40))
"$BUILDER" "$BMC_DIR/regtest" $NEAR >"$WORK/build2.log" 2>&1 || { echo "builder(2) failed"; tail -5 "$WORK/build2.log"; exit 2; }
N2=$(idxcount); echo "  built to $N2 (tip $TIP, gap $((TIP-N2)))"
[ $((TIP-N2)) -le 144 ] || fail "gap $((TIP-N2)) still over the adopt threshold; test cannot prove adoption"
core -rpcwallet=e2ecore generatetoaddress 1 "$CADDR" >/dev/null; TIP=$((TIP+1))
for i in $(seq 30); do [ "$(bmch)" = "$TIP" ] && break; sleep 1; done
sleep 4
if grep -q "ADOPTED at" "$WORK/bmc.log"; then ok "daemon ADOPTED: $(grep -m1 'ADOPTED at' "$WORK/bmc.log" | sed 's/^.*\[bfilter\] //')"
else fail "daemon did not adopt at a $((TIP-N2))-block gap"; grep -i bfilter "$WORK/bmc.log" | tail -8; fi
N3=$(idxcount)
# record i is height i, so "caught up" is tip+1 records -- genesis included
[ "$N3" = "$((TIP+1))" ] && ok "gap closed from undo data: $N3 records == heights 0..$TIP" \
                   || fail "index has $N3 records, want $((TIP+1)) (heights 0..$TIP) -- gap not closed"

echo "== 4. maintains the index as new blocks arrive =="
core -rpcwallet=e2ecore sendtoaddress "$(core -rpcwallet=e2ecore getnewaddress)" 0.25 >/dev/null 2>&1
core -rpcwallet=e2ecore generatetoaddress 3 "$CADDR" >/dev/null; TIP=$((TIP+3))
for i in $(seq 30); do [ "$(bmch)" = "$TIP" ] && break; sleep 1; done
sleep 4
N4=$(idxcount)
[ "$N4" = "$((TIP+1))" ] && ok "kept up: $N4 records == heights 0..$TIP" \
                        || fail "fell behind: $N4 records, want $((TIP+1))"

echo "== 5. every filter byte-identical to Bitcoin Core =="
python3 - "$BMC_DIR/regtest" "$CORE_BIN" "$CORE_DIR" "$CORE_RPC" "$FAR" "$TIP" <<'PY'
import os,struct,subprocess,sys,json
d,corebin,coredir,corerpc,far,tip = sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],int(sys.argv[5]),int(sys.argv[6])
idx=open(os.path.join(d,'bfilters.idx'),'rb').read(); dat=open(os.path.join(d,'bfilters.dat'),'rb')
n=(len(idx)-48)//48
def cli(*a):
    return subprocess.run([corebin+'/bitcoin-cli','-datadir='+coredir,'-rpcport='+corerpc,
                           '-rpcuser=e2e','-rpcpassword=e2epw',*a],capture_output=True,text=True).stdout.strip()
# sample across all three provenances: backfilled, gap-closed, live-appended
heights=sorted(set([1,far//2,far-1,far,far+5,tip-45,tip-40,tip-39,tip-20,tip-4,tip-3,tip-1,tip]))
heights=[h for h in heights if 0<=h<n]
bad=0; checked=0
for h in heights:
    rec=idx[48+h*48:48+(h+1)*48]
    off,ln=struct.unpack('<QQ',rec[0:16])
    dat.seek(off); ours=dat.read(ln).hex()
    bh=cli('getblockhash',str(h))
    theirs=json.loads(cli('getblockfilter',bh,'basic')).get('filter','')
    checked+=1
    if ours!=theirs:
        bad+=1; print("  FAIL: height %d filter differs (ours %d B, core %d B)"%(h,len(ours)//2,len(theirs)//2))
    else:
        tag = 'backfilled' if h<far else ('gap-closed' if h<=tip-4 else 'live-appended')
        print("  ok  h=%-6d %-13s %3d B identical to core"%(h,tag,len(ours)//2))
print("  --- %d heights checked, %d mismatches"%(checked,bad))
sys.exit(1 if bad else 0)
PY
[ $? -eq 0 ] || fail "filter bytes diverged from Core"

echo
[ $FAILURES -eq 0 ] && echo "PASS: lazy adoption proven end to end ($FAILURES failures)" \
                    || echo "FAILURES: $FAILURES"
exit $FAILURES
