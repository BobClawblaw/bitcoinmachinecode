#!/bin/bash
# Capture Bitcoin Core v31.1's RPC FIELD SETS into a fixture the hermetic gate
# can diff against.
#
# WHY A FIXTURE. validation/rpc_field_parity.py needs a live Core and a live
# node, so it cannot run in `make test`. Without something in the gate, field
# drift is caught only when a human looks -- which is how getrawmempool sat at
# four fields for weeks and getblock's coinbase_tx was deleted on a premise
# nobody checked. Freezing Core's answer turns that into a build failure.
#
# Regtest, so this needs no chain and no network: a fresh datadir, 101 blocks
# for a spendable coinbase, and a second node for a real getpeerinfo.
set -u
BIN=${BIN:-/mnt/2tbssd/core-bench/core/bin}
OUT=${OUT:-/storage/bitcoinmachinecode/asm/tests/core_v31_fields.json}
A=$(mktemp -d); B=$(mktemp -d)
cleanup(){ "$BIN/bitcoin-cli" -datadir=$A -conf=$A/bitcoin.conf -regtest stop >/dev/null 2>&1
           "$BIN/bitcoin-cli" -datadir=$B -conf=$B/bitcoin.conf -regtest stop >/dev/null 2>&1
           sleep 2; rm -rf "$A" "$B"; }
trap cleanup EXIT
printf 'regtest=1\nserver=1\nrpcuser=u\nrpcpassword=p\n[regtest]\nrpcport=19801\nport=19802\n' > $A/bitcoin.conf
printf 'regtest=1\nserver=1\nrpcuser=u\nrpcpassword=p\n[regtest]\nrpcport=19803\nport=19804\n' > $B/bitcoin.conf
"$BIN/bitcoind" -datadir=$A -conf=$A/bitcoin.conf -regtest -daemon >/dev/null 2>&1
"$BIN/bitcoind" -datadir=$B -conf=$B/bitcoin.conf -regtest -connect=127.0.0.1:19802 -daemon >/dev/null 2>&1
C1="$BIN/bitcoin-cli -datadir=$A -conf=$A/bitcoin.conf -regtest"
for i in $(seq 1 30); do $C1 getblockcount >/dev/null 2>&1 && break; sleep 2; done
$C1 -named createwallet wallet_name=w >/dev/null 2>&1
ADDR=$($C1 -rpcwallet=w getnewaddress 2>/dev/null)
$C1 generatetoaddress 101 "$ADDR" >/dev/null 2>&1
$C1 getblocktemplate '{"rules":["segwit"]}' >/dev/null 2>&1
# getpeerinfo is the largest contract in the fixture and it needs a real peer.
# The first version of this script waited 40 s, gave up quietly, and produced a
# fixture with getpeerinfo MISSING -- so the gate silently stopped checking the
# very call with the most missing fields. Wait longer, and fail loudly.
PEERED=0
for i in $(seq 1 60); do
  [ "$($C1 getconnectioncount 2>/dev/null)" != "0" ] && { PEERED=1; break; }
  sleep 2
done
if [ "$PEERED" != "1" ]; then
  echo "FAIL: the second regtest node never connected, so getpeerinfo cannot be captured." >&2
  echo "      Refusing to write a fixture that silently omits it." >&2
  exit 1
fi
VER=$($BIN/bitcoin-cli -version 2>/dev/null | head -1)
python3 - "$A" "$OUT" "$VER" <<'PY'
import json,subprocess,sys,os
A,OUT,VER=sys.argv[1],sys.argv[2],sys.argv[3]
CLI=[os.environ.get("BIN","/mnt/2tbssd/core-bench/core/bin")+"/bitcoin-cli",
     "-datadir="+A,"-conf="+A+"/bitcoin.conf","-regtest"]
def call(a):
    r=subprocess.run(CLI+a,capture_output=True,text=True,timeout=60)
    if r.returncode: return None
    try: return json.loads(r.stdout)
    except Exception: return None
bh=subprocess.run(CLI+["getblockhash","101"],capture_output=True,text=True).stdout.strip().strip('"')
CASES={"getblockchaininfo":[],"getmininginfo":[],"getmempoolinfo":[],
       "getnetworkinfo":[],"getnettotals":[],"getchaintxstats":[],
       "getblock":[bh,"1"],"getblockheader":[bh],"getblockstats":["101"],
       "getdeploymentinfo":[],"getrpcinfo":[],"getindexinfo":[],
       "getpeerinfo":[],"getblocktemplate":['{"rules":["segwit"]}']}
skipped=[]
out={"_core_version":VER,"_note":"field sets captured from Core on regtest; "
     "regenerate with validation/capture_core_fields.sh"}
for m,a in CASES.items():
    o=call([m]+a)
    if o is None: continue
    if isinstance(o,list):
        if not o: continue
        o=o[0]
    if isinstance(o,dict):
        # An EMPTY object is not a contract, it is an absence. getindexinfo on
        # regtest returns {} because no index is enabled, and freezing that
        # would put a method in the fixture that asserts nothing -- the same
        # "measuring air" the gate test refuses. Skipped, and reported.
        if not o:
            skipped.append(m); continue
        out[m]=sorted(o.keys())
json.dump(out,open(OUT,"w"),indent=1,sort_keys=True)
out["_skipped_empty"]=sorted(skipped)
json.dump(out,open(OUT,"w"),indent=1,sort_keys=True)
print("wrote",OUT,"with",len([k for k in out if not k.startswith("_")]),"methods; skipped empty:",skipped)
PY
