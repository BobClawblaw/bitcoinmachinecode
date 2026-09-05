#!/bin/bash
# validation/signer_core_diff.sh -- Bitcoin Core's script engine judges the
# raw signer's output for every script form it signs.
#
# validation/signer_cases.c signs one input per form through rpc_dispatch
# (signrawtransactionwithkey) exactly as the RPC would; this script hands each
# signed tx to a scratch regtest bitcoind's signrawtransactionwithkey with an
# EMPTY key set, whose "complete" is Core's VerifyScript verdict on the
# signatures already present. Expected: true for every case our signer calls
# complete, false for the partial-multisig and wrong-key cases.
# Needs the scratch Core build (never the production install).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
B=${CORE_BIN:-/storage/bitcoin-core-source/build/bin}
TMP=$(mktemp -d /tmp/signer_core_diff.XXXX)
cd "$ROOT/asm" || exit 1
CMD=$(make -n -B tests/test_rpc_signraw 2>/dev/null | grep -E "^(cc|gcc).*-o tests/test_rpc_signraw " | tail -1)
[ -n "$CMD" ] || { echo "cannot derive the signer test's link line"; exit 1; }
CMD2=$(echo "$CMD" | sed "s#tests/test_rpc_signraw.c#../validation/signer_cases.c#; s#-o tests/test_rpc_signraw #-o $TMP/cases #")
eval "$CMD2" || exit 1
$TMP/cases > $TMP/cases.txt || exit 1
$B/bitcoind -regtest -datadir=$TMP -port=18555 -rpcport=18556 -listen=0 -connect=0 -dnsseed=0 -daemon=0 -printtoconsole=0 -rpcuser=u -rpcpassword=p &
PID=$!
CLI="$B/bitcoin-cli -regtest -datadir=$TMP -rpcport=18556 -rpcuser=u -rpcpassword=p"
for i in $(seq 1 60); do $CLI getblockcount >/dev/null 2>&1 && break; sleep 1; done
pass=0; fail=0
while IFS='|' read -r label prev hex comp err; do
  [ "$hex" = "-" ] && { echo "SKIP $label (no hex)"; continue; }
  out=$($CLI signrawtransactionwithkey "$hex" '[]' "[$prev]" 2>&1)
  got=$(echo "$out" | python3 -c 'import sys,json
try: print("true" if json.load(sys.stdin).get("complete") else "false")
except Exception: print("ERR")')
  want=$([ "$comp" = "1" ] && echo true || echo false)
  if [ "$got" = "$want" ]; then pass=$((pass+1)); echo "OK   $label -> Core complete=$got"; else fail=$((fail+1)); echo "FAIL $label -> Core: $got (ours: complete=$comp $err)"; fi
done < $TMP/cases.txt
$CLI stop >/dev/null 2>&1; wait $PID 2>/dev/null; rm -rf "$TMP"   # BLD-9: quote it
echo "RESULT: $pass ok, $fail fail"
[ "$fail" = 0 ]
