#!/bin/bash
# live_money_range_check.sh -- replay REAL mainnet transactions through the
# consensus money-range check (audit 2026-08-29 finding 5b).
#
# WHY THIS EXISTS. The unit test pins the boundary. This pins the consequence:
# a consensus check that is too strict does not produce a bug report, it
# produces a chain split -- the node rejects a block the rest of the network
# accepted and stops following the chain. Core accepted every transaction
# sampled here, so a single rejection is a divergence from consensus.
#
# Samples across eras deliberately: pre-BIP16, pre-segwit, segwit activation,
# taproot activation, and the current tip, because output shapes and value
# distributions differ across them.
#
# Read-only: getblockhash / getblock / getrawtransaction on loopback.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=$ROOT/asm/tests/live_money_range_chain
DATA=${1:-$ROOT/data}
PORT=${2:-8331}
PER=${PER:-25}          # transactions sampled per block

[ -x "$BIN" ] || { echo "build it first: make -C $ROOT/asm tests/live_money_range_chain"; exit 2; }
COOKIE=$(cat "$DATA/.cookie" 2>/dev/null) || { echo "no cookie at $DATA/.cookie"; exit 2; }

rpc(){ curl -sS --max-time 25 -u "$COOKIE" --data-binary \
       "{\"jsonrpc\":\"1.0\",\"id\":\"m\",\"method\":\"$1\",\"params\":$2}" \
       "http://127.0.0.1:$PORT/" 2>/dev/null; }

TIP=$(rpc getblockcount '[]' | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])' 2>/dev/null)
[ -n "${TIP:-}" ] || { echo "cannot reach the node on 127.0.0.1:$PORT"; exit 2; }
echo "node tip: $TIP"

HEIGHTS="1 100 57043 91722 120000 170052 210000 227836 250000 279000 363731 481824 500000 550000 629000 687456 709632 750000 800000 850000 900000 $((TIP-1000)) $((TIP-10)) $TIP"

TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
nblk=0
for h in $HEIGHTS; do
    [ "$h" -ge 0 ] 2>/dev/null || continue
    [ "$h" -le "$TIP" ] || continue
    HASH=$(rpc getblockhash "[$h]" | python3 -c 'import json,sys
try: print(json.load(sys.stdin)["result"] or "")
except Exception: print("")' 2>/dev/null)
    [ -n "$HASH" ] || { echo "  (height $h unavailable, skipping)"; continue; }
    TXIDS=$(rpc getblock "[\"$HASH\",1]" | PER=$PER python3 -c '
import json,sys,os
per=int(os.environ.get("PER","25"))
try: txs=json.load(sys.stdin)["result"]["tx"]
except Exception: txs=[]
# take a spread, not just the front of the block
step=max(1,len(txs)//per) if txs else 1
for t in txs[::step][:per]: print(t)' 2>/dev/null)
    [ -n "$TXIDS" ] || { echo "  (height $h: no txids, skipping)"; continue; }
    n=0
    for txid in $TXIDS; do
        RAW=$(rpc getrawtransaction "[\"$txid\"]" | python3 -c '
import json,sys
try:
    r=json.load(sys.stdin)["result"]
    print(r if isinstance(r,str) else "")
except Exception: print("")' 2>/dev/null)
        [ -n "$RAW" ] && { echo "$RAW" >> "$TMP"; n=$((n+1)); }
    done
    echo "  height $h: $n transactions"
    nblk=$((nblk+1))
done

echo "sampled $nblk blocks"
"$BIN" < "$TMP"
rc=$?
[ $rc -eq 0 ] && echo "MONEY-RANGE CHAIN CHECK PASSED" || echo "MONEY-RANGE CHAIN CHECK FAILED (rc=$rc)"
exit $rc
