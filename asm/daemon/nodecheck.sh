#!/bin/bash
# nodecheck.sh -- one-shot health check of the growing single-directory node.
# Runs: storage/dup audit (check_chain), chain integrity spot-verify, and a
# serve round-trip on a few known-stored blocks. Prints a concise verdict.
# Usage: nodecheck.sh <dir> [serve_port]
D="${1:-/storage/bitcoinmachinecode/data}"
PORT="${2:-8341}"
ASM=/storage/bitcoinmachinecode/asm
echo "=== 1) archive audit (dups/gaps/corruption) ==="
"$ASM/daemon/check_chain" "$D" 2>&1 | grep -E 'stored|holes|duplicate|hash-mismatch|chain-breaks|ARCHIVE'

echo
echo "=== 2) highest stored height / progress ==="
python3 -c "
import struct
ix='$D/index.dat'
D=open(ix,'rb').read(); n=len(D)//48
recs=[h for h in range(n) if D[h*48:h*48+32]!=b'\x00'*32]
from collections import Counter
c=Counter(D[h*48:h*48+32] for h in range(n) if D[h*48:h*48+32]!=b'\x00'*32)
print(f'stored {len(recs)} heights; highest={max(recs) if recs else -1}; dup-hashes={sum(1 for v in c.values() if v>1)}')"

echo
echo "=== 3) serve round-trip on up to 3 stored blocks (bytes must be identical) ==="
if [ ! -x "$ASM/tests/serve_test" ]; then
  (cd "$ASM" && gcc -no-pie -O0 -o tests/serve_test tests/serve_test.c sha256.o bitcoin_hash.o bitcoin_net.o bitcoin_p2p.o bitcoin_tx.o bitcoin_cons.o bitcoin_store.o bitcoind.o bitcoin_headers.o node_log.o) 2>/dev/null
fi
"$ASM/daemon/bitcoind" serve "$D" "$PORT" > /tmp/nodecheck_serve.log 2>&1 &
SPID=$!
sleep 3
# pick up to 3 well-separated stored heights
heights=$(python3 -c "
import struct
D=open('$D/index.dat','rb').read(); n=len(D)//48
recs=[h for h in range(n) if D[h*48:h*48+32]!=b'\x00'*32]
import random
random.seed(1)
sel=random.sample(recs,min(3,len(recs)))
print(' '.join(str(h) for h in sorted(sel)))" 2>/dev/null)
ok=0; try=0
for h in $heights; do
  try=$((try+1))
  r=$("$ASM/tests/serve_test" "$D" 127.0.0.1 "$PORT" "$h" 2>&1 | tail -1)
  echo "  height $h: $r"
  echo "$r" | grep -q "SERVE OK" && ok=$((ok+1))
done
kill $SPID 2>/dev/null
echo
echo "served $ok/$try stored blocks byte-identically"
