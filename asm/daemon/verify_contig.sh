#!/bin/bash
# verify_contig.sh -- verify the longest contiguous stored run of the archive.
# Proves the downloaded blocks form a genuine, consensus-valid mainnet chain
# (hash-match + chain-link + PoW + full cons_verify) as it grows.
DIR="${1:-/storage/bitcoinmachinecode/data}"
cd "$(dirname "$0")/.."
rng=$(python3 -c "
import struct
D=open('$DIR/index.dat','rb').read(); n=len(D)//48
stored={h for h in range(n) if D[h*48:h*48+32]!=b'\x00'*32}
best=[];cur=[]
for h in range(n):
    if h in stored:
        cur.append(h)
        if len(cur)>len(best): best=cur[:]
    else: cur=[]
print(best[0],best[-1])")
lo=$(echo $rng|cut -d' ' -f1); hi=$(echo $rng|cut -d' ' -f2)
echo "Verifying longest contiguous stored run: [$lo, $hi] ($((hi-lo+1)) blocks)"
# Prefer the parallel verifier (machine-adaptive worker pool, ~7x on multi-core);
# fall back to the serial verifier if pverify isn't built.
if [ -x ./daemon/pverify ]; then
  ./daemon/pverify "$DIR" "$lo" "$hi" 2>&1 | tail -8
else
  ./daemon/verify  "$DIR" "$lo" "$hi" 2>&1 | tail -8
fi
