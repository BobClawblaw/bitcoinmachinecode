#!/bin/bash
# gaps.sh -- list the missing (hole) height ranges in the archive.
DIR="${1:-/storage/bitcoinmachinecode/data}"
python3 -c "
import struct
D=open('$DIR/index.dat','rb').read(); n=len(D)//48
tip=max(h for h in range(n) if D[h*48:h*48+32]!=b'\x00'*32) if any(D[h*48:h*48+32]!=b'\x00'*32 for h in range(n)) else -1
if tip<0: print('empty'); raise SystemExit
holes=[];i=0
while i<n:
  if D[i*48:i*48+32]==b'\x00'*32:
    j=i
    while j<n and D[j*48:j*48+32]==b'\x00'*32: j+=1
    holes.append((i,j-1)); i=j
  else: i+=1
nh=sum(b-a+1 for a,b in holes)
print(f'tip={tip}  stored={tip+1-nh}  holes={nh}  ({100.0*nh/(tip+1):.2f}%)')
print('hole ranges:')
for a,b in holes[:60]:
    print(f'  {a}..{b}  ({b-a+1} blocks)')
if len(holes)>60: print(f'  ... and {len(holes)-60} more ranges')
"
