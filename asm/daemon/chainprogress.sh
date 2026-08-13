#!/bin/bash
# chainprogress.sh -- progress toward a COMPLETE archive (all heights 0..tip).
DESSERT="${1:-/storage/bitcoinmachinecode/data}"
python3 -c "
import struct, os, sys
D=open('$DESSERT/index.dat','rb').read(); n=len(D)//48
recs=[h for h in range(n) if D[h*48:h*48+32]!=b'\x00'*32]
tippath='$DESSERT/headers.dat'
# tip = highest non-zero record; slot budget = that tip+1 (the heights a complete
# archive must hold, 0..tip).
tip=max(recs) if recs else -1
if tip<0:
    print('empty archive'); sys.exit(0)
have=len(recs)
pct=100.0*have/(tip+1)
missing=tip+1-have
print(f'archive heights:    0..{tip}  (need {tip+1})')
print(f'stored heights:     {have}  ({pct:.2f}%)')
print(f'missing (holes):    {missing}')
# contiguous coverage from genesis
k=0
while k<=tip and D[k*48:k*48+32]!=b'\x00'*32: k+=1
print(f'contiguous-from-0:  0..{k-1 if k>0 else -1}  ({\"COMPLETE from genesis\" if k==tip+1 else \"has a gap\"})' if k>=0 else '')
# blk disk
import subprocess
du=subprocess.run(['du','-sh','$DESSERT'],capture_output=True,text=True).stdout.split()[0] if os.path.isdir('$DESSERT') else '?'
print(f'disk used:          {du}')
"
