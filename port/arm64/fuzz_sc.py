#!/usr/bin/env python3
"""Differential fuzz: secp256k1_scalar.S vs Python big-int mod n."""
import random, subprocess, sys
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FZ="./fz_sc"
def fe4(x): return x.to_bytes(32,'little').hex()
def parse(line):
    t=line.split(); return t[0], int.from_bytes(b''.join(int(x,16).to_bytes(8,'little') for x in t[1:]),'little')
def mod(x): return x%n
def main():
    seed=int(sys.argv[1]) if len(sys.argv)>1 else 1
    iters=int(sys.argv[2]) if len(sys.argv)>2 else 800
    random.seed(seed); fails=0
    for i in range(iters):
        a=random.randrange(0,2**256); b=random.randrange(0,2**256)
        r=random.random()
        if r<0.2: a=random.randrange(0,n)
        if r<0.3: b=random.randrange(0,n)
        if r<0.05: a=n-1
        if r<0.06: b=n-1
        if r<0.03: a=0
        out={}
        rp=subprocess.run([FZ,fe4(a),fe4(b)],capture_output=True,text=True)
        for ln in rp.stdout.splitlines(): t,v=parse(ln); out[t]=v
        exp={'A':mod(a+b),'S':mod(a-b),'M':mod(a*b),'Q':mod(a*a),'I':(pow(a,n-2,n) if a%n else 0)}
        for t in 'ASMQI':
            if (t in 'AS' and not (a<n and b<n)): 
                if t=='A': pass
                continue
            if out[t]!=exp[t]:
                print(f"FAIL {t} i={i}: got {hex(out[t])} exp {hex(exp[t])} a={hex(a)} b={hex(b)}")
                fails+=1
    print(f"sc fuzz: {iters} iters, {fails} failures")
    sys.exit(1 if fails else 0)
if __name__=="__main__": main()
