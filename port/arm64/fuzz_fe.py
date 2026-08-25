#!/usr/bin/env python3
"""Differential fuzz: secp256k1_fe.S (AArch64) vs Python big-int mod p."""
import random, subprocess, sys

P = 2**256 - 2**32 - 977
FZ = "./fz_fe"

def fe4(n):  # n in [0,2^256) -> 4 LE limbs hex
    b = n.to_bytes(32, 'little')
    return b.hex()

def parse(line):
    t = line.split()
    return t[0], [int(x,16) for x in t[1:]]

def mod(x): return x % P

def main():
    seed = int(sys.argv[1]) if len(sys.argv)>1 else 1
    iters = int(sys.argv[2]) if len(sys.argv)>2 else 1000
    random.seed(seed)
    fails=0
    for i in range(iters):
        a = random.randrange(0, 2**256)
        b = random.randrange(0, 2**256)
        # occasionally use full-range / canonical / zero / near-p
        r = random.random()
        if r<0.1: a = random.randrange(0,P)
        if r<0.2: b = random.randrange(0,P)
        if r<0.05: a=0
        if r<0.06: b=0
        if r<0.03: a=P-1
        if r<0.04: b=P-1
        if r<0.02: a=2**256-1
        if r<0.025: b=2**256-1
        rp = subprocess.run([FZ, fe4(a), fe4(b)], capture_output=True, text=True)
        out={}
        for ln in rp.stdout.splitlines():
            tag, limbs = parse(ln); out[tag]=int.from_bytes(b''.join(x.to_bytes(8,'little') for x in limbs),'little')
        exp = {
            'A': mod(a+b),
            'S': mod(a-b),
            'M': mod(a*b),
            'Q': mod(a*a),
            'I': (pow(a,P-2,P) if a % P != 0 else 0),
        }
        for tag in 'ASMQ':
            if tag in 'AS' and not (a<P and b<P):
                continue
            
            if out[tag] != exp[tag]:
                print(f"FAIL {tag} iter {i}: got {hex(out[tag])} exp {hex(exp[tag])} a={hex(a)} b={hex(b)}")
                fails+=1
        if out['I'] != exp['I']:
            print(f"FAIL I iter {i}: got {hex(out['I'])} exp {hex(exp['I'])} a={hex(a)}")
            fails+=1
    print(f"fe fuzz: {iters} iters, {fails} failures")
    sys.exit(1 if fails else 0)

if __name__=="__main__":
    main()
