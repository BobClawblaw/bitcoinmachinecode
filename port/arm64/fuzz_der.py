#!/usr/bin/env python3
"""Differential fuzz for be_to_limbs + der_parse_sig (bitcoin_script.S)
vs independent Python implementations. Runs ./t_der.
"""
import random, subprocess, sys

def be_to_limbs_py(b):
    v = int.from_bytes(b, 'big')
    return (v & ((1<<64)-1), (v>>64)&((1<<64)-1), (v>>128)&((1<<64)-1), v>>192)

def der_parse_py(sig):
    """Mirror der_parse_sig: tolerant DER. Returns (ret, r_limbs, s_limbs, dht)."""
    n = len(sig)
    if n < 8: return (0, (0,0,0,0), (0,0,0,0), 0)
    if sig[0] != 0x30: return (0, (0,0,0,0), (0,0,0,0), 0)
    if sig[2] != 0x02: return (0, (0,0,0,0), (0,0,0,0), 0)
    rlen = sig[3]
    if rlen == 0: return (0, (0,0,0,0), (0,0,0,0), 0)
    rbase = 4
    if rbase + rlen > n: return (0, (0,0,0,0), (0,0,0,0), 0)
    # strip leading zeros down to <=32
    rb, rl = rbase, rlen
    while rl > 32:
        if sig[rb] != 0: return (0, (0,0,0,0), (0,0,0,0), 0)
        rb += 1; rl -= 1
    rlimbs = be_to_limbs_py(sig[rb:rb+rl])
    smark = rb + rl
    if smark >= n or sig[smark] != 0x02: return (0, (0,0,0,0), (0,0,0,0), 0)
    slen = sig[smark+1]
    if slen == 0: return (0, (0,0,0,0), (0,0,0,0), 0)
    sbase = smark + 2
    s_end = sbase + slen
    if s_end > n: return (0, (0,0,0,0), (0,0,0,0), 0)
    sb, sl = sbase, slen
    while sl > 32:
        if sig[sb] != 0: return (0, (0,0,0,0), (0,0,0,0), 0)
        sb += 1; sl -= 1
    slimbs = be_to_limbs_py(sig[sb:sb+sl])
    dht = 0
    if s_end < n and sig[s_end] == 1:
        dht = 1
    return (1, rlimbs, slimbs, dht)

def rand_sig(rng):
    kind = rng.randrange(0, 10)
    if kind < 4:
        # well-formed basic sig (1 hashtype-ish byte or none)
        r=rng.randrange(1,33); s=rng.randrange(1,33)
        while (4+r+s+1) > 0 and 0:
            pass
        body = bytes([0x02,r]) + b'\x00'*(r-32 if r>32 else 0) + rng.randbytes(min(r,32)) \
             + bytes([0x02,s]) + b'\x00'*(s-32 if s>32 else 0) + rng.randbytes(min(s,32))
        hb = (rng.randbytes(1) if rng.random()<0.5 else b'')
        sig = bytes([0x30, len(body)+len(hb)]) + body + hb
        return sig
    elif kind < 7:
        # random bytes (malformed)
        return rng.randbytes(rng.randrange(0,70))
    else:
        # r/s with redundant leading zeros (33-36 byte int), optional hb
        rl=rng.randrange(33,37); sl=rng.randrange(33,37)
        body = bytes([0x02,rl]) + b'\x00'*(rl-32) + rng.randbytes(32) \
             + bytes([0x02,sl]) + b'\x00'*(sl-32) + rng.randbytes(32)
        hb = (rng.randbytes(1) if rng.random()<0.5 else b'')
        sig = bytes([0x30, len(body)+len(hb)]) + body + hb
        # len byte won't match; DER len is irrelevant to parser (uses markers)
        return sig

def main():
    seed=int(sys.argv[1]) if len(sys.argv)>1 else 1
    iters=int(sys.argv[2]) if len(sys.argv)>2 else 4000
    rng=random.Random(seed)
    cases=[]
    for _ in range(iters):
        cases.append(('limbs', rng.randbytes(rng.randrange(1,33))))
    for _ in range(iters):
        cases.append(('der', rand_sig(rng)))
    with open('/tmp/der_cases.txt','w') as f:
        for mode,b in cases:
            f.write(f"{mode} {(b.hex() if b else '-')}\n")
    p=subprocess.run(['./t_der','/tmp/der_cases.txt'],capture_output=True,text=True)
    if p.returncode!=0:
        print("DRIVER FAIL rc",p.returncode,p.stderr); sys.exit(2)
    lines=[l for l in p.stdout.splitlines() if l.strip()]
    assert len(lines)==len(cases), f"{len(lines)} vs {len(cases)}"
    fails=0
    for (mode,b),out in zip(cases,lines):
        if mode=='limbs':
            exp=' '.join('%016x'%x for x in be_to_limbs_py(b))
            if out!=exp:
                fails+=1
                if fails<=5: print("LIMB MISMATCH",b.hex(),"\n exp",exp,"\n got",out)
        else:
            r=der_parse_py(b)
            g=out.split()
            ok = (int(g[0])==r[0])
            if ok and r[0]==1:
                gr=[int(g[i],16) for i in range(1,5)]
                gs=[int(g[i],16) for i in range(5,9)]
                gd=int(g[9])
                ok = (tuple(gr)==r[1] and tuple(gs)==r[2] and gd==r[3])
            if not ok:
                fails+=1
                if fails<=5:
                    exp=f"{r[0]} "+" ".join('%016x'%x for x in r[1])+" "+" ".join('%016x'%x for x in r[2])+f" {r[3]}"
                    print("DER MISMATCH",b.hex(),"\n exp",exp,"\n got",out)
    print(f"seed={seed} iters={iters} cases={len(cases)} FAILS={fails}")
    sys.exit(1 if fails else 0)

if __name__=='__main__': main()
