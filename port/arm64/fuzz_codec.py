#!/usr/bin/env python3
"""Differential fuzz for bitcoin_scriptcodec.S pure primitives (scriptnum
decode/serialize, cast_to_bool, der_sig_strict, check_minimal_push) vs Python.
Runs ./t_codec."""
import random, subprocess, sys

def snum_decode(d, maxsize):
    overflow = 1 if len(d) > maxsize else 0
    val = 0
    for i, b in enumerate(d):
        val |= b << (i*8)
    if d and d[-1] & 0x80:
        mask = (~(0x80 << ((len(d)-1)*8))) & ((1<<64)-1)
        return -(val & mask), overflow
    return val, overflow

def snum_ser(v):
    if v == 0: return b''
    neg = v < 0
    if neg: v = -v
    out = bytearray()
    while v:
        out.append(v & 0xff); v >>= 8
    last = len(out)-1
    if out[last] & 0x80:
        out.append(0x80 if neg else 0x00)
    elif neg:
        out[last] |= 0x80
    return bytes(out)

def cast_bool(d):
    if len(d) == 0: return 0
    for i, b in enumerate(d):
        if b:
            if i == len(d)-1 and b == 0x80: return 0
            return 1
    return 0

def der_strict(sig):
    n = len(sig)
    if n < 9 or n > 73: return 0
    if sig[0] != 0x30: return 0
    if sig[1] != n-3: return 0
    lenR = sig[3]
    if 5 + lenR >= n: return 0
    lenS = sig[5+lenR]
    if lenR + lenS + 7 != n: return 0
    if sig[2] != 0x02: return 0
    if lenR == 0: return 0
    if sig[4] & 0x80: return 0
    if lenR > 1 and sig[4] == 0x00 and not (sig[5] & 0x80): return 0
    if sig[lenR+4] != 0x02: return 0
    if lenS == 0: return 0
    if sig[lenR+6] & 0x80: return 0
    if lenS > 1 and sig[lenR+6] == 0x00 and not (sig[lenR+7] & 0x80): return 0
    return 1

def min_push(op, pushlen, data):
    if pushlen == 0: return 1 if op == 0 else 0
    if pushlen == 1:
        b = data[0]
        if b < 1:          # not_one_min
            if data[0] == 0x81: return 0
            pass             # -> not_one
        elif b > 16:       # not_one
            pass
        else:              # 1..16
            return 0
    # not_one
    if pushlen <= 75: return 1 if op == pushlen else 0
    if pushlen <= 255: return 1 if op == 0x4c else 0
    if pushlen <= 65535: return 1 if op == 0x4d else 0
    return 1

def main():
    seed=int(sys.argv[1]) if len(sys.argv)>1 else 1
    iters=int(sys.argv[2]) if len(sys.argv)>2 else 3000
    rng=random.Random(seed)
    cases=[]
    for _ in range(iters):
        maxsize=rng.choice([4,5,8])
        ln=rng.randrange(0,9)
        cases.append(('snum',ln,maxsize,rng.randbytes(ln)))
    for _ in range(iters):
        v=rng.randint(-2**63,2**63-1)
        if rng.random()<0.3: v=rng.randrange(-100,100)
        cases.append(('sser',v,0,b''))
    for _ in range(iters):
        cases.append(('cb',0,0,rng.randbytes(rng.randrange(0,40))))
    for _ in range(iters):
        # mostly DER-ish sigs
        r=rng.randrange(0,40)
        if r<20:
            # build plausible der + trailing byte
            def be(x):
                b=x.to_bytes(32,'big'); 
                if b[0]&0x80: b=b'\x00'+b
                return b
            rd=be(rng.getrandbits(255)); sd=be(rng.getrandbits(255))
            body=b'\x02'+bytes([len(rd)])+rd+b'\x02'+bytes([len(sd)])+sd
            hb=bytes([rng.randrange(1,3)])
            sig=b'\x30'+bytes([len(body)+len(hb)])+body+hb
            if rng.random()<0.5:
                # corrupt
                sig=bytearray(sig); sig[rng.randrange(len(sig))]^=0x01; sig=bytes(sig)
        else:
            sig=rng.randbytes(rng.randrange(0,80))
        cases.append(('der',0,0,sig))
    for _ in range(iters):
        op=rng.randrange(0,0x100)
        pl=rng.choice([0,1,2,50,75,76,255,256,300,65535,65536,70000])
        data=rng.randbytes(min(max(pl,1),3) if pl>0 else 0)
        cases.append(('minpush',op,pl,data))
    with open('/tmp/codec_cases.txt','w') as f:
        for mode,a,b,c in cases:
            hh = c.hex() if c else '-'
            if mode=='snum': f.write(f"snum {a} {b} {hh}\n")
            elif mode=='sser': f.write(f"sser {a}\n")
            elif mode=='cb': f.write(f"cb {hh}\n")
            elif mode=='der': f.write(f"der {hh}\n")
            else: f.write(f"minpush {a} {b} {hh}\n")
    p=subprocess.run(['./t_codec','/tmp/codec_cases.txt'],capture_output=True,text=True)
    if p.returncode!=0:
        print("DRIVER FAIL rc",p.returncode,p.stderr); sys.exit(2)
    lines=p.stdout.splitlines()   # keep empty lines (sser 0 -> empty serialization)
    assert len(lines)==len(cases), f"{len(lines)} vs {len(cases)}"
    fails=0
    for (mode,a,b,c),out in zip(cases,lines):
        if mode=='snum':
            v,ov=snum_decode(c,b)
            exp=f"{v} {ov}"
            if out!=exp:
                fails+=1
                if fails<=6: print("SNUM",c.hex(),"max",b,"exp",exp,"got",out)
        elif mode=='sser':
            exp=snum_ser(a).hex()
            if out!=exp:
                fails+=1
                if fails<=6: print("SSER",a,"exp",exp,"got",out)
        elif mode=='cb':
            exp=str(cast_bool(c))
            if out!=exp:
                fails+=1
                if fails<=6: print("CB",c.hex(),"exp",exp,"got",out)
        elif mode=='der':
            exp=str(der_strict(c))
            if out!=exp:
                fails+=1
                if fails<=6: print("DER",c.hex(),"exp",exp,"got",out)
        else:
            exp=str(min_push(a,b,c))
            if out!=exp:
                fails+=1
                if fails<=6: print("MINPUSH op",a,"pl",b,"data",c.hex(),"exp",exp,"got",out)
    print(f"seed={seed} iters={iters} cases={len(cases)} FAILS={fails}")
    sys.exit(1 if fails else 0)

if __name__=='__main__': main()
