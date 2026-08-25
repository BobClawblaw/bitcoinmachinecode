#!/usr/bin/env python3
"""Differential fuzz: bitcoin_sighash.S legacy_sighash vs independent Python
implementation of Bitcoin's Legacy SignatureHash (Core SignatureHash()).

Generates random well-formed + malformed txs, all hashtype families incl. the
SIGHASH_SINGLE out-of-range quirk (uint256(1)), runs ./t_sighash, compares.
"""
import hashlib, random, subprocess, sys, os

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def cvint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd'+n.to_bytes(2,'little')
    if n <= 0xffffffff: return b'\xfe'+n.to_bytes(4,'little')
    return b'\xff'+n.to_bytes(8,'little')

class Reader:
    def __init__(self,b): self.b=b; self.p=0
    def take(self,n):
        if self.p+n>len(self.b): raise OverflowError
        v=self.b[self.p:self.p+n]; self.p+=n; return v
    def varint(self):
        c=self.take(1)[0]
        if c<0xfd: return c
        if c==0xfd: return int.from_bytes(self.take(2),'little')
        if c==0xfe: return int.from_bytes(self.take(4),'little')
        return int.from_bytes(self.take(8),'little')

def parse_tx(b):
    r=Reader(b)
    version=r.take(4)
    nin=r.varint()
    ins=[]
    for _ in range(nin):
        po=r.take(36); ss=r.varint(); ins.append((po,r.take(ss),r.take(4)))
    nout=r.varint()
    outs=[]
    for _ in range(nout):
        ins_outs_val=r.take(8); sp=r.varint(); outs.append((ins_outs_val,r.take(sp)))
    lock=r.take(4)
    return version,ins,outs,lock

def solen(sc,i,n):
    if i>=n: return 0
    op=sc[i]
    if op<=0x4b: l=1+op
    elif op==0x4c:
        if i+2>n: return 0
        l=2+sc[i+1]
    elif op==0x4d:
        if i+3>n: return 0
        l=3+int.from_bytes(sc[i+1:i+3],'little')
    elif op==0x4e:
        if i+5>n: return 0
        l=5+int.from_bytes(sc[i+1:i+5],'little')
    else: l=1
    if i+l>n: return 0
    return l

def strip_cs(sc):
    out=bytearray(); i=0; n=len(sc)
    while i<n:
        l=solen(sc,i,n)
        if l==0: out+=sc[i:]; break
        if l==1 and sc[i]==0xab: i+=1; continue
        out+=sc[i:i+l]; i+=l
    return bytes(out)

def legacy_sighash(tx, nIn, sc, hashtype, cap=1<<30):
    """Returns (ret, 32-byte-hash-or-None). ret 1 => hash valid, ret 0 => fail."""
    if len(tx) < 10: return (0, None)
    fACP = bool(hashtype & 0x80)
    base = hashtype & 0x1f
    fSingle = (base == 3)
    fNone   = (base == 2)
    try:
        version, ins, outs, lock = parse_tx(tx)
    except OverflowError:
        return (0, None)
    n_in=len(ins); n_out=len(outs)
    if nIn >= n_in: return (0, None)
    if fSingle and nIn >= n_out:
        return (1, b'\x01'+b'\x00'*31)   # uint256(1) quirk
    pre=[]
    pre.append(version)
    pre.append(cvint(1 if fACP else n_in))
    for i,(po,ssb,seqb) in enumerate(ins):
        if i==nIn:
            pre.append(po)
            scF=strip_cs(sc)
            pre.append(cvint(len(scF))); pre.append(scF)
            pre.append(seqb)
        else:
            if fACP: continue
            pre.append(po); pre.append(cvint(0))
            pre.append(b'\x00'*4 if (fSingle or fNone) else seqb)
    if fNone: pre.append(cvint(0))
    elif fSingle: pre.append(cvint(nIn+1))
    else: pre.append(cvint(n_out))
    if not fNone:
        for j,(val,spk) in enumerate(outs):
            if fSingle:
                if j<nIn: pre.append(b'\xff'*8+b'\x00'); continue
                if j>nIn: continue
            pre.append(val); pre.append(cvint(len(spk))); pre.append(spk)
    pre.append(lock)
    pre.append(hashtype.to_bytes(4,'little'))
    total=b''.join(pre)
    if len(total)>cap: return (0, None)
    return (1, sha256d(total))

def rand_tx(rng, nin, nout, max_ss, max_sp):
    b=bytearray()
    b+=rng.randrange(0,0x100000000).to_bytes(4,'little')
    b+=cvint(nin)
    for _ in range(nin):
        b+=rng.randbytes(32); b+=rng.randrange(0,0x100000000).to_bytes(4,'little')
        ss=rng.randrange(0,max_ss+1); b+=cvint(ss); b+=rng.randbytes(ss)
        b+=rng.randrange(0,0x100000000).to_bytes(4,'little')
    b+=cvint(nout)
    for _ in range(nout):
        b+=rng.randrange(0,0x0021_0000_0000_0000).to_bytes(8,'little')
        sp=rng.randrange(0,max_sp+1); b+=cvint(sp); b+=rng.randbytes(sp)
    b+=rng.randrange(0,0x100000000).to_bytes(4,'little')
    return bytes(b)

def rand_sc(rng, maxlen=90):
    # script with occasional OP_CODESEPARATOR and pushdata to exercise strip
    b=bytearray()
    n=rng.randrange(0,maxlen+1)
    for _ in range(n):
        r=rng.randrange(0,12)
        if r<3: b.append(0xab)                       # lone codeseparator
        elif r<6:
            pl=rng.randrange(0,50); b.append(pl); b+=rng.randbytes(pl)
        elif r<9:
            pl=rng.randrange(0,250); b.append(0x4c); b.append(pl); b+=rng.randbytes(pl)
        else: b.append(rng.randrange(0,0xab))        # random op (may hit 0xab too)
    return bytes(b)

def main():
    seed=int(sys.argv[1]) if len(sys.argv)>1 else 1
    iters=int(sys.argv[2]) if len(sys.argv)>2 else 3000
    rng=random.Random(seed)
    cases=[]
    bases=[1,2,3,0,7]
    for _ in range(iters):
        nin=rng.randrange(1,9); nout=rng.randrange(1,9)
        tx=rand_tx(rng,nin,nout,max_ss=180,max_sp=110)
        # sometimes malformed (truncate)
        if rng.random()<0.10 and len(tx)>12:
            tx=tx[:rng.randrange(0,len(tx)-2)]
        nIn=rng.randrange(0,nin) if rng.random()<0.92 else rng.randrange(nin,nin+3)
        sc=rand_sc(rng)
        if rng.random()<0.8:
            bt= rng.choice(bases); acp=0x80 if rng.random()<0.5 else 0
            if rng.random()<0.15: ht=bt|acp|(rng.randrange(0,0x10000)<<8)
            else: ht=bt|acp
        else:
            ht=rng.randrange(0,0x100000000)
        cases.append((tx,nIn,sc,ht))
    # write cases file
    with open('/tmp/sh_cases.txt','w') as f:
        for tx,nIn,sc,ht in cases:
            f.write(f"{(tx.hex() if tx else '-')} {nIn} {(sc.hex() if sc else '-')} {ht}\n")
    proc=subprocess.run(['./t_sighash','/tmp/sh_cases.txt'],
                        capture_output=True,text=True)
    if proc.returncode!=0:
        print("DRIVER FAILED rc",proc.returncode); print(proc.stderr); sys.exit(2)
    lines=[l for l in proc.stdout.splitlines() if l.strip()]
    assert len(lines)==len(cases), f"expected {len(cases)} lines, got {len(lines)}"
    fails=0
    for (tx,nIn,sc,ht),out in zip(cases,lines):
        g=out.split()
        gret=int(g[0]); ghex=g[1] if len(g)>1 else ''
        exp=legacy_sighash(tx,nIn,sc,ht)
        bad=False
        if exp[0]!=gret: bad=True
        elif exp[0]==1 and exp[1].hex()!=ghex: bad=True
        if bad:
            fails+=1
            if fails<=5:
                print("MISMATCH")
                print("  tx    ",tx.hex()[:120]," nIn",nIn," ht",hex(ht))
                print("  sc    ",sc.hex()[:120])
                print("  exp   ret",exp[0], exp[1].hex() if exp[1] else None)
                print("  got   ret",gret, ghex)
    print(f"seed={seed} iters={iters} cases={len(cases)} FAILS={fails}")
    sys.exit(1 if fails else 0)

if __name__=='__main__': main()
