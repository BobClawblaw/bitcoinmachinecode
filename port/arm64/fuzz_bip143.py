#!/usr/bin/env python3
"""Differential fuzz for segwit_v0_sighash_asm (bitcoin_bip143.S) vs an
independent Python BIP143 implementation. Runs ./t_bip143.
"""
import hashlib, random, subprocess, sys

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def cvint(n):
    if n<0xfd: return bytes([n])
    if n<=0xffff: return b'\xfd'+n.to_bytes(2,'little')
    if n<=0xffffffff: return b'\xfe'+n.to_bytes(4,'little')
    return b'\xff'+n.to_bytes(8,'little')

def segwit_tx(rng, nin, nout, segwit=True, max_ss=40, max_w=6, max_sp=40):
    """Return a serialized (optionally segwit) tx via parse of structure."""
    ins=[]; outs=[]
    for _ in range(nin):
        ins.append({'po':rng.randbytes(32)+rng.randrange(0x100000000).to_bytes(4,'little'),
                    'ss':rng.randbytes(rng.randrange(0,max_ss+1)),
                    'seq':rng.randrange(0x100000000).to_bytes(4,'little'),
                    'wit':[rng.randbytes(rng.randrange(1,40)) for _ in range(rng.randrange(0,max_w+1))]})
    for _ in range(nout):
        outs.append({'val':rng.randrange(0,0x21000000000000).to_bytes(8,'little'),
                     'spk':rng.randbytes(rng.randrange(0,max_sp+1))})
    lock=rng.randrange(0x100000000).to_bytes(4,'little')
    version=rng.randrange(0,0x100000000).to_bytes(4,'little')
    b=bytearray()
    b+=version
    if segwit:
        b+=b'\x00\x01'
    b+=cvint(nin)
    for i in ins:
        b+=i['po']; b+=cvint(len(i['ss'])); b+=i['ss']; b+=i['seq']
    b+=cvint(nout)
    for o in outs:
        b+=o['val']; b+=cvint(len(o['spk'])); b+=o['spk']
    if segwit:
        for i in ins:
            b+=cvint(len(i['wit']))
            for w in i['wit']:
                b+=cvint(len(w)); b+=w
    b+=lock
    return bytes(b)

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

def swtx(txb):
    r=Reader(txb)
    ver=r.take(4)
    segwit=False
    if r.b[r.p:r.p+2]==b'\x00\x01':
        segwit=True; r.take(2)
    nin=r.varint()
    in_off=[r.p]
    ins=[]
    for _ in range(nin):
        po=r.take(36); ss=r.varint(); ins.append({'po':po,'seq':None}); r.take(ss)
        ins[-1]['seq']=r.take(4)
        in_off.append(r.p)
    nout=r.varint()
    out=[None]*nout
    out_off=[r.p]
    for j in range(nout):
        val=r.take(8); sp=r.varint(); spk=r.take(sp)
        out[j]={'val':val,'spk':spk}
        out_off.append(r.p)
    if segwit:
        for _ in range(nin):
            n=r.varint()
            for _ in range(n): n2=r.varint(); r.take(n2)
    lock=r.take(4)
    return ver,segwit,ins,out,lock,in_off,out_off

def bip143(txb, n_in, htype, amount, scriptCode):
    fANYONE = bool(htype & 0x80)
    base = htype & 0x1f
    fNone = base==2
    fSingle = base==3
    try:
        ver,segwit,ins,out,lock,in_off,out_off = swtx(txb)
    except OverflowError:
        return None
    nin=len(ins); nout=len(out)
    if n_in<0 or n_in>=nin: return None
    hp=b'\x00'*32; hs=b'\x00'*32; ho=b'\x00'*32
    if not fANYONE:
        hp=sha256d(b''.join(i['po'] for i in ins))
    if not (fANYONE or fNone or fSingle):
        hs=sha256d(b''.join(i['seq'] for i in ins))
    if fSingle:
        if n_in<nout:
            ho=sha256d(out[n_in]['val']+cvint(len(out[n_in]['spk']))+out[n_in]['spk'])
    elif not fNone:
        allout=b''.join(o['val']+cvint(len(o['spk']))+o['spk'] for o in out)
        ho=sha256d(allout)
    pre=(ver + hp + hs + ins[n_in]['po'] + cvint(len(scriptCode)) + scriptCode
         + amount.to_bytes(8,'little') + ins[n_in]['seq'] + ho + lock
         + htype.to_bytes(4,'little'))
    return sha256d(pre), pre

def rand_ht(rng,bases=(1,2,3,0x41,0x82,0x83)):
    b=rng.choice(bases); acp=0x80 if rng.random()<0.5 else 0
    if rng.random()<0.15: return b|acp|(rng.randrange(0,0x10000)<<8)
    return b|acp

def main():
    seed=int(sys.argv[1]) if len(sys.argv)>1 else 1
    iters=int(sys.argv[2]) if len(sys.argv)>2 else 2000
    rng=random.Random(seed)
    cases=[]
    for _ in range(iters):
        nin=rng.randrange(1,6); nout=rng.randrange(1,6)
        segwit = rng.random()<0.5
        txb=segwit_tx(rng,nin,nout,segwit=segwit)
        nIn=rng.randrange(0,nin)
        if rng.random()<0.08: nIn=rng.randrange(nin,nin+3)  # out of range
        ht=rand_ht(rng)
        amount=rng.randrange(0,0x21000000000000)
        sc=rng.randbytes(rng.randrange(0,80))
        if rng.random()<0.08: txb=txb[:rng.randrange(0,max(0,len(txb)-1))]  # truncate
        cases.append((txb,nIn,ht,amount,sc))
    with open('/tmp/b143_cases.txt','w') as f:
        for txb,nIn,ht,amount,sc in cases:
            f.write(f"{(txb.hex() if txb else '-')} {nIn} {ht} {amount} {(sc.hex() if sc else '-')}\n")
    p=subprocess.run(['./t_bip143','/tmp/b143_cases.txt'],capture_output=True,text=True)
    if p.returncode!=0:
        print("DRIVER FAIL rc",p.returncode,p.stderr); sys.exit(2)
    lines=[l for l in p.stdout.splitlines() if l.strip()]
    assert len(lines)==len(cases), f"{len(lines)} vs {len(cases)}"
    fails=0
    for (txb,nIn,ht,amt,sc),out in zip(cases,lines):
        g=out.split()
        r=bip143(txb,nIn,ht,amt,sc)
        if r is None:
            ok = (int(g[0])==0)
        else:
            exp_hash, exp_pre = r
            ok = (int(g[0])==len(exp_pre) and g[1]==exp_hash.hex())
        if not ok:
            fails+=1
            if fails<=5:
                print("MISMATCH nIn",nIn,"ht",hex(ht),"amt",amt,"txlen",len(txb),"sclen",len(sc))
                print("  driver", out[:160])
                print("  exp  ", "ret", (0 if r is None else len(r[1])), ("" if r is None else r[0].hex()))
    print(f"seed={seed} iters={iters} cases={len(cases)} FAILS={fails}")
    sys.exit(1 if fails else 0)

if __name__=='__main__': main()
