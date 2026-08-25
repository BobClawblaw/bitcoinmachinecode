#!/usr/bin/env python3
"""Differential fuzz: bitcoin_checksig.S sv_checksig_asm (legacy BASE) and
sv_checksig_witness_v0_asm vs an independent Python pipeline composing a full
Core-like checksig: DER parse -> FindAndDelete+legacy_sighash (BASE) or BIP143
(WITNESS_V0) -> be_to_limbs -> pubkey_parse -> ECDSA verify.
Runs ./t_checksig.
"""
import os, random, subprocess, sys, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fuzz_ecdsa as E       # P,N,Gx,Gy,smul,add,aff,INF
import fuzz_sighash as SH    # legacy_sighash, strip_cs
import fuzz_bip143 as B143   # bip143
import fuzz_der as DR        # der_parse_py

def limbs_to_int(L): return L[0] | (L[1]<<64) | (L[2]<<128) | (L[3]<<192)

def parse_pub(pub):
    P=E.P
    if len(pub)==33 and pub[0] in (2,3):
        x=int.from_bytes(pub[1:],'big')
        if x>=P: return None
        y2=(pow(x,3,P)+7)%P
        y=pow(y2,(P+1)//4,P)
        if y*y%P!=y2: return None
        if (y&1)!=(pub[0]&1): y=P-y
        return (x,y)
    if len(pub)==65 and pub[0]==4:
        x=int.from_bytes(pub[1:33],'big'); y=int.from_bytes(pub[33:],'big')
        if x>=P or y>=P: return None
        y2=(pow(x,3,P)+7)%P
        if y*y%P!=y2: return None
        return (x,y)
    return None

def pverify(z,r,s,Q):
    N=E.N
    if not (1<=r<N and 1<=s<N): return False
    w=pow(s,-1,N); u1=(z*w)%N; u2=(r*w)%N
    P1=E.smul((E.Gx,E.Gy),u1); P2=E.smul(Q,u2)
    Pt=E.add(P1,P2)
    if Pt is E.INF: return False
    a=E.aff(Pt)
    return (a[0]%N)==r

def der_encode(r,s):
    def be(v):
        b=v.to_bytes(32,'big')
        if b[0]&0x80: b=b'\x00'+b
        return b
    rb,rx=be(r),be(s)
    body=b'\x02'+bytes([len(rb)])+rb+b'\x02'+bytes([len(rx)])+rx
    return b'\x30'+bytes([len(body)])+body

def predict(mode, tx, nIn, amt, sc, pub, sig):
    if len(sig)==0: return 0
    ht=sig[-1]
    rl=DR.der_parse_py(sig)
    if rl[0]==0: return 0
    rint=limbs_to_int(rl[1]); sint=limbs_to_int(rl[2])
    if mode=='legacy':
        scF=SH.strip_cs(sc)
        lr=SH.legacy_sighash(tx, nIn, scF, ht)
        if lr[0]==0: return 0
        z=lr[1]
    else:
        r=B143.bip143(tx, nIn, ht, amt, sc)
        if r is None: return 0
        z=r[0]
    zint=int.from_bytes(z,'big')
    Q=parse_pub(pub)
    if Q is None: return 0
    return 1 if pverify(zint,rint,sint,Q) else 0

def rand_sc(rng):
    b=bytearray()
    for _ in range(rng.randrange(1,60)):
        r=rng.randrange(10)
        if r<2: b.append(0xab)
        elif r<6: b.append(rng.randrange(0,40)); b+=rng.randbytes(rng.randrange(0,40))
        else: b.append(rng.randrange(1,0xab))
    return bytes(b)

def main():
    seed=int(sys.argv[1]) if len(sys.argv)>1 else 1
    iters=int(sys.argv[2]) if len(sys.argv)>2 else 1500
    rng=random.Random(seed)
    cases=[]
    expects=[]
    for _ in range(iters):
        mode = 'witness' if rng.random()<0.5 else 'legacy'
        nin=rng.randrange(1,5); nout=rng.randrange(1,5)
        tx=B143.segwit_tx(rng,nin,nout,segwit=rng.random()<0.5)
        nIn=rng.randrange(0,nin)
        amt=rng.randrange(0,0x21000000000000)
        sc=rand_sc(rng)
        # build pubkey + valid sig for some z
        d=1+rng.getrandbits(255)%(E.N-1)
        Q=E.smul((E.Gx,E.Gy),d); Qa=E.aff(Q)
        if rng.random()<0.5:
            pub=bytes([2+(Qa[1]&1)])+Qa[0].to_bytes(32,'big')
        else:
            pub=b'\x04'+Qa[0].to_bytes(32,'big')+Qa[1].to_bytes(32,'big')
        # compute z and sign
        ht=rng.choice([1,2,3,0x41,0x82,0x83]) | (0x80 if rng.random()<0.5 else 0)
        if mode=='legacy':
            scF=SH.strip_cs(sc)
            lr=SH.legacy_sighash(tx, nIn, scF, ht)
        else:
            bp=B143.bip143(tx,nIn,ht,amt,sc)
        # fallback if sighash fails (shouldn't for well-formed)
        if mode=='legacy':
            if lr[0]==0: continue
            z=lr[1]
        else:
            if bp is None: continue
            z=bp[0]
        zint=int.from_bytes(z,'big')
        k=1+rng.getrandbits(255)%(E.N-1)
        sg=E.sign(zint,d,k)
        if sg is None: continue
        r,s=sg
        sig=der_encode(r,s)+bytes([ht])
        # maybe corrupt
        which=rng.random()
        if which<0.15:
            # wrong sig bytes
            pos=rng.randrange(len(sig)); new=bytes([rng.randrange(256)])
            sig=sig[:pos]+new+sig[pos+1:]
        elif which<0.22:
            # wrong pubkey (different d)
            d2=1+rng.getrandbits(255)%(E.N-1)
            Q2=E.smul((E.Gx,E.Gy),d2); Qa2=E.aff(Q2)
            pub=bytes([2+(Qa2[1]&1)])+Qa2[0].to_bytes(32,'big')
        elif which<0.27:
            # random garbage sig
            sig=rng.randbytes(rng.randrange(1,72))
        exp=predict(mode,tx,nIn,amt,sc,pub,sig)
        cases.append((mode,tx,nIn,amt,sc,pub,sig))
        expects.append(exp)
    with open('/tmp/cks_cases.txt','w') as f:
        for mode,tx,nIn,amt,sc,pub,sig in cases:
            f.write(f"{mode} {(tx.hex() if tx else '-')} {nIn} {amt} "
                    f"{(sc.hex() if sc else '-')} {pub.hex()} {sig.hex()}\n")
    p=subprocess.run(['./t_checksig','/tmp/cks_cases.txt'],capture_output=True,text=True)
    if p.returncode!=0:
        print("DRIVER FAIL rc",p.returncode,p.stderr); sys.exit(2)
    lines=[l for l in p.stdout.splitlines() if l.strip()]
    assert len(lines)==len(cases), f"{len(lines)} vs {len(cases)}"
    fails=0
    for (mode,tx,nIn,amt,sc,pub,sig),out,exp in zip(cases,lines,expects):
        got=int(out)
        if got!=exp:
            fails+=1
            if fails<=8:
                print("MISMATCH",mode,"nIn",nIn,"ht",hex(sig[-1]),"txlen",len(tx),"sclen",len(sc),"publen",len(pub),"siglen",len(sig))
                print("   exp",exp,"got",got)
                print("   sig",sig.hex()[:120])
    print(f"seed={seed} iters={iters} cases={len(cases)} FAILS={fails}")
    sys.exit(1 if fails else 0)

if __name__=='__main__': main()
