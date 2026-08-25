#!/usr/bin/env python3
"""fuzz_schnorr.py -- differential fuzz of port/arm64/secp256k1_schnorr.S
(schnorr_verify / BIP340) against an independent pure-Python BIP340 impl."""
import subprocess, sys, random, hashlib, os
PRIME=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
def add(p,q):
    if p is None:return q
    if q is None:return p
    if p[0]==q[0]:
        if (p[1]+q[1])%PRIME==0:return None
        l=(3*p[0]*p[0])*pow(2*p[1],PRIME-2,PRIME)%PRIME
    else: l=(q[1]-p[1])*pow(q[0]-p[0],PRIME-2,PRIME)%PRIME
    x=(l*l-p[0]-q[0])%PRIME;y=(l*(p[0]-x)-p[1])%PRIME;return(x,y)
def smul(k):
    R=None;b=(Gx,Gy)
    while k:
        if k&1:R=add(R,b)
        b=add(b,b);k>>=1
    return R
def mpt(P,k):          # k*P for an arbitrary affine point P
    R=None
    b=P
    while k:
        if k&1:R=add(R,b)
        b=add(b,b);k>>=1
    return R
def lift_x(x):
    if x>=PRIME:return None
    y=pow((x*x%PRIME*x+7)%PRIME,(PRIME+1)//4,PRIME)
    if pow(y,2,PRIME)!=(x*x%PRIME*x+7)%PRIME:return None
    return (x, y if y%2==0 else PRIME-y)
def ih(x):return int.from_bytes(x,'big')
def be(v,n=32):return int.to_bytes(v,n,'big')
def tagged(tag,data):
    th=hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th+th+data).digest()
def sign(d,Px,msg,aux):
    t=bytes(a^b for a,b in zip(be(d),tagged("BIP0340/aux",aux)))
    k0=ih(tagged("BIP0340/nonce",t+be(Px)+msg))%N
    if k0==0:return None
    R=smul(k0);k=k0 if R[1]%2==0 else N-k0
    e=ih(tagged("BIP0340/challenge",be(R[0])+be(Px)+msg))%N
    return be(R[0])+be((k+e*d)%N)
def verify2(pk,sig,msg):
    Px=ih(pk)
    if len(sig)!=64:return 0
    if Px>=PRIME:return 0
    Ppt=lift_x(Px)
    if Ppt is None:return 0
    r=ih(sig[:32]);s=ih(sig[32:])
    if r>=PRIME:return 0
    if s>=N:return 0
    e=ih(tagged("BIP0340/challenge",sig[:32]+pk+msg))%N
    eP=mpt(Ppt,e);eP=(eP[0],(PRIME-eP[1])%PRIME)
    sG=smul(s)
    Rpt=add(sG,eP)
    if Rpt is None:return 0
    if Rpt[1]%2==1:return 0
    return 1 if Rpt[0]==r else 0
def main():
    BIN=sys.argv[1] if len(sys.argv)>1 else "./fz_schnorr"
    n=int(sys.argv[2]) if len(sys.argv)>2 else 2000
    seed=int(sys.argv[3]) if len(sys.argv)>3 else int.from_bytes(os.urandom(4),'big')
    rng=random.Random(seed)
    vecs=[];exp=[]
    for _ in range(n):
        d=1+rng.randrange(1,N-1);Px=smul(d)[0];aux=rng.randbytes(32)
        msg=rng.randbytes(rng.choice([0,1,3,32,64,100]))
        sig=sign(d,Px,msg,aux)
        if sig is None:continue
        pk=be(Px)
        vecs.append(sig.hex()+" "+pk.hex()+" "+msg.hex());exp.append(verify2(pk,sig,msg))
        bad=bytes((b+1)%256 for b in msg)
        vecs.append(sig.hex()+" "+pk.hex()+" "+bad.hex());exp.append(verify2(pk,sig,bad))
        bs=bytearray(sig);bs[63]^=1
        vecs.append(bytes(bs).hex()+" "+pk.hex()+" "+msg.hex());exp.append(verify2(pk,bytes(bs),msg))
        x2=(Px+rng.getrandbits(12))%PRIME
        vecs.append(sig.hex()+" "+be(x2).hex()+" "+msg.hex());exp.append(verify2(be(x2),sig,msg))
        # r >= p (invalid) and s == 0 (invalid)
        vecs.append((be((1<<255)|Px)+sig[32:]).hex()+" "+pk.hex()+" "+msg.hex());exp.append(verify2(pk,be((1<<255)|Px)+sig[32:],msg))
        vecs.append((sig[:32]+be(0)).hex()+" "+pk.hex()+" "+msg.hex());exp.append(verify2(pk,sig[:32]+be(0),msg))
        # a fresh valid sig for a different msg, then verify with msg (should be invalid)
        msg2=rng.randbytes(len(msg) or 1)
        sig_d=sign(d,Px,msg2,aux)
        if sig_d is not None:
            vecs.append(sig_d.hex()+" "+pk.hex()+" "+msg.hex());exp.append(verify2(pk,sig_d,msg))
    if not vecs:print("none");sys.exit(2)
    r_=subprocess.run([BIN],input="\n".join(vecs)+"\n",capture_output=True,text=True)
    if r_.returncode!=0:
        print("crash",r_.returncode);print(r_.stderr);sys.exit(2)
    outs=r_.stdout.splitlines()
    if len(outs)!=len(vecs):
        print("LINECOUNT",len(outs),len(vecs));sys.exit(2)
    fails=0
    for i,(v,e,o) in enumerate(zip(vecs,exp,outs)):
        if int(o)!=int(e):
            fails+=1
            if fails<10:print("MISMATCH vec",i,"exp",e,"got",o)
    print(len(vecs),"vectors,",fails,"failures (seed",seed,")")
    sys.exit(1 if fails else 0)
if __name__=="__main__":
    main()
