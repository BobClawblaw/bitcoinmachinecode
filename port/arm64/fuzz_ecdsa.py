#!/usr/bin/env python3
"""fuzz_ecdsa.py -- differential fuzz of port/arm64/secp256k1_ecdsa.S
(ecdsa_verify) against an independent pure-Python ECDSA signer+verifier.
For each case the ASM verify result must match the Python verify result."""
import subprocess, sys, random, os
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
INF=None
def f2p(x):return x%P
def double(X1,Y1,Z1):
    A=f2p(X1*X1);B=f2p(Y1*Y1);C=f2p(B*B);D=f2p(2*((X1+B)*(X1+B)-A-C))
    E=f2p(3*A);F=f2p(E*E);X3=f2p(F-2*D);Y3=f2p(E*(D-X3)-8*C);Z3=f2p(2*Y1*Z1)
    return X3,Y3,Z3
def add(p,q):
    if p is INF:return q
    if q is INF:return p
    X1,Y1,Z1=p;X2,Y2,Z2=q
    Z1Z1=f2p(Z1*Z1);Z2Z2=f2p(Z2*Z2)
    U1=f2p(X1*Z2Z2);U2=f2p(X2*Z1Z1);S1=f2p(Y1*Z2*Z2Z2);S2=f2p(Y2*Z1*Z1Z1)
    if U1==U2:
        if S1!=S2:return INF
        return double(*p)
    H=f2p(U2-U1);R=f2p(S2-S1);HH=f2p(H*H);HHH=f2p(H*HH);V=f2p(U1*HH)
    X3=f2p(R*R-HHH-2*V);Y3=f2p(R*(V-X3)-S1*HHH);Z3=f2p(Z1*Z2*H)
    return X3,Y3,Z3
def smul(xy,k):
    R=INF;b=(xy[0],xy[1],1)
    while k:
        if k&1:R=add(R,b)
        b=double(*b);k>>=1
    return R
def aff(pt):
    if pt is INF:return None
    X,Y,Z=pt;zi=pow(Z,P-2,P);zi2=f2p(zi*zi);zi3=f2p(zi2*zi)
    return f2p(X*zi2),f2p(Y*zi3)
def limbs(v):return [(v>>(64*i))&((1<<64)-1) for i in range(4)]
def f(v):return " ".join("%016x"%x for x in limbs(v & ((1<<256)-1)))
def pv(v):return v # already < n

def sign(z, d, k):
    R=smul((Gx,Gy),k); Rx,Ry=aff(R)
    r=Rx%N
    if r==0:return None
    kinv=pow(k,-1,N)
    s=(kinv*(z+r*d))%N
    if s==0:return None
    return r,s

def pverify(z,r,s,Q):
    if not (1<=r<N and 1<=s<N):return False
    w=pow(s,-1,N);u1=(z*w)%N;u2=(r*w)%N
    P1=smul((Gx,Gy),u1);P2=smul(Q,u2)
    Pt=add(P1,P2)
    if Pt is INF:return False
    a=aff(Pt)
    return (a[0]%N)==r

def main():
    BIN=sys.argv[1] if len(sys.argv)>1 else "./fz_ecdsa"
    n=int(sys.argv[2]) if len(sys.argv)>2 else 2000
    seed=int(sys.argv[3]) if len(sys.argv)>3 else int.from_bytes(os.urandom(4),'big')
    rng=random.Random(seed)
    vecs=[]; exp=[]
    def addv(z,r,s,Qx,Qy,e):
        vecs.append(f"{f(z)} {f(r)} {f(s)} {f(Qx)} {f(Qy)}")
        exp.append(e)
    for _ in range(n):
        d=1+rng.getrandbits(255)%(N-1)
        k=1+rng.getrandbits(255)%(N-1)
        Q=aff(smul((Gx,Gy),d))
        z=rng.getrandbits(256)%N
        sig=sign(z,d,k)
        if sig is None:
            continue
        r,s=sig
        Qx,Qy=Q
        # valid
        addv(z,r,s,Qx,Qy,1)
        # corrupt each of z,r,s,Q by a random delta (usually invalid)
        for var in range(4):
            def tw(z2,r2,s2,Q2):
                return addv(z2,r2,s2,Q2[0],Q2[1], pverify(z2,r2,s2,Q))
            if var==0: tw((z+rng.getrandbits(256)%N),r,s,Q)
            elif var==1: tw(z,(1+rng.getrandbits(255)%(N-1)),s,Q)
            elif var==2: tw(z,r,(1+rng.getrandbits(255)%(N-1)),Q)
            else:
                # random pubkey (valid point on curve)
                d2=1+rng.getrandbits(255)%(N-1)
                Q2=aff(smul((Gx,Gy),d2))
                addv(z,r,s,Q2[0],Q2[1], pverify(z,r,s,Q2))
        # boundary: r=n-1, s=n-1 (out of range, invalid)
        addv(z,N-1,N-1,Qx,Qy,0)
        addv(z,0,1,Qx,Qy,0)
        addv(z,1,0,Qx,Qy,0)
    if not vecs:
        print("no vectors generated"); sys.exit(2)
    r_=subprocess.run([BIN],input="\n".join(vecs)+"\n",capture_output=True,text=True)
    if r_.returncode!=0:
        print("crash/exit",r_.returncode);print(r_.stderr);sys.exit(2)
    outs=r_.stdout.splitlines()
    if len(outs)!=len(vecs):
        print("mismatch lines",len(outs),len(vecs));sys.exit(2)
    fails=0
    for i,(v,e,o) in enumerate(zip(vecs,exp,outs)):
        if int(o)!=int(e):
            if fails<10:
                print(f"MISMATCH vec {i} exp={e} got={o}\n  {v}")
            fails+=1
    print(f"{len(vecs)} vectors, {fails} failures (seed={seed})")
    sys.exit(1 if fails else 0)
if __name__=="__main__":
    main()
