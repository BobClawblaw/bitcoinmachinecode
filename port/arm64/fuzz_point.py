#!/usr/bin/env python3
"""fuzz_point.py -- differential fuzz of port/arm64/secp256k1_point.S against an
independent pure-Python secp256k1 group oracle (Jacobian add-2007-bl,
dbl-2009-l, mixed add, double-and-add scalar mul)."""
import subprocess, sys, random, os

P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
INF = None

def f2p(x): return x % P

def double(X1,Y1,Z1):
    A  = f2p(X1*X1); B = f2p(Y1*Y1); C = f2p(B*B)
    D  = f2p(2*((X1+B)*(X1+B) - A - C))
    E  = f2p(3*A); F = f2p(E*E)
    X3 = f2p(F - 2*D)
    Y3 = f2p(E*(D - X3) - 8*C)
    Z3 = f2p(2*Y1*Z1)
    return X3,Y3,Z3

def add(P,Q):
    if P is INF: return Q
    if Q is INF: return P
    X1,Y1,Z1 = P; X2,Y2,Z2 = Q
    Z1Z1=f2p(Z1*Z1); Z2Z2=f2p(Z2*Z2)
    U1=f2p(X1*Z2Z2); U2=f2p(X2*Z1Z1)
    S1=f2p(Y1*Z2*Z2Z2); S2=f2p(Y2*Z1*Z1Z1)
    if U1==U2:
        if S1!=S2: return INF
        return double(*P)
    H=f2p(U2-U1); R=f2p(S2-S1)
    HH=f2p(H*H); HHH=f2p(H*HH); V=f2p(U1*HH)
    X3=f2p(R*R-HHH-2*V)
    Y3=f2p(R*(V-X3)-S1*HHH)
    Z3=f2p(Z1*Z2*H)
    return X3,Y3,Z3

def addmixed(P,xy):
    X1,Y1,Z1=P; X2,Y2=xy
    Z1Z1=f2p(Z1*Z1)
    U2=f2p(X2*Z1Z1); S2=f2p(Y2*Z1*Z1Z1)
    if U2==X1:
        if S2!=Y1: return (INF, None)
        return (double(*P), None)
    H=f2p(U2-X1); R=f2p(S2-Y1)
    HH=f2p(H*H); HHH=f2p(H*HH); V=f2p(X1*HH)
    X3=f2p(R*R-HHH-2*V)
    Y3=f2p(R*(V-X3)-Y1*HHH)
    Z3=f2p(Z1*H)
    return ((X3,Y3,Z3), H)

def scalarmul(xy,k):
    # simple double-and-add over Jacobian (independent oracle)
    base=(xy[0],xy[1],1)
    R=INF
    while k:
        if k&1: R=add(R,base)
        base=double(*base)
        k>>=1
    return R

def scalar_ladder(xy,k):
    # left-to-right to double check
    if k==0: return INF
    base=(xy[0],xy[1],1)
    R=base
    bits=[int(b) for b in bin(k)[2:]][1:]
    for b in bits:
        R=double(*R)
        if b: R=add(R,base)
    return R

def aff(PT):
    if PT is INF: return None
    X,Y,Z=PT
    zi=pow(Z,P-2,P)
    zi2=f2p(zi*zi); zi3=f2p(zi2*zi)
    return f2p(X*zi2), f2p(Y*zi3)

L=[f'{x & ((1<<64)-1):016x}' for x in (0,0,0,0)]  # dummy

def limbs(v):
    out=[]
    for _ in range(4):
        out.append(v & ((1<<64)-1)); v >>= 64
    return out

def fmt(v):  # field element -> 4 limbs hex string (space sep)
    return " ".join("%016x"%x for x in limbs(v))

def fmt_p(P):
    if P is INF: return "inf"
    a=aff(P)
    return fmt(a[0])+" "+fmt(a[1])

def fmt_j(P):  # Jacobian 12 limbs
    return fmt(P[0])+" "+fmt(P[1])+" "+fmt(P[2])

def lift(xy):
    return (xy[0],xy[1],1)

def main():
    BIN = sys.argv[1] if len(sys.argv)>1 else "./fz_point"
    N   = int(sys.argv[2]) if len(sys.argv)>2 else 3000
    seed = int(sys.argv[3]) if len(sys.argv)>3 else int.from_bytes(os.urandom(4),'big')
    rng = random.Random(seed)
    vectors=[]; expects=[]
    def addv(op,args,exp):
        vectors.append(op+" "+args.strip()); expects.append(exp)
    for _ in range(N):
        k1=rng.getrandbits(255)% (N-1)+1
        k2=rng.getrandbits(255)% (N-1)+1
        P=scalarmul((Gx,Gy),k1)
        Q=scalarmul((Gx,Gy),k2)
        Pj=lift(P); Qj=lift(Q)
        Pa=fmt_p(P); Qa=fmt_p(Q)
        Pjf=fmt_j(Pj); Qjf=fmt_j(Qj)
        # dbl and dbl_ia
        addv("dbl",Pjf,fmt_p(double(*Pj)))
        addv("dbl_ia",Pjf,None)  # in-place
        expects[-1]=expects[-2]
        # add P+Q
        addv("add",Pjf+" "+Qjf,fmt_p(add(Pj,Qj)))
        addv("add_ia",Pjf+" "+Qjf,None); expects[-1]=expects[-2]
        # add P+P (double branch)
        addv("add",Pjf+" "+Pjf,fmt_p(double(*Pj)))
        # add P + (-P) -> inf
        neg=(P[0], f2p(-P[1]), 1)
        addv("add",Pjf+" "+fmt_j(neg),fmt_p(INF))
        # mixed P_jac + affine Q
        r=addmixed(Pj,(Q[0],Q[1]))
        addv("mixed",Pjf+" "+fmt(Q[0])+" "+fmt(Q[1]),fmt_p(r[0]))
        addv("mixed_ia",Pjf+" "+fmt(Q[0])+" "+fmt(Q[1]),None); expects[-1]=expects[-2]
        # mixed P + affine P (double branch)
        addv("mixed",Pjf+" "+fmt(P[0])+" "+fmt(P[1]),fmt_p(double(*Pj)))
        # mixed P + affine(-P) -> inf
        addv("mixed",Pjf+" "+fmt(P[0])+" "+fmt(f2p(P[1]*-1)),
             fmt_p(addmixed(Pj,(P[0],f2p(P[1]*-1)))[0]))
        # mixed_zr : compare result AND z-ratio (handle degenerate zr)
        r=addmixed(Pj,(Q[0],Q[1]))
        if r[1] is None:
            if r[0] is INF:
                zrex=" ".join(["0000000000000000"]*4)   # opposite -> zr=0
            else:
                zrex=fmt(f2p(2*P[1]))                    # double -> zr=2*Y1
        else:
            zrex=fmt(r[1])
        addv("mixed_zr",Pjf+" "+fmt(Q[0])+" "+fmt(Q[1]),
             fmt_p(r[0])+" zr "+zrex)
        # scalar multiples
        for kk in (k1, k2, 1, 2, 5, 0, N-1, rng.getrandbits(255)):
            kk%=N
            exp=fmt_p(scalar_ladder((Q[0],Q[1]),kk))
            addv("scalar",fmt(Q[0])+" "+fmt(Q[1])+" "+" ".join("%016x"%x for x in limbs(kk)),exp)
    payload="\n".join(vectors)+"\n"
    r=subprocess.run([BIN],input=payload,capture_output=True,text=True)
    if r.returncode!=0:
        print("fz_point crashed / exit",r.returncode); print(r.stderr); sys.exit(2)
    outs=r.stdout.splitlines()
    if len(outs)!=len(vectors):
        print("LINE MISMATCH",len(outs),len(vectors)); sys.exit(2)
    fails=0
    for vi,(vec,exp,out) in enumerate(zip(vectors,expects,outs)):
        op=vec.split()[0]
        # normalize 'inf' and ' zr' handling
        got=out.strip()
        # strip op echo
        got=got[len(op):].strip()
        expv=exp.strip()
        # compare whole tokens (x y [zr ...])
        gt=got.split(); ev=expv.split()
        if gt!=ev:
            if fails<10:
                print(f"MISMATCH vec {vi} op {op}\n  ARG: {vec}\n  GOT: {got}\n  EXP: {expv}")
            fails+=1
    print(f"{len(vectors)} vectors, {fails} failures  (seed={seed})")
    sys.exit(1 if fails else 0)

if __name__=="__main__":
    main()
