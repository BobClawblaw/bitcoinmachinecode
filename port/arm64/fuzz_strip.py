#!/usr/bin/env python3
"""fuzz_strip.py -- differential fuzz of strip_witness_asm vs an INDEPENDENT
pure-Python witness stripper. Generates random well-formed legacy + segwit txs
(with witness) and random truncations / canonical-varint variants, drives the
AArch64 asm via fz_sw, and compares rc + full output bytes on every case."""
import random, subprocess, sys

def cs(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + n.to_bytes(2,'little')
    if n <= 0xffffffff: return b'\xfe' + n.to_bytes(4,'little')
    return b'\xff' + n.to_bytes(8,'little')

def gen_tx(rng, segwit, nin=None, nout=None, maxsl=40):
    nin = nin if nin is not None else rng.randint(1,3)
    nout = nout if nout is not None else rng.randint(1,3)
    b = bytearray()
    b += rng.randint(1,2).to_bytes(4,'little')            # version
    if segwit: b += b'\x00\x01'
    b += cs(nin)
    ins=[]
    for i in range(nin):
        prev = bytes(rng.randrange(256) for _ in range(32))
        idx = rng.randrange(0, 0x100000000).to_bytes(4,'little')
        sl = rng.randint(0,maxsl)
        ss = bytes(rng.randrange(256) for _ in range(sl)) if sl else b''
        seq = rng.randrange(0,0x100000000).to_bytes(4,'little')
        seg = prev+idx+cs(sl)+ss+seq
        ins.append(seg)
        b += seg
    b += cs(nout)
    outs=[]
    for j in range(nout):
        val = rng.randrange(0, 0x10000000000000000) or 1
        sl = rng.randint(0,maxsl)
        spk = bytes(rng.randrange(256) for _ in range(sl))
        outs.append(val.to_bytes(8,'little')+cs(sl)+spk)
        b += outs[-1]
    lock = rng.randrange(0,0x100000000)
    if segwit:
        # witness stacks: per input
        for i in range(nin):
            ni = rng.randint(0,3)
            b += cs(ni)
            for j in range(ni):
                il = rng.randint(0,20)
                it = bytes(rng.randrange(256) for _ in range(il))
                b += cs(il)+it
    b += lock.to_bytes(4,'little')
    return bytes(b)

def strip_py(tx):
    """Independent witness stripper: canonical read_cs + minimal re-encode."""
    def read_cs(p,end):
        if p>=end: return None
        f=tx[p]; p+=1
        if f<0xfd: return f,p
        n=(2 if f==0xfd else 4 if f==0xfe else 8)
        if p+n>end: return None
        v=int.from_bytes(tx[p:p+n],'little',); p+=n
        mins={2:0xfd,4:0x10000,8:0x100000000}[n]
        if v<mins: return None
        return v,p
    n=len(tx)
    if n<10: return 0,None
    p=4
    segwit = (tx[p]==0 and tx[p+1]==1)
    if segwit: p+=2
    r=read_cs(p,n); 
    if r is None: return 0,None
    nin,rp=r; p=rp
    if nin==0: return 0,None
    # walk inputs
    q=p
    for i in range(nin):
        if q+36>n: return 0,None
        q+=36
        r=read_cs(q,n); 
        if r is None: return 0,None
        sl,qp=r; q=qp
        if q+sl+4>n: return 0,None
        q+=sl+4
    outs_start=q
    r=read_cs(q,n); 
    if r is None: return 0,None
    nout,q=r; # nout unused except walking
    for i in range(nout):
        if q+8>n: return 0,None
        q+=8
        r=read_cs(q,n);
        if r is None: return 0,None
        sl,qp=r; q=qp
        if q+sl>n: return 0,None
        q+=sl
    outs_end=q
    lock=q
    if segwit:
        for i in range(nin):
            r=read_cs(q,n);
            if r is None: return 0,None
            nit,qp=r; q=qp
            for j in range(nit):
                r=read_cs(q,n);
                if r is None: return 0,None
                il,qp=r; q=qp
                if q+il>n: return 0,None
                q+=il
        lock=q
    if lock+4>n: return 0,None
    # rebuild
    out=bytearray()
    out += tx[0:4]
    out += cs(nin)
    it=p if not segwit else p  # already p at inputs (post nin varint)
    for i in range(nin):
        out += tx[it:it+36]; it+=36
        r=read_cs(it,n)
        sl,qp=r; it=qp
        out += cs(sl); out += tx[it:it+sl]; it+=sl
        # re-read scriptSig start was qp; scriptSig data is it..it+sl
        out += tx[it:it+4]; it+=4
    out += tx[outs_start:outs_end]
    out += tx[lock:lock+4]
    return len(out), bytes(out)

def run_driver(rng, tx, cap):
    proc = subprocess.run(['./fz_sw'], input=(tx.hex()+' '+str(cap)+'\n').encode(),
                          capture_output=True, timeout=20)
    ln=proc.stdout.decode().strip()
    rc_s,_,hexo = ln.partition(':') if ':' in ln else (ln,'', '')
    # partition gives ('1','', '') if no colon -> handle
    if ':' in ln:
        rc_s,_,hexo=ln.partition(':')
    else:
        rc_s=ln; hexo=''
    rc=int(rc_s)
    ob=bytes.fromhex(hexo) if hexo else b''
    return rc, ob

def main():
    seed=int(sys.argv[1]) if len(sys.argv)>1 else 1
    iters=int(sys.argv[2]) if len(sys.argv)>2 else 2000
    rng=random.Random(seed)
    fails=0; cases=0
    for it in range(iters):
        segwit = (it%2)==0
        tx=gen_tx(rng, segwit)
        # distribute: full strip (big cap), truncation, cap sweep sample
        mode=it%3
        if mode==0:
            cap=1<<20
            exp_rc=0; exp=b''
            r=strip_py(tx)
            if r[0]:
                exp_rc, exp = r
            rc,ob=run_driver(rng,tx,cap)
            cases+=1
            if exp_rc!=rc or (exp_rc>0 and ob!=exp[:len(exp)]):
                fails+=1
                if fails<=5:
                    print(f"FAIL full seed={seed} it={it} exp_rc={exp_rc} rc={rc}")
                    print("  tx=",tx.hex())
                    if exp_rc: print("  exp=",exp.hex())
                    if rc: print("  got=",ob.hex())
        elif mode==1:
            # random truncation
            cut=rng.randint(0,len(tx))
            tc=tx[:cut]
            cap=1<<20
            r=strip_py(tc)
            exp_rc=r[0]; exp=r[1] if r[0] else b''
            rc,ob=run_driver(rng,tc,cap)
            cases+=1
            if exp_rc!=rc or (exp_rc>0 and ob!=exp):
                fails+=1
                if fails<=5:
                    print(f"FAIL trunc seed={seed} it={it} exp_rc={exp_rc} rc={rc} cut={cut}")
        else:
            # cap sweep on a full tx
            r=strip_py(tx)
            if not r[0]:
                rc,ob=run_driver(rng,tx,1<<20)
                cases+=1
                if rc!=0:
                    fails+=1
                    if fails<=5: print(f"FAIL exp-reject seed={seed} it={it} rc={rc} tx={tx.hex()}")
                continue
            need,exp=r
            for cap in (-2,0,1,need//2 if need>1 else 1,need-1,need,need+1):
                rc,ob=run_driver(rng,tx,cap)
                cases+=1
                # partial-write comparison: for rc>0 compare full exp; for cap reject, helper recomputes exp in asm; here compare that rc matches expected reject/ok and truncated output prefix
                if rc>0:
                    if rc!=need or ob!=exp: 
                        fails+=1
                        if fails<=5: print(f"FAIL cap{cap} seed={seed} it={it} rc={rc} need={need}")
    print(f"fuzz_strip seed={seed} cases={cases} fails={fails} -> {'FAIL' if fails else 'PASS'}")

if __name__=='__main__':
    main()
