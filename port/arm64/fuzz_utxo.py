#!/usr/bin/env python3
"""Differential fuzzer for bitcoin_utxo.S using FILE-based I/O (pipes truncate
at this volume). Compares t_utxo output vs an independent Python dict oracle.
Each mutating op yields a full sorted walk dump (D/walk) so exact set equality
(keys, value, height/is_coinbase code, slen, script) is verified at every step."""
import subprocess, sys, random, os

def key36(txid,idx):
    return txid + idx.to_bytes(4,'little')

def dumpstr(d,tag="D"):
    out=["%s %d"%(tag,len(d))]
    for k in sorted(d):
        v,h,c,sl,scr=d[k]
        out.append("%s %d %d %d %s"%(k.hex(),v,(h<<1)|c,sl,scr.hex()))
    return out

def main():
    seed=int(sys.argv[1]); iters=int(sys.argv[2]); rng=random.Random(seed)
    SLOTS=512
    lines=["init %d"%SLOTS]
    dict_t={}
    expected=["init ok"]
    live=0
    for _ in range(iters):
        action=rng.choice(['put','put','put','get','get','del','walk'])
        txid=bytes(rng.randrange(256) for _ in range(32))
        if rng.random()<0.6:
            txid=bytes([rng.randrange(256)])*4 + bytes(rng.randrange(256) for _ in range(28))
        idx=rng.randrange(0,4)
        k=key36(txid,idx)
        if live>int(SLOTS*0.6) and action=='put': action='del'
        if action=='put':
            value=rng.getrandbits(60); height=rng.randrange(0,900000); cb=rng.randrange(0,2)
            scr=bytes(rng.randrange(256) for _ in range(rng.randrange(0,80)))
            lines.append("put %s %d %d %d %d %s"%(txid.hex(),idx,value,height,cb,scr.hex() if scr else '-'))
            if k in dict_t:
                expected.append("put 0")
            else:
                dict_t[k]=(value,height,cb,len(scr),scr); expected.append("put 1"); live+=1
            expected.extend(dumpstr(dict_t,"D"))
        elif action=='get':
            lines.append("get %s %d"%(txid.hex(),idx))
            if k in dict_t:
                v,h,c,sl,scr=dict_t[k]
                expected.append("get 1 %d %d %d %d %s"%(v,h,c,sl,scr.hex()))
            else:
                expected.append("get 0")
        elif action=='del':
            lines.append("del %s %d"%(txid.hex(),idx))
            if k in dict_t:
                del dict_t[k]; live-=1; expected.append("del 1")
            else:
                expected.append("del 0")
            expected.extend(dumpstr(dict_t,"D"))
        else: # walk
            lines.append("walk")
            expected.extend(dumpstr(dict_t,"walk"))
    lines.append("count"); expected.append("count %d"%live)

    inp="\n".join(lines)+"\n"
    open('/tmp/utxo_in.txt','w').write(inp)
    with open('/tmp/utxo_out.txt','w') as f:
        r=subprocess.run(['./t_utxo'],stdin=open('/tmp/utxo_in.txt'),stdout=f)
    dev=[l for l in open('/tmp/utxo_out.txt').read().splitlines() if l.strip()]
    exp=[l for l in expected if l.strip()]
    fails=0
    for i,(a,b) in enumerate(zip(dev,exp)):
        if a!=b:
            if fails<12:
                print("MISMATCH line %d\n  dev : %s\n  exp : %s"%(i,a,b))
            fails+=1
    dif=len(dev)-len(exp)
    print("seed=%d iters=%d asmlines=%d exp=%d FAILS=%d len-diff=%d rc=%d"%(
        seed,iters,len(dev),len(exp),fails,dif,r.returncode))

if __name__=='__main__':
    main()
