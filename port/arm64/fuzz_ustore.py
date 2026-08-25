#!/usr/bin/env python3
"""Differential fuzzer for the persistent bitcoin_utxo_store.S: random
put/del/get/sync/reload in a scratch dir; compares t_ustore output vs an
independent Python dict oracle. After every reload the oracle EXPECTS the
current live dict (checkpoint + WAL-tail replay must reproduce the exact set)."""
import subprocess, sys, random, os, shutil

def key36(txid,idx): return txid+idx.to_bytes(4,'little')
def dumpstr(d,tag="D"):
    out=[f"{tag} {len(d)}"]
    for k in sorted(d):
        v,h,c,sl,scr=d[k]; out.append(f"{k.hex()} {v} {(h<<1)|c} {sl} {scr.hex()}")
    return out

def main():
    seed=int(sys.argv[1]); iters=int(sys.argv[2]); rng=random.Random(seed)
    SLOTS=512
    d={}; live=0
    lines=["init %d"%SLOTS]; exp=["init 1"]
    def iset(collide):
        txid=bytes(rng.randrange(256) for _ in range(32))
        if collide and rng.random()<0.5:
            txid=bytes([rng.randrange(256)])*4+bytes(rng.randrange(256) for _ in range(28))
        return txid
    for _ in range(iters):
        # reload points happen fairly often, esp after sync
        if rng.random()<0.06:
            lines.append("reload %d"%SLOTS); exp.append("reload"); exp.extend(dumpstr(d,"D"))
            continue
        if rng.random()<0.08:
            lines.append("sync"); exp.append("sync 1"); continue
        a=rng.choice(['put','put','put','get','get','del'])
        txid=iset(True); idx=rng.randrange(0,4); k=key36(txid,idx)
        if live>int(SLOTS*0.6) and a=='put': a='del'
        if a=='put':
            value=rng.getrandbits(60); h=rng.randrange(0,900000); cb=rng.randrange(0,2)
            scr=bytes(rng.randrange(256) for _ in range(rng.randrange(0,80)))
            lines.append("put %s %d %d %d %d %s"%(txid.hex(),idx,value,h,cb,scr.hex() if scr else '-'))
            if k in d: exp.append("put 0")
            else: d[k]=(value,h,cb,len(scr),scr); exp.append("put 1"); live+=1
            exp.extend(dumpstr(d,"D"))
        elif a=='get':
            lines.append("get %s %d"%(txid.hex(),idx))
            if k in d:
                v,h,c,sl,scr=d[k]; exp.append("get 1 %d %d %d %d %s"%(v,h,c,sl,scr.hex()))
            else: exp.append("get 0")
        else:
            lines.append("del %s %d"%(txid.hex(),idx))
            if k in d: del d[k]; live-=1; exp.append("del 1")
            else: exp.append("del 0")
            exp.extend(dumpstr(d,"D"))
    lines.append("sync"); exp.append("sync 1")
    lines.append("reload %d"%SLOTS); exp.append("reload"); exp.extend(dumpstr(d,"D"))
    lines.append("close"); exp.append("close")

    inp="\n".join(lines)+"\n"
    wd=f"/tmp/ustore_{seed}"; shutil.rmtree(wd,ignore_errors=True); os.makedirs(wd)
    open(wd+'/in.txt','w').write(inp)
    r=subprocess.run(['/home/svc/bitcoinmachinecode/port/arm64/t_ustore'],stdin=open(wd+'/in.txt'),
                      stdout=open(wd+'/out.txt','w'),cwd=wd)
    dev=[l for l in open(wd+'/out.txt').read().splitlines() if l.strip()]
    fails=0
    for i,(a,b) in enumerate(zip(dev,exp)):
        if a!=b:
            if fails<10:
                print(f"MISMATCH line {i}\n  dev : {a}\n  exp : {b}")
            fails+=1
    print(f"seed={seed} iters={iters} asm={len(dev)} exp={len(exp)} FAILS={fails} rc={r.returncode}")

if __name__=='__main__':
    main()
