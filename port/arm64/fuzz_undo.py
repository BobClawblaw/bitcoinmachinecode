#!/usr/bin/env python3
"""Differential fuzz for bitcoin_undo.S vs the C oracle asm/daemon/undo_log.c.
Runs identical op streams in two fresh scratch dirs (one per binary) and diffs
byte-for-byte. Covers append/load/strict+tolerant replay/discard/prune with
random txids/values/scripts incl empty scripts and absent files."""
import random, subprocess, sys, os, shutil

def main():
    seed=int(sys.argv[1]); iters=int(sys.argv[2]); rng=random.Random(seed)
    lines=[]
    for _ in range(iters):
        a=rng.choice(['ap','ap','ap','ld','rp','rpt','dc','pf','pr'])
        if a=='ap':
            h=rng.randrange(-1,40)
            txid=bytes(rng.randrange(256) for _ in range(32)).hex()
            idx=rng.randrange(0,4); value=rng.getrandbits(55); uh=rng.randrange(0,900000)
            cb=rng.randrange(0,2)
            if rng.random()<0.1: script='-'
            else: script=bytes(rng.randrange(256) for _ in range(rng.choice([0,1,2,4,25,80,1000,3000]))).hex()
            lines.append(f"ap {h} {txid} {idx} {value} {uh} {cb} {script}")
        elif a=='ld':
            lines.append(f"ld {rng.randrange(-1,40)} {rng.choice([1,2,5,50])}")
        elif a=='rp':
            lines.append(f"rp {rng.randrange(-1,40)}")
        elif a=='rpt':
            lines.append(f"rpt {rng.randrange(-1,40)}")
        elif a=='dc':
            lines.append(f"dc {rng.randrange(-1,40)}")
        elif a=='pf':
            lines.append(f"pf {rng.randrange(0,30)} {rng.randrange(0,40)} {rng.choice([0,1,5,20])} {rng.randrange(0,40)}")
        else:
            lines.append(f"pr {rng.randrange(0,40)} {rng.choice([0,1,5,20])}")
    inp="\n".join(lines)+"\n"
    base="/home/svc/bitcoinmachinecode/port/arm64"
    out=[]
    for name in ["t_undo_asm","t_undo_c"]:
        wd=f"/tmp/undo_{seed}_{name}"; shutil.rmtree(wd,ignore_errors=True); os.makedirs(wd)
        open(wd+"/in.txt","w").write(inp)
        r=subprocess.run([f"{base}/{name}"],stdin=open(wd+"/in.txt"),stdout=open(wd+"/out.txt","w"),cwd=wd)
        out.append((name,[l for l in open(wd+"/out.txt","rb").read().splitlines() if l.strip()],r.returncode))
    a=out[0]; b=out[1]
    fails=0
    for i in range(max(len(a[1]),len(b[1]))):
        la=a[1][i] if i<len(a[1]) else b"<missing>"
        lb=b[1][i] if i<len(b[1]) else b"<missing>"
        if la!=lb:
            if fails<10: print(f"MISMATCH line {i}\n  asm: {la[:80]}\n  c  : {lb[:80]}")
            fails+=1
    print(f"seed={seed} iters={iters} asm_lines={len(a[1])} c_lines={len(b[1])} rc=({a[2]},{b[2]}) FAILS={fails}")

if __name__=='__main__':
    main()
