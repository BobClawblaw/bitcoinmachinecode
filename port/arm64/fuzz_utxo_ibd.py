#!/usr/bin/env python3
"""IBD-style structural differential for bitcoin_utxo.S.

Mimics how ibd.c drives the UTXO, which the original random fuzz did NOT:
 - transactions each have 1..8 outputs at CONSECUTIVE indices (same txid, idx 0..n-1)
 - real scripts: P2PKH (25B -> 76a914+h20+88ac), P2PK (67B -> 41+pubkey65+ac),
   or a 0..40B arbitrary script (OP_RETURN-ish), rarely empty
 - a "block" = put outputs of a tx, then spend (del) some older prevouts in the
   next block -> interleaved put/del
 - verified at every mutating op by a FULL sorted-set walk dump (exact equality
   of key/value/code/slen/script), exactly like fuzz_utxo.py
 - load driven up to ~60% like the real run
"""
import subprocess, sys, random

def key36(txid,idx):
    return txid + idx.to_bytes(4,'little')

def dumpstr(d,tag="D"):
    out=["%s %d"%(tag,len(d))]
    for k in sorted(d):
        v,h,c,sl,scr=d[k]
        out.append("%s %d %d %d %s"%(k.hex(),v,(h<<1)|c,sl,scr.hex()))
    return out

def mk_script(rng):
    r=rng.random()
    if r<0.40:
        return bytes.fromhex("76a914")+bytes(rng.randrange(256) for _ in range(20))+bytes.fromhex("88ac")
    if r<0.65:
        return bytes.fromhex("41")+bytes([4])+bytes(rng.randrange(256) for _ in range(64))+bytes.fromhex("ac")
    if r<0.95:
        return bytes([rng.randrange(0x01,0x30)])+bytes(rng.randrange(256) for _ in range(rng.randrange(1,40)))
    return b""

def main():
    seed=int(sys.argv[1]); iters=int(sys.argv[2]); rng=random.Random(seed)
    SLOTS=1024
    lines=["init %d"%SLOTS]
    dict_t={}
    expected=["init ok"]
    live=0
    # txs: dict txid -> list of output records currently live (idx,value,height,cb,script)
    for _ in range(iters):
        action=rng.choice(['block','block','block','spend','walk','get'])
        if live>int(SLOTS*0.62) and action=='block' and rng.random()<0.7:
            action='spend'
        if action=='block':
            txid=bytes(rng.randrange(256) for _ in range(32))
            nout=rng.randrange(1,9)
            h=rng.randrange(0,900000)
            for idx in range(nout):
                k=key36(txid,idx)
                if k in dict_t:  # collision with existing live key: skip (shouldn't normally happen)
                    break
                value=rng.getrandbits(58); cb=1 if rng.random()<0.15 else 0
                scr=mk_script(rng)
                lines.append("put %s %d %d %d %d %s"%(txid.hex(),idx,value,h,cb,scr.hex() if scr else '-'))
                dict_t[k]=(value,h,cb,len(scr),scr); live+=1
                expected.append("put 1"); expected.extend(dumpstr(dict_t,"D"))
        elif action=='spend':
            # pick up to 3 random live keys and del them (partial spends, like next block)
            keys=list(dict_t.keys())
            if not keys: continue
            rng.shuffle(keys)
            for k in keys[:3]:
                lines.append("del %s %d"%(k[:32].hex(),int.from_bytes(k[32:36],'little')))
                del dict_t[k]; live-=1
                expected.append("del 1"); expected.extend(dumpstr(dict_t,"D"))
        elif action=='get':
            if not dict_t: continue
            k=random.choice(list(dict_t.keys()))
            txid,idx=k[:32],int.from_bytes(k[32:36],'little')
            lines.append("get %s %d"%(txid.hex(),idx))
            v,h,c,sl,scr=dict_t[k]
            expected.append("get 1 %d %d %d %d %s"%(v,h,c,sl,scr.hex()))
        else: # walk
            lines.append("walk"); expected.extend(dumpstr(dict_t,"walk"))
    lines.append("count"); expected.append("count %d"%live)

    inp="\n".join(lines)+"\n"
    open('/tmp/utxo_ibd_in.txt','w').write(inp)
    with open('/tmp/utxo_ibd_out.txt','w') as f:
        r=subprocess.run(['./t_utxo'],stdin=open('/tmp/utxo_ibd_in.txt'),stdout=f)
    dev=[l for l in open('/tmp/utxo_ibd_out.txt').read().splitlines() if l.strip()]
    exp=[l for l in expected if l.strip()]
    fails=0
    for i,(a,b) in enumerate(zip(dev,exp)):
        if a!=b:
            if fails<8:
                print("MISMATCH line %d\n  dev : %s\n  exp : %s"%(i,a,b))
            fails+=1
    print("seed=%d iters=%d dev=%d exp=%d FAILS=%d rc=%d"%(seed,iters,len(dev),len(exp),fails,r.returncode))

if __name__=='__main__': main()
