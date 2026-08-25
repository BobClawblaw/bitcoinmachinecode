#!/usr/bin/env python3
"""Targeted differential fuzz: CHECKSIG/CHECKMULTISIG (ac/ad/ae/af), BASE
sigversion strip path ENABLED. Builds structurally-valid multisig stacks exactly
as interp_checkmultisig reads them: [.., dummy, sig1..sigm, m, pub1..pubn, n].
m/n are guaranteed small numeric encodings; ms>=1. Compares t_eval vs oracle."""
import subprocess, sys, random
import eval_oracle as O

def nbytes(v):
    b=bytearray(); neg=v<0; v=abs(v)
    while v>0: b.append(v&0xff); v>>=8
    if b and b[-1]&0x80: b.append(0x80 if neg else 0)
    elif neg: b[-1]|=0x80
    return bytes(b)

def main():
    seed=int(sys.argv[1]); iters=int(sys.argv[2]); rng=random.Random(seed)
    cases=[]
    for _ in range(iters):
        cstub = rng.choice(['0','1','1','1'])
        flags = rng.choice([0, 0, O.NULLDUMMY, O.NULLDUMMY|O.MINIMALDATA_F])
        sv = rng.choice([0,0,2])
        if rng.random()<0.6:
            nk = rng.randint(1,3); ms = rng.randint(1,nk)
            # dummy: empty unless we're explicitly testing NULLDUMMY violation
            if flags & O.NULLDUMMY and rng.random()<0.3:
                dummy = b'\x01'          # should trigger SIG_NULLDUMMY (oracle & asm agree)
            else:
                dummy = b''
            sigs=[]
            for i in range(ms):
                if rng.random()<0.85 or True: sigs.append(bytes([0x30,0x45,0x02,0x20]+[rng.getrandbits(8)&0xff]*32+[0x02,0x20]+[rng.getrandbits(8)&0xff]*32))
            keys=[bytes([rng.getrandbits(8)&0xff]*33) for _ in range(nk)]
            stack=[dummy]+sigs+[nbytes(ms)]+keys+[nbytes(nk)]
            op=rng.choice([0xae,0xae,0xae,0xaf])
        else:
            sig = (bytes([0x30,0x45,0x02,0x20]+[rng.getrandbits(8)&0xff]*32+[0x02,0x20]+[rng.getrandbits(8)&0xff]*32)
                   if rng.random()<0.85 else b'')
            pub = bytes([rng.getrandbits(8)&0xff]*33)
            stack=[sig,pub]
            op=rng.choice([0xac,0xac,0xac,0xad])
        stkstr=','.join(x.hex() if x else '-' for x in stack)
        cases.append(f"run {sv} {flags} 0 1 2 {cstub} {stkstr} {bytes([op]).hex()}")

    with open('/tmp/ev_cases.txt','w') as f: f.write('\n'.join(cases)+'\n')
    p=subprocess.run(['./t_eval'],stdin=open('/tmp/ev_cases.txt'),capture_output=True,text=True)
    dev=p.stdout.splitlines()
    fails=0; tot=0
    for i,c in enumerate(cases):
        toks=c.split()
        sv=int(toks[1]);flags=int(toks[2]);lt=int(toks[3]);seq=int(toks[4]);ver=int(toks[5]);cstub=toks[6]
        stk_hex=toks[7];scr=toks[8]
        stk=[bytes.fromhex(x) if x!='-' else b'' for x in stk_hex.split(',') if x!='']
        state={'flags':flags,'sv':sv,'locktime':lt,'seq':seq,'ver':ver,'cks':(cstub=='1')}
        err,Efinal,altf=O.eval_script(state, list(stk), [], bytes.fromhex(scr))
        ok=1 if err==O.OK else 0
        out=f"rc={ok} eo={err} d={len(Efinal)}"
        for j in range(min(len(Efinal),40)):
            out+=f" L{j}:{Efinal[j].hex() if Efinal[j] else ''}"
        if i>=len(dev): print("MISSING driver output case",i); fails+=1; continue
        if dev[i]!=out:
            if fails<15:
                print(f"MISMATCH case {i}\n  dev : {dev[i]}\n  exp : {out}\n  src : {c[:150]}")
            fails+=1
        tot+=1
    print(f"seed={seed} iters={iters} cases={tot} FAILS={fails}")

if __name__=='__main__':
    main()
