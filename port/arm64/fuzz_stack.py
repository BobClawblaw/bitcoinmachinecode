#!/usr/bin/env python3
"""Differential fuzz for bitcoin_scriptcodec.S part 2: element-stack engine,
get_op, vfexec condition stack. Simulates the same ops in Python, compares the
full stdout transcript against the driver."""
import random, subprocess, sys, os

ELEM_SIZE=528

def make_cases(seed, iters):
    rng=random.Random(seed)
    lines=[]
    for _ in range(iters):
        k=rng.randrange(3)
        if k==0:
            # get_op: random script bytes (mostly valid, sometimes truncated)
            n=rng.randrange(1,120)
            code=[]
            i=0
            while i<n:
                op=rng.randrange(256)
                code.append(op); i+=1
                if op<=75 and op>0:            # direct push
                    pl=rng.randrange(0,min(op,40)+1)
                    code+=list(rng.randbytes(pl)); i+=pl
                elif op==0x4c and i<n:         # PUSHDATA1
                    pl=rng.randrange(0,50); code+=[pl]; i+=1
                    avail=n-i
                    if rng.random()<0.5 and pl<=avail:
                        code+=list(rng.randbytes(pl)); i+=pl
                    else:
                        break
                elif op==0x4d and i<n:         # PUSHDATA2
                    if i+2<=n:
                        pl=rng.randrange(0,min(700,300)); code+=list(pl.to_bytes(2,'little')); i+=2
                        avail=n-i
                        if rng.random()<0.5 and pl<=avail:
                            code+=list(rng.randbytes(pl)); i+=pl
                        else: break
                    else: break
                elif op==0x4e and i<n:         # PUSHDATA4
                    if i+4<=n:
                        pl=rng.randrange(0,300); code+=list(pl.to_bytes(4,'little')); i+=4
                        avail=n-i
                        if rng.random()<0.5 and pl<=avail:
                            code+=list(rng.randbytes(pl)); i+=pl
                        else: break
                    else: break
                else:
                    pass                        # plain opcode
                if i>=n: break
            script=bytes(code)
            lines.append("go "+script.hex())
        elif k==1:
            # vfexec sequence
            seq=''.join(rng.choice('10pTdaR') for _ in range(rng.randrange(1,14)))
            lines.append("vf "+seq)
        else:
            # stack sequence
            ops=['P','P','P','P','D','E','X','r','d','T','2','3','R','p']
            parts=['R']   # reset to deterministic state each line
            depth=0
            for _ in range(rng.randrange(3,26)):
                op=rng.choice(ops)
                if op=='P':
                    pl=rng.randrange(0,120); parts.append(f"P {(rng.randbytes(pl).hex() or '-')}"); depth+=1
                elif op=='D':
                    if depth>0:
                        idx=rng.randrange(0,depth); parts.append(f"D {idx}"); depth+=1
                elif op=='E':
                    if depth>0:
                        idx=rng.randrange(0,depth); parts.append(f"E {idx}"); depth-=1
                elif op=='X':
                    if depth>=2: parts.append("X")
                elif op=='r':
                    if depth>0: parts.append("r"); depth-=1
                elif op=='d': parts.append("d")
                elif op=='T':
                    if depth>=1: parts.append("T")
                elif op=='2':
                    if depth>=2: parts.append("2")
                elif op=='3':
                    if depth>=3: parts.append("3")
                elif op=='p':
                    if depth>0: parts.append(f"p {rng.randrange(0,depth)}")
                else: parts.append("R"); depth=0
            lines.append(' '.join(parts))
    return lines

def get_op_py(script, pc):
    if pc>=len(script): return None, None
    op=script[pc]; nxt=pc+1
    if op==0x4e:
        if nxt+4>len(script): return 0, None
        pl=int.from_bytes(script[nxt:nxt+4],'little'); nxt=nxt+4
        if nxt+pl>len(script): return 0,None
        return op+1, nxt+pl
    if op==0x4d:
        if nxt+2>len(script): return 0,None
        pl=int.from_bytes(script[nxt:nxt+2],'little'); nxt=nxt+2
        if nxt+pl>len(script): return 0,None
        return op+1, nxt+pl
    if op==0x4c:
        if nxt>=len(script): return 0,None
        pl=script[nxt]; nxt+=1
        if nxt+pl>len(script): return 0,None
        return op+1, nxt+pl
    if op<=0x4b:  # direct push 0..75 (includes OP_0)
        pl=op
        if nxt+pl>len(script): return 0,None
        return op+1, nxt+pl
    # plain opcode
    return op+1, nxt

class VF:
    def __init__(s): s.st=[]
    def run(s,seq):
        out=[]
        for c in seq:
            if c=='1': s.st.append(1)
            elif c=='0': s.st.append(0)
            elif c=='p': s.st=s.st[:-1]
            elif c=='T': s.st=s.st[:-1]+[1-s.st[-1]] if s.st else s.st
            elif c=='d': out.append("vdep=%d"%len(s.st))
            elif c=='a': out.append("vall=%d"%(1 if all(s.st) else 0))
            elif c=='R': s.st=[]
        return out

class Stack:
    def __init__(s): s.sp=0; s.elems={}
    def run(s,parts):
        out=[]
        i=0
        while i<len(parts):
            op=parts[i]
            if op=='R': s.sp=0; s.elems={}
            elif op=='P':
                hx=parts[i+1]; i+=1
                d=bytes.fromhex(hx) if hx!='-' else b''
                if s.sp>=1000: pass
                else: s.elems[s.sp]=d; s.sp+=1
            elif op=='D':
                idx=int(parts[i+1]); i+=1
                if s.sp>=1000: pass
                else:
                    s.elems[s.sp]=s.elems[idx]; s.sp+=1
            elif op=='E':
                idx=int(parts[i+1]); i+=1
                for j in range(idx,s.sp-1): s.elems[j]=s.elems[j+1]
                if s.sp>idx: s.elems.pop(s.sp-1,None); s.sp-=1
            elif op=='X':
                s.elems[s.sp-1],s.elems[s.sp-2]=s.elems[s.sp-2],s.elems[s.sp-1]
            elif op=='r':
                if s.sp>0: s.sp-=1; s.elems.pop(s.sp,None)
            elif op=='d': out.append("d=%d"%s.sp)
            elif op=='T': out.append("t:"+s.elems[s.sp-1].hex())
            elif op=='2': out.append("s2:"+s.elems[s.sp-2].hex())
            elif op=='3': out.append("s3:"+s.elems[s.sp-3].hex())
            elif op=='p':
                idx=int(parts[i+1]); i+=1
                # elem_ptr reads even if len==0 region; we only read valid idx
                out.append("pe%d:%s"%(idx,s.elems[idx].hex()))
            else:
                raise Exception("bad op "+op)
            i+=1
        return out

def main():
    seed=int(sys.argv[1]); iters=int(sys.argv[2])
    cases=make_cases(seed,iters)
    with open('/tmp/stack_cases.txt','w') as f: f.write('\n'.join(cases)+'\n')
    p=subprocess.run(['./t_stack','/tmp/stack_cases.txt'],capture_output=True,text=True)
    if p.returncode!=0: print("DRIVER FAIL",p.stderr); sys.exit(2)
    dev=p.stdout.splitlines()
    exp=[]
    for c in cases:
        if c.startswith('go '):
            script=bytes.fromhex(c[3:]); pc=0
            for _ in range(300):
                r,npc=get_op_py(script,pc)
                if r is None or r==0: exp.append('end'); break
                exp.append("op=%d pc=%d"%(r,npc)); pc=npc
        elif c.startswith('vf '):
            exp+=VF().run(c[3:].replace(' ',''))
        else:
            exp+=Stack().run(c.split(' '))
    # Since 'end' placement: driver prints end when get fails; python appends end then breaks too
    if len(dev)!=len(exp): print(f"LEN mismatch dev={len(dev)} exp={len(exp)}"); print("dev tail",dev[-5:]); print("exp tail",exp[-5:]); sys.exit(1)
    fails=0
    for i,(a,b) in enumerate(zip(dev,exp)):
        if a!=b:
            print(f"MISMATCH at {i}: dev={a!r} exp={b!r}")
            fails+=1
            if fails>12: break
    print(f"seed={seed} iters={iters} cases={len(cases)} transcript_lines={len(exp)} FAILS={fails}")
    sys.exit(1 if fails else 0)

if __name__=='__main__': main()
