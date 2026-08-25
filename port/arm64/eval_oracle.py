#!/usr/bin/env python3
"""Pure-Python EvalScript mirror of the ported script_eval, for differential
verification (exact rc + final-stack equality vs asm driver). Uses the SAME
custom SCRIPT_ERR_* numbers as the asm. CHECKSIG uses a pluggable stub fn for
the plumbing test (real ECDSA verified separately)."""
import subprocess, sys, random, hashlib

OK=0; EVAL_FALSE=2; OP_RETURN=3; SCRIPTNUM=4; SCRIPT_SIZE=5; PUSH_SIZE=6
OP_COUNT=7; STACK_SIZE=8; SIG_COUNT=9; PUBKEY_COUNT=10; VERIFY=11
EQUALVERIFY=12; CHECKMULTISIGVERIFY=13; CHECKSIGVERIFY=14; NUMEQUALVERIFY=15
BAD_OPCODE=16; DISABLED=17; INV_STACK=18; INV_ALT=19; UNBAL=20; NEG_LOCK=21
UNSAT_LOCK=22; SIG_DER=24; MINIMALDATA=25; SIG_NULLDUMMY=28; CLEANSTACK=30
MINIMALIF=31; DISCOURAGE_SUCCESS=36; TAP_CMS=50; TAP_MINIMALIF=51
DERSIG=1<<2; NULLDUMMY=1<<4; MINIMALDATA_F=1<<6; CLTV_F=1<<9; CSV_F=1<<10
MINIMALIF_F=1<<13; DISCOURAGE_SUCCESS_F=1<<18
MAX_OPS=201; MAX_ELEM=520
DIS=[0x7e,0x7f,0x80,0x81,0x83,0x84,0x85,0x86,0x8d,0x8e,0x95,0x96,0x97,0x98,0x99]

def cnum(d, maxsize=4):
    if len(d)>maxsize: raise OverflowError
    v=0
    for i,b in enumerate(d): v|=b<<(8*i)
    if d and d[-1]&0x80:
        v &= ~(0x80<<(8*(len(d)-1))); v=-v
    return v

def encode_num(v):
    if v==0: return b''
    neg=v<0; v=abs(v); r=bytearray()
    while v: r.append(v&0xff); v>>=8
    if r[-1]&0x80: r.append(0x80 if neg else 0)
    elif neg: r[-1]|=0x80
    return bytes(r)

def tbool(d):
    """Core CastToBool: false iff all bytes are zero, OR a single final 0x80."""
    for i,b in enumerate(d):
        if b != 0:
            if not (i==len(d)-1 and b==0x80):
                return True
    return False

def is_success(op):
    return (op==80 or op==98 or (126<=op<=129) or (131<=op<=134) or
            (137<=op<=138) or (141<=op<=142) or (149<=op<=153) or (187<=op<=254))

class Reader:
    """get_op mirror: returns (opcode, pushlen, newpc); (0,None,pc) on fail."""
    def __init__(s,sc): s.sc=sc; s.L=len(sc)
    def next(s,pc):
        if pc>=s.L: return 0,None,pc
        op=s.sc[pc]; nxt=pc+1
        if op==0x4e:
            if nxt+4>s.L: return 0,None,pc
            pl=int.from_bytes(s.sc[nxt:nxt+4],'little'); nxt+=4
            if nxt+pl>s.L: return 0,None,pc
            return op,nxt+pl,pl
        if op==0x4d:
            if nxt+2>s.L: return 0,None,pc
            pl=int.from_bytes(s.sc[nxt:nxt+2],'little'); nxt+=2
            if nxt+pl>s.L: return 0,None,pc
            return op,nxt+pl,pl
        if op==0x4c:
            if nxt>=s.L: return 0,None,pc
            pl=s.sc[nxt]; nxt+=1
            if nxt+pl>s.L: return 0,None,pc
            return op,nxt+pl,pl
        if op<=0x4b:
            pl=op
            if nxt+pl>s.L: return 0,None,pc
            return op,nxt+pl,pl
        return op,nxt,0

def minpush(op,pushlen,data):
    if pushlen==0: return op==0
    if pushlen==1:
        b=data[0]
        if 1<=b<=16: return False
        if b==0x81: return False
        return op==1
    if pushlen<=75: return op==pushlen
    if pushlen<=255: return op==0x4c
    if pushlen<=65535: return op==0x4d
    return True

def eval_script(state, stk, alt, script):
    flags=state['flags']; sv=state['sv']
    vf=[]; pc=0; opcount=0
    R=Reader(script)
    # tapscript success prescan
    if sv==2:
        tpc=0
        while True:
            op,np,pl=R.next(tpc)
            if not op: break
            if is_success(op):
                return (DISCOURAGE_SUCCESS if flags&DISCOURAGE_SUCCESS_F else OK), stk, alt
            tpc=np
    while True:
        op,np,pl=R.next(pc)
        if not op: break
        opcode=op; pushlen=pl
        if pushlen is None or pushlen>MAX_ELEM: return PUSH_SIZE, stk, alt
        fExec = all(vf)
        if sv!=2 and opcode>0x60:
            opcount+=1
            if opcount>MAX_OPS: return OP_COUNT, stk, alt
        if opcode in DIS: return DISABLED, stk, alt
        if opcode<=0x4e:
            if not fExec: pc=np; continue
            data=script[np-pushlen:np]
            if flags&MINIMALDATA_F and not minpush(opcode,pushlen,data):
                return MINIMALDATA, stk, alt
            if len(stk)>=1000: return STACK_SIZE, stk, alt
            stk.append(data); pc=np; continue
        if not fExec and not (0x63<=opcode<=0x68):
            pc=np; continue
        E=stk
        if opcode==0x4f:
            if len(E)>=1000:return STACK_SIZE,E,alt
            E.append(encode_num(-1))
        elif 0x51<=opcode<=0x60:
            if len(E)>=1000:return STACK_SIZE,E,alt
            E.append(encode_num(opcode-0x50))
        elif opcode==0x61: pass
        elif opcode in (0x63,0x64):
            if not fExec: vf.append(0)
            else:
                if len(E)<1: return INV_STACK,E,alt
                top=E[-1]
                if sv==2:
                    if len(top)>=2 or (len(top)==1 and top[0]!=1): return TAP_MINIMALIF,E,alt
                elif sv==1 and (flags&MINIMALIF_F):
                    if len(top)>=2 or (len(top)==1 and top[0]!=1): return MINIMALIF,E,alt
                v=1 if tbool(top) else 0
                if opcode==0x64: v^=1
                E.pop(); vf.append(v)
        elif opcode==0x67:
            if not vf: return UNBAL,E,alt
            vf[-1]^=1
        elif opcode==0x68:
            if not vf: return UNBAL,E,alt
            vf.pop()
        elif opcode==0x69:
            if not E: return INV_STACK,E,alt
            if not tbool(E[-1]): return VERIFY,E,alt
            E.pop()
        elif opcode==0x6a: return OP_RETURN,E,alt
        elif opcode==0x6b:
            if not E: return INV_STACK,E,alt
            alt.append(E.pop())
        elif opcode==0x6c:
            if not alt: return INV_ALT,E,alt
            if len(E)>=1000:return STACK_SIZE,E,alt
            E.append(alt.pop())
        elif opcode==0x6d:
            if len(E)<2: return INV_STACK,E,alt
            E.pop();E.pop()
        elif opcode==0x6e:
            if len(E)<2: return INV_STACK,E,alt
            E+=[E[-2],E[-1]]
        elif opcode==0x6f:
            if len(E)<3: return INV_STACK,E,alt
            E+=[E[-3],E[-2],E[-1]]
        elif opcode==0x70:
            if len(E)<4: return INV_STACK,E,alt
            E+=[E[-4],E[-3]]
        elif opcode==0x71:
            if len(E)<6: return INV_STACK,E,alt
            i1=len(E)-6; i2=len(E)-5
            x1=E[i1]; x2=E[i2]
            del E[i2]
            del E[i1]
            E += [x1,x2]
        elif opcode==0x72:
            if len(E)<4: return INV_STACK,E,alt
            E[-4],E[-2]=E[-2],E[-4]; E[-3],E[-1]=E[-1],E[-3]
        elif opcode==0x73:
            if len(E)<1: return INV_STACK,E,alt
            if tbool(E[-1]): E.append(E[-1])
        elif opcode==0x74:
            if len(E)>=1000:return STACK_SIZE,E,alt
            E.append(encode_num(len(E)))
        elif opcode==0x75:
            if len(E)<1: return INV_STACK,E,alt
            E.pop()
        elif opcode==0x76:
            if len(E)<1: return INV_STACK,E,alt
            E.append(E[-1])
        elif opcode==0x77:
            if len(E)<2: return INV_STACK,E,alt
            del E[-2]
        elif opcode==0x78:
            if len(E)<2: return INV_STACK,E,alt
            E.append(E[-2])
        elif opcode in (0x79,0x7a):
            if len(E)<2: return INV_STACK,E,alt
            n=cnum(E[-1],4); E.pop()
            if n<0 or n>=len(E): return INV_STACK,E,alt
            v=E[-(1+n)]
            if opcode==0x7a:
                del E[-(1+n)]; E.append(v)
            else: E.append(v)
        elif opcode==0x7b:
            if len(E)<3: return INV_STACK,E,alt
            E[-3],E[-2]=E[-2],E[-3]; E[-2],E[-1]=E[-1],E[-2]
        elif opcode==0x7c:
            if len(E)<2: return INV_STACK,E,alt
            E[-1],E[-2]=E[-2],E[-1]
        elif opcode==0x7d:
            if len(E)<2: return INV_STACK,E,alt
            x2=E[-1];x1=E[-2];E.pop();E.pop();E+=[x2,x1,x2]
        elif opcode==0x82:
            if len(E)<1: return INV_STACK,E,alt
            E.append(encode_num(len(E[-1])))
        elif opcode in (0x87,0x88):
            if len(E)<2: return INV_STACK,E,alt
            b=1 if E[-1]==E[-2] else 0
            E.pop();E.pop()
            if len(E)>=1000:return STACK_SIZE,E,alt
            E.append(encode_num(1) if b else b'')
            if opcode==0x88:
                if not tbool(E[-1]): return EQUALVERIFY,E,alt
                E.pop()
        elif 0x8b<=opcode<=0x92:
            if len(E)<1: return INV_STACK,E,alt
            try: v=cnum(E[-1],4)
            except OverflowError: return SCRIPTNUM,E,alt
            if opcode==0x8b:v+=1
            elif opcode==0x8c:v-=1
            elif opcode==0x8f:v=-v
            elif opcode==0x90:v=abs(v)
            elif opcode==0x91:v=0 if v!=0 else 1
            elif opcode==0x92:v=1 if v!=0 else 0
            E.pop(); E.append(encode_num(v))
        elif 0x93<=opcode<=0xa4:
            if len(E)<2: return INV_STACK,E,alt
            try:
                a=cnum(E[-2],4); b=cnum(E[-1],4)
            except OverflowError: return SCRIPTNUM,E,alt
            if opcode==0x93:r=a+b
            elif opcode==0x94:r=a-b
            elif opcode==0x9a:r=1 if(a!=0 and b!=0)else 0
            elif opcode==0x9b:r=1 if(a!=0 or b!=0)else 0
            elif opcode in(0x9c,0x9d):r=1 if a==b else 0
            elif opcode==0x9e:r=1 if a!=b else 0
            elif opcode==0x9f:r=1 if a<b else 0
            elif opcode==0xa0:r=1 if a>b else 0
            elif opcode==0xa1:r=1 if a<=b else 0
            elif opcode==0xa2:r=1 if a>=b else 0
            elif opcode==0xa3:r=min(a,b)
            elif opcode==0xa4:r=max(a,b)
            E.pop();E.pop()
            if r!=0 and encode_num(r)==b'':
                pass
            E.append(encode_num(r))
            if opcode==0x9d:
                if not tbool(E[-1]): return NUMEQUALVERIFY,E,alt
                E.pop()
        elif opcode==0xa5:
            if len(E)<3: return INV_STACK,E,alt
            try: val=cnum(E[-3],4);mn=cnum(E[-2],4);mx=cnum(E[-1],4)
            except OverflowError: return SCRIPTNUM,E,alt
            E.pop();E.pop();E.pop()
            E.append(encode_num(1) if (mn<=val<mx) else b'')
        elif 0xa6<=opcode<=0xaa:
            if len(E)<1: return INV_STACK,E,alt
            d=E[-1]
            if opcode==0xa8:out=hashlib.sha256(d).digest()
            elif opcode==0xa7:out=hashlib.sha1(d).digest()
            elif opcode==0xa6:out=hashlib.new('ripemd160',d).digest()
            elif opcode==0xa9:out=hashlib.new('ripemd160',hashlib.sha256(d).digest()).digest()
            else:out=hashlib.sha256(hashlib.sha256(d).digest()).digest()
            E.pop();E.append(out)
        elif opcode==0xab: pass
        elif opcode in (0xac,0xad):
            if len(E)<2: return INV_STACK,E,alt
            sig=E[-2];pub=E[-1]
            ok=1 if (len(sig)>0 and state.get('cks')) else 0
            E.pop();E.pop();E.append(encode_num(ok))
            if opcode==0xad:
                if not tbool(E[-1]): return CHECKSIGVERIFY,E,alt
                E.pop()
        elif opcode in (0xae,0xaf):
            if sv==2: return TAP_CMS,E,alt
            rc2,err=multisig(state,E,flags)
            if rc2!=0: return err,E,alt
            if opcode==0xaf:
                if len(E)<1: return INV_STACK,E,alt
                if not tbool(E[-1]): return CHECKMULTISIGVERIFY,E,alt
                E.pop()
        elif opcode==0xb1:
            if flags&CLTV_F:
                if len(E)<1: return INV_STACK,E,alt
                t=cnum(E[-1],5)
                if t<0: return NEG_LOCK,E,alt
                if (t>=500000000)!=(state['locktime']>=500000000): return UNSAT_LOCK,E,alt
                if t>state['locktime']: return UNSAT_LOCK,E,alt
                if state['seq']==0xffffffff: return UNSAT_LOCK,E,alt
        elif opcode==0xb2:
            if flags&CSV_F:
                if len(E)<1: return INV_STACK,E,alt
                t=cnum(E[-1],5)
                if t<0: return NEG_LOCK,E,alt
                if not (t&0x80000000):
                    if state['ver']<2: return UNSAT_LOCK,E,alt
                    if state['seq']&0x80000000: return UNSAT_LOCK,E,alt
                    tf=0x00400000; sm=t&0x0040ffff; tm=state['seq']&0x0040ffff
                    if (sm>=tf)!=(tm>=tf): return UNSAT_LOCK,E,alt
                    if sm>tm: return UNSAT_LOCK,E,alt
        elif opcode==0xba:
            return BAD_OPCODE,E,alt   # without taproot checksig plumbing, NOP-blocked
        else:
            # NOPs 0xb0,b3..b9 and reserved NOP range -> no-op
            if opcode in (0xb0,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9): pass
            else: return BAD_OPCODE,E,alt
        pc=np
    if vf: return UNBAL,E,alt
    if sv==2:
        if len(E)!=1: return CLEANSTACK,E,alt
        if not tbool(E[-1]): return EVAL_FALSE,E,alt
    return OK,E,alt

def multisig(state,E,flags):
    nk=cnum(E[-1],4)
    if nk<0 or nk>20: return 1,PUBKEY_COUNT
    ms=cnum(E[-1-(nk+1)] if len(E)>nk+1 else b'',4)
    if ms<0 or ms>nk: return 1,SIG_COUNT
    need=nk+ms+2
    if len(E)<need+1: return 1,INV_STACK
    if flags&NULLDUMMY and E[0]!=b'': return 1,SIG_NULLDUMMY
    sigs=[E[i] for i in range(need-ms,need)]
    keys=[E[i] for i in range(1,1+nk)]
    isig=0;ikey=0;rem=ms
    while rem>0 and ikey<nk:
        ok=1 if (len(sigs[isig])>0 and state.get('cks')) else 0
        if ok: isig+=1;rem-=1
        ikey+=1
        if rem>(nk-ikey):
            del E[-(need+1):];E.append(b'');return 0,0
    if rem!=0:
        del E[-(need+1):];E.append(b'');return 0,0
    del E[-(need+1):];E.append(encode_num(1));return 0,0

def fmt(E):
    parts=[f"rc={0}"]
    return parts

def main():
    seed=int(sys.argv[1]); iters=int(sys.argv[2]); rng=random.Random(seed)
    cases=make_cases(rng,iters)
    with open('/tmp/ev_cases.txt','w') as f: f.write('\n'.join(cases)+'\n')
    p=subprocess.run(['./t_eval'],stdin=open('/tmp/ev_cases.txt'),capture_output=True,text=True)
    dev=p.stdout.splitlines()
    fails=0; tot=0; rej=0
    for i,c in enumerate(cases):
        toks=c.split()
        if len(toks)<9: continue
        sv=int(toks[1]);flags=int(toks[2]);lt=int(toks[3]);seq=int(toks[4]);ver=int(toks[5]);cstub=toks[6]
        stk_hex=toks[7];scr=toks[8]
        if stk_hex=='--': stk=[]
        else: stk=[bytes.fromhex(x) if x!='-' else b'' for x in stk_hex.split(',') if x!='']
        state={'flags':flags,'sv':sv,'locktime':lt,'seq':seq,'ver':ver,'cks':(cstub=='1')}
        err,Efinal,altf=eval_script(state, list(stk), [], bytes.fromhex(scr))
        # asm prints rc=<err> d=<depth> L<i>:<hex> for first 40
        ok=1 if err==OK else 0
        out=f"rc={ok} eo={err} d={len(Efinal)}"
        for j in range(min(len(Efinal),40)):
            out+=f" L{j}:{Efinal[j].hex() if Efinal[j] else ''}"
        expected=out
        if i>=len(dev):
            print("MISSING driver output for case",i); fails+=1; continue
        if dev[i]!=expected:
            if fails<15:
                print(f"MISMATCH case {i}\n  dev : {dev[i]}\n  exp : {expected}\n  src : {c[:110]}")
            fails+=1
        tot+=1
    print(f"seed={seed} iters={iters} cases={tot} FAILS={fails}")

def make_cases(rng,iters):
    lines=[]
    for _ in range(iters):
        sv=rng.choice([0,2])
        flags=rng.choice([0,MINIMALDATA_F,MINIMALDATA_F|NULLDUMMY,CLTV_F,CSV_F,CLTV_F|CSV_F])
        lt=rng.choice([0,499999999,500000000,600000000,0x5f5e100])
        seq=rng.choice([0,1,0xfffffffe,0xffffffff])
        ver=rng.choice([1,2,3])
        cstub='0'
        nops=rng.randrange(1,12)
        ops=['6b','6c','6d','6e','6f','70','71','72','73','74','75','76','77','78',
             '7b','7c','7d','82','87','8b','8c','8f','90','91','92',
             '93','94','9a','9b','9c','9d','9e','9f','a0','a1','a2','a3','a4','a5',
             'a6','a7','a8','a9','aa','63','67','68','69','6a','4f','51','52','55','5f','60']
        script=bytearray()
        for _ in range(nops):
            o=rng.choice(ops)
            if o=='6a':
                script.append(0x6a)
                break
            script.append(int(o,16))
        pre=[]
        # preload stack: careful — generated stack must not crash under real scripts
        for _ in range(rng.randrange(0,4)):
            pre.append(rng.randbytes(rng.randrange(1,9)))
        stkstr=(','.join(x.hex() if x else '-' for x in pre)) if pre else '--'
        rlt=lt; rseq=seq
        # choose locktime/seq relevant if CLTV/CSV flag to exercise pass/fail
        if flags&CLTV_F: rlt=rng.choice([0,1,10,1000000,499999999,500000000,600000000])
        if flags&CSV_F: rseq=rng.choice([0,1,0x40,0x00400000,0x00500000])
        lines.append(f"run {sv} {flags} {rlt} {rseq} {ver} {cstub} {stkstr} {script.hex()}")
    return lines

if __name__=='__main__':
    main()
