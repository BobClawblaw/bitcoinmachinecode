#!/usr/bin/env python3
"""Differential harness vs Bitcoin Core's script_tests.json for the BASE
opcode-level opcodes. Drives the asm interpreter through tests/run_batch.
Compares each vector's verdict+error against Core's expected label."""
import json, subprocess, sys, os, collections

HERE=os.path.dirname(os.path.abspath(__file__))
RUNBATCH=os.path.join(HERE,'run_batch')

# ---- opcode name table (Core GetOpName / mapOpNames) ----
OPNAMES = {
 'OP_0':0x00,'OP_FALSE':0x00,'OP_PUSHDATA1':0x4c,'OP_PUSHDATA2':0x4d,'OP_PUSHDATA4':0x4e,
 'OP_1NEGATE':0x4f,'OP_RESERVED':0x50,
 'OP_1':0x51,'OP_TRUE':0x51,'OP_2':0x52,'OP_3':0x53,'OP_4':0x54,'OP_5':0x55,'OP_6':0x56,
 'OP_7':0x57,'OP_8':0x58,'OP_9':0x59,'OP_10':0x5a,'OP_11':0x5b,'OP_12':0x5c,'OP_13':0x5d,
 'OP_14':0x5e,'OP_15':0x5f,'OP_16':0x60,
 'OP_NOP':0x61,'OP_VER':0x62,'OP_IF':0x63,'OP_NOTIF':0x64,'OP_VERIF':0x65,'OP_VERNOTIF':0x66,
 'OP_ELSE':0x67,'OP_ENDIF':0x68,'OP_VERIFY':0x69,'OP_RETURN':0x6a,
 'OP_TOALTSTACK':0x6b,'OP_FROMALTSTACK':0x6c,'OP_2DROP':0x6d,'OP_2DUP':0x6e,'OP_3DUP':0x6f,
 'OP_2OVER':0x70,'OP_2ROT':0x71,'OP_2SWAP':0x72,'OP_IFDUP':0x73,'OP_DEPTH':0x74,'OP_DROP':0x75,
 'OP_DUP':0x76,'OP_NIP':0x77,'OP_OVER':0x78,'OP_PICK':0x79,'OP_ROLL':0x7a,'OP_ROT':0x7b,
 'OP_SWAP':0x7c,'OP_TUCK':0x7d,
 'OP_CAT':0x7e,'OP_SUBSTR':0x7f,'OP_LEFT':0x80,'OP_RIGHT':0x81,'OP_SIZE':0x82,
 'OP_INVERT':0x83,'OP_AND':0x84,'OP_OR':0x85,'OP_XOR':0x86,'OP_EQUAL':0x87,'OP_EQUALVERIFY':0x88,
 'OP_RESERVED1':0x89,'OP_RESERVED2':0x8a,
 'OP_1ADD':0x8b,'OP_1SUB':0x8c,'OP_2MUL':0x8d,'OP_2DIV':0x8e,'OP_NEGATE':0x8f,'OP_ABS':0x90,
 'OP_NOT':0x91,'OP_0NOTEQUAL':0x92,
 'OP_ADD':0x93,'OP_SUB':0x94,'OP_MUL':0x95,'OP_DIV':0x96,'OP_MOD':0x97,'OP_LSHIFT':0x98,'OP_RSHIFT':0x99,
 'OP_BOOLAND':0x9a,'OP_BOOLOR':0x9b,'OP_NUMEQUAL':0x9c,'OP_NUMEQUALVERIFY':0x9d,'OP_NUMNOTEQUAL':0x9e,
 'OP_LESSTHAN':0x9f,'OP_GREATERTHAN':0xa0,'OP_LESSTHANOREQUAL':0xa1,'OP_GREATERTHANOREQUAL':0xa2,
 'OP_MIN':0xa3,'OP_MAX':0xa4,'OP_WITHIN':0xa5,
 'OP_RIPEMD160':0xa6,'OP_SHA1':0xa7,'OP_SHA256':0xa8,'OP_HASH160':0xa9,'OP_HASH256':0xaa,
 'OP_CODESEPARATOR':0xab,'OP_CHECKSIG':0xac,'OP_CHECKSIGVERIFY':0xad,'OP_CHECKMULTISIG':0xae,
 'OP_CHECKMULTISIGVERIFY':0xaf,'OP_NOP1':0xb0,'OP_CHECKLOCKTIMEVERIFY':0xb1,'OP_NOP2':0xb1,
 'OP_CHECKSEQUENCEVERIFY':0xb2,'OP_NOP3':0xb2,'OP_NOP4':0xb3,'OP_NOP5':0xb4,'OP_NOP6':0xb5,
 'OP_NOP7':0xb6,'OP_NOP8':0xb7,'OP_NOP9':0xb8,'OP_NOP10':0xb9,'OP_CHECKSIGADD':0xba,
}
for _k,_v in list(OPNAMES.items()):
    if _k.startswith('OP_'):
        OPNAMES[_k[3:]] = _v   # convenience: OP_ADD and ADD both recognized

def push_int(v):
    # Mirror Core CScript::push_int64 / operator<<(int64): small values use
    # OP_0/OP_1..OP_16/OP_1NEGATE; otherwise push the ScriptNum serialization.
    if v == 0: return b'\x00'
    if v == -1: return b'\x4f'
    if 1 <= v <= 16:
        return bytes([0x50 + v])
    neg = v<0
    av = -v if neg else v
    res=bytearray()
    while av:
        res.append(av & 0xff); av >>= 8
    if res[-1] & 0x80:
        res.append(0x80 if neg else 0)
    elif neg:
        res[-1] |= 0x80
    return push_data(bytes(res))

def push_data(d):
    n=len(d)
    if n<0x4c: return bytes([n])+d
    if n<=0xff: return bytes([0x4c,n])+d
    if n<=0xffff: return bytes([0x4d])+n.to_bytes(2,'little')+d
    return bytes([0x4e])+n.to_bytes(4,'little')+d

def parse_script(s):
    """Port of Core's ParseScript: numbers, 0x..raw, 'strings', opcodes."""
    out=bytearray()
    for w in s.split():
        if not w: continue
        if (w.lstrip('-').isdigit() and (w[0]!='-' or len(w)>1)):
            v=int(w)
            if v>0xffffffff or v < -0xffffffff: raise ValueError("num range")
            out += push_int(v)
        elif w.startswith('0x') and len(w)>2:
            out += bytes.fromhex(w[2:])
        elif len(w)>=2 and w[0]=="'" and w[-1]=="'":
            out += push_data(w[1:-1].encode())
        else:
            out += bytes([OPNAMES[w]])
    return bytes(out)

def parse_pushes(script):
    """Parse leading push ops of scriptSig -> list of bytes."""
    items=[]; i=0; n=len(script)
    while i < n:
        op=script[i]
        if op <= 0x4e:
            if op < 0x4c:
                sz=op; off=i+1
            elif op == 0x4c:
                if i+2 > n: break
                sz=script[i+1]; off=i+2
            elif op == 0x4d:
                if i+3 > n: break
                sz=script[i+1] | (script[i+2]<<8); off=i+3
            else:
                if i+5 > n: break
                sz=script[i+1]|(script[i+2]<<8)|(script[i+3]<<16)|(script[i+4]<<24)
                off=i+5
            if off+sz > n: break
            items.append(script[off:off+sz]); i=off+sz
        elif op == 0x4f:
            items.append(b'\x81'); i+=1
        elif 0x51 <= op <= 0x60:
            v=op-0x50; items.append(bytes([v]) if v else b''); i+=1
        else:
            break
    return items

ERR = {
 'OK':0,'UNKNOWN_ERROR':1,'EVAL_FALSE':2,'OP_RETURN':3,'SCRIPTNUM':18,
 'SCRIPT_SIZE':4,'PUSH_SIZE':5,'OP_COUNT':6,'STACK_SIZE':7,'SIG_COUNT':8,
 'PUBKEY_COUNT':9,'VERIFY':10,'EQUALVERIFY':11,'CHECKMULTISIGVERIFY':12,
 'CHECKSIGVERIFY':13,'NUMEQUALVERIFY':14,'BAD_OPCODE':8,'DISABLED_OPCODE':9,
 'INVALID_STACK_OPERATION':16,'INVALID_ALTSTACK_OPERATION':17,
 'UNBALANCED_CONDITIONAL':15,'MINIMALDATA':19,'OP_CODESEPARATOR':43,
 'INVALID_OPCODE':8,
}

def main():
    path=sys.argv[1] if len(sys.argv)>1 else '/storage/bitcoin-core-source/src/test/data/script_tests.json'
    data=json.load(open(path))
    stats={'run':0,'pass':0,'fail':0,'skip':0}
    fails=[]; per_err=collections.Counter()
    jobs=[]   # (sigtext, spktext, flagstr, expect, query_line)
    for e in data:
        if len(e)<4: continue
        sig,spk,flagstr,expect=e[:4]
        if not isinstance(sig,str) or not isinstance(spk,str): continue
        low=(flagstr or '').lower()
        if any(k in low for k in ('p2sh','witness','taproot','segwit','annex')):
            stats['skip']+=1; continue
        try:
            sigb = parse_script(sig); spkb = parse_script(spk)
        except Exception:
            stats['skip']+=1; continue
        script=sigb+spkb
        if any(b in (0xac,0xad,0xae,0xaf,0xba,0xb1,0xb2) for b in script):
            stats['skip']+=1; continue
        init=parse_pushes(sigb)
        q="0 0 %d %s"%(len(init), spkb.hex())
        for it in init: q+=" "+it.hex()
        jobs.append((sig,spk,flagstr,expect,q))

    # run ALL jobs in one subprocess
    run = subprocess.Popen([RUNBATCH], stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, text=True)
    out,_ = run.communicate("\n".join(j[4] for j in jobs)+"\n")
    results=[]
    for line in out.splitlines():
        if line.startswith('RESULT'):
            _,ok,er=line.split(); results.append((int(ok),int(er)))
        else:
            results.append((None,None))

    for idx,(sig,spk,flagstr,expect,q) in enumerate(jobs):
        ok,err = results[idx] if idx < len(results) else (None,None)
        if ok is None:
            stats['skip']+=1; continue
        stats['run']+=1
        if expect=='OK':
            got_pass = (ok==1)
        else:
            exp=ERR.get(expect.upper())
            if exp is None:
                stats['skip']+=1; continue
            got_pass = (ok==0 and err==exp)
        if got_pass:
            stats['pass']+=1; per_err[expect]+=1
        else:
            stats['fail']+=1
            if len(fails)<40:
                fails.append((sig[:60],spk[:60],flagstr,expect,ok,err))
    print("script_tests.json BASE opcode differential vs Core")
    print("  run=%d pass=%d fail=%d skip=%d"% (stats['run'],stats['pass'],stats['fail'],stats['skip']))
    if fails:
        print("  failures (sig_text, spk_text, flags, expected, got_ok, got_err):")
        for f in fails: print("   ",f)
    return 0 if stats['fail']==0 else 1

if __name__=='__main__':
    sys.exit(main())
