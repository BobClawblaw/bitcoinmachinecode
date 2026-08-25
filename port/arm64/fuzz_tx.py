#!/usr/bin/env python3
"""Differential fuzz: bitcoin_tx.S (AArch64) tx_parse + tx_txid vs Python oracle."""
import random, subprocess, hashlib, sys

FZ = "./fz_tx"

def cvarint(n: int) -> bytes:
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + n.to_bytes(2,'little')
    if n <= 0xffffffff: return b'\xfe' + n.to_bytes(4,'little')
    return b'\xff' + n.to_bytes(8,'little')

def gen_input():
    prevout = bytes(random.getrandbits(8) for _ in range(32))
    index = random.getrandbits(32).to_bytes(4,'little')
    scr = bytes(random.getrandbits(8) for _ in range(random.randint(0,12)))
    seq = random.getrandbits(32).to_bytes(4,'little')
    return prevout + index + cvarint(len(scr)) + scr + seq

def gen_output():
    val = random.getrandbits(64).to_bytes(8,'little')
    scr = bytes(random.getrandbits(8) for _ in range(random.randint(0,20)))
    return val + cvarint(len(scr)) + scr

def gen_tx(segwit=True):
    version = random.getrandbits(32).to_bytes(4,'little')
    nin = random.randint(0,4); nout = random.randint(0,4)
    ins = b''.join(gen_input() for _ in range(nin))
    outs = b''.join(gen_output() for _ in range(nout))
    core = cvarint(nin) + ins + cvarint(nout) + outs
    lock = random.getrandbits(32).to_bytes(4,'little')
    if segwit and random.random() < 0.5 and nin > 0:
        witness = b''
        for _ in range(nin):
            nitem = random.randint(0,3)
            witness += cvarint(nitem)
            for _ in range(nitem):
                w = bytes(random.getrandbits(8) for _ in range(random.randint(0,15)))
                witness += cvarint(len(w)) + w
        body = version + b'\x00\x01' + core + witness + lock
    else:
        body = version + core + lock
    return body

def py_parse(b):
    """Return (valid, tx_len, version, n_in, n_out, locktime, in0_scr, in0_len,
    out0_val, out0_scr, out0_len) mirroring the asm; or (0,) if invalid."""
    try:
        p = 0
        if len(b) < 4: return (0,)
        version = int.from_bytes(b[0:4],'little'); p = 4
        segwit = False
        if p+2 <= len(b) and b[p]==0 and b[p+1]==1:
            segwit = True; p += 2
        def vint():
            nonlocal p
            x = b[p]
            if x < 0xfd: p+=1; return x
            if x == 0xfd: v=int.from_bytes(b[p+1:p+3],'little'); p+=3; return v
            if x == 0xfe: v=int.from_bytes(b[p+1:p+5],'little'); p+=5; return v
            v=int.from_bytes(b[p+1:p+9],'little'); p+=9; return v
        nin = vint(); nin_pos = p  # mark for in0 block start detection
        in0_scr=in0_len=0
        for i in range(nin):
            if p+36 > len(b): return (0,)
            p += 36
            sl = vint()
            if p+sl > len(b): return (0,)
            if i==0: in0_scr = p; in0_len = sl
            p += sl
            if p+4 > len(b): return (0,)
            p += 4
        nout = vint()
        out0_val=out0_scr=out0_len=0
        for i in range(nout):
            if p+8 > len(b): return (0,)
            if i==0: out0_val = p
            p += 8
            sl = vint()
            if i==0: out0_scr = p; out0_len = sl
            if p+sl > len(b): return (0,)
            p += sl
        if segwit:
            for _ in range(nin):
                nitem = vint()
                for _ in range(nitem):
                    wl = vint()
                    if p+wl > len(b): return (0,)
                    p += wl
        if p+4 > len(b): return (0,)
        lock = int.from_bytes(b[p:p+4],'little'); p += 4
        return (1, p, version, nin, nout, lock, in0_scr, in0_len, out0_val, out0_scr, out0_len)
    except Exception:
        return (0,)

def py_txid(b):
    try:
        p = 0
        version = b[0:4]; p = 4
        segwit = False
        if p+2 <= len(b) and b[p]==0 and b[p+1]==1:
            segwit=True; p+=2
        start_in = p
        def vint():
            nonlocal p
            x = b[p]
            if x<0xfd: p+=1; return x
            if x==0xfd: v=int.from_bytes(b[p+1:p+3],'little'); p+=3; return v
            if x==0xfe: v=int.from_bytes(b[p+1:p+5],'little'); p+=5; return v
            v=int.from_bytes(b[p+1:p+9],'little'); p+=9; return v
        nin = vint()
        for _ in range(nin):
            p += 36; sl=vint(); p += sl + 4
        nout = vint()
        for _ in range(nout):
            p += 8; sl=vint(); p += sl
        # outputs_end = p
        if len(b) < p+4: return (0, b'')
        lock = b[len(b)-4:len(b)]
        unwit = b[0:4] + b[start_in:p] + lock
        return (1, hashlib.sha256(hashlib.sha256(unwit).digest()).digest())
    except Exception:
        return (0, b'')

def main():
    seed = int(sys.argv[1]) if len(sys.argv)>1 else 1
    iters = int(sys.argv[2]) if len(sys.argv)>2 else 3000
    random.seed(seed)
    fails = 0
    for i in range(iters):
        raw = gen_tx()
        for (tag, rnd_bad) in [("raw", False)]:
            b = raw
            if not rnd_bad and random.random() < 0.15:
                # randomly truncate or corrupt tail to test rejection paths
                cut = random.random()
                if cut < 0.5 and len(b) > 1:
                    b = b[:random.randint(0, len(b))]
        # asm result
        r = subprocess.run([FZ, b.hex()], capture_output=True, text=True)
        lines = r.stdout.splitlines()
        if len(lines) != 2:
            print("BAD OUTPUT", lines); fails+=1; continue
        p0 = lines[0].split()
        Pp = [int(p0[0][1:])] + [int(x) for x in p0[1:]]
        p1 = lines[1].split()
        Tp = [p1[0]] + p1[1:]
        # python
        pp = py_parse(b)
        tp = py_txid(b)
        # compare tx_parse
        got = [Pp[0]]+Pp[1:]
        exp = list(pp)
        if exp[0]==0:
            if got[0]!=0:
                print(f"FAIL parse-validity i={i} got={got[0]} h={b[:40].hex()}"); fails+=1
        else:
            exp_full = [1, exp[1], exp[2], exp[3], exp[4], exp[5], exp[6], exp[7], exp[8], exp[9], exp[10]]
            if got != exp_full:
                print(f"FAIL parse-field {i} got={got} exp={exp_full}"); fails+=1
        # compare txid
        if tp[0]==0:
            if int(Tp[0][1:])!=0:
                print(f"FAIL txid-validity i={i}"); fails+=1
        else:
            if int(Tp[0][1:])!=1:
                print(f"FAIL txid invalid-asmsay i={i}"); fails+=1
            if len(Tp)>1 and Tp[1] != tp[1].hex():
                print(f"FAIL txid-val i={i} got={Tp[1][:16]} exp={tp[1].hex()[:16]}"); fails+=1
    print(f"tx fuzz: {iters} iters, {fails} failures")
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
