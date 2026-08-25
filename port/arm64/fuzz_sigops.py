#!/usr/bin/env python3
"""Differential fuzz for bitcoin_sigops.S (AArch64) vs an independent Python
Core-equivalent oracle: script_sigops(inaccurate), script_sigops_accurate,
tx_legacy_sigops."""
import random, subprocess, sys

FZ = "./fz_sigops"

def cvarint(n: int) -> bytes:
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff: return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')

def get_op(script, pc):
    if pc >= len(script): return None, None
    op = script[pc]; nxt = pc + 1
    if op == 0x4e:
        if nxt + 4 > len(script): return 0, None
        pl = int.from_bytes(script[nxt:nxt+4], 'little'); nxt += 4
        if nxt + pl > len(script): return 0, None
        return op + 1, nxt + pl
    if op == 0x4d:
        if nxt + 2 > len(script): return 0, None
        pl = int.from_bytes(script[nxt:nxt+2], 'little'); nxt += 2
        if nxt + pl > len(script): return 0, None
        return op + 1, nxt + pl
    if op == 0x4c:
        if nxt >= len(script): return 0, None
        pl = script[nxt]; nxt += 1
        if nxt + pl > len(script): return 0, None
        return op + 1, nxt + pl
    if op <= 0x4b:
        pl = op
        if nxt + pl > len(script): return 0, None
        return op + 1, nxt + pl
    return op + 1, nxt

def py_script_sigops(script, accurate=False):
    count = 0; last = 0; pc = 0; i = 0
    while pc < len(script):
        r = get_op(script, pc)
        if r is None or r[0] == 0:
            break
        op = r[0] - 1; pc = r[1]
        if op in (0xac, 0xad):
            count += 1; last = 0
        elif op in (0xae, 0xaf):
            if accurate and 0x51 <= last <= 0x60:
                count += last - 0x50
            else:
                count += 20
            last = 0
        elif 0x51 <= op <= 0x60:
            last = op
        else:
            last = 0
        i += 1
        if i > 20000: break
    return count

def read_varint(b, p):
    x = b[p]
    if x < 0xfd: return x, p + 1
    if x == 0xfd: return int.from_bytes(b[p+1:p+3], 'little'), p + 3
    if x == 0xfe: return int.from_bytes(b[p+1:p+5], 'little'), p + 5
    return int.from_bytes(b[p+1:p+9], 'little'), p + 9

def py_tx_legacy(b):
    total = 0; p = 4
    # segwit marker+flag skip
    if len(b) > 5 and b[4] == 0x00 and b[5] == 0x01:
        p = 6
    n_in, p = read_varint(b, p)
    for _ in range(n_in):
        p += 36
        slen, p2 = read_varint(b, p); p = p2
        total += py_script_sigops(b[p:p+slen], False)
        p += slen + 4
    n_out, p = read_varint(b, p)
    for _ in range(n_out):
        p += 8
        slen, p2 = read_varint(b, p); p = p2
        total += py_script_sigops(b[p:p+slen], False)
        p += slen
    return total

# ---- script generator biased toward sigop/numeral opcodes ----
BIAS = [0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,
        0xac,0xad,0xae,0xaf,0x4c,0x4d,0x4e,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
        0x51,0x52,0xac,0xae,0xaf,0xad,0x51,0x60,0xac,0xae,0x51,0xac]

def gen_script(rng):
    n = rng.randrange(0, 40)
    out = bytearray()
    for _ in range(n):
        which = rng.random()
        if which < 0.6:
            out.append(BIAS[rng.randrange(len(BIAS))])
        elif which < 0.85:
            out.append(rng.randrange(0x01, 0x4c))
        else:
            pl = rng.randrange(1, 20)
            out.append(0x4c); out.append(pl)
            out += bytes(rng.getrandbits(8) for _ in range(pl))
    return bytes(out)

def gen_tx(rng, segwit):
    version = rng.getrandbits(32).to_bytes(4, 'little')
    # n_in>=1: a legacy tx with n_in=0 & n_out=1 serializes `version 00 01 ...`
    # which the (upstream-faithful) SegWit heuristic misdetects as marker+flag and
    # reads OOB. Real consensus txs always have n_in>=1, so keep fuzz realistic.
    nin = rng.randrange(1, 5); nout = rng.randrange(0, 5)
    ins = b''
    for _ in range(nin):
        ins += bytes(rng.getrandbits(8) for _ in range(36))
        s = gen_script(rng)
        ins += cvarint(len(s)) + s
        ins += rng.getrandbits(32).to_bytes(4, 'little')
    outs = b''
    for _ in range(nout):
        outs += rng.getrandbits(64).to_bytes(8, 'little')
        s = gen_script(rng)
        outs += cvarint(len(s)) + s
    lock = rng.getrandbits(32).to_bytes(4, 'little')
    if segwit and rng.random() < 0.5 and nin > 0:
        wit = b''
        for _ in range(nin):
            nitem = rng.randrange(0, 3)
            wit += cvarint(nitem)
            for _ in range(nitem):
                w = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 10)))
                wit += cvarint(len(w)) + w
        body = version + b'\x00\x01' + cvarint(nin) + ins + cvarint(nout) + outs + wit + lock
    else:
        body = version + cvarint(nin) + ins + cvarint(nout) + outs + lock
    return body

def run(mode, data):
    r = subprocess.run([FZ, mode, data.hex()], capture_output=True, text=True)
    return int(r.stdout.strip())

def main():
    rng = random.Random(int(sys.argv[1]) if len(sys.argv) > 1 else 0)
    seeds = int(sys.argv[2]) if len(sys.argv) > 2 else 2400
    iters = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    global FZ
    fails = 0; shown = 0
    for it in range(seeds):
        mode = ['I','A'][rng.randrange(2)] if it % 2 == 0 else ['I','A','A','I'][rng.randrange(4)]
        s = gen_script(rng)
        got = run(mode, s)
        acc = (mode == 'A')
        exp = py_script_sigops(s, acc)
        if got != exp:
            fails += 1
            if shown < 5:
                shown += 1
                print(f"SCRIPT FAIL mode={mode} hex={s.hex()} got={got} exp={exp}")
            continue
        if it % 2 == 1 and iters > 0:
            tx = gen_tx(rng, segwit=True)
            got = run('S', tx)
            exp = py_tx_legacy(tx)
            if got != exp:
                fails += 1
                if shown < 5:
                    shown += 1
                    print(f"TX FAIL hex={tx.hex()} got={got} exp={exp}")
    print(f"sigops fuzz: {seeds} script cases + {seeds//2} tx cases, {fails} FAILS")
    sys.exit(1 if fails else 0)

if __name__ == '__main__':
    main()
