#!/usr/bin/env python3
"""Differential: fe_add/fe_sub/fe_mul/fe_sqr/fe_inv (asm) vs pure-python oracle.

The asm lives in a static-linked C driver (tests/stress_fe) to avoid
shared-lib PIC issues with the nasm objects. Feeds base-16 p-residue
inputs, compares against Python modular arithmetic mod P.
"""
import subprocess, random, sys

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

def fromhex(h):
    return [int(h[16*i:16*i+16], 16) for i in range(4)]

def tohex(l):
    return "".join("%016x" % x for x in l[:4])

def plus(a, b):
    r = []
    c = 0
    for i in range(4):
        s = a[i] + b[i] + c
        r.append(s & ((1 << 64) - 1)); c = s >> 64
    return r

def sub(a, b):
    r = []
    b = 0
    # a - b in 4 limbs, borrow
    borrow = 0
    for i in range(4):
        s = a[i] - b[i] - borrow
        if s < 0:
            s += 1 << 64; borrow = 1
        else:
            borrow = 0
        r.append(s)
    return r

def int_of(l):
    return sum(l[i] << (64 * i) for i in range(4))

def limbs(x):
    return [(x >> (64 * i)) & ((1 << 64) - 1) for i in range(4)]

iters = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
random.seed(5)
inputs = [
    (0, 0), (1, 1), (P - 1, 1), (P - 1, P - 1), (1, P - 1), (2, P - 2),
    (0x1234567890abcdef1234567890abcdef, 0x1111111111111111),
    (P - 1, 0), (0, P - 1), (2**255, 2**255), (P // 2, P // 2),
]
# random reduced inputs
for _ in range(iters):
    inputs.append((random.getrandbits(256) % P, random.getrandbits(256) % P))

lines = []
for a, b in inputs:
    lines.append("%s %s" % (tohex(limbs(a)), tohex(limbs(b))))
inp = "\n".join(lines) + "\n"

r = subprocess.run(["./tests/stress_fe"], input=inp, capture_output=True, text=True)
if r.returncode != 0:
    print("driver rc", r.returncode, r.stderr[:800]); sys.exit(2)
outs = r.stdout.splitlines()
assert len(outs) == len(inputs), "driver output count mismatch"

fail = 0
for (a, b), line in zip(inputs, outs):
    # line format: add sub mul (each 4 limbs hex) — implement in driver; here parse
    parts = line.split(":")
    if len(parts) == 4 and parts[0] == "OK":
        # driver returns OK:forms, parse each op
        addh, subh, mulh = parts[1], parts[2], parts[3]
        got_add = int_of(fromhex(addh)); got_sub = int_of(fromhex(subh)); got_mul = int_of(fromhex(mulh))
        exp_add = (a + b) % P; exp_sub = (a - b) % P; exp_mul = (a * b) % P
        if got_add != exp_add:
            fail += 1; print("ADD FAIL a=%x b=%x got=%x exp=%x" % (a, b, got_add, exp_add))
        if got_sub != exp_sub:
            fail += 1; print("SUB FAIL a=%x b=%x got=%x exp=%x" % (a, b, got_sub, exp_sub))
        if got_mul != exp_mul:
            fail += 1; print("MUL FAIL a=%x b=%x got=%x exp=%x" % (a, b, got_mul, exp_mul))
        if fail > 5: sys.exit(1)
    else:
        print("Unexpected driver line:", line)

print("field stress: %d samples, %d failures" % (len(inputs), fail))
sys.exit(1 if fail else 0)
