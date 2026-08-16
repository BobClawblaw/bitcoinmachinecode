#!/usr/bin/env python3
"""Differential: point_scalar_mul (asm batch driver) vs pure-python oracle.

Feeds N random 256-bit scalars to tests/stress_pointmul (static-linked asm)
and compares each resulting k*G affine point against mul(k,G) in python.
"""
import subprocess, random, sys

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0: return None
    if p == q:
        lam = (3 * p[0] * p[0]) * pow(2 * p[1], P - 2, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], P - 2, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    y = (lam * (p[0] - x) - p[1]) % P
    return (x, y)

def mul(k, p):
    r = None
    while k:
        if k & 1: r = add(r, p)
        p = add(p, p); k >>= 1
    return r

def parse_out(s):
    pts = []
    for line in s.strip().splitlines():
        line = line.strip()
        if line == "inf":
            pts.append(None)
        else:
            xs, ys = line.split()
            x = int(xs, 16); y = int(ys, 16)
            if x == 0 and y == 0:
                pts.append(None)  # some inf representation
            else:
                pts.append((x, y))
    return pts

iters = int(sys.argv[1]) if len(sys.argv) > 1 else 1500
random.seed(11)
scalars = []
# edge cases
edges = [1, 2, 3, N - 1, N - 2, N, 0, 0x1234567890abcdef1234567890abcdef,
         N // 2, 2**255, 2**256 - 1, 7, 0xdeadbeef]
for e in edges:
    scalars.append(e % N if e >= N else e)
for _ in range(iters):
    scalars.append(random.getrandbits(256) % N)

hx = ["%064x" % k for k in scalars]
inp = "\n".join(hx) + "\n"
r = subprocess.run(["./tests/stress_pointmul_ct"], input=inp, capture_output=True, text=True)
if r.returncode != 0:
    print("driver rc", r.returncode, r.stderr[:500]); sys.exit(2)
out = parse_out(r.stdout)
assert len(out) == len(scalars), f"mismatch lens {len(out)} vs {len(scalars)}"

fail = 0
for k, got in zip(scalars, out):
    exp = mul(k, G)
    # normalize: python returns None for infinity
    if got != exp:
        fail += 1
        print("FAIL k=%064x\n  got=%s\n  exp=%s" % (k, got, exp))
        if fail > 5: sys.exit(1)
print("pointmul stress: %d samples, %d failures" % (len(scalars), fail))
sys.exit(1 if fail else 0)
