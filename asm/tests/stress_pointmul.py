#!/usr/bin/env python3
"""Differential harness: point_scalar_mul (asm) vs pure-python oracle.

Drive the asm something via a shared lib, convert the projective (Jacobian)
result to affine, and compare against the reference mul(k, G).

Usage: python3 stress_pointmul.py [iters]
"""
import ctypes, random, sys

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

lib = ctypes.CDLL('./libsecppoint.so')
U64 = ctypes.c_ulonglong
P4 = U64 * 4
P12 = U64 * 12
P8 = U64 * 8

def lp(x):
    return P4(*[(x >> (64 * i)) & ((1 << 64) - 1) for i in range(4)])

def ap(x, y):
    # affine xy packed: x limbs then y limbs
    r = P8()
    for i in range(4):
        r[i] = (x >> (64 * i)) & ((1 << 64) - 1)
        r[4 + i] = (y >> (64 * i)) & ((1 << 64) - 1)
    return r

def to_affine(j):
    # j = [X0..3, Y0..3, Z0..3] as P12 of u64
    z = sum(j[8 + i] << (64 * i) for i in range(4))
    x = sum(j[i] << (64 * i) for i in range(4))
    y = sum(j[4 + i] << (64 * i) for i in range(4))
    if z == 0:
        return None  # infinity
    zi = pow(z, P - 2, P)
    ax = x * zi * zi % P
    ay = y * zi * zi * zi % P
    return (ax, ay)

fail = 0
iters = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
random.seed(7)
# fixed edge cases
edge = [1, 2, 3, N - 1, N - 2, N, 0,
        0x1234567890ABCDEF1234567890ABCDEF, N // 2, 2**255]
for a in edge:
    k = a % N if a >= N else a
    if k == 0:
        continue
    lib.point_scalar_mul.restype = None
    lib.point_scalar_mul.argtypes = [P12, P8, P4]
    # build G affine
    gx, gy = G
    ga = ap(gx, gy)
    kk = P4(*[(k >> (64 * i)) & ((1 << 64) - 1) for i in range(4)])
    r = P12()
    lib.point_scalar_mul(r, ga, kk)
    got = to_affine(r)
    exp = mul(k, G)
    if got != exp:
        fail += 1
        print('EDGE FAIL k=%x got=%s exp=%s' % (k, got, exp))
    else:
        print('edge ok k=%x' % k)

for t in range(iters):
    k = random.getrandbits(256) % N
    if k == 0:
        continue
    gx, gy = G
    ga = ap(gx, gy)
    kk = P4(*[(k >> (64 * i)) & ((1 << 64) - 1) for i in range(4)])
    r = P12()
    lib.point_scalar_mul(r, ga, kk)
    got = to_affine(r)
    exp = mul(k, G)
    if got != exp:
        fail += 1
        print('RAND FAIL k=%x got=%s exp=%s' % (k, got, exp))
        if fail > 5:
            sys.exit(1)

print('pointmul stress: %d iters, %d failures' % (iters, fail))
sys.exit(1 if fail else 0)
