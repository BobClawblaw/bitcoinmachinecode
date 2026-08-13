#!/usr/bin/env python3
import ctypes, sys
P = 2**256 - 2**32 - 977
EXP = (P - 2).to_bytes(32, 'little')
lib = ctypes.CDLL('./libsecpfe.so')
U64 = ctypes.c_ulonglong
P4 = U64 * 4
for fn in ('fe_mul', 'fe_sqr', 'fe_inv'):
    f = getattr(lib, fn)
    f.argtypes = [P4, P4] if fn in ('fe_sqr', 'fe_inv') else [P4, P4, P4]
    f.restype = None

def from_py(x):
    return P4(*[(x >> (64 * i)) & ((1 << 64) - 1) for i in range(4)])
def to_py(a):
    return sum(a[i] << (64 * i) for i in range(4))

a = 2
R = a
for i in range(254, -1, -1):
    X = from_py(R)
    lib.fe_sqr(X, X)
    if EXP[i >> 3] & (1 << (i & 7)):
        A = from_py(a)
        lib.fe_mul(X, X, A)
    got = to_py(X)
    want = R * R % P
    if EXP[i >> 3] & (1 << (i & 7)):
        want = want * a % P
    if got != want:
        print('MISMATCH bit %d input=%x asm=%x want=%x' % (i, R, got, want))
        sys.exit(1)
    R = want
print('ALL STEPS MATCHED (ctypes vs Python)')
