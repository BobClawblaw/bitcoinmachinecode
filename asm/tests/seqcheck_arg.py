#!/usr/bin/env python3
# Persistent-buffer reimplementation of fe_inv loop for a given scalar a (arg).
import ctypes, sys
P = 2**256 - 2**32 - 977
EXP = (P - 2).to_bytes(32, 'little')
a = int(sys.argv[1], 16) if len(sys.argv) > 1 else 2
lib = ctypes.CDLL('./libsecpfe.so')
U64 = ctypes.c_ulonglong
P4 = U64 * 4
lib.fe_mul.argtypes = [P4, P4, P4]
lib.fe_mul.restype = None
lib.fe_sqr.argtypes = [P4, P4]
lib.fe_sqr.restype = None
def to_py(x):
    return sum(x[i] << (64 * i) for i in range(4))
R = P4(*( (a >> (64 * k)) & ((1 << 64) - 1) for k in range(4) ))
A = P4(*( (a >> (64 * k)) & ((1 << 64) - 1) for k in range(4) ))
pyR = a
for i in range(254, -1, -1):
    lib.fe_sqr(R, R)
    if EXP[i >> 3] & (1 << (i & 7)):
        lib.fe_mul(R, R, A)
    pyR = pyR * pyR % P
    if EXP[i >> 3] & (1 << (i & 7)):
        pyR = pyR * a % P
    if to_py(R) != pyR:
        print('MISMATCH bit %d: asm=%x py=%x' % (i, to_py(R), pyR))
        sys.exit(1)
print('a=%x: ALL MATCHED' % a)
