#!/usr/bin/env python3
# Mimic fe_inv with persistent in-place buffers, compare each step to Python.
import ctypes, sys
P = 2**256 - 2**32 - 977
EXP = (P - 2).to_bytes(32, 'little')
lib = ctypes.CDLL('./libsecpfe.so')
U64 = ctypes.c_ulonglong
P4 = U64 * 4
lib.fe_mul.argtypes = [P4, P4, P4]
lib.fe_mul.restype = None
lib.fe_sqr.argtypes = [P4, P4]
lib.fe_sqr.restype = None
def to_py(a):
    return sum(a[i] << (64 * i) for i in range(4))
# persistent in-place buffers (as fe_inv uses stack locals)
R = P4(2, 0, 0, 0)
A = P4(2, 0, 0, 0)
a = 2
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
print('PERSISTENT-BUFFER LOOP: ALL MATCHED')
