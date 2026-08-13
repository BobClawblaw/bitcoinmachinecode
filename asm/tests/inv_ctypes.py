#!/usr/bin/env python3
import ctypes
P = 2**256 - 2**32 - 977
lib = ctypes.CDLL('./libsecpfe.so')
U64 = ctypes.c_ulonglong
P4 = U64 * 4
lib.fe_inv.argtypes = [P4, P4]
lib.fe_inv.restype = None
def from_py(x):
    return P4(*[(x >> (64 * i)) & ((1 << 64) - 1) for i in range(4)])
def to_py(a):
    return sum(a[i] << (64 * i) for i in range(4))
fail = 0
for t in range(200):
    a = (123456789 + t * 987654321) % P
    if a == 0:
        continue
    R = P4()
    lib.fe_inv(R, from_py(a))
    got = to_py(R)
    want = pow(a, P - 2, P)
    if got != want:
        print('INV FAIL a=%x got=%x want=%x' % (a, got, want))
        fail += 1
        if fail > 5:
            break
print('fe_inv via ctypes: %d tests, %d failures' % (200, fail))
