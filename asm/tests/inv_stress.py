#!/usr/bin/env python3
import ctypes, random, sys
P = 2**256 - 2**32 - 977
N = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
lib = ctypes.CDLL('./libsecpfe.so')
U64 = ctypes.c_ulonglong
P4 = U64 * 4
lib.fe_inv.argtypes = [P4, P4]
lib.fe_inv.restype = None
def from_py(x):
    return P4(*[(x >> (64 * i)) & ((1 << 64) - 1) for i in range(4)])
def to_py(a):
    return sum(a[i] << (64 * i) for i in range(4))
random.seed(1234)
fail = 0
for t in range(N):
    a = random.getrandbits(256) % P
    if a == 0:
        continue
    R = P4()
    lib.fe_inv(R, from_py(a))
    if (to_py(R) * a) % P != 1:
        fail += 1
        print('INV FAIL a=%x inv=%x' % (a, to_py(R)))
        if fail > 5:
            break
print('fe_inv randomized: %d iters, %d failures' % (N, fail))
sys.exit(1 if fail else 0)
