#!/usr/bin/env python3
import ctypes, random, sys
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
lib = ctypes.CDLL('./libsecpscalar.so')
U64 = ctypes.c_ulonglong
P4 = U64 * 4
for fn in ('sc_add', 'sc_sub', 'sc_mul'):
    f = getattr(lib, fn); f.argtypes = [P4, P4, P4]; f.restype = None
for fn in ('sc_sqr', 'sc_inv'):
    f = getattr(lib, fn); f.argtypes = [P4, P4]; f.restype = None

def from_py(x):
    return P4(*[(x >> (64 * i)) & ((1 << 64) - 1) for i in range(4)])
def to_py(a):
    return sum(a[i] << (64 * i) for i in range(4))
fail = 0
checks = [
    ('add(0,0)', lib.sc_add, 0, 0, lambda a, b: (a + b) % N),
    ('add(n-1,1)', lib.sc_add, N - 1, 1, lambda a, b: (a + b) % N),
    ('add(n-1,n-1)', lib.sc_add, N - 1, N - 1, lambda a, b: (a + b) % N),
    ('mul(1,1)', lib.sc_mul, 1, 1, lambda a, b: (a * b) % N),
    ('mul(n-1,n-1)', lib.sc_mul, N - 1, N - 1, lambda a, b: (a * b) % N),
    ('mul(0,big)', lib.sc_mul, 0, 0x1234567890abcdef1234567890abcdef, lambda a, b: (a * b) % N),
    ('inv(2)', lib.sc_inv, 2, 0, lambda a, b: pow(2, N - 2, N)),
]
for name, fn, a, b, ref in checks:
    r = P4()
    if fn in (lib.sc_sqr, lib.sc_inv):
        fn(r, from_py(a))
    else:
        fn(r, from_py(a), from_py(b))
    got = to_py(r); exp = ref(a, b)
    if got != exp:
        fail += 1; print('FAIL', name, 'got=%x exp=%x' % (got, exp))
    else:
        print('PASS', name)
random.seed(2024)
iters = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
for t in range(iters):
    a = random.getrandbits(256) % N
    b = random.getrandbits(256) % N
    for fn, ref in ((lib.sc_add, (a + b) % N), (lib.sc_sub, (a - b) % N), (lib.sc_mul, (a * b) % N)):
        r = P4()
        fn(r, from_py(a), from_py(b))
        if to_py(r) != ref:
            fail += 1; print('RAND FAIL a=%x b=%x fn=%s got=%x exp=%x' % (a, b, fn, to_py(r), ref))
            if fail > 5: sys.exit(1)
    r = P4(); lib.sc_sqr(r, from_py(a))
    if to_py(r) != (a * a) % N:
        fail += 1; print('SQR FAIL a=%x' % a)
    if fail > 5: sys.exit(1)
for t in range(300):
    a = random.getrandbits(256) % N
    if a == 0:
        continue
    r = P4(); lib.sc_inv(r, from_py(a))
    if (to_py(r) * a) % N != 1:
        fail += 1; print('INV FAIL a=%x' % a)
print('scalar stress: %d iters, %d failures' % (iters, fail))
sys.exit(1 if fail else 0)
