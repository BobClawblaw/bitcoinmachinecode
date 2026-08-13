#!/usr/bin/env python3
"""Randomized stress test of the assembly secp256k1 field arithmetic.

Drives the assembled fe_add / fe_sub / fe_mul via ctypes and compares against
Python's arbitrary-precision integers as the trusted oracle. This is independent
of the (also AI-written) C test harness -- it validates the machine code against
the Python big-int implementation over tens of thousands of random cases.
"""
import ctypes, random, sys

P = 2**256 - 2**32 - 977
N = int(sys.argv[1]) if len(sys.argv) > 1 else 20000

lib = ctypes.CDLL("./libsecpfe.so")

U64 = ctypes.c_ulonglong
P4 = U64 * 4

lib.fe_add.argtypes = [P4, P4, P4]
lib.fe_sub.argtypes = [P4, P4, P4]
lib.fe_mul.argtypes = [P4, P4, P4]
lib.fe_sqr.argtypes = [P4, P4]
lib.fe_inv.argtypes = [P4, P4]
lib.fe_add.restype = None
lib.fe_sub.restype = None
lib.fe_mul.restype = None
lib.fe_sqr.restype = None
lib.fe_inv.restype = None


def from_py(x):
    return P4(*[(x >> (64 * i)) & ((1 << 64) - 1) for i in range(4)])

def to_py(a):
    return sum(a[i] << (64 * i) for i in range(4))

random.seed(0xB17C0FF)
fail = 0
for i in range(N):
    a = random.getrandbits(256) % P
    b = random.getrandbits(256) % P
    A = from_py(a)
    B = from_py(b)

    R = P4()
    lib.fe_add(R, A, B)
    if to_py(R) != (a + b) % P:
        fail += 1
        print("ADD FAIL %d" % i)
        if fail > 5:
            break

    R = P4()
    lib.fe_sub(R, A, B)
    if to_py(R) != (a - b) % P:
        fail += 1
        print("SUB FAIL %d" % i)
        if fail > 5:
            break

    R = P4()
    lib.fe_mul(R, A, B)
    exp = (a * b) % P
    if to_py(R) != exp:
        fail += 1
        print("MUL FAIL %d: a=%x b=%x got=%x exp=%x" % (i, a, b, to_py(R), exp))
        if fail > 5:
            break

    # fe_sqr: R = a^2 mod p
    R = P4()
    lib.fe_sqr(R, A)
    if to_py(R) != (a * a) % P:
        fail += 1
        print("SQR FAIL %d" % i)
        if fail > 5:
            break

    # fe_inv: R = a^-1 and must satisfy a*R == 1 (unless a == 0)
    if a != 0:
        R = P4()
        lib.fe_inv(R, A)
        inv = pow(a, P - 2, P)
        if to_py(R) != inv:
            fail += 1
            print("INV FAIL %d: a=%x got=%x exp=%x" % (i, a, to_py(R), inv))
            if fail > 5:
                break

print("Stress test: %d iterations, %d failures" % (N, fail))
sys.exit(1 if fail else 0)
