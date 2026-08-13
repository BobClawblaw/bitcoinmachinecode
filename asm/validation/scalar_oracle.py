#!/usr/bin/env python3
"""Validate scalar arithmetic mod the secp256k1 curve order n.
Scalars stored as 4 x u64 little-endian limbs (same as field elements).
This is the oracle for secp256k1_scalar.asm (sc_add, sc_sub, sc_mul)."""
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def to_limbs(x):
    return [(x >> (64*i)) & ((1<<64)-1) for i in range(4)]
def from_limbs(L):
    return sum(L[i] << (64*i) for i in range(4))

def sc_add(a,b): return (a+b) % N

def sc_sub(a,b): return (a-b) % N

def sc_mul(a,b): return (a*b) % N

def sc_inv(a): return pow(a, N-2, N)

def check(name, got, exp):
    if got == exp: print('PASS', name)
    else: print('FAIL', name, 'got=%x exp=%x' % (got, exp))

if __name__ == '__main__':
    import random
    random.seed(99)
    check('add n-1,1 -> 0', sc_add(N-1,1), 0)
    check('sub 0,1 -> n-1', sc_sub(0,1), N-1)
    check('mul overflows mod n', sc_mul(N-1, N-1), (N-1)*(N-1)%N)
    check('inv(2) -> (n+1)/2', sc_inv(2), (N+1)//2)
    check('inv(2)*2==1', sc_mul(2, sc_inv(2)), 1)
    # random consistency
    ok = True
    for _ in range(5000):
        a = random.getrandbits(256) % N; b = random.getrandbits(256) % N
        if sc_add(a,b) != (a+b)%N: ok=False; break
        if sc_sub(a,b) != (a-b)%N: ok=False; break
        if sc_mul(a,b) != (a*b)%N: ok=False; break
    print('random 5000 add/sub/mul:', 'PASS' if ok else 'FAIL')
    # n and n-k encodings for tests
    print('N limbs:', ' '.join('%016x' % ((N>>(64*i))&((1<<64)-1)) for i in range(4)))
    print('(N-1) limbs:', ' '.join('%016x' % (((N-1)>>(64*i))&((1<<64)-1)) for i in range(4)))
    print('n-1 = %064x' % (N-1))
    print('N = %064x' % N)
