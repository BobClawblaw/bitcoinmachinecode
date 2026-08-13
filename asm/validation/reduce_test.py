P = 2**256 - 2**32 - 977
print('P = %x' % P)
print('2^256 mod p =', hex((2**256) % P))
print('2^32+977 =', hex(2**32+977))
import random
random.seed(1)

MASK = (1 << 256) - 1
C = 2**32 + 977

for i in range(5):
    a = random.getrandbits(256)
    b = random.getrandbits(256)
    prod = a * b
    t0 = prod & MASK
    t1 = prod >> 256
    # fold: replace 2^256 by C = 2^32+977, iterate until value < 2^256
    r = t0 + t1 * C
    for _ in range(5):
        r = (r & MASK) + ((r >> 256) * C)
    while r >= P:
        r -= P
    assert r == (a * b) % P, 'mismatch iter %d' % i
    print('ok iter', i)

# verify add/sub
for i in range(5):
    a = random.getrandbits(256) % P
    b = random.getrandbits(256) % P
    s = a + b
    if s >= P:
        s -= P
    assert s == (a + b) % P
    d = a - b
    if d < 0:
        d += P
    assert d == (a - b) % P

print('ALL REDUCTION/ADD/SUB OK')
