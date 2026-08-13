import random
P = 2**256 - 2**32 - 977
MASK = (1 << 256) - 1
C = 2**32 + 977

random.seed(2)
for i in range(10):
    a = random.getrandbits(256)
    b = random.getrandbits(256)
    prod = a * b
    v = prod
    print('iter %d: bits initially %d' % (i, v.bit_length()))
    for k in range(6):
        v = (v & MASK) + ((v >> 256) * C)
        print('   fold %d -> %d bits' % (k, v.bit_length()))
    assert v % P == prod % P
print('DONE - max bits after each fold recorded above')
