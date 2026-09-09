#!/usr/bin/env python3
"""gen_dsl_vecs2.py -- adds op2/3/4 (sc_mul/sc_add/sc_sub) vectors:
modular-reduced operands, unreduced operands, n-1/n/DELTA edges, dense."""
import struct, random, sys

M = (1<<64)-1
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
DELTA = (1<<256) - n
def limbs(v): return [(v>>(64*i))&M for i in range(4)]

random.seed(0xD15EA5E)
out = bytearray()
N = 500
edges = [0,1,2,3,n-1,n,DELTA,DELTA-1,DELTA+1,2**256-1,
         0x3086d221a7d46bcde86c90e49284eb15,      # c1-like value
         0x4437ed6010e88286f547fa90abfe4c30,      # c2-like value
         0x6F547FA90ABFE4C3,                      # MINUS_B1 limb0
         0xE4437ED6010E88286F547FA90ABFE4C3]      # MINUS_B1 value
for i in range(N):
    if i < len(edges):
        a = edges[i]; b = edges[(i*7+3) % len(edges)]
    elif i % 5 == 0:
        a = random.getrandbits(127)          # c1-like small
        b = edges[random.randrange(len(edges))]
    else:
        a = random.getrandbits(256) % n
        b = random.getrandbits(256) % n
    for op in (2,3,4):
        out.append(op)
        for l in limbs(a)+limbs(b): out += struct.pack('<Q', l)
sys.stdout.buffer.write(bytes(out))
print(f"wrote {N} operand pairs x 3 ops", file=sys.stderr)
