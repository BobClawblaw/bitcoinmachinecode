#!/usr/bin/env python3
"""gen_dsl_vecs.py -- vectors for the sc_mul_512 / sc_split_lambda differential."""
import struct, random, sys

M = (1<<64)-1
def limbs(v): return [(v>>(64*i))&M for i in range(4)]

random.seed(0xB00B1E5)
out = bytearray()
N_MUL = 400
N_SPLIT = 400
edges = [0,1,2,3,(1<<64)-1,(1<<64)-2,
         0xBFD25E8CD0364141, 0xBFD25E8CD0364140,
         0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE]

for i in range(N_MUL):
    if i < len(edges)*len(edges):
        a = edges[i % len(edges)]
        b = edges[i // len(edges)]
        a4 = limbs(a); b4 = limbs(b)
    else:
        a4 = [random.getrandbits(64) for _ in range(4)]
        b4 = [random.getrandbits(64) for _ in range(4)]
        if i % 3 == 0:
            a4 = [x >> 32 for x in a4]  # small-ish
        if i % 3 == 1:
            b4 = [x >> 32 for x in b4]
    out.append(0)
    for l in a4+b4: out += struct.pack('<Q', l)

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
lam = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72
ks = [0,1,2,3,n-1,n,n+1,2**256-1, lam, n-2, 2**128, 2**128+1, 2**255, (1<<256)//2]
for i in range(N_SPLIT):
    if i < len(ks):
        k = ks[i] % (1<<256)
    else:
        k = random.getrandbits(256)
        if i % 4 == 0: k %= n
    out.append(1)
    for l in limbs(k): out += struct.pack('<Q', l)

sys.stdout.buffer.write(bytes(out))
print(f"wrote {N_MUL} mul512 + {N_SPLIT} split vectors", file=sys.stderr)
