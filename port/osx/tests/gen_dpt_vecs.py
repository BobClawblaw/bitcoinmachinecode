#!/usr/bin/env python3
"""gen_dpt_vecs.py -- point-layer differential vectors: random operands plus
the degenerate shapes (Z=0 canonical/non-canonical, q==p, mixed x2==X1 with
Z1==1, Y1==0, affine (0,0)), and curve-point scalars for mul ops."""
import struct, random, sys

M = (1<<64)-1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def limbs(v, n=4): return [(v>>(64*i))&M for i in range(n)]
def pack_fe(v): return b''.join(struct.pack('<Q', x) for x in limbs(v))
def pack_jac(x, y, z): return pack_fe(x)+pack_fe(y)+pack_fe(z)

Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

random.seed(0x90117)
out = bytearray()

def rnd_fe(): return random.getrandbits(256) % P
def rnd_jac():
    return pack_jac(rnd_fe(), rnd_fe(), rnd_fe())

NREC = 240
for i in range(NREC):
    shape = i % 7
    if shape == 0:      # random jacobians
        pj, qj = rnd_jac(), rnd_jac()
        axy = pack_fe(rnd_fe()) + pack_fe(rnd_fe())
    elif shape == 1:    # p infinity (canonical) and non-canonical (5,7,0)
        pj = pack_jac(1, 1, 0)
        qj = rnd_jac()
        axy = pack_fe(rnd_fe()) + pack_fe(rnd_fe())
    elif shape == 2:    # p = (X,Y,0) non-canonical inf
        pj = pack_jac(rnd_fe(), rnd_fe(), 0)
        qj = rnd_jac()
        axy = pack_fe(rnd_fe()) + pack_fe(rnd_fe())
    elif shape == 3:    # q == p (doubling branch)
        pj = rnd_jac()
        qj = pj
        axy = pack_fe(rnd_fe()) + pack_fe(rnd_fe())
    elif shape == 4:    # Y1 == 0
        pj = pack_jac(rnd_fe(), 0, rnd_fe())
        qj = rnd_jac()
        axy = pack_fe(rnd_fe()) + pack_fe(0)
    elif shape == 5:    # affine (0,0)
        pj = rnd_jac()
        qj = rnd_jac()
        axy = pack_fe(0) + pack_fe(0)
    else:               # curve point G-ish affine for muls
        pj = rnd_jac()
        qj = rnd_jac()
        axy = pack_fe(Gx) + pack_fe(Gy)

    k = random.getrandbits(256) % P
    # record: all three ops on the same operands
    out.append(0); out += pj
    out.append(1); out += pj + qj
    out.append(2); out += pj + axy
    out.append(3); out += pj + axy
    if i % 3 == 0:
        out.append(4); out += axy + pack_fe(k)
        out.append(5); out += pack_fe(k)
        out.append(6); out += axy + pack_fe(k)
sys.stdout.buffer.write(bytes(out))
print(f"wrote {NREC} shapes", file=sys.stderr)
