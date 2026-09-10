#!/usr/bin/env python3
"""gen_daddr_vecs.py -- differential vectors for bitcoin_addr.

hash160 over boundary/odd lengths (0, 1, 55, 56, 63, 64, 65, 127, 128, 1000)
plus pseudo-random blobs; base58check over paylen edges (0, 1, 4, 5, 20, 21,
25, 64, 78) with all-zero payloads (leading-'1' path, ndigits=0), real-ish
version||hash160 shapes, single nonzero bytes at both ends, and the refusal
cases (79, 100, and the unsigned-negative 0xFFFFFFFF) that must write out[0]=0
and nothing else.
"""
import struct, random, sys

out = bytearray()

def rec_h(b):
    out.append(0); out.extend(struct.pack('<I', len(b))); out.extend(b)

def rec_b(b):
    out.append(1); out.extend(struct.pack('<I', len(b))); out.extend(b)

random.seed(0xA00DE)

# ---- hash160 ----
for n in (0, 1, 2, 55, 56, 63, 64, 65, 127, 128, 1000):
    rec_h(bytes(random.getrandbits(8) for _ in range(n)))
rec_h(b'hello world')
rec_h(b'G')
rec_h(bytes(64))            # all zeros

# ---- base58check ----
for n in (0, 1, 4, 5, 20, 21, 25, 64, 78):
    rec_b(bytes(n))                                  # all-zero payload
    rec_b(bytes([0] + [random.getrandbits(8) for _ in range(n - 1)]) if n else b'')
    rec_b(bytes([random.getrandbits(8) for _ in range(n - 1)] + [0x01]) if n else b'')
    rec_b(bytes(random.getrandbits(8) for _ in range(n)))
# single nonzero at each end of a 21-byte payload
p = bytearray(21); p[0] = 0x80; rec_b(bytes(p))
p = bytearray(21); p[20] = 0x80; rec_b(bytes(p))
# 78-byte extended-key shape (the historic frame-overrun probe)
p = bytearray(78); p[0] = 0x04; p[1] = 0x88; p[77] = 0x01; rec_b(bytes(p))
# refusal shapes: paylen > 78 and the unsigned "negative"
rec_b(bytes(79))
rec_b(bytes(100))
out.append(1); out.extend(struct.pack('<I', 0xFFFFFFFF)); out.extend(b'')

sys.stdout.buffer.write(bytes(out))
