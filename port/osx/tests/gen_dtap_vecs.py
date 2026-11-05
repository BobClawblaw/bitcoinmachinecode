#!/usr/bin/env python3
"""gen_dtap_vecs.py -- differential vectors for secp256k1_taproot.

tagged_hash256 over random tags/msgs (0..2500B, incl. the real tag strings
and one 200KB msg); branch over random/equal/lexicographically-adjacent
pairs (all-ff vs all-00, one-bit differences); leaf over scripts crossing
the 0xfd and 0x10000 compactsize boundaries plus the >cap rejection
(TAP_PREIMG_CAP-70 is 4 MiB-70 -- not reachable through the 8000-byte
driver cap, so the boundary cases are 252..257 and 65533..65537 where the
two/three-byte cs encodings flip); tweak over random internal keys, keys
with the top byte >= p's top byte (0xff -> x > p rejected), the all-ff key,
with and without a merkle root; merkle over control paths of depth 0..8
with random orderings (sibling < node and > node mixed), plus a null
control and a 32-byte (too-short) control.
"""
import struct, random, sys

out = bytearray()
u32 = lambda v: struct.pack('<I', v & 0xFFFFFFFF)
random.seed(0xDAF1)

def rec_tag(tag, msg):
    out.append(0); out.extend(u32(len(tag))); out.extend(tag)
    out.extend(u32(len(msg))); out.extend(msg)

def rec_br(a, b):
    out.append(1); out.extend(a); out.extend(b)

def rec_leaf(ver, script):
    out.append(2); out.append(ver & 0xff); out.extend(u32(len(script))); out.extend(script)

def rec_tweak(ix, mr):
    out.append(3); out.extend(ix)
    if mr is None: out.append(0)
    else: out.append(1); out.extend(mr)

def rec_mr(control, leaf):
    out.append(4); out.extend(u32(len(control) if control else 0))
    if control: out.extend(control)
    out.extend(leaf)

P_TOP = 0xff  # p's top byte is 0xff

for tag in (b"TapTweak", b"TapLeaf", b"TapBranch", b"", b"BIP0341/challenge"):
    for ml in (0, 1, 32, 64, 65, 127, 128, 129, 1000, 2500):
        rec_tag(tag, bytes(random.getrandbits(8) for _ in range(ml)))
rec_tag(b"big", bytes(random.getrandbits(8) for _ in range(200000)))

for _ in range(40):
    rec_br(random.randbytes(32), random.randbytes(32))
same = random.randbytes(32)
rec_br(same, same)
rec_br(b'\x00'*32, b'\xff'*32)
rec_br(b'\xff'*32, b'\x00'*32)
a = bytearray(random.randbytes(32)); b = bytearray(a); b[17] ^= 0x01
rec_br(bytes(a), bytes(b)); rec_br(bytes(b), bytes(a))

for sl in (0, 1, 252, 253, 254, 255, 256, 257, 65533, 65534, 65535, 65536, 65537, 3000):
    rec_leaf(random.choice([0xc0, 0xc1, 0x00, 0xff]),
             bytes(random.getrandbits(8) for _ in range(sl)))

for _ in range(60):
    ix = bytearray(random.randbytes(32))
    mr = random.choice([None, random.randbytes(32)])
    rec_tweak(bytes(ix), mr)
rec_tweak(b'\xff'*32, None)                       # x > p -> reject
ix = bytearray(random.randbytes(32)); ix[0] = 0xff; ix[1] = 0xff
rec_tweak(bytes(ix), random.randbytes(32))        # almost certainly > p
rec_tweak(bytes(32), None)                        # x = 0: lift_x of 0? pubkey_parse decides
rec_tweak(bytes([0x02] + [0xff]*31), None)

for depth in range(0, 9):
    for _ in range(4):
        ctrl = bytearray(random.randbytes(33))
        for _ in range(depth):
            h = bytearray(random.randbytes(32))
            if random.random() < 0.3:             # sibling == node sometimes
                h = bytearray(ctrl[-32:])
            elif random.random() < 0.3:           # sibling one above node
                h = bytearray(ctrl[-32:]); h[0] = (h[0] + 1) & 0xff
            ctrl += h
        rec_mr(bytes(ctrl), random.randbytes(32))
rec_mr(b'', random.randbytes(32))                 # null control
rec_mr(random.randbytes(32), random.randbytes(32))  # 32-byte control -> depth 0

sys.stdout.buffer.write(bytes(out))
