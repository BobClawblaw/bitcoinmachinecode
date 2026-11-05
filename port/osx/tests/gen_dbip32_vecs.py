#!/usr/bin/env python3
"""gen_dbip32_vecs.py -- differential vectors for bitcoin_bip32.

bip32_master over seeds of every length class (0, 1, 15, 16, 17, 63, 64, 65,
128, 200) plus random; bip32_ckd_priv over random (kpar, cpar) pairs and the
edge scalars (0, 1, n-1, n, n+1, all-ff) x hardened/normal/index-0/max u32;
bip32_derive_path over random paths 0..8 deep; fingerprint over random
33-byte inputs (compressed and hybrid prefixes); extkey_serialize over
priv/pub x depths x children x key lens 32/33.
"""
import struct, random, sys

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
out = bytearray()
u32 = lambda v: struct.pack('<I', v & 0xFFFFFFFF)

def rec_master(seed):
    out.append(0); out.extend(u32(len(seed))); out.extend(seed)

def rec_ckd(kpar, cpar, idx):
    out.append(1); out.extend(kpar); out.extend(cpar); out.extend(u32(idx))

def rec_path(seed, idxs):
    out.append(2); out.extend(u32(len(seed))); out.extend(seed)
    out.extend(u32(len(idxs)))
    for i in idxs: out.extend(u32(i))

def rec_fp(pub):
    out.append(3); out.extend(pub)

def rec_ser(ip, depth, pfp, child, cc, key):
    out.append(4); out.append(ip & 0xff); out.append(depth & 0xff)
    out.extend(pfp); out.extend(u32(child)); out.extend(cc)
    out.extend(u32(len(key))); out.extend(key)

random.seed(0xB1EEF)
r32 = lambda: random.randbytes(32)

# master
for n in (0, 1, 15, 16, 17, 63, 64, 65, 128, 200):
    rec_master(random.randbytes(n))
for _ in range(40): rec_master(random.randbytes(random.randrange(1, 80)))
rec_master(bytes.fromhex('000102030405060708090a0b0c0d0e0f'))   # BIP32 vector 1

# ckd_priv
edges = [0, 1, N - 1, N, N + 1, (1 << 256) - 1]
for e in edges:
    k = e.to_bytes(32, 'big')
    for idx in (0, 1, 0x80000000, 0x8000002c, 0xFFFFFFFF, 44):
        rec_ckd(k, r32(), idx)
for _ in range(150):
    rec_ckd(r32(), r32(), random.choice([0, 1, 2, 42, 0x7fffffff, 0x80000000,
                                         0x80000001, 0x8000002c, 0xFFFFFFFF,
                                         random.getrandbits(32)]))
rec_ckd(bytes(32), r32(), 0)          # zero parent key (still runs both sides)
rec_ckd(r32(), bytes(32), 5)

# derive_path
for _ in range(60):
    depth = random.randrange(0, 9)
    idxs = [random.choice([random.getrandbits(31), 0x80000000 | random.getrandbits(31)])
            for _ in range(depth)]
    rec_path(random.randbytes(random.randrange(8, 40)), idxs)
rec_path(bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
         [0x8000002c, 0x80000000, 0x80000000, 0, 0])           # m/44'/0'/0'/0/0

# fingerprint
rec_fp(bytes(33))
rec_fp(bytes([0x02]) + r32())
rec_fp(bytes([0x03]) + r32())
rec_fp(bytes([0x04]) + r32() + b'\x01')   # hybrid
for _ in range(30): rec_fp(random.randbytes(33))

# extkey_serialize
cc = r32()
for ip in (0, 1, 2, 0xff):
    for depth in (0, 1, 3, 255):
        for child in (0, 1, 0x80000000, 0xFFFFFFFF):
            rec_ser(ip, depth, random.randbytes(4), child, cc, random.randbytes(32))
for ip in (0, 1):
    rec_ser(ip, 5, random.randbytes(4), 7, r32(), random.randbytes(33))
rec_ser(1, 0, bytes(4), 0, bytes(32), bytes(32))

sys.stdout.buffer.write(bytes(out))
