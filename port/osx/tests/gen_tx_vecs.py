#!/usr/bin/env python3
"""Generate tx vectors (valid + truncations + poisons) for the tx_parse/tx_txid
cross-arch differential. Usage: gen_tx_vecs.py gen <vectors.bin>
"""
import struct, random, sys

def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)

def mk_legacy(rng, n_in, n_out, script_max=30):
    t = struct.pack('<I', rng.randrange(1, 5)) + varint(n_in)
    for _ in range(n_in):
        t += bytes(rng.randrange(256) for _ in range(32))
        t += struct.pack('<I', rng.randrange(0x100000000))
        sl = rng.randrange(0, script_max)
        t += varint(sl) + bytes(rng.randrange(256) for _ in range(sl))
        t += struct.pack('<I', rng.randrange(0x100000000))
    t += varint(n_out)
    for _ in range(n_out):
        t += struct.pack('<Q', rng.randrange(0, 21_000_000 * 100_000_000))
        sl = rng.randrange(0, script_max)
        t += varint(sl) + bytes(rng.randrange(256) for _ in range(sl))
    t += struct.pack('<I', rng.randrange(0x100000000))
    return t

def mk_segwit(rng, n_in, n_out):
    t = struct.pack('<I', rng.randrange(1, 5)) + b'\x00\x01' + varint(n_in)
    for _ in range(n_in):
        t += bytes(rng.randrange(256) for _ in range(32))
        t += struct.pack('<I', rng.randrange(0x100000000))
        sl = rng.randrange(0, 30)
        t += varint(sl) + bytes(rng.randrange(256) for _ in range(sl))
        t += struct.pack('<I', rng.randrange(0x100000000))
    t += varint(n_out)
    for _ in range(n_out):
        t += struct.pack('<Q', rng.randrange(0, 21_000_000 * 100_000_000))
        sl = rng.randrange(0, 30)
        t += varint(sl) + bytes(rng.randrange(256) for _ in range(sl))
    for _ in range(n_in):
        items = rng.randrange(0, 4)
        t += varint(items)
        for _ in range(items):
            il = rng.randrange(0, 80)
            t += varint(il) + bytes(rng.randrange(256) for _ in range(il))
    t += struct.pack('<I', rng.randrange(0x100000000))
    return t

def gen(path):
    rng = random.Random(4242)
    recs = []
    # determinstic shapes
    recs.append(mk_legacy(rng, 1, 1, 5))
    recs.append(mk_legacy(rng, 0, 0))
    recs.append(mk_legacy(rng, 2, 3, 300))
    recs.append(mk_segwit(rng, 1, 1))
    recs.append(mk_segwit(rng, 2, 2))
    # varint edge cases on counts (0xfd-prefix form with hostile payloads)
    for cnt in (0xfd, 0x100, 0xffff, 0xfe, 0xff):
        t = struct.pack('<I', 1) + b'\xfd' + struct.pack('<H', cnt & 0xffff)
        recs.append(t)
    for _ in range(300):
        n_in = rng.randrange(0, 5)
        n_out = rng.randrange(0, 5)
        if rng.randrange(2):
            recs.append(mk_legacy(rng, n_in, n_out))
        else:
            recs.append(mk_segwit(rng, n_in, n_out))
    # poisoned variants of the first few
    base = recs[:8]
    for t in base:
        for pos in range(min(len(t), 40)):
            m = bytearray(t)
            m[pos] = rng.choice([0xff, 0xfe, 0xfd, 0x00])
            recs.append(bytes(m))
    with open(path, 'wb') as f:
        for t in recs:
            f.write(struct.pack('<II', 0, len(t)))
            f.write(t)
            f.write(struct.pack('<II', 1, len(t)))
            f.write(t)
    print('wrote %d tx vectors (x2 ops)' % len(recs))

if __name__ == '__main__':
    gen(sys.argv[2])
