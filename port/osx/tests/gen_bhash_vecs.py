#!/usr/bin/env python3
"""Generate differential vectors + verify results for bitcoin_hash port.
Usage: gen_bhash_vecs.py gen <vectors.bin>   |  gen_bhash_vecs.py check <vectors.bin> <results.bin>
"""
import hashlib, struct, random, sys

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def block_hash(h):
    return sha256d(h)  # 80-byte header, double-SHA256

def bits_to_target(bits):
    # mirrors asm/bitcoin_hash.asm diff_target (VAL-11 clamping):
    # e3 = exp-3; e3<0 or e3>31 -> 0; else (mant << 8*e3) truncated to 256 bits
    exp = bits >> 24
    mant = bits & 0x00ffffff
    e3 = exp - 3
    if e3 < 0 or e3 > 31:
        return 0
    return (mant << (8 * e3)) & ((1 << 256) - 1)

def nbits_wellformed(bits):
    # Core CheckProofOfWorkImpl range checks as mirrored by pow_check
    if bits & 0x00800000: return False
    if (bits & 0x007fffff) == 0: return False
    exp = bits >> 24
    if exp > 34: return False
    if exp > 33 and ((bits & 0x007fffff) > 0xff): return False
    if exp > 32 and ((bits & 0x007fffff) > 0xffff): return False
    if exp < 3: return False
    return bits_to_target(bits) != 0

def gen(path, n=4000):
    rng = random.Random(1337)
    recs = []
    # sha256d: boundary + random lengths
    for L in [0,1,2,3,4,5,7,8,31,32,33,55,56,63,64,65,111,112,119,120,127,128,129,255,256,511,512,1000,4096]:
        recs.append((0, bytes(rng.randrange(256) for _ in range(L))))
    for _ in range(n):
        recs.append((0, bytes(rng.randrange(256) for _ in range(rng.randrange(0, 1000)))))
    # block_hash: 80-byte headers (valid-ish PoW occasionally)
    for _ in range(400):
        h = bytearray(rng.randrange(256) for _ in range(76))
        bits = rng.choice([0x207fffff, 0x1d00ffff, 0x1b0404cb, 0x1702353d])
        h += struct.pack('<I', bits)
        recs.append((1, bytes(h)))
    # diff_target: interesting compact values
    interesting = [0x01123456, 0x02008000, 0x03000000, 0x0400ffff, 0x1d00ffff,
                   0x207fffff, 0x1b0404cb, 0x1702353d, 0x01003456, 0x00000000,
                   0x00800000, 0x22000000, 0x23ffffff, 0xff123456, 0x10000001,
                   0x0f0000ff, 0x1f0fffff, 0x34c00000, 0x05000000, 0x7fffffff]
    for b in interesting:
        recs.append((2, struct.pack('<I', b)))
    for _ in range(800):
        recs.append((2, struct.pack('<I', rng.randrange(0x100000000))))
    # pow_check: 80-byte headers, nBits at offset 72 (version4|prev32|mrkl32|time4|bits4|nonce4)
    for b in interesting:
        recs.append((3, b'\x00' * 72 + struct.pack('<I', b) + b'\x00' * 4))
    for _ in range(1200):
        recs.append((3, b'\x00' * 72 + struct.pack('<I', rng.randrange(0x100000000)) + b'\x00' * 4))
    # sha256d64: 1..300 pairs of 64B
    for pairs in [1, 2, 3, 64, 1024, 300]:
        data = bytes(rng.randrange(256) for _ in range(pairs * 128))
        recs.append((4, struct.pack('<Q', pairs) + data))
    # merkle_root: n = 1..300 hashes (duplicates to trigger mutation corner)
    for n in [1, 2, 3, 4, 5, 7, 8, 16, 100, 301]:
        hs = bytearray(rng.randrange(256) for _ in range(32 * n))
        if n >= 2:
            hs[32:64] = hs[0:32]  # duplicate -> CVE-2012-2459 mutation flag path
        recs.append((5, bytes(hs)))
    with open(path, 'wb') as f:
        for op, payload in recs:
            f.write(struct.pack('<II', op, len(payload)))
            f.write(payload)
    print(f"wrote {len(recs)} vectors")

def check(vpath, rpath):
    with open(vpath, 'rb') as f:
        data = f.read()
    with open(rpath, 'rb') as f:
        res = f.read()
    off = 0
    roff = 0
    fails = 0
    total = 0
    while off < len(data):
        op, ln = struct.unpack_from('<II', data, off)
        off += 8
        payload = data[off:off+ln]
        off += ln
        total += 1
        if op == 0:
            exp = sha256d(payload)
            got = res[roff:roff+32]; roff += 32
        elif op == 1:
            exp = sha256d(payload)
            got = res[roff:roff+32]; roff += 32
        elif op == 2:
            bits = struct.unpack('<I', payload)[0]
            exp = bits_to_target(bits).to_bytes(32, 'big')  # asm stores BE
            got = res[roff:roff+32]; roff += 32
        elif op == 3:
            bits = struct.unpack_from('<I', payload, 76)[0]
            h = int.from_bytes(sha256d(payload), 'little')  # block hash as LE int
            tgt = bits_to_target(bits)
            exp_v = 1 if (nbits_wellformed(bits) and h <= tgt) else 0
            got_v = struct.unpack_from('<i', res, roff)[0]; roff += 4
            got = b'\x01' if got_v != 0 else b'\x00'
            exp = b'\x01' if exp_v else b'\x00'
        elif op == 4:
            pairs = struct.unpack('<Q', payload[:8])[0]
            blob = payload[8:]
            import hashlib as H
            # contract: in stride 64 bytes, out stride 32 bytes
            exp = b''.join(sha256d(blob[i*64:(i+1)*64]) for i in range(pairs))
            got = res[roff:roff+pairs*32]; roff += pairs*32
        elif op == 5:
            n = ln // 32
            # reference merkle with duplicate-detection mutation flag
            hashes = [payload[i*32:(i+1)*32] for i in range(n)]
            mut = False
            level = hashes
            while len(level) > 1:
                if len(level) % 2 == 1:
                    level.append(level[-1])
                nxt = []
                for i in range(0, len(level), 2):
                    if level[i] == level[i+1]:
                        mut = True
                        nxt.append(b'\x00' * 32)
                    else:
                        nxt.append(sha256d(level[i] + level[i+1]))
                level = nxt
            exp = level[0]
            exp_ret = 1 if mut else 0  # mutation flag byte in eax, 0/1 (VAL-6)
            got = res[roff:roff+32]; roff += 32
            got_ret = struct.unpack_from('<i', res, roff)[0]; roff += 4
            if got_ret != exp_ret:
                print(f"MERKLE RET MISMATCH n={n}: got {got_ret} exp {exp_ret}")
                fails += 1
            if mut:
                got = b'\x00' * 32  # skip root compare on mutation vectors
                exp = b'\x00' * 32
        else:
            continue
        if got != exp:
            fails += 1
            if fails <= 5:
                print(f"MISMATCH op={op} len={ln}: got {got.hex()} exp {exp.hex()}")
    print(f"checked {total} vectors, {fails} failures")
    return 1 if fails else 0

if __name__ == '__main__':
    if sys.argv[1] == 'gen':
        gen(sys.argv[2])
    else:
        sys.exit(check(sys.argv[2], sys.argv[3]))
