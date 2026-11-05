#!/usr/bin/env python3
"""gen_dsighash_vecs.py -- differential vectors for bitcoin_sighash.

Builds valid-ish legacy txs (random input/output counts, scriptSigs and
scriptPubKeys), truncated/corrupt variants, every legacy hashtype group
(1/2/3 x 0x00/0x80, plus the nonstandard low bits), SIGHASH_SINGLE
out-of-range shapes, scriptCodes with OP_CODESEPARATOR (0xab) runs, and
op-unit blobs exercising script_op_len (PUSHDATA1/2/4 forms incl. their
truncated headers), script_push_encode (all four length classes) and
script_find_and_delete (needle present/absent/repeated/malformed tails).
"""
import struct, random, sys

out = bytearray()

def u32(v): return struct.pack('<I', v & 0xFFFFFFFF)

def rec_sighash_all(tx, inidx, script):
    out.append(0); out.extend(u32(len(tx))); out.extend(tx)
    out.extend(u32(inidx)); out.extend(u32(len(script))); out.extend(script)

def rec_legacy(tx, nin, scriptcode, ht):
    out.append(1); out.extend(u32(len(tx))); out.extend(tx)
    out.extend(u32(nin)); out.extend(u32(len(scriptcode))); out.extend(scriptcode)
    out.extend(u32(ht))

def rec_oplen(blob):
    out.append(2); out.extend(u32(len(blob))); out.extend(blob)

def rec_push(data):
    out.append(3); out.extend(u32(len(data))); out.extend(data)

def rec_fad(src, needle):
    out.append(4); out.extend(u32(len(src))); out.extend(src)
    out.extend(u32(len(needle))); out.extend(needle)

random.seed(0x51C6)

def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)

def mk_tx(n_in, n_out, sigmax=60, spkmax=40, truncate=0):
    t = bytearray(struct.pack('<I', 2))
    t += varint(n_in)
    for _ in range(n_in):
        t += bytes(random.getrandbits(8) for _ in range(32))
        t += struct.pack('<I', random.getrandbits(32))
        sl = random.randrange(0, sigmax)
        t += varint(sl) + bytes(random.getrandbits(8) for _ in range(sl))
        t += struct.pack('<I', random.getrandbits(32))
    t += varint(n_out)
    for _ in range(n_out):
        t += struct.pack('<Q', random.getrandbits(63))
        pl = random.randrange(0, spkmax)
        t += varint(pl) + bytes(random.getrandbits(8) for _ in range(pl))
    t += struct.pack('<I', random.getrandbits(32))
    if truncate:
        t = t[:truncate]
    return bytes(t)

def mk_cs_script(n):
    s = bytearray()
    for _ in range(n):
        s += bytes([random.choice([0xab, 0x01, 0x51, 0xa9])])  # OP_CHECKSIG tail
        if random.random() < 0.4:
            s += bytes([random.randrange(1, 0x40)]) + bytes(random.getrandbits(8) for _ in range(s[-1]))
    return bytes(s)

HTS = [1, 2, 3, 0x81, 0x82, 0x83, 0x00, 0x1f, 0x2 | 0x80, 0x3 | 0x80, 0x80000000]

# ---- sighash_all + legacy over a spread of tx shapes ----
for k in range(120):
    n_in = random.randrange(1, 5)
    n_out = random.randrange(1, 4)
    tx = mk_tx(n_in, n_out)
    script = bytes(random.getrandbits(8) for _ in range(random.randrange(1, 80)))
    rec_sighash_all(tx, random.randrange(0, n_in), script)
    rec_legacy(tx, random.randrange(0, n_in), mk_cs_script(random.randrange(1, 8)),
               random.choice(HTS))

# truncated txs (each stage of the walk) for both builders
base = mk_tx(3, 2)
for cut in (5, 9, 10, 11, 40, 41, 45, 46, 80, 120, len(base) - 8, len(base) - 4, len(base) - 1):
    if 0 < cut < len(base):
        rec_sighash_all(base[:cut], 0, b'\x51')
        rec_legacy(base[:cut], 0, b'\x51\xab\x51', 1)

# SIGHASH_SINGLE out-of-range: nIn >= nOut
tx_1o = mk_tx(2, 1)
rec_legacy(tx_1o, 0, b'\x51', 3)          # in 0 >= out 1? nOut=1 -> nIn=0 < 1 ok
rec_legacy(tx_1o, 1, b'\x51', 3)          # in 1 >= nOut 1 -> uint256(1) quirk
rec_legacy(tx_1o, 1, b'\x51', 0x83)
# ACP shapes
rec_legacy(mk_tx(3, 2), 2, b'\x51', 0x81)
rec_legacy(mk_tx(3, 2), 0, b'\x51', 0x2 | 0x80)

# zero-output tx
z = bytearray(struct.pack('<I', 1)) + varint(1)
z += bytes(32) + struct.pack('<I', 0) + varint(0) + struct.pack('<I', 0)  # empty scriptSig
z += varint(0) + struct.pack('<I', 5)
rec_legacy(bytes(z), 0, b'\x51', 1)

# ---- script_op_len units ----
rec_oplen(b'')
rec_oplen(bytes([0x00]))
rec_oplen(bytes([0x4b]) + b'x' * 0x4b)          # direct push, full
rec_oplen(bytes([0x4b]) + b'x' * 0x4a)          # direct push, truncated data
rec_oplen(bytes([0x4c, 0x00]))                   # PUSHDATA1 len 0
rec_oplen(bytes([0x4c, 0xff]) + b'x' * 0xff)
rec_oplen(bytes([0x4c, 0xff]) + b'x' * 0xfe)     # truncated
rec_oplen(bytes([0x4d, 0xff, 0x00]) + b'x' * 0xff)
rec_oplen(bytes([0x4d, 0x02, 0x00]) + b'x' * 2)
rec_oplen(bytes([0x4d, 0x02, 0x00]) + b'x')      # truncated
rec_oplen(bytes([0x4e, 2, 0, 0, 0]) + b'x' * 2)
rec_oplen(bytes([0x4e, 2, 0, 0, 0]))             # PUSHDATA4 no data
rec_oplen(bytes([0x4e]))
rec_oplen(bytes([0xab, 0x51, 0x52]))
rec_oplen(bytes([0xff]))                          # bare high opcode
for _ in range(40):
    n = random.randrange(0, 40)
    rec_oplen(bytes(random.getrandbits(8) for _ in range(n)))

# ---- script_push_encode ----
for dl in (0, 1, 0x4b, 0x4c, 0x4c + 1, 0xff, 0x100, 0xffff, 0x10000, 300):
    rec_push(bytes(random.getrandbits(8) for _ in range(dl)))
rec_push(b'')

# ---- script_find_and_delete ----
sig = bytes([71]) + bytes(random.getrandbits(8) for _ in range(71))   # 71-byte push
script = bytes([0x01, 0x51]) + sig + bytes([0xac]) + sig + bytes([0x01, 0x52])
rec_fad(script, sig)                       # two matches
rec_fad(script, b'\xab')                   # codeseparator needle, none present
rec_fad(bytes([0xab, 0x51, 0xab, 0x52, 0xab]), b'\xab')
rec_fad(script, b'')                       # empty needle: no-op passthrough
rec_fad(bytes([0x4c, 0x02, 0x51, 0x52]), bytes([0x4c, 0x02, 0x51]))  # push-data needle
rec_fad(bytes([0x4d]), b'\x51')            # malformed tail verbatim
rec_fad(bytes([0x4d, 0x02, 0x00, 0x51]), b'\x99')  # unit + trailing junk
for _ in range(30):
    src = bytes(random.getrandbits(8) for _ in range(random.randrange(0, 60)))
    nd = bytes(random.getrandbits(8) for _ in range(random.randrange(0, 6)))
    rec_fad(src, nd)

sys.stdout.buffer.write(bytes(out))
