#!/usr/bin/env python3
"""gen_b143_corpus.py -- corpus for the bip143 cross-arch dump diff
(validation/bip143_corpus_dump.c format: name n_in hashtype amount tx_hex
scriptcode_hex, scriptcode BARE -- the C prepends the compactsize).

Realistic segwit txs (marker+flag, 1..4 inputs, 1..5 outputs incl.
P2WPKH/P2WSH/OP_RETURN shapes, witness stacks of varying shape feeding the
locktime walk), all six standard hashtypes, single/none/ACP midstate rules,
SINGLE with n_in >= nout (uint256(1) quirk), out-of-range n_in, empty and
long scriptCodes, huge amounts, plus the BIP143 example tx and the real
block-481824 tx 562 fixture.
"""
import random, sys

def cs(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff: return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')

def mk_tx(n_in, n_out, ninfix=None):
    t = bytearray(b'\x01\x00\x00\x00\x00\x01')          # version + marker/flag
    t += cs(n_in)
    for i in range(n_in):
        if ninfix is not None and i == 0:
            t += ninfix[0] + ninfix[1] + ninfix[2]
        else:
            t += random.randbytes(32) + struct_pack(random.getrandbits(32))
            sl = random.randrange(0, 40)
            t += cs(sl) + random.randbytes(sl)
            t += struct_pack(random.getrandbits(32))
    t += cs(n_out)
    for _ in range(n_out):
        v = random.choice([random.getrandbits(48), (1 << 53) + random.getrandbits(16),
                           0, (1 << 64) - 1])
        shape = random.randrange(3)
        if shape == 0:                                   # P2WPKH
            spk = b'\x00\x14' + random.randbytes(20)
        elif shape == 1:                                 # P2WSH
            spk = b'\x00\x20' + random.randbytes(32)
        else:                                            # OP_RETURN
            n = random.randrange(1, 60)
            spk = b'\x6a' + random.randbytes(n)
        t += v.to_bytes(8, 'little') + cs(len(spk)) + spk
    for i in range(n_in):                                # witness stacks
        items = random.randrange(0, 4)
        t += cs(items)
        for _ in range(items):
            l = random.randrange(0, 90)
            t += cs(l) + random.randbytes(l)
    t += struct_pack(random.getrandbits(32))             # locktime
    return bytes(t)

def struct_pack(v): return v.to_bytes(4, 'little')

lines = []
def rec(name, n_in, ht, amt, tx, sc):
    lines.append(f"{name} {n_in} {ht} {amt} {tx.hex()} {sc.hex() if sc else '-'}")

random.seed(0xB143C)
SC_P2PKH = bytes.fromhex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")
SC_LONG  = bytes.fromhex("522103eba1693d14de168bfa1f5dea4c62f6b3f3e19b9a4f0a4d5e0"
                         "d5e4d1a3c2b09a421038f1d2a4b9ce0a2e5c3d4f5a6b7c8d9e0f1a2b3"
                         "c4d5e6f708192a3b4c5d6e7f8052ae")
SC_EMPTY = b''
SCS = [("p2pkh", SC_P2PKH), ("long", SC_LONG), ("empty", SC_EMPTY)]

k = 0
for trial in range(90):
    n_in = random.randrange(1, 5)
    n_out = random.randrange(1, 6)
    tx = mk_tx(n_in, n_out)
    for scname, sc in SCS:
        for ht in (1, 2, 3, 0x81, 0x82, 0x83):
            k += 1
            rec(f"r{k:04d}_{scname}", random.randrange(0, n_in), ht,
                random.choice([random.getrandbits(40), (1 << 53) + random.getrandbits(10),
                               (1 << 64) - 1, 0]), tx, sc)

# SINGLE out-of-range: n_in >= n_out
tx_1o = mk_tx(2, 1)
rec("single_oor_a", 0, 3, 1000, tx_1o, SC_P2PKH)   # in 0 < nout 1 -> normal
rec("single_oor_b", 1, 3, 1000, tx_1o, SC_P2PKH)   # in 1 >= nout 1 -> quirk
rec("single_oor_c", 1, 0x83, 1000, tx_1o, SC_P2PKH)
# out-of-range n_in
rec("bad_nin", 7, 1, 1000, tx_1o, SC_P2PKH)
# zero-output tx
z = bytearray(b'\x02\x00\x00\x00\x00\x01' + cs(1))
z += random.randbytes(36) + b'\x00' + b'\xff\xff\xff\xff'
z += b'\x00'                                        # n_out = 0
z += b'\x00' + b'\x01\x51\x01\x02' + b'\x00\x00\x00\x00'   # witness + lock
rec("zero_out", 0, 1, 1000, bytes(z), SC_P2PKH)
# truncated at every interesting stage
full = mk_tx(2, 2)
for cut in (6, 7, 43, 44, 80, 100, len(full) - 5, len(full) - 1):
    rec(f"cut{cut}", 0, 1, 1000, full[:cut], SC_P2PKH)

# BIP143 example tx (with marker/flag; sighash c37af311..)
ex = ("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00"
      "00000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90e"
      "c68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a78"
      "3a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa"
      "815988ac11000000")
rec("bip143_example", 1, 1, 600000000, bytes.fromhex(ex), SC_P2PKH)

# real block-481824 tx 562 (sighash 32f2913c.. via bip143_ref.py)
import json, os
fx = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'asm',
                  'validation', 'fixtures', 'p2wpkh_481824_562.json')
if os.path.exists(fx):
    fix = json.load(open(fx))['hex']
    # scriptCode = implied P2PKH over THIS pubkey's hash160 (8d7a0a34...)
    sc_real = bytes.fromhex("76a9148d7a0a3461e3891723e5fdf8129caa0075060cff88ac")
    rec("real_481824_562", 0, 1, 194300, bytes.fromhex(fix), sc_real)

sys.stdout.write('\n'.join(lines) + '\n')
