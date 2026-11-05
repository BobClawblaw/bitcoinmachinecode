#!/usr/bin/env python3
"""gen_dkeys_vecs.py -- differential vectors for bitcoin_keys.

Records (see dkeys.c):  0: k[32] (small_nonzero)   1: k[32] (to_pubkey)

Covers scalar_small_nonzero's compare lattice (first-differing-byte below /
above / all-equal-at-n / all-equal-prefix tails) and scalar_to_pubkey over
secp256k1-valid scalars, edge scalars (0, 1, n-1, n, n+1, half-order points
of interest) and random 32-byte values both below and above n.  Both arches
run the identical byte stream; the outputs must match even where the input
is not a curve-legal scalar -- the contract is twin equality, not semantics.
"""
import struct, random, sys

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def be32(v):
    return int(v).to_bytes(32, 'big')

out = bytearray()

def rec_nz(k):   out.append(0); out.extend(k.to_bytes(32, 'big'))
def rec_pk(k):   out.append(1); out.extend(k.to_bytes(32, 'big'))

# ---- scalar_small_nonzero compare lattice (op 0) ----
n_b = N.to_bytes(32, 'big')
for k in (
    0,                              # all-zero -> 0
    1,                              # tiny -> 1
    N - 1,                          # largest valid scalar -> 1
    N,                              # == n: x86 falls through to ok -> 1
    N + 1,                          # just above n -> 0
    (1 << 256) - 1,                 # all-FF -> 0
    1 << 255,                       # high bit set -> 0
    0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
):
    rec_nz(k)
# first-differing-byte walk: equal prefix through byte i, then below/above
for i in range(0, 32, 5):
    b = n_b[i]
    lo = bytearray(n_b); lo[i] = b - 1 if b > 0 else b; rec_nz(int.from_bytes(lo,'big')) if b > 0 else rec_nz(int.from_bytes(lo,'big'))
    hi = bytearray(n_b); hi[i] = b + 1 if b < 0xFF else b; rec_nz(int.from_bytes(hi,'big'))
# low scalars below n with equal-prefix starts (0x00 prefix -> < n)
for i in range(1, 32, 7):
    k = bytearray(32); k[i] = 1; rec_nz(int.from_bytes(k,'big'))   # 1 at position i -> < n -> 1
    k = bytearray(32); k[i] = 0x80; rec_nz(int.from_bytes(k,'big'))# depends on i: 0x80 at i, rest 0 -> < n iff i > 0 and byte 0 = 0
# k sharing n's prefix through byte 30, last byte varies
for last in (0x3F, 0x40, 0x41, 0x42, 0x43, 0xFF):
    k = bytearray(n_b); k[31] = last; rec_nz(int.from_bytes(k,'big'))

# ---- scalar_to_pubkey (op 1) ----
for k in (0, 1, 2, 3, N - 1, N, N + 1, (1 << 255) + 1):
    rec_pk(k)
random.seed(0x9EE75)
for i in range(600):
    r = random.getrandbits(256)
    rec_pk(r % N) if i % 2 == 0 else rec_pk(r)   # half curve-legal, half raw
# BIP32-style: the two fixed test keys from test_keys.c
for hexk in ("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",):
    rec_pk(int(hexk, 16))

sys.stdout.buffer.write(bytes(out))
