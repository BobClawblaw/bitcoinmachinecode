#!/usr/bin/env python3
"""gen_dsv_vecs.py -- HMAC-SHA512 differential vectors: RFC 4231 lengths,
BIP32/BIP39-shaped inputs (chain codes, mnemonics, 64-byte seeds), edges
around the 128-byte key boundary (127/128/129 => triggers SHA512(key)), long
messages crossing SHA-512 block boundaries."""
import struct, random, sys, hashlib

random.seed(0xB105F00D)
out = bytearray()
N = 400
for i in range(N):
    if i == 0: kl, ml = 20, 8                      # RFC tc1 shape
    elif i == 1: kl, ml = 4, 28                    # RFC tc2 shape
    elif i == 2: kl, ml = 20, 50                   # RFC tc3 shape
    elif i == 3: kl, ml = 131, 100                 # keylen>128 => SHA512(key)
    elif i == 4: kl, ml = 127, 0                   # boundary 127, empty msg
    elif i == 5: kl, ml = 128, 0                   # boundary 128
    elif i == 6: kl, ml = 129, 1                   # boundary 129
    elif i == 7: kl, ml = 64, 64                   # BIP32 seed shape
    elif i == 8: kl, ml = 32, 64                   # chain-code shape
    elif i == 9: kl, ml = 64, 768                  # PBKDF2 msg shape
    else:
        kl = random.choice([1,4,16,20,32,33,63,64,65,96,127,128,129,130,200,300])
        ml = random.choice([0,1,7,8,63,64,65,111,112,113,127,128,129,255,256,512,600,800])
    key = bytes(random.getrandbits(8) for _ in range(kl))
    msg = bytes(random.getrandbits(8) for _ in range(ml))
    out += struct.pack('<II', kl, ml) + key + msg
sys.stdout.buffer.write(bytes(out))
print(f"wrote {N} hmac vectors", file=sys.stderr)
