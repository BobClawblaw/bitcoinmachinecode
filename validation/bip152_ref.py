# Faithful transcription of Bitcoin Core's BIP152 short-id computation
# (src/crypto/siphash.cpp + src/blockencodings.cpp) into standalone Python.
# Used as the reference oracle the ASM implementation is verified against.
import struct, hashlib

def rotl(x, b): return ((x << b) | (x >> (64-b))) & 0xffffffffffffffff

def sipround(v):
    v0,v1,v2,v3 = v
    v0 = (v0 + v1) & M64; v1 = rotl(v1,13); v1 ^= v0; v0 = rotl(v0,32)
    v2 = (v2 + v3) & M64; v3 = rotl(v3,16); v3 ^= v2
    v0 = (v0 + v3) & M64; v3 = rotl(v3,21); v3 ^= v0
    v2 = (v2 + v1) & M64; v1 = rotl(v1,17); v1 ^= v2; v2 = rotl(v2,32)
    return (v0,v1,v2,v3)

M64 = 0xffffffffffffffff
C0=0x736f6d6570736575; C1=0x646f72616e646f6d; C2=0x6c7967656e657261; C3=0x7465646279746573

def compress2(v, data):
    v0,v1,v2,v3 = v
    v3 ^= data
    v0,v1,v2,v3 = sipround((v0,v1,v2,v3))
    v0,v1,v2,v3 = sipround((v0,v1,v2,v3))
    v0 ^= data
    return (v0,v1,v2,v3)

def finalize4(v):
    v0,v1,v2,v3 = v
    v2 ^= 0xFF
    for _ in range(4):
        v0,v1,v2,v3 = sipround((v0,v1,v2,v3))
    return (v0 ^ v1 ^ v2 ^ v3) & M64

def siphash24_uint256(key, msg32):
    # exact PresaltedSipHasher::operator()(uint256): 4 words + length(32) block
    k0,k1 = key
    v = (C0^k0, C1^k1, C2^k0, C3^k1)
    for i in range(4):
        d = int.from_bytes(msg32[i*8:(i+1)*8],'little')
        v = compress2(v, d)
    v = compress2(v, 32<<56)
    return finalize4(v)

def siphash24_bytes(key, data):
    # general byte-input SipHash-2-4 (CSipHasher.Write(span)+Finalize)
    k0,k1 = key
    v = (C0^k0, C1^k1, C2^k0, C3^k1)
    t=0; c=0
    for b in data:
        t |= b << (8*(c%8)); c += 1
        if (c&7)==0:
            v = compress2(v, t); t = 0
    h = compress2(v, t | (c<<56))
    return finalize4(h)

def shortid_for(header80, nonce, wtxid32):
    # FillShortTxIDSelector: SHA256(header || nonceLE8)
    hsh = hashlib.sha256(header80 + struct.pack('<Q', nonce)).digest()
    k0 = int.from_bytes(hsh[0:8],'little')
    k1 = int.from_bytes(hsh[8:16],'little')
    return siphash24_uint256((k0,k1), wtxid32) & 0xffffffffffff

if __name__ == '__main__':
    # Core test/data/siphash.json vector: empty input, zero key -> 1e924b9d737700d7 (byte path)
    r = siphash24_bytes((0,0), b'')
    print("empty/0key:", hex(r), "expect 0x1e924b9d737700d7", "OK" if r==0x1e924b9d737700d7 else "MISMATCH")
