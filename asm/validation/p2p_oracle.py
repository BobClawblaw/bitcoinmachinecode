#!/usr/bin/env python3
# P2P message-payload oracle (S2) -- deterministic byte-exact builders for the
# messages bitcoin_p2p.asm must produce/parse. Validate asm output against this.
import struct

PROTO = 70016

# --- network byte order helpers (all multi-byte ints are LITTLE endian on the wire)
def u32(v): return struct.pack('<I', v & 0xffffffff)
def u64(v): return struct.pack('<Q', v & 0xffffffffffffffff)
def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)

def getheaders(start_hash: bytes, count=1, hashstop=b'\x00'*32) -> bytes:
    """version, locator_count, locator hashes, stop hash. start_hash is a 32-byte id."""
    out = u32(PROTO)
    out += varint(count)
    for _ in range(count):
        out += start_hash   # little-endian hash as stored
    out += hashstop
    return out

def headers_payload(entries: bytes) -> bytes:
    return varint(len(entries)//81) + entries

def getdata_block(hashid: bytes) -> bytes:
    out = varint(1)
    out += u32(2)          # MSG_BLOCK = 2
    out += hashid
    return out

def ping(nonce: int) -> bytes:
    return u64(nonce)

def pong(nonce: int) -> bytes:
    return u64(nonce)

def verack() -> bytes:
    return b''

if __name__ == '__main__':
    # prove determinism against a fixed sample id
    h = bytes.fromhex('3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a')
    print('getheaders', getheaders(h, 1).hex())
    print('getdata   ', getdata_block(h).hex())
    print('ping      ', ping(0x1122334455667788).hex())
    print('getheaders len', len(getheaders(h, 1)))
    print('getdata len   ', len(getdata_block(h)))
