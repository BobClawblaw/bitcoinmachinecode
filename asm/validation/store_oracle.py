#!/usr/bin/env python3
# Store framing oracle (S3): the on-disk blk file format and index record layout.
import struct
import os

MAGIC = 0xD9B4BEF9  # mainnet

# ---- blk file: each block is framed exactly like Bitcoin Core wraps a raw
# block (which is itself [4B len][magic][block bytes] in the file). We store
# the raw serialized block prefixed with [4B len][4B magic].
def blk_append(blk_bytes: bytes, magic=MAGIC) -> bytes:
    out = struct.pack('<I', len(blk_bytes))
    out += struct.pack('<I', magic)
    out += blk_bytes
    return out

# ---- index record (per height, fixed 48 bytes):
#   [32 hash][8 u64 file_offset][4 u32 block_len][4 u32 height] = 48 bytes
def index_record(hashid: bytes, offset: int, blklen: int, height: int) -> bytes:
    return hashid + struct.pack('<Q', offset) + struct.pack('<I', blklen) + struct.pack('<I', height)

if __name__ == '__main__':
    # genesis block raw is 285 bytes (80-byte hdr + coinbase tx); the serialized
    # genesis block is 285 bytes. Use a synthetic vector to stay self-contained.
    blk = bytes(range(200))  # stand-in raw block
    print('blk frame len (should be 8 + 200 = 208):', len(blk_append(blk)))
    print('frame hex head:', blk_append(blk)[:16].hex())  # 200->'c8000000'? 200=0xc8
    h = bytes.fromhex('1122334455667788990011223344556677889900112233445566778899001122')
    rec = index_record(h, 208, 200, 1)
    print('index record len (should be 48):', len(rec))
    print('index record hex:', rec.hex())
