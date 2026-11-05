#!/usr/bin/env python3
"""gen_dstore_vecs.py -- deterministic bitcoin_store differential vectors.

Record stream (matches dstore.c). Shapes: init/append/get/tip/reload cycles,
rollover across a file boundary via a small MAX_FILE? (no -- MAX_FILE is
fixed 128MB in both; rollover is covered by test_append_linkage on x86 and
not exercised here), prune set/persist, prune+delete at heights 1..3,
truncate_to mid-store and to -1, truncate_index_only, tip_hash,
validates_prevhash, layout_monotonic, sync toggling.

The store files are outputs: the wrapper compares the whole cwd file set.
"""
import struct
import sys


def rec(op, a=0, body=b"", b=None):
    """b defaults to the body length; append passes a/b as the 64-bit len."""
    return struct.pack("<III", op, a, len(body) if b is None else b) + body


def lcg_bytes(seed, n):
    out = bytearray(n)
    x = seed & 0xFFFFFFFFFFFFFFFF
    for i in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out[i] = (x >> 33) & 0xFF
    return bytes(out)


def main():
    parts = []
    parts.append(rec(0))                                       # init
    # append 5 blocks with distinct hashes/sizes
    sizes = [50, 60, 70, 80, 90]
    hashes = [lcg_bytes(0x5100 + i, 32) for i in range(5)]
    for i, (h, sz) in enumerate(zip(hashes, sizes)):
        raw = lcg_bytes(0xA000 + i, sz)
        parts.append(rec(1, sz, h + raw))          # a=len, b=body len
    # get_at every height + 2 out-of-range
    for h in range(7):
        parts.append(rec(2, h))
    # tip
    parts.append(rec(3))
    # tip hash
    parts.append(rec(9))
    # validates_prevhash: matching (hash of tip? no -- header[4..36] == tip hash)
    hdr_ok = b"\x00" * 4 + hashes[4] + b"\x11" * 44            # 80B header
    hdr_bad = b"\x00" * 4 + lcg_bytes(0xBEEF, 32) + b"\x11" * 44
    parts.append(rec(10, 0, hdr_ok, b=80))
    parts.append(rec(10, 0, hdr_bad, b=80))
    # layout monotonic over the whole store
    parts.append(rec(11, 4))
    parts.append(rec(11, 99))
    # reload (re-derives idx_len/tip/pos from the files)
    parts.append(rec(4))
    # append after reload
    raw5 = lcg_bytes(0xA005, 33)
    parts.append(rec(1, 33, lcg_bytes(0x5105, 32) + raw5))
    # get_at all
    for h in range(7):
        parts.append(rec(2, h))
    parts.append(rec(3))
    # sync toggling
    parts.append(rec(12, 0))                                   # off
    raw6 = lcg_bytes(0xA006, 21)
    parts.append(rec(1, 21, lcg_bytes(0x5106, 32) + raw6))
    parts.append(rec(13))
    parts.append(rec(12, 1))                                   # back on
    # prune gate persist only
    parts.append(rec(5, 2))
    parts.append(rec(5, 0))
    # physical prune at height 2 (deletes blk files wholly below, compacts boundary)
    parts.append(rec(6, 2))
    # get_at below/above the prune point
    for h in range(7):
        parts.append(rec(2, h))
    parts.append(rec(3))
    parts.append(rec(9))
    parts.append(rec(11, 5))
    # truncate_to height 3 (keep 0..3)
    parts.append(rec(7, 3))
    for h in range(6):
        parts.append(rec(2, h))
    parts.append(rec(3))
    # append after truncate
    raw7 = lcg_bytes(0xA007, 44)
    parts.append(rec(1, 44, lcg_bytes(0x5107, 32) + raw7))
    parts.append(rec(3))
    # truncate_index_only to height 1 (blk files untouched)
    parts.append(rec(8, 1))
    for h in range(4):
        parts.append(rec(2, h))
    parts.append(rec(3))
    # full wipe via truncate_to(-1)
    parts.append(rec(7, 0xFFFFFFFF))                           # (i32)-1
    for h in range(2):
        parts.append(rec(2, h))
    parts.append(rec(3))
    # append after full wipe
    raw8 = lcg_bytes(0xA008, 15)
    parts.append(rec(1, 15, lcg_bytes(0x5108, 32) + raw8))
    parts.append(rec(3))
    parts.append(rec(9))

    with open(sys.argv[1] if len(sys.argv) > 1 else "dstore_vecs.bin", "wb") as f:
        f.write(b"".join(parts))
    print(f"{len(parts)} records")


if __name__ == "__main__":
    main()
