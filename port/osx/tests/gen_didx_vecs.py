#!/usr/bin/env python3
"""gen_didx_vecs.py -- deterministic bitcoin_idx differential vectors.

Record stream (matches didx.c). Three table phases in one vector file:
  A: small table (64 slots) - put/get/dup/full-table/negative lookups,
     including the real-data shape (leading near-zero bytes, PoW-like).
  B: 1024-slot table - bulk insert 700 (headroom: build inserts ~285 more,
     so the table stays <100% -- a FULL table makes the x86 asm spin forever,
     see OSX_ROADMAP), then idx_build_from_file over a
     generated index.dat written NEXT TO the vectors (the harness runs in a
     scratch cwd): 500 records with holes, wire-order hashes, and dups of
     phase-B hashes to pin the dup-skip path. Dump after.
  C: rebuild again on a fresh init from a hole-rich file; dump.

index.dat files are emitted alongside: idxbuild_a.dat (trivial),
idxbuild_b.dat (500 recs, 40% holes), idxbuild_c.dat (300 recs, no holes,
includes dup hashes vs its own earlier records).
"""
import os
import struct
import sys


def rec(op, a=0, body=b"", b=None):
    return struct.pack("<III", op, a, len(body) if b is None else b) + body


def lcg_bytes(seed, n):
    out = bytearray(n)
    x = seed & 0xFFFFFFFFFFFFFFFF
    for i in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out[i] = (x >> 33) & 0xFF
    return bytes(out)


def powish_hash(seed):
    """real-data shape: leading bytes near zero, entropy in the tail"""
    h = bytearray(lcg_bytes(seed, 32))
    h[0] = 0
    h[1] = 0
    h[2] &= 0x0F
    return bytes(h)


def write_idxdat(path, records):
    """records: list of (hash32 or None); None = hole. 48-byte records."""
    with open(path, "wb") as f:
        for h in records:
            if h is None:
                f.write(b"\x00" * 48)
            else:
                f.write(h + b"\x00" * 16)     # hash[32] + 16 trailing bytes


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    vecpath = os.path.join(outdir, "didx_vecs.bin")
    parts = []

    # ---- phase A: 64-slot table, small-scale semantics ----
    parts.append(rec(0, 64))
    ha = [powish_hash(0xA000 + i) for i in range(40)]
    for i, h in enumerate(ha):
        parts.append(rec(1, i * 3 + 1, h))
    for i, h in enumerate(ha):                    # dups
        parts.append(rec(1, 777, h))
    for i, h in enumerate(ha):                    # found lookups
        parts.append(rec(2, 0, h))
    for i in range(30):                           # negatives
        parts.append(rec(2, 0, lcg_bytes(0xE000 + i, 32)))
    parts.append(rec(3))                          # count
    parts.append(rec(5, 64))                      # dump table A

    # ---- phase B: 1024-slot table + bulk build from file ----
    parts.append(rec(0, 1024))
    hb = [lcg_bytes(0xB000 + i, 32) for i in range(700)]  # 700 puts: 800 would let build pushes fill 1024 slots exactly, where the x86 asm spins forever on a full table (budget-in-r8 bug)
    for i, h in enumerate(hb):
        parts.append(rec(1, 100000 + i, h))
    parts.append(rec(3))
    recs_b = []
    for i in range(500):
        if i % 5 in (1, 3):                       # 40% holes
            recs_b.append(None)
        elif i % 10 == 7:
            recs_b.append(hb[i % 700])            # dup of a phase-B hash
        elif i % 10 == 9:
            recs_b.append(powish_hash(0xBB00 + i))
        else:
            recs_b.append(lcg_bytes(0xBC00 + i, 32))
    write_idxdat(os.path.join(outdir, "idxbuild_b.dat"), recs_b)
    parts.append(rec(4, 0, b"idxbuild_b.dat"))
    parts.append(rec(3))
    parts.append(rec(5, 1024))                    # dump table B

    # ---- phase C: fresh table, hole-free file with self-dups ----
    parts.append(rec(0, 4096))
    recs_c = []
    for i in range(300):
        if i % 50 == 25:
            recs_c.append(recs_c[i - 7])          # exact dup of an earlier rec
        else:
            recs_c.append(powish_hash(0xCC00 + i))
    write_idxdat(os.path.join(outdir, "idxbuild_c.dat"), recs_c)
    parts.append(rec(4, 0, b"idxbuild_c.dat"))
    # spot-check lookups against the built table
    for i in (0, 25, 50, 149, 275, 299):
        parts.append(rec(2, 0, recs_c[i] if recs_c[i] else powish_hash(0xCC00 + i)))
    parts.append(rec(3))
    parts.append(rec(5, 4096))                    # dump table C

    with open(vecpath, "wb") as f:
        f.write(b"".join(parts))
    print(f"{len(parts)} records, {sum(len(p) for p in parts)} bytes")


if __name__ == "__main__":
    main()
