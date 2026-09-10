#!/usr/bin/env python3
"""gen_dlsm_vecs.py -- deterministic bitcoin_utxo_lsm differential vectors.

Record stream (matches dlsm.c): op0 init(a=op_threshold, b=fill_threshold),
op1 put(body=txid32+index4+value8+height4+cb1+slen2+script), op2 del,
op3 get, op4 count, op5 flush, op6 reload, op7 compact, op8 close.

Phases: many small-generation flushes (threshold 50), gets across runs,
dels incl. tombstones that miss the memtable (older-run shadowing), a full
reload, a compaction, post-compact gets, second reload.
"""
import struct
import sys


def rec(op, a=0, body=b""):
    return struct.pack("<III", op, a, len(body)) + body


def lcg_bytes(seed, n):
    out = bytearray(n)
    x = seed & 0xFFFFFFFFFFFFFFFF
    for i in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out[i] = (x >> 33) & 0xFF
    return bytes(out)


def put_rec(txid, index, value, height, cb, script):
    body = (txid + struct.pack("<I", index) + struct.pack("<Q", value) +
            struct.pack("<I", height) + bytes([cb]) +
            struct.pack("<H", len(script)) + script)
    return rec(1, 0, body)


def del_rec(txid, index):
    return rec(2, 0, txid + struct.pack("<I", index))


def get_rec(txid, index):
    return rec(3, 0, txid + struct.pack("<I", index))


def main():
    parts = []
    parts.append(rec(0, 50, b""))                 # op_threshold=50, fill=0
    # phase A: 120 puts (2+ flushes), script sizes cycling
    lens = [0, 12, 33, 255, 0, 20]
    for i in range(120):
        txid = lcg_bytes(0xA100 + i, 32)
        script = lcg_bytes(0xB100 + i, lens[i % len(lens)])
        parts.append(put_rec(txid, i % 3, 1000 + i, 10 + i, i % 2, script))
    parts.append(rec(4))                          # count
    for i in range(0, 120, 7):
        parts.append(get_rec(lcg_bytes(0xA100 + i, 32), i % 3))
    # phase B: del every 4th (some miss the memtable after flushes)
    for i in range(0, 120, 4):
        parts.append(del_rec(lcg_bytes(0xA100 + i, 32), i % 3))
    parts.append(rec(4))
    # gets: deleted keys absent, survivors present
    for i in (0, 4, 8, 1, 2, 119):
        parts.append(get_rec(lcg_bytes(0xA100 + i, 32), i % 3))
    # phase C: reload (rebuild from manifest + WAL)
    parts.append(rec(6))
    parts.append(rec(4))
    for i in (0, 4, 5, 119):
        parts.append(get_rec(lcg_bytes(0xA100 + i, 32), i % 3))
    # phase D: more puts (new generation), then flush
    for i in range(120, 150):
        txid = lcg_bytes(0xA100 + i, 32)
        script = lcg_bytes(0xB100 + i, 30)
        parts.append(put_rec(txid, 0, 5000 + i, 500 + i, 0, script))
    parts.append(rec(5))                          # explicit flush
    parts.append(rec(4))
    # phase E: compaction
    parts.append(rec(7))
    parts.append(rec(4))
    for i in (0, 60, 100, 130, 149):
        parts.append(get_rec(lcg_bytes(0xA100 + i, 32), i % 3))
    # phase F: reload after compaction
    parts.append(rec(6))
    parts.append(rec(4))
    for i in (0, 60, 130, 149):
        parts.append(get_rec(lcg_bytes(0xA100 + i, 32), 0))
    parts.append(rec(8))                          # close

    with open(sys.argv[1] if len(sys.argv) > 1 else "dlsm_vecs.bin", "wb") as f:
        f.write(b"".join(parts))
    print(f"{len(parts)} records")


if __name__ == "__main__":
    main()
