#!/usr/bin/env python3
"""gen_duxst_vecs.py -- deterministic bitcoin_utxo_store differential vectors.

Record stream (matches duxst.c). Shapes: WAL puts/dels with script sizes
0/1/24/255/320/1690 (the 320+ frame-overflow regression), puts/dels/gets
over multiple txids/indexes, count, sync (checkpoint publish), reload
(full WAL + checkpoint+tail), close, re-init, torn-tail bytes appended
raw? (not expressible as ops -- covered by upstream test_utxo_torn_tail
natively on both arches).
"""
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
    parts.append(rec(0))                                      # init
    # 40 puts, varying scripts incl. boundary sizes
    script_lens = [0, 1, 24, 255, 320, 1690, 0, 24] * 5      # 40 puts
    for i, slen in enumerate(script_lens):
        txid = lcg_bytes(0x7100 + i, 32)
        script = lcg_bytes(0x9100 + i, slen)
        parts.append(put_rec(txid, i % 4, 1000 + i, 100 + i, i % 2, script))
    parts.append(rec(4))                                      # count
    # gets: hit every 5th, miss 5
    for i in range(0, 40, 5):
        parts.append(get_rec(lcg_bytes(0x7100 + i, 32), i % 4))
    for i in range(40, 45):
        parts.append(get_rec(lcg_bytes(0x7100 + i, 32), 0))
    # del every 3rd
    for i in range(0, 40, 3):
        parts.append(del_rec(lcg_bytes(0x7100 + i, 32), i % 4))
    parts.append(rec(4))                                      # count
    # full-WAL reload (no checkpoint): re-init + reload
    parts.append(rec(7))                                      # close
    parts.append(rec(0))                                      # init
    parts.append(rec(6))                                      # reload
    parts.append(rec(4))                                      # count
    # gets after replay (values/heights/cb/scripts survive)
    for i in (0, 1, 2, 10, 39):
        parts.append(get_rec(lcg_bytes(0x7100 + i, 32), i % 4))
    # checkpoint + tail
    parts.append(rec(5))                                      # sync
    for i in range(40, 50):
        txid = lcg_bytes(0x7100 + i, 32)
        script = lcg_bytes(0x9100 + i, (i * 37) % 300)
        parts.append(put_rec(txid, i % 4, 2000 + i, 200 + i, i % 2, script))
    for i in range(41, 50, 2):
        parts.append(del_rec(lcg_bytes(0x7100 + i, 32), i % 4))
    parts.append(rec(8))                                      # wal_drain
    # checkpoint+tail reload
    parts.append(rec(7))                                      # close
    parts.append(rec(0))                                      # init
    parts.append(rec(6))                                      # reload
    parts.append(rec(4))                                      # count
    for i in (0, 39, 40, 44, 49):
        parts.append(get_rec(lcg_bytes(0x7100 + i, 32), i % 4))
    # second sync, then more tail, then reload again
    parts.append(rec(5))                                      # sync
    for i in range(50, 60):
        txid = lcg_bytes(0x7100 + i, 32)
        parts.append(put_rec(txid, 0, 3000 + i, 300 + i, 0, lcg_bytes(0x9500 + i, 20)))
    parts.append(rec(7))
    parts.append(rec(0))
    parts.append(rec(6))
    parts.append(rec(4))
    for i in (49, 55, 59):
        parts.append(get_rec(lcg_bytes(0x7100 + i, 32), 0))
    parts.append(rec(7))                                      # close

    with open(sys.argv[1] if len(sys.argv) > 1 else "duxst_vecs.bin", "wb") as f:
        f.write(b"".join(parts))
    print(f"{len(parts)} records")


if __name__ == "__main__":
    main()
