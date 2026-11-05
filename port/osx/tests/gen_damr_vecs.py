#!/usr/bin/env python3
"""gen_damr_vecs.py -- deterministic bitcoin_addrmgr differential vectors.

Record stream (matches damr.c): u32 op | u32 a | u32 b | body.
Covers: amr_init/add(new+dup+rewrite-order)/get_i/lookup/count, the codecs
(v1/v2 over 1..300 records incl. services CompactSize edges fd/fe), and
p2p_addr_count over valid/truncated/varint shapes.
"""
import struct
import sys

def rec(op, a=0, body=b"", b=None):
    return struct.pack("<III", op, a, len(body) if b is None else b) + body


def rec18(ip, port_be, services, lastseen):
    return struct.pack("<IHI", ip, port_be, 0) + struct.pack("<QI", services, lastseen)


def lcg_bytes(seed, n):
    out = bytearray(n)
    x = seed & 0xFFFFFFFFFFFFFFFF
    for i in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out[i] = (x >> 33) & 0xFF
    return bytes(out)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "damr_vecs.bin"
    parts = []
    parts.append(rec(0))                                             # init

    # book ops: adds with new/dup/dup-after-close cycles
    ips = [0x04030201, 0x08070605, 0x0A0B0C0D, 0xC8000102, 0x7F000001]
    for i, ip in enumerate(ips):
        parts.append(rec(1, ip, struct.pack("<IIQ", 0x8D20, 1700000000 + i, 1 + i * 0x408)))
        parts.append(rec(1, ip, struct.pack("<IIQ", 0x8D21, 1700000100 + i, 9)))  # dup
    # get_i over every index + 2 out-of-range
    for i in range(len(ips) + 2):
        parts.append(rec(2, i))
    # lookups: every ip + misses
    for ip in ips + [0x01010101, 0xFFFFFFFF]:
        parts.append(rec(3, ip))
    parts.append(rec(4))                                             # count
    parts.append(rec(5))                                             # close

    # codecs over n = 1..8, 63, 64, 252, 253, 300 records
    for n in list(range(1, 9)) + [63, 64, 252, 253, 300]:
        recs = b"".join(
            rec18(0x01000000 + k, 0x8D20, (k * 7919) & 0xFFFFFFFFFFFF, 1700000000 + k)
            for k in range(n))
        parts.append(rec(6, n, recs))
        parts.append(rec(7, n, recs))
    # services CompactSize edges (253 -> fd, 0x10000 -> fe, 0xffffffff -> fe)
    for svc in (252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000):
        recs = rec18(0x01020304, 0x208D, svc, 7)
        parts.append(rec(6, 1, recs))
        parts.append(rec(7, 1, recs))

    # p2p_addr_count shapes: build a v1 payload then vary plen
    n = 4
    recs = b"".join(rec18(0x0A000000 + k, 0x8D20, 1, 1700000000 + k) for k in range(n))
    parts.append(rec(6, n, recs))                                    # (stream filler)
    v1 = bytes([n]) + b"".join(
        struct.pack("<I", 1700000000 + k) + struct.pack("<Q", 1) +
        b"\x00" * 10 + b"\xff\xff" + struct.pack("<I", 0x0A000000 + k) +
        struct.pack("<H", 0x8D20)
        for k in range(n))
    parts.append(rec(8, len(v1), v1))                                # valid
    parts.append(rec(8, len(v1) - 1, v1))                            # short -> -1
    fd_pay = b"\xfd\x2c\x01" + v1[1:] + b"\x00" * 30                 # fd count shape
    parts.append(rec(8, len(fd_pay), fd_pay))
    fe_pay = b"\xfe\x03\x00\x00\x00" + v1[1:]                        # fe count shape
    parts.append(rec(8, len(fe_pay), fe_pay))
    ff_pay = b"\xff\x03\x00\x00\x00\x00\x00\x00\x00" + v1[1:]        # ff count shape
    parts.append(rec(8, len(ff_pay), ff_pay))
    parts.append(rec(8, 0, b""))                                     # empty -> -1
    parts.append(rec(8, 1, b"\xfd"))                                 # fd short -> -1

    with open(path, "wb") as f:
        f.write(b"".join(parts))
    print(f"{sum(1 for _ in range(len(parts)))} records, {sum(len(p) for p in parts)} bytes")


if __name__ == "__main__":
    main()
