#!/usr/bin/env python3
"""gen_dp2p_vecs.py -- deterministic bitcoin_p2p differential vectors.

Output record stream (matches dp2p.c): u32 op | u32 a | u32 b | body.

  op 0 getheaders:      a=count, b=body len, body=count*32 locator+32 stop
  op 1 getdata:         a=0, b=32, body=32 hash
  op 2 ping:            a=nonce_lo, b=nonce_hi, body=empty
  op 3 headers_count:   a=plen, b=plen, body=plen bytes
  op 4 inv_count:       a=plen, b=plen, body=plen bytes
  op 5 inv_get:         a=index, b=plen, body=plen bytes

Semantics cross-checked against asm/validation/p2p_oracle.py conventions:
version 70016 LE, MSG_WITNESS_BLOCK inventory type, CompactSize rules.
"""
import struct
import sys

PROTOCOL_VER = 70016

ops = []  # (op, a:int, b:int, body:bytes)


def rec(op, a, body=b"", b=None):
    """b defaults to the body length; op 2 passes the nonce hi half as b."""
    ops.append((op, a & 0xFFFFFFFF, (len(body) if b is None else b) & 0xFFFFFFFF, body))


def lcg_bytes(seed, n):
    out = bytearray(n)
    x = seed & 0xFFFFFFFFFFFFFFFF
    for i in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out[i] = (x >> 33) & 0xFF
    return bytes(out)


def headers_shape(count, varint=0):
    """headers_count-shaped payload: version + count varint + count*81 bytes"""
    if varint == 0:
        cnt = bytes([count])
    else:
        cnt = b"\xfd" + struct.pack("<H", count)
    return struct.pack("<I", PROTOCOL_VER) + cnt + lcg_bytes(0x81C0 + count, count * 81)


def inv_shape(items, varint=0):
    out = bytearray()
    if varint == 0:
        out.append(items)
    elif varint == 1:
        out += b"\xfd" + struct.pack("<H", items)
    else:
        out += b"\xfe" + struct.pack("<I", items)
    for i in range(items):
        out += struct.pack("<I", 2 + i * 7)
        out += bytes((i * 11 + k * 3) & 0xFF for k in range(32))
    return bytes(out)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "dp2p_vecs.bin"
    x = 0x5EEDC0DE

    # ---- op 0: getheaders over counts 1..252 + negatives ----
    for count in list(range(1, 30)) + [63, 64, 100, 251, 252]:
        rec(0, count, lcg_bytes(0x10C0 + count, count * 32) + lcg_bytes(0x57C0, 32))
    for bad in (0, 253, 255, 300, 0xFFFFFFFF):
        rec(0, bad, lcg_bytes(0x11D0, 32) + lcg_bytes(0x57D0, 32))

    # ---- op 1: getdata over random hashes ----
    for i in range(30):
        rec(1, 0, lcg_bytes(0xDA7A0000 + i, 32))

    # ---- op 2: ping nonces ----
    for i in range(20):
        x = (x * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        rec(2, x & 0xFFFFFFFF, b=(x >> 32) & 0xFFFFFFFF)

    # ---- op 3: headers_count ----
    rec(3, 1, b"\x00")                                      # 0 headers
    rec(3, 163, b"\x02" + b"\x00" * 162)                    # 2 headers
    rec(3, 100, b"\x02" + b"\x00" * 99)                     # truncated -> -1
    rec(3, 0, b"")                                          # empty -> -1
    rec(3, 246, b"\xfd\x03\x00" + b"\x00" * 243)            # fd varint, 3
    rec(3, 2, b"\xfd\x03")                                  # fd varint short -> -1
    rec(3, 246, b"\xfc" + b"\x00" * 245)                    # 0xfc = 1-byte 252
    rec(3, 246, b"\xfe\x03\x00\x00\x00" + b"\x00" * 241)    # 0xfe -> -1
    rec(3, 246, b"\xff\x03\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 237)  # 0xff -> -1
    for count in (1, 2, 40, 252):
        pay = headers_shape(count)
        rec(3, len(pay), pay)                               # valid
        rec(3, len(pay) - 1, pay)                           # one short -> -1
    for count in (253, 300, 1000):
        pay = headers_shape(count, varint=1)
        rec(3, len(pay), pay)                               # fd-varint shapes
        rec(3, len(pay) - 1, pay)

    # ---- op 4: inv_count ----
    for items, v in ((0, 0), (1, 0), (3, 0), (100, 0), (252, 0), (300, 1), (1000, 1)):
        pay = inv_shape(items, v)
        rec(4, len(pay), pay)
    rec(4, 46, inv_shape(3, 0)[:46])                        # truncated -> -1
    rec(4, 5 + 2 * 36, inv_shape(2, 2))                     # 0xfe -> -1
    rec(4, 0, b"")                                          # empty -> -1
    rec(4, 2, b"\xfd\x03")                                  # fd varint short -> -1

    # ---- op 5: inv_get ----
    pay = inv_shape(3, 0)
    for i in range(4):                                      # 3 valid + 1 out of range
        rec(5, i, pay)
    rec(5, 0, inv_shape(300, 1))                            # fd varint path
    rec(5, 300, inv_shape(300, 1))                          # out of range
    rec(5, 0, inv_shape(2, 2))                              # 0xfe -> 0

    with open(path, "wb") as f:
        for op, a, b, body in ops:
            f.write(struct.pack("<III", op, a, b) + body)
    print(f"{len(ops)} records, {sum(len(body) for *_, body in ops)} body bytes")


if __name__ == "__main__":
    main()
