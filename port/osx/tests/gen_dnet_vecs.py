#!/usr/bin/env python3
"""gen_dnet_vecs.py -- deterministic p2p_frame vectors for dnet.c.

Record: u32 cmdlen | u32 plen | cmd bytes | payload bytes (LE u32s).
Payloads come from a per-record LCG so both arches read identical bytes from
the same vectors file; cmd lengths deliberately straddle the 12-byte command
field (0..16) and payload lengths straddle the drain/boundary shapes used in
past net bugs (55/56/63/64/65, 127/128/129, plus one P2P_MAX_MSG frame).
"""
import struct
import sys

CMDS = [b"verack", b"version", b"getheaders", b"ping", b"pong", b"headers",
        b"block", b"inv", b"getdata", b"tx", b"reject", b"sendcmpct",
        b"addr", b"feeler"]

MAX_MSG = 4_000_000


def lcg_bytes(seed, n):
    out = bytearray(n)
    x = seed & 0xFFFFFFFFFFFFFFFF
    for i in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out[i] = (x >> 33) & 0xFF
    return bytes(out)


def rec(cmd, payload):
    return (struct.pack("<II", len(cmd), len(payload)) + cmd + payload)


def main():
    parts = []
    i = 0
    # fixed boundary lens, cycling cmds, cmd lens 0..16 (12 is the field width)
    lens = [0, 1, 2, 11, 12, 13, 24, 55, 56, 63, 64, 65, 127, 128, 129,
            255, 256, 1000, 4095, 4096, 65535]
    for plen in lens:
        cmd = CMDS[i % len(CMDS)]
        parts.append(rec(cmd, lcg_bytes(0x5EED0000 + i, plen)))
        i += 1
    # cmd-length sweep 0..16 against a mid-size payload (truncation at 12)
    for cmdlen in range(17):
        cmd = lcg_bytes(0xC7D0000 + cmdlen, cmdlen)
        parts.append(rec(cmd, lcg_bytes(0xA11CE000 + cmdlen, 300)))
        i += 1
    # 200 pseudo-random mid-size frames
    x = 0xDEADBEEF
    for _ in range(200):
        x = (x * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        plen = (x >> 33) % 5000
        cmd = CMDS[x % len(CMDS)]
        parts.append(rec(cmd, lcg_bytes(x, plen)))
        i += 1
    # the P2P_MAX_MSG boundary shapes (the x86 framer has no length gate,
    # but the frame builder itself must handle the max message)
    parts.append(rec(b"block", lcg_bytes(0x4000000, MAX_MSG)))
    parts.append(rec(b"block", lcg_bytes(0x4000001, MAX_MSG - 1)))

    with open(sys.argv[1] if len(sys.argv) > 1 else "dnet_vecs.bin", "wb") as f:
        f.write(b"".join(parts))
    print(f"{i + 2} records, {sum(len(p) for p in parts)} bytes")


if __name__ == "__main__":
    import sys
    main()
