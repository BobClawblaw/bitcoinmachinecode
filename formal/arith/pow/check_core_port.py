"""Cross-check core_port.h (the C port of Core used as the reference by the
CBMC harnesses and the differential driver) against an independent Python
big-integer transcription of the same Core functions. Reads `diff_pow dump N`.
A transcription error in either one shows up as a mismatch here."""
import sys

M = 1 << 256


def set_compact(c):
    size = c >> 24
    word = c & 0x7FFFFF
    if size <= 3:
        word >>= 8 * (3 - size)
        t = word
    else:
        t = (word << (8 * (size - 3))) % M
    neg = word != 0 and (c & 0x800000) != 0
    ovf = word != 0 and (size > 34 or (word > 0xFF and size > 33) or (word > 0xFFFF and size > 32))
    return t, neg, ovf


def get_compact(t):
    size = (t.bit_length() + 7) // 8
    if size <= 3:
        c = (t << 8 * (3 - size)) & 0xFFFFFFFFFFFFFFFF
    else:
        c = (t >> 8 * (size - 3)) & 0xFFFFFFFFFFFFFFFF
    c &= 0xFFFFFFFF
    if c & 0x800000:
        c >>= 8
        size += 1
    assert c & ~0x7FFFFF == 0 and size < 256
    return c | (size << 24)


def block_proof(c):
    t, neg, ovf = set_compact(c)
    if neg or ovf or t == 0:
        return 0
    return ((M - 1 - t) // (t + 1) + 1) % M


LIM = {0x1D00FFFF: int("00000000" + "ff" * 28, 16), 0x1E0377AE: 0x377AE << 216}


def next_work(b, ts, lb):
    T = 14 * 24 * 3600
    ts = max(ts, T // 4)
    ts = min(ts, T * 4)
    t, _, _ = set_compact(b)
    t = (t * (ts & 0xFFFFFFFF)) % M
    t //= T
    if t > LIM[lb]:
        t = LIM[lb]
    return get_compact(t)


n = bad = 0
for line in sys.stdin:
    f = line.split()
    b = int(f[0], 16)
    t, neg, ovf = set_compact(b)
    ok = (int(f[1]) == neg and int(f[2]) == ovf and int(f[3], 16) == t
          and int(f[4], 16) == block_proof(b)
          and int(f[6], 16) == get_compact(int(f[5], 16))
          and int(f[9], 16) == next_work(b, int(f[7]), int(f[8], 16)))
    n += 1
    if not ok:
        bad += 1
        if bad < 5:
            print("MISMATCH", line.strip())
print(f"[port] core_port.h vs Python big-int Core: {n} vectors, {bad} mismatches")
sys.exit(1 if bad or n == 0 else 0)
