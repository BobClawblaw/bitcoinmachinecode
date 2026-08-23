#!/usr/bin/env python3
"""gen_schnorr_diff_vectors.py -- BIP340 differential corpus, verdicts from Core.

WHY THIS EXISTS
  asm/secp256k1_schnorr.asm was rewritten on 2026-08-23 (PERF_SCOPE.md 13):
  s*G moved to the fixed-base G comb, e*P to the GLV + wNAF ladder, and the
  final x(R) == r test became projective (r*Z^2 == X mod p) so that the only
  surviving field inversion is the one the even-Y test genuinely needs. Every
  one of those changes can be wrong in a way the 19 official BIP340 vectors do
  not reach -- in particular the two REJECT branches, "x(R) matches but y(R) is
  odd" and "R is the point at infinity", which are the branches a fast path is
  most likely to skip.

  So this builds a corpus that hits those branches on purpose, and takes the
  expected verdict from BITCOIN CORE -- libsecp256k1's
  secp256k1_schnorrsig_verify, via XOnlyPubKey::VerifySchnorr, through the
  SCHNORR command in validation/core_verify_oracle.cpp -- never from this
  project's own previous answer.

  The signature CONSTRUCTION here is a small independent pure-Python
  implementation of BIP340 written from the specification, not a call into
  libsecp256k1 and not a port of anything in this repo. That matters: if the
  constructor and the verifier shared code, a shared misunderstanding would
  cancel out. Core is the arbiter of every verdict either way.

THE CLASSES, and why each one is here
  valid          a correct signature. The baseline; ~40 % of the corpus.
  oddy           R has x(R) == r but y(R) ODD. Constructed by signing WITHOUT
                 BIP340's "negate k if y(R) is odd" normalisation: for a random
                 nonce k, y(k*G) is odd half the time, and the resulting (r, s)
                 reaches the verifier's parity test with everything else
                 correct. This is the single most important negative class for
                 this rewrite and no official vector covers it in bulk.
  infinity       s*G - e*P is the point at infinity. Constructed by choosing r
                 freely, computing e = H(r || pk || m), and setting s = e*d mod
                 n; then s*G = e*(d*G) = e*P exactly. secp256k1 has prime
                 order, so the point at infinity IS the whole "small order"
                 story -- there is no non-trivial small subgroup to test.
  nolift         pk is a 32-byte value that is NOT the x-coordinate of any
                 curve point (x^3 + 7 is not a quadratic residue). lift_x must
                 fail before any arithmetic happens.
  pk_ge_p        pk >= p, including pk == p and pk == 2^256-1.
  pk_zero        pk == 0 (x = 0 is not on secp256k1).
  s_ge_n         s >= n, including s == n and s == n+1 and s == 2^256-1.
  r_ge_p         r >= p, including r == p exactly.
  bitflip        a valid signature with exactly one bit flipped, in r, in s, in
                 the message or in the public key. Spread across all four so a
                 fast path that ignores one of its inputs is caught.
  s_zero         s == 0 (allowed by the range check; R is then -e*P).
  r_zero         r == 0 (a field element, and 0 is not an x-coordinate on this
                 curve, so this must reject at the x compare, not earlier).

USAGE
  python3 asm/validation/gen_schnorr_diff_vectors.py \
      --oracle /path/to/core_verify_oracle [--count N] [--seed S] \
      > asm/tests/schnorr_diff_vec.h

  --check-only prints a summary instead of the header, and is what the bulk
  out-of-tree run (millions of cases) uses.
"""
import argparse
import hashlib
import os
import subprocess
import sys

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


# ---------------------------------------------------------------------------
# secp256k1 in affine coordinates. Small and slow on purpose: this is the
# reference, its only job is to be obviously right.
# ---------------------------------------------------------------------------
def inv(a):
    return pow(a, P - 2, P)


def add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = 3 * x1 * x1 % P * inv(2 * y1) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _jdbl(Q):
    X, Y, Z = Q
    if Y == 0:
        return (0, 0, 0)
    A = X * X % P
    B = Y * Y % P
    C = B * B % P
    D = 2 * ((X + B) ** 2 - A - C) % P
    E = 3 * A % P
    F = E * E % P
    X3 = (F - 2 * D) % P
    Y3 = (E * (D - X3) - 8 * C) % P
    Z3 = 2 * Y * Z % P
    return (X3, Y3, Z3)


def _jadd_affine(Q, p2):
    """Jacobian + affine. p2 must not be None."""
    X1, Y1, Z1 = Q
    if Z1 == 0:
        return (p2[0], p2[1], 1)
    x2, y2 = p2
    Z1Z1 = Z1 * Z1 % P
    U2 = x2 * Z1Z1 % P
    S2 = y2 * Z1 % P * Z1Z1 % P
    if U2 == X1:
        return _jdbl(Q) if S2 == Y1 else (0, 0, 0)
    H = (U2 - X1) % P
    R = (S2 - Y1) % P
    HH = H * H % P
    HHH = H * HH % P
    V = X1 * HH % P
    X3 = (R * R - HHH - 2 * V) % P
    Y3 = (R * (V - X3) - Y1 * HHH) % P
    Z3 = Z1 * H % P
    return (X3, Y3, Z3)


def mul(p, k):
    """k*p, Jacobian internally so the whole multiply costs ONE inversion."""
    k %= N
    if k == 0 or p is None:
        return None
    Q = (0, 0, 0)
    for bit in reversed(range(k.bit_length())):
        Q = _jdbl(Q) if Q[2] else Q
        if (k >> bit) & 1:
            Q = _jadd_affine(Q, p)
    X, Y, Z = Q
    if Z == 0:
        return None
    zi = inv(Z)
    z2 = zi * zi % P
    return (X * z2 % P, Y * z2 % P * zi % P)


G = (GX, GY)


def lift_x(x):
    """BIP340 lift_x: the point with this x and EVEN y, or None."""
    if x >= P:
        return None
    c = (pow(x, 3, P) + 7) % P
    y = pow(c, (P + 1) // 4, P)
    if pow(y, 2, P) != c:
        return None
    return (x, y if y % 2 == 0 else P - y)


def tagged(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def b32(x):
    return x.to_bytes(32, "big")


def challenge(r_bytes, pk_bytes, msg):
    return int.from_bytes(tagged("BIP0340/challenge", r_bytes + pk_bytes + msg), "big") % N


def pubkey(d):
    Pt = mul(G, d)
    return b32(Pt[0]), Pt


def sign(d, msg, k, normalise=True):
    """BIP340 sign with an EXPLICIT nonce.

    normalise=True  -> the real BIP340 rule (negate d if P has odd y, negate k
                       if R has odd y): produces a valid signature.
    normalise=False -> skip only the k negation, so R keeps whatever parity it
                       happened to have. When y(R) is odd this is the 'oddy'
                       class: everything checks out except the parity test.
    """
    Pt = mul(G, d)
    dd = d if Pt[1] % 2 == 0 else N - d
    R = mul(G, k)
    kk = k
    if normalise and R[1] % 2 != 0:
        kk = N - k
        R = (R[0], P - R[1])
    pk = b32(Pt[0])
    e = challenge(b32(R[0]), pk, msg)
    s = (kk + e * dd) % N
    return pk, b32(R[0]) + b32(s)


# ---------------------------------------------------------------------------
# corpus construction
# ---------------------------------------------------------------------------
class Rng:
    """splitmix64 -- deterministic, so a failing case is reproducible."""

    def __init__(self, seed):
        self.s = seed & 0xFFFFFFFFFFFFFFFF

    def u64(self):
        self.s = (self.s + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = self.s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
        return z ^ (z >> 31)

    def u256(self):
        v = 0
        for _ in range(4):
            v = (v << 64) | self.u64()
        return v

    def scalar(self):
        return (self.u256() % (N - 1)) + 1

    def bytes32(self):
        return b32(self.u256())


def build(count, seed):
    rng = Rng(seed)
    cases = []          # (cls, pk, msg, sig)

    def emit(cls, pk, msg, sig):
        cases.append((cls, pk, msg, sig))

    # ---- valid, and its odd-Y twin, from the same nonce family ----
    nvalid = max(1, count * 40 // 100)
    for _ in range(nvalid):
        d = rng.scalar()
        m = rng.bytes32()
        k = rng.scalar()
        pk, sig = sign(d, m, k, normalise=True)
        emit("valid", pk, m, sig)

    noddy = max(1, count * 15 // 100)
    made = 0
    while made < noddy:
        d = rng.scalar()
        m = rng.bytes32()
        k = rng.scalar()
        if mul(G, k)[1] % 2 == 0:
            continue                      # that one would be valid
        pk, sig = sign(d, m, k, normalise=False)
        emit("oddy", pk, m, sig)
        made += 1

    # ---- R = infinity : choose r freely, then s = e*d mod n ----
    for i in range(max(1, count * 5 // 100)):
        d = rng.scalar()
        m = rng.bytes32()
        pk, Pt = pubkey(d)
        dd = d if Pt[1] % 2 == 0 else N - d
        r_bytes = b32(0) if i == 0 else rng.bytes32()
        e = challenge(r_bytes, pk, m)
        s = (e * dd) % N
        emit("infinity", pk, m, r_bytes + b32(s))

    # ---- pk that does not lift ----
    made = 0
    while made < max(1, count * 8 // 100):
        x = rng.u256() % P
        if lift_x(x) is not None:
            continue
        emit("nolift", b32(x), rng.bytes32(), b32(rng.u256() % P) + b32(rng.scalar()))
        made += 1

    # ---- pk out of range / zero ----
    for x in (P, P + 1, 2**256 - 1, P + 0x1000003D0):
        emit("pk_ge_p", b32(x % 2**256), rng.bytes32(), b32(rng.u256() % P) + b32(rng.scalar()))
    emit("pk_zero", b32(0), rng.bytes32(), b32(rng.u256() % P) + b32(rng.scalar()))

    # ---- s >= n, on an OTHERWISE VALID signature (so only that check can reject)
    for delta in (0, 1, 2, 0x10000):
        d = rng.scalar()
        m = rng.bytes32()
        pk, sig = sign(d, m, rng.scalar())
        emit("s_ge_n", pk, m, sig[:32] + b32((N + delta) % 2**256))
    d = rng.scalar(); m = rng.bytes32()
    pk, sig = sign(d, m, rng.scalar())
    emit("s_ge_n", pk, m, sig[:32] + b32(2**256 - 1))

    # ---- r >= p, likewise ----
    for delta in (0, 1, 0x1000003D0):
        d = rng.scalar()
        m = rng.bytes32()
        pk, sig = sign(d, m, rng.scalar())
        emit("r_ge_p", pk, m, b32((P + delta) % 2**256) + sig[32:])
    d = rng.scalar(); m = rng.bytes32()
    pk, sig = sign(d, m, rng.scalar())
    emit("r_ge_p", pk, m, b32(2**256 - 1) + sig[32:])

    # ---- s == 0 and r == 0 ----
    for _ in range(3):
        d = rng.scalar(); m = rng.bytes32()
        pk, sig = sign(d, m, rng.scalar())
        emit("s_zero", pk, m, sig[:32] + b32(0))
        emit("r_zero", pk, m, b32(0) + sig[32:])

    # ---- single-bit flips, spread over r / s / msg / pk ----
    nflip = max(4, count * 32 // 100)
    for i in range(nflip):
        d = rng.scalar()
        m = rng.bytes32()
        pk, sig = sign(d, m, rng.scalar())
        where = i & 3
        bit = rng.u64() % 256
        if where == 0:
            b = bytearray(sig); b[bit // 8] ^= 1 << (bit % 8); emit("bitflip", pk, m, bytes(b))
        elif where == 1:
            b = bytearray(sig); off = 32 + bit // 8; b[off] ^= 1 << (bit % 8); emit("bitflip", pk, m, bytes(b))
        elif where == 2:
            b = bytearray(m); b[bit // 8] ^= 1 << (bit % 8); emit("bitflip", pk, bytes(b), sig)
        else:
            b = bytearray(pk); b[bit // 8] ^= 1 << (bit % 8); emit("bitflip", bytes(b), m, sig)

    return cases


def core_verdicts(oracle, cases, chunk=20000):
    """One Core verdict per case, via the SCHNORR command."""
    out = []
    for i in range(0, len(cases), chunk):
        part = cases[i:i + chunk]
        lines = ["SCHNORR %s %s %s" % (pk.hex(), msg.hex(), sig.hex())
                 for _, pk, msg, sig in part]
        lines.append("QUIT")
        res = subprocess.run([oracle], input="\n".join(lines) + "\n",
                             capture_output=True, text=True)
        got = [l for l in res.stdout.strip().split("\n") if l.startswith("OK ")]
        if len(got) != len(part):
            sys.exit("oracle returned %d lines for %d cases:\n%s"
                     % (len(got), len(part), res.stderr[:2000]))
        out.extend(1 if l.split()[1] == "1" else 0 for l in got)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--count", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=20260823)
    ap.add_argument("--check-only", action="store_true")
    a = ap.parse_args()

    cases = build(a.count, a.seed)
    verds = core_verdicts(a.oracle, cases)

    by = {}
    for (cls, _, _, _), v in zip(cases, verds):
        d = by.setdefault(cls, [0, 0])
        d[v] += 1

    if a.check_only:
        print("%d cases" % len(cases))
        for cls in sorted(by):
            print("  %-9s %6d  core-accept %d / core-reject %d"
                  % (cls, sum(by[cls]), by[cls][1], by[cls][0]))
        return 0

    w = sys.stdout.write
    w("/* schnorr_diff_vec.h -- GENERATED by validation/gen_schnorr_diff_vectors.py\n")
    w(" * DO NOT EDIT. Regenerate with:\n")
    w(" *   python3 validation/gen_schnorr_diff_vectors.py --oracle <core_verify_oracle> \\\n")
    w(" *       --count %d --seed %d > tests/schnorr_diff_vec.h\n" % (a.count, a.seed))
    w(" *\n")
    w(" * Every `want` below is BITCOIN CORE's verdict (libsecp256k1\n")
    w(" * secp256k1_schnorrsig_verify, through XOnlyPubKey::VerifySchnorr and the\n")
    w(" * SCHNORR command in validation/core_verify_oracle.cpp) -- not this\n")
    w(" * project's. Class counts in this file:\n")
    for cls in sorted(by):
        w(" *   %-9s %6d   (core accepts %d, rejects %d)\n"
          % (cls, sum(by[cls]), by[cls][1], by[cls][0]))
    w(" */\n#ifndef SCHNORR_DIFF_VEC_H\n#define SCHNORR_DIFF_VEC_H\n\n")
    w("/* pk, msg and sig are lowercase hex: 64, 64 and 128 characters. */\n")
    w("typedef struct { const char* cls; const char* pk; const char* msg; const char* sig; int want; } schnorr_diff_t;\n\n")
    w("static const schnorr_diff_t SCHNORR_DIFF[] = {\n")
    for (cls, pk, msg, sig), v in zip(cases, verds):
        w('{"%s","%s","%s","%s",%d},\n' % (cls, pk.hex(), msg.hex(), sig.hex(), v))
    w("};\n")
    w("#define SCHNORR_DIFF_N ((int)(sizeof(SCHNORR_DIFF)/sizeof(SCHNORR_DIFF[0])))\n")
    w("\n#endif\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
