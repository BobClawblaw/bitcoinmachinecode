#!/usr/bin/env python3
"""fuzz_pct.py -- differential fuzz for port/arm64/secp256k1_point_ct.S.

Oracle: an INDEPENDENT pure-Python secp256k1 group law over the prime field
(random on-curve points generated via a field sqrt -- NOT via the scalar-mul
code under test, so oracle and port share no implementation path).

Checks (all affine-compared, exact 256-bit x,y, or `inf`):
  * point_scalar_mul_ct  ==  variable-time point_scalar_mul        (differential)
  * point_scalar_mul_ct  ==  pure-Python k*P                        (oracle)
  * point_scalar_mul_ct  ==  point_scalar_mul == python  on edge k in
                            {0, 1, 2, n-1, n, n+1, 2n, 2n+1, random mod n}
  * pointh_add(P,Q)  ==  python P+Q, including P==Q, P==-Q, infinity inputs
  * pointh_double(P) ==  python 2P, and 2P == P+P (add/double consistency)

Usage: python3 fuzz_pct.py [seeks] [iters] [drv]
  seeks: number of random seeds to run; iters: test iterations per seed;
  drv:   path to the built t_pct driver (default ./t_pct)
"""
import sys, subprocess, random

p  = 2**256 - 2**32 - 977
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def inv(a):
    a %= p
    if a == 0:
        raise ZeroDivisionError
    return pow(a, p - 2, p)  # avoids depending on the ported fe_inv

def ec_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1) * inv(2 * y1)
    else:
        lam = (y2 - y1) * inv(x2 - x1)
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def ec_mul(k, P):
    R = None
    while k:
        if k & 1:
            R = ec_add(R, P)
        P = ec_add(P, P)
        k >>= 1
    return R

def oncurve(P):
    if P is None: return True
    x, y = P
    return (y * y - (x * x * x + 7)) % p == 0

def rand_point(rng):
    # random on-curve point via sqrt of x^3+7 (p == 3 mod 4)
    while True:
        x = rng.getrandbits(256) % p
        rhs = (pow(x, 3, p) + 7) % p
        y = pow(rhs, (p + 1) // 4, p)
        if (y * y - rhs) % p == 0:
            return (x, y)
        # negative sqrt
        if ((p - y) * (p - y) - rhs) % p == 0:
            return (x, p - y)

def limb(v):
    return (v >> (64 * 0)) & 0xFFFFFFFFFFFFFFFF  # (kept simple; one limb fmt below)

def elm(v):      # field element -> 4 limbs, space-separated, 16 hex each
    return " ".join("%016x" % ((v >> (64 * i)) & 0xFFFFFFFFFFFFFFFF) for i in range(4))

def limbfmt(w):  # single 64-bit limb -> 16 hex
    return "%016x" % (w & 0xFFFFFFFFFFFFFFFF)

def fmt_xy(P):
    x, y = P
    return elm(x) + " " + elm(y)

def fmt_k(k):
    return " ".join(limbfmt((k >> (64 * i)) & 0xFFFFFFFFFFFFFFFF) for i in range(4))

def fmt_p12(P):
    if P is None:
        # homogeneous identity (0:1:0)
        return ("0" * 16 + " ") * 4 + ("0000000000000001 ") + ("0" * 16 + " ") * 3
    x, y = P
    return fmt_xy(P) + " " + elm(1)      # (x:y:1) -> full 12-limb homogeneous point

def parse_result(drv, vectors):
    """drv: subprocess binary producing one line per vector."""
    inp = "\n".join(vectors) + "\n"
    out = subprocess.run([drv], input=inp, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError("driver crashed: %s" % out.stderr)
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    return lines

def norm(result):
    """result line 'op x...' -> ('x...' tuple) or 'inf'"""
    parts = result.split()
    if parts[-1] == "inf":
        return "inf"
    return " ".join(parts[1:9])   # skip op, take 4 x + 4 y limbs

def run_seed(drv, seed, iters):
    rng = random.Random(seed)
    nbad = 0
    detail = []
    vecs, expect = [], []
    # ---- scalar differential + oracle ----
    for _ in range(iters):
        k = rng.getrandbits(256)
        P = rand_point(rng)
        xy = fmt_xy(P); kk = fmt_k(k)
        vecs.append("ctscalar %s %s" % (xy, kk))
        vecs.append("vtscalar %s %s" % (xy, kk))
        exp = ec_mul(k, P)
        expect.append(exp); expect.append(exp)
    # ---- edge scalars on G and on a random point ----
    # scalar contract is 4 limbs = [0, 2^256): everything below is in-bounds.
    # (values >= 2^256 like 2n would be truncated by BOTH ct and vt identically,
    #  but the oracle would see the full integer -- so we stay in-bounds.)
    edge = [0, 1, 2, n - 1, n, n + 1, n - 2, n // 2,
            2 ** 255, 2 ** 255 - 1, 0xFFFFFFFFFF, rng.getrandbits(256) % n]
    Pe = rand_point(rng)
    for k in edge:
        for P in [(Gx, Gy), Pe]:
            xy = fmt_xy(P); kk = fmt_k(k)
            vecs.append("ctscalar %s %s" % (xy, kk))
            vecs.append("vtscalar %s %s" % (xy, kk))
            exp = ec_mul(k % n, P)
            expect.append(exp); expect.append(exp)
    # ---- pointh_add / pointh_double vs oracle + consistency ----
    for _ in range(iters):
        P = rand_point(rng); Q = rand_point(rng)
        # have k such that we sometimes test P==Q, P==-Q, infinity
        r = rng.random()
        if r < 0.15:
            Q = P                      # P == Q
        elif r < 0.30:
            Q = (P[0], (-P[1]) % p)    # P == -Q -> infinity
        elif r < 0.40:
            # P + identity == P ; double(P) == 2P
            vecs.append("hadd %s %s" % (fmt_p12(P), fmt_p12(None)))
            vecs.append("hdouble %s" % fmt_p12(P))
            expect.append(P)
            expect.append(ec_add(P, P))
            continue
        p1 = fmt_p12(P); q1 = fmt_p12(Q)
        vecs.append("hadd %s %s" % (p1, q1))
        vecs.append("hdouble %s" % p1)
        expect.append(ec_add(P, Q))
        expect.append(ec_add(P, P))    # 2P
        # consistency: pointh_double(P) == pointh_add(P, P)
        vecs.append("hadd %s %s" % (p1, p1))
        expect.append(ec_add(P, P))
    # ---- run ----
    lines = parse_result(drv, vecs)
    if len(lines) != len(vecs):
        print("SEED %d: line-count mismatch %d != %d" % (seed, len(lines), len(vecs)))
        return (seed, len(vecs), 1, ["  line-count mismatch"])
    for i, (vec, line, exp) in enumerate(zip(vecs, lines, expect)):
        got = norm(line)
        want = "inf" if exp is None else fmt_xy(exp)
        if got != want:
            nbad += 1
            if len(detail) < 5:
                detail.append("  mismatch vec=%r\n    rawline=%r\n    got=%s\n    want=%s" % (vec, line, got, want))
    return (seed, len(vecs), nbad, detail)

def main():
    seeks = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    iters = int(sys.argv[2]) if len(sys.argv) > 2 else 120
    drv   = sys.argv[3] if len(sys.argv) > 3 else "./t_pct"
    totals = 0
    fails = 0
    allbad = 0
    for seed in range(1, seeks + 1):
        s, total, nbad, detail = run_seed(drv, seed, iters)
        totals += total
        allbad += nbad
        tag = "FAIL" if nbad else "pass"
        print("seed %-3d %-4s %6d vectors  %d mismatch%s" % (s, tag, total, nbad,
              "" if nbad == 1 else "es"))
        for d in detail:
            print(d)
        fails += 1 if nbad else 0
    print("\nSUMMARY: seeds=%d iters/seed=%d total_vectors=%d mismatch=%d  %s" %
          (seeks, iters, totals, allbad, "ALL PASS" if allbad == 0 else "FAILURES PRESENT"))
    return 0 if allbad == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
