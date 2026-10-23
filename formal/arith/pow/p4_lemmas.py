#!/usr/bin/env python3
"""P4-LEM: the retarget arithmetic of bmc pow_retarget_bits
(asm/bitcoin_pow_rules.c), by loop-step lemmas + composition, UNBOUNDED.
A whole-function CBMC equivalence (cbmc/p4_retarget.c) did not close in
15 min, nor in 5 min with the exponent fixed (SAT equivalence of a
byte-serial multiplier/divider against a word-level one), so the proof is
split. Lines modelled (run.sh greps that each is still in the product):

  MUL  unsigned long long v = (unsigned long long)n[i] * (unsigned long long)ts + carry;
       n[i] = (u8)v; carry = v >> 8;                     (i = 0..39, LSB first)
  DIV  unsigned long long v = (rem << 8) | n[i];
       n[i] = (u8)(v / (unsigned long long)POW_TIMESPAN);
       rem = v % (unsigned long long)POW_TIMESPAN;       (i = 39..0, MSB first)
  clamp: ts in [T/4, 4T], T = 1209600 (the two if-lines before them).

Lemmas (PROVED = negation unsat):
  MUL-STEP    64-bit: n in [0,255], ts in [T/4,4T], carry < ts  =>  v does not
              wrap, v == (u8)v + 256*carry', and carry' < ts (the invariant).
  MUL-COMP    integers, P = 256^i > 0 symbolic: if L + c*P == N*ts and the step
              holds, then L' + c'*(256P) == (N + n*P)*ts. With carry_0 = 0 this
              gives, after 40 steps, value(n) + carry_40 * 256^40 == N*ts; and
              carry_40 == 0 because N < 2^256 and ts < 2^23 (MUL-FITS).
  DIV-STEP    64-bit: rem < T  =>  (rem<<8)|n == 256*rem + n, no wrap,
              q = v/T < 256 (the u8 cast is exact), rem' < T, v == q*T + rem'.
  DIV-COMP    integers: Q*T + rem == H and the step  =>  (256Q + q)*T + rem' ==
              256H + n. With rem_40 = 0 this is long division: the 40 output
              bytes are floor(N*ts / T) and the final rem is the remainder.
  BOUND-<c>   for each retargeting chain (main/testnet4, signet): every
              target <= powLimit times 4T is < 2^256, so Core's mod-2^256
              operator*=(uint32_t) never wraps and Core's q equals bmc's exact
              q; also q < 2^256, so bmc's `over` flag stays 0 there.
  BOUND-regtest-wraps  2^255-ish * 4T >= 2^256 (regtest would wrap) -- moot,
              regtest never calls CalculateNextWorkRequired's arithmetic
              (fPowNoRetargeting; P4s shows bmc returns before it).
Mutants (MUTANT-CAUGHT = sat): carry kept as v >> 7; divisor T+1; ts clamp
upper bound 4T+1 (BOUND).
"""
import sys
from z3 import (BitVec, BitVecVal, Int, Solver, ULE, ULT, UGE, And, Not, Implies,
                ZeroExt, Extract, LShR, URem, UDiv, sat, unsat)

T = 1209600
ok = True


def chk(name, A, G, expect="unsat"):
    global ok
    s = Solver(); s.set("timeout", 120000); s.add(*A); s.add(Not(G))
    r = s.check()
    v = Solver(); v.set("timeout", 120000); v.add(*A); vr = v.check()
    good = (r == unsat) if expect == "unsat" else (r == sat)
    tag = ("PROVED" if expect == "unsat" else "MUTANT-CAUGHT") if good else "FAILED"
    print("%s %s (%s)%s" % (tag, name, r, ("  e.g. " + str(s.model())[:200]) if r == sat else ""))
    print("%s %s-assumptions (%s)" % ("SAT-OK" if vr == sat else "VACUOUS", name, vr))
    ok &= good and vr == sat


def mul_step(mut=None):
    n = BitVec("n", 64); ts = BitVec("ts", 64); c = BitVec("carry", 64)
    A = [ULE(n, 255), UGE(ts, T // 4), ULE(ts, 4 * T), ULT(c, ts)]
    v = n * ts + c
    vw = ZeroExt(64, n) * ZeroExt(64, ts) + ZeroExt(64, c)       # exact (128-bit)
    sh = 7 if mut == "carry-shift-7" else 8
    c2 = LShR(v, sh)
    byte = v & 0xff
    G = And(ZeroExt(64, v) == vw, v == byte + c2 * 256, ULT(c2, ts))
    return A, G


def mul_comp():
    L, c, N, P, n, ts, a, c2 = (Int(x) for x in ("L", "c", "N", "P", "n", "ts", "a", "c2"))
    A = [P > 0, L + c * P == N * ts, n * ts + c == a + 256 * c2]
    G = (L + a * P) + c2 * (256 * P) == (N + n * P) * ts
    return A, G


def div_step(mut=None):
    rem = BitVec("rem", 64); n = BitVec("n", 64)
    D = T + 1 if mut == "divisor" else T
    A = [ULT(rem, T), ULE(n, 255)]
    v = (rem << 8) | n
    q = UDiv(v, BitVecVal(D, 64)); r2 = URem(v, BitVecVal(D, 64))
    G = And(v == rem * 256 + n, ULT(rem, 2**56), ULT(q, 256), ULT(r2, T), v == q * T + r2)
    return A, G


def div_comp():
    Q, rem, H, n, q, r2 = (Int(x) for x in ("Q", "rem", "H", "n", "q", "r2"))
    A = [Q * T + rem == H, 256 * rem + n == q * T + r2]
    G = (256 * Q + q) * T + r2 == 256 * H + n
    return A, G


def bound(full, hi_ts=4 * T):
    X = Int("target"); ts = Int("ts")
    A = [X >= 1, X <= full, ts >= T // 4, ts <= hi_ts]
    return A, X * ts < 2**256


A, G = mul_step(); chk("MUL-STEP", A, G)
A, G = mul_comp(); chk("MUL-COMP", A, G)
X = Int("N"); chk("MUL-FITS", [X >= 0, X < 2**256], X * (4 * T) < 2**320)
A, G = div_step(); chk("DIV-STEP", A, G)
A, G = div_comp(); chk("DIV-COMP", A, G)
MAIN = int("00000000" + "ff" * 28, 16)
SIGNET = 0x377ae << 216
REG = int("7f" + "ff" * 31, 16)
A, G = bound(MAIN); chk("BOUND-main-testnet4", A, G)
A, G = bound(SIGNET); chk("BOUND-signet", A, G)
A, G = bound(REG); chk("BOUND-regtest-wraps", A, G, expect="sat")
A, G = mul_step("carry-shift-7"); chk("MUL-STEP/mutant:carry-shift-7", A, G, expect="sat")
A, G = div_step("divisor"); chk("DIV-STEP/mutant:divisor-T+1", A, G, expect="sat")
# signet's margin is tight: one more second of clamp would wrap
A, G = bound(SIGNET, hi_ts=4 * T + 1300); chk("BOUND-signet/mutant:clamp-4T+1300", A, G, expect="sat")
print("ALL OK" if ok else "SOME CHECK FAILED")
sys.exit(0 if ok else 1)
