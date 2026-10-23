#!/usr/bin/env python3
"""M2-IND: the value ledger, UNBOUNDED in the number of transactions and
inputs, by induction. z3 bit-vector models (64-bit, exactly the C types),
transcribed line by line from the code M2 runs through CBMC:

  bmc  asm/daemon/utxo_live.c, Phase 4.5 (gen/m2_ledger.inc):
         u64 in_t = tx_in[t], out_t = ptx_out[t];
         if (in_t > VAL_MAX_MONEY) reject inputvalues-outofrange      [B1]
         if (in_t < out_t)         reject in-belowout                 [B2]
         fees += in_t - out_t;                                        [B3]
         if (fees > VAL_MAX_MONEY) reject fee-outofrange              [B4]
       ...after the loop:
         u64 cap = val_subsidy(h) + fees; if (ptx_out[0] > cap) reject [B5]
       and tx_in[t] is tx_verify.c's `g_tx_in_sums[tx] += value` (u64).
  Core consensus/tx_verify.cpp CheckTxInputs + validation.cpp ConnectBlock:
         nValueIn += coin; if (!MoneyRange(coin)||!MoneyRange(nValueIn)) [C1]
         if (nValueIn < value_out)                                     [C2]
         txfee = nValueIn - value_out; if (!MoneyRange(txfee))         [C3]
         nFees += txfee; if (!MoneyRange(nFees))                       [C4]
         blockReward = nFees + GetBlockSubsidy; if (GetValueOut() > blockReward) [C5]

Lemmas (each printed PROVED when its negation is unsat):
  IN-STEP   one input: Core's running-sum verdict and bmc's u64 accumulator
            stay related: (core_bad <-> P > MAX) and (p == P) while
            P < 2^64, for every coin in [0, MAX] (assumption A-UTXO).
  IN-WIDTH  k * MAX_MONEY < 2^64 for k <= 8784, so for any tx with at most
            8784 inputs the u64 accumulator equals the true sum (8785 is
            the first count where it could wrap: printed as tightness).
  TX-STEP   one non-coinbase tx: given the input verdict from IN-STEP,
            bmc rejects iff Core rejects, and the fee totals stay equal and
            in [0, MAX] when both accept.
  CB-CAP    the final coinbase check agrees and neither sum overflows, for
            subsidy in [0, 50 BTC] (M3 proves val_subsidy == Core's).
Then each mutation listed in MUTANTS must make its lemma SAT.
"""
import sys
from z3 import (BitVec, BitVecVal, Int, Solver, ULE, ULT, UGT, UGE, And, Or, Not,
                Implies, If, sat, unsat, ZeroExt)

MAX = 2100000000000000
W = 64


def bv(v):
    return BitVecVal(v, W)


def check(name, assumptions, goal, expect="unsat"):
    s = Solver()
    s.set("timeout", 120000)
    s.add(*assumptions)
    s.add(Not(goal))
    r = s.check()
    ok = (r == unsat) if expect == "unsat" else (r == sat)
    tag = ("PROVED" if expect == "unsat" else "MUTANT-CAUGHT") if ok else "FAILED"
    extra = ""
    if r == sat:
        extra = "  counterexample: " + str(s.model())[:300]
    print("%s %s (%s)%s" % (tag, name, r, extra))
    # vacuity: the assumptions alone must be satisfiable
    v = Solver(); v.set("timeout", 120000); v.add(*assumptions)
    vr = v.check()
    print("%s %s-assumptions (%s)" % ("SAT-OK" if vr == sat else "VACUOUS", name, vr))
    return ok and vr == sat


# "Mathematical" values are 128-bit zero-extensions: no sum here can reach
# 2^128, so 128-bit arithmetic on them is exact integer arithmetic (pure
# bit-vector reasoning, which z3 decides quickly; BV2Int did not finish).
X = 128


def Z(e):
    return ZeroExt(X - W, e)


def zv(v):
    return BitVecVal(v, X)


def in_step(mut=None):
    # one input. Core: nValueIn (int64), bad flag; bmc: u64 accumulator p;
    # P = the true running sum.
    nV = BitVec("nValueIn", W); bad = BitVec("bad", 1); p = BitVec("p", W)
    P = BitVec("P", X); coin = BitVec("coin", W)
    A = [
        ULE(coin, bv(MAX)),                                  # A-UTXO
        ULT(P + zv(MAX), zv(2**64)),                         # stays inside u64 (IN-WIDTH)
        Z(p) == P,
        (bad == 1) == UGT(P, zv(MAX)),
        Implies(bad == 0, Z(nV) == P),                       # Core's sum while still ok
    ]
    lim = bv(MAX + 1) if mut == "in-limit" else bv(MAX)
    nV2 = nV + coin                                          # C1 (values >= 0, so unsigned compare == signed)
    core_rej = And(bad == 0, Or(UGT(coin, lim), UGT(nV2, lim)))
    bad2 = If(Or(bad == 1, core_rej), BitVecVal(1, 1), BitVecVal(0, 1))
    p2 = p + coin                                            # tx_verify.c accumulator
    P2 = P + Z(coin)
    G = And(Z(p2) == P2, (bad2 == 1) == UGT(P2, zv(MAX)), Implies(bad2 == 0, Z(nV2) == P2))
    return A, G


def tx_step(mut=None):
    fb = BitVec("fees_bmc", W); fc = BitVec("nFees_core", W)
    S = BitVec("in_sum", W); out = BitVec("value_out", W)
    A = [ULE(fb, bv(MAX)), fb == fc, ULE(out, bv(MAX))]     # relation + M1
    lim = bv(MAX)
    b1 = UGT(S, lim)                                         # B1
    if mut == "no-b1":
        b1 = False
    b2 = ULT(S, out) if mut != "belowout-le" else ULE(S, out)   # B2
    fb2 = fb + (S - out)                                     # B3
    b4 = UGT(fb2, lim) if mut != "fee-limit" else UGT(fb2, bv(MAX + 1))   # B4
    bmc_rej = Or(b1, b2, b4)
    # Core on exact integers (signed int64 values are all in [0, 2^63) here
    # except where noted): C1 verdict from IN-STEP, C2, C3, C4.
    c1 = UGT(Z(S), zv(MAX))
    c2 = ULT(Z(S), Z(out))
    fee = Z(S) - Z(out)                                      # only used when not c2: >= 0
    c3 = UGT(fee, zv(MAX))
    nf = Z(fc) + fee
    c4 = UGT(nf, zv(MAX))
    core_rej = Or(c1, c2, And(Not(c2), c3), And(Not(c2), c4))
    G = And(bmc_rej == core_rej, Implies(Not(core_rej), And(Z(fb2) == nf, ULE(nf, zv(MAX)))))
    return A, G


def cb_cap(mut=None):
    fees = BitVec("fees", W); sub = BitVec("subsidy", W); cb = BitVec("cb_out", W)
    A = [ULE(fees, bv(MAX)), ULE(sub, bv(5000000000)), ULE(cb, bv(MAX))]
    cap = sub + fees                                         # B5, u64
    bmc_rej = UGT(cb, cap) if mut != "cb-ge" else UGE(cb, cap)
    true = Z(fees) + Z(sub)                                  # C5, exact
    core_rej = UGT(Z(cb), true)
    G = And(bmc_rej == core_rej, Z(cap) == true, ULT(true, zv(2**63)))
    return A, G


def main():
    ok = True
    for name, f in (("IN-STEP", in_step), ("TX-STEP", tx_step), ("CB-CAP", cb_cap)):
        A, G = f()
        ok &= check(name, A, G)
    # IN-WIDTH, with tightness
    k = Int("k")
    ok &= check("IN-WIDTH", [k >= 0, k <= 8784], k * MAX < 2**64)
    s = Solver(); s.add(8785 * MAX >= 2**64)
    t = s.check() == sat
    print("%s IN-WIDTH-tight (8785 * MAX_MONEY >= 2^64: %s)" % ("PROVED" if t else "FAILED", t))
    ok &= t
    MUTANTS = (("IN-STEP", in_step, "in-limit"),
               ("TX-STEP", tx_step, "belowout-le"),
               ("TX-STEP", tx_step, "fee-limit"),
               ("TX-STEP", tx_step, "no-b1"),
               ("CB-CAP", cb_cap, "cb-ge"))
    for name, f, m in MUTANTS:
        A, G = f(m)
        ok &= check("%s/mutant:%s" % (name, m), A, G, expect="sat")
    print("ALL OK" if ok else "SOME CHECK FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
