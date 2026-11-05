#!/usr/bin/env python3
"""M4: coinbase maturity (CheckTxInputs' bad-txns-premature-spend-of-coinbase).

bmc has the rule twice and both are modelled here, line by line:
  C   asm/daemon/tx_verify.c txvb_classify:
        long conf = height - (long)uheight;
        if (conf < COINBASE_MATURITY) reject          (long, signed <)
  asm asm/bitcoin_txv_classify.asm txvb_classify_asm:
        mov rax, rsi        ; height
        sub rax, r8         ; - uheight      (64-bit wrapping subtract)
        cmp rax, COINBASE_MATURITY            (%define 100)
        jge .not_cb         ; signed >=  -> mature
  Core consensus/tx_verify.cpp CheckTxInputs:
        if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY)
      with int nSpendHeight, uint32_t-range nHeight stored in an int
      (Coin::nHeight is a 31-bit field), COINBASE_MATURITY = 100.
UNBOUNDED over the domain Core can represent: both heights in [0, 2^31-1].
run.sh greps the four asm lines and the C line so a change breaks the run.
The model is hand-written instruction semantics (not lifted), so it is
trusted to match NASM's encoding of these four instructions.
"""
import sys
from z3 import BitVec, BitVecVal, Solver, And, Not, ULE, sat, unsat, Extract, SignExt

ok = True


def run(name, mut=None):
    global ok
    h = BitVec("height", 64); u = BitVec("uheight", 64)
    A = [ULE(h, BitVecVal(2**31 - 1, 64)), ULE(u, BitVecVal(2**31 - 1, 64))]
    M = 99 if mut == "maturity-99" else 100
    # C: signed 64-bit
    c_rej = (h - u) < BitVecVal(100, 64)
    # asm: sub then signed compare; jge taken = mature
    rax = h - u
    if mut == "jae":
        from z3 import UGE
        mature = UGE(rax, BitVecVal(M, 64))
    else:
        mature = rax >= BitVecVal(M, 64)
    asm_rej = Not(mature)
    # Core: int (32-bit signed) arithmetic on the same values
    h32 = Extract(31, 0, h); u32 = Extract(31, 0, u)
    core_rej = (h32 - u32) < BitVecVal(100, 32)
    s = Solver(); s.set("timeout", 60000); s.add(*A)
    s.add(Not(And(c_rej == core_rej, asm_rej == core_rej)))
    r = s.check()
    v = Solver(); v.add(*A); vr = v.check()
    if mut is None:
        good = r == unsat
        print("%s %s (%s)" % ("PROVED" if good else "FAILED", name, r))
    else:
        good = r == sat
        print("%s %s (%s)%s" % ("MUTANT-CAUGHT" if good else "FAILED", name, r,
                                "  counterexample: " + str(s.model()) if r == sat else ""))
    print("%s %s-assumptions (%s)" % ("SAT-OK" if vr == sat else "VACUOUS", name, vr))
    ok &= good and vr == sat


run("MATURITY")
run("MATURITY/mutant:maturity-99", "maturity-99")
run("MATURITY/mutant:jae", "jae")
sys.exit(0 if ok else 1)
