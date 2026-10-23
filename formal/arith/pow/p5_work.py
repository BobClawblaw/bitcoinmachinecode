#!/usr/bin/env python3
"""P5: chainwork arithmetic in asm/bitcoin_chainwork.asm, against Core v31.1
chain.cpp GetBlockProof ((~t / (t+1)) + 1, 0 for a negative/overflow/zero
target) and the arith_uint256 chainwork sum.

Method: hand-written x86-64 semantics of the instructions involved, in z3
bit-vectors (NOT lifted: the semantics of rcl/sub/sbb/setc/not/add/adc are
trusted), proved for all inputs; backed by diff_pow, which runs the real
assembled u256_div / block_work / chainwork_add against core_port.h on
millions of inputs. u256_div's 256-iteration loop is proved by an inductive
step lemma (no unrolling):

  DIV-STEP   one iteration (`.loop` .. `.no_commit`): R < B, B != 0, bit in {0,1}:
             shl-by-rcl of R gives (R<<1 mod 2^256, COUT = bit 255);
             R |= bit; S = R - B mod 2^256 with CF = borrow;
             commit = COUT | !CF; R' = commit ? S : R.
             Claim: commit == (2R + bit >= B) and R' == 2R + bit - commit*B
             exactly (257-bit arithmetic), and R' < B.
  DIV-COMP   integers: if Qh*B + R == H and the step holds then
             (2Qh + commit)*B + R' == 2H + bit. Over i = 255..0 (the loop
             runs exactly 256 times: i starts at 255, `test rax,rax; jz .done`
             after the body) H becomes A and Qh the quotient: q = floor(A/B).
  BITSEL     bit i of A as the code reads it, (A[i>>6] >> (i&63)) & 1 over 4
             little-endian limbs, == bit i of A; and `or [Q+(i>>6)*8], 1<<(i&63)`
             sets exactly bit i (i in [0,255]).
  C2T        compact_to_target_le == Core SetCompact's target for every nBits
             with exponent 3..32 and the sign bit clear (the pow-valid ones
             with exponent >= 3); outside that, exponent < 3 and exponent
             33/34 decode to 0 (block_work then returns 0).
  WORK       block_work's tail: notA = ~t, divB = t + 1 (no carry: t < 2^256-1
             since the mantissa is <= 0x7fffff), q + 1 truncated to 128 bits
             == the low 128 bits of Core's (~t/(t+1))+1, for t != 0.
  CW-ADD     chainwork_add (add/adc, jnc, saturate) == a + b whenever
             a + b < 2^128 (Core's 256-bit sum), and 2^128-1 otherwise.
Mutants: DIV-STEP with commit = !CF only (drops COUT); C2T with the offset
bound `cmp ecx, 29` -> 30; CW-ADD without saturation.
Note on COUT: DIV-STEP is proved for every R < B, which is more than the loop
needs. In the real loop the remainder entering the step for bit i is
(A >> (i+1)) mod B < 2^(255-i) <= 2^255, so bit 255 of R is never set and
COUT is always 0: dropping it is an EQUIVALENT mutation of the real code
(run.sh's object mutant therefore drops the `xor eax, 1` instead, which the
differential test catches). The z3 mutant above is caught only because the
lemma's domain is wider than the reachable one.
"""
import sys
from z3 import (BitVec, BitVecVal, Int, Solver, ULT, ULE, UGE, UGT, And, Or, Not, If,
                Implies, ZeroExt, Extract, LShR, UDiv, Concat, sat, unsat)

ok = True


def chk(name, A, G, expect="unsat"):
    global ok
    s = Solver(); s.set("timeout", 300000); s.add(*A); s.add(Not(G))
    r = s.check()
    v = Solver(); v.set("timeout", 120000); v.add(*A); vr = v.check()
    good = (r == unsat) if expect == "unsat" else (r == sat)
    tag = ("PROVED" if expect == "unsat" else "MUTANT-CAUGHT") if good else "FAILED"
    print("%s %s (%s)" % (tag, name, r)); sys.stdout.flush()
    print("%s %s-assumptions (%s)" % ("SAT-OK" if vr == sat else "VACUOUS", name, vr))
    ok &= good and vr == sat


def div_step(mut=None):
    R = BitVec("R", 256); B = BitVec("B", 256); bit = BitVec("bit", 256)
    A = [B != 0, ULT(R, B), ULE(bit, 1)]
    cout = Extract(255, 255, R) == 1                 # rcl chain from CF=0: carry out = bit 255
    Rs = (R << 1) | bit                              # low limb LSB is 0 after the shift
    S = Rs - B                                       # sub/sbb chain
    cf = ULT(Rs, B)                                  # final borrow
    commit = Or(cout, Not(cf)) if mut != "no-cout" else Not(cf)
    R2 = If(commit, S, Rs)
    X = 257
    ex = ZeroExt(1, R) * 2 + ZeroExt(1, bit)         # exact 2R + bit
    Bx = ZeroExt(1, B)
    G = And(commit == UGE(ex, Bx),
            ZeroExt(1, R2) == If(commit, ex - Bx, ex),
            ULT(R2, B))
    return A, G


def div_comp():
    Qh, B, R, H, bit, c, R2 = (Int(x) for x in ("Qh", "B", "R", "H", "bit", "c", "R2"))
    A = [Qh * B + R == H, R2 == 2 * R + bit - c * B]
    return A, (2 * Qh + c) * B + R2 == 2 * H + bit


def bitsel():
    Av = BitVec("A", 256); i = BitVec("i", 64)
    A = [ULE(i, 255)]
    limbs = [Extract(64 * k + 63, 64 * k, Av) for k in range(4)]
    li = LShR(i, 6); sh = i & 63
    sel = If(li == 0, limbs[0], If(li == 1, limbs[1], If(li == 2, limbs[2], limbs[3])))
    got = LShR(sel, sh) & 1
    want = Extract(0, 0, LShR(Av, ZeroExt(192, i)))
    # quotient bit set: OR 1<<sh into limb li == OR (1<<i) into the 256-bit Q
    Q = BitVec("Q", 256)
    ql = [Extract(64 * k + 63, 64 * k, Q) for k in range(4)]
    one = BitVecVal(1, 64) << sh
    nl = [If(li == k, ql[k] | one, ql[k]) for k in range(4)]
    Qn = Concat(nl[3], nl[2], nl[1], nl[0])
    G = And(Extract(0, 0, got) == want, Qn == (Q | (BitVecVal(1, 256) << ZeroExt(192, i))))
    return A, G


def set_compact(bits):
    size = LShR(bits, 24); word0 = bits & 0x7FFFFF
    small = ULE(size, 3)
    word = If(small, LShR(word0, (3 - size) * 8), word0)
    t = If(small, ZeroExt(224, word), ZeroExt(224, word0) << ZeroExt(224, (size - 3) * 8))
    nz = word != 0
    neg = And(nz, (bits & 0x800000) != 0)
    ovf = And(nz, Or(UGT(size, 34), And(UGT(word, 0xFF), UGT(size, 33)), And(UGT(word, 0xFFFF), UGT(size, 32))))
    return t, neg, ovf


def c2t(bits, mut=None):
    # compact_to_target_le: eax = exp, edx = mantissa (24 bits);
    # exp < 3 -> 0 ; ecx = exp-3 ; ecx > 29 -> 0 ; else bytes ecx, ecx+1, ecx+2 = mantissa LE
    e = LShR(bits, 24); m = bits & 0xFFFFFF
    lim = 30 if mut == "offset-30" else 29
    ecx = e - 3
    placed = ZeroExt(224, m) << ZeroExt(224, ecx * 8)
    if mut == "offset-30":
        # with the bound at 30, ecx == 30 writes bytes 30,31 only (the `cmp ecx,30; jae` stops the 3rd)
        placed = If(ecx == 30, ZeroExt(224, m & 0xFFFF) << 240, placed)
    return If(ULT(e, 3), BitVecVal(0, 256), If(UGT(ecx, lim), BitVecVal(0, 256), placed))


def c2t_lemma(mut=None):
    bits = BitVec("bits", 32)
    t, neg, ovf = set_compact(bits)
    e = LShR(bits, 24)
    dom = And(UGE(e, 3), ULE(e, 32), (bits & 0x800000) == 0)
    A = [dom]
    return A, c2t(bits, mut) == t


def c2t_outside():
    bits = BitVec("bits", 32)
    e = LShR(bits, 24)
    A = [Or(ULT(e, 3), e == 33, e == 34)]
    return A, c2t(bits) == 0


def work():
    t = BitVec("t", 256)
    A = [t != 0, ULE(t, (BitVecVal(0x7FFFFF, 256) << 232))]   # mantissa <= 0x7fffff at the top exponent
    q = UDiv(~t, t + 1)                                      # u256_div (DIV-STEP/COMP)
    bmc = Extract(127, 0, q + 1)                             # add/adc on the low two limbs
    core = Extract(127, 0, UDiv(~t, t + 1) + 1)
    return A, And(bmc == core, t + 1 != 0)


def cw_add(mut=None):
    a = BitVec("a", 128); b = BitVec("b", 128)
    s = a + b
    carry = ULT(s, a)
    out = s if mut == "no-sat" else If(carry, BitVecVal(2**128 - 1, 128), s)
    ex = ZeroExt(128, a) + ZeroExt(128, b)
    G = If(ULT(ex, BitVecVal(2**128, 256)), ZeroExt(128, out) == ex, out == BitVecVal(2**128 - 1, 128))
    return [], G


for name, f in (("DIV-STEP", div_step), ("DIV-COMP", div_comp), ("BITSEL", bitsel),
                ("C2T", c2t_lemma), ("C2T-outside", c2t_outside), ("WORK", work), ("CW-ADD", cw_add)):
    A, G = f(); chk(name, A, G)
A, G = div_step("no-cout"); chk("DIV-STEP/mutant:no-cout", A, G, expect="sat")
# the C2T domain excludes ecx == 30, so the mutant is shown on the outside lemma instead
bits = BitVec("bits", 32); e = LShR(bits, 24)
chk("C2T-outside/mutant:offset-30", [Or(ULT(e, 3), e == 33, e == 34)], c2t(bits, "offset-30") == 0, expect="sat")
A, G = cw_add("no-sat"); chk("CW-ADD/mutant:no-saturation", A, G, expect="sat")
print("ALL OK" if ok else "SOME CHECK FAILED")
sys.exit(0 if ok else 1)
