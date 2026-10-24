"""Lift the REAL assembled bitcoin_scriptcodec.o with angr (VEX IR ->
claripy/z3) and prove its ScriptNum primitives equal Bitcoin Core v31.1's.

  scriptnum_decode(len, data, maxsize|minimal<<8) vs CScriptNum(vch,
      fRequireMinimal, nMaxNumSize) (script/script.h:245, set_vch :375)
  scriptnum_serialize(int64)  vs CScriptNum::serialize (script/script.h:341)
  cast_to_bool(len, data)     vs CastToBool (script/interpreter.cpp:36)

The binary is a gcc link of the object (scriptnum/.build/lift_bin) so the
TLS relocations of snum_overflow / scriptnum_buf are resolved exactly as in
the daemon; angr runs every path of each function to its `ret` with the data
bytes, the value and the flags fully symbolic, then asks z3 whether ANY path
can produce an output different from Core's. unsat on every path = proved.

Usage: sn_lift.py BINARY [--expect-cex]   (--expect-cex: a mutant binary;
the run passes only if a counterexample is found).
"""
import sys
import logging
import angr
from angr import claripy

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)
logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)

BIN = sys.argv[1]
EXPECT_CEX = "--expect-cex" in sys.argv
ONLY = [a.split("=", 1)[1] for a in sys.argv if a.startswith("--only=")]
proj = angr.Project(BIN, auto_load_libs=False)
sym = lambda n: proj.loader.find_symbol(n).rebased_addr
RET = 0xdead0000
BUF = 0x7f000000
results = []


def tls_addr(name):
    """Address of a TLS variable for thread 0: run the object's own
    snum_overflow_addr helper for snum_overflow; scriptnum_buf is read off
    the serialize result pointer instead (it returns it in rax)."""
    st = proj.factory.call_state(sym("snum_overflow_addr"), ret_addr=RET)
    sm = proj.factory.simgr(st)
    sm.run(until=lambda s: all(x.addr == RET for x in s.active) or not s.active)
    fin = (sm.active + sm.deadended)[0]
    return fin.solver.eval(fin.regs.rax)


def run_all(state, limit=4000):
    sm = proj.factory.simgr(state)
    n = 0
    while sm.active and n < limit:
        sm.step()
        sm.move(from_stash="active", to_stash="done", filter_func=lambda s: s.addr == RET)
        n += 1
    if sm.active or sm.errored:
        raise RuntimeError("paths did not finish: active=%d errored=%r" % (len(sm.active), sm.errored))
    return sm.done


def check(name, paths, mismatch_fn):
    """mismatch_fn(state) -> claripy bool that is True when the path's output
    differs from Core's. Proved iff unsat on every path (under the path's
    own constraints)."""
    cex = None
    for s in paths:
        if s.solver.satisfiable(extra_constraints=[mismatch_fn(s)]):
            cex = s
            break
    ok = cex is None
    if EXPECT_CEX:
        results.append((name, not ok))
        print(("MUTANT-CAUGHT %s" % name) if not ok else ("MUTANT-MISSED %s" % name))
    else:
        results.append((name, ok))
        print(("PROVED %s  (%d paths)" % (name, len(paths))) if ok else ("FAILED %s" % name))
    return cex


# ------------------------------------------------------------- decode
def core_decode(d, L, maxsize, minimal):
    """(throws, value) per CScriptNum(vch, fRequireMinimal, nMaxNumSize)."""
    over = claripy.UGT(claripy.BVV(L, 64), maxsize)
    if L > 0:
        top = d[L - 1]
        nonmin = (top & 0x7f) == 0
        if L == 1:
            nonmin_full = nonmin
        else:
            nonmin_full = claripy.And(nonmin, (d[L - 2] & 0x80) == 0)
        bad_min = claripy.And(minimal == 1, nonmin_full)
    else:
        bad_min = claripy.BoolV(False)
    throws = claripy.Or(over, bad_min)
    if L == 0:
        return throws, claripy.BVV(0, 64)
    acc = claripy.BVV(0, 64)
    for i in range(min(L, 8)):
        acc = acc | (d[i].zero_extend(56) << (8 * i))
    if L <= 8:
        mask = ~(claripy.BVV(0x80, 64) << (8 * (L - 1)))
        val = claripy.If((d[L - 1] & 0x80) != 0, -(acc & mask), acc)
    else:
        val = acc  # never compared: Core has no int64 meaning past 8 bytes
    return throws, val


def prove_decode():
    ov = tls_addr("snum_overflow")
    for L in range(0, 13):
        d = [claripy.BVS("d%d" % i, 8) for i in range(L)]
        msz = claripy.BVS("maxsize", 8)
        minimal = claripy.BVS("minimal", 1)
        rdx = msz.zero_extend(56) | (minimal.zero_extend(63) << 8)
        st = proj.factory.call_state(sym("scriptnum_decode"), L, BUF, rdx, ret_addr=RET,
                                     add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                                  angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
        for i in range(L):
            st.memory.store(BUF + i, d[i])
        if L > 8:
            # callers pass maxsize 4 or 5 (SNUM_MAX); past 8 bytes Core's
            # value is undefined, so only the throw flag is compared, for
            # every maxsize up to 8
            st.solver.add(claripy.ULE(msz, 8))
        paths = run_all(st)
        def mism(s, d=d, L=L, msz=msz, minimal=minimal):
            throws, val = core_decode(d, L, msz.zero_extend(56), minimal)
            flag = s.memory.load(ov, 8, endness="Iend_LE")
            got_throw = flag != 0
            if L > 8:
                return got_throw != throws
            return claripy.Or(got_throw != throws,
                              claripy.And(claripy.Not(throws), s.regs.rax != val))
        check("scriptnum_decode len=%d" % L, paths, mism)


# ---------------------------------------------------------- serialize
def core_serialize(v):
    """(length, bytes[0..9]) per CScriptNum::serialize, as claripy terms."""
    neg = claripy.SLT(v, 0)
    absv = claripy.If(neg, -v, v)          # Core: ~uint64(value) + 1
    # n = number of bytes of absv (0 for absv == 0)
    n = claripy.BVV(0, 64)
    for k in range(1, 9):
        n = claripy.If(claripy.UGE(absv, claripy.BVV(1 << (8 * (k - 1)), 64)) if k > 1
                       else absv != 0, claripy.BVV(k, 64), n)
    raw = [claripy.Extract(8 * i + 7, 8 * i, absv) for i in range(8)] + [claripy.BVV(0, 8)]
    out = []
    for i in range(9):
        b = raw[i]
        # byte n-1: OR in the sign if its top bit is clear; byte n: the
        # sign byte when the top bit of byte n-1 is set
        is_last = n == (i + 1)
        is_ext = n == i
        prev = raw[i - 1] if i > 0 else claripy.BVV(0, 8)
        top_set_last = (b & 0x80) != 0
        top_set_prev = (prev & 0x80) != 0
        b = claripy.If(claripy.And(is_last, claripy.Not(top_set_last), neg), b | 0x80, b)
        b = claripy.If(claripy.And(is_ext, n != 0, top_set_prev),
                       claripy.If(neg, claripy.BVV(0x80, 8), claripy.BVV(0, 8)), b)
        out.append(b)
    last_top = claripy.BVV(0, 1)
    for k in range(1, 9):
        last_top = claripy.If(n == k, claripy.Extract(7, 7, raw[k - 1]), last_top)
    length = claripy.If(claripy.And(n != 0, last_top == 1), n + 1, n)
    return length, out


def prove_serialize():
    v = claripy.BVS("v", 64)
    st = proj.factory.call_state(sym("scriptnum_serialize"), v, ret_addr=RET,
                                 add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                              angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
    paths = run_all(st)
    def mism(s):
        length, out = core_serialize(v)
        terms = [s.regs.rdx != length]
        base = s.regs.rax
        for i in range(9):
            got = s.memory.load(base + i, 1)
            terms.append(claripy.And(claripy.UGT(length, i), got != out[i]))
        return claripy.Or(*terms)
    check("scriptnum_serialize all int64", paths, mism)


# --------------------------------------------------------- castToBool
def prove_cast():
    for L in list(range(0, 10)) + [16]:
        d = [claripy.BVS("c%d" % i, 8) for i in range(L)]
        st = proj.factory.call_state(sym("cast_to_bool"), L, BUF, ret_addr=RET,
                                     add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                                  angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
        for i in range(L):
            st.memory.store(BUF + i, d[i])
        paths = run_all(st)
        # Core CastToBool: true iff some byte is nonzero, except a lone
        # nonzero LAST byte equal to 0x80 (negative zero)
        res = claripy.BoolV(False)
        for i in reversed(range(L)):
            here = claripy.If(i == L - 1, d[i] != 0x80, claripy.BoolV(True)) if i == L - 1 else claripy.BoolV(True)
            res = claripy.If(d[i] != 0, here if i == L - 1 else claripy.BoolV(True), res)
        # rebuild in scan order (first nonzero byte decides)
        core = claripy.BoolV(False)
        for i in reversed(range(L)):
            decide = (d[i] != 0x80) if i == L - 1 else claripy.BoolV(True)
            core = claripy.If(d[i] != 0, decide, core)
        def mism(s, core=core):
            got = claripy.Extract(0, 0, s.regs.rax) == 1
            return claripy.Or(got != core, claripy.Extract(63, 1, s.regs.rax) != 0)
        check("cast_to_bool len=%d" % L, paths, mism)


todo = {"decode": prove_decode, "serialize": prove_serialize, "cast": prove_cast}
for k, f in todo.items():
    if not ONLY or k in ONLY:
        f()
bad = [n for n, ok in results if not ok]
if EXPECT_CEX:
    # a mutant run passes if at least one property caught it
    sys.exit(0 if any(ok for _, ok in results) else 1)
sys.exit(1 if bad else 0)
