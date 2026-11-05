"""proofs_misc.py -- range checks and the bip340_sign.c helpers (real gcc output)."""
import time
import z3
import x86sym as X
import common as Cm
import proofs_fe as F


def enum_paths_ret(fn, args, st, mode='fork'):
    img = Cm.image()
    m = X.Machine(img, mode=mode)
    fin = Cm.call(m, st, fn, args)
    return m, fin


def check_paths(fin, spec_bool, ret_w=32):
    """on every path, (path condition) => ret == spec ; returns (ok, counterexample)"""
    for f in fin:
        ret = z3.Extract(ret_w - 1, 0, X.bv(f.regs['rax'], 64))
        s = z3.Solver()
        s.add(*f.pc)
        s.add(ret != z3.If(spec_bool, z3.BitVecVal(1, ret_w), z3.BitVecVal(0, ret_w)))
        if s.check() == z3.sat:
            return False, s.model()
        if Cm.abi_ok(f):
            return False, None
    return True, None


def small_nonzero(R, pid):
    """scalar_small_nonzero(k[32] big-endian) == 1  iff  0 < k < n  (k == n and [n, 2^256) rejected)"""
    t0 = time.time()
    img = Cm.image()
    st = Cm.new_state(img)
    kb = [z3.BitVec('kb%d' % i, 8) for i in range(32)]
    for i, b in enumerate(kb):
        st.mem.store(Cm.BUF[1] + i, b, 1)
    m, fin = enum_paths_ret('scalar_small_nonzero', [Cm.BUF[1]], st)
    K = z3.Concat(*kb)          # big-endian bytes -> integer
    spec = z3.And(K != 0, z3.ULT(K, z3.BitVecVal(Cm.N, 256)))
    ok, mdl = check_paths(fin, spec)
    note = ''
    if mdl is not None:
        note = ' COUNTEREXAMPLE k=%#x' % mdl.eval(K, model_completion=True).as_long()
    R.add(pid, 'scalar_small_nonzero', 'returns 1 iff 0 < k < n for all 2^256 k (so k == n and every k >= n '
          'and k == 0 return 0); %d paths enumerated%s' % (len(fin), note), 'lifter path enumeration + z3',
          'unbounded (all 2^256 inputs)', 'PROVED' if ok else 'VIOLATED', time.time() - t0)
    return ok


def in_range(R, pid):
    """ecdsa_in_range (rsi -> 4 LE limbs): eax == 1 iff 0 < x < n"""
    t0 = time.time()
    img = Cm.image()
    st = Cm.new_state(img)
    x = Cm.sym_limbs('x')
    Cm.put(st, Cm.BUF[1], x)
    m, fin = enum_paths_ret(img.symbols['ecdsa_in_range'], [0, Cm.BUF[1]], st)
    spec = z3.And(Cm.val(x) != 0, z3.ULT(Cm.val(x), z3.BitVecVal(Cm.N, 256)))
    ok, mdl = check_paths(fin, spec)
    R.add(pid, 'ecdsa_in_range', 'returns 1 iff 0 < x < n (all 2^256 x); %d paths' % len(fin),
          'lifter path enumeration + z3', 'unbounded', 'PROVED' if ok else 'VIOLATED', time.time() - t0)
    return ok


def reduce_n(R, pid):
    """bip340_sign.c reduce_n (sub4 + sel4 inlined, real -O2 code): r == a mod n for every a < 2^256;
    constant time (mode 'ct': no symbolic branch or address)"""
    t0 = time.time()
    img = Cm.image()
    m = X.Machine(img, mode='ct')
    st = Cm.new_state(img)
    a = Cm.sym_limbs('a_')
    Cm.put(st, Cm.BUF[1], a)
    m.write_log = []
    fin = Cm.call(m, st, img.symbols['reduce_n'], [Cm.BUF[0], Cm.BUF[1]])
    out = Cm.get(fin[0], Cm.BUF[0])
    A, Rr = F.ext(Cm.val(a), 264), F.ext(Cm.val(out), 264)
    nW = z3.BitVecVal(Cm.N, 264)
    r, dt, _ = Cm.prove([], z3.And(Rr == z3.If(z3.UGE(A, nW), A - nW, A), z3.ULT(Rr, nW)))
    ok = len(fin) == 1 and not Cm.abi_ok(fin[0]) and not F.writes_ok(m, Cm.BUF[0], 32)
    R.add(pid, 'reduce_n (bip340_sign.c)', 'r == a mod n, r < n for every a < 2^256 (2^256 < 2n); constant '
          'time; stack canary intact; ABI, writes OK', 'lifter (ct mode) + z3 QF_BV', 'unbounded',
          r if ok else 'VIOLATED', time.time() - t0)


def cneg_n(R, pid):
    """cneg_n(r, a, flag): r == (flag&1) ? n - a : a, for a in [1, n): r in [1, n); constant time in a and flag"""
    t0 = time.time()
    img = Cm.image()
    m = X.Machine(img, mode='ct')
    st = Cm.new_state(img)
    a = Cm.sym_limbs('a_')
    Cm.put(st, Cm.BUF[1], a)
    flag = z3.BitVec('flag', 32)
    m.write_log = []
    fin = Cm.call(m, st, img.symbols['cneg_n'], [Cm.BUF[0], Cm.BUF[1], z3.ZeroExt(32, flag)])
    out = Cm.get(fin[0], Cm.BUF[0])
    A, Rr = Cm.val(a), Cm.val(out)
    nW = z3.BitVecVal(Cm.N, 256)
    neg = z3.Extract(0, 0, flag) == 1
    goal = z3.And(Rr == z3.If(neg, nW - A, A), z3.ULT(Rr, nW), Rr != 0)
    r, dt, _ = Cm.prove([A != 0, z3.ULT(A, nW)], goal)
    ok = len(fin) == 1 and not Cm.abi_ok(fin[0]) and not F.writes_ok(m, Cm.BUF[0], 32)
    R.add(pid, 'cneg_n (bip340_sign.c)', 'a in [1,n) => r == (flag odd ? n - a : a), r in [1,n), for all a and '
          'all 32-bit flag (incl. the CRY-2 all-ones-limb case); constant time in a and flag', 'lifter (ct) + z3',
          'unbounded', r if ok else 'VIOLATED', time.time() - t0)
    r2, _, mdl = Cm.prove([], goal)
    R.add(pid + '.pre', 'cneg_n', 'the precondition a in [1,n) is needed (a == 0 with flag odd gives r == n): '
          'callers pass d0 in [1,n) and k0 != 0 after reduce_n', 'z3 QF_BV', 'unbounded',
          'PROVED' if r2 == 'VIOLATED' else 'NOTE-holds-without', 0.0)
