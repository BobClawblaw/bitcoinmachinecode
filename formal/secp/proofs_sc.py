"""proofs_sc.py -- the scalar (mod n) proofs over the lifted real code.

sc_mul: the 16 MULACC blocks, the 8 FOLD blocks and the 3 CONDS blocks are
cut at their first instructions.  For each cut-point segment the
accumulator (10 limbs at [rbp-0x50]) is replaced by fresh symbols:
  MULACC (one run from entry):  acc == sum a_i*b_j*2^(64(i+j))         (algebraic)
  FOLD k (fresh acc X):          acc' == X_lo + (limbs 4..8 of X)*DELTA  (algebraic)
  bound chain:  X_0 <= (2^256-1)^2,  X_{k+1} <= V_{k+1}, V_8 <= 2^256-1  (z3 LIA)
  CONDS (fresh X < 2^256):       r == X mod n, r < n                   (z3 QF_BV)
  glue: DELTA == 2^256 - n, so X_lo + X_hi*DELTA == X (mod n)            (z3 LIA)
"""
import time
import z3
import x86sym as X
import common as Cm
import linform as LF
import proofs_fe as F

DELTA = 2**256 - Cm.N
G1 = 0x3086D221A7D46BCDE86C90E49284EB153DAA8A1471E8CA7FE893209A45DBB031
G2 = 0xE4437ED6010E88286F547FA90ABFE4C4221208AC9DF506C61571B4AE8AC47F71
MB1 = 0xE4437ED6010E88286F547FA90ABFE4C3
MB2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE8A280AC50774346DD765CDA83DB1562C
A1 = Cm.N - MB2
A2 = (-Cm.LAMBDA * A1) % Cm.N


def cuts(img, fn):
    base = img.symbols[fn]
    end = img.symbols['sc_sqr'] if fn == 'sc_mul' else None
    folds, conds = [], []
    a = base
    while a != end and img.insns[a][0] != 'ret':
        t = img.insns[a][0]
        if t.startswith('lea    rdi,[rbp-0xa0]'):
            folds.append(a)
        if t.startswith('mov    r8,QWORD PTR [rbp-0x50]') and folds:
            conds.append(a)
        a = img.next_addr[a]
    return folds, conds


def acc_addrs(rbp):
    return [rbp - 0x50 + 8 * i for i in range(10)]


def sc_mul_proofs(R, pid):
    t0 = time.time()
    img = Cm.image()
    folds, conds = cuts(img, 'sc_mul')
    snaps = {}

    def grab(name):
        return lambda st: snaps.setdefault(name, st.copy())
    probes = {a: grab(('fold', i)) for i, a in enumerate(folds)}
    probes.update({a: grab(('cond', i)) for i, a in enumerate(conds)})
    alg = LF.Alg()
    m, finals, ins, outp = F.run_sym('sc_mul', 2, alg=alg, probes=probes)
    a, b = ins
    ok_shape = len(finals) == 1 and not Cm.abi_ok(finals[0]) and not F.writes_ok(m, outp, 32)
    # MULACC
    s0 = snaps[('fold', 0)]
    rbp = s0.regs['rbp']
    acc = [s0.mem.load(x, 8) for x in acc_addrs(rbp)]
    spec = {}
    for i in range(4):
        for j in range(4):
            spec = LF.f_add(spec, LF.f_scale(LF.f_mul(alg.form(a[i], 64), alg.form(b[j], 64)), 1 << (64 * (i + j))))
    r, how = alg.check_eq(alg.value(acc), spec)
    R.add(pid + '.mulacc', 'sc_mul', '16 MULACC: 10-limb acc == sum a_i*b_j*2^(64(i+j)) exactly; one path, ABI, '
          'writes OK  [%s]' % how, 'algebraic + z3 LIA', 'unbounded (all 2^512 inputs)',
          r if ok_shape else 'VIOLATED', time.time() - t0)
    allok = r == 'PROVED' and ok_shape
    # FOLD k
    ends = folds[1:] + [conds[0]]
    for k, (st_a, en_a) in enumerate(zip(folds, ends)):
        t1 = time.time()
        s = snaps[('fold', k)].copy()
        xs = Cm.sym_limbs('x%d_' % k, 10)
        for ad, v in zip(acc_addrs(rbp), xs):
            s.mem.store(ad, v, 8)
        al = LF.Alg()
        mk = X.Machine(img, alg=al)
        fin = mk.run(s, stop_at=en_a, skip_first=True)
        assert len(fin) == 1
        out = [fin[0].mem.load(ad, 8) for ad in acc_addrs(rbp)]
        hi = al.value(xs[4:9])
        spec = LF.f_add(al.value(xs[:4]), LF.f_scale(hi, DELTA))
        r, how = al.check_eq(al.value(out), spec)
        R.add('%s.fold%d' % (pid, k + 1), 'sc_mul', 'FOLD %d: acc\' == X_lo + X[4..8]*DELTA exactly  [%s]' % (k + 1, how),
              'algebraic', 'unbounded (all 2^640 X)', r, time.time() - t1)
        allok &= r == 'PROVED'
    # bound chain (LIA)
    t1 = time.time()
    V = (2**256 - 1)**2
    bounds = [V]
    okb = True
    for k in range(len(folds)):
        H = V >> 256
        cand = [min(V, 2**256 - 1), V - H * Cm.N]
        if H >= 1:
            cand.append(2**256 - 1 + (H - 1) * DELTA)
        V2 = max(cand)
        Lo, Hi = z3.Ints('Lo Hi')
        s = z3.SolverFor('QF_LIA')
        s.add(Lo >= 0, Lo < 2**256, Hi >= 0, Lo + 2**256 * Hi <= V)
        s.add(z3.Or(Hi >= 2**320, Lo + Hi * DELTA > V2))     # limb 9 would be non-zero, or the bound fails
        okb &= s.check() == z3.unsat
        V = V2
        bounds.append(V)
    okb &= V <= 2**256 - 1
    R.add(pid + '.bound', 'sc_mul', 'bound chain over the %d FOLDs (limb 9 always 0): value after the last '
          'FOLD <= 2^256-1 (needs >= 4 folds; bounds 2^%s)' % (len(folds), ','.join('%.1f' % (b.bit_length())
                                                                                  for b in bounds)),
          'z3 LIA', 'unbounded', 'PROVED' if okb else 'VIOLATED', time.time() - t1)
    allok &= okb
    # CONDS: from the first CONDS with fresh X (limbs 0..3), to the end
    t1 = time.time()
    s = snaps[('cond', 0)].copy()
    xs = Cm.sym_limbs('y', 4)
    for ad, v in zip(acc_addrs(rbp)[:4], xs):
        s.mem.store(ad, v, 8)
    mk = X.Machine(img)
    fin = mk.run(s)
    assert len(fin) == 1
    out = Cm.get(fin[0], outp)
    Xv = F.ext(Cm.val(xs), 264)
    nW = z3.BitVecVal(Cm.N, 264)
    Rr = F.ext(Cm.val(out), 264)
    r, dt, _ = Cm.prove([], z3.And(Rr == z3.If(z3.UGE(Xv, nW), Xv - nW, Xv), z3.ULT(Rr, nW)))
    R.add(pid + '.conds', 'sc_mul', '3 CONDS from any X < 2^256: r == X mod n, r < n; ABI OK', 'z3 QF_BV',
          'unbounded', r if not Cm.abi_ok(fin[0]) else 'VIOLATED', time.time() - t1)
    allok &= r == 'PROVED'
    g = z3.Solver()
    g.add(DELTA != 2**256 - Cm.N)
    R.add(pid + '.glue', 'sc_mul', 'DELTA == 2^256 - n (each FOLD is a congruence mod n)', 'z3 LIA', 'unbounded',
          'PROVED' if g.check() == z3.unsat else 'VIOLATED', 0.0)
    return allok


def sc_mul_512(R, pid):
    t0 = time.time()
    alg = LF.Alg()
    m, finals, ins, outp = F.run_sym('sc_mul_512', 2, alg=alg)
    a, b = ins
    out = Cm.get(finals[0], outp, 8)
    spec = {}
    for i in range(4):
        for j in range(4):
            spec = LF.f_add(spec, LF.f_scale(LF.f_mul(alg.form(a[i], 64), alg.form(b[j], 64)), 1 << (64 * (i + j))))
    r, how = alg.check_eq(alg.value(out), spec)
    ok = len(finals) == 1 and not Cm.abi_ok(finals[0]) and not F.writes_ok(m, outp, 64)
    R.add(pid, 'sc_mul_512', 'r[0..7] == a*b exactly (512-bit); one path, ABI, writes OK  [%s]' % how,
          'algebraic + z3 LIA', 'unbounded', r if ok else 'VIOLATED', time.time() - t0)


def add_sub(R, pid, fn, op):
    t0 = time.time()
    m, finals, ins, outp = F.run_sym(fn, 2)
    a, b = ins
    out = Cm.get(finals[0], outp)
    nW = z3.BitVecVal(Cm.N, 264)
    A, B, Rr = F.ext(Cm.val(a), 264), F.ext(Cm.val(b), 264), F.ext(Cm.val(out), 264)
    if op == 'add':
        s = A + B
        spec = z3.If(z3.UGE(s, nW), s - nW, s)
    else:
        spec = z3.If(z3.UGE(A, B), A - B, A + nW - B)
    goal = z3.And(Rr == spec, z3.ULT(Rr, nW))
    r, dt, _ = Cm.prove([z3.ULT(A, nW), z3.ULT(B, nW)], goal)
    ok = len(finals) == 1 and not Cm.abi_ok(finals[0]) and not F.writes_ok(m, outp, 32)
    R.add(pid, fn, 'a,b < n => r == (a %s b) mod n, r < n; one path, ABI, writes OK' % ('+' if op == 'add' else '-'),
          'z3 QF_BV', 'unbounded', r if ok else 'VIOLATED', time.time() - t0)
    r2, dt2, mdl = Cm.prove([], goal)
    note = ''
    if r2 == 'VIOLATED':
        note = ' (e.g. a=%#x, b=%#x)' % tuple(X.from_limbs([mdl.eval(x, model_completion=True).as_long() for x in v])
                                             for v in (a, b))
    R.add(pid + '.pre', fn, 'the precondition a,b < n is needed%s' % note, 'z3 QF_BV', 'unbounded',
          'PROVED' if r2 == 'VIOLATED' else 'NOTE-holds-without', dt2)


def sc_half(R, pid):
    t0 = time.time()
    m, finals, ins, outp = F.run_sym('sc_half_ct', 1)
    (a,) = ins
    out = Cm.get(finals[0], outp)
    nW = z3.BitVecVal(Cm.N, 264)
    A, Rr = F.ext(Cm.val(a), 264), F.ext(Cm.val(out), 264)
    goal = z3.And(z3.Or(Rr * 2 == A, Rr * 2 == A + nW), z3.ULT(Rr, nW))
    r, dt, _ = Cm.prove([z3.ULT(A, nW)], goal)
    ok = len(finals) == 1 and not Cm.abi_ok(finals[0])
    R.add(pid, 'sc_half_ct', 'a < n => 2r == a (mod n), r < n', 'z3 QF_BV', 'unbounded',
          r if ok else 'VIOLATED', time.time() - t0)


def sc_inv(R, pid):
    t0 = time.time()
    img = Cm.image()
    log = []
    m = X.Machine(img, hooks=F.exp_hooks(img, mul='sc_mul', sqr=None, tag='sw', log=log), mode='ct')
    st = Cm.new_state(img)
    Cm.put(st, Cm.BUF[1], F.token(1, 'sw'))
    fin = Cm.call(m, st, 'sc_inv', [Cm.BUF[0], Cm.BUF[1]])
    e = F.read_exp(fin[0], Cm.BUF[0], 'sw')
    ok = e == Cm.N - 2 and len(fin) == 1 and not Cm.abi_ok(fin[0])
    R.add(pid, 'sc_inv', 'square-and-multiply over N_EXP builds a^(n-2) (%d sc_mul); its branches read only '
          'the public exponent' % len(log), 'exponent tracking over proved sc_mul', 'exact',
          'PROVED' if ok else 'VIOLATED', time.time() - t0)


# --------------------------------------------------------------------------
def split_glue(R, pid):
    """sc_split_lambda's own code, with every callee (proved separately) summarised
    by a hook that records its arguments and returns fresh symbols"""
    t0 = time.time()
    img = Cm.image()
    calls = []

    def hook(name, nout):
        def h(m, st):
            rdi, rsi, rdx = (m.concrete_addr(st, st.regs[r]) for r in ('rdi', 'rsi', 'rdx'))
            args = [[z3.simplify(X.bv(st.mem.load(p + 8 * i, 8), 64)) for i in range(4)] for p in (rsi, rdx)]
            outv = Cm.sym_limbs('%s%d_' % (name, len(calls)), nout)
            calls.append((name, rdi, rsi, rdx, args, outv))
            F.clobber(st)
            Cm.put(st, rdi, outv)
        return h
    hooks = {img.symbols['sc_mul_512']: hook('mul512_', 8), img.symbols['sc_mul']: hook('mul_', 4),
             img.symbols['sc_add']: hook('add_', 4), img.symbols['sc_sub']: hook('sub_', 4)}
    m = X.Machine(img, hooks=hooks, mode='fork')
    st = Cm.new_state(img)
    k = Cm.sym_limbs('k_')
    Cm.put(st, Cm.BUF[2], k)
    fin = Cm.call(m, st, 'sc_split_lambda', [Cm.BUF[0], Cm.BUF[1], Cm.BUF[2]])
    seq = [c[0] for c in calls]
    ok = seq == ['mul512_', 'mul512_', 'mul_', 'mul_', 'add_', 'mul_', 'sub_', 'mul_', 'add_']
    notes = []
    if ok:
        c = {i: calls[i] for i in range(9)}
        K = Cm.val(k)

        def same(x, y):
            s = z3.Solver()
            s.add(Cm.val(x) != Cm.val(y))
            return s.check() == z3.unsat

        def isconst(x, v):
            return same(x, X.to_int_limbs(v))
        ok &= same(c[0][4][0], k) and isconst(c[0][4][1], G1)
        ok &= same(c[1][4][0], k) and isconst(c[1][4][1], G2)
        for idx, call_ in ((2, 0), (3, 1)):
            P = Cm.val(c[call_][5])                                    # the 512-bit product
            rnd = z3.LShR(z3.ZeroExt(1, P) + (1 << 383), 384)          # round(P / 2^384)
            arg = F.ext(Cm.val(c[idx][4][0]), 513)
            r, dt, _ = Cm.prove([], arg == rnd)
            ok &= r == 'PROVED'
            notes.append('c%d == round(k*g%d/2^384): %s' % (idx - 1, idx - 1, r))
        ok &= isconst(c[2][4][1], MB1) and isconst(c[3][4][1], MB2)
        ok &= same(c[4][4][0], c[2][5]) and same(c[4][4][1], c[3][5]) and c[4][1] == Cm.BUF[1]   # r2 = d1 + d2
        ok &= same(c[5][4][0], c[4][5]) and isconst(c[5][4][1], Cm.LAMBDA)                       # t = r2*lambda
        ok &= same(c[6][4][0], k) and same(c[6][4][1], c[5][5]) and c[6][1] == Cm.BUF[0]          # r1 = k - t
        ok &= isconst(c[7][4][0], Cm.LAMBDA) and same(c[7][4][1], c[4][5])                       # lambda*r2
        ok &= same(c[8][4][0], c[7][5]) and same(c[8][4][1], c[6][5])                            # + r1
        # the return value is 1 exactly when the recombination equals k (both paths)
        for f in fin:
            ret = z3.Extract(31, 0, X.bv(f.regs['rax'], 64))
            pc = z3.And(*f.pc) if f.pc else z3.BoolVal(True)
            eqk = Cm.val(c[8][5]) == K
            s = z3.Solver()
            s.add(pc, z3.Not(ret == z3.If(eqk, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))))
            ok &= s.check() == z3.unsat
            ok &= not Cm.abi_ok(f)
    R.add(pid, 'sc_split_lambda', 'dataflow: c_i = round(k*g_i/2^384) (the 383-bit rounding), r2 = c1*(-b1) + '
          'c2*(-b2), r1 = k - lambda*r2, returns (lambda*r2 + r1 == k); %s' % '; '.join(notes),
          'lifter + z3 QF_BV, callees summarised', 'unbounded', 'PROVED' if ok else 'VIOLATED', time.time() - t0)
    return ok


def split_math(R, pid):
    """with the proved callee specs: for every k < n, |k1|, |k2| < 2^128 and the
    function returns 1; for k >= n it returns 0"""
    t0 = time.time()
    N, L = Cm.N, Cm.LAMBDA
    consts = (L * MB1) % N == A1 and (-L * A1) % N == A2 and (L ** 3) % N == 1 and MB2 == N - A1
    k, c1, c2 = z3.Ints('k c1 c2')
    s = z3.SolverFor('QF_LIA')
    s.add(k >= 0, k < N)
    s.add(2**384 * c1 <= k * G1 + 2**383, k * G1 + 2**383 < 2**384 * (c1 + 1))
    s.add(2**384 * c2 <= k * G2 + 2**383, k * G2 + 2**383 < 2**384 * (c2 + 1))
    k2 = c1 * MB1 - c2 * A1            # == r2 (mod n): c2*MB2 == -c2*A1
    k1 = k - c1 * A1 - c2 * A2         # == k - lambda*k2 (mod n), by the constants above
    B = 2**128
    res = []
    for nm, e in (('k2', k2), ('k1', k1)):
        s.push()
        s.add(z3.Or(e >= B, e <= -B))
        res.append(s.check() == z3.unsat)
        s.pop()
    ok = consts and all(res)
    R.add(pid, 'sc_split_lambda (math)', 'k < n => the integers k1 = k - c1*a1 - c2*a2 and k2 = c1*(-b1) - c2*a1 '
          'satisfy |k1|,|k2| < 2^128, and r1 == k1, r2 == k2 (mod n), so the signed representatives the '
          'callers take (bit 255 => negative) are k1, k2 and fit the 129-bit (glvj) / 132-bit (glv) windows; '
          'the recombination check is (k1 + lambda*k2) mod n == k, true iff k < n (k >= n: returns 0)',
          'z3 LIA + constant checks', 'unbounded (all k < n)', 'PROVED' if ok else 'VIOLATED', time.time() - t0)
    return ok
