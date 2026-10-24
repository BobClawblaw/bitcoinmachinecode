"""proofs_fe.py -- the field (mod p) proofs over the lifted real code.

fe_mul / fe_sqr are proved in two parts that meet at the label fe_mul.reduce
(the cut-point where fe_sqr jumps in):
  product part (algebraic, linform.py): the eight registers r8..r15 at
     .reduce hold exactly sum_{i,j} a_i*b_j*2^(64(i+j)), for all inputs;
  reduction part: from .reduce with r8..r15 = an ARBITRARY 512-bit T,
        S  = r8..r11 + rsi*2^256 at `mulx rbx,rax,rsi`:   S == T_lo + C*T_hi     (algebraic)
        V2 + c*2^256 at the next `sbb rax,rax`:          == S_lo + u4*C        (algebraic)
        V2 + c*2^256 <= 2^256 - 1 + C^2                                        (LIA)
        tail from that point, with v, c FRESH and only the bound above assumed:
          r == X - p if X >= p else X  where X = v + c*C,  and r < p           (z3 QF_BV)
     Each congruence step is 2^256 == C (mod p), checked once in LIA.
  Hence r < p and r == a*b (mod p) for every 256-bit a, b (no precondition).
"""
import time
import z3
import x86sym as X
import common as Cm
import linform as LF

W = 640


def ext(v, w=W):
    return z3.ZeroExt(w - v.size(), v) if v.size() < w else v


def find_after(img, start, prefix, nth=1, limit=4000):
    a, k = start, 0
    for _ in range(limit):
        t = img.insns[a][0]
        if t.startswith(prefix):
            k += 1
            if k == nth:
                return a
        a = img.next_addr[a]
    raise RuntimeError('pattern %r not found after %#x' % (prefix, start))


def writes_ok(m, out_addr, out_len):
    """every store went to the output buffer or below the entry stack pointer"""
    bad = []
    for a, n, rip in m.write_log:
        if out_addr <= a and a + n <= out_addr + out_len:
            continue
        if Cm.STACK_TOP - 0x100000 <= a and a + n <= Cm.STACK_TOP:
            continue
        bad.append((hex(a), n, hex(rip)))
    return bad


def run_sym(fn, nin, alg=None, probes=None, alias=None, pre=('a_', 'b_'), product_mode='abstract'):
    img = Cm.image()
    m = X.Machine(img, alg=alg, probes=probes or {}, product_mode=product_mode)
    st = Cm.new_state(img)
    ins = [Cm.sym_limbs(pre[k]) for k in range(nin)]
    for k in range(nin):
        Cm.put(st, Cm.BUF[1 + k], ins[k])
    args = [Cm.BUF[0]] + [Cm.BUF[1 + k] for k in range(nin)]
    if alias is not None:
        args[0] = args[1 + alias]
    m.write_log = []
    finals = Cm.call(m, st, fn, args)
    return m, finals, ins, args[0]


# --------------------------------------------------------------------------
def product_part(R, fn, pid):
    t0 = time.time()
    img = Cm.image()
    alg = LF.Alg()
    snap = {}

    def probe(st):
        snap.setdefault('T', [st.regs['r%d' % i] for i in range(8, 16)])
        snap.setdefault('rbp', st.regs['rbp'])
    m, finals, ins, outp = run_sym(fn, 2 if fn == 'fe_mul' else 1, alg=alg,
                                   probes={img.symbols['fe_mul.reduce']: probe})
    a = ins[0]
    b = ins[1] if fn == 'fe_mul' else ins[0]
    T = alg.value(snap['T'])
    spec = {}
    for i in range(4):
        for j in range(4):
            spec = LF.f_add(spec, LF.f_scale(LF.f_mul(alg.form(a[i], 64), alg.form(b[j], 64)), 1 << (64 * (i + j))))
    res, how = alg.check_eq(T, spec)
    if snap['rbp'] != 0:          # the reduction's `adcx rsi, rbp` absorbs a carry only if rbp == 0
        res, how = 'VIOLATED', 'rbp != 0 at .reduce'
    abi, wr = Cm.abi_ok(finals[0]), writes_ok(m, outp, 32)
    if len(finals) != 1 or abi or wr:
        res, how = 'VIOLATED', 'paths=%d abi=%s writes=%s' % (len(finals), abi, wr)
    R.add(pid, fn, 'at .reduce r8..r15 == sum a_i*b_j*2^(64(i+j)) exactly, rbp == 0; one path; ABI and '
          'write set OK  [%s; %d carries shown 0 by interval]' % (how, alg.zero_carries),
          'algebraic + z3 LIA', 'unbounded (all 2^512 / 2^256 inputs)', res, time.time() - t0)
    return res


def reduction(R, pid):
    t0 = time.time()
    img = Cm.image()
    red = img.symbols['fe_mul.reduce']
    a_S = find_after(img, red, 'mulx   rbx,rax,rsi')
    a_V2 = find_after(img, a_S, 'sbb    rax,rax')
    # cut-point state at .reduce: run fe_mul on zeros, then make r8..r15 fresh
    m0 = X.Machine(img)
    st = Cm.new_state(img)
    Cm.put(st, Cm.BUF[1], [0] * 4)
    Cm.put(st, Cm.BUF[2], [0] * 4)
    cut = {}
    m0.probes = {red: lambda s: cut.setdefault('st', s.copy())}
    Cm.call(m0, st, 'fe_mul', [Cm.BUF[0], Cm.BUF[1], Cm.BUF[2]])
    s = cut['st']
    t = Cm.sym_limbs('t', 8)
    for i in range(8):
        s.regs['r%d' % (8 + i)] = t[i]
    alg = LF.Alg()
    snaps = {}

    def pS(st):
        snaps['S'] = ([st.regs['r%d' % i] for i in range(8, 12)], st.regs['rsi'])

    def pV2(st):
        snaps['V2'] = ([st.regs['r%d' % i] for i in range(8, 12)], st.flags['CF'])
        snaps['st'] = st.copy()
    m = X.Machine(img, alg=alg, probes={a_S: pS, a_V2: pV2})
    m.run(s)
    Sl, u4 = snaps['S']
    fS = LF.f_add(alg.value(Sl), LF.f_scale(alg.form(u4, 64), 1 << 256))
    fT = alg.value(t)
    spec_S = LF.f_add(alg.value(t[:4]), LF.f_scale(alg.value(t[4:]), Cm.C))
    r1 = alg.check_eq(fS, spec_S)
    R.add(pid + '.1', 'fe_mul.reduce', 'S = r8..r11 + rsi*2^256 == T_lo + C*T_hi  [%s]' % r1[1],
          'algebraic', 'unbounded (all 2^512 T)', r1[0], time.time() - t0)
    V2l, c = snaps['V2']
    fV2 = LF.f_add(alg.value(V2l), LF.f_scale(alg.bform(c), 1 << 256))
    spec_V2 = LF.f_add(alg.value(Sl), LF.f_scale(alg.form(u4, 64), Cm.C))
    r2 = alg.check_eq(fV2, spec_V2)
    R.add(pid + '.2', 'fe_mul.reduce', 'V2 + c*2^256 == S_lo + u4*C  [%s]' % r2[1],
          'algebraic', 'unbounded', r2[0], time.time() - t0)
    # the bound the tail relies on; T_lo + C*T_hi <= (2^256-1)(1+C) gives u4 <= C
    alg.facts.append((fS, 0, (2**256 - 1) * (1 + Cm.C)))      # interval-valid: fS == spec_S
    lo, hi = alg.interval(spec_S)
    ok_iv = hi <= (2**256 - 1) * (1 + Cm.C)
    r3 = alg.check_le(fV2, 2**256 - 1 + Cm.C * Cm.C)
    if not ok_iv:
        r3 = ('VIOLATED', 'interval of S')
    R.add(pid + '.3', 'fe_mul.reduce', 'V2 + c*2^256 <= 2^256 - 1 + C^2  [%s]' % r3[1],
          'z3 LIA', 'unbounded', r3[0], time.time() - t0)
    # tail: fresh v, c at the V2 point
    s2 = snaps['st']
    v = Cm.sym_limbs('v', 4)
    for i in range(4):
        s2.regs['r%d' % (8 + i)] = v[i]
    cb = z3.Bool('c')
    s2.flags['CF'] = cb
    mt = X.Machine(img)
    fin = mt.run(s2)
    assert len(fin) == 1
    out = Cm.get(fin[0], Cm.BUF[0])
    V = ext(Cm.val(v), 320)
    pre = [z3.Implies(cb, z3.ULE(V, Cm.C * Cm.C - 1))]
    Xv = V + z3.If(cb, z3.BitVecVal(Cm.C, 320), z3.BitVecVal(0, 320))
    pW = z3.BitVecVal(Cm.P, 320)
    rr = ext(Cm.val(out), 320)
    goal = z3.And(rr == z3.If(z3.UGE(Xv, pW), Xv - pW, Xv), z3.ULT(rr, pW))
    r4, dt, _ = Cm.prove(pre, goal)
    abi = Cm.abi_ok(fin[0])
    if abi:
        r4 = 'VIOLATED'
    R.add(pid + '.4', 'fe_mul.reduce', 'tail: r == (X >= p ? X - p : X), X = v + c*C, r < p; ABI OK',
          'z3 QF_BV (cut-point)', 'unbounded (all v, c under the .3 bound)', r4, dt)
    # glue: the congruences
    sol = z3.Solver()
    x, y = z3.Ints('x y')
    sol.add(z3.Not(z3.And(2**256 * x - Cm.C * x == Cm.P * x, Cm.C == 2**256 - Cm.P)))
    g = 'PROVED' if sol.check() == z3.unsat else 'VIOLATED'
    R.add(pid + '.5', 'fe_mul.reduce', 'glue: 2^256*x - C*x == p*x, so each fold is a congruence mod p',
          'z3 LIA', 'unbounded', g, 0.0)
    return all(z == 'PROVED' for z in (r1[0], r2[0], r3[0], r4, g))


# --------------------------------------------------------------------------
def add_like(R, pid, fn, op, nin=2, alias=None, check_pre=True):
    """fe_add / fe_sub / the inline-macro wrappers: a,b < p => r == (a op b) mod p, r < p"""
    t0 = time.time()
    m, finals, ins, outp = run_sym(fn, nin, alias=alias)
    a = ins[0]
    b = ins[1] if nin == 2 else ins[0]
    out = Cm.get(finals[0], outp)
    pW = z3.BitVecVal(Cm.P, 320)
    A, B, Rr = ext(Cm.val(a), 320), ext(Cm.val(b), 320), ext(Cm.val(out), 320)
    if op == 'add':
        s = A + B
        spec = z3.If(z3.UGE(s, pW), s - pW, s)
    else:
        spec = z3.If(z3.UGE(A, B), A - B, A + pW - B)
    pre = [z3.ULT(A, pW), z3.ULT(B, pW)]
    goal = z3.And(Rr == spec, z3.ULT(Rr, pW))
    res, dt, _ = Cm.prove(m.side + pre, goal)
    abi, wr = Cm.abi_ok(finals[0]), writes_ok(m, outp, 32)
    if abi or wr or len(finals) != 1:
        res = 'VIOLATED'
    R.add(pid, fn + (' (r aliases a)' if alias == 0 else ''),
          'a,b < p => r == (a %s b) mod p and r < p; one path; ABI, write set OK' % ('+' if op == 'add' else '-'),
          'z3 QF_BV', 'unbounded (all canonical a, b)', res, time.time() - t0)
    if check_pre:
        r2, dt2, mdl = Cm.prove(m.side, goal)
        note = ''
        if r2 == 'VIOLATED':
            av = X.from_limbs([mdl.eval(x, model_completion=True).as_long() for x in a])
            bv_ = X.from_limbs([mdl.eval(x, model_completion=True).as_long() for x in b])
            note = ' (e.g. a=%#x, b=%#x)' % (av, bv_)
        R.add(pid + '.pre', fn, 'the precondition a,b < p is needed: without it z3 finds a wrong/non-canonical '
              'result%s' % note, 'z3 QF_BV', 'unbounded',
              'PROVED' if r2 == 'VIOLATED' else 'NOTE-holds-without', dt2)
    return res


def fe_half(R, pid):
    """FE_HALF (inline in pointj_add_ge_ct): V canonical => V' == V/2 mod p, V' < p"""
    t0 = time.time()
    img = Cm.image()
    base = img.symbols['pointj_add_ge_ct']
    a = find_after(img, base, 'movabs rcx,0xfffffffefffffc2f')
    # back up to `mov rax,r8` (3 instructions before) -- the macro's first instruction
    rev = {v: k for k, v in img.next_addr.items()}
    start = rev[rev[rev[a]]]
    assert img.insns[start][0].startswith('mov    rax,r8'), img.insns[start]
    end = find_after(img, a, 'rcr    r8,1')
    end = img.next_addr[end]
    st = Cm.new_state(img)
    v = Cm.sym_limbs('v', 4)
    for i in range(4):
        st.regs['r%d' % (8 + i)] = v[i]
    st.rip = start
    m = X.Machine(img)
    fin = m.run(st, stop_at=end)
    assert len(fin) == 1
    out = [fin[0].regs['r%d' % i] for i in range(8, 12)]
    V = ext(Cm.val(v), 320)
    pW = z3.BitVecVal(Cm.P, 320)
    Rr = ext(Cm.val(out), 320)
    # 2*R == V (mod p) with 2R < 2p: equivalently 2R == V or 2R == V + p
    goal = z3.And(z3.Or(Rr * 2 == V, Rr * 2 == V + pW), z3.ULT(Rr, pW))
    res, dt, _ = Cm.prove([z3.ULT(V, pW)], goal)
    R.add(pid, 'FE_HALF (pointj_add_ge_ct)', 'V < p => 2*V\' == V (mod p) and V\' < p', 'z3 QF_BV',
          'unbounded', res, time.time() - t0)
    return res


def eq_zero_c(R, pid):
    """fe_is_zero / fe_equal (crypto_fe_sqrt.c, real gcc output)"""
    t0 = time.time()
    img = Cm.image()
    out = []
    for fn, nin in (('fe_is_zero', 1), ('fe_equal', 2)):
        m = X.Machine(img)
        st = Cm.new_state(img)
        a, b = Cm.sym_limbs('a_'), Cm.sym_limbs('b_')
        Cm.put(st, Cm.BUF[1], a)
        Cm.put(st, Cm.BUF[2], b)
        fin = Cm.call(m, st, fn, [Cm.BUF[1], Cm.BUF[2]])
        assert len(fin) == 1
        ret = fin[0].regs['rax']
        ret = z3.Extract(31, 0, X.bv(ret, 64))
        spec = (Cm.val(a) == 0) if fn == 'fe_is_zero' else (Cm.val(a) == Cm.val(b))
        goal = ret == z3.If(spec, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        res, dt, _ = Cm.prove([], goal)
        if Cm.abi_ok(fin[0]):
            res = 'VIOLATED'
        R.add(pid + ('.zero' if nin == 1 else '.eq'), fn, 'returns 1 iff a == 0 / a == b (as 256-bit '
              'integers; field equality for canonical inputs); branch-free', 'z3 QF_BV', 'unbounded', res,
              time.time() - t0)
        out.append(res)
    return out


# --------------------------------------------------------------------------
# addition chains: exponent tracking.  Every field value is a 4-limb token
# pw<e>_<i>; the hooks for fe_mul / fe_sqr (proved above for ALL inputs:
# r == a*b mod p, r < p, only r[] and their own frame written, callee-saved
# registers preserved) add / double the exponent.
def token(e, tag='pw'):
    return [z3.BitVec('%s%d_%d' % (tag, e, i), 64) for i in range(4)]


def read_exp(st, addr, tag='pw'):
    ls = [st.mem.load(addr + 8 * i, 8) for i in range(4)]
    ls = [x if X.isc(x) else z3.simplify(x) for x in ls]     # SSE copies leave Extract(Concat(..))
    es = set()
    for i, x in enumerate(ls):
        if X.isc(x) or not z3.is_const(x):
            raise X.SymError('not a token at %#x' % addr)
        name = str(x)
        if not name.startswith(tag) or not name.endswith('_%d' % i):
            raise X.SymError('limb %d of %#x is %s' % (i, addr, name))
        es.add(int(name[len(tag):name.rindex('_')]))
    if len(es) != 1:
        raise X.SymError('mixed token at %#x' % addr)
    return es.pop()


def clobber(st):
    for r in ('rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'):
        st.regs[r] = None
    for f in st.flags:
        st.flags[f] = X.UNDEF


def exp_hooks(img, mul='fe_mul', sqr='fe_sqr', tag='pw', log=None):
    def h_mul(m, st):
        ra = m.concrete_addr(st, st.regs['rdi'])
        e = read_exp(st, m.concrete_addr(st, st.regs['rsi']), tag) + read_exp(st, m.concrete_addr(st, st.regs['rdx']), tag)
        clobber(st)
        Cm.put(st, ra, token(e, tag))
        if log is not None:
            log.append(('mul', e))

    def h_sqr(m, st):
        ra = m.concrete_addr(st, st.regs['rdi'])
        e = 2 * read_exp(st, m.concrete_addr(st, st.regs['rsi']), tag)
        clobber(st)
        Cm.put(st, ra, token(e, tag))
        if log is not None:
            log.append(('sqr', e))
    h = {img.symbols[mul]: h_mul}
    if sqr:
        h[img.symbols[sqr]] = h_sqr
    return h


def chain(R, pid, fn, want, what, alias=False):
    t0 = time.time()
    img = Cm.image()
    log = []
    m = X.Machine(img, hooks=exp_hooks(img, log=log), mode='ct')
    st = Cm.new_state(img)
    Cm.put(st, Cm.BUF[1], token(1))
    outp = Cm.BUF[1] if alias else Cm.BUF[0]
    fin = Cm.call(m, st, fn, [outp, Cm.BUF[1]])
    e = read_exp(fin[0], outp)
    res = 'PROVED' if (e == want and len(fin) == 1 and not Cm.abi_ok(fin[0])) else 'VIOLATED'
    R.add(pid, fn + (' (r aliases a)' if alias else ''),
          'the chain computes a^(%s): exponent built == %s (%d sqr, %d mul); no secret branch/address' %
          (what, 'yes' if e == want else hex(e), sum(1 for k, _ in log if k == 'sqr'),
           sum(1 for k, _ in log if k == 'mul')),
          'exponent tracking over proved fe_mul/fe_sqr', 'exact', res, time.time() - t0)
    return res


def fe_sqrt_c(R, pid):
    """crypto_fe_sqrt.c fe_sqrt: on the path returning 1, r == a^((p+1)/4) and the
    path condition is (a^((p+1)/4))^2 == a; on the path returning 0 r is untouched"""
    t0 = time.time()
    img = Cm.image()
    m = X.Machine(img, hooks=exp_hooks(img), mode='fork')
    st = Cm.new_state(img)
    Cm.put(st, Cm.BUF[1], token(1))
    Cm.put(st, Cm.BUF[0], [0, 0, 0, 0])
    fin = Cm.call(m, st, 'fe_sqrt', [Cm.BUF[0], Cm.BUF[1]])
    want = (Cm.P + 1) // 4
    ok = len(fin) == 2
    for f in fin:
        ret = X.bv(f.regs['rax'], 64)
        r1 = z3.simplify(z3.Extract(31, 0, ret) == 1)
        if z3.is_true(r1):
            ok &= read_exp(f, Cm.BUF[0]) == want
            pc = z3.simplify(z3.And(*f.pc))
            # the success condition is exactly chk == a, chk = token 2*want
            spec = Cm.val(token(2 * want)) == Cm.val(token(1))
            s = z3.Solver()
            s.add(z3.Not(pc == spec))
            ok &= s.check() == z3.unsat
        else:
            ok &= z3.is_true(z3.simplify(z3.Extract(31, 0, ret) == 0))
            ok &= Cm.get(f, Cm.BUF[0]) == [0, 0, 0, 0]
    R.add(pid, 'fe_sqrt (C)', 'returns 1 with r == a^((p+1)/4) exactly when (a^((p+1)/4))^2 == a; else 0, r '
          'untouched', 'exponent tracking + path enumeration', 'exact', 'PROVED' if ok else 'VIOLATED',
          time.time() - t0)


def exps_math(R, pid):
    """the two exponents are the right ones (Python big-int facts + Euler)"""
    ok = (Cm.P % 4 == 3) and pow(3, Cm.P - 1, Cm.P) == 1 and all(pow(x, Cm.P - 2, Cm.P) * x % Cm.P == 1
                                                               for x in (2, 3, 12345, Cm.P - 1))
    R.add(pid, 'fe_inv / sqrt', 'p == 3 mod 4, so a^((p+1)/4) is a root when one exists; a^(p-2) == 1/a '
          '(Fermat; p prime)', 'math (python spot check of Fermat)', 'n/a', 'PROVED' if ok else 'VIOLATED', 0.0)
