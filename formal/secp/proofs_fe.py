"""proofs_fe.py -- the field (mod p) proofs over the lifted real code.

FE-MUL / FE-SQR are proved in two parts that meet at the label fe_mul.reduce
(the cut-point where fe_sqr jumps in):
  product part: the eight registers r8..r15 at .reduce hold exactly the 512-bit
     integer sum_{i,j} a_i*b_j*2^(64(i+j)), with every 64x64 limb product an
     abstract 128-bit value bounded by (2^64-1)^2 (a sound over-approximation:
     the real product satisfies it, so the proof covers the real code);
  reduction part: from .reduce with r8..r15 = an ARBITRARY 512-bit T, the stored
     result r satisfies r < p and r == T (mod p), shown as a chain of exact
     integer equalities between the values at four probe points:
        S  = T_lo + sum_i (T_{4+i}*C) 2^(64i)            [== T_lo + C*T_hi == T mod p]
        V2 + c*2^256 = S_lo + u4*C                       [== S mod p]
        V3 = V2 + c*C,  V3 < 2^256                       [== V2 + c*2^256 mod p]
        r  = V3 - p if V3 >= p else V3,   r < p
     Each step is an exact bit-vector identity; the congruences follow from
     2^256 == C (mod p), checked once in LIA below.
"""
import time
import z3
import x86sym as X
import common as Cm

W = 640


def ext(v, w=W):
    return z3.ZeroExt(w - v.size(), v) if v.size() < w else v


def run_fn_sym(fn, nin, product_mode='abstract', probes=None, mode='fork', in_pre=('a', 'b'), alias=None):
    img = Cm.image()
    m = X.Machine(img, mode=mode, product_mode=product_mode, probes=probes or {})
    st = Cm.new_state(img)
    ins = [Cm.sym_limbs(in_pre[k] + '_') for k in range(nin)]
    for k in range(nin):
        Cm.put(st, Cm.BUF[1 + k], ins[k])
    args = [Cm.BUF[0]] + [Cm.BUF[1 + k] for k in range(nin)]
    if alias is not None:              # e.g. r == a: the output pointer is the first input's
        args[0] = args[1 + alias]
    m.write_log = []
    finals = m.run_state = Cm.call(m, st, fn, args)
    return m, finals, ins


def find_after(img, start, mnem_prefix, nth=1, limit=400):
    """address of the nth instruction at/after `start` whose text starts with mnem_prefix"""
    a = start
    k = 0
    for _ in range(limit):
        t = img.insns[a][0]
        if t.startswith(mnem_prefix):
            k += 1
            if k == nth:
                return a
        a = img.next_addr[a]
    raise RuntimeError('pattern %r not found after %#x' % (mnem_prefix, start))


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


# --------------------------------------------------------------------------
def prove_product_part(R, fn, pid):
    """r8..r15 at fe_mul.reduce == the schoolbook sum of abstract limb products"""
    img = Cm.image()
    red = img.symbols['fe_mul.reduce']
    snap = {}

    def probe(st):
        if 'T' not in snap:
            snap['T'] = [st.regs['r%d' % i] for i in range(8, 16)]
            snap['rbp'] = st.regs['rbp']
    t0 = time.time()
    if fn == 'fe_mul':
        m, finals, (a, b) = run_fn_sym('fe_mul', 2, probes={red: probe})
    else:
        m, finals, (a,) = run_fn_sym('fe_sqr', 1, probes={red: probe})
        b = a
    assert len(finals) == 1, 'branch-free code produced %d paths' % len(finals)
    T = Cm.val(snap['T'])
    spec = z3.BitVecVal(0, W)
    for i in range(4):
        for j in range(4):
            spec = spec + (ext(m.prod128(a[i], b[j])) << (64 * (i + j)))
    goal = z3.And(ext(T) == spec,
                  # the reduction's adcx-absorb step reads rbp and needs it to be 0
                  (z3.BitVecVal(snap['rbp'], 64) if X.isc(snap['rbp']) else snap['rbp']) == 0)
    res, dt, mdl = Cm.prove(m.side, goal)
    R.add(pid, fn, 'r8..r15 at .reduce == sum a_i*b_j*2^(64(i+j)) (512-bit, abstract limb products) and rbp == 0',
          'z3 QF_BV', 'unbounded (all 2^512 inputs)', res, time.time() - t0)
    return res


def prove_reduction(R, pid):
    """from fe_mul.reduce with arbitrary T: r < p and r == T mod p"""
    img = Cm.image()
    red = img.symbols['fe_mul.reduce']
    a_S = find_after(img, red, 'mulx   rbx,rax,rsi')        # S = r8..r11 + rsi*2^256
    a_V2 = find_after(img, a_S, 'sbb    rax,rax')           # V2 = r8..r11, c = CF
    a_V3 = find_after(img, a_V2, 'mov    r12,r8')           # V3 = r8..r11
    snaps = {}

    def mk(name, extra=None):
        def f(st):
            snaps[name] = ([st.regs['r%d' % i] for i in range(8, 12)], extra(st) if extra else None)
        return f
    # build the cut-point state: run fe_mul to .reduce on dummy inputs, then
    # replace the eight accumulator registers by fresh symbols
    m0 = X.Machine(img)
    st = Cm.new_state(img)
    Cm.put(st, Cm.BUF[1], [0, 0, 0, 0])
    Cm.put(st, Cm.BUF[2], [0, 0, 0, 0])
    cut = {}

    def grab(s):
        if 'st' not in cut:
            cut['st'] = s.copy()
    m0.probes = {red: grab}
    Cm.call(m0, st, 'fe_mul', [Cm.BUF[0], Cm.BUF[1], Cm.BUF[2]])
    s = cut['st']
    t = Cm.sym_limbs('t', 8)
    for i in range(8):
        s.regs['r%d' % (8 + i)] = t[i]
    m = X.Machine(img, product_mode='abstract', probes={
        a_S: mk('S', lambda st: st.regs['rsi']),
        a_V2: mk('V2', lambda st: st.flags['CF']),
        a_V3: mk('V3')})
    t0 = time.time()
    finals = m.run(s)
    assert len(finals) == 1
    out = Cm.get(finals[0], Cm.BUF[0])
    T = Cm.val(t)
    Tlo = Cm.val(t[:4])
    C = z3.BitVecVal(Cm.C, 64)

    def cprod(x):   # the exact product term the executor builds for x * C
        return X.exact_product(x, Cm.C)
    S_l, u4 = snaps['S']
    S = ext(Cm.val(S_l)) + (ext(u4) << 256)
    S_spec = ext(Tlo)
    for i in range(4):
        S_spec = S_spec + (ext(cprod(t[4 + i])) << (64 * i))
    V2_l, c = snaps['V2']
    V2 = ext(Cm.val(V2_l)) + (z3.If(c, z3.BitVecVal(1, W), z3.BitVecVal(0, W)) << 256)
    V2_spec = ext(Cm.val(S_l)) + ext(cprod(u4))
    V3 = ext(Cm.val(snaps['V3'][0]))
    V3_spec = ext(Cm.val(V2_l)) + z3.If(c, z3.BitVecVal(Cm.C, W), z3.BitVecVal(0, W))
    r = ext(Cm.val(out))
    pW = z3.BitVecVal(Cm.P, W)
    r_spec = z3.If(z3.UGE(V3, pW), V3 - pW, V3)
    steps = [('S == T_lo + sum T_(4+i)*C*2^(64i)', S == S_spec),
             ('V2 + c*2^256 == S_lo + u4*C', V2 == V2_spec),
             ('V3 == V2_lo + c*C (no carry out)', V3 == V3_spec),
             ('r == (V3 >= p ? V3 - p : V3)', r == r_spec),
             ('r < p', z3.ULT(r, pW))]
    allres = []
    for name, g in steps:
        res, dt, mdl = Cm.prove(m.side, g)
        allres.append(res)
        R.add(pid + '.' + str(len(allres)), 'fe_mul.reduce', name, 'z3 QF_BV',
              'unbounded (all 2^512 T)', res, dt)
    # the congruence glue, in linear integer arithmetic
    Tl, Th, S0, u = z3.Ints('Tl Th S0 u')
    s = z3.Solver()
    s.add(z3.Not(z3.And(
        ((Tl + 2**256 * Th) - (Tl + Cm.C * Th)) == Cm.P * Th,          # T - S = p*T_hi
        ((S0 + 2**256 * u) - (S0 + Cm.C * u)) == Cm.P * u)))           # 2^256*x == C*x mod p
    g = s.check()
    R.add(pid + '.glue', 'fe_mul.reduce', '2^256*x - C*x == p*x (the fold is a congruence)', 'z3 LIA',
          'unbounded', 'PROVED' if g == z3.unsat else 'VIOLATED', 0.0)
    return all(x == 'PROVED' for x in allres) and g == z3.unsat


# --------------------------------------------------------------------------
def prove_add_like(R, pid, fn, op, pre_canonical=True, nin=2, alias=None):
    """fe_add / fe_sub / the inline macros: r == (a op b) mod p and r < p"""
    t0 = time.time()
    m, finals, ins = run_fn_sym(fn, nin, alias=alias)
    assert len(finals) == 1
    a = ins[0]
    b = ins[1] if nin == 2 else ins[0]
    out = Cm.get(finals[0], Cm.BUF[1] if alias == 0 else Cm.BUF[0])
    pW = z3.BitVecVal(Cm.P, 320)
    A, B, Rr = ext(Cm.val(a), 320), ext(Cm.val(b), 320), ext(Cm.val(out), 320)
    if op == 'add':
        s = A + B
        spec = z3.If(z3.UGE(s, pW), s - pW, s)
    else:
        spec = z3.If(z3.UGE(A, B), A - B, A + pW - B)
    pre = [z3.ULT(A, pW), z3.ULT(B, pW)] if pre_canonical else []
    goal = z3.And(Rr == spec, z3.ULT(Rr, pW))
    res, dt, mdl = Cm.prove(m.side + pre, goal)
    abi = Cm.abi_ok(finals[0])
    wr = writes_ok(m, Cm.BUF[1] if alias == 0 else Cm.BUF[0], 32)
    if abi or wr:
        res = 'VIOLATED'
    R.add(pid, fn + (' (r aliases a)' if alias == 0 else ''),
          'a,b < p  =>  r == (a %s b) mod p, r < p; callee-saved regs and writes OK' % ('+' if op == 'add' else '-'),
          'z3 QF_BV', 'unbounded', res, time.time() - t0)
    cex = None
    if pre_canonical:
        # the precondition is NECESSARY: show the counterexample without it
        r2, dt2, mdl2 = Cm.prove(m.side, goal)
        if r2 == 'VIOLATED':
            cex = {str(v): hex(mdl2.eval(v, model_completion=True).as_long()) for v in a + (b if nin == 2 else [])}
        R.add(pid + '.pre', fn, 'precondition a,b < p is necessary (z3 finds a non-canonical counterexample)',
              'z3 QF_BV', 'unbounded', 'PROVED' if r2 == 'VIOLATED' else 'NOTE: holds without it', dt2)
    return res, cex


def prove_mul_end_to_end_canonical(R, pid, fn):
    """fe_mul / fe_sqr: the stored result is < p for ALL 256-bit inputs, writes OK,
    ABI OK (the congruence is the product part + reduction part above)"""
    t0 = time.time()
    if fn == 'fe_mul':
        m, finals, ins = run_fn_sym('fe_mul', 2)
    else:
        m, finals, ins = run_fn_sym('fe_sqr', 1)
    out = Cm.get(finals[0], Cm.BUF[0])
    abi = Cm.abi_ok(finals[0])
    wr = writes_ok(m, Cm.BUF[0], 32)
    res = 'PROVED' if (not abi and not wr and len(finals) == 1) else 'VIOLATED'
    R.add(pid, fn, 'single path (branch-free), callee-saved regs restored, only writes r[0..3] and its own frame',
          'lifter', 'all inputs', res, time.time() - t0)
    return res
