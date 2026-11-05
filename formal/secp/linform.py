"""linform.py -- exact algebraic shadow of the carry-chain arithmetic.

Bit-blasting (z3 QF_BV) cannot prove that a 4x4 schoolbook carry chain equals
the 512-bit product: it has to rediscover the re-association of ~40 additions,
which a SAT solver does not do (a 4-term fold took 58 s abstracted, >120 s
exact).  This module proves those identities the way CryptoLine does: as exact
polynomial identities over the integers, with ranges discharged separately.

While the executor runs, every ADD/ADC/ADCX/ADOX/SUB/SBB/NEG/INC/DEC it executes
records, for its 64-bit result r and carry/borrow c, the identity that its
bit-vector semantics guarantees (and that `selfcheck()` proves with z3):
      add:  val(r) + 2^w * c = val(a) + val(b) + cin
      sub:  val(r) - 2^w * c = val(a) - val(b) - bin
Every value gets a polynomial form F(v) over integer atoms with exact integer
coefficients, F(v) == val(v):
   * an input limb, an abstract product half, an opaque value (the result of
     AND/OR/XOR/CMOV/...) is an atom with bounds [0, 2^w - 1];
   * a carry/borrow is an atom in [0, 1], unless interval arithmetic over the
     operands' bounds shows it is always 0, in which case it is the constant 0
     (each such decision is logged with its bound);
   * a 64x64 product x*y (from MUL/MULX) records hi as an atom and
     lo = F(x)*F(y) - 2^64*hi  (exact; x*y is a degree-2 monomial).
A claim "value == spec" is then checked by expanding both sides: if the
difference is the zero polynomial the claim is PROVED with no solver at all.
Otherwise the residual goes to z3 as linear integer arithmetic (monomials as
bounded integer atoms) together with every recorded range fact (each result
register lies in [0, 2^w - 1]).
Soundness rests on: the identities above (checked by `selfcheck`), the atom
bounds (inputs and registers are w-bit; hi(x*y) <= floor(max(x)max(y)/2^64)),
and sound interval arithmetic (all atoms are non-negative).
"""
import z3

TWO64 = 1 << 64


class Atom:
    __slots__ = ('k', 'lo', 'hi', 'name', 'ref')

    def __init__(self, k, lo, hi, name, ref):
        self.k, self.lo, self.hi, self.name, self.ref = k, lo, hi, name, ref


def f_add(*fs):
    out = {}
    for f in fs:
        for m, c in f.items():
            v = out.get(m, 0) + c
            if v:
                out[m] = v
            else:
                out.pop(m, None)
    return out


def f_scale(f, k):
    return {m: c * k for m, c in f.items()} if k else {}


def f_mul(f, g):
    out = {}
    for m1, c1 in f.items():
        for m2, c2 in g.items():
            m = tuple(sorted(m1 + m2))
            v = out.get(m, 0) + c1 * c2
            if v:
                out[m] = v
            else:
                out.pop(m, None)
    return out


def f_const(c):
    return {(): c} if c else {}


class Alg:
    def __init__(self):
        self.forms = {}      # z3 ast id -> (expr, form)
        self.atoms = {}      # atom key -> Atom
        self.facts = []      # (form, lo, hi): lo <= form <= hi holds
        self.zero_carries = 0
        self.carry_atoms = 0
        self.n = 0

    # ---------------- atoms and forms
    def atom(self, name, lo, hi, ref=None):
        self.n += 1
        k = self.n
        self.atoms[k] = Atom(k, lo, hi, name, ref)
        return {(k,): 1}

    def form(self, v, w):
        """form of a bit-vector value (int or z3 BV)"""
        if isinstance(v, int) and not isinstance(v, bool):
            return f_const(v)
        e = self.forms.get(v.get_id())
        if e is not None:
            return e[1]
        s = z3.simplify(v)
        if z3.is_bv_value(s):
            return f_const(s.as_long())
        if z3.is_app_of(v, z3.Z3_OP_ZERO_EXT):
            f = self.form(v.arg(0), v.arg(0).size())
            self.forms[v.get_id()] = (v, f)
            return f
        f = self.atom(str(v)[:40], 0, (1 << w) - 1, v)
        self.forms[v.get_id()] = (v, f)
        return f

    def bform(self, c):
        """form of a flag (Python bool or z3 Bool) as 0/1"""
        if isinstance(c, bool):
            return f_const(1 if c else 0)
        e = self.forms.get(c.get_id())
        if e is not None:
            return e[1]
        if z3.is_true(c):
            return f_const(1)
        if z3.is_false(c):
            return f_const(0)
        f = self.atom('flag', 0, 1, c)
        self.forms[c.get_id()] = (c, f)
        return f

    def bind(self, v, f):
        if isinstance(v, int) and not isinstance(v, bool):
            return
        if isinstance(v, bool):
            return
        if v.get_id() not in self.forms:
            self.forms[v.get_id()] = (v, f)

    # ---------------- intervals (sound: atoms are non-negative)
    def interval(self, f):
        lo = hi = 0
        for m, c in f.items():
            mlo, mhi = 1, 1
            for k in m:
                a = self.atoms[k]
                mlo *= a.lo
                mhi *= a.hi
            if c > 0:
                lo += c * mlo
                hi += c * mhi
            else:
                lo += c * mhi
                hi += c * mlo
        return lo, hi

    def clamp(self, f, w):
        lo, hi = self.interval(f)
        return max(lo, 0), min(hi, (1 << w) - 1)

    # ---------------- the instruction hooks
    def on_add(self, a, b, cin, r, cout, w):
        fa, fb, fc = self.form(a, w), self.form(b, w), self.bform(cin)
        s = f_add(fa, fb, fc)
        la, ha = self.clamp(fa, w)
        lb, hb = self.clamp(fb, w)
        lc, hc = self.interval(fc)
        if ha + hb + max(hc, 0) < (1 << w):
            self.zero_carries += 1
            fr = s
            self.bind_flag(cout, {})
        else:
            self.carry_atoms += 1
            fco = self.bform_new(cout)
            fr = f_add(s, f_scale(fco, -(1 << w)))
        self.bind(r, fr)
        self.facts.append((fr, 0, (1 << w) - 1))

    def on_sub(self, a, b, bin_, r, bout, w):
        fa, fb, fc = self.form(a, w), self.form(b, w), self.bform(bin_)
        d = f_add(fa, f_scale(fb, -1), f_scale(fc, -1))
        la, ha = self.clamp(fa, w)
        lb, hb = self.clamp(fb, w)
        lc, hc = self.interval(fc)
        if la - hb - max(hc, 0) >= 0:
            self.zero_carries += 1
            fr = d
            self.bind_flag(bout, {})
        else:
            self.carry_atoms += 1
            fbo = self.bform_new(bout)
            fr = f_add(d, f_scale(fbo, 1 << w))
        self.bind(r, fr)
        self.facts.append((fr, 0, (1 << w) - 1))

    def bind_flag(self, c, f):
        if isinstance(c, bool):
            return
        if c.get_id() not in self.forms:
            self.forms[c.get_id()] = (c, f)

    def bform_new(self, c):
        if isinstance(c, bool):
            return f_const(1 if c else 0)
        e = self.forms.get(c.get_id())
        if e is not None:
            return e[1]
        f = self.atom('carry', 0, 1, c)
        self.forms[c.get_id()] = (c, f)
        return f

    def on_product(self, x, y, hi, lo):
        fx, fy = self.form(x, 64), self.form(y, 64)
        if not isinstance(hi, int) and hi.get_id() in self.forms:
            return
        _, hx = self.clamp(fx, 64)
        _, hy = self.clamp(fy, 64)
        fh = self.atom('hi', 0, (hx * hy) >> 64, hi)
        self.bind(hi, fh)
        fl = f_add(f_mul(fx, fy), f_scale(fh, -TWO64))
        self.bind(lo, fl)
        self.facts.append((fl, 0, TWO64 - 1))

    # ---------------- claims
    def value(self, limbs, w=64):
        f = {}
        for i, v in enumerate(limbs):
            f = f_add(f, f_scale(self.form(v, w), 1 << (w * i)))
        return f

    def check_eq(self, lhs, rhs, timeout_s=300):
        """lhs == rhs as integers.  Returns ('PROVED', how) or ('OPEN'/'VIOLATED', info)"""
        res = f_add(lhs, f_scale(rhs, -1))
        if not res:
            return 'PROVED', 'polynomial identity (residual 0)'
        return self._lia(res, 'eq', timeout_s)

    def check_le(self, f, bound, timeout_s=300):
        lo, hi = self.interval(f)
        if hi <= bound:
            return 'PROVED', 'interval'
        return self._lia(f_add(f, f_const(-bound)), 'le', timeout_s)

    def _lia(self, res, kind, timeout_s):
        """z3 linear integer arithmetic over the atoms + range facts"""
        iv = {}

        def ivar(m):
            if m not in iv:
                iv[m] = z3.Int('m_' + '_'.join(map(str, m)))
            return iv[m]

        def expr(f):
            e = 0
            for m, c in f.items():
                e = e + (c if m == () else c * ivar(m))
            return e
        s = z3.SolverFor('QF_LIA')
        s.set('timeout', timeout_s * 1000)
        # every monomial is bounded by its atoms' product bounds
        mons = set()
        for f, _, _ in self.facts:
            mons.update(m for m in f if m)
        mons.update(m for m in res if m)
        for m in mons:
            lo, hi = 1, 1
            for k in m:
                lo *= self.atoms[k].lo
                hi *= self.atoms[k].hi
            s.add(ivar(m) >= lo, ivar(m) <= hi)
        for f, lo, hi in self.facts:
            e = expr(f)
            s.add(e >= lo, e <= hi)
        r = expr(res)
        # vacuity: the facts alone must be satisfiable
        if s.check() != z3.sat:
            return 'VACUOUS', 'range facts unsatisfiable'
        s.add(r != 0 if kind == 'eq' else r > 0)
        ans = s.check()
        if ans == z3.unsat:
            return 'PROVED', 'LIA over %d range facts' % len(self.facts)
        if ans == z3.sat:
            return 'VIOLATED', 'LIA countermodel (may be spurious: monomials are independent atoms)'
        return 'OPEN', s.reason_unknown()


def selfcheck():
    """the add/sub identities the shadow relies on, proved against the
    executor's own bit-vector semantics for w = 64 (all inputs)"""
    import x86sym as X
    m = X.Machine.__new__(X.Machine)
    a, b = z3.BitVecs('a b', 64)
    cin = z3.Bool('cin')
    out = []
    for kind in ('add', 'sub'):
        if kind == 'add':
            r, c, _ = X.Machine._addc(m, None, a, b, cin, 64)
            lhs = z3.ZeroExt(2, r) + z3.If(c, z3.BitVecVal(1 << 64, 66), z3.BitVecVal(0, 66))
            rhs = z3.ZeroExt(2, a) + z3.ZeroExt(2, b) + z3.If(cin, z3.BitVecVal(1, 66), z3.BitVecVal(0, 66))
        else:
            r, c, _ = X.Machine._subb(m, None, a, b, cin, 64)
            lhs = z3.SignExt(2, z3.Concat(z3.BitVecVal(0, 1), r)) - \
                z3.If(c, z3.BitVecVal(1 << 64, 67), z3.BitVecVal(0, 67))
            lhs = z3.Extract(65, 0, lhs)
            rhs = z3.ZeroExt(2, a) - z3.ZeroExt(2, b) - z3.If(cin, z3.BitVecVal(1, 66), z3.BitVecVal(0, 66))
        s = z3.Solver()
        s.add(lhs != rhs)
        out.append((kind, s.check() == z3.unsat))
    return out
