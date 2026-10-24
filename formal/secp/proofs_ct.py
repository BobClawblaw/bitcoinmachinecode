"""proofs_ct.py -- constant time: the lifter runs in mode 'ct', where any branch
condition or memory address that is not a concrete value raises CTViolation.
The secret inputs are symbolic, every pointer and every public input is
concrete, so "every branch and address is concrete" means none depends on a
secret (it is stronger than syntactic independence: a branch whose condition
merely mentions a secret but simplifies to a constant would also pass, and
there are none).

Callees already proved constant time on their own (for ALL inputs) are
summarised by hooks: fe_mul / fe_sqr write fresh symbols (or the exact value,
when every input limb is concrete), clobber the caller-saved registers and
leave the flags undefined -- matching what the proofs of those functions
established (only r[] and their frame written, callee-saved preserved).
"""
import time
import z3
import x86sym as X
import common as Cm
import proofs_fe as F

GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
CNT = [0]


def ct_hooks(img, which=('fe_mul', 'fe_sqr')):
    def mk(kind):
        def h(m, st):
            ra = m.concrete_addr(st, st.regs['rdi'])
            srcs = [m.concrete_addr(st, st.regs['rsi'])]
            if kind in ('fe_mul', 'sc_mul'):
                srcs.append(m.concrete_addr(st, st.regs['rdx']))
            vals = [[st.mem.load(p + 8 * i, 8) for i in range(4)] for p in srcs]
            if all(X.isc(v) for vs in vals for v in vs):
                ints = [X.from_limbs(vs) for vs in vals]
                mod = Cm.P if kind.startswith('fe') else Cm.N
                r = ints[0] * (ints[1] if len(ints) > 1 else ints[0]) % mod
                outv = X.to_int_limbs(r)
            else:
                CNT[0] += 1
                outv = Cm.sym_limbs('ct%d_' % CNT[0])
            F.clobber(st)
            Cm.put(st, ra, outv)
        return h
    return {img.symbols[w]: mk(w) for w in which}


def run_ct(fn, args_setup, hooks=('fe_mul', 'fe_sqr'), allow=None, scan=None):
    img = Cm.image()
    m = X.Machine(img, mode='ct', product_mode='fresh', hooks=ct_hooks(img, hooks) if hooks else {})
    if allow:
        m.ct_allow = allow
    st = Cm.new_state(img)
    if scan is not None:
        st.mem.store(img.symbols['ct_scan_path'], scan, 1)
    args = args_setup(st)
    m.write_log = []
    fin = Cm.call(m, st, fn, args)
    return m, fin


def secret(st, addr, name, n=4):
    v = Cm.sym_limbs(name, n)
    Cm.put(st, addr, v)
    return v


def public_point(st, addr):
    Cm.put(st, addr, X.to_int_limbs(GX) + X.to_int_limbs(GY))


def ct_check(R, pid, fn, setup, what, hooks=('fe_mul', 'fe_sqr'), allow=None, scan=None):
    t0 = time.time()
    try:
        m, fin = run_ct(fn, setup, hooks, allow, scan)
        res = 'PROVED' if len(fin) == 1 and not Cm.abi_ok(fin[0]) else 'VIOLATED'
        steps = fin[0].steps
        note = '%d instructions executed' % steps
        if m.ct_forced:
            note += '; forced %d x the documented identity-check branch' % len(m.ct_forced)
    except X.CTViolation as e:
        res, note = 'VIOLATED', str(e)[:300]
    R.add(pid, fn + ('' if scan is None else (' [scan=%s]' % ('avx2' if scan == 1 else 'cmov'))),
          'no branch and no memory address depends on %s (%s)' % (what, note),
          'lifter ct mode', 'all secret values (symbolic); public inputs fixed', res, time.time() - t0)
    return res


def all_ct(R):
    B = Cm.BUF
    img = Cm.image()
    split = img.symbols['sc_split_lambda']
    # the four `jne .bad` of the recombination check: SC-SPLIT proves they are
    # never taken for k < n, the documented precondition of the GLV callers
    allow = {}
    a = split
    while img.insns[a][0] != 'ret':
        t = img.insns[a][0]
        if t.startswith('jne') and '<sc_split_lambda.bad>' in t:
            allow[a] = False
        a = img.next_addr[a]

    def two(fn_in=2):
        def s(st):
            secret(st, B[1], 'a_')
            if fn_in == 2:
                secret(st, B[2], 'b_')
            return [B[0], B[1], B[2]]
        return s
    for fn in ('fe_add', 'fe_sub', 'fe_mul', 'sc_add', 'sc_sub', 'sc_mul', 'sc_mul_512',
               'w_fe_addm', 'w_fe_subm'):
        ct_check(R, 'CT-' + fn, fn, two(2), 'a, b', hooks=None)
    for fn in ('fe_sqr', 'sc_sqr', 'sc_half_ct', 'w_fe_dbl'):
        ct_check(R, 'CT-' + fn, fn, two(1), 'a', hooks=None)
    ct_check(R, 'CT-fe_inv', 'fe_inv', two(1), 'a (fe_mul/fe_sqr inlined, not hooked)', hooks=None)
    ct_check(R, 'CT-fe_pow_sqrt', 'fe_pow_sqrt', two(1), 'a (inlined)', hooks=None)
    ct_check(R, 'CT-sc_inv', 'sc_inv', two(1), 'a (sc_mul hooked)', hooks=('sc_mul',))

    def split_setup(st):
        secret(st, B[2], 'k_')
        return [B[0], B[1], B[2]]
    ct_check(R, 'CT-sc_split_lambda', 'sc_split_lambda', split_setup, 'k, except the identity check',
             hooks=None, allow=allow)

    def pt2(st):
        secret(st, B[1], 'p_', 12)
        secret(st, B[2], 'q_', 12)
        return [B[0], B[1], B[2]]

    def pt1(st):
        secret(st, B[1], 'p_', 12)
        return [B[0], B[1]]

    def pt_ge(st):
        secret(st, B[1], 'p_', 12)
        secret(st, B[2], 'q_', 8)
        return [B[0], B[1], B[2]]
    ct_check(R, 'CT-pointh_add', 'pointh_add', pt2, 'either point')
    ct_check(R, 'CT-pointh_double', 'pointh_double', pt1, 'the point')
    ct_check(R, 'CT-pointj_add_ge_ct', 'pointj_add_ge_ct', pt_ge, 'either point')

    def gen(st):
        secret(st, B[1], 'k_')
        return [B[0], B[1]]

    def kp(st):
        public_point(st, B[1])
        secret(st, B[2], 'k_')
        return [B[0], B[1], B[2]]
    ct_check(R, 'CT-gen_ct', 'point_scalar_mul_gen_ct', gen, 'k (G table scanned with cmov)')
    ct_check(R, 'CT-mul_ct', 'point_scalar_mul_ct', kp, 'k')
    ct_check(R, 'CT-win_ct', 'point_scalar_mul_win_ct', kp, 'k')
    for scan in (1, 2):   # 1 = the AVX2 vpblendvb scan, 2 = the cmov scan
        ct_check(R, 'CT-glv_ct.%d' % scan, 'point_scalar_mul_glv_ct', kp, 'k (k < n)', allow=allow, scan=scan)
        ct_check(R, 'CT-glvj_ct.%d' % scan, 'point_scalar_mul_glvj_ct', kp, 'k (k < n)', allow=allow, scan=scan)
