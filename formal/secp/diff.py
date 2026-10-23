"""diff.py -- differential tests backing every proof.

(1) the REAL objects (build/drv, linked from the worktree's asm/ objects) vs
    Python big-integer arithmetic, on edge values and random inputs;
(2) the lifter (x86sym, concrete mode) vs the real objects on the same inputs,
    so a semantic error in the lifter cannot hide behind a proof;
(3) the lifter's z3 path (FORCE_Z3: concrete inputs as z3 constants) vs the
    real objects on a few inputs per function.
Exits non-zero on any mismatch.  Seeded, so the run is reproducible.
"""
import os
import random
import subprocess
import sys
import z3
import common as Cm
import x86sym as X

P, N = Cm.P, Cm.N
M = 2**256
random.seed(int(os.environ.get('SEED', '20261023')))
NRAND = int(os.environ.get('NRAND', '300'))

EDGE = sorted(set([0, 1, 2, 3, P - 1, P, P + 1, P - 2, N - 1, N, N + 1, N - 2, M - 1, M - 2, 2**255, 2**255 - 1,
                   Cm.C, Cm.C - 1, M - Cm.C, (N - 1) // 2, (N + 1) // 2, (P - 1) // 2, (P + 1) // 2, 2**128,
                   2**128 - 1, 2**64 - 1, 2**64]
                  + [((2**64 - 1) << (64 * k)) for k in range(4)]
                  + [M - 1 - ((2**64 - 1) << (64 * k)) for k in range(4)]
                  + [(2**64 - 1) | ((2**64 - 1) << 128), ((2**64 - 1) << 64) | ((2**64 - 1) << 192)]))


def rnd():
    k = random.random()
    if k < 0.2:
        return random.getrandbits(256)
    if k < 0.4:
        return random.randrange(P)
    if k < 0.6:
        return random.randrange(N)
    if k < 0.8:     # limbs of extreme values
        return X.from_limbs([random.choice([0, 1, 2**64 - 1, 2**63, random.getrandbits(64)]) for _ in range(4)])
    return random.choice(EDGE) ^ random.getrandbits(random.randrange(1, 40))


def h(x):
    return '%064x' % x


class Drv:
    def __init__(self):
        self.p = subprocess.Popen([os.path.join(Cm.BUILD, 'drv')], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  text=True, bufsize=1)

    def batch(self, lines):
        out = []
        chunk = 300           # stay under the 64 KiB pipe buffers (no deadlock)
        for i in range(0, len(lines), chunk):
            q = lines[i:i + chunk]
            self.p.stdin.write('\n'.join(q) + '\n')
            self.p.stdin.flush()
            for _ in q:
                out.append(self.p.stdout.readline().strip())
        return out


def inv(a, m):
    return pow(a, m - 2, m)


def qr_sqrt(a):
    r = pow(a, (P + 1) // 4, P)
    return (r, 1) if r * r % P == a % P else (None, 0)


# name -> (arity, domain predicate, spec(args) -> expected output string)
def hx(*xs):
    return ' '.join(h(x) for x in xs)


SPECS = {
    'fe_add': (2, lambda a, b: a < P and b < P, lambda a, b: hx((a + b) % P)),
    'fe_sub': (2, lambda a, b: a < P and b < P, lambda a, b: hx((a - b) % P)),
    'w_fe_addm': (2, lambda a, b: a < P and b < P, lambda a, b: hx((a + b) % P)),
    'w_fe_subm': (2, lambda a, b: a < P and b < P, lambda a, b: hx((a - b) % P)),
    'w_fe_dbl': (1, lambda a: a < P, lambda a: hx(2 * a % P)),
    'fe_mul': (2, lambda a, b: True, lambda a, b: hx(a * b % P)),
    'fe_sqr': (1, lambda a: True, lambda a: hx(a * a % P)),
    'fe_inv': (1, lambda a: True, lambda a: hx(pow(a, P - 2, P))),
    'fe_pow_sqrt': (1, lambda a: True, lambda a: hx(pow(a, (P + 1) // 4, P))),
    'fe_inv_var': (1, lambda a: a < P, lambda a: hx(pow(a, P - 2, P))),
    'sc_add': (2, lambda a, b: a < N and b < N, lambda a, b: hx((a + b) % N)),
    'sc_sub': (2, lambda a, b: a < N and b < N, lambda a, b: hx((a - b) % N)),
    'sc_mul': (2, lambda a, b: True, lambda a, b: hx(a * b % N)),
    'sc_sqr': (1, lambda a: True, lambda a: hx(a * a % N)),
    'sc_inv': (1, lambda a: True, lambda a: hx(pow(a, N - 2, N))),
    'sc_inv_var': (1, lambda a: a < N, lambda a: hx(pow(a, N - 2, N))),
    'sc_half_ct': (1, lambda a: a < N, lambda a: hx(a * ((N + 1) // 2) % N)),
    'sc_mul_512': (2, lambda a, b: True, lambda a, b: '%0128x' % (a * b)),
    'reduce_n': (1, lambda a: True, lambda a: hx(a % N)),
    'scalar_small_nonzero': (1, lambda a: True, lambda a: str(int(0 < a < N))),
    'ecdsa_in_range': (1, lambda a: True, lambda a: str(int(0 < a < N))),
    'fe_is_zero': (1, lambda a: True, lambda a: str(int(a == 0))),
    'fe_equal': (2, lambda a, b: True, lambda a, b: str(int(a == b))),
}


def split_ok(k, out):
    r1s, r2s, ok = out.split()
    r1, r2, ok = int(r1s, 16), int(r2s, 16), int(ok)
    if k >= N:
        return ok == 0
    s1 = r1 - N if r1 >> 255 else r1
    s2 = r2 - N if r2 >> 255 else r2
    return ok == 1 and r1 < N and r2 < N and (s1 + Cm.LAMBDA * s2 - k) % N == 0 and abs(s1) < 2**128 and abs(s2) < 2**128


def inputs(arity, nrand):
    if arity == 1:
        xs = [(e,) for e in EDGE] + [(rnd(),) for _ in range(nrand)]
    else:
        xs = [(a, b) for a in EDGE for b in EDGE] + [(rnd(), rnd()) for _ in range(nrand)]
        xs += [(a, rnd()) for a in EDGE] + [(rnd(), a) for a in EDGE]
    return xs


def main():
    d = Drv()
    fails = 0
    total = 0
    real = {}
    for name, (ar, dom, spec) in SPECS.items():
        nr = NRAND if name not in ('fe_inv', 'fe_pow_sqrt', 'sc_inv') else NRAND // 3
        xs = inputs(ar, nr)
        if ar == 2 and name in ('fe_inv',):
            xs = xs[:400]
        lines = ['%s %s' % (name, ' '.join(h(x) for x in args)) for args in xs]
        outs = d.batch(lines)
        bad = 0
        nd = 0
        for args, o in zip(xs, outs):
            if not dom(*args):
                continue
            nd += 1
            if o != spec(*args):
                bad += 1
                if bad <= 3:
                    print('  MISMATCH %s%s: got %s want %s' % (name, tuple(hex(a) for a in args), o, spec(*args)))
        real[name] = (xs, outs)
        total += nd
        fails += bad
        print('DIFF %-22s %6d in-domain vectors  %s' % (name, nd, 'OK' if not bad else 'FAIL %d' % bad))
    # functions with structured outputs
    ks = [e for e in EDGE] + [rnd() for _ in range(NRAND)] + [random.randrange(N) for _ in range(NRAND)]
    outs = d.batch(['sc_split_lambda %s' % h(k) for k in ks])
    bad = sum(1 for k, o in zip(ks, outs) if not split_ok(k, o))
    print('DIFF %-22s %6d vectors  %s' % ('sc_split_lambda', len(ks), 'OK' if not bad else 'FAIL %d' % bad))
    fails += bad
    real['sc_split_lambda'] = ([(k,) for k in ks], outs)
    xs = [(a, f) for a in EDGE + [rnd() for _ in range(NRAND)] for f in (0, 1, 2, 3, -1) if 0 < a < N]
    outs = d.batch(['cneg_n %s %d' % (h(a), f) for a, f in xs])
    bad = sum(1 for (a, f), o in zip(xs, outs) if o != h(N - a if f & 1 else a))
    print('DIFF %-22s %6d vectors  %s' % ('cneg_n', len(xs), 'OK' if not bad else 'FAIL %d' % bad))
    fails += bad
    xs = [a % P for a in EDGE] + [random.randrange(P) for _ in range(NRAND)] + [pow(random.randrange(P), 2, P)
                                                                                 for _ in range(NRAND)]
    outs = d.batch(['fe_sqrt %s' % h(a) for a in xs])
    bad = 0
    for a, o in zip(xs, outs):
        r, ok = o.split()
        want_r, want_ok = qr_sqrt(a)
        if int(ok) != want_ok or (want_ok and int(r, 16) != want_r) or (not want_ok and int(r, 16) != 0):
            bad += 1
    print('DIFF %-22s %6d vectors  %s' % ('fe_sqrt', len(xs), 'OK' if not bad else 'FAIL %d' % bad))
    fails += bad
    groups = [[random.randrange(1, N) for _ in range(random.randrange(1, 9))] for _ in range(100)] + [[1], [N - 1, 2]]
    outs = d.batch(['sc_inv_batch ' + ' '.join(h(x) for x in g) for g in groups])
    bad = sum(1 for g, o in zip(groups, outs) if o.split() != [h(inv(x, N)) for x in g])
    print('DIFF %-22s %6d batches  %s' % ('sc_inv_batch', len(groups), 'OK' if not bad else 'FAIL %d' % bad))
    fails += bad
    # (2)/(3) the lifter against the real code
    img = Cm.image()
    lf = 0
    nlift = 0
    for name, (xs, outs) in real.items():
        if name in ('fe_inv_var', 'sc_inv_var'):
            continue
        heavy = name in ('fe_inv', 'fe_pow_sqrt', 'sc_inv')
        sel = list(range(len(xs)))
        random.shuffle(sel)
        sel = sel[:8 if heavy else 120]
        for idx in sel:
            got = lift_run(img, name, xs[idx])
            nlift += 1
            if got != outs[idx]:
                lf += 1
                if lf <= 5:
                    print('  LIFTER MISMATCH %s%s: lifter %s real %s' % (name, xs[idx], got, outs[idx]))
        # the z3 path on two vectors
        if not heavy:
            for idx in sel[:2]:
                X.FORCE_Z3[0] = True
                try:
                    got = lift_run(img, name, xs[idx])
                finally:
                    X.FORCE_Z3[0] = False
                nlift += 1
                if got != outs[idx]:
                    lf += 1
                    print('  LIFTER(z3) MISMATCH %s%s: lifter %s real %s' % (name, xs[idx], got, outs[idx]))
    print('LIFT %d lifter runs vs the real objects: %s' % (nlift, 'OK' if not lf else 'FAIL %d' % lf))
    fails += lf
    print('DIFF-TOTAL failures=%d' % fails)
    return 1 if fails else 0


def cval(v):
    if X.isc(v):
        return v
    s = z3.simplify(v)
    assert z3.is_bv_value(s), 'lifter result not concrete'
    return s.as_long()


def lift_run(img, name, args):
    m = X.Machine(img)
    st = Cm.new_state(img)
    B = Cm.BUF
    if name == 'scalar_small_nonzero':
        (k,) = args
        for i in range(32):
            st.mem.store(B[1] + i, (k >> (8 * (31 - i))) & 0xff, 1)
        fin = Cm.call(m, st, name, [B[1]])
        return str(cval(fin[0].regs['rax']) & 0xffffffff)
    if name == 'ecdsa_in_range':
        Cm.put(st, B[1], X.to_int_limbs(args[0]))
        fin = Cm.call(m, st, img.symbols[name], [0, B[1]])
        return str(cval(fin[0].regs['rax']) & 0xffffffff)
    if name == 'sc_split_lambda':
        Cm.put(st, B[2], X.to_int_limbs(args[0]))
        fin = Cm.call(m, st, name, [B[0], B[1], B[2]])
        f = fin[0]
        r1 = X.from_limbs([cval(v) for v in Cm.get(f, B[0])])
        r2 = X.from_limbs([cval(v) for v in Cm.get(f, B[1])])
        return '%s %s %d' % (h(r1), h(r2), cval(f.regs['rax']) & 0xffffffff)
    for i, a in enumerate(args):
        Cm.put(st, B[1 + i], X.to_int_limbs(a))
    if name in ('fe_is_zero', 'fe_equal'):
        fin = Cm.call(m, st, name, [B[1], B[2]])
        return str(cval(fin[0].regs['rax']) & 0xffffffff)
    fn = img.symbols[name]
    fin = Cm.call(m, st, fn, [B[0], B[1], B[2]])
    n = 8 if name == 'sc_mul_512' else 4
    out = X.from_limbs([cval(v) for v in Cm.get(fin[0], B[0], n)])
    return '%0128x' % out if n == 8 else h(out)


if __name__ == '__main__':
    sys.exit(main())
