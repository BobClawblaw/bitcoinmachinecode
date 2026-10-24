"""run_all.py -- every secp proof, one after the other in this one process.
   run_all.py [--only ID[,ID...]]   (an ID selects every row whose id starts with it)
Exits 0 only if every selected row is PROVED; writes build/results.tsv."""
import os
import sys
import time
import z3
import common as Cm
import linform as LF
import proofs_fe as F
import proofs_sc as S
import proofs_misc as M
import proofs_ct as T

GROUPS = [
    ('LF-SELF', lambda R: [R.add('LF-SELF.%s' % k, 'x86sym _addc/_subb', 'the integer identity the algebraic '
                                 'shadow assumes for %s holds for the executor\'s 64-bit semantics' % k, 'z3 QF_BV',
                                 'unbounded', 'PROVED' if ok else 'VIOLATED', 0.0) for k, ok in LF.selfcheck()]),
    ('FE-MUL-P', lambda R: F.product_part(R, 'fe_mul', 'FE-MUL-P')),
    ('FE-SQR-P', lambda R: F.product_part(R, 'fe_sqr', 'FE-SQR-P')),
    ('FE-RED', lambda R: F.reduction(R, 'FE-RED')),
    ('FE-ADD', lambda R: F.add_like(R, 'FE-ADD', 'fe_add', 'add')),
    ('FE-ADD-AL', lambda R: F.add_like(R, 'FE-ADD-AL', 'fe_add', 'add', alias=0, check_pre=False)),
    ('FE-SUB', lambda R: F.add_like(R, 'FE-SUB', 'fe_sub', 'sub')),
    ('FE-ADDM', lambda R: F.add_like(R, 'FE-ADDM', 'w_fe_addm', 'add')),
    ('FE-DBL', lambda R: F.add_like(R, 'FE-DBL', 'w_fe_dbl', 'add', nin=1, check_pre=False)),
    ('FE-SUBM', lambda R: F.add_like(R, 'FE-SUBM', 'w_fe_subm', 'sub')),
    ('FE-HALF', lambda R: F.fe_half(R, 'FE-HALF')),
    ('FE-EQZ', lambda R: F.eq_zero_c(R, 'FE-EQZ')),
    ('FE-INV', lambda R: (F.chain(R, 'FE-INV', 'fe_inv', Cm.P - 2, 'p-2'),
                          F.chain(R, 'FE-INV-AL', 'fe_inv', Cm.P - 2, 'p-2', alias=True))),
    ('FE-SQRT', lambda R: (F.chain(R, 'FE-SQRT', 'fe_pow_sqrt', (Cm.P + 1) // 4, '(p+1)/4'),
                           F.fe_sqrt_c(R, 'FE-SQRT-C'), F.exps_math(R, 'FE-EXP'))),
    ('SC-ADD', lambda R: S.add_sub(R, 'SC-ADD', 'sc_add', 'add')),
    ('SC-SUB', lambda R: S.add_sub(R, 'SC-SUB', 'sc_sub', 'sub')),
    ('SC-MUL', lambda R: S.sc_mul_proofs(R, 'SC-MUL')),
    ('SC-M512', lambda R: S.sc_mul_512(R, 'SC-M512')),
    ('SC-HALF', lambda R: S.sc_half(R, 'SC-HALF')),
    ('SC-INV', lambda R: S.sc_inv(R, 'SC-INV')),
    ('SC-SPLIT', lambda R: (S.split_glue(R, 'SC-SPLIT'), S.split_math(R, 'SC-SPLIT-M'))),
    ('SC-RANGE', lambda R: M.small_nonzero(R, 'SC-RANGE')),
    ('SC-INRANGE', lambda R: M.in_range(R, 'SC-INRANGE')),
    ('B340', lambda R: (M.reduce_n(R, 'B340-RED'), M.cneg_n(R, 'B340-CNEG'))),
    ('CT', lambda R: T.all_ct(R)),
]


def main():
    only = None
    if '--only' in sys.argv:
        only = sys.argv[sys.argv.index('--only') + 1].split(',')
    R = Cm.Result()
    t0 = time.time()
    for gid, fn in GROUPS:
        if only and not any(gid.startswith(o) or o.startswith(gid) for o in only):
            continue
        try:
            fn(R)
        except Exception as e:          # a crash in a proof is a failed proof
            R.add(gid, '-', 'harness raised %s: %s' % (type(e).__name__, str(e)[:200]), '-', '-', 'ERROR', 0.0)
    rows = [r for r in R.rows if not only or any(r['id'].startswith(o) for o in only)]
    bad = [r for r in rows if r['result'] != 'PROVED']
    os.makedirs(Cm.BUILD, exist_ok=True)
    with open(os.path.join(Cm.BUILD, 'results.tsv'), 'w') as f:
        for r in R.rows:
            f.write('\t'.join(str(r[k]) for k in ('id', 'fn', 'result', 'secs', 'method', 'bound', 'claim')) + '\n')
    print('PROOFS: %d rows, %d not PROVED, %.0f s' % (len(rows), len(bad), time.time() - t0))
    for r in bad:
        print('  NOT PROVED: %s %s %s' % (r['id'], r['result'], r['claim'][:160]))
    return 1 if bad or not rows else 0


if __name__ == '__main__':
    sys.exit(main())
