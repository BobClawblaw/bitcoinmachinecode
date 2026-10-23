"""common.py -- shared harness code: load the image, set up a call with
symbolic or concrete buffers, run it, read the results, check the ABI."""
import os
import time
import z3
import x86sym as X

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.environ.get('B', os.path.join(HERE, 'build'))

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
C = 2**32 + 977
LAMBDA = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
BETA = 0x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE

BUF = [0x10000000 + 0x1000 * i for i in range(16)]     # argument buffers
STACK_TOP = 0x7ff0000000

_IMG = {}


def image(path=None):
    path = path or os.path.join(BUILD, 'img.elf')
    if path not in _IMG:
        _IMG[path] = X.Image(path)
    return _IMG[path]


def sym_limbs(prefix, n=4):
    return [z3.BitVec('%s%d' % (prefix, i), 64) for i in range(n)]


def new_state(img):
    st = X.State(img)
    st.mem.store(X.FS_BASE + 0x28, X.CANARY, 8)
    # callee-saved registers get recognisable symbolic values, so the ABI check
    # can confirm they come back unchanged; scratch registers are undefined.
    for r in X.CALLEE_SAVED:
        st.regs[r] = z3.BitVec('saved_' + r, 64)
    return st


def put(st, addr, limbs):
    for i, v in enumerate(limbs):
        st.mem.store(addr + 8 * i, v, 8)


def get(st, addr, n=4):
    return [st.mem.load(addr + 8 * i, 8) for i in range(n)]


def call(m, st, fn, args):
    """args: list of ints or z3 values for rdi, rsi, rdx, rcx, r8, r9"""
    for r, v in zip(['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'], args):
        st.regs[r] = v
    m.setup_call(st, m.img.symbols[fn] if isinstance(fn, str) else fn, STACK_TOP)
    finals = m.run(st)
    return finals


def abi_ok(st):
    """callee-saved registers restored, rsp popped past the return address"""
    probs = []
    for r in X.CALLEE_SAVED:
        v = st.regs[r]
        if X.isc(v) or not z3.eq(z3.simplify(v), z3.BitVec('saved_' + r, 64)):
            probs.append(r)
    if st.regs['rsp'] != STACK_TOP + 8:
        probs.append('rsp')
    return probs


def val(limbs, w=None):
    """little-endian 64-bit limbs -> one bit-vector of width w (zero-extended)"""
    v = X.limbs_val(limbs)
    if w and w > v.size():
        v = z3.ZeroExt(w - v.size(), v)
    return v


def K(x, w):
    return z3.BitVecVal(x, w)


class Result:
    def __init__(self):
        self.rows = []

    def add(self, pid, fn, claim, method, bound, result, secs, mutation=''):
        self.rows.append(dict(id=pid, fn=fn, claim=claim, method=method, bound=bound,
                              result=result, secs=secs, mutation=mutation))
        print('%-10s %-8s %7.1fs  %s :: %s' % (pid, result, secs, fn, claim), flush=True)


def prove(constraints, goal, timeout_s=600, name=''):
    """unbounded validity check of goal under constraints; returns
    ('PROVED', secs) or ('VIOLATED', model) or ('OPEN', reason).
    Also checks the hypotheses are satisfiable (vacuity)."""
    t0 = time.time()
    s = z3.SolverFor('QF_BV')
    s.set('timeout', timeout_s * 1000)
    s.add(*constraints)
    r0 = s.check()
    if r0 == z3.unsat:
        return 'VACUOUS', time.time() - t0, None
    s.add(z3.Not(goal))
    r = s.check()
    dt = time.time() - t0
    if r == z3.unsat:
        return 'PROVED', dt, None
    if r == z3.sat:
        return 'VIOLATED', dt, s.model()
    return 'OPEN', dt, s.reason_unknown()
