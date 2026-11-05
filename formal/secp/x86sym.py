"""x86sym -- a small bit-precise symbolic executor for x86-64 machine code.

It runs the REAL assembled object: the code is linked into an image at a fixed
address, decoded by GNU objdump (Intel syntax), and each instruction is given
the semantics written in this file, over values that are either Python ints
(concrete) or z3 bit-vectors (symbolic).  Every instruction semantic and every
flag rule is written once, against the primitive layer below, so the concrete
path (used to co-simulate against the real CPU) and the symbolic path (used by
the proofs) share the same formulas; `force_z3=True` sends concrete inputs
through the z3 path too, so the z3 primitives are co-simulated as well.

Trusted here (the lifting semantics): the instruction table in
`Machine._exec`, the flag rules in `_flags_*`, the 32-bit-write zero-extension
rule, and objdump's decoder.  Undefined flags (e.g. after MUL, IMUL, BT, or a
multi-bit shift's OF) are tracked as UNDEF and a read of one is an error.

Memory is byte-addressed with concrete addresses only.  A symbolic address or a
symbolic branch condition is either explored (mode 'fork': both sides, with a
path condition) or reported as a constant-time violation (mode 'ct').
"""
import re
import struct
import subprocess
import z3

M64 = (1 << 64) - 1
FS_BASE = 0x7e00000000          # thread block; [fs:0x28] holds the stack canary
CANARY = 0x5ca1ab1e0ddba11c
UNDEF = object()


class SymError(Exception):
    pass


class CTViolation(SymError):
    pass


# --------------------------------------------------------------------------
# primitive layer: values are int (concrete, already reduced mod 2^w) or z3
# --------------------------------------------------------------------------
FORCE_Z3 = [False]
UNINIT_READS = [0]
STACK_LO, STACK_HI = 0x7fe0000000, 0x7ff0000000
UNDEF_N = [0]


def isc(v):
    return isinstance(v, int) and not isinstance(v, bool)


def mask(w):
    return (1 << w) - 1


def bv(v, w):
    """z3 view of a value of width w"""
    if isc(v):
        return z3.BitVecVal(v, w)
    assert v.size() == w, (v.size(), w)
    return v


def lift(v, w):
    """concrete values become z3 constants when FORCE_Z3 is on"""
    if FORCE_Z3[0] and isc(v):
        return z3.BitVecVal(v, w)
    return v


def p_add(a, b, w):
    if isc(a) and isc(b):
        return (a + b) & mask(w)
    return bv(a, w) + bv(b, w)


def p_sub(a, b, w):
    if isc(a) and isc(b):
        return (a - b) & mask(w)
    return bv(a, w) - bv(b, w)


def p_and(a, b, w):
    if isc(a) and isc(b):
        return a & b
    return bv(a, w) & bv(b, w)


def p_or(a, b, w):
    if isc(a) and isc(b):
        return a | b
    return bv(a, w) | bv(b, w)


def p_xor(a, b, w):
    if isc(a) and isc(b):
        return a ^ b
    if not isc(a) and not isc(b) and z3.eq(a, b):
        return 0                      # x ^ x == 0 exactly (zero idiom)
    return bv(a, w) ^ bv(b, w)


def p_not(a, w):
    if isc(a):
        return (~a) & mask(w)
    return ~a


def p_mul(a, b, w):
    if isc(a) and isc(b):
        return (a * b) & mask(w)
    return bv(a, w) * bv(b, w)


def p_shl(a, n, w):
    assert isc(n)
    if isc(a):
        return (a << n) & mask(w)
    return a << n if n < w else z3.BitVecVal(0, w)


def p_lshr(a, n, w):
    assert isc(n)
    if isc(a):
        return a >> n
    return z3.LShR(a, n) if n < w else z3.BitVecVal(0, w)


def p_ashr(a, n, w):
    assert isc(n)
    if isc(a):
        s = a - (1 << w) if a >> (w - 1) else a
        return (s >> n) & mask(w)
    return a >> n


def p_extract(a, hi, lo):
    if isc(a):
        return (a >> lo) & mask(hi - lo + 1)
    return z3.simplify(z3.Extract(hi, lo, a)) if z3.is_const(a) else z3.Extract(hi, lo, a)


def p_zext(a, w_from, w_to):
    if w_to == w_from:
        return a
    if isc(a):
        return a
    return z3.ZeroExt(w_to - w_from, a)


def p_sext(a, w_from, w_to):
    if w_to == w_from:
        return a
    if isc(a):
        if a >> (w_from - 1):
            return (a | (mask(w_to) ^ mask(w_from))) & mask(w_to)
        return a
    return z3.SignExt(w_to - w_from, a)


def p_concat(hi, lo, whi, wlo):
    if isc(hi) and isc(lo):
        return (hi << wlo) | lo
    return z3.Concat(bv(hi, whi), bv(lo, wlo))


def p_eq(a, b, w):
    if isc(a) and isc(b):
        return a == b
    return bv(a, w) == bv(b, w)


def p_ult(a, b, w):
    if isc(a) and isc(b):
        return a < b
    return z3.ULT(bv(a, w), bv(b, w))


def b_not(c):
    if isinstance(c, bool):
        return not c
    return z3.Not(c)


def b_and(a, b):
    if isinstance(a, bool) and isinstance(b, bool):
        return a and b
    if a is False or b is False:
        return False
    if a is True:
        return b
    if b is True:
        return a
    return z3.And(a, b)


def b_or(a, b):
    if isinstance(a, bool) and isinstance(b, bool):
        return a or b
    if a is True or b is True:
        return True
    if a is False:
        return b
    if b is False:
        return a
    return z3.Or(a, b)


def b_xor(a, b):
    if isinstance(a, bool) and isinstance(b, bool):
        return a != b
    return z3.Xor(tobool(a), tobool(b))


def tobool(c):
    if isinstance(c, bool):
        return z3.BoolVal(c)
    return c


def p_ite(c, a, b, w):
    if isinstance(c, bool):
        return a if c else b
    if isc(a) and isc(b) and a == b:
        return a
    return z3.If(c, bv(a, w), bv(b, w))


def b2v(c, w):
    """bool -> 0/1 of width w"""
    if isinstance(c, bool):
        return 1 if c else 0
    return z3.If(c, z3.BitVecVal(1, w), z3.BitVecVal(0, w))


def msb(a, w):
    if isc(a):
        return bool(a >> (w - 1))
    return z3.Extract(w - 1, w - 1, a) == 1


def is_concrete_bool(c):
    return isinstance(c, bool)


# --------------------------------------------------------------------------
# ELF image + objdump decoding
# --------------------------------------------------------------------------
class Image:
    def __init__(self, path):
        self.path = path
        data = open(path, 'rb').read()
        self.sections = []           # (addr, bytes) for SHF_ALLOC sections
        shoff = struct.unpack_from('<Q', data, 0x28)[0]
        shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
        shdrs = []
        for i in range(shnum):
            name, typ, flags, addr, off, size = struct.unpack_from('<IIQQQQ', data, shoff + i * shentsize)
            shdrs.append((name, typ, flags, addr, off, size))
        strtab = shdrs[shstrndx]
        for name, typ, flags, addr, off, size in shdrs:
            if flags & 2 and addr:                       # SHF_ALLOC
                if typ == 8:                             # NOBITS
                    self.sections.append((addr, bytes(size)))
                else:
                    self.sections.append((addr, data[off:off + size]))
        self.symbols = {}
        out = subprocess.run(['nm', path], capture_output=True, text=True, check=True).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3:
                self.symbols[parts[2]] = int(parts[0], 16)
        self.addr2sym = {}
        for k, v in self.symbols.items():
            self.addr2sym.setdefault(v, k)
        self.insns = {}
        self.next_addr = {}
        self._decode()

    def static_byte(self, addr):
        for a, d in self.sections:
            if a <= addr < a + len(d):
                return d[addr - a]
        return None

    def _decode(self):
        out = subprocess.run(['objdump', '-d', '-M', 'intel', '--no-show-raw-insn', '-w', self.path],
                             capture_output=True, text=True, check=True).stdout
        rx = re.compile(r'^\s*([0-9a-f]+):\t(.*)$')
        prev = None
        for line in out.splitlines():
            m = rx.match(line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            text = m.group(2)
            comment = None
            if '#' in text:
                text, comment = text.split('#', 1)
            text = text.strip()
            if not text:
                continue
            self.insns[addr] = (text, comment)
            if prev is not None:
                self.next_addr[prev] = addr
            prev = addr


REG64 = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp'] + ['r%d' % i for i in range(8, 16)]
SUBREG = {}
for r, d, wd, b in [('rax', 'eax', 'ax', 'al'), ('rbx', 'ebx', 'bx', 'bl'), ('rcx', 'ecx', 'cx', 'cl'),
                    ('rdx', 'edx', 'dx', 'dl'), ('rsi', 'esi', 'si', 'sil'), ('rdi', 'edi', 'di', 'dil'),
                    ('rbp', 'ebp', 'bp', 'bpl'), ('rsp', 'esp', 'sp', 'spl')]:
    SUBREG[r] = (r, 64)
    SUBREG[d] = (r, 32)
    SUBREG[wd] = (r, 16)
    SUBREG[b] = (r, 8)
for i in range(8, 16):
    SUBREG['r%d' % i] = ('r%d' % i, 64)
    SUBREG['r%dd' % i] = ('r%d' % i, 32)
    SUBREG['r%dw' % i] = ('r%d' % i, 16)
    SUBREG['r%db' % i] = ('r%d' % i, 8)
for i in range(16):
    SUBREG['ymm%d' % i] = ('ymm%d' % i, 256)
    SUBREG['xmm%d' % i] = ('ymm%d' % i, 128)

PTRSZ = {'BYTE': 8, 'WORD': 16, 'DWORD': 32, 'QWORD': 64, 'XMMWORD': 128, 'YMMWORD': 256}

CC = {
    'o': lambda f: f('OF'), 'no': lambda f: b_not(f('OF')),
    'b': lambda f: f('CF'), 'c': lambda f: f('CF'), 'nae': lambda f: f('CF'),
    'ae': lambda f: b_not(f('CF')), 'nb': lambda f: b_not(f('CF')), 'nc': lambda f: b_not(f('CF')),
    'e': lambda f: f('ZF'), 'z': lambda f: f('ZF'),
    'ne': lambda f: b_not(f('ZF')), 'nz': lambda f: b_not(f('ZF')),
    'be': lambda f: b_or(f('CF'), f('ZF')), 'na': lambda f: b_or(f('CF'), f('ZF')),
    'a': lambda f: b_and(b_not(f('CF')), b_not(f('ZF'))), 'nbe': lambda f: b_and(b_not(f('CF')), b_not(f('ZF'))),
    's': lambda f: f('SF'), 'ns': lambda f: b_not(f('SF')),
    'l': lambda f: b_xor(f('SF'), f('OF')), 'nge': lambda f: b_xor(f('SF'), f('OF')),
    'ge': lambda f: b_not(b_xor(f('SF'), f('OF'))), 'nl': lambda f: b_not(b_xor(f('SF'), f('OF'))),
    'le': lambda f: b_or(f('ZF'), b_xor(f('SF'), f('OF'))),
    'g': lambda f: b_and(b_not(f('ZF')), b_not(b_xor(f('SF'), f('OF')))),
}


class Mem:
    def __init__(self, img):
        self.img = img
        self.b = {}          # addr -> int or BV8

    def copy(self):
        m = Mem(self.img)
        m.b = dict(self.b)
        return m

    def rbyte(self, a):
        v = self.b.get(a)
        if v is not None:
            return v
        s = self.img.static_byte(a)
        if s is None:
            if STACK_LO <= a < STACK_HI:
                # never-written stack: an arbitrary value (a fresh symbol), so
                # any result that depended on it would fail its proof
                UNINIT_READS[0] += 1
                v = z3.BitVec('uninit_%x' % a, 8)
                self.b[a] = v
                return v
            raise SymError('read of uninitialised memory at %#x' % a)
        return s

    def load(self, a, n):
        bs = [self.rbyte(a + i) for i in range(n)]
        if all(isc(x) for x in bs):
            v = 0
            for i, x in enumerate(bs):
                v |= x << (8 * i)
            return lift(v, 8 * n)
        # fast path: the n bytes are consecutive extracts of one value
        x0 = bs[0]
        if not isc(x0) and z3.is_app_of(x0, z3.Z3_OP_EXTRACT):
            base = x0.arg(0)
            lo0 = x0.params()[1]
            ok = base.size() >= lo0 + 8 * n
            for i, x in enumerate(bs):
                if not ok:
                    break
                if isc(x) or not z3.is_app_of(x, z3.Z3_OP_EXTRACT) or not z3.eq(x.arg(0), base) \
                        or x.params()[1] != lo0 + 8 * i:
                    ok = False
            if ok:
                if lo0 == 0 and base.size() == 8 * n:
                    return base
                return z3.Extract(lo0 + 8 * n - 1, lo0, base)
        v = bv(bs[n - 1], 8)
        for i in range(n - 2, -1, -1):
            v = z3.Concat(v, bv(bs[i], 8))
        return v

    def store(self, a, v, n):
        for i in range(n):
            self.b[a + i] = p_extract(v, 8 * i + 7, 8 * i) if not isc(v) else (v >> (8 * i)) & 0xff


def exact_product(x, y):
    """the canonical 128-bit product term: a constant operand always goes second,
    so a spec that builds the same term shares it with the code"""
    xc = isc(x) or z3.is_bv_value(z3.simplify(bv(x, 64)))
    yc = isc(y) or z3.is_bv_value(z3.simplify(bv(y, 64)))
    if xc and not yc:
        x, y = y, x
    if isc(y) or z3.is_bv_value(z3.simplify(bv(y, 64))):
        yv = y if isc(y) else z3.simplify(bv(y, 64)).as_long()
        return z3.ZeroExt(64, bv(x, 64)) * z3.BitVecVal(yv, 128)
    return z3.ZeroExt(64, bv(x, 64)) * z3.ZeroExt(64, bv(y, 64))


class State:
    def __init__(self, img):
        self.img = img
        self.regs = {r: None for r in REG64}
        self.ymm = {('ymm%d' % i): None for i in range(16)}
        self.flags = {'CF': UNDEF, 'OF': UNDEF, 'ZF': UNDEF, 'SF': UNDEF, 'PF': UNDEF}
        self.mem = Mem(img)
        self.rip = None
        self.pc = []          # path condition (z3 bools)
        self.steps = 0

    def copy(self):
        s = State.__new__(State)
        s.img = self.img
        s.regs = dict(self.regs)
        s.ymm = dict(self.ymm)
        s.flags = dict(self.flags)
        s.mem = self.mem.copy()
        s.rip = self.rip
        s.pc = list(self.pc)
        s.steps = self.steps
        return s


# --------------------------------------------------------------------------
# the machine
# --------------------------------------------------------------------------
class Machine:
    """mode: 'fork' explores symbolic branches; 'ct' raises CTViolation on any
    symbolic branch condition or memory address (the constant-time check)."""

    RET_MAGIC = 0xdead0000

    def __init__(self, img, mode='fork', product_mode='abstract', hooks=None, probes=None,
                 max_steps=50_000_000, ct_log=None, alg=None):
        self.img = img
        self.mode = mode
        self.product_mode = product_mode
        self.hooks = hooks or {}          # addr -> fn(machine, state) emulating a call
        self.probes = probes or {}        # addr -> fn(state) called BEFORE the instruction
        self.max_steps = max_steps
        self.products = {}                # key -> (hi, lo, x, y)
        self.side = []                    # side constraints (product facts)
        self.nprod = 0
        self.ct_log = ct_log
        self.trace_mnems = set()
        self.write_log = None             # list of (addr, n) when set
        self.alg = alg                    # linform.Alg: the algebraic shadow (optional)
        self.ct_allow = {}                # addr -> forced direction (see branch())
        self.ct_forced = []

    # ---------------- operands
    def reg_read(self, st, name):
        base, w = SUBREG[name]
        if w == 256 or w == 128:
            v = st.ymm[base]
            if v is None:
                raise SymError('read of undefined %s' % base)
            return v if w == 256 else p_extract(v, 127, 0)
        v = st.regs[base]
        if v is None:
            raise SymError('read of undefined register %s at %#x' % (base, st.rip))
        if w == 64:
            return v
        return p_extract(v, w - 1, 0)

    def reg_write(self, st, name, v):
        base, w = SUBREG[name]
        if w == 256:
            st.ymm[base] = v
            return
        if w == 128:            # VEX-encoded 128-bit writes zero the upper half
            st.ymm[base] = p_zext(v, 128, 256)
            return
        if w == 64:
            st.regs[base] = v
        elif w == 32:           # 32-bit writes zero-extend into the 64-bit register
            st.regs[base] = p_zext(v, 32, 64)
        else:                   # 8/16-bit writes merge
            old = st.regs[base]
            if old is None:              # the untouched upper bits are unknown: a fresh symbol
                UNDEF_N[0] += 1
                old = z3.BitVec('undef_%s_%d' % (base, UNDEF_N[0]), 64)
            hi = p_extract(old, 63, w)
            st.regs[base] = p_concat(hi, v, 64 - w, w)

    def xmm_write_legacy(self, st, name, v):
        base, w = SUBREG[name]
        assert w == 128
        old = st.ymm[base]
        hi = p_extract(old, 255, 128) if old is not None else 0
        st.ymm[base] = p_concat(hi, v, 128, 128)

    def addr_of(self, st, memtxt, comment):
        # memtxt like "[rsi+0x8]" or "[rip+0x123]" or "[r14+rcx*1+0x10]" or "ds:0x401000"
        mfs = re.match(r'^fs:(0x[0-9a-f]+)$', memtxt)
        if mfs:
            return FS_BASE + int(mfs.group(1), 16)
        m = re.match(r'^(?:([a-z]s):)?\[(.*)\]$', memtxt)
        if not m:
            m2 = re.match(r'^(?:ds:)?(0x[0-9a-f]+)$', memtxt)
            if m2:
                return int(m2.group(1), 16)
            raise SymError('bad memory operand %r' % memtxt)
        inner = m.group(2)
        if inner.startswith('rip'):
            # objdump prints the resolved target in the comment
            tgt = int(comment.strip().split()[0], 16)
            return tgt
        terms = re.findall(r'([+-]?)([^+-]+)', inner)
        a = 0
        for sign, t in terms:
            t = t.strip()
            if '*' in t:
                r, sc = t.split('*')
                v = p_mul(self.reg_read(st, r), int(sc), 64)
            elif t in SUBREG:
                v = self.reg_read(st, t)
            else:
                v = int(t, 16) & M64
            a = p_sub(a, v, 64) if sign == '-' else p_add(a, v, 64)
        return a

    def concrete_addr(self, st, a, what='address'):
        if isc(a):
            return a
        s = z3.simplify(a)
        if z3.is_bv_value(s):
            return s.as_long()
        if self.mode == 'ct':
            raise CTViolation('symbolic memory %s at %#x: %s' % (what, st.rip, s))
        raise SymError('symbolic memory %s at %#x (unsupported): %s' % (what, st.rip, s))

    def parse_op(self, txt):
        txt = txt.strip()
        m = re.match(r'^(BYTE|WORD|DWORD|QWORD|XMMWORD|YMMWORD) PTR (.*)$', txt)
        if m:
            return ('m', PTRSZ[m.group(1)], m.group(2))
        if txt in SUBREG:
            return ('r', SUBREG[txt][1], txt)
        if re.match(r'^-?0x[0-9a-f]+$', txt) or re.match(r'^-?\d+$', txt):
            return ('i', None, int(txt, 0))
        if txt.startswith('['):
            return ('m', None, txt)
        raise SymError('cannot parse operand %r' % txt)

    def rd(self, st, op, comment, w=None):
        kind, ow, x = op
        if kind == 'r':
            return self.reg_read(st, x)
        if kind == 'i':
            return lift(x & mask(w), w)
        ow = ow or w
        a = self.concrete_addr(st, self.addr_of(st, x, comment))
        if self.ct_log is not None:
            self.ct_log.append(('load', st.rip, a))
        return st.mem.load(a, ow // 8)

    def wr(self, st, op, comment, v, w=None):
        kind, ow, x = op
        if kind == 'r':
            self.reg_write(st, x, v)
            return
        if kind != 'm':
            raise SymError('write to immediate')
        ow = ow or w
        a = self.concrete_addr(st, self.addr_of(st, x, comment))
        if self.write_log is not None:
            self.write_log.append((a, ow // 8, st.rip))
        st.mem.store(a, v, ow // 8)

    # ---------------- flags
    def flag(self, st, name):
        v = st.flags[name]
        if v is UNDEF:
            raise SymError('read of undefined flag %s at %#x (%s)' % (name, st.rip, st.img.insns[st.rip][0]))
        return v

    def set_zs(self, st, r, w):
        st.flags['ZF'] = p_eq(r, 0, w)
        st.flags['SF'] = msb(r, w)
        st.flags['PF'] = UNDEF          # never consumed by the code under proof; reads would fail

    def _addc(self, st, a, b, cin, w, setflags='all'):
        """a + b + cin; returns (result, carry_out, overflow)"""
        ci = b2v(cin, w + 1)
        s = p_add(p_add(p_zext(a, w, w + 1), p_zext(b, w, w + 1), w + 1), ci, w + 1)
        r = p_extract(s, w - 1, 0)
        cout = p_eq(p_extract(s, w, w), 1, 1)
        sa, sb, sr = msb(a, w), msb(b, w), msb(r, w)
        ov = b_and(b_not(b_xor(sa, sb)), b_xor(sr, sa))     # same sign in, different sign out
        if getattr(self, 'alg', None) is not None and not (isc(r) and isc(a) and isc(b)):
            self.alg.on_add(a, b, cin, r, cout, w)
        return r, cout, ov

    def _subb(self, st, a, b, bin_, w):
        """a - b - bin; returns (result, borrow, overflow)"""
        bi = b2v(bin_, w + 1)
        d = p_sub(p_sub(p_zext(a, w, w + 1), p_zext(b, w, w + 1), w + 1), bi, w + 1)
        r = p_extract(d, w - 1, 0)
        bout = p_eq(p_extract(d, w, w), 1, 1)
        sa, sb, sr = msb(a, w), msb(b, w), msb(r, w)
        ov = b_and(b_xor(sa, sb), b_xor(sr, sa))             # different sign in, sign flips
        if getattr(self, 'alg', None) is not None and not (isc(r) and isc(a) and isc(b)):
            self.alg.on_sub(a, b, bin_, r, bout, w)
        return r, bout, ov

    # ---------------- products
    def product(self, x, y):
        """full 128-bit product of two 64-bit values, returns (hi, lo)"""
        if isc(x) and isc(y) and not FORCE_Z3[0]:
            p = x * y
            return p >> 64, p & M64
        if self.product_mode == 'fresh':          # CT runs: values are irrelevant, keep terms small
            self.nprod += 1
            return z3.BitVec('fh%d' % self.nprod, 64), z3.BitVec('fl%d' % self.nprod, 64)
        if isc(x) or isc(y) or z3.is_bv_value(z3.simplify(bv(x, 64))) or z3.is_bv_value(z3.simplify(bv(y, 64))) \
                or self.product_mode == 'exact':
            p = exact_product(x, y)
            hi, lo = z3.Extract(127, 64, p), z3.Extract(63, 0, p)
            if self.alg is not None:
                self.alg.on_product(x, y, hi, lo)
            return hi, lo
        key = self.prod_key(x, y)
        if key not in self.products:
            self.nprod += 1
            hi = z3.BitVec('ph%d' % self.nprod, 64)
            lo = z3.BitVec('pl%d' % self.nprod, 64)
            full = z3.Concat(hi, lo)
            # sound over-approximation of a 64x64 product: 0 <= x*y <= (2^64-1)^2
            self.side.append(z3.ULE(full, z3.BitVecVal(M64 * M64, 128)))
            self.products[key] = (hi, lo, x, y)
        hi, lo, _, _ = self.products[key]
        if self.alg is not None:
            self.alg.on_product(x, y, hi, lo)
        return hi, lo

    @staticmethod
    def prod_key(x, y):
        a, b = z3.simplify(bv(x, 64)).sexpr(), z3.simplify(bv(y, 64)).sexpr()
        return (a, b) if a <= b else (b, a)

    def prod128(self, x, y):
        """the 128-bit product term the executor used for x*y (for specs)"""
        key = self.prod_key(x, y)
        if key not in self.products:
            raise SymError('product %s * %s was never computed by the code' % key)
        hi, lo, _, _ = self.products[key]
        return z3.Concat(hi, lo)

    # ---------------- execution
    def setup_call(self, st, fn_addr, stack_top=0x7ff0000000):
        st.regs['rsp'] = stack_top
        st.mem.store(stack_top, self.RET_MAGIC, 8)
        st.rip = fn_addr

    def run(self, st, stop_at=None, skip_first=False):
        """run until return to RET_MAGIC (or until rip == stop_at); returns the
        list of final states (one per feasible path)"""
        work = [st]
        done = []
        first = skip_first
        while work:
            s = work.pop()
            while True:
                if s.rip == self.RET_MAGIC or (s.rip == stop_at and not first):
                    done.append(s)
                    break
                first = False
                s.steps += 1
                if s.steps > self.max_steps:
                    raise SymError('step budget exhausted')
                if s.rip in self.probes:
                    self.probes[s.rip](s)
                forks = self._exec(s)
                if forks:
                    work.extend(forks)
                    break
        return done

    def branch(self, st, cond, target, fallthrough):
        """returns None if concrete (state updated), else list of forked states"""
        if isinstance(cond, bool):
            st.rip = target if cond else fallthrough
            return None
        sc = z3.simplify(cond)
        if z3.is_true(sc):
            st.rip = target
            return None
        if z3.is_false(sc):
            st.rip = fallthrough
            return None
        if self.mode == 'ct':
            allow = getattr(self, 'ct_allow', {})
            if st.rip in allow:      # a documented data-dependent branch, forced to its proved direction
                self.ct_forced.append(st.rip)
                st.rip = target if allow[st.rip] else fallthrough
                return None
            raise CTViolation('symbolic branch at %#x: %s' % (st.rip, str(sc)[:200]))
        out = []
        for c, t in ((sc, target), (z3.Not(sc), fallthrough)):
            s2 = st.copy()
            s2.pc.append(c)
            sol = z3.Solver()
            sol.add(*s2.pc)
            sol.add(*self.side)
            if sol.check() != z3.unsat:
                s2.rip = t
                out.append(s2)
        return out

    def _exec(self, st):
        text, comment = self.img.insns.get(st.rip, (None, None))
        if text is None:
            raise SymError('no instruction at %#x' % st.rip)
        nxt = self.img.next_addr.get(st.rip)
        parts = text.split(None, 1)
        mn = parts[0]
        rest = parts[1] if len(parts) > 1 else ''
        if mn in ('rep', 'repz', 'repe') and rest.startswith('movs'):
            if rest.startswith('movsq') or 'QWORD PTR es:[rdi]' in rest:
                mn, rest = 'rep_movsq', ''
            else:
                raise SymError('rep %s not modelled' % rest)
        if mn == 'cs' or mn == 'ds':
            parts = rest.split(None, 1)
            mn = parts[0]
            rest = parts[1] if len(parts) > 1 else ''
        ops = self._split_ops(rest)
        self.trace_mnems.add(mn)
        F = lambda n: self.flag(st, n)
        R = lambda o, w=None: self.rd(st, o, comment, w)
        W = lambda o, v, w=None: self.wr(st, o, comment, v, w)

        def width(o, other=None):
            if o[1]:
                return o[1]
            if other is not None and other[1]:
                return other[1]
            raise SymError('operand width unknown: %s' % text)

        if mn in ('nop', 'endbr64', 'vzeroupper') or mn.startswith('nop'):
            st.rip = nxt
            return None
        if mn in ('mov', 'movabs'):
            d, s = ops
            w = width(d, s)
            W(d, R(s, w), w)
        elif mn in ('movzx', 'movsx', 'movsxd'):
            d, s = ops
            wd = width(d)
            ws = s[1] if s[1] else 32
            v = R(s, ws)
            W(d, p_zext(v, ws, wd) if mn == 'movzx' else p_sext(v, ws, wd), wd)
        elif mn == 'lea':
            d, s = ops
            a = self.addr_of(st, s[2], comment)
            w = width(d)
            W(d, a if w == 64 else p_extract(a, w - 1, 0), w)
        elif mn in ('add', 'adc', 'sub', 'sbb', 'cmp'):
            d, s = ops
            w = width(d, s)
            if mn in ('sub', 'sbb') and s == d and d[0] == 'r' and st.regs[SUBREG[d[2]][0]] is None:
                a = b = lift(0, w)        # x - x (- CF) does not depend on x: an undefined x is fine
            else:
                a = R(d, w)
                b = R(s, w)
            if s[0] == 'i':
                b = lift(s[2] & mask(w), w)   # objdump prints the sign-extended immediate
            if mn in ('add', 'adc'):
                r, c, o = self._addc(st, a, b, F('CF') if mn == 'adc' else False, w)
            else:
                r, c, o = self._subb(st, a, b, F('CF') if mn == 'sbb' else False, w)
            st.flags['CF'], st.flags['OF'] = c, o
            self.set_zs(st, r, w)
            if mn != 'cmp':
                W(d, r, w)
        elif mn in ('adcx', 'adox'):
            d, s = ops
            w = width(d, s)
            fl = 'CF' if mn == 'adcx' else 'OF'
            r, c, _ = self._addc(st, R(d, w), R(s, w), F(fl), w)
            st.flags[fl] = c
            W(d, r, w)
        elif mn in ('inc', 'dec'):
            (d,) = ops
            w = width(d)
            if mn == 'inc':
                r, _, o = self._addc(st, R(d, w), 1, False, w)
            else:
                r, _, o = self._subb(st, R(d, w), 1, False, w)
            st.flags['OF'] = o
            self.set_zs(st, r, w)
            W(d, r, w)
        elif mn == 'neg':
            (d,) = ops
            w = width(d)
            a = R(d, w)
            r, c, o = self._subb(st, 0, a, False, w)
            st.flags['CF'], st.flags['OF'] = c, o
            self.set_zs(st, r, w)
            W(d, r, w)
        elif mn in ('and', 'or', 'xor', 'test'):
            d, s = ops
            w = width(d, s)
            if mn == 'xor' and s == d and d[0] == 'r':
                a = None                      # zero idiom: the old value is not read
            else:
                a = R(d, w)
            if s[0] == 'i':
                b = lift(s[2] & mask(w), w)   # objdump prints the sign-extended immediate
            elif mn == 'xor' and s == d:
                b = a
            else:
                b = R(s, w)
            if mn == 'xor' and s == d:
                r = lift(0, w)                    # zero idiom: exactly 0
            else:
                r = {'and': p_and, 'test': p_and, 'or': p_or, 'xor': p_xor}[mn](a, b, w)
            st.flags['CF'] = False
            st.flags['OF'] = False
            self.set_zs(st, r, w)
            if mn != 'test':
                W(d, r, w)
        elif mn == 'not':
            (d,) = ops
            w = width(d)
            W(d, p_not(R(d, w), w), w)
        elif mn in ('shl', 'shr', 'sar', 'sal'):
            d, s = ops
            w = width(d)
            a = R(d, w)
            cnt = R(s, 8) if s[0] != 'i' else s[2]
            if not isc(cnt):
                raise SymError('symbolic shift count at %#x' % st.rip)
            cnt &= (63 if w == 64 else 31)
            if cnt:
                if mn in ('shl', 'sal'):
                    r = p_shl(a, cnt, w)
                    cf = p_eq(p_extract(a, w - cnt, w - cnt), 1, 1) if cnt <= w else False
                    of = b_xor(msb(r, w), cf) if cnt == 1 else UNDEF
                elif mn == 'shr':
                    r = p_lshr(a, cnt, w)
                    cf = p_eq(p_extract(a, cnt - 1, cnt - 1), 1, 1)
                    of = msb(a, w) if cnt == 1 else UNDEF
                else:
                    r = p_ashr(a, cnt, w)
                    cf = p_eq(p_extract(a, cnt - 1, cnt - 1), 1, 1)
                    of = False if cnt == 1 else UNDEF
                st.flags['CF'], st.flags['OF'] = cf, of
                self.set_zs(st, r, w)
                W(d, r, w)
        elif mn in ('shld', 'shrd'):
            d, s, c = ops
            w = width(d)
            a, b = R(d, w), R(s, w)
            cnt = c[2] if c[0] == 'i' else R(c, 8)
            if not isc(cnt):
                raise SymError('symbolic shift count')
            cnt &= 63
            if cnt:
                cat = p_concat(a, b, w, w) if mn == 'shld' else p_concat(b, a, w, w)
                if mn == 'shld':
                    r = p_extract(p_shl(cat, cnt, 2 * w), 2 * w - 1, w)
                    cf = p_eq(p_extract(a, w - cnt, w - cnt), 1, 1)
                else:
                    r = p_extract(p_lshr(cat, cnt, 2 * w), w - 1, 0)
                    cf = p_eq(p_extract(a, cnt - 1, cnt - 1), 1, 1)
                st.flags['CF'] = cf
                st.flags['OF'] = UNDEF if cnt != 1 else b_xor(msb(r, w), msb(a, w))
                self.set_zs(st, r, w)
                W(d, r, w)
        elif mn == 'mulx':
            hi_o, lo_o, s = ops
            w = width(hi_o)
            assert w == 64
            hi, lo = self.product(self.reg_read(st, 'rdx'), R(s, 64))
            W(lo_o, lo, 64)
            W(hi_o, hi, 64)        # if hi == lo the high half wins
        elif mn == 'mul':
            (s,) = ops
            w = width(s)
            assert w == 64
            hi, lo = self.product(self.reg_read(st, 'rax'), R(s, 64))
            self.reg_write(st, 'rax', lo)
            self.reg_write(st, 'rdx', hi)
            st.flags['CF'] = st.flags['OF'] = b_not(p_eq(hi, 0, 64))
            for f in ('ZF', 'SF', 'PF'):
                st.flags[f] = UNDEF
        elif mn == 'imul':
            if len(ops) == 1:
                raise SymError('one-operand imul not modelled')
            if len(ops) == 2:
                d, s = ops
                w = width(d)
                a, b = R(d, w), R(s, w)
            else:
                d, s, i = ops
                w = width(d)
                a, b = R(s, w), lift(i[2] & mask(w), w)
            full = p_mul(p_sext(a, w, 2 * w), p_sext(b, w, 2 * w), 2 * w)
            r = p_extract(full, w - 1, 0)
            ovf = b_not(p_eq(full, p_sext(r, w, 2 * w), 2 * w))
            st.flags['CF'] = st.flags['OF'] = ovf
            for f in ('ZF', 'SF', 'PF'):
                st.flags[f] = UNDEF
            W(d, r, w)
        elif mn.startswith('cmov'):
            d, s = ops
            w = width(d)
            c = CC[mn[4:]](F)
            v = p_ite(c, R(s, w), R(d, w), w)
            W(d, v, w)              # a 32-bit cmov zero-extends even when not taken
        elif mn.startswith('set') and mn[3:] in CC:
            (d,) = ops
            W(d, b2v(CC[mn[3:]](F), 8), 8)
        elif mn == 'bt':
            d, s = ops
            w = width(d, s)
            a = R(d, w)
            if s[0] == 'i':
                k = s[2] % w
            else:
                k = R(s, w)
                if not isc(k):
                    if self.mode == 'ct':
                        raise CTViolation('symbolic bit index at %#x' % st.rip)
                    raise SymError('symbolic bt index')
                k %= w
            st.flags['CF'] = p_eq(p_extract(a, k, k), 1, 1)
            for f in ('OF', 'SF', 'PF'):
                st.flags[f] = UNDEF
        elif mn == 'bswap':
            (d,) = ops
            w = width(d)
            a = R(d, w)
            bs = [p_extract(a, 8 * i + 7, 8 * i) for i in range(w // 8)]
            r = bs[0]
            for i in range(1, w // 8):
                r = p_concat(r, bs[i], 8 * i, 8)
            W(d, r, w)
        elif mn == 'xchg':
            d, s = ops
            w = width(d, s)
            a, b = R(d, w), R(s, w)
            W(d, b, w)
            W(s, a, w)
        elif mn == 'push':
            (s,) = ops
            v = R(s, 64)
            sp = p_sub(st.regs['rsp'], 8, 64)
            st.regs['rsp'] = sp
            st.mem.store(self.concrete_addr(st, sp), v, 8)
        elif mn == 'pop':
            (d,) = ops
            sp = self.concrete_addr(st, st.regs['rsp'])
            W(d, st.mem.load(sp, 8), 64)
            st.regs['rsp'] = p_add(sp, 8, 64)
        elif mn == 'rep_movsq':
            n = self.concrete_addr(st, self.reg_read(st, 'rcx'), 'count')
            si = self.concrete_addr(st, self.reg_read(st, 'rsi'))
            di = self.concrete_addr(st, self.reg_read(st, 'rdi'))
            for i in range(n):
                v = st.mem.load(si + 8 * i, 8)
                if self.write_log is not None:
                    self.write_log.append((di + 8 * i, 8, st.rip))
                st.mem.store(di + 8 * i, v, 8)
            st.regs['rcx'] = 0
            st.regs['rsi'] = (si + 8 * n) & M64
            st.regs['rdi'] = (di + 8 * n) & M64
        elif mn == 'call':
            tgt = int(rest.split()[0], 16)
            if tgt in self.hooks:
                self.hooks[tgt](self, st)
                st.rip = nxt
                return None
            sp = p_sub(st.regs['rsp'], 8, 64)
            st.regs['rsp'] = sp
            st.mem.store(self.concrete_addr(st, sp), nxt, 8)
            st.rip = tgt
            return None
        elif mn == 'ret':
            sp = self.concrete_addr(st, st.regs['rsp'])
            ra = st.mem.load(sp, 8)
            st.regs['rsp'] = p_add(sp, 8, 64)
            st.rip = self.concrete_addr(st, ra, 'return address')
            return None
        elif mn == 'jmp':
            tgt = rest.split()[0]
            if not re.match(r'^[0-9a-f]+$', tgt):
                raise SymError('indirect jmp not modelled')
            st.rip = int(tgt, 16)
            return None
        elif mn.startswith('j') and mn[1:] in CC:
            tgt = int(rest.split()[0], 16)
            return self.branch(st, CC[mn[1:]](F), tgt, nxt)
        elif mn in ('rcr', 'rcl'):
            d, s = ops
            w = width(d)
            cnt = s[2] if s[0] == 'i' else None
            if cnt != 1:
                raise SymError('rcr/rcl only modelled for a count of 1')
            a = R(d, w)
            cin = b2v(F('CF'), 1)
            if mn == 'rcr':
                r = p_concat(cin, p_extract(a, w - 1, 1), 1, w - 1)
                st.flags['CF'] = p_eq(p_extract(a, 0, 0), 1, 1)
                st.flags['OF'] = b_xor(msb(r, w), p_eq(p_extract(r, w - 2, w - 2), 1, 1))
            else:
                r = p_concat(p_extract(a, w - 2, 0), cin, w - 1, 1)
                st.flags['CF'] = msb(a, w)
                st.flags['OF'] = b_xor(msb(r, w), st.flags['CF'])
            W(d, r, w)
        # ---- legacy SSE (128-bit; the upper half of the ymm register is preserved)
        elif mn in ('movdqu', 'movdqa', 'movaps', 'movups'):
            d, s = ops
            v = R(s, 128)
            if d[0] == 'r':
                self.xmm_write_legacy(st, d[2], v)
            else:
                W(d, v, 128)
        elif mn in ('pxor', 'por', 'pand'):
            d, s = ops
            a, b = R(d, 128), R(s, 128)
            if mn == 'pxor' and s == d:
                r = lift(0, 128)
            else:
                r = {'pxor': p_xor, 'por': p_or, 'pand': p_and}[mn](a, b, 128)
            self.xmm_write_legacy(st, d[2], r)
        elif mn == 'psrldq':
            d, s = ops
            n = s[2]
            r = p_lshr(R(d, 128), 8 * n, 128) if n < 16 else lift(0, 128)
            self.xmm_write_legacy(st, d[2], r)
        elif mn == 'movq':
            d, s = ops
            if d[0] == 'r' and SUBREG[d[2]][1] == 64:
                W(d, p_extract(R(s, 128), 63, 0), 64)
            elif d[0] == 'r':          # movq xmm, r/m64 zeroes bits 64..127
                self.xmm_write_legacy(st, d[2], p_zext(R(s, 64), 64, 128))
            else:
                W(d, p_extract(R(s, 128), 63, 0), 64)
        # ---- the AVX2 subset of the constant-time table scan
        elif mn == 'vmovd':
            d, s = ops
            W(d, p_zext(R(s, 32), 32, 128), 128)
        elif mn == 'vpbroadcastd':
            d, s = ops
            x = p_extract(R(s, 128), 31, 0)
            r = x
            for i in range(1, 8):
                r = p_concat(x, r, 32, 32 * i)
            W(d, r, 256)
        elif mn in ('vpxor', 'vpaddd', 'vpcmpeqd'):
            d, a_, b_ = ops
            w = SUBREG[d[2]][1] if d[0] == 'r' else 256
            if mn == 'vpxor' and a_ == b_:
                a = b = None                      # zero idiom: the old value is not read
            else:
                a, b = R(a_, w), R(b_, w)
            if mn == 'vpxor':
                r = lift(0, w) if a_ == b_ else p_xor(a, b, w)
            else:
                lanes = []
                for i in range(w // 32):
                    x, y = p_extract(a, 32 * i + 31, 32 * i), p_extract(b, 32 * i + 31, 32 * i)
                    lanes.append(p_add(x, y, 32) if mn == 'vpaddd'
                                 else p_ite(p_eq(x, y, 32), 0xffffffff, 0, 32))
                r = lanes[0]
                for i in range(1, len(lanes)):
                    r = p_concat(lanes[i], r, 32, 32 * i)
            W(d, r, w)
        elif mn == 'vpblendvb':
            d, a_, b_, m_ = ops
            w = 256
            a, b, m = R(a_, w), R(b_, w), R(m_, w)
            bs = []
            for i in range(32):
                sel = p_eq(p_extract(m, 8 * i + 7, 8 * i + 7), 1, 1)
                bs.append(p_ite(sel, p_extract(b, 8 * i + 7, 8 * i), p_extract(a, 8 * i + 7, 8 * i), 8))
            r = bs[0]
            for i in range(1, 32):
                r = p_concat(bs[i], r, 8, 8 * i)
            W(d, r, w)
        elif mn == 'vmovdqu':
            d, s = ops
            w = width(d, s) if d[0] == 'm' or s[0] == 'm' else 256
            if d[0] == 'r':
                w = SUBREG[d[2]][1]
            elif s[0] == 'r':
                w = SUBREG[s[2]][1]
            W(d, R(s, w), w)
        else:
            raise SymError('instruction not modelled: %s at %#x' % (text, st.rip))
        st.rip = nxt
        return None

    @staticmethod
    def _split_ops(rest):
        if not rest:
            return []
        out, depth, cur = [], 0, ''
        for ch in rest:
            if ch == '[':
                depth += 1
            elif ch == ']':
                depth -= 1
            if ch == ',' and depth == 0:
                out.append(cur)
                cur = ''
            else:
                cur += ch
        out.append(cur)
        res = []
        for o in out:
            o = o.strip()
            m = re.match(r'^(BYTE|WORD|DWORD|QWORD|XMMWORD|YMMWORD) PTR (.*)$', o)
            if m:
                res.append(('m', PTRSZ[m.group(1)], m.group(2).strip()))
            elif o in SUBREG:
                res.append(('r', SUBREG[o][1], o))
            elif re.match(r'^-?0x[0-9a-f]+$', o) or re.match(r'^-?\d+$', o):
                res.append(('i', None, int(o, 0)))
            elif o.startswith('[') or re.match(r'^[a-z]s:', o):
                res.append(('m', None, o))
            else:
                # call/jmp targets like "401234 <fe_sqr>" are handled by the caller
                res.append(('x', None, o))
        return res


# --------------------------------------------------------------------------
# helpers for harnesses
# --------------------------------------------------------------------------
def limbs_val(limbs, w=64):
    """concatenate little-endian limbs into one bit-vector"""
    v = bv(limbs[-1], w)
    for x in reversed(limbs[:-1]):
        v = z3.Concat(v, bv(x, w))
    return v


def to_int_limbs(x, n=4):
    return [(x >> (64 * i)) & M64 for i in range(n)]


def from_limbs(ls):
    return sum(int(v) << (64 * i) for i, v in enumerate(ls))


def zx(v, w):
    """zero-extend a z3 bit-vector to width w"""
    v = bv(v, v.size()) if not isc(v) else v
    if isc(v):
        return z3.BitVecVal(v, w)
    return z3.ZeroExt(w - v.size(), v) if v.size() < w else v


CALLEE_SAVED = ['rbx', 'rbp', 'r12', 'r13', 'r14', 'r15']
