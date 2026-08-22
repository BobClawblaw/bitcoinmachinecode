#!/usr/bin/env python3
"""
abi_stack_audit.py -- SysV AMD64 stack-alignment auditor for this tree's NASM sources.

100% AI-authored, like the assembly it audits.

WHY THIS EXISTS
---------------
Incident #18 (commit b18114b): node_serve_loop reserved a frame whose size kept
RSP at 8 mod 16 at every nested `call`.  The SysV AMD64 ABI requires RSP == 0
mod 16 *at the call instruction*, so the callee sees 8 mod 16 on entry and its
`push rbp` restores 0.  Assembly callees in this tree never notice (no 16-byte
aligned stack operands anywhere), so the bug slept until a C logging call landed
on that path and glibc's vsnprintf executed `movaps %xmm0,-0xc0(%rbp)`.
That faults: #GP, delivered as SIGSEGV with si_addr == NULL.

WHAT IT DOES
------------
Abstract-interprets RSP mod 16 (and RBP mod 16, so `leave` / `mov rsp,rbp` /
`lea rsp,[rbp-N]` are modelled) over the control-flow graph of every assembly
function, from every entry point, and reports the parity at each `call` and at
each tail `jmp` to an external symbol.

Every function is analysed under BOTH possible entry parities:

  entry 8  -- the ABI-correct one (caller's `call` pushed 8 onto an aligned RSP)
  entry 0  -- what a *violating* caller delivers

A function whose calls are all aligned under entry 8 is ABI-correct.  A function
whose calls are only aligned under entry 0 is COMPENSATED: it was tuned against
a broken caller, and "fixing" that caller breaks it.  That distinction is the
whole point of the tool -- a naive global fix converts latent bugs into live
ones.

Usage:
  scripts/abi_stack_audit.py [--asmdir asm] [--format table|csv|summary]
  scripts/abi_stack_audit.py --check      # CI mode: exit 1 on any violation
"""

import argparse
import os
import re
import sys
from collections import defaultdict, OrderedDict

# ---------------------------------------------------------------------------
# Lexing
# ---------------------------------------------------------------------------

LABEL_RE = re.compile(r'^([A-Za-z_.$?][A-Za-z0-9_.$?@]*):')
DIRECTIVES = {
    'section', 'segment', 'global', 'extern', 'default', 'bits', 'align',
    'db', 'dw', 'dd', 'dq', 'dt', 'do', 'resb', 'resw', 'resd', 'resq',
    'times', 'equ', 'incbin', 'struc', 'endstruc', 'istruc', 'iend', 'at',
    'common', 'cpu', 'org', 'absolute', 'group', 'import', 'export', 'library',
    'module', 'uppercase', 'safeseh', 'static',
}

JCC = set('''jo jno js jns je jz jne jnz jb jnae jc jnb jae jnc jbe jna ja jnbe
jl jnge jge jnl jle jng jg jnle jp jpe jnp jpo jcxz jecxz jrcxz loop loope
loopne loopz loopnz'''.split())

TERMINATORS = {'ret', 'retn', 'retf', 'iret', 'iretq', 'ud2', 'hlt', 'syscall',
               'sysret', 'int3'}


def strip_comment(line):
    out = []
    in_s = None
    i = 0
    while i < len(line):
        c = line[i]
        if in_s:
            if c == '\\' and in_s != '`':
                out.append(c)
                i += 1
                if i < len(line):
                    out.append(line[i])
                    i += 1
                continue
            if c == in_s:
                in_s = None
            out.append(c)
        else:
            if c == ';':
                break
            if c in '"\'`':
                in_s = c
            out.append(c)
        i += 1
    return ''.join(out)


class Insn(object):
    __slots__ = ('file', 'line', 'mnem', 'ops', 'raw', 'labels', 'scope')

    def __init__(self, file, line, mnem, ops, raw, scope):
        self.file = file
        self.line = line
        self.mnem = mnem
        self.ops = ops
        self.raw = raw
        self.labels = []
        self.scope = scope

    def __repr__(self):
        return '%s:%d %s %s' % (self.file, self.line, self.mnem,
                                ','.join(self.ops))


class AsmFile(object):
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)
        self.insns = []           # list[Insn]
        self.labels = {}          # fully-qualified CODE label -> insn index
        self.data_labels = set()  # labels defined in .data/.bss/.rodata
        self.globals = []         # order-preserving list of exported names
        self.externs = set()
        self.defines = {}
        self._parse()

    # -- constant folding -------------------------------------------------
    def eval_imm(self, expr):
        e = expr.strip()
        if not e:
            return None
        for k, v in self.defines.items():
            e = re.sub(r'\b%s\b' % re.escape(k), '(%s)' % v, e)
        e = re.sub(r'\b(0[xX][0-9a-fA-F]+)\b', r'\1', e)
        e = re.sub(r'\b(\d+)h\b', r'0x\1', e)
        e = re.sub(r'\b(byte|word|dword|qword|oword)\b', '', e, flags=re.I)
        if not re.match(r'^[\s0-9a-fA-FxX()+\-*/<>|&%~]+$', e):
            return None
        try:
            return int(eval(e, {'__builtins__': {}}, {}))
        except Exception:
            return None

    def _parse(self):
        scope = None
        pending = []
        section = '.text'
        with open(self.path, 'r', errors='replace') as fh:
            raw_lines = fh.readlines()
        for n, raw in enumerate(raw_lines, 1):
            line = strip_comment(raw).strip()
            if not line:
                continue

            m = re.match(r'^%\s*define\s+(\S+)\s+(.*)$', line)
            if m:
                self.defines[m.group(1)] = m.group(2).strip()
                continue
            m = re.match(r'^(\S+)\s+equ\s+(.*)$', line, re.I)
            if m and not line.lower().startswith(('%', 'section')):
                self.defines[m.group(1)] = m.group(2).strip()
                continue
            if line.startswith('%'):
                continue

            ms = re.match(r'^(?:section|segment)\s+(\S+)', line, re.I)
            if ms:
                section = ms.group(1)
                continue

            # labels (possibly several, possibly label + insn on one line)
            while True:
                m = LABEL_RE.match(line)
                if not m:
                    break
                lab = m.group(1)
                if lab.startswith('.'):
                    full = (scope or '') + lab
                else:
                    scope = lab
                    full = lab
                if section.startswith('.text'):
                    pending.append(full)
                    self.labels[full] = len(self.insns)
                else:
                    # A label in .data/.bss/.rodata is storage, not an entry
                    # point.  Without this, `global interp_slice` (a scratch
                    # buffer) would be analysed as a function whose body is
                    # whatever code happens to follow in the next .text block.
                    self.data_labels.add(full)
                line = line[m.end():].strip()
            if not line:
                continue

            parts = line.split(None, 1)
            mnem = parts[0].lower()
            rest = parts[1] if len(parts) > 1 else ''

            if mnem in ('global', 'export'):
                for g in re.split(r'[,\s]+', rest.strip()):
                    if g and g not in self.globals:
                        self.globals.append(g)
                continue
            if mnem == 'extern':
                for g in re.split(r'[,\s]+', rest.strip()):
                    if g:
                        self.externs.add(g)
                continue
            if mnem in DIRECTIVES:
                continue

            ops = split_operands(rest)
            ins = Insn(self.name, n, mnem, ops, line, scope)
            ins.labels = pending
            pending = []
            self.insns.append(ins)
        # a trailing label with no instruction points one past the end; fine.


def split_operands(s):
    out = []
    depth = 0
    cur = []
    in_s = None
    for c in s:
        if in_s:
            cur.append(c)
            if c == in_s:
                in_s = None
            continue
        if c in '"\'`':
            in_s = c
            cur.append(c)
            continue
        if c in '[(':
            depth += 1
        elif c in '])':
            depth -= 1
        if c == ',' and depth == 0:
            out.append(''.join(cur).strip())
            cur = []
            continue
        cur.append(c)
    if ''.join(cur).strip():
        out.append(''.join(cur).strip())
    return out


# ---------------------------------------------------------------------------
# Abstract interpretation
# ---------------------------------------------------------------------------

UNK = None  # unknown parity


class CallSite(object):
    def __init__(self, func, insn, target, parity, kind):
        self.func = func
        self.insn = insn
        self.target = target
        self.parity = parity      # set of ints, or {'?'}
        self.kind = kind          # 'call' | 'tailjmp'
        self.cls = None
        self.note = ''


def resolve_target(af, ins, op):
    t = op.strip()
    if t.startswith('.'):
        return (ins.scope or '') + t
    return t


def transfer(af, ins, st):
    """Apply ins to state (rsp, rbp).  Returns new state or None if the
    instruction terminates the path."""
    rsp, rbp = st
    m = ins.mnem
    ops = ins.ops

    def bump(d):
        return (UNK if rsp is UNK else (rsp + d) % 16, rbp)

    if m == 'push':
        return bump(-8)
    if m == 'pop':
        if ops and ops[0].strip().lower() == 'rbp':
            return (UNK if rsp is UNK else (rsp + 8) % 16, UNK)
        return bump(8)
    if m in ('pushfq', 'pushf'):
        return bump(-8)
    if m in ('popfq', 'popf'):
        return bump(8)
    if m == 'leave':
        return (UNK if rbp is UNK else (rbp + 8) % 16, UNK)

    if m in ('sub', 'add') and ops and ops[0].strip().lower() == 'rsp':
        v = af.eval_imm(ops[1]) if len(ops) > 1 else None
        if v is None:
            return (UNK, rbp)
        return bump(-v if m == 'sub' else v)

    if m == 'and' and ops and ops[0].strip().lower() == 'rsp':
        v = af.eval_imm(ops[1]) if len(ops) > 1 else None
        if v is not None and (v % 16) == 0:
            return (0, rbp)          # snapped to alignment
        return (UNK, rbp)

    if m == 'mov' and ops and ops[0].strip().lower() == 'rsp':
        src = ops[1].strip().lower() if len(ops) > 1 else ''
        if src == 'rbp':
            return (rbp, rbp)
        return (UNK, rbp)

    if m == 'lea' and ops and ops[0].strip().lower() == 'rsp':
        mm = re.match(r'^\[\s*rbp\s*([+-])\s*([^\]]+)\]$',
                      ops[1].strip(), re.I) if len(ops) > 1 else None
        if mm and rbp is not UNK:
            v = af.eval_imm(mm.group(2))
            if v is not None:
                d = -v if mm.group(1) == '-' else v
                return ((rbp + d) % 16, rbp)
        return (UNK, rbp)

    if m == 'xchg' and any(o.strip().lower() == 'rsp' for o in ops):
        return (UNK, rbp)

    # rbp writes
    if m == 'mov' and ops and ops[0].strip().lower() == 'rbp':
        src = ops[1].strip().lower() if len(ops) > 1 else ''
        return (rsp, rsp if src == 'rsp' else UNK)
    if m == 'lea' and ops and ops[0].strip().lower() == 'rbp':
        mm = re.match(r'^\[\s*rsp\s*([+-])\s*([^\]]+)\]$',
                      ops[1].strip(), re.I) if len(ops) > 1 else None
        if mm and rsp is not UNK:
            v = af.eval_imm(mm.group(2))
            if v is not None:
                d = -v if mm.group(1) == '-' else v
                return (rsp, (rsp + d) % 16)
        return (rsp, UNK)
    if m in ('add', 'sub', 'and', 'or', 'xor') and ops and \
            ops[0].strip().lower() == 'rbp':
        return (rsp, UNK)

    return st


def analyse_function(af, entry_label, entry_parity, all_labels, limit=200000):
    """Walk the CFG from entry_label.  Returns (callsites, reachable_indices,
    unknown_seen)."""
    start = af.labels.get(entry_label)
    if start is None:
        return [], set(), False
    seen = {}
    work = [(start, (entry_parity % 16, UNK))]
    calls = OrderedDict()   # insn index -> CallSite (parity accumulated)
    reach = set()
    steps = 0
    unknown = False
    while work:
        steps += 1
        if steps > limit:
            unknown = True
            break
        idx, st = work.pop()
        if idx >= len(af.insns):
            continue
        key = (idx, st)
        if key in seen:
            continue
        seen[key] = True
        reach.add(idx)
        ins = af.insns[idx]
        m = ins.mnem

        # Do not walk into a *different* exported function's body: a fallthrough
        # into the next global is a real edge only if it is genuine fallthrough,
        # which it is in NASM.  We allow it (the assembler does), but stop when
        # we hit a label that begins another analysed entry to avoid conflating
        # frames -- except on plain fallthrough, which is legitimate.

        if m == 'call':
            tgt = resolve_target(af, ins, ins.ops[0]) if ins.ops else '?'
            cs = calls.get(idx)
            if cs is None:
                cs = CallSite(entry_label, ins, tgt, set(), 'call')
                calls[idx] = cs
            cs.parity.add('?' if st[0] is UNK else st[0])
            # `call` pushes 8 then the callee pops it: net zero on return.
            work.append((idx + 1, st))
            continue

        if m in TERMINATORS:
            continue

        if m == 'jmp':
            tgt = resolve_target(af, ins, ins.ops[0]) if ins.ops else '?'
            if tgt in af.labels:
                work.append((af.labels[tgt], st))
            elif re.match(r'^[A-Za-z_.$?][A-Za-z0-9_.$?@]*$', tgt):
                # tail call to an external / cross-file symbol
                cs = calls.get(idx)
                if cs is None:
                    cs = CallSite(entry_label, ins, tgt, set(), 'tailjmp')
                    calls[idx] = cs
                cs.parity.add('?' if st[0] is UNK else st[0])
            continue

        if m in JCC:
            tgt = resolve_target(af, ins, ins.ops[0]) if ins.ops else '?'
            if tgt in af.labels:
                work.append((af.labels[tgt], st))
            work.append((idx + 1, st))
            continue

        st2 = transfer(af, ins, st)
        if st2 is None:
            continue
        if st2[0] is UNK:
            unknown = True
        work.append((idx + 1, st2))

    return list(calls.values()), reach, unknown


# ---------------------------------------------------------------------------
# C-callee SSE / stack-touch classification (empirical, from objdump)
# ---------------------------------------------------------------------------

ALIGNED_SSE = re.compile(
    r'\b(movaps|movapd|movdqa|movntdq|movntps|movntpd|movntdqa)\b')
STACK_OPND = re.compile(r'\(%r(bp|sp)\)|\(%rsp,|\(%rbp,')


def scan_object_files(objdir):
    """symbol -> ('SSE-STACK'|'STACK'|'LEAF'|'?', evidence)"""
    import subprocess
    info = {}
    if not os.path.isdir(objdir):
        return info
    objs = [os.path.join(objdir, f) for f in sorted(os.listdir(objdir))
            if f.endswith('.o')]
    for o in objs:
        try:
            out = subprocess.run(['objdump', '-d', '--no-show-raw-insn', o],
                                 capture_output=True, text=True,
                                 timeout=120).stdout
        except Exception:
            continue
        cur = None
        acc = []
        for ln in out.splitlines():
            m = re.match(r'^[0-9a-f]+ <([^>]+)>:$', ln)
            if m:
                if cur:
                    info[cur] = classify_body(acc, o)
                cur = m.group(1)
                acc = []
                continue
            if cur:
                acc.append(ln)
        if cur:
            info[cur] = classify_body(acc, o)
    return info


def classify_body(lines, obj):
    sse_stack = None
    touches_stack = False
    for ln in lines:
        if ALIGNED_SSE.search(ln) and STACK_OPND.search(ln):
            sse_stack = ln.strip()
        if re.search(r'\b(sub|add)\s+\$0x[0-9a-f]+,%rsp\b', ln) or \
           re.search(r'\bpush\s+%rbp\b', ln):
            touches_stack = True
        if re.search(r'\bcall\b', ln):
            touches_stack = True
    if sse_stack:
        return ('SSE-STACK', '%s: %s' % (os.path.basename(obj), sse_stack))
    if touches_stack:
        return ('STACK', os.path.basename(obj))
    return ('LEAF', os.path.basename(obj))


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Whole-program fixed point over (function, entry parity)
# ---------------------------------------------------------------------------

class Program(object):
    def __init__(self, files):
        self.files = files
        self.byname = {}         # file name -> AsmFile
        self.gsym = {}           # exported symbol -> (AsmFile, label)
        self.asm_labels = set()  # every label any .asm source defines
        for af in files:
            self.byname[af.name] = af
            for lab in af.labels:
                self.asm_labels.add(lab)
            for g in af.globals:
                if g in af.labels:
                    self.gsym[g] = (af, g)

    def resolve(self, af, target):
        """Return (AsmFile, label) for a call/jmp target, or None if the
        target leaves assembly (C, libc) or is indirect."""
        if target in af.labels:
            return (af, target)
        if target in self.gsym:
            return self.gsym[target]
        return None


def run_fixed_point(prog, entry_parity=8, roots=None):
    """Propagate entry parities through the assembly call graph.

    Roots are the exported functions, which C (the daemon, the tests, libc
    callbacks) enters with the ABI parity.  Every asm->asm call then delivers
    (site parity - 8) mod 16 to its callee, so a violating caller shows up as
    an abnormal entry parity on the callee -- which is exactly how a
    COMPENSATED function stays quietly correct."""
    if roots is None:
        roots = []
        for af in prog.files:
            for g in af.globals:
                if g in af.labels:
                    roots.append((af, g))
    seen = set()
    work = [(af, g, entry_parity) for (af, g) in roots]
    for af, g, _ in list(work):
        seen.add((af.name, g, entry_parity))
    out = OrderedDict()          # (file, func, parity) -> [CallSite]
    entries = defaultdict(set)   # (file, func) -> {parities}
    while work:
        af, lab, ep = work.pop()
        entries[(af.name, lab)].add(ep)
        cs_list, _, _ = analyse_function(af, lab, ep, prog.asm_labels)
        out[(af.name, lab, ep)] = cs_list
        for cs in cs_list:
            tgt = prog.resolve(af, cs.target)
            if tgt is None:
                continue
            taf, tlab = tgt
            for p in cs.parity:
                if p == '?':
                    continue
                # `call` pushes the 8-byte return address; a tail `jmp` does not.
                nep = (p - 8) % 16 if cs.kind == 'call' else p % 16
                key = (taf.name, tlab, nep)
                if key not in seen:
                    seen.add(key)
                    work.append((taf, tlab, nep))
    return out, entries


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def parity_str(pset):
    if not pset:
        return '-'
    return '/'.join(sorted(('?' if p == '?' else str(p)) for p in pset))


def classify_site(cs, cinfo, prog):
    """A target defined by any .asm source is assembly; anything else is C or
    libc.  For C the verdict is empirical: SSE-against-a-stack-operand in the
    compiled object is what actually faults."""
    want = 0 if cs.kind == 'call' else 8
    bad = any(p == '?' or p != want for p in cs.parity)
    tgt = cs.target
    if not bad:
        return 'CORRECT', ''
    if tgt in prog.asm_labels:
        return 'VIOLATION-LATENT(asm)', 'asm callee, no aligned stack operand'
    ci = cinfo.get(tgt)
    if ci and ci[0] == 'SSE-STACK':
        return 'VIOLATION-LIVE', ci[1]
    if ci and ci[0] == 'STACK':
        return 'VIOLATION-LIVE(C frame)', 'C, frame/nested call: ' + ci[1]
    if ci and ci[0] == 'LEAF':
        return 'VIOLATION-LATENT(C leaf)', 'no frame, no SSE: ' + ci[1]
    return 'VIOLATION-LIVE(unknown)', 'external symbol, not found in tree'


def verdict_for(func_calls_8, func_calls_0):
    def ok(cl):
        if cl is None:
            return False
        for cs in cl:
            want = 0 if cs.kind == 'call' else 8
            for p in cs.parity:
                if p == '?' or p != want:
                    return False
        return True
    if not func_calls_8:
        return 'NO-CALLS'
    o8, o0 = ok(func_calls_8), ok(func_calls_0)
    if o8 and o0:
        return 'SELF-ALIGNING'
    if o8:
        return 'ABI-CORRECT'
    if o0:
        return 'NEEDS-ENTRY-0'
    return 'MIXED'


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--asmdir', default='asm')
    ap.add_argument('--objdir', default=None,
                    help='directory of built .o files for empirical C-callee '
                         'classification (default: same as --asmdir)')
    ap.add_argument('--format', default='table',
                    choices=('table', 'csv', 'summary', 'violations',
                             'functions'))
    ap.add_argument('--check', action='store_true',
                    help='CI mode: exit 1 if any reachable call site is '
                         'misaligned')
    ap.add_argument('--external-only', action='store_true',
                    help='with --check, fail only on call sites that LEAVE '
                         'assembly (C, libc, indirect).  Those are the ones '
                         'that can fault today; asm->asm misalignment is '
                         'latent because nothing in this tree uses a 16-byte '
                         'aligned stack operand.  This is the invariant CI '
                         'enforces: it would have failed on 5aea7c0, the '
                         'commit that put a C logging call on node_serve_loop\'s '
                         'misaligned path and caused incident #18.')
    ap.add_argument('--func', default=None)
    args = ap.parse_args()

    asmdir = args.asmdir
    objdir = args.objdir or asmdir

    files = [AsmFile(os.path.join(asmdir, f))
             for f in sorted(os.listdir(asmdir)) if f.endswith('.asm')]
    prog = Program(files)
    cinfo = scan_object_files(objdir)

    reached, entries = run_fixed_point(prog, 8)

    # Per-function "what parity does this function WANT" -- analysed in
    # isolation under both entry parities, independent of who actually calls it.
    want = {}
    for af in files:
        targets = set(af.globals) & set(af.labels)
        # internal helpers: any label used as a call/jmp target inside the file
        for ins in af.insns:
            if ins.mnem in ('call', 'jmp') and ins.ops:
                t = resolve_target(af, ins, ins.ops[0])
                if t in af.labels:
                    targets.add(t)
        for lab in sorted(targets):
            c8, _, _ = analyse_function(af, lab, 8, prog.asm_labels)
            c0, _, _ = analyse_function(af, lab, 0, prog.asm_labels)
            want[(af.name, lab)] = (verdict_for(c8, c0), c8, c0)

    rows = []
    for (fname, lab, ep), cs_list in reached.items():
        v = want.get((fname, lab), ('?', None, None))[0]
        multi = len(entries[(fname, lab)]) > 1
        for cs in cs_list:
            cls, ev = classify_site(cs, cinfo, prog)
            rows.append(dict(file=fname, func=lab, entry=ep, verdict=v,
                             multi_entry=multi, line=cs.insn.line,
                             kind=cs.kind, target=cs.target,
                             parity=parity_str(cs.parity), cls=cls, ev=ev,
                             exported=(lab in prog.gsym)))

    if args.func:
        rows = [r for r in rows if r['func'] == args.func]

    emit(rows, entries, want, prog, args)

    if args.check:
        bad = [r for r in rows if r['cls'] != 'CORRECT']
        if args.external_only:
            bad = [r for r in bad if r['cls'] != 'VIOLATION-LATENT(asm)']
        if bad:
            sys.stderr.write(
                '\nABI CHECK FAILED: %d reachable call site(s) violate the '
                'SysV 16-byte stack alignment.\n' % len(bad))
            for r in bad[:60]:
                sys.stderr.write('  %s:%d  in %s (entry %d)  -> %s  '
                                 'rsp%%16=%s  %s\n'
                                 % (r['file'], r['line'], r['func'], r['entry'],
                                    r['target'], r['parity'], r['cls']))
            if len(bad) > 60:
                sys.stderr.write('  ... and %d more\n' % (len(bad) - 60))
            return 1
        n_ext = len([r for r in rows
                     if r['cls'] not in ('CORRECT', 'VIOLATION-LATENT(asm)')])
        n_bad = len([r for r in rows if r['cls'] != 'CORRECT'])
        if args.external_only:
            sys.stderr.write(
                'ABI CHECK OK: every call site that leaves assembly has '
                'RSP == 0 mod 16.  (%d reachable call sites scanned; %d '
                'asm->asm sites are still misaligned -- latent, tracked in '
                'LOG.md incident #20.)\n' % (len(rows), n_bad))
        else:
            sys.stderr.write('ABI CHECK OK: %d reachable call sites, all '
                             'aligned.\n' % len(rows))
    return 0


def emit(rows, entries, want, prog, args):
    if args.format == 'csv':
        print('file,func,exported,entry_parity,multi_entry,verdict,line,kind,'
              'target,rsp_mod16,class,evidence')
        for r in rows:
            print('%s,%s,%d,%d,%d,%s,%d,%s,%s,%s,%s,"%s"' % (
                r['file'], r['func'], int(r['exported']), r['entry'],
                int(r['multi_entry']), r['verdict'], r['line'], r['kind'],
                r['target'], r['parity'], r['cls'], r['ev']))
    elif args.format == 'functions':
        agg = {}
        for r in rows:
            k = (r['file'], r['func'])
            a = agg.setdefault(k, dict(exported=r['exported'], verdict=r['verdict'],
                                       n=0, bad=0, live=0))
            a['n'] += 1
            if r['cls'] != 'CORRECT':
                a['bad'] += 1
            if 'LIVE' in r['cls']:
                a['live'] += 1
        print('%-26s %-30s %-4s %-14s %-10s %5s %5s %5s  %s'
              % ('FILE', 'FUNCTION', 'EXP', 'ISOLATED', 'ENTERED-AT',
                 'CALLS', 'BAD', 'LIVE', 'NOTE'))
        for k in sorted(agg):
            a = agg[k]
            eps = sorted(entries[k])
            note = ''
            if a['verdict'] == 'NEEDS-ENTRY-0' and eps == [0]:
                note = 'COMPENSATED -- fixing its caller BREAKS this'
            elif a['verdict'] == 'NEEDS-ENTRY-0' and 8 in eps:
                note = 'VIOLATES when entered correctly'
            elif a['verdict'] == 'MIXED':
                note = 'internally inconsistent: no entry parity works'
            if len(eps) > 1:
                note = ('MULTI-ENTRY; ' + note) if note else 'MULTI-ENTRY'
            print('%-26s %-30s %-4s %-14s %-10s %5d %5d %5d  %s'
                  % (k[0], k[1], 'yes' if a['exported'] else '-', a['verdict'],
                     ','.join(str(e) for e in eps), a['n'], a['bad'],
                     a['live'], note))
    elif args.format in ('table', 'violations'):
        cur = None
        for r in rows:
            if args.format == 'violations' and r['cls'] == 'CORRECT':
                continue
            key = (r['file'], r['func'], r['entry'])
            if key != cur:
                cur = key
                print('\n== %-26s %-30s entry=%d %s%s [%s]'
                      % (r['file'], r['func'], r['entry'],
                         'EXPORTED ' if r['exported'] else 'internal ',
                         '*MULTI-ENTRY*' if r['multi_entry'] else '',
                         r['verdict']))
            print('   L%-6d %-7s %-30s rsp%%16=%-4s %-26s %s'
                  % (r['line'], r['kind'], r['target'], r['parity'],
                     r['cls'], r['ev']))

    # ---- counts ----------------------------------------------------------
    cls_counts = defaultdict(int)
    for r in rows:
        cls_counts[r['cls']] += 1
    fn_verdicts = defaultdict(int)
    for (fname, lab), parities in entries.items():
        v = want.get((fname, lab), ('?',))[0]
        fn_verdicts[v] += 1
    multi = sorted(k for k, v in entries.items() if len(v) > 1)

    print('\n---- functions reached (by isolated-analysis verdict) ----')
    for k in sorted(fn_verdicts):
        print('  %-16s %5d' % (k, fn_verdicts[k]))
    print('  %-16s %5d' % ('TOTAL', sum(fn_verdicts.values())))
    print('---- reachable call sites ----')
    for k in sorted(cls_counts):
        print('  %-28s %5d' % (k, cls_counts[k]))
    print('  %-28s %5d' % ('TOTAL', sum(cls_counts.values())))
    print('---- functions entered at MORE THAN ONE parity ----')
    if not multi:
        print('  (none)')
    for k in multi:
        print('  %s %s  entries=%s' % (k[0], k[1],
                                       sorted(entries[k])))


if __name__ == '__main__':
    sys.exit(main())
