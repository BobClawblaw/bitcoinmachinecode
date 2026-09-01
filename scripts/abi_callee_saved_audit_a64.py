#!/usr/bin/env python3
"""
abi_callee_saved_audit_a64.py -- AArch64 (GNU as) callee-saved register
preservation auditor for this tree's port/arm64/*.S sources.  AArch64
companion to scripts/abi_callee_saved_audit.py (SysV AMD64 / NASM).

100% AI-authored, like the assembly it audits.

WHY THIS EXISTS
---------------
The port develops ON the aarch64 machine and the C-side tests are built
natively against the .S objects with the host compiler at -O2.  Unlike the x86
tree (whole consensus path pinned to -O0), -O2 keeps live state in
callee-saved registers across calls, so ONE .S function that writes x19-x28
without saving/restoring it corrupts the caller's locals.  That class is the
prime suspect for the interpreter/store SIGSEGV cluster (test_dersig_encoding,
test_interp_legacy_spend, test_archive_truncate_nonmonotonic, ...), where
gdb showed "some asm callee clobbers main's x22".  The UTXO_LSM_BARRIER
convention in utxo_live.c (a compiler barrier after every bitcoin_utxo_lsm.S
call) is a workaround for exactly this property; this tool makes the audit
systematic instead of per-incident.

AArch64 register contract audited
---------------------------------
Callee-saved (must survive any call): x19-x28 (w19-w28 writes count: they
zero-extend and clobber the full register), x29 (FP, frame-managed), x30 (LR,
clobbered by bl/blr and reloaded before ret).  x0-x17 + x18 are caller-saved;
sp is managed.  FP/SIMD v0-v31: v8-v15 are callee-saved for the LOW 64 bits
(d0-d7); this tool tracks d8-d15/v8-v15-bottom as callee-saved too.

WHAT IT REPORTS
---------------
  UNSAVED-CLOBBER   (sound for direct writes, gated with --check)
      A function writes a callee-saved register and never saves it (no
      `str`/`stp` of that register to memory anywhere in the function), or
      saves it but has no matching `ldr`/`ldp` restore.  Direct class only:
      this alone breaks every -O2 C caller.

  CALLS-OFFENDER    (informational)
      The function calls a UNSAVED-CLOBBER offender.  If it also keeps a live
      value in the clobbered register across that call, it inherits the bug.
      Liveness is NOT computed -- inspect these by hand; the save/restore in
      the caller does NOT protect values it legitimately keeps in the
      register across the offending call.

  SAVE-AREA-EXPOSED (a shape, NOT a proof -- reported, not gated)
      A store/`str`-stage addresses locals at NEGATIVE offsets from x29 (FP)
      while callee-saved save slots also live below FP.  This tree's prologue
      convention is `stp x29,x30,[sp,#-N]!; mov x29,sp; stp x19,x20,[sp,#-16]!`
      which puts the save area BELOW the new FP; any [x29,#-N] local with
      N > (bytes already reserved below FP) walks straight into it.  This is
      the GLV TAB[8]-class bug (frame-slot collision), pitfall #1 in the port
      memory.  Whether an indexed write reaches depends on buffer lengths, so
      this is the risk list, not the failure list.

Usage:
  scripts/abi_callee_saved_audit_a64.py [--asmdir port/arm64] \
      [--format table|summary] [--check]
      [file.S ...]           # default: every *.S under --asmdir
"""

import argparse
import os
import re
import sys
from collections import OrderedDict

# ---------------------------------------------------------------------------
# Register model
# ---------------------------------------------------------------------------

def norm_reg(tok):
    """Token -> canonical 64-bit name for callee-saved tracking, else None.

    wN writes clobber xN (AArch64 zero-extends into the full register), so
    both forms normalize to xN.  x29/x30 track as 'x29'/'x30'.  dN/vN: only
    the low 64 bits of v8-v15 are callee-saved -> tracked as 'd8'..'d15'.
    """
    t = tok.strip().lower()
    if not re.match(r'^[xwzdvhq][0-9]+$|^sp$|^xzr$|^wzr$|^lr$|^fp$', t):
        return None
    if t in ('sp', 'xzr', 'wzr'):
        return None
    if t == 'lr':
        return 'x30'
    if t == 'fp':
        return 'x29'
    if t[0] in ('w', 'x'):
        n = int(t[1:])
        return 'x%d' % n if 19 <= n <= 30 else None
    if t[0] == 'd':
        n = int(t[1:])
        return 'd%d' % n if 8 <= n <= 15 else None
    if t[0] == 'v':
        n = int(t[1:])
        return 'd%d' % n if 8 <= n <= 15 else None
    return None


CALLEE_SAVED_ORDER = ['x%d' % i for i in range(19, 29)] + \
                     ['x29', 'x30'] + ['d%d' % i for i in range(8, 16)]

# Ops whose FIRST operand is written (beyond ldr/ldp handled separately).
DST_FIRST = {
    'mov', 'movz', 'movn', 'movk', 'mvn', 'mrs', 'msr',
    'add', 'adds', 'sub', 'subs', 'adc', 'adcs', 'sbc', 'sbcs', 'neg', 'negs',
    'ngc', 'ngcs', 'and', 'ands', 'orr', 'orn', 'eor', 'eon', 'bic', 'bics',
    'lsl', 'lsr', 'asr', 'asrv', 'ror', 'rorv', 'lslv', 'lsrv',
    'madd', 'msub', 'mneg', 'smaddl', 'umaddl', 'smsubl', 'umsubl',
    'smull', 'umull', 'smulh', 'umulh', 'smnegl', 'umnegl',
    'sdiv', 'udiv', 'sdivl', 'udivl',
    'sdive', 'urem', 'srem',
    'cset', 'csetm', 'csinc', 'csinv', 'csneg', 'csel',
    'adr', 'adrp',
    'sxtb', 'sxth', 'sxtw', 'uxtb', 'uxth', 'uxtw', 'sbfiz', 'ubfiz',
    'sbfx', 'ubfx', 'extr', 'bfi', 'bfm', 'sbfm', 'ubfm',
    'fmov', 'fabs', 'fneg', 'fsqrt', 'fcvt', 'fcvtzs', 'fcvtzu', 'scvtf',
    'ucvtf', 'lslv', 'rev', 'rev16', 'rev32', 'rev64', 'rbit', 'cls', 'clz',
    'cnt', 'aesd', 'aese', 'sha1c', 'sha1h', 'sha256h', 'sha256h2',
    'sha256su0', 'sha256su1', 'dup', 'ins',
}
# cmp/tst and friends: no register writes.
NO_DST = {'cmp', 'cmn', 'tst', 'ccmp', 'ccmn', 'teq',
          'b', 'br', 'ba', 'bl', 'blr', 'ret', 'cbz', 'cbnz', 'tbz', 'tbnz',
          'nop', 'hlt', 'brk', 'svc', 'dmb', 'dsb', 'isb', 'hint', 'prfm'}
# Loads: first operand (ldp: first TWO) written.  Stores: none, but they SAVE.
LOAD_OPS = {'ldr', 'ldur', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh', 'ldrsw', 'ldrd',
            'ld1', 'ld2', 'ld3', 'ld4', 'ldar', 'ldapr', 'ldaxr', 'ldxr',
            'ldxp', 'ldaxp', 'ldnp', 'ldpsw', 'ldtr', 'ldurb', 'ldurh',
            'ldursb', 'ldursh', 'ldursw', 'ldumax', 'ldumina', 'ldset', 'ldseta',
            'ldp'}
STORE_OPS = {'str', 'stur', 'strb', 'strh', 'st1', 'st2', 'st3', 'st4',
             'stlr', 'stxr', 'stxp', 'stlxr', 'stlxp', 'stnp', 'sttr',
             'stumina', 'stset', 'stp'}
# stlxr writes the STATUS into its FIRST operand -- handle specially.
BRANCH_OPS = {'b', 'br', 'ba', 'bl', 'blr', 'ret', 'cbz', 'cbnz', 'tbz',
              'tbnz'}

MEM_RE = re.compile(r'\[([^\]]*)\](\s*,\s*#?\S+)?(\s*!)?')


def split_operands(s):
    """Split an operand string on top-level commas (bracket-aware)."""
    ops, depth, cur = [], 0, ''
    for ch in s:
        if ch == '[':
            depth += 1
        elif ch == ']':
            depth -= 1
        if ch == ',' and depth == 0:
            ops.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        ops.append(cur.strip())
    return ops


def mem_base(expr):
    """'[x29, #-8]' -> ('x29', -8); '[sp]' -> ('sp', 0); indexed -> None."""
    m = MEM_RE.search(expr)
    if not m:
        return None
    inner = re.sub(r'\b(byte|halfword|word|doubleword|quadword)\b', '',
                   m.group(1), flags=re.I).strip()
    mm = re.match(r'^(sp|x29|xzr|wzr)\s*(?:,\s*(#-?[^,]*))?$', inner)
    if not mm:
        return None
    base = 'x29' if mm.group(1) == 'x29' else 'sp'
    off = mm.group(2)
    if off is None:
        return (base, 0)
    off = off.lstrip('#').replace(' ', '')
    try:
        return (base, int(off, 0))
    except ValueError:
        return None  # symbolic/immediate macro -> unknown


# ---------------------------------------------------------------------------
# Function extraction
# ---------------------------------------------------------------------------

def extract_functions(path):
    """[(name, [(lineno, text), ...])] for every label-defined function.

    Function extent: from its label to the next column-0 label (or EOF).
    Local labels (this tree's style: `.name:`) do NOT start a new function.
    """
    funcs = []
    cur_name, cur_body = None, []
    for lineno, line in enumerate(open(path, encoding='utf-8', errors='replace'), 1):
        code = line.split('//')[0].split(';')[0].rstrip('\n')
        if not code.strip():
            cur_body.append((lineno, ''))
            continue
        m = re.match(r'^([A-Za-z_.$][A-Za-z0-9_.$]*):', code)
        if m and not m.group(1).startswith('.'):
            if cur_name is not None:
                funcs.append((cur_name, cur_body))
            cur_name, cur_body = m.group(1), [(lineno, code)]
        else:
            if cur_name is not None:
                cur_body.append((lineno, code))
    if cur_name is not None:
        funcs.append((cur_name, cur_body))
    return funcs


# ---------------------------------------------------------------------------
# Per-instruction analysis
# ---------------------------------------------------------------------------

class Insn:
    __slots__ = ('op', 'ops', 'lineno', 'writes', 'saves', 'restores', 'is_bl')

    def __init__(self, line, lineno=0):
        self.lineno = lineno
        self.writes = set()
        self.saves = {}       # reg -> (base, off) memory slot
        self.restores = set()
        self.is_bl = False
        code = line.strip()
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_.]*)\s*(.*)$', code)
        if not m:
            return
        op = m.group(1).lower()
        self.op = op
        rest = m.group(2)
        self.ops = split_operands(rest) if rest else []
        low = op

        if low in BRANCH_OPS:
            if low in ('bl', 'blr'):
                self.is_bl = True
                self.writes.add('x30')
            return

        if low in ('stlxr',):
            if self.ops:
                r = norm_reg(self.ops[0])
                if r:
                    self.writes.add(r)
            return

        if low in STORE_OPS:
            # str x19, [sp, #8]  -> x19 SAVED at that slot
            for srcop in self.ops:
                r = norm_reg(srcop)
                if r:
                    for dstop in self.ops:
                        if '[' in dstop:
                            slot = mem_base(dstop)
                            if slot:
                                self.saves[r] = slot
                            break
            # stp x19,x20,[sp,#-16]!
            if low in ('stp', 'stnp') and len(self.ops) >= 3:
                for srcop in self.ops[:2]:
                    r = norm_reg(srcop)
                    if r:
                        slot = mem_base(self.ops[2])
                        if slot is None:
                            slot = (None, None)
                        self.saves[r] = slot
            self._writeback()
            return

        if low in LOAD_OPS:
            # ldr x0, [x29,#-8] / ldp x19,x20,[sp],#16
            for dstop in self.ops:
                r = norm_reg(dstop)
                if r:
                    self.writes.add(r)
            if low in ('ldp', 'ldnp', 'ldxp', 'ldaxp') and len(self.ops) >= 3:
                slot = mem_base(self.ops[2])
                for dstop in self.ops[:2]:
                    r = norm_reg(dstop)
                    if r:
                        self.writes.add(r)
                        if slot:
                            self.restores.add(r)
                        self._writeback_base(self.ops[2])
            elif self.ops:
                # memory operand may be ops[-1] ([x29,#-8]) or ops[-2]
                # (post-index [sp],#16); find the bracketed one
                slot = None
                for opnd in self.ops:
                    if '[' in opnd:
                        slot = mem_base(opnd)
                        break
                r = norm_reg(self.ops[0])
                if r and slot:
                    self.restores.add(r)
                self._writeback()
            return

        if low in NO_DST:
            return

        # generic: destination-first
        if self.ops:
            r = norm_reg(self.ops[0])
            if r:
                self.writes.add(r)
            # writeback on e.g. `add sp, sp, #32` is just a normal write
        return

    def _writeback(self):
        for opnd in self.ops:
            if MEM_RE.search(opnd) and re.search(r'\]\s*!?', opnd):
                if re.search(r'\]\s*!', opnd):
                    mm = MEM_RE.search(opnd)
                    inner = mm.group(1).split(',')[0].strip()
                    r = norm_reg(inner)
                    if r:
                        self.writes.add(r)

    def _writeback_base(self, opnd):
        mm = MEM_RE.search(opnd)
        if mm and re.search(r'\]\s*!', opnd):
            inner = mm.group(1).split(',')[0].strip()
            r = norm_reg(inner)
            if r:
                self.writes.add(r)


def analyze_function(body):
    insns = []
    in_macro = False
    for lineno, text in body:
        # /* */ comments only in this tree; '#' is the IMMEDIATE prefix on
        # AArch64 and must never be treated as a comment character.
        code = re.sub(r'/\*.*?\*/', ' ', text).strip()
        # numeric local labels may share a line with the instruction ("1: ldp")
        code = re.sub(r'^(\d+\s*:\s*)+', '', code)
        if not code or code.startswith('.'):
            # .macro bodies are templates, not code of the enclosing function
            if code.startswith('.macro'):
                in_macro = True
            elif code.startswith('.endm'):
                in_macro = False
            continue
        if in_macro:
            continue
        code = re.sub(r'\s*//.*$', '', code)
        if not code:
            continue
        insns.append(Insn(code, lineno))
    return insns


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def audit_file(path):
    """-> (offenders, callers_of, exposed) where
    offenders: [(func, reg, reason)]  reason in {'no-save','no-restore'}
    callers_of: [(func, callee)]
    exposed:   [(func, line, text)]   save-area-exposed shapes
    """
    offenders, callers_of, exposed = [], [], []
    offender_names = set()
    funcs = extract_functions(path)
    by_name = {}
    for name, body in funcs:
        by_name[name] = body

    for name, body in funcs:
        insns = analyze_function(body)
        saves = {}
        restores = set()
        writes = {}
        calls = []
        for ins in insns:
            for r in ins.saves:
                saves.setdefault(r, ins.saves[r])
            restores |= ins.restores
            for r in ins.writes:
                writes.setdefault(r, ins.lineno)
            if ins.is_bl:
                tgt = ins.ops[0] if ins.ops else ''
                calls.append(tgt)
        for r, line in sorted(writes.items()):
            if r not in saves:
                offenders.append((name, r, 'no-save', line))
                offender_names.add(name)
            elif r not in restores:
                offenders.append((name, r, 'no-restore', line))
                offender_names.add(name)
        for tgt in calls:
            if tgt in offender_names or tgt in by_name and tgt in offender_names:
                callers_of.append((name, tgt))
        # save-area-exposed: negative-FP locals with save slots below FP
        has_low_saves = any(base == 'sp' and off is not None and off < 0
                            for r, (base, off) in saves.items())
        for lineno, text in body:
            code = re.sub(r'/\*.*?\*/', ' ', text)
            m = re.search(r'\[\s*x29\s*,\s*#(-0x[0-9a-fA-F]+|-\d+)\s*\]', code)
            if m and has_low_saves and not re.match(r'\s*(stp|str)\b', code):
                # a [x29,#-N] LOCAL access (not itself a save)
                off = int(m.group(1), 0)
                if off <= -8:
                    exposed.append((name, lineno, text.strip()))
    return offenders, callers_of, exposed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--asmdir', default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'port', 'arm64'))
    ap.add_argument('--format', choices=['table', 'summary'], default='table')
    ap.add_argument('--check', action='store_true',
                    help='exit 1 on any UNSAVED-CLOBBER')
    ap.add_argument('files', nargs='*')
    args = ap.parse_args()

    files = args.files or sorted(
        os.path.join(args.asmdir, f)
        for f in os.listdir(args.asmdir) if f.endswith('.S'))
    total_offenders = 0
    for path in files:
        offenders, callers_of, exposed = audit_file(path)
        real = [(f, r, why, ln) for f, r, why, ln in offenders
                if why == 'no-save' or why == 'no-restore']
        total_offenders += len(real)
        if args.format == 'summary':
            print(f'{os.path.basename(path)}: {len(real)} unsaved-clobber, '
                  f'{len(exposed)} exposed-frame shapes')
            continue
        for f, r, why, ln in real:
            print(f'UNSAVED-CLOBBER {os.path.basename(path)}:{ln}: '
                  f'{f} writes {r} ({why})')
        for f, tgt in sorted(set(callers_of)):
            print(f'CALLS-OFFENDER  {os.path.basename(path)}: {f} -> {tgt}')
        for f, ln, text in exposed:
            print(f'SAVE-AREA-EXPOSED {os.path.basename(path)}:{ln}: '
                  f'{f}: {text[:90]}')
    if args.check and total_offenders:
        print(f'--check: {total_offenders} UNSAVED-CLOBBER violation(s)',
              file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
