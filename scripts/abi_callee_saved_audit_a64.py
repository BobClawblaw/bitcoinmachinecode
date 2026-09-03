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

  SAVE-AREA-ALIAS   (sound, gated with --check)
      A direct store of statically-known size and statically-known address
      overlaps a save slot that is live at that instruction.  This is the
      hand-check that found GLV's TAB[8] sitting on top of AUXX/ZR/AI/DGE
      (worklog 2026-09-01): the scratch area and the save area were both
      addressed off sp and nothing in the build noticed the overlap.  Ported
      from scripts/abi_callee_saved_audit.py's check of the same name, which
      is gated in the x86 CI.

      Two things this AArch64 version resolves rather than skips, because the
      port's frames are written in those idioms and skipping them would have
      left the check blind exactly where the class lives:
        * `.equ`/`.set` frame maps -- secp256k1_glv_mul.S declares
          `.equ TAB, 0x120 ... .equ FRAME, 0x6C0` and stores read `[sp, #TAB]`;
          unresolved, those stores have no address at all.
        * `mov xN,#imm / movk xN,#imm,lsl #16 / sub sp, sp, xN` -- cons_verify
          and utxo_store_reload allocate a FIXED megabyte-scale frame through a
          register.  Constants are followed only into the registers that move
          sp, and any other write to one forgets the value.

      What it still cannot see, named per function by --list-unmodelled: a
      register used as a second frame base (`mov x28, sp` then `[x28,#TAB]`),
      an alignment-clamped sp (`mov x9,sp / and x9,x9,#-16 / mov sp,x9` --
      point_scalar_mul_glv, the GLV function itself, is in that set), and a
      buffer whose size really is an argument.  Covering those needs offsets as
      ranges and a report only on overlap-for-every-value; until then the
      coverage line states the followed/unfollowed counts, so silence means
      "checked", never "the analysis gave up quietly".  A label merely reached
      at two stack depths is NOT a give-up: both states are walked
      independently, which is what makes loops and multi-exit epilogues
      checkable instead of skipped.

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
        self.op = ''
        self.ops = []
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
        #
        # Cut from the opener to end of line, NOT `/* ... */` as a pair:
        # extract_functions() already truncated the line at its first ';' --
        # inherited from NASM, where ';' starts a comment, and a C comment like
        # `#48 /* buf at sp+0..31 ; sp stays 16-aligned */` gets severed inside
        # itself.  A paired regex then matches nothing, the comment text stays
        # in the operand, and the instruction misreads (`sub sp, sp, <junk>`
        # looks like a dynamic frame and the whole function is skipped).
        code = re.sub(r'/\*.*', ' ', text).strip()
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

# ---------------------------------------------------------------------------
# SAVE-AREA-ALIAS: a frame walk, in entry-sp coordinates
# ---------------------------------------------------------------------------
#
# Everything is measured as an offset from the stack pointer AT FUNCTION ENTRY
# (0 = where the return address sits).  Pushing grows downward, so a frame of
# 48 bytes lives at [-48, 0).  The tree's own prologue convention
#
#     stp x29,x30,[sp,#-16]!   -> x29 at -16, x30 at -8
#     stp x19,x20,[sp,#-16]!   -> x19 at -32, x20 at -24
#
# means save slots are just the low addresses of whatever has been reserved, so
# a scratch slot handed out by hand (`str x8, [sp, #64]` after a 48-byte frame)
# is a fixed number of bytes above the deepest thing the code believes it owns.

SCALAR_SIZE = {'x': 8, 'd': 8, 'w': 4, 's': 4, 'h': 2, 'b': 1}

# Scalar stores and the width each writes; None means "whatever the source
# register's width is" (str w0 writes 4, str x0 writes 8).  Anything not listed
# never claims an alias -- a store whose size is not known cannot be shown to
# overlap a slot.  stp is the whole tree's prologue and stnp appears with it;
# the acquire/release and unaligned forms are not used anywhere under
# port/arm64 today, but they are priced here so adding one cannot silently
# disable the check.
STORE_SCALAR = {'str': None, 'strb': 1, 'strh': 2,
                'stur': None, 'sturb': 1, 'sturh': 2,
                'stlr': None, 'stlrb': 1, 'stlrh': 2,
                'sttr': None, 'sttrb': 1, 'sttrh': 2}
STORE_PAIR = ('stp', 'stnp')

CALLEE_SAVED_SET = set(CALLEE_SAVED_ORDER)


def reg_operand(tok):
    """('x19'|'w3'|'xzr'|None, bytes_written).  Vector/predicate operands are
    deliberately None -- they are not modelled, and a store that cannot be
    sized is never reported as an alias."""
    t = tok.strip().lower()
    if not re.match(r'^[xwdshb][0-9]+$', t) and t not in ('xzr', 'wzr', 'sp'):
        return (None, None)
    if t in ('sp',):
        return (None, None)
    if t in ('xzr', 'wzr'):
        return ('xzr', 8 if t == 'xzr' else 4)
    return (t, SCALAR_SIZE.get(t[0]))


SYMOPS = re.compile(r'^[0-9A-Za-z_xa-fA-F+\-*/%&|^~()<>\s]*$')
SYMNAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')


def file_macros(path):
    """{macro_name: moves_sp} -- an invocation expands to the body, so a macro
    that moves sp is NOT invisible to the frame and a walk that ignores macro
    calls would be silently wrong.  Every macro under port/arm64 is
    frame-neutral today (checked: 12 of them, none write sp); the audit refuses
    to assume that stays true, and a function that calls one which does move sp
    is reported as unmodelled rather than analysed against a fiction."""
    macros = {}
    name, body = None, []
    for line in open(path, encoding='utf-8', errors='replace'):
        code = line.split('//')[0].split('/*')[0].strip()
        m = re.match(r'^\.macro\s+([A-Za-z_][A-Za-z0-9_]*)', code)
        if m:
            name, body = m.group(1), []
            continue
        if name is None:
            continue
        if re.match(r'^\.endm\b', code):
            joined = ' '.join(body)
            macros[name] = bool(re.search(
                r'^\s*(add|sub|mov|stp|ldr|ldp)\s+sp\b|\]\s*!', joined,
                re.M | re.I))
            name = None
            continue
        body.append(code)
    return macros


def file_symbols(path):
    """{name: int} for every .equ/.set/.equiv in the file, evaluated in order.

    The port's frame maps are symbolic -- secp256k1_glv_mul.S is
    `.equ TAB, 0x120 / .equ AUXX, 0x320 / ... / .equ FRAME, 0x6C0`, and stores
    read `[sp, #TAB]`.  Without resolving these the walk sees no address at all
    for exactly the functions whose overlapping frame regions this auditor
    exists to find (TAB on top of AUXX was the 2026-09-01 GLV bug), so symbolic
    offsets are resolved rather than skipped.
    """
    syms = {}
    for line in open(path, encoding='utf-8', errors='replace'):
        code = line.split('//')[0].split('/*')[0]
        m = re.match(r'\s*\.(?:set|equ|equiv)\s+([A-Za-z_][A-Za-z0-9_]*)\s*,\s*(.*)$',
                     code)
        if not m:
            continue
        name, expr = m.group(1), m.group(2).strip()
        val = eval_expr(expr, syms)
        if val is not None:
            syms[name] = val
    return syms


def eval_expr(text, syms):
    """Evaluate a GAS absolute expression, or None if anything in it is not
    a literal or an already-defined symbol.  Deliberately narrow: an
    unresolved name yields None (the store is then unmodelled), never a guess."""
    t = text.strip().rstrip(')') if text.strip().count('(') < text.strip().count(')') else text.strip()
    if not t or not SYMOPS.match(t):
        return None
    # Mask numeric literals before looking for names: `0x60` otherwise reads as
    # the identifier `x60` and every hex constant looks unresolved.
    masked = re.sub(r'0[xX][0-9a-fA-F]+|\d+', ' ', t)
    unknown = [n for n in SYMNAME.findall(masked) if n not in syms]
    if unknown:
        return None
    try:
        val = eval(t.replace('$', ''), {'__builtins__': {}}, dict(syms))
    except Exception:
        return None
    return int(val) if isinstance(val, int) else None


def mem_operand(expr, syms=None):
    """'[x29, #-8]!' -> ('x29', -8, True); '[sp], #16' handled by the caller.
    None when the base is a general register or the offset cannot be resolved."""
    m = MEM_RE.search(expr)
    if not m:
        return None
    inner = re.sub(r'\b(byte|halfword|word|doubleword|quadword)\b', '',
                   m.group(1), flags=re.I).strip()
    mm = re.match(r'^(sp|x29)\s*(?:,\s*(#-?[^,]*))?$', inner)
    if not mm:
        return None
    base = mm.group(1)
    off = mm.group(2)
    if off is None:
        return (base, 0, bool(m.group(3)))
    off = off.lstrip('#').replace(' ', '')
    try:
        return (base, int(off, 0), bool(m.group(3)))
    except ValueError:
        val = eval_expr(off, syms or {})
        if val is None:
            return None          # genuinely symbolic -> address unknown
        return (base, int(val), bool(m.group(3)))


def parse_items(body):
    """[(kind, ...)] keeping the label lines analyze_function() throws away:
      ('label', name, idx_at_which_code_follows)   ('ins', Insn, lineno, text)
    Numeric labels (`1:` / `b 1f`) are kept: the tree uses them heavily, and a
    walk that cannot resolve them cannot follow a loop."""
    items = []
    in_macro = False
    for lineno, text in body:
        # extract_functions() already cut the line at the first ';' (a NASM
        # habit it kept), and a comment like `#48  /* buf at sp+0..31 ; sp stays
        # 16-aligned */` is cut INSIDE the comment -- so the opener is left with
        # no closer and the operand text ends up carrying `/* buf at ...`.  The
        # second regex is what makes such a comment invisible; without it those
        # instructions parse as `sub sp, sp, <nonsense>` and the whole function
        # is written off as a dynamic frame (23 functions were, wrongly).
        code = re.sub(r'/\*.*?\*/', ' ', text)
        code = re.sub(r'/\*.*$', ' ', code).strip()
        mnum = re.match(r'^(\d+)\s*:\s*(.*)$', code)
        if mnum:
            items.append(('numlabel', mnum.group(1), len(items)))
            code = mnum.group(2).strip()
            if not code:
                continue
        code = re.sub(r'\s*//.*$', '', code).strip()
        if not code:
            continue
        # A LOCAL label starts with '.' too -- `.cc_const:` is a jump target,
        # not a directive.  Skipping every '.'-leading line (the first draft
        # did that in the same breath as `.macro`) made each branch to a local
        # label look unresolvable and wrote off 91 functions as "frame not
        # followed".  The coverage line is what caught it: it said 112
        # unmodelled out of 759, which is far too many to be true.
        mlbl = re.match(r'^([A-Za-z_.$][A-Za-z0-9_.$]*):\s*(.*)$', code)
        if mlbl:
            items.append(('label', mlbl.group(1), len(items)))
            code = mlbl.group(2).strip()
            if not code:
                continue
        if code.startswith('.'):
            if code.startswith('.macro'):
                in_macro = True
            elif code.startswith('.endm'):
                in_macro = False
            continue
        if in_macro:
            continue
        items.append(('ins', Insn(code, lineno), lineno, code))
    return items


def label_index(items):
    """name -> item index, with numeric labels resolved per b 1f / b 1b rules
    (the target is the NEXT/PREVIOUS definition of that number)."""
    named = {}
    numeric = {}
    for i, it in enumerate(items):
        if it[0] == 'label':
            named.setdefault(it[1], i)
        elif it[0] == 'numlabel':
            numeric.setdefault(it[1], []).append(i)
    return named, numeric


def resolve(items, named, numeric, tgt, here):
    t = tgt.strip()
    if t in named:
        return named[t]
    m = re.match(r'^(\d+)([fb])$', t)
    if m:
        cand = numeric.get(m.group(1), [])
        if m.group(2) == 'f':
            for i in cand:
                if i >= here:
                    return i
        else:
            for i in reversed(cand):
                if i <= here:
                    return i
    return None


def store_writes(ins, syms=None):
    """(writes, base, imm, writeback, post) for a store whose memory operand has
    a modelled base (sp or x29) and a statically-known immediate; [] when any of
    that is unknown.  `writes` entries are (reg_or_None, offset_WITHIN_the_
    addressed_bytes, size) -- the operand's own immediate stays OUT of them, so
    the caller adds it exactly once (the prologue's `[sp,#-16]!` is a store at
    sp-16 whose sp is THEN moved to sp-16; adding the -16 twice is how a first
    implementation reports every frame as half its real size)."""
    ops = ins.ops
    if not ops:
        return []
    mem_i = next((i for i, o in enumerate(ops) if '[' in o), None)
    if mem_i is None:
        return []
    mo = mem_operand(ops[mem_i], syms)
    if mo is None:
        return []
    base, off, _wb = mo
    # post-index `... , [sp], #16`: the offset rides OUTSIDE the brackets and
    # applies to sp AFTER the access, so the address is plain sp.
    ins_post = 0
    if mem_i + 1 < len(ops) and re.match(r'^#?-?\d', ops[mem_i + 1] or ''):
        try:
            ins_post = int(ops[mem_i + 1].lstrip('#').replace(' ', ''), 0)
            off = 0
        except ValueError:
            return []
    op = ins.op
    srcs = ops[:mem_i]
    out = []
    if op in STORE_PAIR:
        if len(srcs) < 2:
            return []
        r1, s1 = reg_operand(srcs[0])
        r2, s2 = reg_operand(srcs[1])
        if s1 is None or s2 is None:
            return []
        out.append((r1, 0, s1))
        out.append((r2, s1, s2))
    elif op in STORE_SCALAR:
        if not srcs:
            return []
        r, sz = reg_operand(srcs[0])
        if sz is None:
            return []
        if STORE_SCALAR[op] is not None:
            sz = STORE_SCALAR[op]
        out.append((r, 0, sz))
    else:
        return []
    return out, base, off, bool(re.search(r'\]\s*!', ops[mem_i])), ins_post


def plain_reg(tok):
    """Canonical xN for ANY general register token (wN -> xN, since a w-write
    clobbers the whole register).  norm_reg() is the callee-saved-only one the
    other checks use; sp-adjuster registers are usually caller-saved (x9, x14,
    x26), so constant tracking needs a normalizer that does not filter."""
    t = tok.strip().lower()
    m = re.match(r'^([xw])([0-9]+)$', t)
    if not m:
        return None
    n = int(m.group(2))
    return None if n > 30 else 'x%d' % n


def _imm_value(tok, syms):
    t = tok.strip().lstrip('#').replace(' ', '')
    if not t:
        return None
    try:
        return int(t, 0)
    except ValueError:
        return eval_expr(t, syms or {})


def _lsl_value(ops_tail):
    """`lsl #16` in the tail of a movz/movk -> 16; absent -> 0; odd shape -> None."""
    joined = ' '.join(o.strip().lower() for o in ops_tail)
    if not joined:
        return 0
    m = re.search(r'lsl\s+#\s*(0x[0-9a-f]+|\d+)', joined)
    if m:
        try:
            return int(m.group(1), 0)
        except ValueError:
            return None
    return 0 if 'asr' not in joined and 'lsl' not in joined else None


def _track_consts(op, ops, writes, consts, sp_regs, syms):
    """Follow a literal into the registers that move sp, and forget it the
    moment anything else touches them.  Nothing is ever assumed: an
    instruction that could compute a value is a forgetting event, not a
    chance to guess one."""
    out = dict(consts)
    if not out and not sp_regs:
        return out
    if op in ('bl', 'blr'):
        for k in [k for k in out if int(k[1:]) < 18]:
            out.pop(k)                     # caller-saved: a call may clobber it
        return out
    dst = plain_reg(ops[0]) if ops else None
    if dst not in sp_regs:
        return out
    if op in ('mov', 'movz') and len(ops) >= 2:
        src = ops[1].strip()
        shift = _lsl_value(ops[2:])
        val = _imm_value(src, syms) if src.startswith('#') else None
        if val is None and op == 'mov':
            src_reg = plain_reg(src)
            val = out.get(src_reg) if src_reg else None   # `mov xN, xM`
            shift = 0
        if val is None or shift is None:
            out.pop(dst, None)
        else:
            out[dst] = (val << shift) & ((1 << 64) - 1)   # movz zeroes the rest
        return out
    if op == 'movk' and len(ops) >= 2:
        shift = _lsl_value(ops[2:])
        val = _imm_value(ops[1], syms)
        if dst not in out or val is None or shift is None:
            out.pop(dst, None)             # partial knowledge is no knowledge
        else:
            # `1 << 16 - 1 << shift` is NOT ((1<<16)-1)<<shift: Python binds
            # '-' tighter than '<<'.  Build the 16-bit window explicitly.
            mask = ((1 << 16) - 1) << shift
            out[dst] = ((out[dst] & ~mask) | ((val & 0xffff) << shift)) \
                & ((1 << 64) - 1)
        return out
    out.pop(dst, None)
    return out


def walk_frame(items, named, numeric, syms=None, sp_macros=(),
               limit=20000):
    """-> (findings, modelled) where findings are (lineno, text, detail) and
    modelled is False if the frame could not be followed with certainty."""
    findings = []
    def give(why):
        return findings, False, why
    modelled = True
    # Which registers move sp dynamically (`sub sp, sp, xN`)?  Only those get
    # constants tracked, and only by the literal-materialisation idiom this
    # tree uses.  cons_verify is `mov x26,#0x0100 / movk x26,#0x0010,lsl #16 /
    # sub sp, sp, x26` -- a fixed 1 MiB + 256 frame wearing a register's
    # clothes; treating it as unknowable skipped the consensus entry point
    # entirely, which is precisely where a frame overlap would be worst.
    sp_regs = set()
    for it in items:
        if it[0] == 'ins' and it[1].op in ('add', 'sub') and len(it[1].ops) == 3 \
                and it[1].ops[0].strip().lower() == 'sp' \
                and it[1].ops[1].strip().lower() == 'sp':
            r = plain_reg(it[1].ops[2])
            if r:
                sp_regs.add(r)
    start = None
    for i, it in enumerate(items):
        if it[0] in ('label', 'numlabel'):
            continue
        start = i
        break
    if start is None:
        return [], True, None
    # state = (spdelta, fpdelta, live-slots, known-constants)
    seen = set()
    work = [(start, 0, None, (), ())]
    budget = limit
    while work:
        budget -= 1
        if budget <= 0:
            return give('walk budget exhausted (function too large to follow)')
        idx, spd, fpd, live, consts_t = work.pop()
        consts = dict(consts_t)
        key = (idx, spd, fpd, live, consts_t)
        if key in seen:
            continue
        seen.add(key)
        while idx < len(items):
            it = items[idx]
            if it[0] != 'ins':
                idx += 1
                continue
            ins, lineno, text = it[1], it[2], it[3]
            op = ins.op
            ops = ins.ops
            if op in sp_macros:
                return give('calls the sp-moving macro %s' % op)
            if sp_regs:
                consts = _track_consts(op, ops, ins.writes, consts, sp_regs, syms)
                consts_t = frozenset(consts.items())
                key2 = (idx, spd, fpd, live, consts_t)
                if key2 in seen:
                    break
                seen.add(key2)
            # ---- frame-pointer anchor ------------------------------------
            if op == 'mov' and len(ops) == 2 and \
                    ops[0].strip().lower() in ('x29', 'fp') and \
                    ops[1].strip().lower() == 'sp':
                fpd = spd
                idx += 1
                continue
            # ---- explicit sp moves ---------------------------------------
            if op in ('add', 'sub') and ops and ops[0].strip().lower() == 'sp':
                if len(ops) == 3 and ops[1].strip().lower() == 'sp':
                    raw = ops[2].lstrip('#').replace(' ', '')
                    imm = None
                    try:
                        imm = int(raw, 0)
                    except ValueError:
                        imm = eval_expr(raw, syms or {})   # `sub sp, sp, #FRAME`
                    if imm is None:
                        imm = consts.get(plain_reg(ops[2]) or '')
                    if imm is None:
                        return give('dynamic frame: add/sub sp, sp, <register>')
                    spd = spd + imm if op == 'add' else spd - imm
                    live = tuple(e for e in live if e[1] >= spd)
                    idx += 1
                    continue
                return give('unrecognised sp arithmetic')
            if op == 'mov' and len(ops) == 2 and ops[0].strip().lower() == 'sp':
                src = ops[1].strip().lower()
                if src in ('x29', 'fp') and fpd is not None:
                    spd = fpd
                    live = tuple(e for e in live if e[1] >= spd)
                    idx += 1
                    continue
                return give('mov sp, <register>: frame set outside the model')
            # ---- stores: alias test, then the save it performs -----------
            if op in STORE_OPS:
                sw = store_writes(ins, syms)
                if sw:
                    writes, base, off, wb, post = sw
                    if base == 'x29':
                        if fpd is None:
                            idx += 1
                            continue      # no frame anchor yet: address unknown
                        anchor = fpd + off        # fixed, however far sp has moved
                    else:
                        anchor = spd + off        # pre-index writes at sp+off too
                    for reg, within, sz in writes:
                        lo = anchor + within
                        for sreg, soff, ssz in live:
                            if lo < soff + ssz and soff < lo + sz:
                                if sreg == reg and soff == lo and ssz == sz:
                                    continue            # the register's own slot
                                findings.append((lineno, text.strip(),
                                    '%d-byte store at entry_sp%+d overwrites '
                                    'saved %s (at entry_sp%+d, live here)'
                                    % (sz, lo, sreg, soff)))
                    for reg, within, sz in writes:
                        if reg is None or reg == 'xzr':
                            continue
                        if reg not in CALLEE_SAVED_SET:
                            continue      # a scratch spill is not a save slot
                        # Only the FIRST save of a register is its save slot.
                        # Replacing it (the first draft did) makes the check
                        # both noisy and blind: fd_write_all writes x19 into a
                        # pollfd struct on the stack, and re-tracking x19 there
                        # reported the following `strh w1,[sp,#4]` (the struct's
                        # events field) as clobbering x19 -- while the real save
                        # slot, 48 bytes higher, disappeared from the model.
                        if any(e[0] == reg for e in live):
                            continue
                        live = live + ((reg, anchor + within, sz),)
                    if wb:
                        spd = spd + off
                    elif post:
                        spd = spd + post
                    if wb or post:
                        live = tuple(e for e in live if e[1] >= spd)
                    idx += 1
                    continue
                # unmodelled store shape: it cannot alias by construction
                # (no static address), but a writeback we did not see could
                # move sp, so refuse rather than guess.
                if any(re.search(r'\]\s*!', o) for o in ops):
                    return give('store writeback at an unmodelled address')
                idx += 1
                continue
            # ---- loads: restore drops the slot, writeback moves sp -------
            if op in LOAD_OPS:
                mem_i = next((i for i, o in enumerate(ops) if '[' in o), None)
                if mem_i is not None:
                    mo = mem_operand(ops[mem_i], syms)
                    post = 0
                    if mo is not None and mem_i + 1 < len(ops) and \
                            re.match(r'^#?-?\d', ops[mem_i + 1] or ''):
                        try:
                            post = int(ops[mem_i + 1].lstrip('#').replace(' ', ''), 0)
                        except ValueError:
                            return give('post-index offset is not a literal')
                    # A load from an UNMODELLED address ([x1,#8]) is not
                    # necessarily a restore, so it does not get to retire a
                    # slot -- dropping one there would hide a real alias.
                    if mo is not None:
                        regs = [norm_reg(o) for o in ops[:2]] if op in (
                            'ldp', 'ldnp') else [norm_reg(ops[0])] if ops else []
                        for r in regs:
                            if r:
                                live = tuple(e for e in live if e[0] != r)
                        if mo[2]:
                            spd = spd + mo[1]
                            live = tuple(e for e in live if e[1] >= spd)
                        elif post:
                            spd = spd + post
                            live = tuple(e for e in live if e[1] >= spd)
                    elif any(re.search(r'\]\s*!', o) for o in ops):
                        return give('load writeback at an unmodelled address')
                idx += 1
                continue
            # ---- control flow --------------------------------------------
            if op == 'ret':
                break
            if op == 'bl':
                idx += 1
                continue
            if op in ('b', 'br') or op.startswith('b.'):
                tgt = resolve(items, named, numeric, ops[0] if ops else '', idx)
                if tgt is None:
                    if op == 'br':
                        return give('computed branch (br <reg>)')
                    break                             # tail call out of the file
                work.append((tgt, spd, fpd, live, consts_t))
                if op != 'b' and op != 'br':
                    work.append((idx + 1, spd, fpd, live, consts_t))
                break
            if op in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                tgt = resolve(items, named, numeric,
                              ops[-1] if ops else '', idx)
                if tgt is None:
                    return give('branch target is not a label in this function')
                work.append((tgt, spd, fpd, live, consts_t))
                work.append((idx + 1, spd, fpd, live, consts_t))
                break
            idx += 1
    return findings, True, None


def audit_alias(path):
    """-> (findings, modelled_n, unmodelled) -- findings are
    (func, lineno, text, detail), unmodelled are (func, why)."""
    findings, modelled_n, unmodelled = [], 0, []
    syms = file_symbols(path)
    sp_macros = {k for k, moves in file_macros(path).items() if moves}
    for name, body in extract_functions(path):
        items = parse_items(body)
        named, numeric = label_index(items)
        f, ok, why = walk_frame(items, named, numeric, syms, sp_macros=sp_macros)
        if ok:
            modelled_n += 1
        else:
            unmodelled.append((name, why))
        for lineno, text, detail in f:
            findings.append((name, lineno, text, detail))
    return findings, modelled_n, unmodelled


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


SELFTEST = [
    # (file, function, expected aliases in that function)
    ('good.S', 'good_fn', 0),          # the correct prologue + scratch + reload
    ('good.S', 'good_scratch', 0),     # frame reserved with `sub sp`, saves at top
    ('bad.S', 'bad_tab', 1),           # scratch store onto x20's save slot
    ('bad.S', 'bad_frame', 1),         # same, in the `sub sp` convention
]


def selftest():
    """Prove the alias check still fires.

    Two of this project's 2026-09-03 incidents were test tools that reported
    success while comparing nothing (a dead oracle protocol, a link-check that
    gated the suite into running no tests).  A frame auditor is the same shape
    of risk: one regex regression and it reports a clean tree forever.  So the
    planted bugs live in the repo, and this says what must be found.
    """
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     'testdata', 'abi_alias_a64')
    if not os.path.isdir(d):
        print('selftest: missing %s' % d, file=sys.stderr)
        return 1
    bad = 0
    for fname in sorted(os.listdir(d)):
        if not fname.endswith('.S'):
            continue
        findings, modelled, unmodelled = audit_alias(os.path.join(d, fname))
        by_func = {}
        for f, ln, text, detail in findings:
            by_func[f] = by_func.get(f, 0) + 1
        for f, why in unmodelled:
            print('selftest: %s:%s frame not followed (%s)' % (fname, f, why),
                  file=sys.stderr)
            bad += 1
        for want_file, func, expected in SELFTEST:
            if fname != want_file:
                continue
            # (the first draft unpacked this in the wrong order, so `fname !=
            # want_file` was true for every row, every row was skipped, and the
            # selftest printed 'ok' having compared nothing -- the exact failure
            # mode it exists to catch, reproduced internally on first try.)
            got = by_func.get(func, 0)
            ok = (got == expected)
            if not ok:
                bad += 1
            print('selftest %-9s %-14s expected %d alias(es), found %d  %s'
                  % (fname, func, expected, got, 'ok' if ok else 'FAIL'))
    if bad:
        print('selftest FAILED: the alias check is not seeing what it must',
              file=sys.stderr)
        return 1
    print('selftest ok: planted save-area aliases found, clean frames clean')
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--asmdir', default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'port', 'arm64'))
    ap.add_argument('--format', choices=['table', 'summary'], default='table')
    ap.add_argument('--check', action='store_true',
                    help='exit 1 on any UNSAVED-CLOBBER or SAVE-AREA-ALIAS')
    ap.add_argument('--no-alias', action='store_true',
                    help='skip the frame walk (fast, but the alias check is the '
                         'point of it)')
    ap.add_argument('--list-unmodelled', action='store_true',
                    help='name the functions whose frame was not followed')
    ap.add_argument('--selftest', action='store_true',
                    help='run the check against scripts/testdata/abi_alias_a64 '
                         'and fail if the planted aliases stop being found')
    ap.add_argument('files', nargs='*')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    files = args.files or sorted(
        os.path.join(args.asmdir, f)
        for f in os.listdir(args.asmdir) if f.endswith('.S'))
    total_offenders = 0
    total_alias = 0
    total_modelled = 0
    total_unmodelled = 0
    unmodelled_files = 0
    for path in files:
        offenders, callers_of, exposed = audit_file(path)
        alias, modelled_n, unmodelled = ([], 0, []) if args.no_alias \
            else audit_alias(path)
        real = [(f, r, why, ln) for f, r, why, ln in offenders
                if why == 'no-save' or why == 'no-restore']
        total_offenders += len(real)
        total_alias += len(alias)
        total_modelled += modelled_n
        total_unmodelled += len(unmodelled)
        if unmodelled:
            unmodelled_files += 1
        if args.list_unmodelled:
            for n, why in unmodelled:
                print(f'UNMODELLED        {os.path.basename(path)}: {n}'
                      f'  ({why})')
        if args.format == 'summary':
            print(f'{os.path.basename(path)}: {len(real)} unsaved-clobber, '
                  f'{len(alias)} save-area-alias, '
                  f'{len(exposed)} exposed-frame shapes '
                  f'({modelled_n} frames followed, {len(unmodelled)} not)')
            continue
        for f, r, why, ln in real:
            print(f'UNSAVED-CLOBBER {os.path.basename(path)}:{ln}: '
                  f'{f} writes {r} ({why})')
        for f, ln, text, detail in alias:
            print(f'SAVE-AREA-ALIAS   {os.path.basename(path)}:{ln}: '
                  f'{f}: {detail}  |  {text[:70]}')
        for f, tgt in sorted(set(callers_of)):
            print(f'CALLS-OFFENDER  {os.path.basename(path)}: {f} -> {tgt}')
        for f, ln, text in exposed:
            print(f'SAVE-AREA-EXPOSED {os.path.basename(path)}:{ln}: '
                  f'{f}: {text[:90]}')
    print(f'# frame model followed: {total_modelled} function(s); '
          f'{total_unmodelled} not modelled (dynamic sp, an unknown sp move, or '
          f'a computed branch) in {unmodelled_files} file(s) -- those are NOT '
          f'checked for aliasing; --list-unmodelled names them with the reason')
    if args.check and (total_offenders or total_alias):
        print(f'--check: {total_offenders} UNSAVED-CLOBBER and '
              f'{total_alias} SAVE-AREA-ALIAS violation(s)', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
