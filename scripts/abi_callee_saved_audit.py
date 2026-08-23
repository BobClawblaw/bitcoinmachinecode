#!/usr/bin/env python3
"""
abi_callee_saved_audit.py -- SysV AMD64 *callee-saved register preservation*
auditor for this tree's NASM sources.  Static companion to
tests/bench_abi_audit, which measures the same property dynamically.

100% AI-authored, like the assembly it audits.

WHY THIS EXISTS
---------------
scripts/abi_stack_audit.py (incident #20) audits RSP *alignment* at call sites.
That is a different property from register *preservation*, and `make abi-check`
passed cleanly on a build in which six functions -- including `script_eval`, the
consensus-path script interpreter entered for every input of every transaction
-- returned with the caller's rbx/r12/r13/r14/r15 holding interpreter state.

Every one of them was the same mistake:

    push rbp
    mov  rbp, rsp
    push rbx / r12 / r13 / r14 / r15      <-- save area at rbp-0x08 .. rbp-0x28
    sub  rsp, N
    ...
    lea  rdi, [rbp-0x30]                  <-- a 32-byte buffer that GROWS UP
    call sha256_full                      <-- ... straight through the save area

The save area sat *between* rbp and the locals, so a buffer addressed from the
low end wrote over it and the epilogue's `pop`s handed the caller digest bytes.
The fix in every case was to move the pushes above `push rbp`, so the save area
lives at [rbp+8 ...] and every [rbp-N] local is inside the function's own
reservation.

Nothing had broken in production only because every C file on the consensus
path is pinned to -O0 (asm/Makefile), and -O0 keeps nothing live in a
callee-saved register across a call.  That is accidental protection.  This tool
exists so the protection is no longer accidental.

WHAT IT REPORTS
---------------
Three checks, in decreasing order of certainty:

  UNSAVED-CLOBBER   (sound, gated in CI)
      A callee-saved register is written on a path from entry to `ret` and is
      not restored from its own save slot before that `ret`.  Propagated
      transitively through the assembly call graph, so a function that merely
      *calls* an offender is reported too (this is how `cons_verify` inherits
      `pow_check`'s destroyed r13).  Calls that leave assembly contribute
      nothing: C and libc obey the ABI.

  SAVE-AREA-ALIAS   (sound, gated in CI)
      A direct memory write of statically-known size and address overlaps a
      save slot that is live at that instruction.

  SAVE-AREA-EXPOSED (a shape, NOT a proof -- reported, not gated)
      A frame address at [rbp-N] escapes (via `lea` into a register, or an
      indexed write) while a live save slot sits at a HIGHER address than N.
      Any buffer written through that address grows toward the save area.
      Whether it reaches depends on the buffer's length, which is not knowable
      here -- so this is the risk list, not the failure list.  Every one of the
      six real bugs is in it; so are correct functions whose buffers happen to
      be short enough.  The clean shape (pushes above `push rbp`) makes the
      finding structurally impossible rather than merely currently-harmless,
      which is why the fixes took that form.

Usage:
  scripts/abi_callee_saved_audit.py [--asmdir asm] [--format table|summary|exposed]
  scripts/abi_callee_saved_audit.py --check      # CI mode: exit 1 on a sound violation
"""

import argparse
import os
import re
import sys
from collections import defaultdict, OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from abi_stack_audit import (          # noqa: E402
    AsmFile, Program, resolve_target, JCC, TERMINATORS)


# ---------------------------------------------------------------------------
# Register naming
# ---------------------------------------------------------------------------

CALLEE_SAVED = ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15')

_SUB = {}
for _full, _names in (
        ('rbx', ('rbx', 'ebx', 'bx', 'bl', 'bh')),
        ('rbp', ('rbp', 'ebp', 'bp', 'bpl')),
        ('r12', ('r12', 'r12d', 'r12w', 'r12b')),
        ('r13', ('r13', 'r13d', 'r13w', 'r13b')),
        ('r14', ('r14', 'r14d', 'r14w', 'r14b')),
        ('r15', ('r15', 'r15d', 'r15w', 'r15b'))):
    for _n in _names:
        _SUB[_n] = _full

REG_WIDTH = {}
for _w, _rs in ((8, 'rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'),
                (4, 'eax ebx ecx edx esi edi ebp esp r8d r9d r10d r11d r12d r13d r14d r15d'),
                (2, 'ax bx cx dx si di bp sp r8w r9w r10w r11w r12w r13w r14w r15w'),
                (1, 'al bl cl dl ah bh ch dh sil dil bpl spl r8b r9b r10b r11b r12b r13b r14b r15b')):
    for _r in _rs.split():
        REG_WIDTH[_r] = _w

SIZE_KW = {'byte': 1, 'word': 2, 'dword': 4, 'qword': 8, 'tword': 10,
           'oword': 16, 'xmmword': 16, 'yword': 32}

# ops[0] is read-only for these, so a bare callee-saved register there is not
# a write.  (`push` is separate; `bt` reads, `bts`/`btr`/`btc` write.)
NO_WRITE_DST = {
    'cmp', 'test', 'push', 'jmp', 'call', 'ret', 'retn', 'bt', 'prefetch',
    'prefetcht0', 'prefetcht1', 'prefetcht2', 'prefetchnta', 'nop', 'ud2',
    'cmpsb', 'cmpsw', 'cmpsd', 'cmpsq', 'int3', 'hlt', 'lfence', 'sfence',
    'mfence', 'pause', 'clflush',
} | JCC

# These write ops[1] (or a second destination) as well.
TWO_DST = {'xchg', 'cmpxchg', 'xadd'}


def norm(tok):
    """A bare register token -> its 64-bit name, else None."""
    t = tok.strip().lower()
    if not re.match(r'^[a-z][a-z0-9]*$', t):
        return None
    return _SUB.get(t)


def is_mem(op):
    return '[' in op


# ---------------------------------------------------------------------------
# Memory-operand decoding
# ---------------------------------------------------------------------------

MEM_RE = re.compile(r'\[([^\]]*)\]')


def operand_size(af, ins, which):
    """Byte width of a memory operand, or None if not determinable."""
    for op in ins.ops:
        for kw, sz in SIZE_KW.items():
            if re.match(r'^\s*%s\b' % kw, op, re.I):
                return sz
    for i, op in enumerate(ins.ops):
        if i == which or is_mem(op):
            continue
        w = REG_WIDTH.get(op.strip().lower())
        if w:
            return w
        if re.match(r'^(x|y)mm\d+$', op.strip().lower()):
            return 16 if op.strip().lower().startswith('x') else 32
    # movs/stos etc, or an immediate-only store: unknown.
    return None


def decode_frame_addr(af, expr, rsp_off, rbp_off):
    """Decode `[rbp-0x30]` / `[rsp+8]` / `[rbp-0x90 + rdx*4]`.

    Returns (base_off, indexed) where base_off is a byte offset relative to the
    function's entry RSP, or None if the address is not frame-relative or not
    statically known.  `indexed` means a variable index is present, so the
    access extends an unknown distance ABOVE base_off.
    """
    m = MEM_RE.search(expr)
    if not m:
        return None
    inner = m.group(1)
    body = re.sub(r'\b(byte|word|dword|qword|tword|oword|xmmword|yword)\b', '',
                  inner, flags=re.I).strip()
    mb = re.match(r'^\s*(rbp|rsp)\s*(.*)$', body, re.I)
    if not mb:
        return None
    base = mb.group(1).lower()
    rest = mb.group(2).strip()
    base_off = rbp_off if base == 'rbp' else rsp_off
    if base_off is None:
        return None

    # Strip ONLY genuine index-register terms.  Anything else that looks like an
    # identifier is a NASM %define or `equ` constant -- schnorr_verify's frame
    # is entirely built from them ([rbp+KEYSCR], KEYSCR == -0x372) -- and must
    # be handed to eval_imm, not discarded. Discarding it silently turned every
    # such reference into "displacement 0" and produced a wall of phantom
    # "overwrites saved rbp" findings.
    indexed = False
    def _drop(m):
        nonlocal indexed
        if m.group(2).lower() in REG_WIDTH:
            indexed = True
            return ''
        return m.group(0)
    disp_src = re.sub(r'([+\-]?)\s*\b([A-Za-z_][A-Za-z0-9_]*)\b\s*(\*\s*\d+)?',
                      _drop, rest)
    disp = 0
    if disp_src.strip():
        s = disp_src.strip()
        v = af.eval_imm(s if s[0] in '+-' else '+' + s)
        if v is None:
            return None
        disp = v
    return (base_off + disp, indexed)


# ---------------------------------------------------------------------------
# Per-function abstract interpretation
# ---------------------------------------------------------------------------

def at_risk(save_off, buf_off, rbp_off):
    """Can a buffer based at `buf_off` and growing upward reach this save slot
    without first running off the top of the local region?

    Only slots BELOW the frame pointer qualify.  When the pushes are above
    `push rbp` -- the shape every fix in this commit adopts -- the save area is
    at [rbp+8 ...], so reaching it means overrunning the entire reservation and
    the saved rbp as well, which is a frame overflow rather than the aliasing
    this check is about.  Without this condition the check fires on the FIXED
    layout too, since the save slots are still at higher addresses than the
    locals.
    """
    if save_off < buf_off:
        return False
    top = rbp_off if rbp_off is not None else 0
    return save_off < top


class Finding(object):
    gap = None            # SAVE-AREA-EXPOSED: bytes of slack before the save area

    def __init__(self, kind, file, func, line, detail):
        self.kind = kind
        self.file = file
        self.func = func
        self.line = line
        self.detail = detail

    def __repr__(self):
        return '%s %s:%d %s %s' % (self.kind, self.file, self.line,
                                   self.func, self.detail)


# ---------------------------------------------------------------------------
# Known-good exceptions
# ---------------------------------------------------------------------------
#
# Four internal labels in this tree are *deliberately* entered mid-frame and
# share their parent's save area.  The analysis starts at the label with an
# empty stack, so the epilogue's pops have nothing to pair with and every
# register looks unrestored.  Each is a documented convention, not a defect:
#
#   siphash24_uint256.sipround / .sipround2 -- the SipHash rounds operate on
#       v0..v3 held in the PARENT's rbx/r12/r13/r14 by design; siphash24_uint256
#       itself saves and restores all four.  (This pair is also the one
#       COMPENSATED alignment site in docs/ABI_STACK_ALIGNMENT.md.)
#   fe_mul.reduce -- fe_sqr does `jmp fe_mul.reduce` after pushing the same
#       registers in the same order that .reduce's epilogue pops
#       (secp256k1_fe.asm has the entry contract written out above the label).
#   point_add_mixed.body -- point_add_mixed_zr `jmp`s into it after building an
#       identical frame.
#
# Anything else appearing here is a real finding.
KNOWN_SHARED_FRAME = {
    ('bitcoin_cmpct.asm', 'siphash24_uint256.sipround'),
    ('bitcoin_cmpct.asm', 'siphash24_uint256.sipround2'),
    ('secp256k1_fe.asm', 'fe_mul.reduce'),
    ('secp256k1_point.asm', 'point_add_mixed.body'),
}


def release(stack, new_rsp):
    """RSP has been set directly to `new_rsp` (via `mov rsp,rbp`,
    `lea rsp,[rbp-N]`, `leave` or `add rsp,N`).  Everything below that address
    is freed.  Entries are bottom-first, so their offsets decrease; keep the
    prefix that is still at or above the new RSP."""
    if new_rsp is None:
        return ()
    out = []
    for e in stack:
        off = e[2]
        if off is None or off < new_rsp:
            break
        out.append(e)
    return tuple(out)


class FuncResult(object):
    def __init__(self):
        self.own_clobber = set()   # callee-saved regs lost by this body alone
        self.calls = set()         # in-tree asm targets (file, label)
        self.leaves_asm = False    # calls C / libc / indirect
        self.findings = []
        self.unknown = False       # analysis gave up somewhere


def analyse(af, entry, prog, limit=400000):
    """Walk the CFG of `entry` in `af`, tracking RSP/RBP offsets relative to
    entry RSP, the live callee-saved save slots, and which callee-saved
    registers currently hold something other than the caller's value."""
    start = af.labels.get(entry)
    res = FuncResult()
    if start is None:
        return res
    # state = (rsp, rbp, stack, rbp_depth, clob)
    #   rsp/rbp:   byte offset from entry RSP (entry RSP == 0), or None
    #   stack:     LIFO tuple of entries, bottom first.  ('r', reg, off) for a
    #              register push, ('p', nbytes) for a `sub rsp` reservation,
    #              ('p', None) for an unknown-size adjustment (`and rsp,-16`).
    #              Pairing pushes with pops through the LIFO -- rather than by
    #              absolute offset -- is what lets this analyse the
    #              `and rsp,-16` self-aligning functions (schnorr_verify,
    #              taproot_tweak_pubkey, tagged_hash256, ecdsa_verify), whose
    #              RSP offset is unknowable but whose push/pop bracket is
    #              perfectly well formed.
    #   rbp_depth: len(stack) when `mov rbp,rsp` ran, so `mov rsp,rbp`/`leave`
    #              can truncate back to it.
    #   clob:      frozenset of callee-saved regs holding a non-entry value
    init = (0, None, (), None, frozenset())
    work = [(start, init)]
    seen = set()
    steps = 0
    seen_lines = set()

    def add(kind, ins, detail, gap=None):
        key = (kind, ins.line, detail)
        if key in seen_lines:
            return
        seen_lines.add(key)
        f = Finding(kind, af.name, entry, ins.line, detail)
        f.gap = gap
        res.findings.append(f)

    while work:
        steps += 1
        if steps > limit:
            res.unknown = True
            break
        idx, st = work.pop()
        if idx >= len(af.insns):
            continue
        key = (idx, st)
        if key in seen:
            continue
        seen.add(key)
        ins = af.insns[idx]
        m = ins.mnem
        rsp, rbp, stack, rbp_depth, clob = st
        saves = frozenset((e[1], e[2]) for e in stack
                          if e[0] == 'r' and e[1] and e[2] is not None)

        # ---- terminators ------------------------------------------------
        if m in ('ret', 'retn', 'retf'):
            if clob:
                add('UNSAVED-CLOBBER', ins,
                    'returns with %s not restored' % ' '.join(sorted(clob)))
                res.own_clobber |= set(clob)
            continue
        if m in TERMINATORS:
            continue

        # ---- calls ------------------------------------------------------
        if m == 'call':
            tgt = resolve_target(af, ins, ins.ops[0]) if ins.ops else '?'
            r = prog.resolve(af, tgt)
            if r is None:
                res.leaves_asm = True
            else:
                res.calls.add((r[0].name, r[1]))
            work.append((idx + 1, st))
            continue

        if m == 'jmp':
            tgt = resolve_target(af, ins, ins.ops[0]) if ins.ops else '?'
            if tgt in af.labels:
                work.append((af.labels[tgt], st))
            else:
                # tail call: the callee returns for us, so anything we still
                # owe the caller is owed at that point too.
                if clob:
                    add('UNSAVED-CLOBBER', ins,
                        'tail-jumps to %s with %s not restored'
                        % (tgt, ' '.join(sorted(clob))))
                    res.own_clobber |= set(clob)
                r = prog.resolve(af, tgt)
                if r is None:
                    res.leaves_asm = True
                else:
                    res.calls.add((r[0].name, r[1]))
            continue

        if m in JCC:
            tgt = resolve_target(af, ins, ins.ops[0]) if ins.ops else '?'
            if tgt in af.labels:
                work.append((af.labels[tgt], st))
            work.append((idx + 1, st))
            continue

        # ---- memory writes and escaping frame addresses -----------------
        if ins.ops:
            dst = ins.ops[0]
            if is_mem(dst) and m not in NO_WRITE_DST:
                d = decode_frame_addr(af, dst, rsp, rbp)
                if d is not None and saves:
                    lo, indexed = d
                    sz = operand_size(af, ins, 0)
                    if indexed or sz is None:
                        above = [(o, r) for (r, o) in saves if at_risk(o, lo, rbp)]
                        if above:
                            gap = min(o for o, _ in above) - lo
                            add('SAVE-AREA-EXPOSED', ins,
                                'indexed/unsized store based at entry_rsp%+d; '
                                'nearest saved reg (%s) is %d bytes above'
                                % (lo, min(above)[1], gap), gap)
                    else:
                        hit = sorted(r for (r, o) in saves
                                     if o < lo + sz and lo < o + 8)
                        if hit:
                            add('SAVE-AREA-ALIAS', ins,
                                '%d-byte store at entry_rsp%+d overwrites '
                                'saved %s' % (sz, lo, ' '.join(hit)))
            if m == 'lea' and len(ins.ops) > 1 and saves and \
                    ins.ops[0].strip().lower() != 'rsp':
                # `lea rsp,[rbp-0x28]` is a stack-pointer restore, not a buffer
                # address -- excluded, or every self-aligning function
                # (ecdsa_verify, point_scalar_mul_glv) reports 0 bytes of
                # headroom against the save slot it is deliberately landing on.
                d = decode_frame_addr(af, ins.ops[1], rsp, rbp)
                if d is not None:
                    lo, _ = d
                    above = [(o, r) for (r, o) in saves if at_risk(o, lo, rbp)]
                    if above:
                        gap = min(o for o, _ in above) - lo
                        add('SAVE-AREA-EXPOSED', ins,
                            'frame address entry_rsp%+d escapes into %s; '
                            'nearest saved reg (%s) is %d bytes above -- a '
                            'buffer longer than that grows into the save area'
                            % (lo, ins.ops[0].strip(), min(above)[1], gap), gap)

        # ---- state transfer ---------------------------------------------
        nrsp, nrbp, nstack, ndepth, nclob = rsp, rbp, stack, rbp_depth, clob

        if m == 'push':
            nrsp = None if rsp is None else rsp - 8
            r = norm(ins.ops[0]) if ins.ops else None
            nstack = stack + (('r', r if (r and r not in clob) else None,
                               nrsp),)
        elif m in ('pushfq', 'pushf'):
            nrsp = None if rsp is None else rsp - 8
            nstack = stack + (('r', None, nrsp),)
        elif m in ('popfq', 'popf'):
            nrsp = None if rsp is None else rsp + 8
            nstack = stack[:-1] if stack else stack
        elif m == 'pop':
            r = norm(ins.ops[0]) if ins.ops else None
            top = stack[-1] if stack else None
            nstack = stack[:-1] if stack else stack
            if r:
                if top is not None and top[0] == 'r' and top[1] == r:
                    nclob = clob - {r}          # restored from its own slot
                else:
                    nclob = clob | {r}          # popped something else
                if r == 'rbp':
                    nrbp = None
                    ndepth = None
            nrsp = None if rsp is None else rsp + 8
        elif m == 'leave':
            nrsp = None if rbp is None else rbp + 8
            nstack = release(stack, rbp)
            top = nstack[-1] if nstack else None
            nstack = nstack[:-1] if nstack else nstack
            nclob = (clob - {'rbp'}) if (top and top[0] == 'r' and
                                         top[1] == 'rbp') else clob | {'rbp'}
            nrbp = None
            ndepth = None
        elif m in ('sub', 'add') and ins.ops and \
                ins.ops[0].strip().lower() == 'rsp':
            v = af.eval_imm(ins.ops[1]) if len(ins.ops) > 1 else None
            if v is None or rsp is None:
                nrsp = None
            else:
                nrsp = rsp - v if m == 'sub' else rsp + v
            if m == 'sub':
                nstack = stack + (('p', v, nrsp),)
            elif nrsp is not None:
                nstack = release(stack, nrsp)
            elif stack and stack[-1][0] == 'p' and stack[-1][1] == v:
                # RSP offset unknown (a self-aligning `and rsp,-16` above), but
                # this `add` releases exactly the reservation on top.
                nstack = stack[:-1]
            else:
                nstack = ()
        elif ins.ops and ins.ops[0].strip().lower() == 'rsp':
            if m == 'mov' and len(ins.ops) > 1 and \
                    ins.ops[1].strip().lower() == 'rbp':
                nrsp = rbp
                nstack = release(stack, rbp)
            elif m == 'lea' and len(ins.ops) > 1:
                # `lea rsp,[rbp-0x28]` -- the idiom the self-aligning functions
                # (ecdsa_verify, point_scalar_mul_glv) use to undo an
                # `and rsp,-16` and land exactly on top of their save area.
                d = decode_frame_addr(af, ins.ops[1], rsp, rbp)
                nrsp = d[0] if (d is not None and not d[1]) else None
                nstack = release(stack, nrsp)
            elif m == 'and':
                # self-aligning snap: the offset becomes unknowable, but the
                # push/pop bracket above it is still well formed.
                nrsp = None
                nstack = stack + (('p', None, None),)
            else:
                nrsp = None
                nstack = ()
        else:
            # generic register write
            if ins.ops and m not in NO_WRITE_DST:
                dsts = [ins.ops[0]]
                if m in TWO_DST and len(ins.ops) > 1:
                    dsts.append(ins.ops[1])
                for d0 in dsts:
                    r = norm(d0)
                    if not r:
                        continue
                    if r == 'rbp' and m in ('mov', 'lea') and len(ins.ops) > 1:
                        src = ins.ops[1].strip().lower()
                        if m == 'mov' and src == 'rsp':
                            nrbp = rsp
                            ndepth = len(stack)
                        elif m == 'lea':
                            dd = decode_frame_addr(af, ins.ops[1], rsp, rbp)
                            nrbp = dd[0] if (dd is not None and not dd[1]) else None
                            ndepth = None
                        else:
                            nrbp = None
                            ndepth = None
                    elif r == 'rbp':
                        nrbp = None
                        ndepth = None
                    nclob = nclob | {r}

        work.append((idx + 1, (nrsp, nrbp, nstack, ndepth, nclob)))

    return res


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def collect_entries(af):
    """Exported functions, plus internal labels that are genuine function
    entries: `call` targets, and cross-scope tail-`jmp` targets.

    Local `.labels` reached only by an intra-function `jmp` are LOOP LABELS.
    Analysing one as a function entry starts the walk in the middle of a frame,
    below the prologue, so every callee-saved register the body touches looks
    unsaved -- 458 phantom findings across 442 "functions" before this filter.
    """
    targets = set(af.globals) & set(af.labels)
    for ins in af.insns:
        if not ins.ops:
            continue
        if ins.mnem == 'call':
            t = resolve_target(af, ins, ins.ops[0])
            if t in af.labels:
                targets.add(t)
        elif ins.mnem == 'jmp':
            t = ins.ops[0].strip()
            if not t.startswith('.') and t != ins.scope and t in af.labels:
                targets.add(t)
    return sorted(targets)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--asmdir', default='asm')
    ap.add_argument('--format', default='table',
                    choices=('table', 'summary', 'exposed'))
    ap.add_argument('--check', action='store_true',
                    help='CI mode: exit 1 on any UNSAVED-CLOBBER or '
                         'SAVE-AREA-ALIAS (the two sound checks).  '
                         'SAVE-AREA-EXPOSED is a shape, not a proof, and never '
                         'fails the build.')
    ap.add_argument('--exported-only', action='store_true',
                    help='with --check, fail only on exported functions.  Not '
                         'needed today -- the tree is clean at zero with the '
                         'four KNOWN_SHARED_FRAME labels excluded -- but kept '
                         'as a narrower gate if a future internal convention '
                         'legitimately trips the analysis.')
    ap.add_argument('--no-allowlist', action='store_true',
                    help='report the KNOWN_SHARED_FRAME labels too (see the '
                         'comment on that set for why they are excluded).')
    ap.add_argument('--func', default=None)
    args = ap.parse_args()

    files = [AsmFile(os.path.join(args.asmdir, f))
             for f in sorted(os.listdir(args.asmdir)) if f.endswith('.asm')]
    prog = Program(files)

    results = OrderedDict()
    for af in files:
        for lab in collect_entries(af):
            results[(af.name, lab)] = analyse(af, lab, prog)

    # ---- transitive clobber over the assembly call graph -----------------
    inherited = defaultdict(set)
    changed = True
    rounds = 0
    while changed and rounds < 200:
        changed = False
        rounds += 1
        for key, r in results.items():
            total = set(r.own_clobber) | inherited[key]
            for c in r.calls:
                if c in results:
                    add = (results[c].own_clobber | inherited[c])
                    if not add.issubset(total):
                        total |= add
            # A register this function saves and restores on every path is
            # not inherited: own_clobber already reflects what survives to
            # the `ret`.  Anything a callee destroys and we do not re-save
            # does propagate.
            saved_here = _saved_regs(prog, key)
            total -= saved_here
            if total != inherited[key]:
                inherited[key] = total
                changed = True

    exported = {(af.name, g) for af in files for g in af.globals
                if g in af.labels}

    rows = []
    for key, r in results.items():
        if args.func and key[1] != args.func:
            continue
        if key in KNOWN_SHARED_FRAME and not args.no_allowlist:
            continue
        for f in r.findings:
            rows.append((key, f, key in exported))
        inh = inherited[key] - r.own_clobber
        if inh:
            rows.append((key,
                         Finding('INHERITED-CLOBBER', key[0], key[1], 0,
                                 'calls a function that destroys %s'
                                 % ' '.join(sorted(inh))),
                         key in exported))

    sound = [x for x in rows
             if x[1].kind in ('UNSAVED-CLOBBER', 'SAVE-AREA-ALIAS',
                              'INHERITED-CLOBBER')]
    shape = [x for x in rows if x[1].kind == 'SAVE-AREA-EXPOSED']

    if args.format == 'exposed':
        _dump(shape, 'SAVE-AREA-EXPOSED (risk shape, not a proof)')
    elif args.format == 'table':
        _dump(sound, 'SOUND VIOLATIONS')
        _risk_table(shape)

    n_exp_sound = len([x for x in sound if x[2]])
    print('\n---- summary ----')
    print('  functions analysed          %5d  (%d exported)'
          % (len(results), len(exported)))
    print('  UNSAVED/ALIAS/INHERITED     %5d  (%d in exported functions)'
          % (len(sound), n_exp_sound))
    print('  SAVE-AREA-EXPOSED (shape)   %5d  (%d exported)'
          % (len(shape), len([x for x in shape if x[2]])))

    if args.check:
        bad = [x for x in sound if x[2]] if args.exported_only else sound
        if bad:
            sys.stderr.write('\nCALLEE-SAVED CHECK FAILED: %d violation(s).\n'
                             % len(bad))
            for key, f, exp in bad[:60]:
                sys.stderr.write('  %s:%s  %s  %s -- %s\n'
                                 % (f.file, f.line or '-', f.func, f.kind,
                                    f.detail))
            return 1
        sys.stderr.write('CALLEE-SAVED CHECK OK: %d functions, no register '
                         'left unrestored at any `ret`.\n' % len(results))
    return 0


_SAVED_CACHE = {}


def _saved_regs(prog, key):
    """Callee-saved registers this function pushes in its own prologue."""
    if key in _SAVED_CACHE:
        return _SAVED_CACHE[key]
    af = prog.byname.get(key[0])
    out = set()
    if af is not None:
        i = af.labels.get(key[1])
        if i is not None:
            j = i
            while j < len(af.insns) and j < i + 12:
                ins = af.insns[j]
                if ins.mnem == 'push' and ins.ops:
                    r = norm(ins.ops[0])
                    if r:
                        out.add(r)
                elif ins.mnem in ('mov', 'sub', 'add', 'lea'):
                    pass
                else:
                    break
                j += 1
    _SAVED_CACHE[key] = out
    return out


def _risk_table(rows):
    """One line per function, ordered by how little slack it has.

    `headroom` is the distance from the lowest escaping frame address to the
    nearest live save slot above it: a buffer written through that address has
    to be longer than `headroom` bytes to corrupt the save area.  Small numbers
    are the ones worth reading; a function whose pushes are above `push rbp`
    never appears here at all, because it has no save slot below rbp to reach.
    """
    print('\n==== SAVE-AREA-EXPOSED (risk shape, not a proof) ====')
    if not rows:
        print('  (none -- no function places a callee-saved save slot above an '
              'escaping frame address)')
        return
    agg = {}
    for key, f, exp in rows:
        g = f.gap
        cur = agg.get(key)
        if cur is None or (g is not None and (cur[0] is None or g < cur[0])):
            agg[key] = (g, f.line, exp, len([1 for k, _, _ in rows if k == key]))
    print('  %-26s %-30s %-4s %9s %6s' %
          ('FILE', 'FUNCTION', 'EXP', 'HEADROOM', 'SITES'))
    for key in sorted(agg, key=lambda k: (agg[k][0] is None, agg[k][0])):
        g, line, exp, n = agg[key]
        print('  %-26s %-30s %-4s %9s %6d' %
              (key[0], key[1], 'yes' if exp else '-',
               ('%d B' % g) if g is not None else '?', n))


def _dump(rows, title):
    print('\n==== %s ====' % title)
    if not rows:
        print('  (none)')
        return
    cur = None
    for key, f, exp in sorted(rows, key=lambda x: (x[0][0], x[0][1], x[1].line)):
        if key != cur:
            cur = key
            print('\n  %s  %s%s' % (key[0], key[1],
                                    '  [exported]' if exp else ''))
        print('    L%-6s %-18s %s' % (f.line or '-', f.kind, f.detail))


if __name__ == '__main__':
    sys.exit(main())
