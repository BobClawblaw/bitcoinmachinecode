"""retarget.py -- move clang x86_64-linux IR onto the Windows COFF target
while keeping the SysV calling convention (bmc_win).

The bmc C code and musl are compiled for x86_64-linux-gnu (LP64, SysV, Linux
struct layouts -- bit-identical to the Linux build) to LLVM IR. This pass then
  * swaps the target triple to x86_64-pc-windows-msvc (COFF objects),
  * swaps the datalayout mangling component (m:e -> m:w),
  * pins every define / declare / call / invoke that has no explicit calling
    convention to x86_64_sysvcc, because on a Windows triple the default
    convention would silently become Win64.
Functions declared __attribute__((ms_abi)) (the winsys entry points) come out
of clang as win64cc and are left alone; so are intrinsics (@llvm.*).
"""
import re
import sys

_LINKAGE = (r'private|internal|available_externally|linkonce|weak|common|appending|'
            r'extern_weak|linkonce_odr|weak_odr|external')
_PREFIX = r'(?:%s|dso_local|dso_preemptable|default|hidden|protected|dllimport|dllexport|' \
          r'unnamed_addr|local_unnamed_addr|thread_local(?:\(\w+\))?)' % _LINKAGE
_DEF_RE = re.compile(r'^(define|declare)((?:\s+%s)*)\s' % _PREFIX)
_CC_RE = re.compile(r'^(?:ccc|fastcc|coldcc|x86_64_sysvcc|win64cc|cc \d+|preserve_\w+|'
                    r'swiftcc|swifttailcc|tailcc|ghccc|cfguard_checkcc)\b')
_CALL_RE = re.compile(r'\b((?:tail |musttail |notail )?(?:call|invoke))'
                      r'((?: (?:fast|nnan|ninf|nsz|arcp|contract|afn|reassoc))*) ')
_CALLEE_RE = re.compile(r'(@[\w.$\-]+|@"[^"]+"|%[\w.$\-]+|%"[^"]+")\(')


def _fix_defdecl(line):
    m = _DEF_RE.match(line)
    if not m:
        return line
    rest = line[m.end():]
    name = rest.split('(', 1)[0]
    if '@llvm.' in name or _CC_RE.match(rest):
        return line
    return line[:m.end()] + 'x86_64_sysvcc ' + rest


def _fix_calls(line):
    out = []
    pos = 0
    for m in _CALL_RE.finditer(line):
        after = line[m.end():]
        if _CC_RE.match(after) or after.startswith('asm '):
            continue
        callee = _CALLEE_RE.search(after)
        if callee and callee.group(1).startswith('@llvm.'):
            continue
        # inline asm call: "call void asm sideeffect ..." -- the callee is asm
        if re.match(r'[^(]*\basm\b', after.split('(', 1)[0]):
            continue
        out.append(line[pos:m.end()])
        out.append('x86_64_sysvcc ')
        pos = m.end()
    out.append(line[pos:])
    return ''.join(out)


# Names the code generator may call on its own (memcpy for a struct copy,
# fmod for frem, ...). On a Windows triple those libcalls use the Win64
# convention, so the SysV definitions and every explicit SysV call are moved
# to __bmc_sv_<name>; the plain names are served by Win64-ABI code
# (winsys/ws_stub.asm for mem*, compiler-rt and thunks for the rest).
_LIBM = ('''acos acosh asin asinh atan atan2 atanh cbrt ceil copysign cos cosh exp exp10 exp2 expm1
fabs floor fma fmax fmin fmod frexp hypot ldexp llrint llround log log10 log1p log2 lrint lround
modf nearbyint pow remainder rint round scalbn sin sincos sinh sqrt tan tanh trunc''').split()
LIBCALL_NAMES = {'memcpy', 'memmove', 'memset', 'memcmp', 'bcmp'}
for _n in _LIBM:
    LIBCALL_NAMES.update((_n, _n + 'f', _n + 'l'))
_LIBCALL_RE = re.compile(r'@(%s)(?![\w.$])' % '|'.join(sorted(LIBCALL_NAMES, key=len, reverse=True)))


_STRLIT_RE = re.compile(r'c"[^"]*"|![\w.]*"[^"]*"')


def _code_only(ln, fn):
    """Apply fn to ln with string literals (c"..." and metadata strings) masked out."""
    lits = []

    def keep(m):
        lits.append(m.group(0))
        return '\x00%d\x00' % (len(lits) - 1)
    masked = _STRLIT_RE.sub(keep, ln)
    masked = fn(masked)
    return re.sub(r'\x00(\d+)\x00', lambda m: lits[int(m.group(1))], masked)


_ELF_ONLY = re.compile(r'^\s*\.(type|size|ident|note\b)|^\s*\.section\s+"?\.note\.GNU-stack')


def _asm_line(body):
    """One top-level asm line: None to drop an ELF-only directive COFF has no
    meaning for (.type/.size/.ident, the GNU-stack note), else the line."""
    if _ELF_ONLY.match(body.replace('\\09', '\t')):
        return None
    return re.sub(r'^(\s*)\.section\s+\.rodata\b', r'\1.section .rdata', body)


# Data the assembly exports is only as aligned as its .asm places it, but
# clang takes the SysV ABI's word for an `extern` array of 16+ bytes (16) and
# may fold a load of it into an alignment-checked SSE operand (the gcc gate
# never emits one there; tests/test_bip39's m39_guard sits at 8 mod 16). In a
# module that declares such an external global, its declared alignment and
# the alignment claimed by loads/stores/memory intrinsics are capped at 8;
# allocas keep theirs (the assembly may rely on aligned stack buffers).
_EXT_ALIGN_RE = re.compile(r'^(@[\w.$"\-]+ = (?:[\w()]+ )*?external (?:[\w()]+ )*?global .*, align )(\d+)(.*)$')
_OP_ALIGN_RE = re.compile(r'\balign (16|32|64)\b')


def _cap_external_alignment(lines):
    capped = False
    for i, ln in enumerate(lines):
        m = _EXT_ALIGN_RE.match(ln)
        if m and int(m.group(2)) > 8:
            lines[i] = m.group(1) + '8' + m.group(3)
            capped = True
    if not capped:
        return
    for i, ln in enumerate(lines):
        if not ln.startswith(' ') or ' alloca ' in ln:
            continue
        if ' load ' in ln or ln.lstrip().startswith('store ') or '@llvm.mem' in ln or ' load atomic' in ln:
            lines[i] = _OP_ALIGN_RE.sub('align 8', ln)


def retarget_text(text, triple='x86_64-pc-windows-msvc'):
    lines = text.split('\n')
    _cap_external_alignment(lines)
    text = '\n'.join(lines)
    res = []
    in_masm = False
    for ln in text.split('\n'):
        # module asm: `module asm "..."` (older) or a `module asm(...)` header
        # followed by indented "..." lines (LLVM 23)
        m = re.match(r'^module asm "(.*)"$', ln)
        if m:
            body = _asm_line(m.group(1))
            if body is not None:
                res.append('module asm "%s"' % body)
            continue
        if ln.startswith('module asm('):
            in_masm = True
            res.append(ln)
            continue
        if in_masm:
            m = re.match(r'^(\s+)"(.*)"$', ln)
            if m:
                body = _asm_line(m.group(2))
                if body is not None:
                    res.append('%s"%s"' % (m.group(1), body))
                continue
            in_masm = False
        if ln.startswith('target triple'):
            ln = 'target triple = "%s"' % triple
        elif ln.startswith('target datalayout'):
            ln = ln.replace('-m:e-', '-m:w-')
        elif ln.startswith('!') or ln.startswith('attributes') or ln.startswith(';'):
            pass
        else:
            ln = _code_only(ln, lambda s: _LIBCALL_RE.sub(lambda m: '@__bmc_sv_' + m.group(1), s))
            if ln.startswith('define') or ln.startswith('declare'):
                ln = _fix_defdecl(ln)
            elif not ln.startswith('@') and ('call ' in ln or 'invoke ' in ln):
                ln = _code_only(ln, _fix_calls)
        res.append(ln)
    return '\n'.join(res)


def main(argv):
    src, dst = argv[1], argv[2]
    with open(src, encoding='utf-8') as f:
        text = f.read()
    with open(dst, 'w', encoding='utf-8', newline='\n') as f:
        f.write(retarget_text(text))


if __name__ == '__main__':
    main(sys.argv)
