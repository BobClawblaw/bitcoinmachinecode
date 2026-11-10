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


def retarget_text(text, triple='x86_64-pc-windows-msvc'):
    text = _LIBCALL_RE.sub(lambda m: '@__bmc_sv_' + m.group(1), text)
    res = []
    for ln in text.split('\n'):
        if ln.startswith('target triple'):
            ln = 'target triple = "%s"' % triple
        elif ln.startswith('target datalayout'):
            ln = ln.replace('-m:e-', '-m:w-')
        elif ln.startswith('define') or ln.startswith('declare'):
            ln = _fix_defdecl(ln)
        elif 'call ' in ln or 'invoke ' in ln:
            ln = _fix_calls(ln)
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
