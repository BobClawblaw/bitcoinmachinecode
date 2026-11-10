"""asm_xform.py -- adapt a bmc NASM source (ELF64, Linux) to win64 (bmc_win).

The upstream .asm files are not edited; build.py assembles the transformed
copy. Each rewrite is mechanical and checked:
  * `syscall`            -> red-zone-safe call of __bmc_sys_sv (winsys/ws_stub.asm)
  * TLS_ADDR macro body  -> PE TLS: gs:[0x58] -> the EXE's block (index 0)
                            + (var - _tls_start) from two ADDR32NB relocations
  * section .tbss        -> .tls$BMC (inside the PE TLS template)
  * section .rodata      -> .rdata ; ELF .note.GNU-stack dropped
  * global x:function    -> global x (COFF has no symbol types)
  * the weak bmc_tls_scratch fallback include -> extern (the fallback lives in
    an archive member, so a strong C definition still wins, as with ELF weak)
Anything ELF-specific left over (..gottpoff, fs:) fails the build loudly.
"""
import re

_SYSCALL = re.compile(r'^(\s*)syscall\b(.*)$')
_GOT = re.compile(r'^(\s*)mov\s+(%1|\w+)\s*,\s*\[\s*rel\s+(%2|\w+)\s+wrt\s+\.\.gottpoff\s*\](.*)$')
_FSADD = re.compile(r'^\s*add\s+(%1|\w+)\s*,\s*(qword\s+)?\[\s*fs:0\s*\].*$')
_SECTION = re.compile(r'^(\s*)section\s+(\S+)(.*)$', re.I)
_GLOBAL = re.compile(r'^(\s*global\s+)(.*)$')


def _fix_global(rest):
    code, sep, comment = rest.partition(';')
    names = []
    for item in code.split(','):
        item = item.strip()
        if not item:
            continue
        names.append(item.split(':', 1)[0].split()[0])
    return ', '.join(names) + ((' ;' + comment) if sep else '')


def transform(text, name):
    out = ['%include "win_prelude.inc"']
    for ln in text.split('\n'):
        m = _SYSCALL.match(ln)
        if m:
            ind = m.group(1)
            out.append('%slea  rsp, [rsp-128]      ; bmc_win: syscall -> winsys%s' % (ind, m.group(2)))
            out.append('%scall __bmc_sys_sv' % ind)
            out.append('%slea  rsp, [rsp+128]' % ind)
            continue
        m = _GOT.match(ln)
        if m:
            ind, dst, sym = m.group(1), m.group(2), m.group(3)
            out.append('%smov   %s, [gs:0x58]            ; bmc_win: PE TLS pointer array' % (ind, dst))
            out.append('%smov   %s, [%s]                ; the EXE block (TLS index 0)' % (ind, dst, dst))
            out.append('%sadd   %s, %s wrt ..imagebase' % (ind, dst, sym))
            out.append('%ssub   %s, _tls_start wrt ..imagebase' % (ind, dst))
            continue
        if _FSADD.match(ln):
            continue
        m = _SECTION.match(ln)
        if m:
            sec = m.group(2)
            if sec == '.note.GNU-stack':
                continue
            if sec in ('.tbss', '.tdata'):
                out.append('%ssection .tls$BMC data align=64' % m.group(1))
                continue
            if sec == '.rodata':
                out.append('%ssection .rdata%s' % (m.group(1), m.group(3)))
                continue
        m = _GLOBAL.match(ln)
        if m:
            out.append(m.group(1) + _fix_global(m.group(2)))
            continue
        if re.match(r'^\s*%include\s+"bmc_tls_scratch\.inc"', ln):
            out.append('extern bmc_tls_scratch            ; bmc_win: fallback in port/win/asm')
            continue
        out.append(ln)
    res = '\n'.join(out)
    code = re.sub(r';[^\n]*', '', res)
    if '..gottpoff' in code or re.search(r'\bfs:', code):
        raise RuntimeError('%s: ELF TLS construct left after transform' % name)
    return res
