#!/usr/bin/env python3
"""fix_syscalls.py -- rewrite Linux arm64 raw syscalls in the adapted
arm-port modules to Darwin BSD syscalls (bmc_osx).

Linux arm64: nr in x8, svc #0, error = negative errno.
Darwin arm64: nr in x16, svc #0x80, error = positive errno + CARRY SET.

Mappings used by the four syscall-carrying modules:
  openat  56 -> 463     pread64 67 -> pread 153     close 57 -> 6
  lseek   62 -> 199     read    63 -> 3             flock  32 -> 131
  AT_FDCWD -100 -> -2 (Darwin value)

Error-test rewrites: `tbnz x0,#63,label` (negative test) IMMEDIATELY after an
svc becomes `b.cs label` (carry test).  getrandom (serve) becomes a call to
_bmcshim_getrandom (port/osx/bmcshim.c, arc4random_buf).
"""
import re, sys

NR = {56: 463, 67: 153, 57: 6, 62: 199, 63: 3, 32: 131}

def convert(path):
    lines = open(path).read().split('\n')
    out = []
    i = 0
    nsvc = 0
    last_svc = -10
    while i < len(lines):
        ln = lines[i]
        s = ln.strip()
        # getrandom block (bitcoin_serve nonce): replaced with the shim call
        if s.startswith('movz x8, #278'):
            # consume: movz x8 / svc / cmp x0,#8 / b.eq rdy -- emit the call
            j = i
            while j < len(lines) and 'b.eq' not in lines[j] and 'svc' not in lines[j]:
                j += 1
            # skip through the b.eq line
            while j < len(lines) and 'b.eq' not in lines[j]:
                j += 1
            label = lines[j].split('b.eq')[1].strip()
            out.append('\tbl _bmcshim_getrandom          /* Darwin: arc4random_buf')
            out.append('\t                               (always succeeds; x0 kept nonzero) */')
            out.append(f'\tb {label}')
            i = j + 1
            nsvc += 1
            continue
        m = re.match(r'(\s*)mov\s+[xw]8,\s*#(\d+)\s*(/\*.*\*/)?\s*$', ln)
        if m and int(m.group(2)) in NR and i + 1 < len(lines) and 'svc' in lines[i+1]:
            nr = NR[int(m.group(2))]
            out.append(f'{m.group(1)}mov x16, #{nr}{("   " + m.group(3)) if m.group(3) else ""}')
            out.append(lines[i+1].replace('svc  #0', 'svc  #0x80').replace('svc #0', 'svc #0x80'))
            last_svc = len(out)
            i += 2
            nsvc += 1
            continue
        if re.fullmatch(r'svc\s+#0', s):
            out.append(re.sub(r'\bsvc\s+#0\b', 'svc #0x80', ln))
            last_svc = len(out)
            i += 1
            continue
        m = re.match(r'(\s*)mov\s+x0,\s*#-100(\s*/\* AT_FDCWD \*/)?\s*$', ln)
        if m:
            out.append(f'{m.group(1)}mov x0, #-2{m.group(2) or "        /* AT_FDCWD (Darwin) */"}')
            i += 1
            continue
        # negative-error test immediately after an svc -> carry test
        m = re.match(r'(\s*)tbnz\s+x0,\s*#63,\s*(\S+)\s*(/\*.*)?\s*$', ln)
        if m and len(out) - last_svc == 1:
            out.append(f'{m.group(1)}b.cs {m.group(2)}{(("   " + m.group(3)) if m.group(3) else "")}')
            i += 1
            continue
        out.append(ln)
        i += 1
    open(path, 'w').write('\n'.join(out))
    print(f'{path}: {nsvc} syscall sites converted')

for p in sys.argv[1:]:
    convert(p)
