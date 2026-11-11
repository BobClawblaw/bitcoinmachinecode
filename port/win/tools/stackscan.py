"""stackscan.py -- where is a hung bmc_win process? (debug aid)

Attaches lldb to <pid> once (on Windows the inferior does not survive the
session), dumps each thread's stack words and symbolizes those that fall in
the executable, using its linker map (lld /map). The SysV code has no
unwind tables, so a backtrace stops at the first frame of ours; a raw scan
of return addresses still shows the call chain.

Usage: python port/win/tools/stackscan.py <pid> <exe.map> [words] [threads]
"""
import bisect
import re
import subprocess
import sys

LLDB = r'C:\Program Files\LLVM\bin\lldb.exe'


def load_map(path):
    syms = []
    for ln in open(path, encoding='utf-8', errors='replace'):
        m = re.match(r'\s*0001:[0-9a-f]+\s+(\S+)\s+([0-9a-f]{16})\s+(\S+)', ln)
        if m:
            syms.append((int(m.group(2), 16), m.group(1), m.group(3)))
    syms.sort()
    return syms


def main(argv):
    pid, mp = argv[1], argv[2]
    words = int(argv[3]) if len(argv) > 3 else 400
    nthreads = int(argv[4]) if len(argv) > 4 else 12
    syms = load_map(mp)
    addrs = [s[0] for s in syms]
    lo, hi = addrs[0], addrs[-1] + 0x100000
    cmds = []
    for t in range(1, nthreads + 1):
        cmds += ['-o', 'script print("@@THREAD %d")' % t, '-o', 'thread select %d' % t,
                 '-o', 'memory read --force -fx -s8 -c%d $rsp' % words]
    rr = subprocess.run([LLDB, '-b', '-p', pid] + cmds, capture_output=True, text=True)
    text = rr.stdout + rr.stderr
    for part in text.split('@@THREAD ')[1:]:
        tid = part.split('\n', 1)[0].strip()
        if 'invalid thread' in part.lower():
            continue
        print('--- thread #%s' % tid)
        seen = 0
        for v in re.findall(r'0x([0-9a-f]{16})', part):
            a = int(v, 16)
            if lo <= a < hi:
                i = bisect.bisect_right(addrs, a) - 1
                print('   %s %s+0x%x (%s)' % (hex(a), syms[i][1], a - syms[i][0], syms[i][2]))
                seen += 1
                if seen > 25:
                    break


if __name__ == '__main__':
    main(sys.argv)
