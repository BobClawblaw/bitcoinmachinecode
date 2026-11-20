"""prof_report.py -- symbolize a BMC_WIN_PROF dump (debug aid).

Usage: python port/win/tools/prof_report.py <dump file (path#pid)> <exe.map> [top]

Prints the hottest functions (samples per symbol, by the linker map) and
the syscall counts by number.
"""
import bisect
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stackscan import load_map  # noqa: E402


def main(argv):
    dump, mp = argv[1], argv[2]
    top = int(argv[3]) if len(argv) > 3 else 25
    syms = load_map(mp)
    addrs = [s[0] for s in syms]
    lo, hi = addrs[0], addrs[-1] + 0x100000
    by_sym = collections.Counter()
    sysc = []
    total = outside = 0
    with open(dump) as f:
        head = f.readline().split()
        for ln in f:
            p = ln.split()
            if p[0] == 'r':
                rip, n = int(p[1], 16), int(p[2])
                total += n
                if lo <= rip < hi:
                    i = bisect.bisect_right(addrs, rip) - 1
                    by_sym['%s (%s)' % (syms[i][1], syms[i][2])] += n
                else:
                    outside += n
                    by_sym['<system DLL / kernel>'] += n
            elif p[0] == 's':
                sysc.append((int(p[2]), int(p[1])))
    print('samples %s (dropped %s); %d outside the image' % (head[0], head[1], outside))
    for name, n in by_sym.most_common(top):
        print('%6.1f%%  %7d  %s' % (100.0 * n / max(total, 1), n, name))
    print('syscalls:')
    for n, nr in sorted(sysc, reverse=True)[:15]:
        print('  %4d  %d' % (nr, n))


if __name__ == '__main__':
    main(sys.argv)
