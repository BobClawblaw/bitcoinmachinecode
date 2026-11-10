#!/usr/bin/env python3
"""run_tests.py -- build and run asm/Makefile's `make test` harness list on
Windows (bmc_win).

Every `./tests/<name> [args]` line of the Makefile's test recipe is built
from its own Makefile rule (build.py) and run from asm/, as `make test`
does. Results are written to port/win/out/test-results.txt.

Usage: python port/win/run_tests.py [--only name,name] [--from name] [--timeout s]
"""
import os
import re
import shlex
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import build  # noqa: E402

ASM = build.ASM


def recipe():
    """The `./tests/...` command lines of the Makefile's `test:` recipe."""
    lines = open(os.path.join(ASM, 'Makefile'), encoding='utf-8').read().split('\n')
    start = next(i for i, l in enumerate(lines) if l.startswith('test:'))
    out = []
    for l in lines[start + 1:]:
        if l.startswith('\t'):
            cmd = l[1:].strip()
            if cmd.startswith('./tests/'):
                out.append(cmd)
        elif l and not l.startswith('#') and not l.startswith('tests/'):
            break
    return out


def main(argv):
    only = None
    frm = None
    timeout = 600
    i = 1
    while i < len(argv):
        if argv[i] == '--only':
            only = set(argv[i + 1].split(','))
            i += 2
        elif argv[i] == '--from':
            frm = argv[i + 1]
            i += 2
        elif argv[i] == '--timeout':
            timeout = int(argv[i + 1])
            i += 2
        else:
            sys.exit('unknown arg ' + argv[i])
    cmds = recipe()
    results = []
    built = {}
    started = frm is None
    for cmd in cmds:
        parts = shlex.split(cmd)
        name = parts[0][len('./tests/'):]
        if not started:
            if name != frm:
                continue
            started = True
        if only and name not in only:
            continue
        if any(re.search(r'[|><;&$`]', p) for p in parts[1:]):
            results.append((name, 'SKIP', 'shell syntax in recipe line'))
            continue
        if name not in built:
            try:
                built[name] = build.build_test(name)
            except Exception as e:  # noqa: BLE001
                built[name] = None
                msg = str(e).strip().split('\n')
                results.append((name, 'BUILD', ' | '.join(m for m in msg if 'error' in m.lower())[:600]
                                or msg[-1][:600]))
                print('BUILD FAIL', name, flush=True)
                continue
        exe = built[name]
        if exe is None:
            continue
        t0 = time.time()
        try:
            # output to a file, not a pipe: a grandchild holding the pipe open
            # must not stall the run; on timeout the whole tree is killed
            logp = os.path.join(build.OUT, 'logs', name + '.log')
            os.makedirs(os.path.dirname(logp), exist_ok=True)
            with open(logp, 'wb') as lf:
                p = subprocess.Popen([exe] + parts[1:], cwd=ASM, stdout=lf, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL)
                try:
                    rc = p.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    subprocess.run(['taskkill', '/F', '/T', '/PID', str(p.pid)], capture_output=True)
                    p.wait()
                    rc = None
            dt = time.time() - t0
            tail = open(logp, 'rb').read().decode('utf-8', 'replace').strip().split('\n')[-3:]
            status = 'TIMEOUT' if rc is None else 'PASS' if rc == 0 else 'FAIL(%d)' % rc
            results.append((name, status, '%.1fs %s' % (dt, ' | '.join(tail)[:400])))
        except OSError as e:
            results.append((name, 'ERROR', str(e)))
        print(results[-1][1], cmd, flush=True)
    path = os.path.join(build.OUT, 'test-results.txt')
    with open(path, 'w', encoding='utf-8') as f:
        for n, s, d in results:
            f.write('%-8s %-45s %s\n' % (s, n, d))
    counts = {}
    for _, s, _ in results:
        k = s.split('(')[0]
        counts[k] = counts.get(k, 0) + 1
    print(counts)
    print('results:', path)


if __name__ == '__main__':
    main(sys.argv)
