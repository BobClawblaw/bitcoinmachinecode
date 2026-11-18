#!/usr/bin/env python3
"""run_tests.py -- build and run asm/Makefile's `make test` harness list on
Windows (bmc_win).

Every `./tests/<name> [args]` line of the Makefile's test recipe is built
from its own Makefile rule (build.py) and run from asm/, as `make test`
does, then the port's own tests (port/win/tests/test_win_*.c). Results
are written to <out>/test-results.txt.

It is the Windows gate: the exit status is 0 only when every test passed
or is a known Windows limit (KNOWN below, reported N/A, as the Mac reports
the x86-only tests). A FAIL, TIMEOUT, BUILD or ERROR anywhere exits 1.

Usage: python port/win/run_tests.py [--only name,name] [--from name] [--timeout s] [--no-port]
"""
import glob
import os
import re
import shlex
import shutil
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


class Unexpandable(Exception):
    pass


def make_vars():
    """The Makefile's variable assignments, NAME -> (op, raw value), with
    backslash continuations joined. Later assignments win, as in make
    (`+=` appends, `?=` only sets an unset name)."""
    text = open(os.path.join(ASM, 'Makefile'), encoding='utf-8').read().replace('\\\n', ' ')
    vs = {}
    for l in text.split('\n'):
        if l.startswith('\t'):
            continue
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*(:=|\?=|\+=|=)\s*(.*)$', l)
        if not m:
            continue
        name, op, val = m.groups()
        if op == '+=' and name in vs:
            vs[name] = (vs[name][0], vs[name][1] + ' ' + val)
        elif op == '?=' and name in vs:
            continue
        else:
            vs[name] = (op, val)
    return vs


def expand(s, vs, depth=0):
    """Expand the make syntax a recipe line uses: $(VAR), $(shell seq a b)
    and $(wildcard pattern). Anything else raises Unexpandable."""
    if depth > 20:
        raise Unexpandable('recursive variable')
    out = ''
    i = 0
    while i < len(s):
        if s.startswith('$(', i):
            lvl, j = 1, i + 2
            while j < len(s) and lvl:
                lvl += {'(': 1, ')': -1}.get(s[j], 0)
                j += 1
            if lvl:
                raise Unexpandable('unbalanced $(')
            body = expand(s[i + 2:j - 1], vs, depth + 1)
            fn, _, arg = body.partition(' ')
            if fn == 'shell':
                a = arg.split()
                if len(a) != 3 or a[0] != 'seq':
                    raise Unexpandable('$(shell %s)' % arg)
                out += ' '.join(str(n) for n in range(int(a[1]), int(a[2]) + 1))
            elif fn == 'wildcard':
                # absolute POSIX paths (/storage/...) have no Windows match
                out += ' '.join(p for pat in arg.split() if not pat.startswith('/')
                                for p in sorted(glob.glob(os.path.join(ASM, pat))))
            elif re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', body):
                if body in os.environ:
                    out += os.environ[body]
                elif body in vs:
                    out += expand(vs[body][1], vs, depth + 1)
            else:
                raise Unexpandable('$(%s)' % body)
            i = j
        elif s[i] == '$':
            raise Unexpandable('$ outside $(...)')
        else:
            out += s[i]
            i += 1
    return out


# tests that are slow on Windows only from the syscall cost: the bad-object
# repro of test_lsm_lost_tombstones walks run files in 15- and 37-byte
# reads, tens of millions of them (~16 min here, against the default 10)
SLOW = {'test_lsm_lost_tombstones_bad': 1800}

# tests that cannot pass on Windows, and why: reported N/A, not FAIL. A test
# here that passes is reported PASS (and should come off the list).
KNOWN = {
    'test_cli_prompt': 'its terminal cases need a pty (forkpty), which winsys does not emulate, and one '
                       'case passes a 40,000-byte argument through sh, past the 32,767-character '
                       'Windows command line',
    'test_sd_watchdog': "systemd's watchdog datagram: AF_UNIX SOCK_DGRAM and the abstract namespace "
                        "do not exist on Windows (nor does systemd)",
    'test_drop_appends': "measures a file's page-cache residency through mincore on a fresh mapping; "
                         "Windows has no unprivileged per-file cache residency query",
    'test_mpool_get_once': 'needs ptrace',
    'test_elf_hardening': 'checks PIE, RELRO and NX in ELF headers; the Windows binaries are PE',
}

# timing checks whose bound was set on Linux and that Windows meets with
# little room: a failure is run again, up to RETRY_MAX attempts in all, as
# port/osx does for its timing tests. A pass on a later attempt is a PASS,
# with the attempt in the detail; failing every attempt is a FAIL.
RETRY = {
    # getindexinfo's "< 0.5 ms CPU per call" is ~0.4 ms here: two
    # CreateFileW a call at tens of us each (~0.025 ms on Linux and the Mac)
    'test_rpc_responsive': 'a 0.5 ms CPU bound; Windows file opens use ~0.4 ms of it',
}
RETRY_MAX = 3

TOOLS = ['daemon/bmcbitcoind', 'daemon/bmc_cli', 'daemon/bmc_wallet_cli', 'daemon/bmc_rpcd',
         'daemon/bmc_build_addr_hist', 'daemon/bmc_build_coinstats_hist',
         'daemon/bmc_build_txospender_index', 'daemon/bmc_merge_index_runs',
         'tests/verify_p2sh_shim', 'tests/bip30_shim']   # helpers some tests run


def main(argv):
    only = None
    frm = None
    timeout = 600
    port_tests = True
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
        elif argv[i] == '--no-port':
            port_tests = False
            i += 1
        else:
            sys.exit('unknown arg ' + argv[i])
    cmds = recipe()
    mvars = make_vars()
    results = []
    built = {}
    # the tests exec the daemon's tools by their source-tree names
    # (daemon/bmc_cli), directly or through sh: they are installed where the
    # Linux build puts them, as <name>.exe (gitignored), and winsys's stat,
    # access and exec find "<name>.exe" for "<name>"; BMC_WIN_BINDIR covers
    # the rest
    for tool in TOOLS:
        try:
            exe = build.build_target(tool)
            shutil.copy2(exe, os.path.join(ASM, tool.replace('/', os.sep) + '.exe'))
        except Exception as e:  # noqa: BLE001
            # a stale copy (an orphan still holding the old exe) makes the
            # tests that run it fail for no reason of theirs: an error
            results.append((tool, 'ERROR', 'tool did not build or install: ' +
                            str(e).strip().split('\n')[-1][:200]))
            print('ERROR tool %s did not build or install' % tool, flush=True)
    os.environ['BMC_WIN_BINDIR'] = os.path.join(build.OUT, 'bin')
    # the tests' system()/popen() lines and #! scripts are POSIX shell: with
    # Git for Windows installed, its sh runs them (winsys: BMC_WIN_SH)
    if 'BMC_WIN_SH' not in os.environ:
        for cand in (os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), 'Git', 'bin', 'sh.exe'),):
            if os.path.exists(cand):
                os.environ['BMC_WIN_SH'] = cand
                break
    started = frm is None
    if port_tests and not frm:
        for src in sorted(glob.glob(os.path.join(HERE, 'tests', 'test_win_*.c'))):
            cmds.append('port:' + os.path.splitext(os.path.basename(src))[0])
    for cmd in cmds:
        port = cmd.startswith('port:')
        parts = [cmd] if port else shlex.split(cmd)
        name = cmd[5:] if port else parts[0][len('./tests/'):]
        if not started:
            if name != frm:
                continue
            started = True
        if only and name not in only:
            continue
        if not port:
            # the recipe's make variables, and `< /dev/null` (stdin is
            # always /dev/null here); any other shell syntax is a SKIP
            args = parts[1:]
            if args[-2:] == ['<', '/dev/null']:
                args = args[:-2]
            try:
                if any('$' in a for a in args):
                    args = shlex.split(expand(' '.join(args), mvars))
            except Unexpandable as e:
                results.append((name, 'SKIP', 'make syntax the harness does not expand: %s' % e))
                continue
            parts = parts[:1] + args
        if any(re.search(r'[|><;&$`]', p) for p in parts[1:]):
            results.append((name, 'SKIP', 'shell syntax in recipe line'))
            continue
        if name not in built:
            try:
                built[name] = build.build_port_test(name) if port else build.build_test(name)
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
        try:
            # output to a file, not a pipe: a grandchild holding the pipe open
            # must not stall the run; on timeout the whole tree is killed
            logp = os.path.join(build.OUT, 'logs', name + '.log')
            os.makedirs(os.path.dirname(logp), exist_ok=True)
            attempt = 0
            while True:
                attempt += 1
                t0 = time.time()
                with open(logp, 'wb') as lf:
                    p = subprocess.Popen([exe] + parts[1:], cwd=ASM, stdout=lf, stderr=subprocess.STDOUT,
                                         stdin=subprocess.DEVNULL)
                    try:
                        rc = p.wait(timeout=max(timeout, SLOW.get(name, 0)))
                    except subprocess.TimeoutExpired:
                        subprocess.run(['taskkill', '/F', '/T', '/PID', str(p.pid)], capture_output=True)
                        p.wait()
                        rc = None
                if rc != 0 and name in RETRY and attempt < RETRY_MAX:
                    continue
                break
            dt = time.time() - t0
            tail = open(logp, 'rb').read().decode('utf-8', 'replace').strip().split('\n')[-3:]
            status = 'TIMEOUT' if rc is None else 'PASS' if rc == 0 else 'FAIL(%d)' % rc
            detail = '%.1fs %s' % (dt, ' | '.join(tail)[:400])
            if attempt > 1:
                detail = 'attempt %d of %d (%s) -- %s' % (attempt, RETRY_MAX, RETRY[name], detail)
            if status != 'PASS' and name in KNOWN:
                status, detail = 'N/A', KNOWN[name] + ' -- ' + detail
            results.append((name, status, detail))
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
    bad = sum(v for k, v in counts.items() if k not in ('PASS', 'SKIP', 'N/A'))
    print('GATE:', 'PASS' if not bad else 'FAIL (%d)' % bad)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
