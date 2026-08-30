#!/usr/bin/env python3
"""gate_log_audit.py -- "the gate said nothing, so it must have passed"

WHY THIS EXISTS. On 2026-08-30 a full gate FAILED and was reported as green.
Adding a second layer to daemon/signet.c gave that file new dependencies on
merkle_root and sha256_full; the layer 1 test's link line did not name them,
so tests/test_signet_solution failed to LINK. Under `make -k` the build kept
going, but the `test:` recipe never ran at all, because a prerequisite of it
had failed. The log therefore contained:

  * no "FAIL" lines           -- no test ever ran to fail
  * no "TESTS FAILED"         -- likewise
  * one `*** [...] Error 1`   -- easy to miss in ~12,000 lines
  * MAKE_EXIT=2               -- the only unambiguous signal

Grepping a gate log for failure words is therefore NOT a gate check. A log
with zero failures is exactly what a gate that ran nothing looks like, and the
two are indistinguishable without asking the other question: did every test
that is supposed to run actually run?

This asks that question. It is deliberately a POST-HOC audit of the log rather
than a check inside the `test:` recipe -- a check inside that recipe would be
skipped by the very failure it is meant to catch.

WHAT IT DOES NOT DO. It cannot tell a test that passed from one that ran and
printed nothing; make's exit status covers that (a non-zero test aborts the
recipe). It reads only what the log records, so a log truncated by a killed
terminal reads as an unfinished gate -- which is the correct answer.

Usage:
  scripts/gate_log_audit.py <gate.log> [--asmdir asm] [--quiet]
Exit 0 only if the gate finished, exited 0, and ran every gated test.
"""
import os, re, sys

def gated_tests(makefile):
    """The commands the `test:` recipe runs, in order."""
    lines = open(makefile, encoding='utf-8', errors='replace').read().split('\n')
    i = 0
    while i < len(lines) and not lines[i].startswith('test:'):
        i += 1
    if i == len(lines):
        sys.exit("gate-log-audit: no `test:` target in " + makefile)
    # step over the prerequisite list, including its backslash continuations
    while lines[i].rstrip().endswith('\\'):
        i += 1
    i += 1
    # The recipe ends at the next TARGET, not at the first line without a tab.
    # make permits comment lines and blank lines at column 0 in the middle of a
    # recipe, and this Makefile has them -- stopping at the first one silently
    # audited 121 of 270 tests and would have passed a gate in which the other
    # 149 never ran, which is the exact failure this script exists to catch.
    target = re.compile(r'^[^\t#\s][^:=]*:(?!=)')
    runs = []
    while i < len(lines):
        line = lines[i]
        if line.strip() and not line.startswith('\t'):
            if line.lstrip().startswith('#'):
                i += 1; continue          # comment inside the recipe
            if target.match(line):
                break                     # next rule: the recipe is over
        s = line.strip()
        if s.startswith('@'):
            s = s[1:].strip()
        if s.startswith('./'):
            runs.append(s.split()[0])
        i += 1
    return runs

def selftest(asmdir):
    """Prove the audit rejects what it must. A checker nobody checks is just a
    second thing to trust: this builds synthetic logs whose verdict is known
    and fails loudly if any of them is judged wrong."""
    import subprocess, tempfile
    runs = gated_tests(os.path.join(asmdir, 'Makefile'))
    if len(runs) < 50:
        print("GATE AUDIT SELFTEST FAILED: only %d gated tests parsed out of the "
              "`test:` recipe -- the parser is truncating" % len(runs))
        return 1
    good = '\n'.join(runs) + '\nMAKE_EXIT=0\n'
    cases = [
        ("a complete, clean gate", good, 0),
        ("a gate still running (no MAKE_EXIT)", '\n'.join(runs) + '\n', 1),
        ("make exited non-zero", '\n'.join(runs) + '\nMAKE_EXIT=2\n', 1),
        ("the build failed so NO test ran", 'gcc ...\nmake: *** [Makefile:1] '
         'Error 1\nMAKE_EXIT=2\n', 1),
        ("every test ran but ONE", '\n'.join(runs[:-1]) + '\nMAKE_EXIT=0\n', 1),
        ("one test in the middle skipped",
         '\n'.join(runs[:40] + runs[41:]) + '\nMAKE_EXIT=0\n', 1),
        ("a test reported a failure", good.replace('MAKE_EXIT=0',
         '  FAIL something\nTESTS FAILED (1 failure)\nMAKE_EXIT=0'), 1),
        ("a test segfaulted", good.replace('MAKE_EXIT=0',
         'Segmentation fault\nMAKE_EXIT=0'), 1),
    ]
    bad = 0
    d = tempfile.mkdtemp()
    for name, body, want in cases:
        f = os.path.join(d, 'l.log')
        open(f, 'w').write(body)
        r = subprocess.run([sys.executable, os.path.abspath(__file__), f,
                            '--asmdir', asmdir, '--quiet'],
                           capture_output=True, text=True)
        ok = (r.returncode != 0) == (want != 0)
        print("  %s %s" % ("ok " if ok else "FAIL", name))
        if not ok:
            bad += 1
            print("      wanted exit %d, got %d: %s" % (want, r.returncode,
                                                        r.stdout.strip()))
    print("GATE AUDIT SELFTEST %s (%d gated tests parsed)"
          % ("OK" if not bad else "FAILED", len(runs)))
    return 1 if bad else 0

def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    quiet = '--quiet' in sys.argv
    asmdir = 'asm'
    for k, a in enumerate(sys.argv):
        if a == '--asmdir' and k + 1 < len(sys.argv):
            asmdir = sys.argv[k+1]
    if '--selftest' in sys.argv:
        asmdir2 = 'asm'
        for k, a in enumerate(sys.argv):
            if a == '--asmdir' and k + 1 < len(sys.argv):
                asmdir2 = sys.argv[k+1]
        return selftest(asmdir2)
    if not args:
        sys.exit(__doc__.strip().split('Usage:')[-1].strip())
    logpath = args[0]
    if not os.path.exists(logpath):
        sys.exit("gate-log-audit: no such log: " + logpath)
    log = open(logpath, encoding='utf-8', errors='replace').read()
    problems = []

    # 1. Did the gate finish, and what did make actually return? A missing
    #    MAKE_EXIT means the wrapper never recorded one -- the gate is still
    #    running, or was killed. Both are "not a pass".
    m = re.search(r'^MAKE_EXIT=(-?\d+)\s*$', log, re.M)
    if not m:
        problems.append("no MAKE_EXIT line: the gate did not finish, or the "
                        "wrapper never recorded make's exit status")
        exit_code = None
    else:
        exit_code = int(m.group(1))
        if exit_code != 0:
            problems.append("make exited %d" % exit_code)

    # 2. Did every gated test actually run? This is the check that a
    #    failure-word grep cannot make.
    runs = gated_tests(os.path.join(asmdir, 'Makefile'))
    missing = [t for t in runs if not re.search(r'^%s(\s|$)' % re.escape(t), log, re.M)]
    if missing:
        problems.append("%d of %d gated test(s) never ran, starting with: %s"
                        % (len(missing), len(runs), ', '.join(missing[:6])))

    # 3. Failure markers. Last, not first: they are the weakest signal here.
    for pat, what in ((r'^\s*FAIL\b', 'FAIL line'),
                      (r'TESTS FAILED', 'TESTS FAILED'),
                      (r'^make(\[\d+\])?: \*\*\* ', 'make error'),
                      (r'Segmentation fault|AddressSanitizer|ThreadSanitizer:',
                       'crash/sanitizer report')):
        hits = re.findall(pat, log, re.M)
        if hits:
            problems.append("%d %s(s) in the log" % (len(hits), what))

    if problems:
        print("GATE LOG AUDIT FAILED: " + logpath)
        for p in problems:
            print("  - " + p)
        if missing and not quiet:
            print("  tests that never ran:")
            for t in missing:
                print("      " + t)
        return 1
    if not quiet:
        print("GATE LOG AUDIT OK: make exited %d; all %d gated tests ran; "
              "no failure markers." % (exit_code, len(runs)))
    return 0

sys.exit(main())
