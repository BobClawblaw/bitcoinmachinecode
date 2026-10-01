#!/usr/bin/env python3
"""makefile_header_audit.py -- "this rule compiles main.c but does not rebuild when its headers change"

WHY THIS EXISTS. On 2026-10-01 a revert-check edited daemon/dlc_rules.h and ran
`make tests/test_dialhelper`. Nothing rebuilt: no rule that compiles
daemon/main.c listed dlc_rules.h as a prerequisite (not the daemon's, not
runtime-check's, not one of the 19 tests that #include main.c). The previous
binary ran, the "reverted" test passed, and the pass read as "the test does not
cover the fix". The build printed nothing, so the usual guard -- refuse to run
after a build that printed anything -- could not catch it. main.c includes 48
local headers; the daemon's rule listed five.

WHAT THIS DOES. For every HUB source (default: daemon/main.c), it reads the
hub's direct `#include "..."` lines, resolves each against the hub's directory,
and requires every rule whose EXPANDED prerequisites (from `make -qp`, the same
database makefile_link_audit.py reads) contain the hub to also contain every
one of those headers. A finding is always "add THESE headers to THAT rule";
in asm/Makefile the cure is the MAIN_C_HDRS variable.

LIMITS, stated plainly:
  * Direct includes only. A header that includes another header is not
    followed; neither are system headers (<...>).
  * Only the hub sources named are audited. Other .c files in the tree have the
    same exposure and are not checked here.
  * It reads prerequisites, not recipes: it says nothing about what gcc is
    given, only about what make watches. .PHONY targets are skipped: they make
    no file and are never stale (runtime-check lists main.c only to grep it).
"""
import os, re, subprocess, sys

INCLUDE_RE = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.M)

def make_db(asmdir):
    """Every rule with its EXPANDED prerequisites, from `make -qp`."""
    env = dict(os.environ)
    for k in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'MAKEOVERRIDES'):
        env.pop(k, None)
    p = subprocess.run(['make', '--no-print-directory', '-qp'], cwd=asmdir,
                       capture_output=True, text=True, timeout=900, env=env)
    rules, phony = {}, set()
    for ln in p.stdout.splitlines():
        if not ln or ln.startswith(('\t', '#', ' ')):
            continue
        m = re.match(r'^([^:#=]+?):(?!=)\s*(.*)$', ln)
        if not m:
            continue
        tgt, pre = m.group(1).strip(), m.group(2).split()
        if tgt == '.PHONY':
            phony.update(pre)
            continue
        if tgt.startswith('.') or '%' in tgt:
            continue
        rules[tgt] = pre
    for t in phony:                  # a phony target makes no file, so it cannot be stale
        rules.pop(t, None)           # (runtime-check lists main.c to grep it, not to compile it)
    return rules

def hub_headers(asmdir, hub):
    """The hub's direct local includes, as paths relative to asmdir."""
    src = open(os.path.join(asmdir, hub), errors='replace').read()
    base = os.path.dirname(hub)
    out = set()
    for inc in INCLUDE_RE.findall(src):
        out.add(os.path.normpath(os.path.join(base, inc)))
    return sorted(out)

def audit(asmdir, hubs):
    rules = make_db(asmdir)
    findings = []
    for hub in hubs:
        hdrs = hub_headers(asmdir, hub)
        for tgt in sorted(rules):
            pre = set(os.path.normpath(p) for p in rules[tgt])
            if hub not in pre:
                continue
            missing = [h for h in hdrs if h not in pre]
            if missing:
                findings.append((tgt, hub, missing, len(hdrs)))
    return findings

def selftest():
    """A checker nobody checks is just a second thing to trust. Build a tiny
    project whose rule is missing a header the hub includes, and require the
    audit to say so -- and to stay quiet once the header is listed."""
    import tempfile
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, 'daemon'))
    open(os.path.join(d, 'daemon', 'rules.h'), 'w').write('#define X 1\n')
    open(os.path.join(d, 'top.h'), 'w').write('#define Y 2\n')
    open(os.path.join(d, 'daemon', 'main.c'), 'w').write(
        '#include <stdio.h>\n#include "rules.h"\n#include "../top.h"\nint main(void){ return X + Y; }\n')
    cases = [
        ("a rule compiling the hub that lists none of its headers",
         "app: daemon/main.c\n\tgcc -o $@ daemon/main.c\n", 1),
        ("a rule listing one header of two",
         "app: daemon/main.c daemon/rules.h\n\tgcc -o $@ daemon/main.c\n", 1),
        ("a rule listing both (the ../ include resolved to top.h)",
         "app: daemon/main.c daemon/rules.h top.h\n\tgcc -o $@ daemon/main.c\n", 0),
        ("both headers listed through a variable",
         "HDRS := daemon/rules.h top.h\napp: daemon/main.c $(HDRS)\n\tgcc -o $@ daemon/main.c\n", 0),
        ("a rule that does not compile the hub is not audited",
         "other: top.h\n\ttrue\n", 0),
        ("a .PHONY target that lists the hub (to grep it) is not audited",
         ".PHONY: scan\nscan: daemon/main.c\n\tgrep -c X daemon/main.c\n", 0),
    ]
    bad = 0
    for name, mk, want in cases:
        open(os.path.join(d, 'Makefile'), 'w').write("all:\n\t@true\n\n" + mk)
        r = subprocess.run([sys.executable, os.path.abspath(__file__),
                            '--asmdir', d, '--check'],
                           capture_output=True, text=True)
        ok = (r.returncode != 0) == (want != 0)
        print("  %s %s" % ("ok " if ok else "FAIL", name))
        if not ok:
            bad += 1
            print("      wanted exit %d, got %d\n%s" % (want, r.returncode, r.stdout))
    print("HEADER AUDIT SELFTEST %s" % ("OK" if not bad else "FAILED"))
    return 1 if bad else 0

def main():
    if '--selftest' in sys.argv:
        return selftest()
    asmdir = '.'
    hubs = []
    a = sys.argv[1:]
    i = 0
    while i < len(a):
        if a[i] == '--asmdir':
            asmdir = a[i + 1]; i += 2; continue
        if a[i] == '--hub':
            hubs.append(a[i + 1]); i += 2; continue
        i += 1
    if not hubs:
        hubs = ['daemon/main.c']
    findings = audit(asmdir, hubs)
    if not findings:
        print("HEADER CHECK OK: every rule that compiles %s lists every header it includes" % ", ".join(hubs))
        return 0
    print("HEADER CHECK FAILED: %d rule(s) compile a hub without listing its headers "
          "(a header-only edit would not rebuild them)" % len(findings))
    for tgt, hub, missing, n in findings:
        shown = ", ".join(missing[:6]) + (" ..." if len(missing) > 6 else "")
        print("  %s: compiles %s, missing %d of its %d header(s): %s" % (tgt, hub, len(missing), n, shown))
    return 1 if '--check' in sys.argv else 0

if __name__ == '__main__':
    sys.exit(main())
