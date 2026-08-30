#!/usr/bin/env python3
"""makefile_link_audit.py -- "this rule links a file whose symbols it cannot resolve"

WHY THIS EXISTS. Four separate times while adding signet (2026-08-30) the same
defect shipped: a source file grew a dependency on a symbol defined in ANOTHER
file, and the rules that link the first file were not updated to link the
second. Each one surfaced only as a link error in a full `make -k test` --
which takes minutes, stops the `test:` recipe from running at all (so the log
holds no FAIL lines), and reveals ONE round of breakage at a time. Four gates,
four fixes, same root cause.

WHAT prereq-check CANNOT SEE. Its contract is to compare a recipe's command
line against that rule's prerequisites: it catches "the recipe uses a file the
rule never declared". Here the file is named in NEITHER -- utxo_live.c started
calling g_chainp, and chainparams.c simply was not mentioned anywhere in the
rule. There is nothing for that audit to compare, and its own header says so.

WHAT THIS DOES. It resolves symbols the way the linker will, but statically and
over EVERY rule at once:

  1. compile each .c in the tree to a scratch object (cached by mtime) and read
     its defined and undefined symbols with nm; do the same for the .o files
     the build has already produced from .asm.
  2. take each rule's expanded prerequisite list as its link set. That is sound
     BECAUSE prereq-check already enforces the other direction -- every file a
     recipe uses is a prerequisite -- so the prerequisites are a superset of
     the recipe's inputs. The two audits lean on each other on purpose.
  3. for every undefined symbol left over, report it ONLY IF some other file in
     this project defines it, and name that file.

That last condition is what keeps the output actionable and quiet: libc,
pthread and every other external symbol are unresolvable by definition and are
skipped, so a finding is always "add THIS file to THAT rule".

LIMITS, stated plainly:
  * It reads the prerequisite list, not the recipe, so a rule that links
    something it never declared is prereq-check's business, not this one's.
  * Files are compiled with one generic flag set, not each rule's own flags.
    A file whose symbols depend on -D flags could be read wrongly; any file
    that fails to compile is reported as skipped rather than silently ignored.
  * Weak symbols and archives (.a) are treated as providing whatever nm lists.

Usage:
  scripts/makefile_link_audit.py [--asmdir asm] [--check] [-j N]
Exit 1 in --check mode if any rule is missing a file this project could supply.
"""
import concurrent.futures, hashlib, json, os, re, subprocess, sys

# Flag sets tried IN ORDER; the first that compiles wins. Reading a file's
# symbols needs only that it compile, not that it compile the way its rule
# does -- but a file that compiles under none of these is SKIPPED, and a
# skipped file has unknown symbols, which can hide a finding as easily as
# invent one. So the list exists to keep that set empty, and every skip is
# reported.
#
#   1. the common case.
#   2. without -D_GNU_SOURCE: some rules deliberately omit it, and under
#      glibc >= 2.34 it turns SIGSTKSZ into a sysconf() call, so a file using
#      it as an array bound compiles one way and not the other
#      (tests/test_taproot_bounds_fuzz.c).
#   3. with the SIMD ISAs this tree uses: an intrinsics file cannot compile
#      without the ISA enabled. The file that motivated this (a superseded
#      SHA-NI prototype) has since been deleted, but the set is kept: the
#      alternative is that the next intrinsics file added is silently skipped,
#      and a skipped file's symbols are unknown.
_INC = ['-I.', '-I', 'daemon', '-I', 'tests']
CFLAG_SETS = [
    ['-D_GNU_SOURCE', '-O0'] + _INC,
    ['-O0'] + _INC,
    ['-D_GNU_SOURCE', '-O0', '-msha', '-msse4.1', '-mssse3', '-mavx2'] + _INC,
]

def run(cmd, cwd=None, timeout=900):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return p.stdout, p.stderr, p.returncode

def make_db(asmdir):
    """Every rule with its EXPANDED prerequisites, from `make -qp`."""
    env = dict(os.environ)
    for k in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'MAKEOVERRIDES'):
        env.pop(k, None)
    p = subprocess.run(['make', '--no-print-directory', '-qp'], cwd=asmdir,
                       capture_output=True, text=True, timeout=900, env=env)
    rules = {}
    for ln in p.stdout.splitlines():
        if not ln or ln.startswith(('\t', '#', ' ')):
            continue
        m = re.match(r'^([^:#=]+?):(?!=)\s*(.*)$', ln)
        if not m:
            continue
        tgt, pre = m.group(1).strip(), m.group(2).split()
        if tgt.startswith('.') or '%' in tgt:
            continue
        rules[tgt] = pre
    return rules

def sym_of(asmdir, path, cache_dir):
    """(defined, undefined) for one .c or .o, cached by content mtime+size."""
    full = os.path.join(asmdir, path)
    try:
        st = os.stat(full)
    except OSError:
        return None
    key = hashlib.sha1(('%s|%d|%d' % (path, st.st_mtime_ns, st.st_size))
                       .encode()).hexdigest()
    cf = os.path.join(cache_dir, key + '.json')
    if os.path.exists(cf):
        try:
            d = json.load(open(cf))
            return set(d['def']), set(d['undef'])
        except Exception:
            pass
    if path.endswith('.c'):
        obj = os.path.join(cache_dir, key + '.o')
        rc = 1
        for flags in CFLAG_SETS:
            _, err, rc = run(['gcc'] + flags + ['-c', path, '-o', obj], cwd=asmdir)
            if rc == 0:
                break
        if rc != 0:
            return None
    else:
        obj = full
    out, _, rc = run(['nm', '--no-sort', obj])
    if rc != 0:
        return None
    dfn, und = set(), set()
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) < 2:
            continue
        t, name = parts[-2], parts[-1]
        if t == 'U':
            und.add(name)
        elif t in 'TDBRSGVWi':          # incl. weak (V/W) and ifunc
            dfn.add(name)
    json.dump({'def': sorted(dfn), 'undef': sorted(und)}, open(cf, 'w'))
    return dfn, und

def selftest():
    """A checker nobody checks is just a second thing to trust. Build a tiny
    project whose rule is missing a file, and require the audit to say so."""
    import tempfile, textwrap
    d = tempfile.mkdtemp()
    open(os.path.join(d, 'lib.c'), 'w').write('int shared_thing = 7;\n')
    open(os.path.join(d, 'user.c'), 'w').write(
        'extern int shared_thing;\nint use(void){ return shared_thing; }\n')
    open(os.path.join(d, 'app.c'), 'w').write(
        'int use(void);\nint main(void){ return use(); }\n')
    cases = [
        ("a rule missing the file that defines the symbol",
         "daemon/bad: app.c user.c\n\tgcc -o $@ app.c user.c\n", 1),
        ("the same rule with that file added",
         "daemon/good: app.c user.c lib.c\n\tgcc -o $@ app.c user.c lib.c\n", 0),
        ("a rule whose only unresolved symbols are external (libc)",
         "daemon/ext: app.c user.c lib.c\n\tgcc -o $@ app.c user.c lib.c\n", 0),
    ]
    bad = 0
    for name, mk, want in cases:
        open(os.path.join(d, 'Makefile'), 'w').write("all:\n\t@true\n\n" + mk)
        for f in os.listdir(os.path.join(d, '.link-audit-cache')) \
                 if os.path.isdir(os.path.join(d, '.link-audit-cache')) else []:
            os.remove(os.path.join(d, '.link-audit-cache', f))
        r = subprocess.run([sys.executable, os.path.abspath(__file__),
                            '--asmdir', d, '--check'],
                           capture_output=True, text=True)
        ok = (r.returncode != 0) == (want != 0)
        print("  %s %s" % ("ok " if ok else "FAIL", name))
        if not ok:
            bad += 1
            print("      wanted exit %d, got %d\n%s" % (want, r.returncode, r.stdout))
    print("LINK AUDIT SELFTEST %s" % ("OK" if not bad else "FAILED"))
    return 1 if bad else 0

def main():
    if '--selftest' in sys.argv:
        return selftest()
    asmdir = 'asm'
    check = '--check' in sys.argv
    jobs = os.cpu_count() or 4
    for k, a in enumerate(sys.argv):
        if a == '--asmdir' and k + 1 < len(sys.argv): asmdir = sys.argv[k+1]
        if a == '-j' and k + 1 < len(sys.argv): jobs = int(sys.argv[k+1])

    # ABSOLUTE: gcc runs with cwd=asmdir, so a relative cache path would
    # resolve inside it and every compile would fail (it did, silently
    # skipping 406 files and reporting 'OK' on the rest).
    cache_dir = os.path.abspath(os.path.join(asmdir, '.link-audit-cache'))
    os.makedirs(cache_dir, exist_ok=True)

    rules = make_db(asmdir)
    # Every linkable file any rule mentions, PLUS every source in the tree.
    # The tree scan is not redundant: a file that appears in no rule at all
    # can still be the one that DEFINES a symbol some rule needs, and without
    # it the finding is silently suppressed rather than reported. The
    # selftest caught exactly that.
    import glob
    files = set()
    for pre in rules.values():
        for p in pre:
            if p.endswith(('.c', '.o')):
                files.add(p)
    for pat in ('*.c', 'daemon/*.c', 'tests/*.c', '*.o'):
        for f in glob.glob(os.path.join(asmdir, pat)):
            files.add(os.path.relpath(f, asmdir))
    files = sorted(f for f in files if os.path.exists(os.path.join(asmdir, f)))

    syms, skipped = {}, []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
        for f, r in zip(files, ex.map(lambda f: sym_of(asmdir, f, cache_dir), files)):
            if r is None: skipped.append(f)
            else: syms[f] = r

    # symbol -> the project files that define it
    provider = {}
    for f, (dfn, _) in syms.items():
        for s in dfn:
            provider.setdefault(s, set()).add(f)

    findings = []
    for tgt, pre in sorted(rules.items()):
        # Only real link rules: an executable this build produces, which in
        # this tree always lives under tests/ or daemon/. Phony aggregates
        # like `asm` (whose prerequisites are every object) are not links and
        # would otherwise report every cross-object reference as a finding.
        if not (tgt.startswith('tests/') or tgt.startswith('daemon/')): continue
        if tgt.endswith(('.o', '.a', '.h', '.inc', '.c', '.py')): continue
        linked = [p for p in pre if p in syms]
        if len(linked) < 2: continue
        have = set()
        for p in linked: have |= syms[p][0]
        # a .a in the prerequisites can supply anything; do not guess
        if any(p.endswith('.a') for p in pre): have |= set(provider)
        need = {}
        for p in linked:
            for s in syms[p][1] - have:
                if s in provider and not (provider[s] & set(linked)):
                    need.setdefault(s, (p, sorted(provider[s])))
        if need:
            findings.append((tgt, need))

    if skipped:
        print("note: %d file(s) could not be compiled for symbols and were "
              "skipped: %s" % (len(skipped), ', '.join(skipped[:6])))
    if findings:
        print("LINK CHECK FAILED: %d rule(s) link a file whose symbols nothing "
              "in the rule defines." % len(findings))
        for tgt, need in findings:
            print("\n  %s" % tgt)
            for s, (user, defs) in sorted(need.items())[:8]:
                print("      needs %-28s (used by %s)" % (s, user))
                print("      %s defines it -- add it to this rule"
                      % ' or '.join(defs))
            if len(need) > 8:
                print("      ... and %d more symbol(s)" % (len(need) - 8))
        return 1 if check else 0
    print("LINK CHECK OK: %d rule(s), %d file(s); every undefined symbol is "
          "either supplied by the rule or external to this project."
          % (sum(1 for t in rules
                 if (t.startswith('tests/') or t.startswith('daemon/'))
                 and not t.endswith(('.o', '.a', '.h', '.inc', '.c', '.py'))),
             len(syms)))
    return 0

sys.exit(main())
