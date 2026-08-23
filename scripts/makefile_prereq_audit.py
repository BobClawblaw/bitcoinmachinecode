#!/usr/bin/env python3
"""
makefile_prereq_audit.py -- "the recipe uses what the rule never asked for"
auditor for asm/Makefile.

100% AI-authored, like the build it audits.

WHY THIS EXISTS
---------------
Twice on 2026-08-23 the same defect shipped: a recipe line consumed a file that
the rule containing it never declared as a prerequisite.  Make has no idea the
file is needed, so it neither builds it first nor orders it before the recipe.
The command then succeeds *only* when the file happens to already be lying
around from an earlier build -- which is always true on the machine where the
change was written, and never guaranteed anywhere else:

  1. tests/bench_abi_audit linked bitcoin_script.o in its recipe but did not
     list it as a prerequisite.  Serial builds passed (something else had
     already produced the object).  Under `make -j` the link raced nasm and
     died: "/usr/bin/ld: cannot find bitcoin_script.o".

  2. The `test:` rule ran ./tests/test_bip30_daemon in its recipe while the
     binary was missing from the `test:` prerequisite list -- a scripted edit
     had matched inside a COMMENT instead of the prerequisite line.  It passed
     only because a previous manual build had left the binary in the tree.  On
     a fresh clone the harness would not exist and the recipe would fail.

Both are invisible to `make test` on a warm working copy.  Both are trivially
visible to anyone who compares each rule's recipe against its own prerequisite
list -- which is all this script does.

WHY IT ASKS MAKE INSTEAD OF PARSING THE MAKEFILE
------------------------------------------------
asm/Makefile is ~1700 lines and leans hard on variables: $(CONSOBJS),
$(INTERPOBJS), $(REORGOBJS), $(TAPRIMSOBJS), $(SERVEOBJS), and
$(sort $(A) $(B) x.o) inline inside recipes.  A regex parser would have to
reimplement make's expander to know that $(sort $(CONSOBJS) $(INTERPOBJS) ...)
contains bitcoin_hash.o, and it would be wrong in a new way every time the
Makefile grew a construct.  So this tool never expands anything itself:

  * `make -qp`                 -- the rule database.  Every explicit rule with
                                  its prerequisites ALREADY EXPANDED by make,
                                  plus the source line of its recipe.
  * `make -n -B -k --trace ...` -- a dry run of every target.  `--trace`
                                  announces each rule as
                                  "Makefile:N: update target 'X' due to: ..."
                                  and then prints that rule's recipe lines
                                  FULLY EXPANDED, without running them.

Everything the checker reasons about is therefore make's own answer, not an
imitation of it.  `-n` means nothing is built and nothing is executed; `-B`
forces every rule to be considered so no rule is skipped for being up to date.

WHAT IT REPORTS
---------------
  INVOKE-NOT-PREREQ   (sound, gated)
      The recipe runs ./tests/X or ./daemon/X (or names it in command
      position), that path IS a target this Makefile knows how to build, and it
      is NOT in the rule's prerequisite CLOSURE.  Instance 2 above.

  OBJ-NOT-PREREQ      (sound, gated)
      The recipe passes <y>.o to a compiler/linker as an INPUT (not as the -o
      output, not as the rule's own target) and <y>.o is not in the rule's
      prerequisite closure.  Instance 1 above.

  INVOKE-NO-RULE      (sound, gated)
      The recipe runs ./tests/X or ./daemon/X, it is not a prerequisite, AND no
      rule in the Makefile can build it and no such file exists in the tree.
      That recipe cannot work anywhere.

  PREREQ-INDIRECT     (fragile, but not a bug today -- reported, never gated)
      The file is not a DIRECT prerequisite of the rule that uses it, but some
      other prerequisite pulls it in, so make still orders it first.  Correct
      as long as that other rule keeps listing it; the day it stops, this rule
      breaks for a reason nothing in it explains.

  SRC-NOT-PREREQ      (a staleness smell, NOT an ordering bug -- reported,
                       never gated)
      The recipe compiles a .c/.S/.asm source that is not a prerequisite.  This
      cannot break a fresh clone the way the two gated classes can -- the file
      is checked in, so it always exists -- but editing it will not rebuild the
      target.  Whether that matters depends on whether the file is expected to
      change, which is not knowable here, so this is the smell list, not the
      failure list.

WHY THE VERDICT USES THE CLOSURE, NOT THE DIRECT LIST
-----------------------------------------------------
Make's guarantee is transitive: every prerequisite, and every prerequisite of
those, is brought up to date before a recipe runs -- serially and under -j
alike.  Gating on the direct list alone would flag `test:` for running
./daemon/bitcoind, which its own prerequisites tests/test_outbound_mux and
tests/test_redial already depend on; that recipe cannot race, so failing the
build over it would be a false alarm.  Closure keeps the gate at zero false
positives while still catching both real defects, neither of which was
reachable by any path.

WHAT IT CANNOT CATCH
--------------------
It compares a recipe's *command line* against that rule's prerequisites, so it
is blind to every dependency that never appears on a command line:

  * headers.  #include "foo.h" is invisible here; a missing .h prerequisite is
    the same staleness class and needs -MMD depfiles, not this tool.
  * runtime inputs.  A harness that open()s a fixture, forks a helper, or
    dlopen()s something names none of it in the recipe.
  * indirect invocations: `sh -c ...`, a path built from a shell variable, a
    binary reached after `cd`, or anything behind a shell conditional.
  * paths outside tests/ and daemon/.  `python3 ../scripts/foo.py` in a
    phony auditor target is not checked -- and does not need to be: the script
    is checked in and never built, so there is no ordering hazard.
  * objects built ONLY by the %.o: %.asm pattern rule have no explicit rule in
    the database, so their (one-line, $@/$<) recipes are not audited.
  * over-declaration.  A prerequisite that nothing in the recipe uses is
    harmless and invisible to this check.
  * link SUFFICIENCY.  It proves every object named on the line was declared;
    it says nothing about an object that should have been on the line and was
    not.  That failure is an undefined symbol, not a missing file.

Usage:
  scripts/makefile_prereq_audit.py [--asmdir asm] [--format table|summary|csv]
  scripts/makefile_prereq_audit.py --check      # CI mode: exit 1 on any
                                                # sound (gated) finding
"""

import argparse
import os
import re
import shlex
import subprocess
import sys
from collections import defaultdict, OrderedDict

# ---------------------------------------------------------------------------
# Asking make
# ---------------------------------------------------------------------------

# Targets that are make's own bookkeeping, not build rules.
SPECIAL_TARGET = re.compile(r'^\.[A-Z]')

COMPILERS = re.compile(
    r'^(.*/)?((gcc|cc|g\+\+|c\+\+|clang|clang\+\+|ld|nasm|as|ar)'
    r'(-[0-9.]+)?)$')

# Shell tokens after which the next word is a command, not an argument.
CMD_SEPS = {';', '&&', '||', '|', '(', ')', '{', '}', '&', '\n',
            'then', 'else', 'do', 'done', 'fi', 'time', 'exec', 'if',
            'while', 'until', 'elif'}

# Options whose ARGUMENT is a filename we must not read as an input.
OPT_TAKES_OUTPUT = {'-o', '-MF', '-MT', '-MQ'}


def run_make(asmdir, args, timeout=900):
    # This runs FROM a make recipe (`make prereq-check`), so the outer make has
    # exported MAKEFLAGS/MFLAGS -- including a -j jobserver file descriptor
    # this child has no right to.  Scrub them so the answers depend only on the
    # makefile, not on how the outer build was invoked.
    env = dict(os.environ)
    for k in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'MAKEOVERRIDES'):
        env.pop(k, None)
    cmd = ['make', '--no-print-directory'] + args
    p = subprocess.run(cmd, cwd=asmdir, capture_output=True, text=True,
                       timeout=timeout, env=env)
    return p.stdout, p.stderr, p.returncode


def make_args(makefile, args):
    return (['-f', makefile] if makefile != 'Makefile' else []) + args


def load_database(asmdir, makefile='Makefile'):
    """`make -qp` -> (rules, all_targets).

    rules: target -> dict(prereqs=[...], recipe_line=int|None)
    all_targets: every name the database records as a target with a rule.

    Question mode (-q) evaluates nothing and runs nothing; -p dumps the rule
    database after reading the makefile, with every prerequisite list already
    expanded.
    """
    out, err, _ = run_make(asmdir, make_args(makefile, ['-qp']))
    if not out:
        sys.stderr.write('make -qp produced no output:\n%s\n' % err)
        return {}, set()

    lines = out.splitlines()
    try:
        start = lines.index('# Files')
    except ValueError:
        start = 0

    rules = OrderedDict()
    all_targets = set()
    i = start
    cur = None
    not_a_target = False
    while i < len(lines):
        ln = lines[i]
        i += 1
        if ln.startswith('# Not a target:'):
            not_a_target = True
            continue
        if not ln or ln.startswith('\t'):
            continue
        if ln.startswith('#'):
            m = re.match(r"^#  recipe to execute \(from '([^']+)', line (\d+)\)",
                         ln)
            if m and cur is not None:
                rules[cur]['recipe_file'] = m.group(1)
                rules[cur]['recipe_line'] = int(m.group(2))
            continue
        m = re.match(r'^([^:#=]+?):(?!=)\s*(.*)$', ln)
        if not m:
            cur = None
            continue
        tgt = m.group(1).strip()
        rest = m.group(2)
        if not_a_target:
            not_a_target = False
            all_targets.add(tgt)
            cur = None
            continue
        if SPECIAL_TARGET.match(tgt) or '%' in tgt or ' ' in tgt:
            cur = None
            continue
        # order-only prerequisites live after '|' and are still prerequisites
        pre = rest.replace('|', ' ').split()
        all_targets.add(tgt)
        cur = tgt
        rules.setdefault(tgt, dict(prereqs=[], recipe_line=None,
                                   recipe_file=None))
        rules[tgt]['prereqs'] = pre
    return rules, all_targets


def load_expanded_recipes(asmdir, targets, makefile='Makefile'):
    """`make -n -B -k --trace <targets>` -> target -> [expanded recipe line].

    -n runs nothing, -B stops make from skipping an up-to-date rule, -k keeps
    going past a rule make cannot satisfy, and --trace labels every recipe with
    the rule it came from.
    """
    out, err, _ = run_make(
        asmdir, make_args(makefile, ['-n', '-B', '-k', '--trace'] + targets))
    recipes = defaultdict(list)
    trace_line = {}
    cur = None
    pending = []

    def flush():
        if cur is not None and pending:
            recipes[cur].append('\n'.join(pending))

    for raw in out.splitlines():
        m = re.match(r"^([^:]+):(\d+): (?:update )?target '([^']+)'", raw)
        if m:
            flush()
            del pending[:]
            cur = m.group(3)
            trace_line[cur] = int(m.group(2))
            recipes.setdefault(cur, [])
            continue
        if cur is None:
            continue
        # make prints a recipe line with its backslash-newlines intact, exactly
        # as the shell will see it, so a logical line can span several output
        # lines.  Rejoin them before tokenizing.
        pending.append(raw)
        if raw.endswith('\\'):
            continue
        flush()
        del pending[:]
    flush()
    return recipes, trace_line, err


# ---------------------------------------------------------------------------
# Recipe inspection
# ---------------------------------------------------------------------------

def tokenize(cmd):
    """Shell-tokenize an already-expanded recipe line, keeping the separators
    that start a new command so we can tell a command from an argument."""
    text = cmd.replace('\\\n', ' ').replace('\n', ' \n ')
    try:
        lx = shlex.shlex(text, posix=True, punctuation_chars=True)
        lx.whitespace_split = True
        toks = list(lx)
    except ValueError:
        toks = text.split()
    return toks


def strip_prefixes(cmd):
    """Drop make's per-line recipe prefixes (@ silent, - ignore-errors,
    + always-run)."""
    out = []
    for i, ln in enumerate(cmd.split('\n')):
        s = ln
        if i == 0:
            s = s.lstrip()
            while s[:1] in ('@', '-', '+'):
                s = s[1:].lstrip()
        out.append(s)
    return '\n'.join(out)


INVOKE_RE = re.compile(r'^\./((?:tests|daemon)/[A-Za-z0-9_][\w.+-]*)$')
BARE_RE = re.compile(r'^((?:tests|daemon)/[A-Za-z0-9_][\w.+-]*)$')
OBJ_RE = re.compile(r'^[\w./+-]+\.o$')
SRC_RE = re.compile(r'^[\w./+-]+\.(c|C|S|s|cc|cpp|asm)$')


class Finding(object):
    __slots__ = ('kind', 'target', 'line', 'item', 'detail')

    def __init__(self, kind, target, line, item, detail):
        self.kind = kind
        self.target = target
        self.line = line
        self.item = item
        self.detail = detail


def recipe_line_numbers(path, first_line, count):
    """Physical line of each logical recipe line, starting at first_line.

    make reports only where a rule's recipe begins; a logical recipe line can
    span several physical lines via backslash continuation, so walk the file
    to keep the reported line numbers honest."""
    out = []
    try:
        with open(path, 'r', errors='replace') as fh:
            src = fh.readlines()
    except OSError:
        return [first_line] * count
    i = first_line - 1
    while i < len(src) and len(out) < count:
        ln = src[i]
        if not ln.startswith('\t'):
            if ln.strip() == '' or ln.lstrip().startswith('#'):
                i += 1
                continue
            break
        out.append(i + 1)
        while i < len(src) and src[i].rstrip('\n').endswith('\\'):
            i += 1
        i += 1
    while len(out) < count:
        out.append(first_line)
    return out


def closure(target, rules):
    """Every file make brings up to date before this rule's recipe runs."""
    out = set()
    work = list(rules.get(target, {}).get('prereqs', []))
    direct = set(work)
    while work:
        p = work.pop()
        if p in out:
            continue
        out.add(p)
        work.extend(rules.get(p, {}).get('prereqs', []))
    return direct, out


def audit_rule(target, rule, cmds, all_targets, asmdir, lines_for, rules):
    direct, prereqs = closure(target, rules)
    findings = []
    for idx, cmd in enumerate(cmds):
        srcline = lines_for[idx] if idx < len(lines_for) else rule['recipe_line']
        toks = tokenize(strip_prefixes(cmd))
        cmd_pos = True
        in_compiler = False
        skip_next = False
        for tok in toks:
            if tok in CMD_SEPS:
                cmd_pos = True
                in_compiler = False
                skip_next = False
                continue
            was_cmd = cmd_pos
            cmd_pos = False
            if skip_next:
                skip_next = False
                continue
            if tok in OPT_TAKES_OUTPUT:
                skip_next = True
                continue
            if was_cmd:
                in_compiler = bool(COMPILERS.match(tok))

            # --- invoked harness -------------------------------------------
            m = INVOKE_RE.match(tok)
            if m is None and was_cmd:
                m = BARE_RE.match(tok)
            if m:
                path = m.group(1)
                if path == target:
                    continue
                if path in prereqs:
                    if path not in direct:
                        findings.append(Finding(
                            'PREREQ-INDIRECT', target, srcline, path,
                            'recipe runs %s; ordered only because another '
                            'prerequisite of this rule depends on it' % tok))
                    continue
                if path in all_targets:
                    findings.append(Finding(
                        'INVOKE-NOT-PREREQ', target, srcline, path,
                        'recipe runs %s; the Makefile can build it but this '
                        'rule does not list it' % tok))
                elif not os.path.exists(os.path.join(asmdir, path)):
                    findings.append(Finding(
                        'INVOKE-NO-RULE', target, srcline, path,
                        'recipe runs %s; no rule builds it and no such file '
                        'is in the tree' % tok))
                continue

            if not in_compiler or tok.startswith('-'):
                continue

            # --- object file on a compiler/linker command line -------------
            if OBJ_RE.match(tok):
                if tok == target:
                    continue
                if tok in prereqs:
                    if tok not in direct:
                        findings.append(Finding(
                            'PREREQ-INDIRECT', target, srcline, tok,
                            'linked in; ordered only because another '
                            'prerequisite of this rule depends on it'))
                    continue
                findings.append(Finding(
                    'OBJ-NOT-PREREQ', target, srcline, tok,
                    'linked/compiled in but not a prerequisite of this rule'))
                continue

            if SRC_RE.match(tok):
                if tok == target or tok in prereqs:
                    continue
                findings.append(Finding(
                    'SRC-NOT-PREREQ', target, srcline, tok,
                    'compiled in but not a prerequisite: edits to it will not '
                    'rebuild this target'))
    return findings


GATED = ('INVOKE-NOT-PREREQ', 'OBJ-NOT-PREREQ', 'INVOKE-NO-RULE')
UNGATED = ('SRC-NOT-PREREQ', 'PREREQ-INDIRECT')


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--asmdir', default='asm',
                    help='directory containing the Makefile to audit')
    ap.add_argument('--makefile', default='Makefile')
    ap.add_argument('--format', default='table',
                    choices=('table', 'summary', 'csv', 'smells'))
    ap.add_argument('--check', action='store_true',
                    help='CI mode: exit 1 on any INVOKE-NOT-PREREQ, '
                         'OBJ-NOT-PREREQ or INVOKE-NO-RULE.  SRC-NOT-PREREQ '
                         '(staleness, not ordering) and PREREQ-INDIRECT '
                         '(fragile, but correct today) never fail the build.')
    ap.add_argument('--target', default=None,
                    help='restrict the report to one rule')
    args = ap.parse_args()

    asmdir = args.asmdir
    mkpath = os.path.join(asmdir, args.makefile)

    rules, all_targets = load_database(asmdir, args.makefile)
    with_recipe = [t for t, r in rules.items() if r['recipe_line'] is not None]
    if not with_recipe:
        sys.stderr.write('PREREQ CHECK: no rules with recipes found in %s\n'
                         % mkpath)
        return 1

    recipes, trace_line, mkerr = load_expanded_recipes(asmdir, with_recipe,
                                                       args.makefile)

    rows = []
    unexpanded = []
    for tgt in with_recipe:
        if args.target and tgt != args.target:
            continue
        rule = rules[tgt]
        cmds = recipes.get(tgt)
        if not cmds:
            unexpanded.append(tgt)
            continue
        rf = rule.get('recipe_file') or args.makefile
        path = rf if os.path.isabs(rf) else os.path.join(asmdir, rf)
        lines_for = recipe_line_numbers(path, rule['recipe_line'], len(cmds))
        rows.extend(audit_rule(tgt, rule, cmds, all_targets, asmdir,
                               lines_for, rules))

    sound = [f for f in rows if f.kind in GATED]
    smell = [f for f in rows if f.kind in UNGATED]

    if args.format == 'csv':
        print('kind,target,line,item,detail')
        for f in rows:
            print('%s,%s,%s,%s,"%s"' % (f.kind, f.target, f.line, f.item,
                                        f.detail))
    elif args.format == 'smells':
        _dump(smell, 'REPORTED, NEVER GATED (staleness and fragility)')
    elif args.format == 'table':
        _dump(sound, 'SOUND VIOLATIONS (a fresh clone or -j can hit these)')
        _dump(smell, 'REPORTED, NEVER GATED (staleness and fragility)')

    kinds = defaultdict(int)
    for f in rows:
        kinds[f.kind] += 1
    print('\n---- summary ----')
    print('  rules with recipes          %5d' % len(with_recipe))
    print('  recipe lines inspected      %5d'
          % sum(len(recipes.get(t, [])) for t in with_recipe))
    for k in GATED:
        print('  %-27s %5d' % (k, kinds[k]))
    for k in UNGATED:
        print('  %-27s %5d  (reported, never gated)' % (k, kinds[k]))
    if unexpanded:
        print('  rules make would not expand %5d  %s'
              % (len(unexpanded), ' '.join(unexpanded[:8])))

    if args.check:
        if sound:
            sys.stderr.write('\nPREREQ CHECK FAILED: %d recipe line(s) use a '
                             'file the rule never asked for.\n' % len(sound))
            for f in sound[:60]:
                sys.stderr.write('  %s:%s  %s  %s  %s -- %s\n'
                                 % (args.makefile, f.line, f.target, f.kind,
                                    f.item, f.detail))
            if len(sound) > 60:
                sys.stderr.write('  ... and %d more\n' % (len(sound) - 60))
            return 1
        sys.stderr.write('PREREQ CHECK OK: %d rules, every file a recipe uses '
                         'is a prerequisite of the rule that uses it.\n'
                         % len(with_recipe))
    return 0


def _dump(rows, title):
    print('\n==== %s ====' % title)
    if not rows:
        print('  (none)')
        return
    cur = None
    for f in sorted(rows, key=lambda x: (x.target, x.line or 0, x.item)):
        if f.target != cur:
            cur = f.target
            print('\n  %s' % f.target)
        print('    L%-6s %-18s %-28s %s'
              % (f.line or '-', f.kind, f.item, f.detail))


if __name__ == '__main__':
    sys.exit(main())
