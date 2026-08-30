#!/usr/bin/env python3
"""makefile_runlist_audit.py -- every test_*.c is either in the gate or is
explicitly declared manual, with a reason.

WHY THIS EXISTS. Twice in one session a test was written, run by hand, and
never added to `make test` -- once because only the build rule was added and
once because no rule was added at all. Both times the gate stayed green and
the assertions simply never executed. `prereq-check` catches a rule that does
not depend on what it links; this catches a test that nothing runs.

The allowlist is the deliverable. It converts "we do not know why this is not
in the gate" into a reviewed statement, one line per test, that a reader can
disagree with.

Exit 0 when every test_*.c is accounted for; 1 otherwise.
"""
import re, os, sys, glob

# Tests deliberately outside `make test`. Each needs a reason a reader can
# check -- "it is slow" is a reason, "it was like that when I got here" is not.
MANUAL = {
    "test_gh_real":            "needs a live peer: replays the getheaders path against a real node",
    "test_addr_ingest":        "needs a live peer: asks a real node for addresses over getaddr",
    "test_ibd_scale":          "large-scale IBD demonstration, runs for hours",
    "test_archive_verify":     "integration against a COPY of the real archive; needs one to exist",
    "test_real_block":         "needs real block data from the archive",
    "test_mpool_delete_stress":"randomized stress, unbounded runtime by design",
    "test_utxo_delete_stress": "randomized stress, unbounded runtime by design",
    "test_truncate_guard":     "no build rule; superseded by test_truncate_guard_prim",
    "test_truncate_guard_prim":"needs a prepared archive fixture (chdir's into a datadir)",
    "test_nsb_range":          "no build rule; scratch probe, never integrated",
    "test_utxo_recover":       "needs a datadir whose UTXO store has SEVERAL runs to compact; "
                               "a small chain gives manifest_n=0 and the assertion cannot fire. "
                               "Build fixed 2026-08-30; run as: tests/test_utxo_recover <datadir> [chain] "
                               "-- pass the chain the fixture came from, or mainnet's "
                               "activation heights reject every block",
}

# Non-test binaries that live in tests/ and are invoked BY other tests rather
# than run directly. Listed so the checker does not flag them as unrun.
HELPERS = {"bip30_shim", "consensus_shim", "run_batch", "verify_p2sh_shim",
           "fakepeer_headers", "smoke_interp", "bip30_daemon_shim",
           "fullchain_shim", "point_ref", "point_ct_ref"}

def main():
    asmdir = "asm"
    for i, a in enumerate(sys.argv):
        if a == "--asmdir" and i + 1 < len(sys.argv):
            asmdir = sys.argv[i + 1]
    mk_path = os.path.join(asmdir, "Makefile")
    mk = open(mk_path).read()

    # the `test:` target's prerequisites: from "test:" to the first line that
    # does not end in a continuation backslash
    m = re.search(r'^test:', mk, re.M)
    if not m:
        print("RUNLIST CHECK: no `test:` target found in", mk_path); return 1
    buf = []
    for line in mk[m.end():].split('\n'):
        buf.append(line)
        if not line.rstrip().endswith('\\'):
            break
    prereqs = set(re.findall(r'tests/([A-Za-z0-9_]+)', '\n'.join(buf)))
    runs    = set(re.findall(r'^\t\./tests/([A-Za-z0-9_]+)', mk, re.M))
    srcs    = {os.path.basename(f)[:-2] for f in glob.glob(os.path.join(asmdir, "tests/test_*.c"))}

    problems = []
    for t in sorted(srcs):
        if t in MANUAL or t in HELPERS:
            continue
        has_rule = re.search(r'^tests/%s:' % re.escape(t), mk, re.M) is not None
        if not has_rule:
            problems.append((t, "has no Makefile rule and is not declared manual"))
        elif t not in prereqs:
            problems.append((t, "is not a prerequisite of `test` (may run stale or missing)"))
        elif t not in runs:
            problems.append((t, "is BUILT by `test` but never RUN"))

    # an allowlist entry for a test that no longer exists is stale
    for t in sorted(MANUAL):
        if t not in srcs:
            problems.append((t, "is on the manual allowlist but tests/%s.c does not exist" % t))

    # and a prerequisite that is never run, excluding known helpers
    for t in sorted(prereqs - runs):
        if t in HELPERS or t in MANUAL or not t.startswith("test_"):
            continue
        if all(t != p[0] for p in problems):
            problems.append((t, "is BUILT by `test` but never RUN"))

    if problems:
        print("RUNLIST CHECK FAILED: %d test(s) are neither gated nor declared manual." % len(problems))
        for t, why in problems:
            print("  %-32s %s" % (t, why))
        print("\nFix by adding it to BOTH the `test:` prerequisites and the run list,")
        print("or by adding it to MANUAL in scripts/makefile_runlist_audit.py with a reason.")
        return 1

    manual_here  = set(MANUAL) & srcs
    helpers_here = HELPERS & srcs
    print("RUNLIST CHECK OK: %d test source(s); %d gated, %d declared manual, %d helpers."
          % (len(srcs), len(srcs) - len(manual_here) - len(helpers_here),
             len(manual_here), len(helpers_here)))
    return 0

sys.exit(main())
