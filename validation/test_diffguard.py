#!/usr/bin/env python3
"""Tests for diffguard -- the refusal that stops a differential reporting
success after comparing nothing. Run: python3 validation/test_diffguard.py"""
import os, subprocess, sys

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib")
sys.path.insert(0, LIB)
from diffguard import require_cases, require_sources  # noqa: E402

passed = failed = 0
def ck(name, ok):
    global passed, failed
    if ok: print(f"ok  : {name}"); passed += 1
    else:  print(f"FAIL: {name}"); failed += 1

def exits_with(fn, code):
    """Run fn in a child so sys.exit is observable; return True if it exited `code`."""
    src = (f"import sys; sys.path.insert(0, {LIB!r}); from diffguard import "
           f"require_cases, require_sources; {fn}")
    r = subprocess.run([sys.executable, "-c", src], capture_output=True, text=True)
    return r.returncode == code

print("== require_cases ==")
ck("a healthy count passes through and returns n", require_cases(40, "things") == 40)
ck("zero cases exits 2, not 0",        exits_with('require_cases(0, "things")', 2))
ck("...and 2 is distinct from 1",      not exits_with('require_cases(0, "things")', 1))
ck("below an explicit minimum exits 2", exits_with('require_cases(3, "things", minimum=10)', 2))
ck("exactly the minimum passes",        exits_with('require_cases(10, "things", minimum=10); sys.exit(0)', 0))

print("== require_sources ==")
ck("every source populated -> total returned",
   require_sources({"synthetic": 40, "real": 12}) == 52)
# The quiet failure: one source goes silent and the tool still says ALL MATCH.
ck("ONE empty source exits 2 even though others have cases",
   exits_with('require_sources({"synthetic": 40, "real": 0})', 2))
ck("all sources empty exits 2",
   exits_with('require_sources({"synthetic": 0, "real": 0})', 2))
ck("an explicit minimum is honoured per source",
   exits_with('require_sources({"synthetic": 40, "real": 3}, minimum=5)', 2))

print("== the shape this exists to stop ==")
# Reproduce the original bug: an empty case dict, summarised the old way.
cases = {}
fails = 0
summary = f"ALL {len(cases)} MATCH" if not fails else "DIFFS"
ck("the OLD shape really does report success on zero cases", summary == "ALL 0 MATCH")
ck("...and the guard refuses that exact input", exits_with('require_cases(0, "cases")', 2))

print("== the ratchet: unguarded differentials may shrink, never grow ==")
# All 17 *_diff.py tools are now guarded (2026-09-13). The ratchet stays at 0 so
# a NEW differential that forgets the guard fails here rather than shipping able
# to report "ALL 0 MATCH" over an empty case set. Raise this only with a reason.
UNGUARDED_MAX = 0
here = os.path.dirname(os.path.abspath(__file__))
unguarded = []
for fn in sorted(os.listdir(here)):
    if not fn.endswith("_diff.py"):
        continue
    body = open(os.path.join(here, fn), encoding="utf-8", errors="replace").read()
    if "require_cases" not in body and "require_sources" not in body:
        unguarded.append(fn)
ck(f"unguarded differentials <= {UNGUARDED_MAX} (found {len(unguarded)})",
   len(unguarded) <= UNGUARDED_MAX)
ck(f"the bound is tight -- lower it when one is converted (found {len(unguarded)})",
   len(unguarded) == UNGUARDED_MAX)
if unguarded:
    print("      still unguarded: " + ", ".join(unguarded))

print(f"\npassed {passed}, failed {failed}")
sys.exit(1 if failed else 0)
