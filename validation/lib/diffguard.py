"""diffguard -- refuse to report success for a differential that compared nothing.

WHY. Every *_diff.py here ends with the same shape:

    fails = 0
    for name, case in cases.items():
        ...
    print(f"ALL {len(cases)} MATCH" if not fails else ...)
    sys.exit(1 if fails else 0)

With an empty `cases` the loop never runs, `fails` stays 0, and the tool prints
"ALL 0 MATCH" and exits 0. A differential that compared nothing reports success.

That is not hypothetical. The muhash capstone did exactly this for months: its
walk timed out, an empty result compared equal to an empty oracle value, and
every benchmark run "passed" a check that had never executed. It took a real
divergence -- and a day of chasing a node defect that did not exist -- to find
out. None of the 12 differential tools in this directory guards against it.

The second failure is quieter and more likely: a tool whose cases come from
several sources (synthetic vectors plus live ones pulled from an oracle) still
passes when one source silently yields nothing. It tests less than it claims and
says nothing about the difference.
"""
import sys


def require_cases(n, what, minimum=1):
    """Exit 2 unless at least `minimum` cases were collected.

    Exit 2, not 1: a differential that could not run is not the same answer as
    a differential that ran and found a mismatch, and a caller diffing exit
    codes should not have to guess which happened.
    """
    if n < minimum:
        print(f"REFUSING TO REPORT: collected {n} {what} (need at least {minimum}).",
              file=sys.stderr)
        print("A differential that compares nothing is not a passing differential.",
              file=sys.stderr)
        sys.exit(2)
    return n


def require_sources(counts, minimum=1):
    """Every named source must have contributed at least `minimum` cases.

    `counts` maps a source name to how many cases it produced, e.g.
    {"synthetic": 40, "real": 0}. The zero is the point: without this, a tool
    whose live source went quiet still prints ALL 40 MATCH and exits 0.
    """
    empty = sorted(k for k, v in counts.items() if v < minimum)
    if empty:
        detail = ", ".join(f"{k}={counts[k]}" for k in sorted(counts))
        print(f"REFUSING TO REPORT: these case sources produced nothing: "
              f"{', '.join(empty)}  ({detail})", file=sys.stderr)
        print("The run would have reported success while testing less than it claims.",
              file=sys.stderr)
        sys.exit(2)
    return sum(counts.values())
