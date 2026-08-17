#!/usr/bin/env python3
# hole_ranges.py -- list contiguous missing-height ranges in index.dat, so
# unified_ibd can be re-run with EXPLICIT sub-tip ranges (its resume logic
# does not auto-detect holes; it only extends past the last stored height).
#
# Usage: hole_ranges.py <data_dir> [--merge-gap N] [--span]
#   Prints one "<start> <end>" line per range (inclusive).
#   --merge-gap N (default 2000): coalesce holes separated by <=N already-
#   -stored heights into one range, trading a bit of redundant re-download
#   for far fewer unified_ibd invocations (each has real worker-startup and
#   peer-handshake overhead). Irrelevant with --span (see below).
#   --span: print ONE line "<first_hole_start> <tip>" instead of the
#   per-hole list -- the combined span a single unified_ibd invocation can
#   cover in one process, since its worker chunks now skip already-archived
#   heights on their own (chunk_all_present in unified_ibd.c), so handing it
#   the whole span is safe and avoids a process-relaunch (with a fresh
#   ~20s peer re-probe) between every hole.
import sys, os

def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <data_dir> [--merge-gap N]", file=sys.stderr)
        return 2
    data_dir = sys.argv[1]
    merge_gap = 2000
    if "--merge-gap" in sys.argv:
        merge_gap = int(sys.argv[sys.argv.index("--merge-gap") + 1])

    path = os.path.join(data_dir, "index.dat")
    D = open(path, "rb").read()
    n = len(D) // 48
    zero = b"\x00" * 32
    present = [D[h*48:h*48+32] != zero for h in range(n)]
    recs = [h for h in range(n) if present[h]]
    if not recs:
        print("empty archive", file=sys.stderr)
        return 0
    tip = max(recs)

    # raw holes: contiguous runs of missing heights within [0, tip]
    raw = []
    h = 0
    while h <= tip:
        if not present[h]:
            start = h
            while h <= tip and not present[h]:
                h += 1
            raw.append((start, h - 1))
        else:
            h += 1

    # coalesce holes separated by a short filled run (<= merge_gap)
    merged = []
    for start, end in raw:
        if merged and start - merged[-1][1] - 1 <= merge_gap:
            merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))

    total_hole_heights = sum(e - s + 1 for s, e in raw)
    total_covered = sum(e - s + 1 for s, e in merged)
    print(f"# tip={tip} raw_holes={len(raw)} merged_ranges={len(merged)} "
          f"hole_heights={total_hole_heights} covered_heights={total_covered} "
          f"(redundant_redownload={total_covered - total_hole_heights})",
          file=sys.stderr)

    if "--span" in sys.argv:
        if not raw:
            print("no holes", file=sys.stderr)
            return 0
        # end MUST be < tip (strictly) or unified_ibd's resume logic treats
        # it as a forward-resume request and jumps straight to tip+1,
        # silently skipping every hole (the tip height itself is never a
        # hole -- it's non-zero by definition -- so tip-1 loses nothing).
        print(raw[0][0], tip - 1)
        return 0

    for s, e in merged:
        print(s, e)
    return 0

if __name__ == "__main__":
    sys.exit(main())
