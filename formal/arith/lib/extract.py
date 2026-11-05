#!/usr/bin/env python3
"""Pull product source text into a proof harness, verbatim, at run time.

The harnesses never carry a copy of the code they verify: run.sh calls this
script to cut the exact text out of the product file each time, so a change
to the product is a change to what is proved.

  extract.py FILE func NAME          the definition of function NAME (from its
                                     signature line to its closing brace)
  extract.py FILE block REGEX        the brace block whose body contains the
                                     first line matching REGEX: walks back to
                                     the nearest line that is only "{", then
                                     forward to its matching "}"
  extract.py FILE lines START END    from the first line matching START to the
                                     first later line matching END, inclusive
  extract.py FILE typedef NAME       "typedef struct { ... } NAME;"

Fails (exit 1) if the anchor is missing or matches more than once, so a
refactor that moves the code breaks the proof loudly instead of silently
proving nothing. Output carries a #line directive back to the product file.
"""
import re
import sys


def die(msg):
    sys.stderr.write("extract.py: " + msg + "\n")
    sys.exit(1)


def brace_end(lines, start):
    depth = 0
    seen = False
    for i in range(start, len(lines)):
        # strip string/char literals and comments well enough for this tree
        s = re.sub(r'"(\\.|[^"\\])*"', '""', lines[i])
        s = re.sub(r"'(\\.|[^'\\])'", "''", s)
        s = re.sub(r"/\*.*?\*/", "", s)
        s = s.split("//")[0]
        for ch in s:
            if ch == "{":
                depth += 1
                seen = True
            elif ch == "}":
                depth -= 1
                if seen and depth == 0:
                    return i
    die("unbalanced braces from line %d" % (start + 1))


def unique(lines, rx, what):
    hits = [i for i, l in enumerate(lines) if re.search(rx, l)]
    if len(hits) != 1:
        die("%s: anchor %r matched %d lines (need exactly 1)" % (what, rx, len(hits)))
    return hits[0]


def main():
    if len(sys.argv) < 4:
        die("usage: extract.py FILE MODE ARG [ARG]")
    path, mode = sys.argv[1], sys.argv[2]
    with open(path) as f:
        lines = f.read().split("\n")
    if mode == "func":
        name = sys.argv[3]
        s = unique(lines, r"^[A-Za-z_][\w \*]*\b%s\s*\(" % re.escape(name), "func " + name)
        e = brace_end(lines, s)
    elif mode == "block":
        k = unique(lines, sys.argv[3], "block")
        s = k
        while s >= 0 and lines[s].strip() != "{":
            s -= 1
        if s < 0:
            die("no opening brace line before anchor")
        e = brace_end(lines, s)
        if e < k:
            die("anchor is not inside the block found")
    elif mode == "lines":
        s = unique(lines, sys.argv[3], "lines start")
        e = None
        for i in range(s, len(lines)):
            if re.search(sys.argv[4], lines[i]):
                e = i
                break
        if e is None:
            die("end anchor not found")
    elif mode == "typedef":
        name = sys.argv[3]
        e = unique(lines, r"^\}\s*%s\s*;" % re.escape(name), "typedef " + name)
        s = e
        while s >= 0 and not lines[s].startswith("typedef struct"):
            s -= 1
        if s < 0:
            die("typedef start not found")
    else:
        die("unknown mode " + mode)
    rel = path[path.rfind("/asm/") + 1:] if "/asm/" in path else path.split("/")[-1]
    sys.stdout.write('#line %d "%s"\n' % (s + 1, rel))
    sys.stdout.write("\n".join(lines[s:e + 1]) + "\n")


if __name__ == "__main__":
    main()
