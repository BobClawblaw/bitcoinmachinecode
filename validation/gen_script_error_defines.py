#!/usr/bin/env python3
"""Emit bitcoin_interp.asm's SCRIPT_ERR_* defines from Core's script_error.h.

The asm interpreter is the AUTHORITATIVE consensus implementation, so it must
report Core's own ScriptError values directly rather than have a C layer
translate them. Hand-transcribing an enum whose members are implicitly
numbered is exactly how the wrong values got asserted here once already, so
the mapping is generated, never typed.

Re-run after a Core upgrade; a name that disappears from Core is reported
rather than silently kept.

2026-08-20: this used to only VALUE-CHECK names the asm already defined --
it never checked the reverse direction (a name Core has that the asm simply
never typed in the first place), so a missing define was invisible to it
forever. Found the hard way: SCRIPT_ERR_CHECKMULTISIGVERIFY was never in
bitcoin_interp.asm's list at all (nothing needed it until a real mainnet
CHECKMULTISIGVERIFY bug did), and this script ran clean the whole time
because it only ever iterated the asm's own (incomplete) list. It now walks
Core's enum too and ADDS any name the asm is missing, not just reports it --
"generated, never typed" only holds if that's true for new names as well as
existing ones.

Also: ASM/CHDR used to be hardcoded to this project's pre-rename absolute
path (/storage/bmc-scriptverify), which no longer exists -- this script
could not have run successfully since that rename regardless of the
one-directional check above. They are now derived from this script's own
location instead, so running it inside any worktree (not just the main
checkout) rewrites THAT worktree's files, matching how every other change
in this repo is made and tested in isolation before merging.
"""
import re, sys, os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HDR = "/storage/bitcoin-core-source/src/script/script_error.h"
ASM = os.path.join(REPO_ROOT, "asm", "bitcoin_interp.asm")
CHDR = os.path.join(REPO_ROOT, "asm", "script_error_codes.h")

# --- parse Core's enum: implicit numbering, comments and blank lines ignored
body = open(HDR).read()
m = re.search(r"typedef enum ScriptError_t\s*\{(.*?)\}", body, re.S)
if not m: sys.exit("could not find ScriptError_t enum in " + HDR)
body = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)
body = re.sub(r"//.*", "", body)

core, nxt = {}, 0
for tok in body.split(","):
    tok = tok.strip()
    if not tok: continue
    if "=" in tok:
        name, val = tok.split("=", 1)
        name = name.strip(); nxt = int(val.strip(), 0)
    else:
        name = tok
    if not re.fullmatch(r"SCRIPT_ERR_[A-Z0-9_]+", name):
        sys.exit("unexpected enumerator: %r" % tok)
    core[name] = nxt
    nxt += 1
print("parsed %d Core ScriptError values" % len(core))

# --- read the names the asm currently defines, preserving order
asm = open(ASM).read()
# NOTE: the block this script writes is COLUMN-PADDED, so the pattern must
# tolerate runs of whitespace. It originally required a single space, which
# meant a second run matched only the longest (unpadded) name, spliced a
# one-line block over the range, and destroyed 23 of the 24 defines. A
# generator that cannot re-read its own output is a destructive tool.
defs = re.findall(r"^%define (SCRIPT_ERR_[A-Z0-9_]+)[ \t]+(\d+)[ \t]*$", asm, re.M)
if not defs: sys.exit("no SCRIPT_ERR defines found in " + ASM)
EXPECT_MIN = 20
if len(defs) < EXPECT_MIN:
    sys.exit("only %d defines parsed (expected >=%d) -- refusing to rewrite %s, "
             "this is what a bad pattern looks like" % (len(defs), EXPECT_MIN, ASM))

missing, seen, lines, changed = [], set(), [], 0
for name, old in defs:
    seen.add(name)
    if name not in core:
        missing.append(name); continue
    new = core[name]
    if int(old) != new: changed += 1
    lines.append((name, old, new))       # old kept as str; None means "new entry"

if missing:
    sys.exit("asm defines names Core does not have: %s" % ", ".join(missing))

# --- the other direction: a name Core has that the asm never defined at all.
# Value-checking existing entries can never catch this -- there is no entry
# to check. Add these too rather than merely reporting them; a generator
# that only fixes known-wrong values but not known-missing ones still leaves
# hand-typing as the only way new error codes ever reach the asm.
added = sorted((n for n in core if n not in seen), key=lambda n: core[n])
for name in added:
    lines.append((name, None, core[name]))

if added:
    print("\nadding %d name(s) Core has that the asm never defined: %s"
          % (len(added), ", ".join(added)))

# --- re-sort the whole block by Core's canonical numeric value. Once names
# can be added, preserving the old (arbitrary, insertion-order) layout would
# mean deciding where a new name "belongs" textually; sorting by value is
# unambiguous, deterministic, and matches how the C header below is already
# ordered.
lines.sort(key=lambda t: t[2])

width = max(len(n) for n, _, _ in lines)
out = ["%%define %-*s %d" % (width, n, v) for n, _, v in lines]

print("\n%-*s  old -> new" % (width, "name"))
for n, o, v in lines:
    if o is None:
        print("%-*s  NEW -> %3d" % (width, n, v))
    else:
        print("%-*s  %3s -> %3d%s" % (width, n, o, v, "   CHANGED" if int(o) != v else ""))
print("\n%d value(s) changed, %d name(s) added, %d total" % (changed, len(added), len(lines)))

# --- emit the C header too, so tests and C wrappers cannot drift either.
#     The tapscript test carried its own hand-written enum with the pre-Core
#     values; when the asm was corrected it reported 12 failures that were all
#     the TEST being stale. One generated source removes that failure mode.
h = ["/* GENERATED by validation/gen_script_error_defines.py -- DO NOT EDIT.",
     " * Bitcoin Core ScriptError values, read from Core's own script_error.h.",
     " * The asm interpreter (bitcoin_interp.asm) is the authoritative consensus",
     " * implementation and emits these values directly; this header exists so C",
     " * tests and wrappers compare against the same numbers rather than a",
     " * hand-copied enum. Re-run the generator after a Core upgrade. */",
     "#ifndef SCRIPT_ERROR_CODES_H", "#define SCRIPT_ERROR_CODES_H", ""]
cw = max(len(n) for n in core)
for n, v in sorted(core.items(), key=lambda kv: kv[1]):
    h.append("#define %-*s %d" % (cw, n, v))
h += ["", "#endif", ""]
open(CHDR, "w").write("\n".join(h))
print("wrote", CHDR, "with", len(core), "values")

# --- splice the new block in, in place
start = asm.index("%define SCRIPT_ERR_OK")
end   = asm.index("\n", asm.rindex("%define SCRIPT_ERR_"))
open(ASM, "w").write(asm[:start] + "\n".join(out) + asm[end:])
print("rewrote the define block in", ASM)

# --- self-check: re-read and re-parse. If this script cannot recover its own
#     output, it must not be trusted to run a second time.
again = re.findall(r"^%define (SCRIPT_ERR_[A-Z0-9_]+)[ \t]+(\d+)[ \t]*$",
                   open(ASM).read(), re.M)
got = {n: int(v) for n, v in again}
want = {n: v for n, _, v in lines}
if got != want:
    sys.exit("SELF-CHECK FAILED: re-parsed %d defines, expected %d; "
             "the output is not readable by this script's own pattern"
             % (len(got), len(want)))
print("self-check ok: %d defines re-parse to the intended values" % len(got))
