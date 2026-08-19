# Engineering rules

Rules earned by breaking things in this repo. Every one cites the incident
that produced it, because a rule without its scar tissue gets argued away.

Written 2026-08-18 after a session that produced four errors of three kinds.

---

## 1. Read before asserting

**Never state a constant, symbol, identifier, or file layout from memory when
the file is on disk.**

Four errors in one session, all this shape:

| claimed from memory | reality |
|---|---|
| Core `dbcache=450`, `maxconnections=125` | 1024 and 200 |
| the asm `ScriptError` numbering matched Core, the C enum was wrong | exactly backwards |
| test vectors named `SS_MS`, `SPK_MS`, `TX_MS` | `SS_23`, `SPK_23`, `SS_1OF1`... |
| a patch anchor `%define SCRIPT_ERR_CLEANSTACK 53` | already regenerated to `30`, and column-padded |

Each was one `grep` away. A wrong premise then propagates into the code, the
test, and the commit message — and the test encodes the same wrong assumption
and passes.

**In practice**

- Do not reference an identifier not read *in this session*. `grep` it.
- Core facts come from `/storage/bitcoin-core-source/src` (full source tree)
  or `/storage/bitcoin/bin/bitcoind --help`. Never recall.
- Never hand-count an implicitly-numbered C enum. Generate the mapping and let
  a script own it — see `validation/gen_script_error_defines.py`.
- Re-read a file before writing a patch anchor against it. Its state earlier
  in the same session is not its state now.
- "Should be" or "presumably" about something checkable means stop and check.

---

## 2. Verification must prove the outcome, not a proxy

**A green test, a log line, and exit 0 are all proxies. Assert the
post-condition the feature exists to produce.**

- Seven green `PASS` lines while a destructive test **deleted a ~600GB
  archive**. It asserted on `index.dat` record counts and never opened a block
  file.
- `listen=0` was reported verified because the log line appeared and the
  process exited 0. It printed the line and *died* — the caller treated an
  intentional `-1` as fatal. **Exit 0 from a daemon that should still be
  running is a failure signal, not a pass.**
- `archive_check`'s unit tests passed while its reader was wrong: it read
  bodies at `data_pos` instead of `data_pos + 8` (an 8-byte frame precedes
  every block). The fixture wrote bare payloads at `data_pos` — the same wrong
  assumption as the code — so both were wrong together. Only a live run
  against a real archive exposed it, and then *every* block reported corrupt.
- Twelve tapscript assertions broke when the interpreter was corrected. They
  hard-coded absolute error numbers, so they pinned the old behaviour.

**In practice**

- Ask what post-condition the feature exists to produce and assert that. Still
  running? Actually connected? Data still present and readable?
- Build fixtures from the FORMAT SPEC, not from what the code under test
  assumes. A fixture mirroring the implementation tests nothing.
- Prefer asserting **agreement with an independently validated reference**
  over absolute values. Absolute-value assertions rot, then pin the bug.
  `tests/test_scriptverify_parity.c` compares against an implementation
  already differentially validated against Core — that shape survives
  renumbering.
- A feature that has only ever passed a unit test is unverified. Run it
  against real data before saying it works.
- Report a red suite immediately, before fixing it.

---

## 3. Destructive tools get proven on a copy first

Two incidents, one cause: **a destructive operation run on real data before
being proven on a fixture.**

**Archive loss.** `store_truncate_to` assumes blocks were appended in
increasing height order. It was called to "repair" an archive whose diagnosed
defect *was* out-of-order blocks. It cut the first block file and unlinked
~4,855 more. The contradiction was in the commit message written minutes
earlier.

**Generator ate 23 defines.** A script rewriting `bitcoin_interp.asm`'s
`%define` block, pointed straight at the real file. It WROTE column-padded
lines but PARSED expecting single spaces, so a second run matched only the one
unpadded name and spliced a one-line block over the range — destroying 23 of
24 consensus error codes. Recovered by `git checkout` only because the file
had been committed a minute earlier.

**In practice**

1. Before calling a destructive primitive, state its PRECONDITION and check
   the data satisfies it. "The data is malformed" is a red flag, never a
   justification, for a primitive that assumes well-formed data.
2. Put the guard IN the primitive, not in one caller — other callers exist.
   (`store_truncate_to` now calls `store_layout_monotonic` itself.)
3. Any tool rewriting a tracked file in place: run against a COPY, diff it,
   and only then touch the real path. Default to trial; require `--apply`.
4. An in-place rewriter must be IDEMPOTENT and SELF-CHECKING — re-read its own
   output and assert it round-trips. **A tool that cannot read what it writes
   is a destructive tool, not a generator.**
5. Add a plausibility floor: refuse to rewrite when the parse yields far fewer
   items than expected. That is exactly what a broken pattern looks like.
6. Commit immediately BEFORE running such a tool. This is the entire
   difference between the two incidents above.
7. Refusing to act leaves a recoverable system; destroying data does not.
   When in doubt, refuse and log loudly.

---

## 4. Consensus code specifics

- The **asm is authoritative**. Consensus semantics live in `.asm`; C is a
  thin wrapper with no semantic content. Where the two disagree, the asm is
  fixed — not wrapped in a translation layer.
- Core's error codes are **generated**, never transcribed:
  `validation/gen_script_error_defines.py` reads Core's `script_error.h` and
  emits both the asm `%define` block and `asm/script_error_codes.h`. Re-run it
  after a Core upgrade.
- Watch for **raw numeric error codes**. `interp_checkmultisig` stored
  `interp_err` as literal `20` and `12` — matching no numbering scheme at all
  — and they silently survived a generated renumbering. Grep for raw stores,
  not just symbolic ones.
- A division of responsibility that cannot be implemented is a bug. The
  interpreter documented NULLDUMMY as "the caller enforces it", but it pops
  the dummy during operand cleanup, so no caller can see it. The result: the
  interpreter **accepted a spend Core rejects**.

---

## 5. Working on this machine

See the repo README for the full topology. The traps that recur:

- `pkill -f <pattern>` matches the ssh command line itself and kills the
  session. Use explicit PIDs.
- `/tmp` on the host is not writable by the service user.
- Heredocs inside single-quoted ssh commands break on quoting. Write the
  script locally, `scp` it, run it, delete it.
- macOS `sed -i` requires a backup-suffix argument. A failed `sed` in an
  `a && b && c` chain silently skips the rest while a later line still runs.
- Git worktrees embed an absolute path tied to the host that created them.
