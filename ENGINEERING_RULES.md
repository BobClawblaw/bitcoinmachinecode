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

## 5. A pointer into a growable buffer dies at the next growth

**Never hand out (or store) a raw pointer into a buffer that can still be
`realloc()`'d later in the same pass. Hand out a stable offset/index and
resolve it to an address only once the buffer is done growing.**

A per-block byte-pool bump allocator (`bytepool_alloc`, `daemon/tx_verify.c`)
returned a raw pointer into its own `realloc()`-backed buffer, and callers
stored that pointer directly. A LATER input's allocation in the same block's
resolve loop could trigger a `realloc()` that relocated the buffer, silently
dangling every pointer already handed to EARLIER inputs in that same loop —
this reached real production (a "legacy script verification failed"
rejection on real mainnet block data) before being root-caused. It was
non-deterministic across process runs, because whether `realloc()` relocates
depends on that process's own heap layout — which is exactly why an
isolated reproduction of the same code sometimes passed and sometimes
didn't, and is a strong tell for this class of bug when you see it.

**In practice**

- Any allocator whose backing store can grow mid-pass (bump allocators,
  arenas, dynamic arrays) must return something relocation-proof — an
  offset or index — not a pointer, unless the caller can prove the buffer
  is fully sized (no further growth possible) before the pointer is used.
- If a pointer-returning version is kept for convenience, document — at the
  allocator, not just at each call site — exactly when it's safe: only
  after the LAST call into that allocator for the current pass has
  returned.
- A regression test for this shape must force the relocation to actually
  happen (allocate enough total bytes to cross the initial capacity, not
  just call the allocator a couple of times) and then check an
  EARLY-allocated entry's data, not just the last one.

---

## 6. Assembly must honour the SysV stack ABI at every `call`

**At the `call` instruction RSP must be 0 mod 16.** The callee then sees
8 mod 16 on entry (the return address), and its `push rbp` puts the frame back
at 0. Compiler-generated C assumes this and places 16-byte-aligned SSE spills
accordingly.

This repo got the same bug twice. Incident #18 (`b18114b`): `node_serve_loop`
reserved `0x50` after a six-push prologue, leaving RSP at 8 mod 16 at every
nested call. Incident #20 (audit): `script_eval` reserved `0x100` and did the
same thing at all 215 of its call sites, including the C `checksig_fn`
callback on the consensus script path — 43 more functions had the same defect.

Both slept for months, because misalignment is invisible while only assembly
is called: **every `movdqa` in this tree is register-to-register, with no
16-byte-aligned stack operand anywhere.** #18 became lethal when a C log call
landed on the path; #20 would have become lethal at the first `-O2` build or
the first log line. In both cases the faulting instruction was glibc's
`movaps %xmm0,-0xc0(%rbp)` inside `vsnprintf`, and the fault address was
**NULL** — that NULL is the signature of an alignment trap (#GP delivered as
SIGSEGV), not of a null-pointer dereference.

**In practice**

- Compute the parity, do not eyeball it. Entry is 8 mod 16; each `push` and
  each `pop` flips it; the frame reservation must be an ODD multiple of 8
  whenever the push count leaves RSP at 8. A `sub rsp, <multiple of 16>` on
  top of an odd push count is the bug, every time.
- A comment claiming a size is "alignment-neutral" or that the asm callees
  "require" 8 mod 16 is the bug defending itself. Both incidents shipped with
  one. Preserving a misaligned RSP is not neutral.
- A `push`/`call`/`pop` bracket inside a function flips the parity for that
  call only. Pair the push, exactly as `b18114b` did.
- When only ONE call in a function leaves assembly, bracket that call with
  `sub rsp,8` / `add rsp,8` instead of resizing the frame. Resizing changes
  the entry parity delivered to every asm callee below it, and some of them
  may be silently relying on the broken one.
- Before changing a caller's parity, check whether any callee is
  *compensated* — correct only because its caller is wrong.
  `siphash24_uint256.sipround2` is the live example in this tree.
- `make abi-check` (`scripts/abi_stack_audit.py`) proves the property over
  every call site in every `.asm` source. Run it before claiming an assembly
  change is alignment-safe. Run against `b18114b^` it flags #18 directly.

---

## 7. Working on this machine

See the repo README for the full topology. The traps that recur:

- `pkill -f <pattern>` matches the ssh command line itself and kills the
  session. Use explicit PIDs.
- `/tmp` on the host is not writable by the service user.
- Heredocs inside single-quoted ssh commands break on quoting. Write the
  script locally, `scp` it, run it, delete it.
- macOS `sed -i` requires a backup-suffix argument. A failed `sed` in an
  `a && b && c` chain silently skips the rest while a later line still runs.
- Git worktrees embed an absolute path tied to the host that created them.
