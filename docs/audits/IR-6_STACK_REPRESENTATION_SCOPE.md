# IR-6 — OP_ROLL moves whole records; the stack representation

Scoping report, 2026-09-05. Companion to `INTERP_REVIEW_2026-09-05.md` (IR-6,
HIGH) — the one finding of that review still open.

**Status: scoped, correctness pinned, not started.** The fix is a change to the
stack representation, and the representation is part of an ABI the daemon's C
verifier and five test harnesses depend on. It wants its own branch, the
differential harnesses extended first, and its own review.

---

## The defect

`stack_erase_index` (`bitcoin_scriptcodec.asm:905`) removes the element at an
index by shifting every record above it down one slot, each shift an
`elem_move` of `len + 4` bytes — 524 for a max-size item. Core moves a 24-byte
vector header. `OP_ROLL` is erase + append, so a tapscript leaf of
`<998> OP_ROLL` repeated is O(rolls × records) in bytes moved, and tapscript
caps neither script size nor opcode count.

**The cost model is confirmed, not estimated.** 60,000 rolls over 999
items of 520 bytes moves ~31 GB and takes **669 ms** on this machine
(`test_scr_interp_bounds`, IR-6 vector b). Scaled to the ~850,000 rolls a
3.4 MB leaf holds: ~445 GB, ~9.6 s — matching the review's own measurement of
10.9 s. Every block, from one consensus-valid input, worse on a slower node.

## Why it is not a contained edit

Two facts decide the shape of any fix:

* **The interpreter is clean.** `bitcoin_interp.asm` never computes a record
  address itself — every access goes through `stack_top_ptr`,
  `stack_elem_ptr`, `stack_dup_index` and friends. A representation change
  confined to those primitives would be invisible to it.
* **Every caller outside the interpreter is not.** `bitcoin_scriptverify.c`
  defines `sv_rec(s,i) = s->e + i*ELEM_SIZE`, `sv_len` reads the length at
  `+0` and `sv_dat` the data inline at `+ELEM_DATA_OFF`. The asm driver
  mirrors it, and `test_interp.c`, `test_scr_interp_bounds.c`,
  `test_scr7_cms_bounds.c`, `test_stack_push_len.c` and
  `test_tapscript_scale.c` build initial stacks and read final ones the same
  way.

So "position p's record lives at `elems + p*ELEM_SIZE`, data inline" is a
published ABI. Both ways of making the shift cheap break it:

| Option | Shift cost | What it breaks |
|---|---|---|
| **A. Handle table** — positions index a table of slot numbers; records never move | 4 bytes/record | slot order stops matching position order, so every direct indexer reads the wrong element |
| **B. Descriptor records** — `{len, data*}` in the array, bytes in a per-stack arena (Core's own shape) | 16 bytes/record | data is no longer inline at `rec+ELEM_DATA_OFF` |

Option A can be made ABI-preserving by normalising at the boundaries:
identity table on entry, records physically permuted once to match handles on
exit — O(sp) each, against O(rolls × records) saved. The open question is
where the per-stack handle state lives: the primitives take `(&sp, elems)`
with no room for it, main and alt stacks are live at once, and thread-local
state must not be shared between them. Answering that likely means giving the
primitives a `stack_t*` that bundles `(sp, elems, handles)` — which touches
every call site in the interpreter and every external caller, i.e. the same
blast radius as B.

## What is already done

The safety net is in place at both levels: directly through `script_eval`
(below) and through `sv_run_v` in `test_checksig_diff` (step 1).

`test_scr_interp_bounds` pins the correctness the change must preserve, so the
refactor has a safety net before it starts:

* **(a)** BASE, 25 rolls over 10 items — the **full** final order is asserted
  element by element (no CLEANSTACK there to force a drain).
* **(b)** tapscript, 60,000 rolls over 999 × 520-byte items, drained to one
  element because CLEANSTACK is consensus — the survivor is the old bottom,
  `R mod 999`, which a wrong rotation gets wrong. Reports the time and fails
  above a generous 8 s ceiling.

The time bound is deliberately **not** the perf assertion: it is a ceiling
against a pathological regression. The O(1)-per-roll assertion lands with the
representation change, and gets the revert-the-fix treatment then.

## The order of work

1. ~~Extend the driver differentials to compare stack contents.~~ **Corrected,
   and done differently.** `test_svs_drv_diff` and `test_wv0_drv_diff` compare
   verdicts only, and cannot do otherwise: `sv_verify_script` owns its stacks
   internally, and both "drivers" call the same asm interpreter, so a change
   inside the primitives moves both sides identically. The differential that
   *does* compare stack contents byte for byte is `test_checksig_diff`, whose
   `diff_run` memcmps `sp * ELEM_SIZE` after running a script through
   `sv_run_v` with a caller-owned stack. Six rolling vectors (roll, roll+swap,
   roll x3, tuck-after-roll, pick-after-roll, and the depth-0 no-op) were added
   there, so the ABI contract the change must preserve — element `p` readable
   at `elems + p*ELEM_SIZE`, data inline, after rolling — is asserted at that
   level too, not only through `script_eval` directly.
2. Decide A-with-normalisation versus B on the evidence of (1); B is closer to
   Core and admits an easier differential.
3. Change the representation and every direct indexer in one branch.
4. Tighten the IR-6 ceiling to the O(1) assertion; revert-control it.

Until then IR-6 stays open in `INTERP_REVIEW_2026-09-05.md` §7, and this file
is the reason why.
