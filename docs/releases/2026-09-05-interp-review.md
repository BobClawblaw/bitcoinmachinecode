# 2026-09-05 — interpreter review closed; MuHash re-verified; fresh clone builds

One line per batch is what `git log --first-parent main` shows from here; this
file is the paragraph behind the line. Details, proofs and IDs live in the
documents it points to.

- **Script interpreter review** (`docs/audits/INTERP_REVIEW_2026-09-05.md`):
  17 findings from an in-session code review of the four interpreter files;
  13 closed by ID, each with a test watched to fail first — two consensus
  false-accepts (`IR-1` stack cap, `IR-2` DER hashtype bound), one latent
  (`IR-3`), three valid-block DoS shapes (`IR-4` O(1) condition stack,
  `IR-5` per-transaction sighash memo, `IR-7`), two policy gaps, one
  memory-unsafety, four LOWs, and `IR-6` -- the stack representation, closed
  last: rolls now rotate 4-byte handles instead of 524-byte records
  (2203 ms -> 49 ms on a 200,000-roll storm) with the external stack ABI
  untouched. `IR-11`/`IR-15`/`IR-16` are tracked, accepted or deferred with
  reasons. Nothing from that review is open.
- **MuHash** (`validation/muhash_vs_core.sh`): the "byte-identical to Core"
  claim re-made from two independently synced datadirs at 965,651 and made
  re-runnable; the 963,967 record of 2026-08-25 confirmed against Core today.
- **Fresh clone** (`scripts/makefile_link_audit.py`): `make test` no longer
  aborts at link-check on a tree with no objects.
- **Real-mined transaction corpus** (`docs/reports/MINED_TX_CORPUS.md`): 17
  chain transactions verified at their own heights, with the coverage gaps
  named.
