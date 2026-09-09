# 2026-09-09 — A block another leg just stored is not the peer's fault

Production's first hour on snapshot n closed six legs an hour as `ours/sync-failed-3x ... where=10`. Failure code 10 is the archive refusing a duplicate: a sibling leg had stored the same block moments earlier, so the append found it not tip-linked. The pass was ending with `.fail`, which do_outbound_sync counted as a strike against the peer; three of them retired a healthy leg.

- **A refused duplicate ends the pass well** (`.done`, ok=1): the code stays set for the log, and the next rotation rebuilds the locator from the true tip, exactly the recovery the comment beside it already described.
- **The fetch gate refuses a hash the store already holds** (`idx_get` on the worker's hash index) before claiming it in the in-flight table, so the duplicate is not fetched at all. The in-flight counter's "duplicate fetches avoided" now counts both.

`test_sync_dup` (new, **watched to fail**: where=10, the pass failed): a first peer stores block 0; a second peer, asked from a stale locator, serves it again; the pass ends well with nothing counted and the next pass, from the true tip, fetches block 1. Its own binary because the archive's hash index is process-global. `test_dialhelper`: the gate refuses a known hash, claims a fresh one for this leg, refuses it to another leg while the claim lives, and frees it when the pass ends.

---

PR #152 (`batch/2026-09-09-duplicate-block`), merged 22:5xZ as `1081365e`; tag `duplicate-block-2026-09-09`. Gate MAKE_EXIT 0, 348 passes. Staged as `deploy-20260909o`; production runs n.
