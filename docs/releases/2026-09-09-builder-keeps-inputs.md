# 2026-09-09 — The coinstats builder keeps a pass's inputs until it completes

The second self-repair attempt died right after pass 1's marker (the Claude Code harness stopped the background task that had launched it, on a memory heuristic, with 100 GB free). The resumed pass 2 joined half-empty buckets and reported 22 million unmatched spends: the loader had been deleting each bucket file as it read it, so the dead pass 2 had already consumed part of pass 1's output.

- A pass keeps its inputs until it completes: bucket files go after pass 2's marker, range files after pass 3's; a resume that finds its inputs missing starts over. Peak disk is roughly twice the consumed estimate (about 830 GB was free).
- `test_coinstats_hist_build`: outputs present for the next pass, removed after its marker, a marker with a missing bucket starts over with the clean digest; **watched to fail** on the consuming builder. Gate `make -j8 test`: MAKE_EXIT 0, 0 failures (the expected test_rpc_signer segfault); audits exit 0.

---

PR #135 (`batch/2026-09-09-builder-keeps-inputs`), merged 04:05Z as `1651290d`; tag `builder-keeps-inputs-2026-09-09`. The third rebuild (03:50Z, from scratch) completed and was adopted at 06:10Z.
