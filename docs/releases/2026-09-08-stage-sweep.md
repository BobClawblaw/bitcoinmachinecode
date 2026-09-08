# 2026-09-08 — Stale staged chunks are swept and the staged gauge is the directory's count

Run 18 held six staged files wholly below the committer's cursor: a chunk's owner finished after a cursor helper had already delivered it and published its copy over nothing. They stayed forever (the committer only looks at the cursor's chunk) and inflated the staged gauge that gates the cursor help, which then fired on chunks whose owner was still delivering.

- The worker discards a finished chunk whose heights are already committed instead of publishing it.
- The committer sweeps files wholly below the cursor after every commit and discard, and sets the gauge to the count of published chunks in the directory, so it cannot drift.
- Worklog session 30 and the facade note's lock section.

`test_dialhelper`: two stale chunks below cursor 180 are swept, two above stay, the gauge is recounted (2, not the 99 it was set to); the cursor-help check stages a third of the window as real files. Verified live on run 18: zero stale files after the resume, no spurious cursor helps. Gate `make -j8 test`: 0 failures (one expected test_rpc_signer segfault); 8 static audits exit 0.

---

PR #104 (`batch/2026-09-08-stage-sweep`), merged 10:21Z as `85d22cea`; tag `stage-sweep-2026-09-08`.
