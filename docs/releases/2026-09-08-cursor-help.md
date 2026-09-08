# 2026-09-08 — The committer asks for its stalled cursor chunk once the pool has moved on

Run 18 on the in-order committer sat six minutes at 484,201: one trickling peer held the chunk at the committer's cursor while 85 chunks above it were staged, and the only help path fired when the window was full and a worker had waited 2 s at it. Before the committer the same peer left a hole while "stored" kept rising; now the committed tip is the truth and the stall is too.

The committer publishes the chunk it has waited on for 10 s once at least 8 chunks are staged above it (the pool has moved on; a bare clock fired five duplicate downloads in four minutes at height 490,000, where a 40-block chunk is 40 MB); a worker takes it at its next claim as a helper, one at a time; the want clears the moment the chunk commits. The tick line counts cursor helps.

Also corrects the operations doc: the txospender index is 98 GB on mainnet (measured), not 35.

Test: `test_dialhelper` runs the committer in a child on a shared control block with a 300 ms seam: nothing staged above -> not published; 8 staged -> published after the delay; committed and cleared when the chunk appears; the next missing chunk published in turn; STOP ends the run. Gate `make -j8 test`: 0 failures (one expected test_rpc_signer segfault); 8 static audits exit 0.

---

PR #101 (`batch/2026-09-08-cursor-help`), merged 09:35Z as `e50165a9`; tag `cursor-help-2026-09-08`.
