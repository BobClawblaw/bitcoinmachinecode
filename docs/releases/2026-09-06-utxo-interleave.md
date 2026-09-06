# 2026-09-06 — UTXO connect interleaved with the parallel download (step 1)

On the last benchmark the UTXO set was built *after* the 19.5 h download,
in a 4.5 h catch-up the download's own worker spent in a 10 s sleep loop
while sixteen helpers fetched blocks. `dl_catchup` now connects under an 8 s
budget between reaps, stopping at the first hole in the archive; the
catch-up that used to follow the download runs under it.

- `utxo_live_catchup_bounded(store, max_ms, stop_at_hole)` shares the whole
  connect loop with the unbounded call; the budget is checked where the
  shutdown flag is, after a block.
- A block rejected mid-download stops the helpers before the archive is
  truncated, then the rotation takes the heavier chain that avoids the mark.
- **Caveat that changes the benchmark recipe:** the boot-time catch-up runs
  in the parent before the UTXO writer exists and cannot interleave. A
  fresh-clone run of this step needs `bmc.bootcatchup=0` so the worker's
  far-behind trigger owns the download. Moving boot catch-up into the worker
  is the next change on this path.
- Found on the way, not fixed: outbound sockets lack `TCP_NODELAY` and
  `p2p_write` is two writes; a loopback getdata cost ~45 ms until the test
  fixture set `TCP_QUICKACK`.

Landed with `utxo-modules-2026-09-06` (the MuHash fold worker, IFMA modmul,
radix flush, wtxid cache, short-id table): together these are every lever in
`UTXO_INLINE_BUILD_PERF_SCOPE.md` except the ChaCha20 keystream.
