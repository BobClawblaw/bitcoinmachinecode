# Building the UTXO set inline, the way Core does — the 3-hour gap

**Date:** 2026-09-06. **Companion:** `UTXO_INLINE_CONNECT_SCOPE.md` covers
the *semantics* of connecting as we go (the tip is the connected tip; a
block that fails to connect is rejected, not fatal). This document is about
the **time**: the fresh-install benchmark (`BobClawblaw/bmc-benchmark-2026-09`,
2026-09-04→06, dedicated SSD, same `dbcache=8192` on both sides) measured
Core v31.1 at **21.0 h** end to end and this node at **24.1 h**, and the
split says exactly where the 3.1 h is.

## 1. What the benchmark measured

| phase | bmc | Core v31.1 |
|---|---|---|
| headers | 416k in 129 s | inline |
| block download | 719k blocks, **19.5 h at 11.1 MB/s, flat**; ~1 TB archive; disk idle | 21.0 h total, download and validation interleaved |
| UTXO build | **4.5 h** bulk catch-up, 60.6 blk/s average, full script verification, *after* the download gate closed | inline: every block connected as it arrives (`par=4`) |
| end to end | **24.1 h** | **21.0 h** |
| UTXO parity | identical muhash / txouts / amount, three ways | — |

The download is peer-bound at 11.1 MB/s on both sides (the bench notes
disk was idle throughout). Core's 21 h *is* its download; it has nothing
left to do at the end because `ConnectBlock` ran on every block as it
landed. Our 24.1 h is the same download plus a serial phase that begins
when it ends. **The gap is not that our UTXO code is 3 h slower than Core's;
it is that ours runs afterwards.** Whether it could hide inside the download
is a rate question, answered in §3.

## 2. Why it runs afterwards — the code

`serve_download_worker` (`main.c`) is one process. During IBD it calls
`dl_catchup(dir, 16)` (`main.c:4105`), which forks 16 fetch helpers
(`dlc_worker`) that claim height ranges through shared counters and write
blocks and index records to the archive **themselves**, and then sits in a
monitor loop:

```
while(alive>0){ nanosleep(10 s); reap; dlc_scan_progress(&tip,&present); fprintf("[dlc] == elapsed ... stored ... holes ..."); }
```

For 19.5 h the worker does nothing but print. `utxo_live_catchup(store_buf)`
(`utxo_live.c:2914`) — the connect step: per block, `store_read_at`, the
in-block outpoint index, `tx_verify_block_connect_all` across the parallel
verify workers, then the puts/dels into the LSM, undo records, a checkpoint
every 64 blocks or 2 s — runs only after `dl_catchup` returns (or when the
"apply-first" backlog rule, `DL_APPLY_FIRST_BACKLOG` 500, stops the legs).
The UTXO set has a single writer, the worker, and the helpers never touch it
— so the two loops can share the process without a new hazard. They just
never do today.

Core, for comparison: network threads download; the validation thread
connects each block as it arrives; `par` script-check threads verify;
the coins live in an in-RAM cache (`dbcache`) flushed to LevelDB a handful
of times per IBD. Nothing is serialised behind the download's end.

## 3. Can connect keep pace with download?

What the download delivers at the heavy end of the chain: 11.1 MB/s over
~1.5 MB blocks ≈ **7 blocks/s**. What connect does there:

| source | regime | blocks/s |
|---|---|---|
| bench, whole run | IBD, 16 verify workers, every height | 60.6 average (dominated by light early blocks) |
| live node log (`logs/main/bitcoin.main.log.1`, 155 ticks at ~965k) | steady state, other duties, heavy blocks | p50 5.8, p90 12.0, max 125 |
| live node log (`.log`, 123 ticks) | same | p50 2.0, p90 8.9, max 16.1 |

So at the heavy end, connect in its *current* form runs at roughly the
download rate — sometimes ahead, sometimes behind — and over the whole
chain it needs 4.5 h of the 19.5 h. Interleaved from the start, the early
chain's connect is trivially hidden, and the question reduces to the lag at
the tip end: a residual measured in minutes, not hours, if the heavy-block
rate holds near the p90 figures; up to an hour or so if it sits at the p50.
Either way the end-to-end lands at **~19.5–20.5 h against Core's 21.0 h.**

That estimate is the thing to measure first, not assume: there is **no
per-block cost instrumentation** in the apply loop today (§4 step 0).

## 4. Design

### Step 0 — instrument before changing anything

Per block in `utxo_live_catchup`: microseconds in (a) `store_read_at`,
(b) the in-block index, (c) `tx_verify_block_connect_all`, (d) LSM
gets, (e) LSM puts/dels + WAL, (f) checkpoint fsync, (g) flush/compaction
stalls. Summed per progress tick and printed with the existing
`catchup progress` line. One commit, no behaviour change, and it turns §3's
range into a number per regime. This is also what tells us whether the
levers in §4.3 are needed at all.

### Finding while scoping the cache model (2026-09-06, evening): the MuHash fold is on the bulk connect path

`coinstats_index.c`'s `csi_on_add` / `csi_on_remove` run for every created
output and every spent input during connect whenever `g_csi.valid` is set —
and on a fresh sync it is set from the start (`csi_seed_from_walk` at applied
height 0, `main.c:5055`). Each call is one MuHash3072 element: ChaCha
expansion, SHA, and a 3072-bit modular multiply in `bitcoin_muhash.asm`.
Measured in isolation on this host: **1.66 µs per element**. A full sync
creates ~3.3 billion outputs and spends ~3.1 billion of them, so the fold
alone is on the order of **6.4 billion × 1.66 µs ≈ 3 hours of single-threaded
CPU on the connect thread** — the same order as the entire 4.5 h bulk phase.
Step 0 now instruments it as phase (h); if the number holds, it is the
largest single lever in this document, ahead of the WAL:

1. **Bulk mode: do not fold per coin at all.** Leave the index invalid
   while catching up and seed it from a walk at "caught up" — 165M coins ×
   1.66 µs ≈ **5 minutes** — which is what `csi_seed_from_walk` already does
   at boot. The same bulk/steady split the cache scope uses.
2. **Steady state: take the fold off the connect thread.** MuHash is
   commutative, so a fold worker consuming a ring of coin records (the
   announce-ring shape) folds while the next block connects; the tip-regime
   cost today is ~10k elements × 1.66 µs ≈ 17 ms per heavy block on the
   connect thread.
3. **A faster modmul.** `num3072_mul` is a plain limb loop (`mul`/`adc`);
   BMI2/ADX (`mulx`/`adcx`/`adox`) chains are ~2×, and an AVX-512 IFMA
   (52-bit limb) variant behind the same CPU-dispatch pattern the SHA-NI
   path uses is 3–5×. Assembly work, cleanly separable, verified against the
   existing Core vectors (`tests/muhash_vectors.h`).

### Step 1 — connect inside the download loop (the structural fix)

Replace the monitor loop's `nanosleep(10 s)` with a **budgeted connect**:

```
while(alive>0){
    store_reload(store_buf);                       /* see the helpers' appends */
    long done = utxo_live_catchup_bounded(store_buf, /*max_ms*/ 8000, /*stop_at_hole*/ 1);
    if(done == 0) nanosleep(2 s);                  /* nothing contiguous to connect: idle briefly */
    reap; progress line (now also prints applied height and lag);
}
```

`utxo_live_catchup_bounded` is `utxo_live_catchup` with a time budget and a
hard stop at the first hole (`store_read_at` on an all-zero record): the
helpers fill heights out of order, so connect follows the **contiguous
prefix**, which `dlc_scan_progress` already computes. Everything inside
the block stays as it is — the same verify workers, the same LSM, the same
checkpoint cadence. When `dl_catchup` returns, the existing
`utxo_live_catchup` call drains whatever lag remains, exactly as today.

The "apply-first when backlog > 500" rule becomes a recovery path (the
backlog can only grow past 500 now if connect is *slower* than download),
and the sibling scope's §3.1 — the node's tip is the connected tip — is
what makes the interleaving visible correctly to peers and RPC.

**Expected result:** the 4.5 h phase disappears into the 19.5 h download;
end to end ≈ download + tip lag.

### Step 2 — the CPU budget

The worker's process now does connect while 16 helpers download. The
helpers are network- and disk-bound (the bench: disk idle, CPU low); the
verify workers are separate processes already. The one real contention is
the verify workers' cores against the helpers' `cons_verify` structural
checks; on the bench host (the bench reports 26.6 effective cores for
parallel taproot verification) this is not the constraint. Measure in
step 0; if it is, the helpers' count and the verify workers' count are the
two knobs, both already configurable.

### Step 3 — levers if connect lags the download at the tip end

In order of expected yield, each gated on step 0's numbers:

1. **Checkpoint cadence in bulk mode.** Every 64 blocks or 2 s the
   checkpoint fsyncs `utxo.idx` and `utxo.dat`. Core flushes its cache a
   few times per IBD. During bulk connect (applied height far below the
   stored tip, undo records intact), a checkpoint every N thousand blocks
   or every 60 s is as safe — recovery replays from the last checkpoint —
   and removes most of the fsync time. Steady state keeps today's cadence.
2. **LSM lookup path.** Every input is an `utxo_lsm_get`: memtable, then
   runs via Bloom filters, then the mmapped run. The in-block outpoint
   index already short-circuits same-block spends. Instrumentation says
   whether gets are a first-order cost; if so, a larger bulk memtable
   (`UTXO_LIVE_BULK_SLOTS_LOG2`, 4M slots today) raises the hit rate the
   way `dbcache` does for Core, at the RSS cost the bench already tolerated
   (~30 GB peak).
3. **Compaction scheduling.** Background compaction is in (14 runs → 1 in
   58 s at the bench). Its trigger (`UTXO_LIVE_COMPACT_THRESHOLD` 12 runs)
   is fixed; with connect interleaved, compactions land during the download
   rather than after it, which is free — unless a compaction's I/O contends
   with the helpers' writes. Measure; the knob exists (`bmc.utxocompactthreshold`).
4. **Verify workers.** 16 today; the bench's parallel taproot figure says
   the host has headroom. A knob, not a change.

Scoped separately, not on this list: adopting Core's cache-and-flush model
(`UTXO_CACHE_MODEL_SCOPE.md`). It would be a rewrite of a tested, crash-consistent store
for a gain that step 1 mostly captures without it. If step 0 shows the LSM
writes themselves dominate at the tip end — not the fsyncs, not the gets —
that conclusion changes, and the number will say so.

## 5. Tests and the proof

- `test_utxo_catchup_bounded` (gated): a synthetic archive with holes at
  known heights; the bounded call connects exactly the contiguous prefix,
  stops at the hole, resumes past it when filled, honours the time budget,
  and leaves `utxo_applied_height.dat` consistent. **Negative control**: the
  unbounded call on the same archive does what it does today — stops at
  the hole by failing, and connects nothing while the download loop runs.
- `test_dlc_interleave` (gated, fake peers): a download with helpers that
  deliver heights out of order; the progress line shows applied height
  rising *during* the download; at the download gate the lag is bounded.
- The existing crash-consistency suites (`test_utxo_catchup_crash_resume`,
  `test_utxo_catchup_shutdown`, `test_utxo_checkpoint`) run unchanged —
  they are the proof that a SIGTERM mid-interleave lands on a checkpoint.
- **The benchmark re-run is the acceptance test**: the same contract as
  2026-09-04 (fresh clone, `dbcache=8192`, same host, Core v31.1 after),
  reporting download gate, applied height at the gate, and end to end.
  Target: **end to end ≤ 20.5 h**, muhash parity three ways, RSS peak
  recorded. CC-8's replay is not this test (it verifies every script by
  design); it is the *other* headline, and it should be restarted on the
  interleaved code when this lands so `applied == stored` on every tick.

## 6. Risks

- **Reading the archive while 16 helpers append to it.** They already do:
  `store_read_at` is a pread by height and the index is pre-sized
  grow-only; the contiguous-prefix rule means connect never reads a height
  a helper is still writing. `store_reload` per loop pass is the only new
  call; measure its cost (it is a re-read of a small header).
- **The applied-height file and a crash.** Unchanged mechanism, exercised
  more often. The three crash suites above are the gate.
- **Memory.** Connect's verify workers plus 16 helpers plus the bulk
  memtable in one machine: the bench ran connect after the helpers had
  exited. Record RSS on the re-run; the knobs are the two worker counts.
- **A block that fails to connect mid-download.** Today that halts the
  worker; with interleaving it would halt the download too. The sibling
  scope's §3.3 (reject, mark, continue) should land first or together.

## 7. Order

1. Step 0 instrumentation (small, no behaviour change; a commit of its own).
2. Sibling scope §3.1 + §3.3 (tip = connected tip; reject-not-halt).
3. Step 1 interleave, with the two new tests.
4. The benchmark re-run. Read the numbers; then, and only then, step 3.
