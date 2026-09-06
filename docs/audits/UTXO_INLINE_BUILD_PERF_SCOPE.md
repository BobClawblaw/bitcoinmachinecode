# Building the UTXO set inline, the way Core does — the 3-hour gap

**Date:** 2026-09-06. **Companion:** `UTXO_INLINE_CONNECT_SCOPE.md` covers
the *semantics* of connecting as we go (the tip is the connected tip; a
block that fails to connect is rejected, not fatal). This document is about
the **time**: the fresh-install benchmark (`BobClawblaw/bmc-benchmark-2026-09`,
2026-09-04→06, dedicated SSD, same `dbcache=8192` on both sides) measured
**The 21.0 h Core figure is a FLOOR, not a fair result (corrected
2026-09-06).** The harness wrote `par=8` and `maxconnections=64` into Core's
config with no reason recorded anywhere, against Core's defaults of `par=0`
(auto: cores, clamped to 15, plus the calling thread) and
`maxconnections=125`. Core therefore ran with eight script-verification
threads on a 32-core box and half its connection budget, and the handicap was
applied to ONE side only. Both lines are removed from the harness. Pulling the
other way, this node evaluates every script (a fresh archive has no
assumevalid block) while Core's default skips signature checking below its
built-in block. Neither bias is quantified. Any claim of parity with Core
must state both.

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

**Landed 2026-09-06** (`daemon/utxo_live.c`, `tx_verify.c`, `undo_log.c`;
`tests/test_utxo_catchup_timing`). Every progress tick now ends with
`| read 3% idx 2% verify 61% get 9% put 14% ckpt 8% flush 3% csi 0% other 0%
(N ms/blk over M)`, percentages of the tick's wall, and a call that applied
two or more blocks ends with one `[utxo_live] catchup timing: ...` line with
the same breakdown over the whole call. Phase definitions (the enum's own
comment in `utxo_live.c` is the authority): `read` = `store_read_at`;
`idx` = parse + the in-block index; `verify` = `tx_verify_block_connect_all`
minus its Phase 1 lookup pass; `get` = that lookup pass + BIP30 gets;
`put` = the apply walk (undo capture, put/del, buffered WAL) + the block-end
WAL drain, minus the flushes and folds inside it; `ckpt` =
`persist_applied_height` (WAL fsync + height file + the coinstats commit);
`flush` = `mac_flush` inside a put/del + the per-block compaction poll/start
(the inline fallback lands here; a background compaction's own time does
not); `csi` = phase (h), `csi_on_add` per created output and
`csi_on_remove` per spent input. Two things the scope's list did not say:
the undo capture does a **second** `utxo_lsm_get` per input on the apply
path (inside `put`, not `get` -- splitting it costs two clock reads per
input), and the checkpoint is per block within 64 of the tip, so a small
synthetic chain reads ~98% `ckpt`. `utxo_live_set_timing(0)` removes the
clock reads; the counters then stay at zero.

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

**Found by step 0 (2026-09-06, instrumentation agent):** the apply path does
a *second* `utxo_lsm_get` per input inside `undo_capture_and_del` (get → undo
append → del), after the verify-side resolve already looked the same input
up. Every input is looked up twice; the second is charged to `put`. Carrying
the resolved coin from verify into apply is a lever in its own right, gated
on the `get` share the breakdown reports.
   *Measured (2026-09-06, `tests/bench_muhash`, one pinned core of this
   host):* the BMI2/ADX body landed at **603 ns vs 944 ns** for the multiply
   (1.57×, not the ~2× guessed above — the row chains are bounded by one
   `mulx` per cycle and the two flag chains) and **1307 ns vs 1640 ns per
   element** (1.25×): the multiply was 58% of an element, and the SHA256 +
   six scalar ChaCha20 blocks are now the larger half of what remains.
   The AVX-512 IFMA body (60 limbs of 52 bits, `vpmadd52luq/huq` column
   sums into 64-bit lanes, one scalar carry pass, then the same fold as the
   ADX body) followed at **301 ns** on the multiply (**3.28×**) and
   **1005 ns per element** (**1.65×**); at that point the multiply is 30% of
   an element and the SHA256 + ChaCha20 expansion is the rest, so the next
   lever on the per-element cost is the ChaCha20 keystream, not the modmul.
   Dispatch is `num3072_mul` in `bitcoin_muhash.asm` (CPUID leaf 7 — BMI2,
   ADX, AVX512F, AVX512IFMA — plus OSXSAVE/XGETBV for the IFMA body, cached
   exactly like `shani_ready`); the generic body is the fallback and
   `tests/test_muhash_mul_diff` holds each accelerated body to it limb for
   limb.

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

**Landed 2026-09-06 (branch `batch/2026-09-06-utxo-interleave`), with these
deviations from the text above, each decided against the code as found:**

- **The boot-time catch-up does not interleave.** `dl_catchup` runs twice:
  from `main()` at boot (`bmc.bootcatchup=1`, the default) in the PARENT,
  before `utxo_live_init` -- which runs in the download worker, the single
  writer -- and from the worker's far-behind trigger. Only the worker's run
  connects while it downloads (`g_utxo_live_on` gates it); the boot run
  still hands a full archive to the worker's drain, and the boot log now
  says so. A fresh-clone benchmark of this step must run with
  `bmc.bootcatchup=0` so the worker's trigger does the download. Moving the
  boot catch-up into the worker is a separate change (it would open the node
  for service before the download).
- **`store_reload` per pass is inside the bounded call**, not a separate
  call in the loop; the loop's tick is now `connect (≤ 8 s) → idle 2 s only
  if nothing connected → reap`, with the peer-status table, the dead-weight
  kills and the EMA on their own 10 s cadence and every per-tick rate
  divided by the tick's real length. One more bounded pass runs after the
  last helper exits, so the gate lag is what one pass leaves.
- **The unbounded call never "stopped at the hole by failing"**: it stops
  at the hole, logs a WARNING, classes the stop archive/recovery and returns
  the count applied (≥ 0). `test_utxo_catchup_bounded` pins that as the
  negative control. The bounded call stops at the hole silently (reason
  `HOLE`, no classification); `utxo_live_last_stop_reason()` names the exit.
- **A rejection mid-download stops the helpers.** The reject hook stops
  them BEFORE `chain_invalidate_block` truncates the archive under them
  (their remaining chunks were all on the rejected chain); `dl_catchup`
  returns, the rotation's legs take the heavier chain that avoids the mark,
  and the far-behind trigger re-runs the parallel download on it. A connect
  failure that is not a rejection (store error, halt) does not stop the
  download: connect backs off 30 s and the rotation's recovery path owns it
  after the download, as before.
- **The new-block choke point** (3.1) is one function now, fired from the
  rotation and from the download loop, so announce/ZMQ/index tails/mempool
  follow the connected tip during the download.
- `dlc_scan_progress` does not compute the contiguous prefix; the progress
  line's `lag` uses `dlc_first_hole` (prefix end − applied).
- Found while writing `test_dlc_interleave`, not fixed here: against a
  loopback peer the per-block `getdata` round trip is ~45 ms (21 blk/s per
  helper) until the peer ACKs immediately (`TCP_QUICKACK`), after which it
  is ~5 ms (179 blk/s). The node's outbound sockets have no `TCP_NODELAY`,
  and a message goes out as more than one segment, so Nagle holds the tail
  for the peer's delayed ACK. On the real network the RTT hides most of it;
  worth a look when the helpers' rate is next measured.

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

### The pipelined download: a 12x lever that trips a false consensus rejection — OPEN, 2026-09-06

`daemon/ibd_pipeline.c` (branch `batch/2026-09-06-ibd-pipeline-v2`, first cut
landed as PR #47 and reverted in PR #48) sends ONE getdata for a whole
40-block chunk instead of one per block. The win on a real sync is large and
was measured twice, against the same peer pool on the same afternoon:

| build | blocks stored | elapsed |
|---|---|---|
| serial fetch (main) | 74,638 | 74 min |
| pipelined fetch | 75,425 | 6 min |

That is roughly **12x on the early chain**, where blocks are small and the
cost is one round trip each — the phase that costs hours of a full sync. The
microbenchmark agrees: `tests/bench_ibd_fetch` removes 39 of every 40 round
trips (33.9x at 5 ms, 39.4x at 50 ms).

**Why it is not landed.** Both pipelined runs died with a FALSE
`bad-txns-BIP30`: at height 48,585 and, in the second run, 74,765. In each
case the Core oracle confirms an ordinary block whose coinbase output is
unique and unspent to this day; the archive was correct at those heights
(slot N held block N against the oracle); and the rejected bytes really were
that block. So the UTXO set already contained the block's own coinbase: the
block had been applied once already, under an earlier height.

**What has been ruled out.**

* *The archive being shifted* — checked slot by slot against the oracle.
* *Arrival-order storage.* The fetcher was changed to hold out-of-order
  arrivals and store a chunk in ascending height order (bounded 24 MB hold,
  peers answer in request order in practice so it is normally empty). The
  fault reproduced anyway, at a different height.
* *A reader/writer ordering hole in the store.* Both `store_append` and
  `store_append_shared` honour STO-11: block bytes are durable before the
  index record that points at them.
* *The out-of-order fixture.* `test_dlc_interleave` gained a mode where the
  fake peer answers every getdata backwards. It passes with the fault present
  AND absent — 600 blocks over 3 loopback peers is not enough concurrency to
  provoke it.

**ROOT CAUSE, corrected 2026-09-06 22:30Z: the ARCHIVE is wrong, written
wrong. It is a writer race, not a stale reader.**

The 16:00Z conclusion below was mistaken and is kept here because the way it
was wrong matters. It rested on hand-parsing a datadir at heights 2,843-2,847
and finding record and body in agreement, and concluded the reader must be
returning stale bytes. The fix that followed -- drop the fast reader's cached
fd and mmap window on a mismatch and re-read -- was then run against a real
sync (run 5, 22:12Z, the pipelined build with the archive guard):

* **Zero false `bad-txns-BIP30`**, past both heights where earlier pipelined
  runs died. The guard works: nothing wrong is ever applied.
* But the connect **wedged** at height 44,862 -- `applied` frozen while the
  download ran on -- with 30 guard trips a minute at two heights, and
  dropping the caches did not cure a single one.

Hand-parsing THAT archive settles it. At height 44,863:

| | |
|---|---|
| index record's hash | `0000000014121f6d...` |
| Core oracle's hash for 44,863 | `0000000014121f6d...` — the record is RIGHT |
| hash of the body at the recorded position | `0000000012ad2107...` |
| that body's real height, per the oracle | **44,888** |

So the record correctly names block 44,863 and points at bytes belonging to
block 44,888 -- another block from the SAME 40-block chunk. The archive is
internally inconsistent, on disk, at rest. No reader could have been right.

`store_append_shared` takes the block-file `flock`, computes the append
position with `lseek(SEEK_END)`, writes the body, then writes the 48-byte
record at `height*48`. Two blocks of one chunk ending up at overlapping
positions is what happens if that sequence is not serialised in practice --
one writer's bytes land where another's record already points. The serial
downloader wrote roughly one block per network round trip and never hit it;
the pipelined one writes a whole chunk per round trip, about 12x the rate,
and hits it within minutes.

**Next step, and it is a measurement, not a guess:** verify the lock is
actually held across the position computation and both writes -- print the
`flock` fd and the computed position per append under a debug flag, run the
pipelined fetch, and look for two appends that computed the same position.
Until that is answered the pipelined download stays off main.

**The wider question this raises, which no test covers:** every other reader
holding a store handle across writes by another process — the RPC block fetch,
the filter builder, the tx index, the archive verifier — shares those caches.

**Reproducer.** A real fresh mainnet sync, `bmc.bootcatchup=0`, pipelined
build, on an otherwise idle box: five to six minutes to the failure. It does
NOT reproduce when the box is busy — the second attempt, sharing bandwidth
with another sync, passed 74,399 blocks cleanly.

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
