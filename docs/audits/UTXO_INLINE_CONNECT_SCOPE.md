# Building the UTXO set inline, the way Core connects blocks — scope

Scoping report, 2026-09-06. Not started. Companion to
`docs/CORE_BEHAVIORAL_COMPAT.md` §1 ("Consensus and validation").

> **Companion (2026-09-06):** `UTXO_INLINE_BUILD_PERF_SCOPE.md` quantifies the *time* cost of the decoupling this document describes — the 3.1 h gap to Core v31.1 in the fresh-install benchmark — and scopes the interleaving that removes it.

## 1. What Core does

Core keeps two notions apart and never lets the second run ahead of the
first for anything it says to the network:

1. **Accepting a block to disk** (`AcceptBlock`): PoW, header context,
   structural checks; the block lands in `blk*.dat` in whatever order it
   arrived (IBD downloads a 1024-block window out of order).
2. **Connecting** (`ConnectBlock` inside `ActivateBestChain`): in chain
   order, against the UTXO view — every input resolved, every script run
   (parallel script-check threads), amounts, sigops, BIP30/34/68/112/113,
   the undo record written, the coins DB updated. `ActivateBestChain` runs
   **after every accepted block**, so the connected tip trails the stored
   tip only by blocks that are still in flight.

Everything Core announces, serves as its tip, reports to RPC and ZMQ, and
folds into `coinstatsindex` is the **connected** tip. A block whose
`ConnectBlock` fails is marked `BLOCK_FAILED_VALID`, is never in the active
chain, and the node moves to the next-best candidate without human help.

## 2. What this node does today

The pieces exist; what differs is *when* they run and *what the node calls
its tip*.

| stage | Core | here |
|---|---|---|
| store | `AcceptBlock` | `cons_verify` (structural, no UTXO view) → `store_append`; three writers: `node_sync_multi` on a leg, an inbound child's `.do_block`, and the parallel downloader `dl_catchup` (out of order, hole-tracked) |
| connect | `ConnectBlock`, after every block | `utxo_live_catchup(store_buf)` (`utxo_live.c`): from the persisted applied height up to the **stored** tip, in order, `apply_block_at` = full validation against the UTXO set with the parallel verify workers (`txvb_*`), undo records, checkpoints. Run from the worker's rotation with a budget, and in "apply-first" mode once the backlog exceeds `DL_APPLY_FIRST_BACKLOG` (500) |
| the tip the node reports | connected | **stored**: `g_node_status->tip_height = *(int*)(store_buf+24)` (`main.c:5348`, `8469`); `node_announce_tip(fd, store_buf, ...)` announces the stored tip; ZMQ `hashblock` fires on store |
| a block that fails connect | marked invalid, chain moves on | `apply_block_at` returns 0 → `[utxo_live] FATAL: apply_block failed ... stopping catch-up`; a lookup-trust failure sets `g_halted` for the life of the process. The block stays in the archive at its height and stays the announced tip |

So the honest description is: **connect is already Core's ConnectBlock; it
is just decoupled from store by a backlog, and the node's public tip is the
store's, not the connection's.** During steady state at the tip the backlog
is normally 0–1 blocks and the difference is invisible. During IBD, after a
reorg, or after any block that fails to connect, it is not.

Concrete consequences today:

- a block that is stored but fails connect has already been announced and
  served as our tip, and `getblockcount` counted it;
- the node halts on such a block instead of rejecting it — Core's behaviour
  when a miner produces an invalid block is to drop it and continue;
- `dl_catchup` can put hundreds of thousands of unconnected blocks on disk
  before the first is connected; a peer asking `getheaders` from us during
  that window is told about a tip we have not validated;
- `coinstatsindex` folds on connect (correct), but `getblockcount` and
  `getbestblockhash` report the stored tip, so the two disagree during a
  backlog (CSI-1 was the visible edge of this).

## 3. Design: connect-as-you-go

Keep the store/connect split (Core has it too); close the three gaps.

### 3.1 The node's tip is the connected tip

One rule, applied everywhere the stored tip is read for the outside world:
`tip = utxo_live_applied_height()` when live tracking is on, else the stored
tip (the degraded mode already logged as "continuing WITHOUT live UTXO
tracking"). Sites: `g_node_status->tip_height` (2), `node_announce_tip`
(pass the connected height, or gate the call on `applied == stored`), the
ZMQ `hashblock` publish (move it to the connect side: `utxo_live` already
has `g_mined_cb` per block — publish there), `getblockcount`,
`getbestblockhash`, `getblockchaininfo.blocks` (keep `headers` as the header
store count, as Core does), `getblock` for heights above the connected tip
(Core: the block exists but is not in the active chain → error -1 "Block not
available" unless verbosity 0 and data present). The store's own tip
remains the archive's high-water mark, used by the downloader.

### 3.2 Connect immediately after every store

At each of the three store sites, run the connect step for the contiguous
prefix that just became available, before the rotation does anything else:

- **`node_sync_multi` leg sync** (`main.c` ~5822 already calls
  `utxo_live_catchup` right after; keep, but make it unconditional and
  unbudgeted for ≤ 2 blocks, so a tip block is connected before the next
  leg is polled);
- **inbound `.do_block`** (a sibling process): it cannot connect (single
  writer); it already fires `g_utxo_apply_hook` → the worker's
  `txoq_service`. Add a `utxo_live_catchup` call in that hook path so the
  worker connects the block on its next quiescent point rather than its next
  rotation;
- **`dl_catchup`** (IBD): connect the contiguous prefix as chunks complete —
  a `utxo_live_catchup` call inside the chunk-completion loop, budgeted so
  download and connect interleave (Core interleaves them on separate
  threads; here the worker is one process, so connect gets a time slice per
  chunk). The "apply-first when backlog > 500" mode becomes unreachable in
  normal operation and stays as the recovery path.

### 3.3 A block that fails to connect is rejected, not fatal

`apply_block_at` returning 0 for a *validation* reason (as opposed to a
store/lookup inconsistency, which keeps `g_halted` semantics) becomes:

1. log the reason (`utxo_live_last_reject`), height, hash;
2. `invset_add(hash)` + `invset_save` — the CC-10 mark, so the header
   fetch and the reorg analyzer refuse the chain from now on;
3. `archive_truncate_safe(st, h-1)` + header-store rollback to `h` — the
   same two calls `txoq_mark_block` makes for `invalidateblock`, so this is
   `invalidateblock` invoked by the node on itself;
4. mark the peer that delivered the block (the worker knows the leg) with a
   consensus violation via `txr_report_violation_fd` — Core disconnects and
   discourages it;
5. continue: the next rotation fetches headers from other peers and takes
   the heavier chain that avoids the mark.

Because the connected tip is `h-1` throughout (3.1), nothing was announced
that has to be retracted.

### 3.4 What stays as it is

Parallel script verification in connect (already there), undo records and
checkpoints (already there), `assumevalid` (a connect-time switch already),
the offline `build_utxo` (a batch tool for a fresh set; unchanged), the
serve children's read-only view (unchanged; they still serve stored blocks
on `getdata`, as Core serves any block it has data for).

## 4. Tests

- **Tip semantics** (unit, gated): with a fake applied height below the
  stored tip, `getblockcount`, `getbestblockhash`, the status block, and the
  announce path all report the applied height; `getblock` above it returns
  Core's error. Negative control: the switch off → the stored tip, as today.
- **Connect follows store** (gated, `test_utxo_live` family): store N
  blocks through each of the three writers on a synthetic chain; after each,
  the applied height equals the stored tip before the next store. Negative
  control: the hooks disabled → the backlog grows to N.
- **Rejection instead of halt** (gated): a synthetic block that spends a
  nonexistent output is stored at `h`; connect fails; the archive is at
  `h-1`, `invalid.dat` holds the hash, the header store is at `h`, the node
  is not halted, and a subsequent valid block at `h` from another source
  connects. Negative control: today's behaviour — the FATAL log and a stuck
  applied height.
- **End to end on regtest** against real Core: Core mines; our connected tip
  follows within one block; Core `invalidateblock`s its own tip and mines a
  sibling; we follow the sibling. Then the inverse: a hand-built invalid
  block submitted via `submitblock` is rejected without a restart.
- **IBD proof**: the CC-8 replay, restarted on the new code, must show
  `applied == stored` at every progress line (today it shows the backlog).

## 5. Risks and the order

- 3.1 is the largest behavioural change for the least code; every RPC and
  the announce path read one function. Do it first, alone, with its test.
- 3.3 changes what a validation failure means for a running node; it reuses
  CC-10's tested disconnect/truncate path, but the *classification* of
  failures (validation vs inconsistency) inside `utxo_live.c` must be exact
  — a lookup failure treated as "invalid block" would truncate a good chain.
  Read `g_last_fail_kind` values before touching it.
- 3.2 in `dl_catchup` competes with the downloader for the one worker
  process; the budget is the tuning knob, and CC-8 is the benchmark.
- Nothing here changes consensus rules; it changes *when* they run and what
  the node says while they have not yet run.

**Size:** medium (3.1 small, 3.3 medium, 3.2 medium). Three commits, three
gates, one regtest script.
