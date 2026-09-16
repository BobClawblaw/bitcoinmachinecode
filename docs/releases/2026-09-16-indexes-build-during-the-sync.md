# Every index builds during the sync (2026-09-16)

**What changed for an operator:** a fresh node configured with
`txindex=1 txospenderindex=1 addrindex=1 blockfilterindex=1 coinstatsindex=1`
reaches the tip with all five indexes current. There is no build step after
initial block download, and no supervisor waiting for IBD to end. The same
trailing builders keep the indexes current afterwards at the same cadence.

Before this, four of the five were built by offline whole-chain tools — hours
each, ~700 GB of scratch for the address history — and the fifth (coinstats)
was invalidated at height 91,842 by the first pre-BIP34 duplicate coinbase and
only re-seeded at the next boot.

## How

An index is now a **set of sorted runs** plus a bounded tail. A run is a file
in exactly the old base format covering a contiguous height range:
`txindex.dat` (a node's existing base) is simply the run that starts at 0, and
`txindex.r<from>-<to>.dat` follows it. Every `bmc.indexrunblocks` heights
(default 20,000), once they are applied 144 below the applied height, the
daemon spawns the builder over that range into a new run at nice 10, then
rotates the tail to drop what the run now covers. At six runs it merges them
into one with a streaming k-way merge. Lookups ask each run, then the tail —
so the linear tail scan is bounded by the run interval rather than by the
chain.

The address history got there by a different route: its spends now come from
**undo data**, which this node keeps for every block, so one height range is
self-contained and needs no whole-chain join. That is the fact that made the
700 GB temp peak unnecessary.

Block filters need no runs at all — they are positional by height — so the
daemon simply creates the files and builds from genesis at the block choke
point, closing gaps in slices so the apply path never stalls.

## Configuration

| key | default | meaning |
|---|---|---|
| `txindex` | `0` | now means what it means in Core; it used to print "has no effect" |
| `txospenderindex` | `0` | a real flag now (it "changed nothing" before) |
| `addrindex` | `0` | **set it before the sync** — historic spends need undo |
| `blockfilterindex`, `coinstatsindex` | `0` | as in Core |
| `bmc.indexrunblocks` | `20000` | heights per run (1,000–200,000) |

## Notes

- A node with existing single-file bases keeps them; they are runs.
- The whole-chain builders still exist for a one-off rebuild.
- `getindexinfo` reports each index's reach as it grows during the sync.
- Details and the reasoning: `docs/devlog/INDEX_RUNS.md`.
