# Run 22: a clean sync that produced the wrong UTXO set

2026-09-11. Fresh mainnet IBD, commit `4a4872cf`, `dbcache=8192`,
`bmc.catchupworkers=8`, `bmc.bootcatchup=0`.

## The run looked perfect

| | |
|---|---|
| blocks stored and applied | 966,369 in **20h 08m** |
| UTXO engine caught up | 20h 15m |
| bad blocks, gaps, apply lag | zero, none, zero |
| tip vs Core oracle | same height AND same block hash |
| stall evictions | 11, none costing measurable time |

Core v31.1, same box, same cache, same disk, also at 8 download peers, took
**21h 11m** to the same height. Core lost 138 minutes between heights 835,000
and 840,000 to a single stalling peer, which its own log names at the moment it
recovered. Segment by segment bmc is 8-12% slower than Core from height 500,000
onward and level below it, so the hour we finished ahead is Core's stall, not
our throughput.

## The capstone failed

```
MUHASH h=966494 ours=34eddd67… 165206507  oracle=f235648f… 165206507
FAIL muhash differs at 966494
```

**This is the first time the muhash comparison has ever completed.** Earlier
runs timed out, and an empty result compared equal to an empty oracle value, so
the harness printed nothing and the run passed. The capstone has therefore never
actually verified anything before today.

## Ruling out the easy explanations

Each of these was tested, not assumed.

| hypothesis | test | result |
|---|---|---|
| a fork | block hash at 966,494 on bench, oracle and production | all three identical |
| a moving set during the walk | froze the bench node (`setnetworkactive false`), re-hashed | still differs, and the value is stable across repeats |
| our muhash code is wrong | production's index at 966,000 vs oracle | **identical** |
| our WALK path is wrong | production's walk vs its own index vs oracle at 966,496 | **all three identical** |

So the implementation is correct on both code paths, and production, which was
built by `reindex-chainstate`, is byte-correct against Core.

## What actually differs

At height 966,495, both nodes on the same block, the bench node frozen:

| field | bench | Core oracle | same |
|---|---|---|---|
| txouts | 165,203,925 | 165,203,925 | yes |
| bogosize | 12,942,059,030 | 12,942,059,030 | yes |
| total_amount | 20,082,569.88121624 | 20,082,569.88121624 | yes |
| muhash | `2f8a7959…` | `dcfaa870…` | **no** |

Every aggregate matches exactly. Only the set hash differs.

That combination is the finding. The outpoints, the values and the scripts must
be right, or `txouts`, `total_amount` and `bogosize` would move. What feeds
muhash and feeds none of those three is the coin's **height and coinbase flag**,
which our store packs as `code = (height << 1) | coinbase`. Both the walk and
the index hand that `code` to the same `utxo_stats_add`, so the hashing is
shared and the inputs are what differ.

**Conclusion: the fresh parallel-download sync writes correct coins with wrong
height metadata for at least one of them.** This is not a consensus break for
spending — the chain is identical and every value is right — but it is wrong
data, and it is exactly what the capstone exists to catch.

## What is kept

The bench UTXO store and header store are archived at
`/mnt/10gbusb1/bench-archive/run22-20260910-8workers/evidence` (16 GB): the only
reproduction. The 962 GB of blocks and undo were not archived, being
re-downloadable. The stored set can be re-hashed offline with
`asm/daemon/utxo_setinfo <datadir> --muhash`, which also takes
`--override <txid>:<n>=<height>` — the tool for confirming a suspected coin
without a twenty-hour sync.

## Why it cost twenty hours to learn, and what changes

The answer was a single bit at the tip: "the set differs". It named no block.

`validation/fresh_ibd_run.sh` replaces the previous runner and changes two
things:

* **The check can now fail.** It refuses to render a verdict on anything that is
  not 64 hex characters from both sides, so the empty-equals-empty pass is
  impossible. It also compares at a settled height 20 below the tip rather than
  at a tip the network is still moving.
* **The answer is now a block, not a bit.** With `coinstatsindex=1` the node
  records a muhash for every height as it syncs, so on failure the harness
  bisects our per-height record against the oracle's and prints the first
  divergent height. From there it is one block, then one coin.

The index costs sync time, so the next run's wall clock is **not** comparable
with run 22's or with Core's. That is deliberate. Run 22 settled the timing
question; correctness is the open one.
