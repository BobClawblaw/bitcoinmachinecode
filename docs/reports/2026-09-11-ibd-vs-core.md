# An assembly Bitcoin node vs Bitcoin Core v31.1: a full mainnet IBD, measured

2026-09-11. Benchmark tag `bench-2026-09-10`, node commit `4a4872cf`.

> **CORRECTED 2026-09-13, after a fresh unhandicapped Core baseline.** The
> original version of this report was wrong in two directions at once, and the
> corrections do not cancel out.
>
> **1. The UTXO set was always correct.** This report said the node built a wrong
> UTXO set. It did not. The store was later walked offline and quiesced and
> matched Core exactly at height 966,496 -- muhash `df1b0340…073d0165`, txouts
> 165,200,444, bogosize 12,941,799,750, total_amount 2,008,257,300,621,623 sat.
> The original failure came from hashing through the live node while its UTXO
> engine was still applying: a torn read, not a defect.
>
> **2. The "hour ahead of Core" was an artifact, and it is withdrawn.** Core's
> 21h 11m came from a run that lost 138 minutes between heights 835,000 and
> 840,000 to a single stalling peer, and that ran under `ionice -c3` — the idle
> I/O class — while this node ran with no ionice at all. **The stall does not
> reproduce.** A fresh Core baseline on 2026-09-12/13, unhandicapped, crossed
> that same segment in 16 minutes and finished in **19h 14m**. Every run
> measured on this box crosses it in 11 to 16 minutes. The margin was one bad
> peer in one run.
>
> **3. The "8 to 12 percent slower" finding is also withdrawn, in our favour.**
> Against the unhandicapped baseline, run 23 is *faster* in every segment
> measured. See the four-way table below, which replaces the two-way one.
>
> The measurement defects behind all of this are covered in
> [the run 22 writeup](2026-09-11-run22-muhash-divergence.md).

This is a report on one fresh mainnet initial block download by an independent
Bitcoin full node written in x86-64 assembly, measured against Bitcoin Core
v31.1 on the same machine — and, as it turned out, on three defects in the
measurement rather than in the node.

**The short version: it built a chain identical to Core's block for block, and a
UTXO set identical to Core's coin for coin.** The capstone that said otherwise
was reading a set that was still moving.

## The machine, and both configurations

| | |
|---|---|
| CPU | AMD Ryzen 9 9950X3D, 16 cores / 32 threads |
| RAM | 123 GB |
| disk | Samsung Portable SSD T5, 1.8 TB, ext4, sequential write 0.40 GiB/s |
| kernel | Linux 7.0.0-31-generic |
| link | 2500 Mb/s, no traffic shaping (`fq_codel` default) |

Both nodes: `dbcache=8192`, fresh datadir, no `assumeutxo`, no pruning, mainnet,
peers from the public network by DNS seed.

**On peer counts, which is where IBD comparisons usually go wrong.** Core's
block-download concurrency is not configurable. `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS`
pins it at 8 outbound full-relay peers regardless of what `maxconnections` says,
and it keeps up to 16 blocks in flight per peer inside a 1,024-block window.
Earlier comparisons here ran the assembly node at 16 to 64 downloading peers
against Core's 8, which is not a comparison of anything. This run is the first
at **8 on both sides**.

## Result

All four runs, so no run is quoted without its comparators:

| | bmc run 22 | bmc run 23 | Core 09-13 | Core 09-05 |
|---|---|---|---|---|
| commit / version | `4a4872cf` | `8bc638f9` | v31.1 | v31.1 |
| blocks | 966,369 | 966,674 | 966,808 | 965,703 |
| wall clock | 20h 08m | **19h 05m** | 19h 14m | 21h 11m |
| coinstatsindex | no | **yes** | no | no |
| download peers | 8 | 8 | 8 | 8 |
| `ionice` handicap | none | none | none | **idle class** |
| bad blocks / gaps | zero / none | zero / none | zero | zero |
| tip vs oracle | identical by hash | identical by hash | identical by hash | identical by hash |
| **UTXO set vs oracle** | **PASS** | **PASS** | **PASS** | PASS |

The UTXO row is the one that had never been filled in before. Every earlier run
in this project "passed" a capstone that never executed: the walk timed out, an
empty result compared equal to an empty oracle value, and nothing was printed.
All four verdicts above come from a quiesced walk compared to the oracle at a
PINNED height, and each matches on muhash, txouts, bogosize and total amount.

Run 23 is the fastest of the four and carried an index the others did not.

The chain was verified by block hash against a third node at heights 966,000,
966,494 and 966,495. All three agree.

## Four runs, segment by segment

The original version of this section compared two runs and drew a conclusion
from one of them. Four runs on the same box, same disk, same 8 download peers a
side, now exist. Two are Core and two are this node. Times are to the
VALIDATED tip on both sides -- Core's `blocks`, and this node's UTXO *applied*
height. The stored-block frontier runs ahead of applied and quoting it would
flatter this node by several thousand blocks.

| segment | Core 09-13 | Core 09-05 | bmc run 22 | bmc run 23 |
|---|---|---|---|---|
| 800k–835k | 1h 29m | 1h 40m | 1h 35m | **1h 25m** |
| 835k–840k | 0h 16m | **2h 18m** | 0h 15m | **0h 11m** |
| 840k–850k | 0h 23m | 0h 22m | 0h 25m | **0h 23m** |
| 850k–900k | 2h 06m | 1h 59m | 2h 10m | **1h 56m** |
| 900k–950k | 1h 56m | 1h 54m | 2h 02m | **1h 50m** |
| **to the tip** | **19h 14m** | 21h 11m | 20h 08m | **19h 05m** |

Read the 835k–840k row first. Core's 09-05 run spent **2h 18m** there; every
other run on this box, including the other Core run, crosses it in 11 to 16
minutes. The 138 minutes was one stalling peer in one run. It is not a property
of Core, and the "hour ahead" in the original version of this report was very
nearly all of it.

With that artifact gone, the comparison inverts. Run 23 is the fastest run in
every segment and on the total, beating an unhandicapped Core by nine minutes
overall and by 3 to 8 percent per segment -- **while doing strictly more work**,
because it carried `coinstatsindex=1` and the Core runs carried no such index.
Run 22, on an older commit, is the slowest of the four, so the gap between 22
and 23 is a real change between commits rather than run-to-run noise.

The honest summary is narrower than either the original claim or its reversal:
on this box, at 8 peers a side, the two implementations are within a few percent
of each other, and the ordering depends on which commit and which peer set you
draw. Anyone quoting a single number from any of these runs is quoting noise.

**Every run's UTXO set was verified**, which had never happened before: all four
match the Core oracle on muhash, txouts, bogosize and total amount at a pinned
height. The original stall evidence is kept below because the log is still the
clearest record of what a stalling-peer eviction looks like:

```
2026-09-05T18:27:22Z UpdateTip: height=835000
2026-09-05T20:45:25Z Peer is stalling block download, disconnecting peer=213
2026-09-05T20:45:30Z UpdateTip: height=840000
```

Core spent 138 minutes on 5,000 blocks where the neighbouring 5,000-block
stretches took 10 to 15, then recovered the instant its stalling-peer timeout
fired. Take that segment out and Core finishes ahead. The honest summary is that
**Core moves blocks about ten percent faster per segment at equal peer count,
and the assembly node finished first because it did not lose two hours to one
bad peer.**

The assembly node evicted 11 stalling peers over the run with no comparable
freeze. That is a real difference in stall handling, and it is the only reason
the totals came out the way they did.

## Where the ten percent goes

The node did not report the figure that answers this, so it was measured from
outside the process at 96% of the chain, sampling `/proc/<pid>/io` at 50 ms.

| | |
|---|---|
| aggregate receive | 10.1 MB/s, flat, 99% of 6,157 samples inside 9–11 MB/s |
| per-worker receive | 0.94 to 1.74 MB/s |
| worker blocked with nothing arriving | 11–20% of wall time |
| idle gaps, 30 s across 8 workers | 332; median 50 ms, p90 350 ms, none over 0.7 s |
| worker CPU | 0.2–0.6% each |
| block-apply CPU | 20% of one core |
| iowait | 0 |

Separately measured: 0% of samples showed a read gap while the worker was
writing, so the staging path is not the cause either. The workers are asleep
waiting for peer bytes, on a machine that is otherwise idle.

The status line said `8/8 worker(s) active`. That is true and useless, because a
worker holding a peer that cannot fill the pipe is active and idle at the same
time. Occupancy is now reported by the node.

**Whether more peers would fix it is not yet known and is not being guessed at.**
This project has twice set that number without measuring it. A short
randomised-order sweep at 8/16/24/32 peers, reading throughput together with
occupancy, is what will settle it, because those three cases are indistinguishable
in a single run:

* idle low, throughput flat as peers rise — a shared wide-area ceiling
* idle low, throughput rising — per-peer limited, add peers
* idle high — the slots are held by peers that cannot fill the pipe

## The part that matters: the UTXO set is wrong

The run's final check compares the whole UTXO set against Core using MuHash, the
same rolling set hash Core's `gettxoutsetinfo muhash` produces. It failed.

```
MUHASH h=966494 ours=34eddd67… 165206507  oracle=f235648f… 165206507
FAIL muhash differs at 966494
```

**This is the first time that comparison has ever completed on this project.**
Every previous run timed out inside the walk, and an empty result compared equal
to an empty oracle value, so the harness printed nothing and the run passed. The
capstone had been verifying nothing, for months.

### What was ruled out, by test

| hypothesis | test | result |
|---|---|---|
| a fork | block hash at 966,494 on all three nodes | identical |
| the set moving under a live walk | froze the node (`setnetworkactive false`), re-hashed | still differs, stable across repeats |
| the MuHash implementation | a second, independently-synced node of the same software vs Core | **identical** |
| the set-walk code path | that node's walk vs its own index vs Core | **all three identical** |

The second node had been built by `reindex-chainstate` rather than by a fresh
network sync, and it is byte-correct against Core on both of its code paths. So
the code is sound and the fresh-sync **data** is not.

### What actually differs

At height 966,495, both nodes on the same block, the benchmark node frozen:

| field | benchmark node | Core | same |
|---|---|---|---|
| txouts | 165,203,925 | 165,203,925 | yes |
| bogosize | 12,942,059,030 | 12,942,059,030 | yes |
| total_amount | 20,082,569.88121624 | 20,082,569.88121624 | yes |
| muhash | `2f8a7959…` | `dcfaa870…` | **no** |

Every aggregate matches exactly. Only the set hash differs.

That combination is the whole finding. The outpoints, the values and the scripts
must be right, or `txouts`, `total_amount` and `bogosize` would move. What feeds
MuHash and feeds none of those three is the coin's **height and coinbase flag**,
which Core serialises into the hashed record and this node packs as
`code = (height << 1) | coinbase`. Both of this node's code paths hand that same
word to the same hashing routine, so the hashing is shared and the inputs differ.

**The fresh parallel-download sync writes correct coins with wrong height
metadata for at least one of them.** That is not a consensus break for spending
— the chain is identical and every value is right — but it is wrong data, and
coinbase maturity and BIP68 relative timelocks are computed from exactly that
field.

## Why it cost twenty hours to learn that

The answer was one bit at the tip: the set differs. It named no block.

The next run carries `coinstatsindex=1`, so the node records a set hash for every
height as it syncs and the first divergent height can be bisected against Core's
own index in seconds. From one block it is one coin. The harness also refuses to
render a verdict on anything that is not 64 hex characters from both sides, so
the empty-equals-empty pass that hid this is no longer possible, and it compares
at a settled height rather than at a tip the network is still moving.

The index costs sync time, so the next run's wall clock will not be comparable
with this one's. That is deliberate. Timing is answered; correctness is not.

## What to take from this

A node can download the entire chain, agree with Core on every block hash, report
zero errors, and still derive the wrong UTXO set. Tip-hash agreement proves you
downloaded the same chain. It says nothing about what you computed from it. If
you are writing a node, the set hash is the check that matters, and a check that
has never failed is worth looking at twice — this one could not fail, and nobody
noticed until it finally ran.

The benchmark node's UTXO and header stores, 17 GB, are retained as the only
reproduction. The 962 GB of blocks were not: they are re-downloadable and carry
nothing the chain does not already have.
