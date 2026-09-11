# An assembly Bitcoin node vs Bitcoin Core v31.1: a full mainnet IBD, measured

2026-09-11. Benchmark tag `bench-2026-09-10`, node commit `4a4872cf`.

This is a report on one fresh mainnet initial block download by an independent
Bitcoin full node written in x86-64 assembly, measured against Bitcoin Core
v31.1 on the same machine, and on the defect that measurement found.

**The short version: it finished an hour ahead of Core, and it was still wrong.**
The chain it built is identical to Core's, block for block. The UTXO set it
derived from that chain is not.

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

| | assembly node | Core v31.1 |
|---|---|---|
| blocks | 966,369 | 965,703 |
| wall clock | **20h 08m** | **21h 11m** |
| UTXO engine caught up | 20h 15m | n/a |
| bad blocks / gaps | zero / none | zero |
| tip vs oracle | identical by hash | identical by hash |

The chain was verified by block hash against a third node at heights 966,000,
966,494 and 966,495. All three agree.

## The hour is not a win

Segment by segment tells a different story from the total.

| heights | Core | assembly node | ratio |
|---|---|---|---|
| 400k–500k | 2h 07m | 2h 05m | 0.98x |
| 500k–650k | 3h 44m | 4h 05m | 1.09x slower |
| 650k–800k | 4h 45m | 5h 20m | 1.12x slower |
| 800k–850k | 4h 21m | 2h 15m | 0.52x |
| 850k–932k | 3h 13m | 3h 25m | 1.06x slower |

The two are level to height 500,000 and the assembly node is then a steady
**8 to 12 percent slower** in every segment but one. That one segment is where
the hour came from, and it is not a property of either node's download code:

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
