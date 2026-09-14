# Cluster mempool: design and staged plan

> **CORRECTED 2026-09-14.** The staging below was written from Core's source
> without reading enough of ours, and two of its seven stages describe work that
> was already done. Kept because the design section is still right and the
> correction is the useful part.
>
> **Eviction (stage 6) was already cluster-aware.** `bitcoin_mempool_policy.c`
> implements connected components, ancestor-set greedy linearization, chunking
> and worst-chunk eviction, described in its own comments as Core v31
> `TrimToSize`, and `test_mempool_chunks` covers the CPFP-versus-single case
> that cluster eviction exists to fix.
>
> **Mining (stage 7) was already cluster-aware.** `rpc_chain.c` builds clusters,
> chunks them, orders chunks by feerate across clusters, and fills the block by
> chunk.
>
> **Accept already enforces Core's limit** — 64 transactions / 101 kvB, rejecting
> with `too-large-cluster`, including the wide shapes ancestor limits miss and
> the post-replacement view for RBF.
>
> So the actual state after stages 1-5 is not "a cluster mempool where there was
> none". It is **three implementations of the same idea in one tree**: the
> eviction path, the mining path, and `mempool_cluster.c`. That is the problem
> worth solving now, and it is not a refactor:
>
> - the mining path computes feerate over **vsize** where the module uses
>   **adjusted weight**, and breaks ties by **txid** where the module uses index.
>   Both change which transactions land in a block.
> - the mining path has **no test coverage of selection at all**.
>
> **The order that work has to happen in:** characterisation tests pinning
> today's selection behaviour, then the unification, then a differential against
> Core with `mining_polish_diff.py` on the live node. Rewriting block selection
> with nothing in the gate that could catch a regression is not a thing to do
> blind.
>
> The cluster bound is now 64 everywhere (it was 64 / 128 / 512), pinned by a
> test.


2026-09-13. Decision taken: implement it, rather than record it as a permanent
divergence. This file is the design and the staging, written before the code so
the hard parts are named in advance.

## What Core actually does

Core replaced the ancestor/descendant mempool with a **cluster mempool**.

1. **Cluster.** A connected component of the in-mempool dependency graph.
   Bounded by `DEFAULT_CLUSTER_LIMIT = 64` transactions (`policy/policy.h`).
   That bound is the single most useful fact in this design: **a cluster's
   membership fits in one `uint64_t` bitset**, so ancestor and descendant sets
   are one word each and set algebra is a machine instruction.
2. **Linearization.** An ordering of the cluster that respects topology
   (parents before children) and is good in the "feerate diagram" sense.
   Computed by `cluster_linearize::Linearize` (`cluster_linearize.h`, ~2,058
   lines, mostly one `SpanningForestState` class).
3. **Chunks.** The linearization split into runs of non-increasing feerate.
   This part is tiny and exactly specified (`ChunkLinearizationInfo`):

   > walk the linearization; each transaction starts as a singleton chunk;
   > while the new chunk's feerate exceeds the previous chunk's, absorb the
   > previous chunk into it.

   Everything user-visible — `getmempoolcluster`, `chunkweight`, `fees.chunk`
   — is a projection of the chunks.

## The fact that shapes the whole plan

**Core's linearization is not canonical, and we cannot bit-match it in general.**
`Linearize()` takes an `rng_seed` "to prevent peers from predicting exactly
which clusters would be hard for us to linearize", and a `max_cost` budget; it
returns a flag saying whether the result is *optimal with minimal chunks*. Two
correct implementations agree only when both reach that optimum, where the
result is canonical up to the `fallback_order` comparator.

So the parity target is **not** "identical chunk lists to Core on the same
mempool". It is:

* topologically valid (every parent precedes every child);
* chunk feerates non-increasing;
* **identical to Core whenever the optimum is reached**, which for clusters of
  the size seen in practice is the common case;
* never worse, in the feerate-diagram sense, than the ancestor-score ordering
  we can compute cheaply.

A differential against Core must therefore compare *diagram quality and
topology*, not raw equality, or it will report divergences that are not defects.
This is exactly the trap the muhash capstone fell into from the other side:
comparing the wrong thing confidently.

## What it buys, in order of actual importance

1. **Mining template selection.** Chunks in feerate order is how Core fills a
   block. This is the real argument for doing the work; today this node selects
   by ancestor score, which can differ.
2. **Eviction.** Core evicts the lowest-feerate chunk, not the lowest-feerate
   transaction. Evicting a parent whose child pays for it is a real defect.
3. **RBF.** Cluster-aware replacement rules.
4. **The RPC fields.** `getmempoolcluster` for clusters above one transaction,
   plus `chunkweight` and `fees.chunk`. Cosmetic next to the above.

## Staging

Each stage lands on its own, gated, and is useful without the next.

| stage | content | verification |
|---|---|---|
| 1 | cluster discovery: connected components over the existing parent edges, bounded at 64, as `uint64_t` membership + per-member ancestor/descendant words | unit tests over hand-built graphs: chains, forks, diamonds, the 64 bound, a cluster that would exceed it |
| 2 | chunking, exactly as `ChunkLinearizationInfo` | unit tests incl. the absorb rule; vectors taken from Core's own test cases |
| 3 | linearization v1: ancestor-score greedy, topologically valid, deterministic | property tests: topology holds, chunk feerates non-increasing, never worse than input order |
| 4 | wire to RPC: `getmempoolcluster` for n>1, `chunkweight`, `fees.chunk` | the existing field-parity differential, plus a diagram-quality comparison against Core |
| 5 | linearization v2: optimization toward Core's optimum under a cost budget | compare diagram quality against Core over live mempool clusters |
| 6 | wire to eviction | the eviction tests, extended: a parent whose child pays for it must not be evicted first |
| 7 | wire to mining template | template differential against Core at the same tip |

Stages 6 and 7 in the table below were ALREADY DONE before this work started --
see the correction above. Stages 1 and 2 are exactly specified and fully testable
offline. Stage 3 gives a
correct, usable linearization. Stage 5 is where the hard search lives, and it is
deliberately last among the linearization work: a valid-but-suboptimal
linearization is a working mempool, while a subtly wrong one is a broken one.

## What must not happen

* No partial wiring. Stages 6 and 7 change which transactions get evicted and
  mined. Neither lands until the linearization underneath it is tested, because
  a bad linearization there loses money rather than printing a wrong number.
* No claiming parity we have not measured. Until stage 5, the honest statement
  is "topologically valid and chunked like Core's, ordering may differ".
* The existing ancestor/descendant graph stays. It answers
  `getmempoolancestors`/`getmempooldescendants`, which Core still serves, and it
  is what stage 1 is built from.
