/* mempool_cluster.h -- Core's cluster mempool: clusters, linearization, chunks.
 *
 * See docs/devlog/PLAN_CLUSTER_MEMPOOL.md for the design and the staging.
 *
 * A CLUSTER is a connected component of the in-mempool dependency graph,
 * bounded at MPC_MAX_CLUSTER transactions (Core's DEFAULT_CLUSTER_LIMIT, 64).
 * That bound is why this header can be as simple as it is: membership and the
 * ancestor/descendant sets are one uint64_t each, so set algebra is a single
 * instruction and a cluster costs 24 bytes per member.
 *
 * A LINEARIZATION is an ordering of the cluster in which every parent precedes
 * every child. CHUNKS are that ordering split into runs of non-increasing
 * feerate, by the rule in Core's ChunkLinearizationInfo.
 */
#ifndef MEMPOOL_CLUSTER_H
#define MEMPOOL_CLUSTER_H
#include <stdint.h>

#define MPC_MAX_CLUSTER 64          /* Core DEFAULT_CLUSTER_LIMIT (policy.h) */

/* One member of a cluster. `ancestors` and `descendants` INCLUDE self, which is
 * Core's convention in DepGraph::Entry and matches this node's existing
 * ancestorcount/descendantcount semantics. Bit k refers to members[k]. */
typedef struct {
    uint64_t ancestors;
    uint64_t descendants;
    uint64_t fee;               /* sat */
    uint64_t weight;            /* Core's sigops-ADJUSTED weight */
} mpc_member;

typedef struct {
    int         n;                          /* members in use */
    int         truncated;                  /* the component exceeded the bound */
    mpc_member  m[MPC_MAX_CLUSTER];
    unsigned char txid[MPC_MAX_CLUSTER][32];
} mpc_cluster;

/* One chunk: a set of members and their summed fee/weight. */
typedef struct {
    uint64_t members;           /* bitset over cluster member indices */
    uint64_t fee;
    uint64_t weight;
} mpc_chunk;

typedef struct {
    int       n;
    mpc_chunk c[MPC_MAX_CLUSTER];
} mpc_chunking;

/* Split a linearization into chunks, exactly as Core's ChunkLinearizationInfo:
 * each transaction starts as a singleton chunk, and while the new chunk's
 * feerate exceeds the previous chunk's, the previous is absorbed into it.
 * `lin` holds cl->n member indices in linearization order.
 * Returns 0, or -1 if lin is not a permutation of the cluster's members. */
int mpc_chunk_linearization(const mpc_cluster* cl, const int* lin, mpc_chunking* out);

/* Is `lin` topologically valid -- does every parent precede every child?
 * 1 yes / 0 no. A linearization that fails this is not merely suboptimal, it is
 * unusable: it would have a block template spend an output before creating it. */
int mpc_is_topological(const mpc_cluster* cl, const int* lin);

/* Build a linearization: an ordering in which every parent precedes every child.
 *
 * STAGE 3 (see the plan): ancestor-score greedy. Repeatedly take the remaining
 * ancestor-closed set with the best feerate and emit it, topologically, then
 * remove it and repeat. This is the classic mining ordering and is what this
 * node already selects by; it is deterministic, always topologically valid, and
 * never worse than emitting in arrival order.
 *
 * It is NOT Core's optimum. Core v31 searches with a spanning-forest algorithm
 * under a cost budget and a seeded RNG, and reports whether it reached the
 * optimum; two correct implementations agree only where both do. Improving on
 * this is stage 5 and is deliberately separate: a valid-but-suboptimal
 * linearization is a working mempool, a subtly wrong one is a broken one.
 *
 * Ties are broken as Core breaks them when emitting ready chunks
 * (SpanningForestState::GetLinearization): better feerate first, then SMALLER
 * weight, then lowest member index. Deterministic ordering matters beyond
 * tidiness -- an unstable order makes two runs over the same mempool disagree
 * and turns a differential into noise.
 *
 * Writes cl->n indices into lin[]. Returns 0, or -1 on a malformed cluster.  */
int mpc_linearize_ancestor_score(const mpc_cluster* cl, int* lin);

/* Sum fee and weight over a member bitset. */
void mpc_set_totals(const mpc_cluster* cl, uint64_t set, uint64_t* fee, uint64_t* weight);

/* Compare two feerates as Core's FeeFrac does: a.fee/a.weight vs b.fee/b.weight
 * by cross-multiplication, so no division and no floating point. Returns
 * -1/0/1. 64x64 products can overflow 64 bits, so this uses __int128. */
int mpc_feerate_cmp(uint64_t fee_a, uint64_t wt_a, uint64_t fee_b, uint64_t wt_b);

#endif
