/* mempool_cluster.c -- see mempool_cluster.h and
 * docs/devlog/PLAN_CLUSTER_MEMPOOL.md.
 *
 * Stage 1 and 2 of the cluster mempool: the chunking rule and the topological
 * check. Both are exactly specified by Core, which is why they come first --
 * they can be tested to the letter offline, with no oracle and no mempool. */
#include <string.h>
#include "mempool_cluster.h"

int mpc_feerate_cmp(uint64_t fee_a, uint64_t wt_a, uint64_t fee_b, uint64_t wt_b)
{
    /* Core's FeeFrac compares fee_a/size_a against fee_b/size_b by
     * cross-multiplication (util/feefrac.h): no division, no rounding, no
     * floating point -- two feerates that differ by one satoshi in a thousand
     * blocks must not compare equal because a double lost the difference.
     * The products overflow 64 bits routinely (a 5,000,000 sat fee against a
     * 4,000,000 weight is already 2e13, and the pair multiplies), so the
     * arithmetic is done in 128 bits.
     *
     * A zero weight would be a division by zero in the rational form. It cannot
     * occur for a real transaction, and treating it as "lowest" keeps the
     * comparator total rather than letting a malformed entry order randomly. */
    if (wt_a == 0 && wt_b == 0) return 0;
    if (wt_a == 0) return -1;
    if (wt_b == 0) return 1;
    __int128 l = (__int128)fee_a * (__int128)wt_b;
    __int128 r = (__int128)fee_b * (__int128)wt_a;
    return l < r ? -1 : (l > r ? 1 : 0);
}

int mpc_is_topological(const mpc_cluster* cl, const int* lin)
{
    if (!cl || !lin) return 0;
    uint64_t seen = 0;
    for (int i = 0; i < cl->n; i++) {
        int idx = lin[i];
        if (idx < 0 || idx >= cl->n) return 0;
        uint64_t bit = (uint64_t)1 << idx;
        if (seen & bit) return 0;                    /* repeated member */
        /* every ancestor must already have been placed. ancestors includes
         * self, so mask self out before the test. */
        uint64_t need = cl->m[idx].ancestors & ~bit;
        if ((need & seen) != need) return 0;
        seen |= bit;
    }
    return seen == (cl->n >= 64 ? ~(uint64_t)0 : (((uint64_t)1 << cl->n) - 1));
}

int mpc_chunk_linearization(const mpc_cluster* cl, const int* lin, mpc_chunking* out)
{
    if (!cl || !lin || !out) return -1;
    memset(out, 0, sizeof *out);

    /* reject anything that is not a permutation of the members: chunking a
     * malformed ordering would silently produce a plausible-looking answer over
     * the wrong set, which is the failure mode this project keeps paying for. */
    uint64_t seen = 0;
    for (int i = 0; i < cl->n; i++) {
        int idx = lin[i];
        if (idx < 0 || idx >= cl->n) return -1;
        uint64_t bit = (uint64_t)1 << idx;
        if (seen & bit) return -1;
        seen |= bit;
    }

    for (int i = 0; i < cl->n; i++) {
        int idx = lin[i];
        mpc_chunk nc = { (uint64_t)1 << idx, cl->m[idx].fee, cl->m[idx].weight };
        /* Core: "As long as the new chunk has a higher feerate than the last
         * chunk so far, absorb it." Strictly higher -- equal feerates do NOT
         * merge, which is what keeps chunk boundaries stable when a cluster
         * holds several transactions at the same rate. */
        while (out->n > 0 &&
               mpc_feerate_cmp(nc.fee, nc.weight,
                               out->c[out->n - 1].fee, out->c[out->n - 1].weight) > 0) {
            mpc_chunk* prev = &out->c[out->n - 1];
            nc.members |= prev->members;
            nc.fee     += prev->fee;
            nc.weight  += prev->weight;
            out->n--;
        }
        out->c[out->n++] = nc;
    }
    return 0;
}

void mpc_set_totals(const mpc_cluster* cl, uint64_t set, uint64_t* fee, uint64_t* weight)
{
    uint64_t f = 0, w = 0;
    for (int i = 0; i < cl->n; i++)
        if (set & ((uint64_t)1 << i)) { f += cl->m[i].fee; w += cl->m[i].weight; }
    if (fee) *fee = f;
    if (weight) *weight = w;
}

int mpc_linearize_ancestor_score(const mpc_cluster* cl, int* lin)
{
    if (!cl || !lin || cl->n < 0 || cl->n > MPC_MAX_CLUSTER) return -1;
    uint64_t all = (cl->n >= 64) ? ~(uint64_t)0 : (((uint64_t)1 << cl->n) - 1);
    uint64_t remaining = all;
    int out = 0;

    while (remaining) {
        /* Pick the best ancestor-closed set among what is left. Restricting each
         * candidate's ancestors to `remaining` is what keeps this correct as the
         * loop proceeds: ancestors already emitted are no longer a cost, which
         * is exactly why a CPFP child becomes attractive once its parent is
         * gone -- and why the parent gets pulled in with it when it is not. */
        int best = -1;
        uint64_t best_set = 0, best_fee = 0, best_wt = 0;
        for (int i = 0; i < cl->n; i++) {
            if (!(remaining & ((uint64_t)1 << i))) continue;
            uint64_t set = cl->m[i].ancestors & remaining;
            if (!set) return -1;                   /* self must be in its own ancestors */
            uint64_t fee, wt;
            mpc_set_totals(cl, set, &fee, &wt);
            if (best < 0) { best = i; best_set = set; best_fee = fee; best_wt = wt; continue; }
            int c = mpc_feerate_cmp(fee, wt, best_fee, best_wt);
            /* Core's emission order: feerate high to low, then SMALLER weight,
             * then lowest index. The last two are not cosmetic -- without a
             * total order, two runs over the same cluster can disagree and a
             * differential becomes noise. */
            int better = (c > 0) || (c == 0 && wt < best_wt) ||
                         (c == 0 && wt == best_wt && i < best);
            if (better) { best = i; best_set = set; best_fee = fee; best_wt = wt; }
        }
        if (best < 0) return -1;

        /* Emit the chosen set in topological order: repeatedly take the lowest
         * member whose own ancestors within the set are already placed. */
        uint64_t placed = 0, todo = best_set;
        while (todo) {
            int chosen = -1;
            for (int i = 0; i < cl->n; i++) {
                if (!(todo & ((uint64_t)1 << i))) continue;
                uint64_t need = cl->m[i].ancestors & best_set & ~((uint64_t)1 << i);
                if ((need & placed) == need) { chosen = i; break; }
            }
            if (chosen < 0) return -1;             /* a cycle: not a valid DAG */
            lin[out++] = chosen;
            placed |= (uint64_t)1 << chosen;
            todo   &= ~((uint64_t)1 << chosen);
        }
        remaining &= ~best_set;
    }
    return (out == cl->n) ? 0 : -1;
}

static int mpc_find(const mpc_cluster* cl, const unsigned char txid[32])
{
    for (int i = 0; i < cl->n; i++)
        if (memcmp(cl->txid[i], txid, 32) == 0) return i;
    return -1;
}

int mpc_build_cluster(void* ctx, mpc_lookup_fn look,
                      const unsigned char seed[32], mpc_cluster* out)
{
    if (!look || !seed || !out) return -1;
    memset(out, 0, sizeof *out);

    mpc_entry e;
    if (look(ctx, seed, &e) != 1) return -1;

    /* --- 1. collect the connected component, breadth-first ---------------
     * Through parents AND children: a cluster is the whole component, not the
     * ancestor set. A sibling that shares a parent is in the same cluster even
     * though neither is an ancestor of the other, and it competes for the same
     * block space -- which is the entire reason Core groups them. */
    memcpy(out->txid[0], seed, 32);
    out->n = 1;
    for (int head = 0; head < out->n; head++) {
        if (look(ctx, out->txid[head], &e) != 1) return -1;
        out->m[head].fee = e.fee;
        out->m[head].weight = e.weight;
        for (int side = 0; side < 2; side++) {
            int cnt = side ? e.n_children : e.n_parents;
            for (int k = 0; k < cnt; k++) {
                const unsigned char* id = side ? e.children[k] : e.parents[k];
                if (mpc_find(out, id) >= 0) continue;
                if (out->n >= MPC_MAX_CLUSTER) { out->truncated = 1; return 0; }
                memcpy(out->txid[out->n], id, 32);
                out->n++;
            }
        }
    }

    /* --- 2. direct parent edges, restricted to the component ------------- */
    for (int i = 0; i < out->n; i++) {
        out->m[i].ancestors = (uint64_t)1 << i;         /* includes self */
        out->m[i].descendants = (uint64_t)1 << i;
    }
    uint64_t direct[MPC_MAX_CLUSTER];
    memset(direct, 0, sizeof direct);
    for (int i = 0; i < out->n; i++) {
        if (look(ctx, out->txid[i], &e) != 1) return -1;
        for (int k = 0; k < e.n_parents; k++) {
            int p = mpc_find(out, e.parents[k]);
            if (p >= 0) direct[i] |= (uint64_t)1 << p;
        }
    }

    /* --- 3. transitive closure ------------------------------------------
     * Repeat until nothing changes. Bounded by n passes for a DAG, and n <= 64,
     * so the loop is bounded whatever the graph shape -- a cycle would
     * otherwise spin here rather than being reported. */
    for (int pass = 0; pass < out->n + 1; pass++) {
        int changed = 0;
        for (int i = 0; i < out->n; i++) {
            uint64_t acc = out->m[i].ancestors | direct[i];
            uint64_t d = direct[i];
            while (d) {
                int p = __builtin_ctzll(d); d &= d - 1;
                acc |= out->m[p].ancestors;
            }
            if (acc != out->m[i].ancestors) { out->m[i].ancestors = acc; changed = 1; }
        }
        if (!changed) goto closed;
    }
    return -1;      /* did not converge: the graph is not a DAG */
closed:
    /* --- 4. descendants are the transpose of ancestors ------------------- */
    for (int i = 0; i < out->n; i++)
        for (int j = 0; j < out->n; j++)
            if (out->m[j].ancestors & ((uint64_t)1 << i))
                out->m[i].descendants |= (uint64_t)1 << j;
    return 0;
}

/* ---- PostLinearize --------------------------------------------------------
 * One pass, as Core states it (cluster_linearize.h):
 *
 *   Start with an empty list of groups L=[]. For every transaction i in the old
 *   linearization, front to back: append a new group C=[i]. While L has a group
 *   P immediately before C whose feerate is LOWER than C's: if C depends on P,
 *   merge P into C (P+C); otherwise swap P and C. Output is the concatenation.
 *
 * The backward pass is the same with the input reversed, ancestors and
 * descendants exchanged, the feerate sense flipped, and the output reversed --
 * which is Core's "the meanings of parent/child, and of high/low feerate are
 * reversed".
 *
 * n <= 64, so groups are plain arrays and the O(n^2) shape costs nothing worth
 * the linked lists Core needs at its scale. */
typedef struct { int idx[MPC_MAX_CLUSTER]; int n; uint64_t members, fee, weight; } mpc_group;

static void mpc_one_pass(const mpc_cluster* cl, int* lin, int backward)
{
    mpc_group g[MPC_MAX_CLUSTER];
    int ng = 0;

    for (int step = 0; step < cl->n; step++) {
        int i = backward ? lin[cl->n - 1 - step] : lin[step];
        mpc_group* c = &g[ng++];
        c->n = 1; c->idx[0] = i;
        c->members = (uint64_t)1 << i;
        c->fee = cl->m[i].fee; c->weight = cl->m[i].weight;

        int pos = ng - 1;
        while (pos > 0) {
            mpc_group* P = &g[pos - 1];
            mpc_group* C = &g[pos];
            /* forward: absorb/overtake a PRECEDING group of LOWER feerate.
             * backward: the sense is flipped, so it is a HIGHER one. */
            int cmp = mpc_feerate_cmp(P->fee, P->weight, C->fee, C->weight);
            if (!(backward ? (cmp > 0) : (cmp < 0))) break;

            /* Does C depend on P? Forward: any member of C has an ancestor in
             * P. Backward: the relation is transposed, so it is descendants. */
            uint64_t link = 0;
            for (int k = 0; k < C->n; k++)
                link |= backward ? cl->m[C->idx[k]].descendants
                                 : cl->m[C->idx[k]].ancestors;
            int depends = (link & P->members) != 0;

            if (depends) {
                /* merge P into C, keeping P's members in front of C's */
                mpc_group merged;
                merged.n = 0;
                for (int k = 0; k < P->n; k++) merged.idx[merged.n++] = P->idx[k];
                for (int k = 0; k < C->n; k++) merged.idx[merged.n++] = C->idx[k];
                merged.members = P->members | C->members;
                merged.fee = P->fee + C->fee;
                merged.weight = P->weight + C->weight;
                g[pos - 1] = merged;
                for (int k = pos; k < ng - 1; k++) g[k] = g[k + 1];
                ng--; pos--;
            } else {
                mpc_group t = *P; *P = *C; *C = t;   /* swap: C moves earlier */
                pos--;
            }
        }
    }

    int out = 0;
    for (int k = 0; k < ng; k++)
        for (int j = 0; j < g[k].n; j++) lin[out++] = g[k].idx[j];
    if (backward) {                                  /* the pass built it reversed */
        for (int k = 0; k < cl->n / 2; k++) {
            int t = lin[k]; lin[k] = lin[cl->n - 1 - k]; lin[cl->n - 1 - k] = t;
        }
    }
}

int mpc_post_linearize(const mpc_cluster* cl, int* lin)
{
    if (!cl || !lin || !mpc_is_topological(cl, lin)) return -1;
    /* backward first: that is what gives the moved-tree property */
    mpc_one_pass(cl, lin, 1);
    mpc_one_pass(cl, lin, 0);
    /* A pass that produced a non-topological order would be a defect, not a
     * worse linearization -- refuse rather than hand back something a block
     * template would spend out of order. */
    return mpc_is_topological(cl, lin) ? 0 : -1;
}

int mpc_diagram_at_least_as_good(const mpc_cluster* cl, const int* a, const int* b)
{
    mpc_chunking ca, cb;
    if (mpc_chunk_linearization(cl, a, &ca) != 0) return 0;
    if (mpc_chunk_linearization(cl, b, &cb) != 0) return 0;
    /* Walk B's cumulative curve. At each of B's breakpoints, A must have got at
     * least as much fee into the same weight budget. Both hold the same
     * transactions, so the curves meet at the end; only the path matters. */
    uint64_t bw = 0, bf = 0;
    for (int i = 0; i < cb.n; i++) {
        bw += cb.c[i].weight; bf += cb.c[i].fee;
        /* fee A achieves within weight budget bw, taking whole chunks and then
         * a proportional slice of the chunk it lands inside (the diagram is
         * piecewise linear, which is what makes chunks the right unit) */
        uint64_t aw = 0; __int128 af = 0;
        for (int k = 0; k < ca.n; k++) {
            if (aw + ca.c[k].weight <= bw) { aw += ca.c[k].weight; af += ca.c[k].fee; continue; }
            uint64_t room = bw - aw;
            if (room && ca.c[k].weight)
                af += ((__int128)ca.c[k].fee * (__int128)room) / (__int128)ca.c[k].weight;
            aw = bw; break;
        }
        if (af < (__int128)bf) return 0;
    }
    return 1;
}
