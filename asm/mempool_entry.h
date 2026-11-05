/* mempool_entry.h -- the POD bridge between the tx-accept policy registry
 * (bitcoin_mempool_policy.c, which owns the graph layout) and the RPC layer
 * (rpc_node.c, which renders getmempoolentry/-ancestors/-descendants).
 * Deliberately a plain struct of copies: the registry walk happens under
 * mp_lock inside bitcoin_mempool_policy.c; the RPC side only ever sees this
 * snapshot, never live registry pointers. */
#ifndef MEMPOOL_ENTRY_H
#define MEMPOOL_ENTRY_H

/* Caps: Core policy limits ancestor/descendant chains to 25; 64 leaves head
 * room without making the struct silly. depends/spentby are DIRECT edges
 * (also policy-capped well below 64). */
#define MPE_MAX_SET 64

typedef struct mp_entry_info {
    unsigned long long fee;          /* this tx, sat */
    unsigned long long size;         /* this tx, raw serialized bytes (registry unit) */
    /* DIRECT edges */
    int n_depends;                   /* parents (in-mempool inputs) */
    unsigned char depends[MPE_MAX_SET][32];
    int n_spentby;                   /* children (mempool txs spending us) */
    unsigned char spentby[MPE_MAX_SET][32];
    /* TRANSITIVE closures, INCLUDING this tx itself (Core semantics:
     * ancestorcount/descendantcount count the tx itself). Fees are the
     * registry's per-tx fees summed over the set. */
    int n_anc;                       /* |ancestors| incl self */
    unsigned char anc[MPE_MAX_SET][32];
    unsigned long long anc_fee;
    unsigned long long anc_size;     /* bytes over the same set (for the
                                        ancestor-package feerate GBT sorts by) */
    int n_desc;                      /* |descendants| incl self */
    unsigned char desc[MPE_MAX_SET][32];
    unsigned long long desc_fee;
    /* BIP141 sigop COST (x4 units), computed with prevout scripts at accept
     * time (tx_accept.c) and stored in the registry node; 0 for nodes
     * registered before the field existed or for genuinely sigop-free txs
     * (taproot keyspend-only) -- consumers treat it as exact. */
    unsigned int sigop_cost;
} mp_entry_info;

/* The WHOLE registry's graph, compactly (2026-10-06). A bulk caller used to
 * get one mp_entry_info per node: four fixed 64-txid arrays, ~8.3 KB each,
 * ~560 MB written at a 68k pool and ~+790 MB peak RSS per verbose
 * getrawmempool. Here each node is a small header and its four sets live in
 * one shared member list, in order depends, spentby, anc, desc.
 * mp_graph_expand rebuilds the node's mp_entry_info exactly (same members,
 * same order) for the consumers that read that shape. Owner frees with
 * mp_graph_free.
 *
 * 2026-10-07: a member is the INDEX of its node in this graph (4 bytes), not
 * its txid (32): every member of a node's sets is itself a node, so its txid
 * is node[i].txid. At a 68k pool that is mostly chains -- the test's shape
 * and, at ~90% cluster members, production's -- the txid list was ~50 MB of
 * the call's ~63 MB graph. A builder whose member is not (yet) a node cannot
 * use this format; mp_graph_append's caller resolves each member first. */
typedef struct mp_graph_node {
    unsigned char txid[32];
    unsigned long long fee, size, anc_fee, anc_size, desc_fee;
    unsigned long off;               /* first member in mp_graph.mem */
    unsigned int sigop_cost;
    unsigned short n_depends, n_spentby, n_anc, n_desc;
} mp_graph_node;
typedef struct mp_graph {
    mp_graph_node* node; long n, cap;
    unsigned int* mem; unsigned long n_mem, cap_mem;   /* node indices */
} mp_graph;

#include <stdlib.h>
#include <string.h>
static inline void mp_graph_free(mp_graph* g){
    free(g->node); free(g->mem); memset(g, 0, sizeof *g);
}
/* append one node: its header from e (the counts and sums; e's txid arrays
 * are not read) and its members from idx, the node indices of e's depends,
 * spentby, anc and desc in that order. 0 on success, -1 on allocation
 * failure (the graph is left valid, without the node) */
static inline int mp_graph_append(mp_graph* g, const unsigned char txid[32], const mp_entry_info* e,
                                  const unsigned int* idx){
    unsigned long k = (unsigned long)e->n_depends + e->n_spentby + e->n_anc + e->n_desc;
    if (g->n == g->cap){
        long c2 = g->cap ? g->cap * 2 : 1024;
        mp_graph_node* n2 = (mp_graph_node*)realloc(g->node, (size_t)c2 * sizeof *n2);
        if (!n2) return -1;
        g->node = n2; g->cap = c2;
    }
    if (g->n_mem + k > g->cap_mem){
        unsigned long c2 = g->cap_mem ? g->cap_mem * 2 : 4096;
        while (c2 < g->n_mem + k) c2 *= 2;
        unsigned int* m2 = (unsigned int*)realloc(g->mem, (size_t)c2 * sizeof *m2);
        if (!m2) return -1;
        g->mem = m2; g->cap_mem = c2;
    }
    mp_graph_node* o = &g->node[g->n];
    memcpy(o->txid, txid, 32);
    o->fee = e->fee; o->size = e->size; o->sigop_cost = e->sigop_cost;
    o->anc_fee = e->anc_fee; o->anc_size = e->anc_size; o->desc_fee = e->desc_fee;
    o->off = g->n_mem;
    o->n_depends = (unsigned short)e->n_depends; o->n_spentby = (unsigned short)e->n_spentby;
    o->n_anc = (unsigned short)e->n_anc; o->n_desc = (unsigned short)e->n_desc;
    memcpy(g->mem + g->n_mem, idx, (size_t)k * sizeof *idx);
    g->n_mem += k; g->n++;
    return 0;
}
/* node q's direct edges, as node indices, without expanding it */
static inline const unsigned int* mp_graph_depends(const mp_graph* g, long q){
    return g->mem + g->node[q].off;
}
static inline const unsigned int* mp_graph_spentby(const mp_graph* g, long q){
    return g->mem + g->node[q].off + g->node[q].n_depends;
}
/* node q as the full record: the counted members are set, the arrays past
 * them are not (no consumer reads past a count) */
static inline void mp_graph_expand(const mp_graph* g, long q, mp_entry_info* out){
    const mp_graph_node* o = &g->node[q];
    const unsigned int* m = g->mem + o->off;
    out->fee = o->fee; out->size = o->size; out->sigop_cost = o->sigop_cost;
    out->anc_fee = o->anc_fee; out->anc_size = o->anc_size; out->desc_fee = o->desc_fee;
    out->n_depends = o->n_depends; out->n_spentby = o->n_spentby;
    out->n_anc = o->n_anc; out->n_desc = o->n_desc;
    for (int i = 0; i < o->n_depends; i++) memcpy(out->depends[i], g->node[*m++].txid, 32);
    for (int i = 0; i < o->n_spentby; i++) memcpy(out->spentby[i], g->node[*m++].txid, 32);
    for (int i = 0; i < o->n_anc; i++)     memcpy(out->anc[i],     g->node[*m++].txid, 32);
    for (int i = 0; i < o->n_desc; i++)    memcpy(out->desc[i],    g->node[*m++].txid, 32);
}

#endif
