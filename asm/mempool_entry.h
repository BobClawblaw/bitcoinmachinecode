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
 * one shared txid list, in order depends, spentby, anc, desc -- a singleton
 * costs its header plus two txids (itself, in anc and in desc).
 * mp_graph_expand rebuilds the node's mp_entry_info exactly (same members,
 * same order) for the consumers that read that shape. Owner frees with
 * mp_graph_free. */
typedef struct mp_graph_node {
    unsigned char txid[32];
    unsigned long long fee, size, anc_fee, anc_size, desc_fee;
    unsigned long off;               /* first member in mp_graph.mem */
    unsigned int sigop_cost;
    unsigned short n_depends, n_spentby, n_anc, n_desc;
} mp_graph_node;
typedef struct mp_graph {
    mp_graph_node* node; long n, cap;
    unsigned char (*mem)[32]; unsigned long n_mem, cap_mem;
} mp_graph;

#include <stdlib.h>
#include <string.h>
static inline void mp_graph_free(mp_graph* g){
    free(g->node); free(g->mem); memset(g, 0, sizeof *g);
}
/* append one node from its full record; 0 on success, -1 on allocation
 * failure (the graph is left valid, without the node) */
static inline int mp_graph_append(mp_graph* g, const unsigned char txid[32], const mp_entry_info* e){
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
        unsigned char (*m2)[32] = (unsigned char (*)[32])realloc(g->mem, (size_t)c2 * 32);
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
    unsigned char (*m)[32] = g->mem + g->n_mem;
    memcpy(m, e->depends, (size_t)e->n_depends * 32); m += e->n_depends;
    memcpy(m, e->spentby, (size_t)e->n_spentby * 32); m += e->n_spentby;
    memcpy(m, e->anc, (size_t)e->n_anc * 32); m += e->n_anc;
    memcpy(m, e->desc, (size_t)e->n_desc * 32);
    g->n_mem += k; g->n++;
    return 0;
}
/* node q's direct edges, without expanding it */
static inline const unsigned char (*mp_graph_depends(const mp_graph* g, long q))[32]{
    return (const unsigned char (*)[32])g->mem + g->node[q].off;
}
static inline const unsigned char (*mp_graph_spentby(const mp_graph* g, long q))[32]{
    return (const unsigned char (*)[32])g->mem + g->node[q].off + g->node[q].n_depends;
}
/* node q as the full record: the counted members are set, the arrays past
 * them are not (no consumer reads past a count) */
static inline void mp_graph_expand(const mp_graph* g, long q, mp_entry_info* out){
    const mp_graph_node* o = &g->node[q];
    const unsigned char (*m)[32] = (const unsigned char (*)[32])g->mem + o->off;
    out->fee = o->fee; out->size = o->size; out->sigop_cost = o->sigop_cost;
    out->anc_fee = o->anc_fee; out->anc_size = o->anc_size; out->desc_fee = o->desc_fee;
    out->n_depends = o->n_depends; out->n_spentby = o->n_spentby;
    out->n_anc = o->n_anc; out->n_desc = o->n_desc;
    memcpy(out->depends, m, (size_t)o->n_depends * 32); m += o->n_depends;
    memcpy(out->spentby, m, (size_t)o->n_spentby * 32); m += o->n_spentby;
    memcpy(out->anc, m, (size_t)o->n_anc * 32); m += o->n_anc;
    memcpy(out->desc, m, (size_t)o->n_desc * 32);
}

#endif
