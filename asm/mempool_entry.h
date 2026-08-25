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
    int n_desc;                      /* |descendants| incl self */
    unsigned char desc[MPE_MAX_SET][32];
    unsigned long long desc_fee;
} mp_entry_info;

#endif
