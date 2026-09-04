/* bitcoin_mempool_policy.c -- mempool POLICY layer, Core-parity semantics.
 *
 * 100% pure C glue over the repo's verified asm primitives (same model as
 * wallet_core.c):
 *   - bitcoin_mempool.asm (mpool_put/get/del): structural tx storage
 *   - daemon/mempool_compact.c (mpool_compact): blob reclamation
 *   - the caller supplies the BIP141 txid (computed via bitcoin_tx.asm tx_txid)
 *
 * This is the gatekeeper Core calls MemPoolAccept + CTxMemPool policy, read
 * from Core's own source (validation.cpp / txmempool.cpp / policy/{policy,
 * rbf}.cpp) rather than remembered (LOG.md 2026-08-27 gap survey):
 *
 *   1. standardness (IsStandardTx): version bounds, weight/size bounds,
 *      scriptsig size + push-only, output script types, datacarrier budget,
 *      dust (spend-cost model at the 3000 sat/kvB discard rate) -- with
 *      Core's exact reject strings. Disable with acceptnonstdtxn (Core's
 *      own regtest-only knob; several vector tests use it too).
 *   2. fee checks over VSIZE (BIP141 weight/4), not raw length: min relay
 *      floor ("min relay fee not met") and the DYNAMIC mempool floor
 *      ("mempool min fee not met") which decays exactly like Core's
 *      rolling minimum (halflife 12h, faster when the pool is emptier,
 *      zero below incrementalrelayfee/2, paused until a block connects
 *      after each bump).
 *   3. RBF per Core's ReplacementChecks / classic BIP125: signaling checked
 *      on the REPLACED txs and only when fullrbf is off; conflicts evicted
 *      WITH their descendants; disjointness ("bad-txns-spends-conflicting-
 *      tx"); no new unconfirmed inputs ("replacement-adds-unconfirmed");
 *      <=100 evicted ("too many potential replacements"); fees >= replaced
 *      total AND the increment pays for the replacement's own vsize at
 *      incrementalrelayfee ("insufficient fee").
 *   4. ancestor / descendant count+vsize limits ("too-long-mempool-chain").
 *   5. TrimToSize eviction by descendant PACKAGE: evict argmin of
 *      max(own feerate, with-descendants feerate) together with its whole
 *      descendant set; the removed package feerate + incrementalrelayfee
 *      becomes the rolling floor ("mempool full" when the incoming tx
 *      itself would be the worst).
 *   6. block-connect reconciliation (Core removeForBlock): confirmed txs
 *      leave pool+graph, txs CONFLICTING with a block's spends leave with
 *      their descendants, and the rolling floor is allowed to decay again.
 *   7. expiry with descendants (the daemon's timer calls
 *      mpool_policy_remove_expired).
 *   8. fee-rate estimator (EMA of accepted feerates, sat/kvB).
 *
 * KNOWN DELTAS, stated (LOG.md): this list is older than the file. TRUC/v3
 * topology, package relay, ephemeral anchors and (2026-09-03) TRUC sibling
 * eviction ARE implemented now; what remains is that Core v31's
 * cluster-mempool TrimToSize evicts linearization chunks and its chain
 * limits are cluster limits -- this file implements the classic
 * ancestor/descendant model the node's config knobs expose. BIP125
 * inherited signaling (an unsignaled tx with a signaling unconfirmed
 * ancestor) is simplified to direct signaling -- moot under fullrbf=1,
 * the modern default.
 *
 * The policy owns a mutable workspace (state): a flat zero-initialized
 * buffer of mpool_policy_state_size(n) bytes, mpool_policy_state_init'd.
 * `pol` is a small config struct. Accept is atomic: on any policy failure
 * both the structural mempool and this state are untouched.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include "daemon/seqlocks.h"          /* MEM-2: realloc for the evictor working arrays */
#include <time.h>

/* ---------------- asm glue (declared; resolved at link) ------------------- */
/* Resolves a confirmed prevout's value/script. NOT literally bitcoin_utxo.
 * asm's own `utxo_get` -- see daemon/tx_accept.c for the live definition and
 * the naming rationale. */
extern long mempool_resolve_confirmed_utxo(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, const unsigned char** script,
                     unsigned long* slen);
/* bitcoin_mempool.asm */
extern long mpool_put(void* mp, const unsigned char txid[32],
                      const unsigned char* tx, unsigned long txlen);
extern long mpool_del(void* mp, const unsigned char txid[32]);
extern void mpool_compact(void* mp);   /* daemon/mempool_compact.c */
extern const unsigned char* mpool_get(void* mp, const unsigned char txid[32],
                                      unsigned long* out_len);

/* ---------------- limits --------------------------------------------------- */
#define MPOL_MAX_IN     2048      /* inputs walked per tx (matches MV_MAX_IN) */
/* ---- MEM-3 (audit 2026-09-03): parents are stored OUT OF LINE ------------
 *
 * The cap used to be 24, inline, and mpol_collect_parents silently dropped
 * everything past it. parent[] is the ONLY record of the graph -- descendants
 * are discovered by walking it (collect_descendant_txids, the cluster walk,
 * remove_node) -- so a dropped parent did not exist as far as every later
 * operation was concerned, and anc_cnt, computed from the truncated list,
 * under-reported so the ancestor and cluster limits both passed. Broadcast 30
 * low-feerate parents and a child spending all 30, RBF-replace the 30th, and
 * the child stayed in the pool spending an output the replacement had
 * conflicted -- with getblocktemplate happily including it, because every
 * REGISTERED ancestor was present.
 *
 * The comment justifying 24 was itself the error: it cites Core's pre-v31
 * 25-ancestor CHAIN limit, but this node implements v31 CLUSTER limits (64
 * transactions), under which a child of 63 parents forming a 64-cluster is
 * legal and Core accepts it. So the cap has to be 63, not 24.
 *
 * Storing 63 inline was measured, not estimated: mpol_node grows 184 -> 336
 * bytes, i.e. +152 MB at the default 1,048,576-node sizing, in a MAP_SHARED
 * region several processes map. So the list is SPLIT: the first
 * MPOL_INLINE_PARENTS live in the node, and the rare node that needs more
 * borrows a fixed-size block from a shared overflow pool. Real transactions
 * have one to three in-pool parents, so the pool is almost never touched.
 *
 * The node gets SMALLER as a result -- parent[24] (96 bytes) becomes
 * parent[8] plus a 4-byte block index, 60 bytes less per node, about -60 MB
 * at the default sizing -- and the pool costs a few MB. Net: less memory than
 * before AND the cap Core actually permits.
 *
 * When the pool is exhausted the transaction is REJECTED
 * ("too-long-mempool-chain"), never truncated. That is the invariant the
 * whole finding is about: either every parent link is recorded, or the
 * transaction does not enter the pool. */
#define MPOL_INLINE_PARENTS 8
#define MPOL_MAX_PARENTS   63     /* v31 cluster limit: a 64-node cluster has
                                   * at most 63 distinct direct parents */
#define MPOL_OVF_SLOTS     (MPOL_MAX_PARENTS - MPOL_INLINE_PARENTS)
#define MPOL_OVF_NONE      0xFFFFFFFFu
#define MPOL_MAX_REPLACEMENTS 100 /* Core MAX_REPLACEMENT_CANDIDATES */

/* ---- BIP431 TRUC (topologically restricted until confirmation) ------------
 * A version=3 transaction buys predictable RBF by accepting a much tighter
 * shape: at most one unconfirmed ancestor and one unconfirmed descendant, a
 * small size cap, and no mixing with non-TRUC unconfirmed relatives. The
 * point is that a TRUC parent's fee can always be raised by its single
 * child, and neither can be pinned by a stranger attaching megabytes of
 * low-feerate descendants. Core's numbers, not ours. */
#define TRUC_VERSION           3
#define TRUC_MAX_VSIZE         10000
#define TRUC_CHILD_MAX_VSIZE   1000
#define TRUC_ANCESTOR_LIMIT    2
#define TRUC_DESCENDANT_LIMIT  2
#define MPOL_PKG_MAX     128      /* descendant-set walk bound: desc_cnt is
                                   * capped at max_desc (64 by default) by admission,
                                   * so 128 is comfortable headroom */

/* ---- package effective-feerate context ----------------------------------
 * Set for the duration of ONE package submission, by the worker, which is
 * single-threaded for this. While set, the two fee floors in mpol_accept are
 * evaluated against the package aggregate instead of the individual
 * transaction -- Core's effective feerate, the mechanism by which a child
 * pays for its parent.
 *
 * ALWAYS cleared by the caller when the package finishes, success or not. A
 * value left set here would silently relax the fee floor for ordinary
 * single-transaction traffic, so mpol_package_fee_context(0,0) is the reset
 * and the package path calls it on every exit. */
static uint64_t g_pkg_fee = 0, g_pkg_vsize = 0;

/* ---- package MEMBERSHIP context -----------------------------------------
 * The fee context above says what the package pays; this says who is in it.
 * TRUC needs the second, because in a package a member's parent is not in
 * the mempool yet -- it is another member. Without this the topology rules
 * simply do not fire during package validation: find_node() misses, the
 * transaction looks parentless, and a v2 child of a v3 parent sails through
 * the very check meant to stop it (caught by the regtest differential
 * against Core, not by any test of ours). Set and cleared by the caller
 * around both validation passes, exactly like the fee context. */
#define MPOL_PKG_CTX_MAX 25
static const unsigned char* g_pkg_tx[MPOL_PKG_CTX_MAX];
static unsigned long        g_pkg_len[MPOL_PKG_CTX_MAX];
static unsigned char        g_pkg_txid[MPOL_PKG_CTX_MAX][32];
static int                  g_pkg_n = 0;

void mpol_package_context(const unsigned char* const* txs, const unsigned long* lens,
                          const unsigned char* txids, int n){
    if (!txs || n <= 0){ g_pkg_n = 0; return; }
    if (n > MPOL_PKG_CTX_MAX) n = MPOL_PKG_CTX_MAX;
    for (int i = 0; i < n; i++){
        g_pkg_tx[i] = txs[i]; g_pkg_len[i] = lens[i];
        memcpy(g_pkg_txid[i], txids + i*32, 32);
    }
    g_pkg_n = n;
}

/* index of the package member with this txid, or -1 */
static int mpol_pkg_find(const unsigned char txid[32]){
    for (int i = 0; i < g_pkg_n; i++)
        if (!memcmp(g_pkg_txid[i], txid, 32)) return i;
    return -1;
}

void mpol_package_fee_context(unsigned long long fee, unsigned long long vsize){
    g_pkg_fee = (uint64_t)fee; g_pkg_vsize = (uint64_t)vsize;
}

static const char* _mpol_last_reason = "accepted";

/* ---------------- config (pol): caller fills via mpool_policy_init --------- */
typedef struct {
    uint64_t relay_fee_rate;   /* min relay feerate, sat per kvB (Core v30 default 100 = 0.1 sat/vB) */
    uint32_t max_anc, max_anc_bytes;    /* counts; vsize budgets */
    uint32_t max_desc, max_desc_bytes;
    uint32_t rbf_enabled;      /* == Core mempoolfullrbf: replacement allowed
                                  without the replaced tx signaling BIP125.
                                  0 => replaced tx must signal (classic). */
    uint32_t accept_nonstd;    /* Core -acceptnonstdtxn: skip standardness */
    uint64_t incremental_fee;  /* incrementalrelayfee, sat/kvB */
    uint64_t dust_relay_kvb;   /* -dustrelayfee, sat/kvB (Core default 3000) */
    uint64_t datacarrier_bytes;/* -datacarriersize budget (Core v31: 100000) */
    unsigned permit_bare_multisig;/* -permitbaremultisig (Core default: 1).
                                  * getmempoolinfo REPORTED this as always-1
                                  * while nothing could set it -- advertising
                                  * a policy the operator cannot change. */
} mpol_cfg;

/* ---------------- policy state layout (flat buffer, zero-init) ------------ */
/* header (MPOL_HDR bytes):
 *   +0  magic  +4 cap  +8 n_out  +12 n_claims  +16 n_tx  +20 stamp
 *   +24 fee-EMA (sat/kvB)   +32 samples   +40 accepted-bytes (raw)
 *   +48 rolling minfee floor, sat/kvB     +56 floor last-update (unix s)
 *   +64 pool raw bytes currently stored   +72 pool blob capacity
 *   +80 flags: bit0 = a block has connected since the floor last rose
 *              (Core blockSinceLastRollingFeeBump; decay gate)
 *   +88 MEM-3 overflow free-list head (block index, MPOL_OVF_NONE = empty)
 *   +92 MEM-3 overflow block count                                      */
typedef struct { unsigned char txid[32]; uint32_t index; uint32_t _p; uint64_t value; } mpol_out;
typedef struct { unsigned char prev[32]; uint32_t index; uint32_t claimer; } mpol_claim;
typedef struct {
    unsigned char txid[32];
    uint64_t size, fee;        /* size = VSIZE (BIP141), fee in sat */
    uint64_t raw_len;          /* serialized length (blob accounting) */
    uint64_t desc_fee;         /* fee of self + all in-pool descendants */
    uint32_t anc_cnt, anc_bytes;
    uint32_t desc_cnt, desc_bytes;   /* include self (Core convention) */
    uint32_t sigop_cost;       /* BIP141 sigop cost (x4 units), set post-add
                                  by mpool_policy_set_sigops -- accept-time
                                  data the RPC template reads back exactly
                                  (mining-polish graft at the 2026-08-27
                                  policy-parity merge)                       */
    uint32_t n_parents;
    /* MEM-3: the first MPOL_INLINE_PARENTS entries live here; entry k >=
     * MPOL_INLINE_PARENTS lives at slot (k - MPOL_INLINE_PARENTS) of the
     * overflow block `povf`. Read them through mpol_par_at / mpol_par_set --
     * never touch parent[] directly, or the k >= 8 entries become invisible
     * exactly the way the old truncation made them invisible. */
    uint32_t parent[MPOL_INLINE_PARENTS];
    uint32_t povf;             /* overflow block index, or MPOL_OVF_NONE */
    uint32_t version;          /* nVersion. BIP431 TRUC rules turn on a
                                  PARENT's version, so it must outlive the
                                  parent's own acceptance -- there is nowhere
                                  else to read it from at child time without
                                  re-parsing the parent out of the pool. */
} mpol_node;

#define MPOL_MAGIC 0x504F4C59u
#define MPOL_HDR   96u
#define MPOL_F_BLOCK_SINCE_BUMP 1ull

static mpol_out*   mpol_outreg_base(void* st){ size_t cap = *(uint32_t*)((char*)st+4);
    return (mpol_out*)((char*)st + MPOL_HDR + 4*cap); }
static mpol_claim* mpol_claims_base(void* st){ size_t cap = *(uint32_t*)((char*)st+4);
    return (mpol_claim*)((char*)st + MPOL_HDR + 4*cap + cap*sizeof(mpol_out)); }
static mpol_node*  mpol_nodes_base(void* st){ size_t cap = *(uint32_t*)((char*)st+4);
    return (mpol_node*)((char*)st + MPOL_HDR + 4*cap + cap*sizeof(mpol_out)
                        + cap*sizeof(mpol_claim)); }

/* ---- MEM-3 overflow pool ------------------------------------------------
 *
 * Appended AFTER the node array, so every existing base pointer keeps its
 * arithmetic. How many blocks: one per 64 nodes plus a floor of 64, because
 * a node needs one only when it has more than MPOL_INLINE_PARENTS in-pool
 * parents.
 *
 * One block per EIGHT nodes, plus a floor of 64. That is already a wildly
 * pessimistic ratio -- it says one transaction in eight has more than eight
 * unconfirmed parents, where real pools are dominated by one- and two-parent
 * spends -- and it is chosen that way because exhaustion, while handled
 * safely (a clean reject, never a truncated list), is the one outcome that
 * costs a legitimate transaction its place in the pool. The cluster limit
 * does NOT bound this on its own: many-parent transactions can sit in many
 * different clusters, so the count is bounded by n, not by 64.
 *
 * At the default 1,048,576-node sizing that is 131,136 blocks = 27.5 MB,
 * against the 64 MB the shrunken node gives back: still a net saving on the
 * layout it replaces, and 156 MB less than storing 63 parents inline. */
static uint32_t mpol_ovf_nblocks_for(unsigned n){ return n/8u + 64u; }
static uint32_t mpol_ovf_nblocks(void* st){ return *(uint32_t*)((char*)st+92); }
static uint32_t* mpol_ovf_base(void* st){ size_t cap = *(uint32_t*)((char*)st+4);
    return (uint32_t*)((char*)st + MPOL_HDR + 4*cap + cap*sizeof(mpol_out)
                       + cap*sizeof(mpol_claim) + cap*sizeof(mpol_node)); }
static uint32_t* mpol_ovf_block(void* st, uint32_t blk){
    /* Bounds-checked because this index comes out of a MAP_SHARED region that
     * several processes write: a corrupted or stale povf must not become an
     * out-of-region pointer. NULL makes every caller fail closed. */
    if (blk >= mpol_ovf_nblocks(st)) return 0;
    return mpol_ovf_base(st) + (size_t)blk * MPOL_OVF_SLOTS; }

/* Entry k of a node's parent list, wherever it lives. */
static uint32_t mpol_par_at(void* st, const mpol_node* nd, uint32_t k){
    if (k < MPOL_INLINE_PARENTS) return nd->parent[k];
    if (nd->povf == MPOL_OVF_NONE) return MPOL_OVF_NONE;   /* cannot happen; fail closed */
    { const uint32_t* b = mpol_ovf_block(st, nd->povf);
      if (!b || k - MPOL_INLINE_PARENTS >= MPOL_OVF_SLOTS) return MPOL_OVF_NONE;
      return b[k - MPOL_INLINE_PARENTS]; }
}
static void mpol_par_set(void* st, mpol_node* nd, uint32_t k, uint32_t v){
    if (k < MPOL_INLINE_PARENTS){ nd->parent[k] = v; return; }
    if (nd->povf == MPOL_OVF_NONE) return;
    { uint32_t* b = mpol_ovf_block(st, nd->povf);
      if (!b || k - MPOL_INLINE_PARENTS >= MPOL_OVF_SLOTS) return;
      b[k - MPOL_INLINE_PARENTS] = v; }
}
/* Claim a block for a node that needs more than the inline slots. 1 on
 * success, 0 when the pool is exhausted -- the caller then REFUSES the
 * transaction rather than recording a short list. The free list threads
 * through slot 0 of each free block. */
/* ========================================================================== */
/* MEM-12 (audit 2026-09-03): hash indices over the three linear tables       */
/*                                                                            */
/* find_node, find_outreg and find_claim were linear over up to a million     */
/* entries and are called PER INPUT PER ACCEPT. The audit's verdict was       */
/* "CONFIRMED for complexity; timings PLAUSIBLE (not measured)", so they were */
/* measured first (tests/bench_mempool_scale.c), and the cost is exactly      */
/* linear in pool size:                                                       */
/*                                                                            */
/*     entries   us/accept   block-connect (200 tx)                           */
/*      10,000       12.6        4.0 ms                                       */
/*      20,000       39.5        7.9 ms                                       */
/*      40,000       74.6       15.8 ms                                       */
/*      80,000      151.6       33.4 ms                                       */
/*                                                                            */
/* At the default 1,048,576-entry sizing that extrapolates to ~2.0 ms PER     */
/* ACCEPT and ~6.6 s for a 3,000-transaction block connect -- all under       */
/* mp_lock, in the download worker, blocking every accept in every process.   */
/* The attacker's cost is the relay floor.                                    */
/*                                                                            */
/* Chained hashing, the same shape as the MEM-9 fix in daemon/tx_relay.c:     */
/* head[] per bucket, next[] per entry, both living in the shared state so    */
/* every process that maps it sees one index. Chaining rather than open       */
/* addressing because all three tables remove by SWAP-WITH-LAST, which        */
/* relocates a surviving entry -- tombstones would accumulate on exactly the  */
/* churn a mempool is made of.                                                */
/*                                                                            */
/* A bucket hit always re-verifies the full key, so a hash collision costs an */
/* extra compare and never a wrong answer. Every walk is bounded by the entry */
/* count: a corrupted chain must degrade to the scan it replaced, not hang    */
/* the worker -- the lesson MEM-9's negative control taught, where a missing  */
/* unlink produced an infinite loop rather than a wrong answer.               */
/* ========================================================================== */
#define MPOL_IDX_NONE 0xFFFFFFFFu
static uint32_t mpol_nbuckets_for(unsigned n){
    uint32_t b = 64; while (b < n) b <<= 1; return b;
}
static uint32_t mpol_nbuckets(void* st){ return mpol_nbuckets_for(*(uint32_t*)((char*)st+4)); }
/* The six arrays sit after the overflow pool: three head[] of nbuckets and
 * three next[] of cap, in the order node, outreg, claim. */
static uint32_t* mpol_idx_base(void* st){
    size_t cap = *(uint32_t*)((char*)st+4);
    return (uint32_t*)((char*)mpol_ovf_base(st)
                       + (size_t)mpol_ovf_nblocks(st) * MPOL_OVF_SLOTS * sizeof(uint32_t));
    (void)cap;
}
static uint32_t* mpol_node_head(void* st){ return mpol_idx_base(st); }
static uint32_t* mpol_node_next(void* st){ return mpol_node_head(st) + mpol_nbuckets(st); }
static uint32_t* mpol_out_head(void* st){ return mpol_node_next(st) + *(uint32_t*)((char*)st+4); }
static uint32_t* mpol_out_next(void* st){ return mpol_out_head(st) + mpol_nbuckets(st); }
static uint32_t* mpol_clm_head(void* st){ return mpol_out_next(st) + *(uint32_t*)((char*)st+4); }
static uint32_t* mpol_clm_next(void* st){ return mpol_clm_head(st) + mpol_nbuckets(st); }

static uint32_t mpol_fnv(const unsigned char* p, size_t n, uint32_t extra){
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++){ h ^= p[i]; h *= 16777619u; }
    for (int i = 0; i < 4; i++){ h ^= (unsigned char)(extra >> (8*i)); h *= 16777619u; }
    return h;
}
static uint32_t mpol_h_node(void* st, const unsigned char txid[32]){
    return mpol_fnv(txid, 32, 0) & (mpol_nbuckets(st) - 1u); }
static uint32_t mpol_h_out(void* st, const unsigned char txid[32], uint32_t idx){
    return mpol_fnv(txid, 32, idx) & (mpol_nbuckets(st) - 1u); }
static uint32_t mpol_h_clm(void* st, const unsigned char prev[32], uint32_t idx){
    return mpol_fnv(prev, 32, idx) & (mpol_nbuckets(st) - 1u); }

/* Generic chain ops. `head`/`next` name the table; `slot` is its array index. */
static void mpol_chain_link(uint32_t* head, uint32_t* next, uint32_t bucket, uint32_t slot){
    next[slot] = head[bucket];
    head[bucket] = slot;
}
static void mpol_chain_unlink(uint32_t* head, uint32_t* next, uint32_t bucket,
                              uint32_t slot, uint32_t bound){
    uint32_t* pp = &head[bucket];
    uint32_t guard = 0;
    while (*pp != MPOL_IDX_NONE && guard++ <= bound){
        if (*pp == slot){ *pp = next[slot]; next[slot] = MPOL_IDX_NONE; return; }
        pp = &next[*pp];
    }
}

/* Node index: key is the 32-byte txid, slot is the node array index. */
static void mpol_node_idx_link(void* st, uint32_t slot){
    mpol_node* t = mpol_nodes_base(st);
    mpol_chain_link(mpol_node_head(st), mpol_node_next(st),
                    mpol_h_node(st, t[slot].txid), slot);
}
static void mpol_node_idx_unlink(void* st, uint32_t slot){
    mpol_node* t = mpol_nodes_base(st);
    mpol_chain_unlink(mpol_node_head(st), mpol_node_next(st),
                      mpol_h_node(st, t[slot].txid), slot,
                      *(uint32_t*)((char*)st+4));
}
/* Outreg index: key is (txid, index). */
static void mpol_out_idx_link(void* st, uint32_t slot){
    mpol_out* o = mpol_outreg_base(st);
    mpol_chain_link(mpol_out_head(st), mpol_out_next(st),
                    mpol_h_out(st, o[slot].txid, o[slot].index), slot);
}
static void mpol_out_idx_unlink(void* st, uint32_t slot){
    mpol_out* o = mpol_outreg_base(st);
    mpol_chain_unlink(mpol_out_head(st), mpol_out_next(st),
                      mpol_h_out(st, o[slot].txid, o[slot].index), slot,
                      *(uint32_t*)((char*)st+4));
}
/* Claim index: key is (prev, index). `claimer` is payload, not key, so the
 * renumbering pass in remove_node does not touch the index. */
static void mpol_clm_idx_link(void* st, uint32_t slot){
    mpol_claim* c = mpol_claims_base(st);
    mpol_chain_link(mpol_clm_head(st), mpol_clm_next(st),
                    mpol_h_clm(st, c[slot].prev, c[slot].index), slot);
}
static void mpol_clm_idx_unlink(void* st, uint32_t slot){
    mpol_claim* c = mpol_claims_base(st);
    mpol_chain_unlink(mpol_clm_head(st), mpol_clm_next(st),
                      mpol_h_clm(st, c[slot].prev, c[slot].index), slot,
                      *(uint32_t*)((char*)st+4));
}

static int mpol_par_reserve(void* st, mpol_node* nd, uint32_t n_par){
    if (n_par <= MPOL_INLINE_PARENTS) return 1;
    if (nd->povf != MPOL_OVF_NONE) return 1;
    uint32_t* head = (uint32_t*)((char*)st+88);
    if (*head == MPOL_OVF_NONE) return 0;
    uint32_t blk = *head;
    uint32_t* b = mpol_ovf_block(st, blk);
    if (!b){ *head = MPOL_OVF_NONE; return 0; }   /* corrupt head: stop, do not truncate */
    *head = b[0];
    nd->povf = blk;
    for (uint32_t i = 0; i < MPOL_OVF_SLOTS; i++) b[i] = MPOL_OVF_NONE;
    return 1;
}
static void mpol_par_release(void* st, mpol_node* nd){
    if (nd->povf == MPOL_OVF_NONE) return;
    uint32_t* head = (uint32_t*)((char*)st+88);
    uint32_t* b = mpol_ovf_block(st, nd->povf);
    if (b){ b[0] = *head; *head = nd->povf; }
    nd->povf = MPOL_OVF_NONE;
}

/* an optional "forget this txid" callback (daemon/mempool_cfg.c clears its
 * arrival-time table with it); NULL in the standalone tests */
/* bytespersigop (Core DEFAULT_BYTES_PER_SIGOP 20). The accept caller computes
 * the sigop cost BEFORE admission -- it needs the UTXO view for the P2SH and
 * witness counts, which mpol_accept does not have -- and parks it here.
 * mpol_accept reads AND clears it as its first act, so a rejection cannot
 * leave it parked for the next transaction. See the note at the top of
 * mpol_accept for what it then feeds. */
static uint64_t mpol_pending_sigops;
static uint64_t mpol_bytes_per_sigop = 20;          /* Core DEFAULT_BYTES_PER_SIGOP */
void mpool_policy_set_pending_sigops(unsigned long long cost_x4){ mpol_pending_sigops = cost_x4; }
void mpool_policy_set_bytespersigop(unsigned long long n){ mpol_bytes_per_sigop = n ? n : 20; }
static void (*g_forget_cb)(const unsigned char txid[32]) = 0;
void mpool_policy_set_forget_cb(void (*fn)(const unsigned char*)){ g_forget_cb = fn; }

/* ========================================================================== */
/* public API                                                                 */
/* ========================================================================== */

size_t mpool_policy_state_size(unsigned n){
    return MPOL_HDR + (size_t)4*n + (size_t)n*sizeof(mpol_out)
           + (size_t)n*sizeof(mpol_claim) + (size_t)n*sizeof(mpol_node)
           + (size_t)mpol_ovf_nblocks_for(n) * MPOL_OVF_SLOTS * sizeof(uint32_t)
           /* MEM-12: three chained indices -- head[nbuckets] + next[n] each */
           + 3u * ((size_t)mpol_nbuckets_for(n) + (size_t)n) * sizeof(uint32_t);
}

void mpool_policy_state_init(void* st, unsigned n){
    memset(st, 0, mpool_policy_state_size(n));
    *(uint32_t*)st = MPOL_MAGIC;
    *(uint32_t*)((char*)st+4) = n;
    /* MEM-3: thread the overflow free list. cap must be set FIRST -- every
     * base pointer is computed from it. A zeroed header would otherwise mean
     * "block 0 is free and its next is block 0", an instant cycle. */
    { uint32_t nb = mpol_ovf_nblocks_for(n);
      *(uint32_t*)((char*)st+92) = nb;
      *(uint32_t*)((char*)st+88) = nb ? 0u : MPOL_OVF_NONE;
      for (uint32_t i = 0; i < nb; i++)
          mpol_ovf_block(st, i)[0] = (i + 1 < nb) ? (i + 1) : MPOL_OVF_NONE; }
    /* MEM-12: an empty chain is MPOL_IDX_NONE, not 0 -- slot 0 is a real
     * entry, so a zeroed head array would claim every bucket holds it. */
    { uint32_t nb = mpol_nbuckets_for(n);
      memset(mpol_node_head(st), 0xFF, (size_t)(nb + n) * sizeof(uint32_t));
      memset(mpol_out_head(st),  0xFF, (size_t)(nb + n) * sizeof(uint32_t));
      memset(mpol_clm_head(st),  0xFF, (size_t)(nb + n) * sizeof(uint32_t)); }
}

void mpool_policy_init(mpol_cfg* pol, uint64_t relay_fee_rate,
                       unsigned max_anc, unsigned max_anc_bytes,
                       unsigned max_desc, unsigned max_desc_bytes,
                       unsigned rbf_enabled){
    pol->relay_fee_rate  = relay_fee_rate;
    pol->max_anc         = max_anc;
    pol->max_anc_bytes   = max_anc_bytes;
    pol->max_desc        = max_desc;
    pol->max_desc_bytes  = max_desc_bytes;
    pol->rbf_enabled     = rbf_enabled;
    pol->accept_nonstd   = 0;
    pol->incremental_fee = relay_fee_rate;          /* sat/kvB, same unit */
    pol->dust_relay_kvb  = 3000;                    /* Core DUST_RELAY_TX_FEE */
    pol->datacarrier_bytes = 100000;                /* Core v31 default */
    pol->permit_bare_multisig = 1;                  /* Core DEFAULT_PERMIT_BAREMULTISIG */
}

void mpool_policy_set_incremental(void* polv, unsigned long long satkvb){
    mpol_cfg* pol = (mpol_cfg*)polv;
    if (satkvb > 0) pol->incremental_fee = satkvb;
}
void mpool_policy_set_dust(void* polv, unsigned long long satkvb){
    ((mpol_cfg*)polv)->dust_relay_kvb = satkvb;
}
void mpool_policy_set_datacarrier(void* polv, unsigned long long bytes){
    ((mpol_cfg*)polv)->datacarrier_bytes = bytes;
}
void mpool_policy_set_baremultisig(void* polv, unsigned v){
    ((mpol_cfg*)polv)->permit_bare_multisig = v ? 1u : 0u;
}
unsigned mpool_policy_get_baremultisig(const void* polv){
    return ((const mpol_cfg*)polv)->permit_bare_multisig;
}
void mpool_policy_set_acceptnonstd(void* polv, unsigned v){
    ((mpol_cfg*)polv)->accept_nonstd = v ? 1u : 0u;
}
/* the structural pool's blob capacity, for the decay speed-up thresholds */
void mpool_policy_set_poolcap(void* st, unsigned long long cap){
    *(uint64_t*)((char*)st+72) = cap;
}

uint64_t mpool_policy_estimate_feerate(void* st){
    return *(uint64_t*)((char*)st + 24);
}
long mpool_policy_estimate(void* st, unsigned long long* satperkb,
                           unsigned long long* samples){
    if (!st || *(uint32_t*)st != MPOL_MAGIC) return 0;
    if (satperkb) *satperkb = *(uint64_t*)((char*)st + 24);
    if (samples)  *samples  = *(uint64_t*)((char*)st + 32);
    return 1;
}

const char* mpool_policy_reason(void* pol){ (void)pol; return _mpol_last_reason; }

/* ========================================================================== */
/* wire walks                                                                 */
/* ========================================================================== */

/* SER-3 / VAL-10 (audit 2026-09-03): CANONICAL CompactSize on the ADMISSION
 * path too.
 *
 * Core's ReadCompactSize throws "non-canonical ReadCompactSize()" for a value
 * encoded in a wider form than it needs, and "size too large" above MAX_SIZE
 * (0x02000000). The block-connect and witness readers were fixed earlier
 * (daemon/tx_verify.c, daemon/block_witness.c, daemon/utxo_walk.h,
 * bitcoin_txv_parse.asm), which closed the CONSENSUS hole. This reader is the
 * one the MEMPOOL uses -- parse_tx for every admission, and the transaction
 * count in block_connect -- so leaving it lax meant a transaction Core cannot
 * deserialize could still enter this node's pool and be RELAYED from it. A
 * relay divergence rather than a chain split, but the same defect.
 *
 * The minimum each width may encode: 0xfd for the 3-byte form, 0x10000 for
 * the 5-byte, 0x100000000 for the 9-byte. Nothing valid is lost, because a
 * canonical encoder never emits the wider form. */
#define MPOL_CS_MAX_SIZE 0x02000000ULL
static uint64_t rd_varint(const unsigned char** p, const unsigned char* end, int* ok){
    const unsigned char* b = *p; *ok = 0;
    if (b >= end) return 0;
    unsigned char f = *b++;
    uint64_t v, minimum;
    if (f < 0xfd){ *ok = 1; *p = b; return f; }
    else if (f == 0xfd){ if (end-b < 2) return 0; v = (uint64_t)b[0]|((uint64_t)b[1]<<8); b += 2; minimum = 0xfdULL; }
    else if (f == 0xfe){ if (end-b < 4) return 0; v=0; for(int i=0;i<4;i++) v|=(uint64_t)b[i]<<(8*i); b += 4; minimum = 0x10000ULL; }
    else { if (end-b < 8) return 0; v=0; for(int i=0;i<8;i++) v|=(uint64_t)b[i]<<(8*i); b += 8; minimum = 0x100000000ULL; }
    if (v < minimum || v > MPOL_CS_MAX_SIZE) return 0;   /* non-canonical, or over MAX_SIZE */
    *ok = 1; *p = b;
    return v;
}

/* One full parse: prevouts, sequences, output sum, VSIZE (BIP141), the
 * non-witness serialized size, version, and per-input scriptsig spans (for
 * standardness). Returns n_in > 0, or <= 0 on malformed. */
typedef struct {
    int      n_in;
    uint32_t version;
    int      is_segwit;
    uint64_t nonwit_len;       /* serialized size without witness */
    uint64_t weight, vsize;
    unsigned long long sum_out;
    unsigned long n_out;
    const unsigned char* out_start;   /* first output record */
    const unsigned char* in_start;    /* first input record  */
    uint32_t locktime;   /* MEM-1: the trailing 4 bytes. parse_tx read every
                            other field of the transaction and skipped this
                            one, because nothing consumed it -- the audit's
                            note that "the 4-byte nLockTime is never decoded
                            on the admission path at all". */
} mpol_txmeta;

static int parse_tx(const unsigned char* tx, unsigned long txlen,
                    unsigned char prev[][32], uint32_t* idx, uint32_t* seq,
                    mpol_txmeta* m){
    const unsigned char* p = tx; const unsigned char* end = tx + txlen;
    int ok;
    if (txlen < 10) return -1;
    m->version = (uint32_t)(p[0]|(p[1]<<8)|(p[2]<<16)|((uint32_t)p[3]<<24));
    p += 4;
    m->is_segwit = 0;
    if (p + 2 <= end && p[0]==0x00 && p[1]==0x01){ m->is_segwit = 1; p += 2; }
    uint64_t n_in = rd_varint(&p, end, &ok); if (!ok || !n_in) return -1;
    if (n_in > MPOL_MAX_IN) return -1;
    m->in_start = p;
    for (uint64_t i = 0; i < n_in; i++){
        if (p+36 > end) return -1;
        memcpy(prev[i], p, 32);
        idx[i] = (uint32_t)(p[32]|(p[33]<<8)|(p[34]<<16)|((uint32_t)p[35]<<24));
        p += 36;
        uint64_t sl = rd_varint(&p, end, &ok); if (!ok) return -1;
        if (sl + 4 > (uint64_t)(end - p)) return -1;
        p += sl;
        seq[i] = (uint32_t)(p[0]|(p[1]<<8)|(p[2]<<16)|((uint32_t)p[3]<<24));
        p += 4;
    }
    uint64_t n_out = rd_varint(&p, end, &ok); if (!ok || !n_out) return -1;
    m->n_out = (unsigned long)n_out;
    m->out_start = p;
    m->sum_out = 0;
    for (uint64_t i = 0; i < n_out; i++){
        if (p+8 > end) return -1;
        uint64_t v = 0; for (int k=0;k<8;k++) v |= ((uint64_t)p[k])<<(8*k);
        m->sum_out += v;
        p += 8;
        uint64_t sl = rd_varint(&p, end, &ok); if (!ok) return -1;
        if (sl > (uint64_t)(end - p)) return -1;
        p += sl;
    }
    /* witness section (if segwit): everything from here to locktime */
    uint64_t wit_len = 0;
    if (m->is_segwit){
        if (end - p < 4) return -1;
        wit_len = (uint64_t)(end - p) - 4;
    }
    m->locktime = (uint32_t)(end[-4] | (end[-3]<<8) | (end[-2]<<16) | ((uint32_t)end[-1]<<24));
    m->nonwit_len = m->is_segwit ? (txlen - 2 - wit_len) : txlen;
    m->weight = m->nonwit_len * 3 + txlen;
    m->vsize  = (m->weight + 3) / 4;
    m->n_in = (int)n_in;
    return (int)n_in;
}

/* ---------------------------------------------------------------- MEM-1
 * Chain context for the finality rules (audit 2026-09-03).
 *
 * Core's MemPoolAccept::PreChecks rejects !CheckFinalTxAtTip ("non-final")
 * and !CheckSequenceLocks ("non-BIP68-final") using STANDARD_LOCKTIME_VERIFY_
 * FLAGS, i.e. against the NEXT block's height and the tip's median time past.
 * This layer had neither: parse_tx read the sequences only for BIP125
 * signalling and never decoded nLockTime at all.
 *
 * What that let through: a transaction with nLockTime = tip+500, or a v2 with
 * a relative lock against a freshly confirmed input, passed every check,
 * entered the shared pool, was announced to every peer (Core peers reject it
 * as non-final and keep it in recent-rejects), and was selected by
 * getblocktemplate -- so a miner on this template produces a block Core
 * rejects.
 *
 * The arithmetic is daemon/seqlocks.h, shared with the block-connect path so
 * the two points cannot drift.
 *
 * NOT CONFIGURED => NOT ENFORCED, deliberately. next_height < 0 means the
 * embedder has not supplied chain context, which is the case for every unit
 * test that drives this layer with synthetic transactions and no chain. The
 * daemon wires it at every tip change. Enforcing with a zero height would
 * reject everything. */
static long           g_seq_next_height = -1;
static unsigned long  g_seq_tip_mtp     = 0;
static int            g_seq_csv_active  = 0;
static long (*g_seq_height_fn)(const unsigned char txid[32], unsigned long index,
                               unsigned long long* out_height) = 0;

void mpool_policy_set_seqlocks(long next_height, unsigned long tip_mtp, int csv_active,
                               long (*height_fn)(const unsigned char*, unsigned long,
                                                 unsigned long long*)){
    g_seq_next_height = next_height;
    g_seq_tip_mtp     = tip_mtp;
    g_seq_csv_active  = csv_active;
    g_seq_height_fn   = height_fn;
}

/* ========================================================================== */
/* standardness (Core policy.cpp IsStandardTx, exact reason strings)          */
/* ========================================================================== */

static int script_is_pushonly(const unsigned char* s, unsigned long n){
    unsigned long i = 0;
    while (i < n){
        unsigned char op = s[i++];
        if (op > 0x60) return 0;              /* > OP_16 */
        if (op >= 0x01 && op <= 0x4b){ if (i + op > n) return 0; i += op; }
        else if (op == 0x4c){ if (i >= n) return 0; unsigned long l = s[i]; i += 1 + l; if (i > n) return 0; }
        else if (op == 0x4d){ if (i+2 > n) return 0; unsigned long l = s[i]|(s[i+1]<<8); i += 2 + l; if (i > n) return 0; }
        else if (op == 0x4e){ if (i+4 > n) return 0; unsigned long l = s[i]|(s[i+1]<<8)|((unsigned long)s[i+2]<<16)|((unsigned long)s[i+3]<<24); i += 4 + l; if (i > n) return 0; }
    }
    return 1;
}

/* Solver-lite over an output script. Core TxoutType equivalents. */
enum { SPK_NONSTD=0, SPK_P2PK, SPK_P2PKH, SPK_P2SH, SPK_MULTISIG,
       SPK_NULLDATA, SPK_WITNESS_V0_KEY, SPK_WITNESS_V0_SCRIPT,
       SPK_WITNESS_V1_TAP, SPK_WITNESS_UNKNOWN, SPK_ANCHOR };
static int classify_spk(const unsigned char* s, unsigned long n){
    if (n == 25 && s[0]==0x76 && s[1]==0xa9 && s[2]==0x14 && s[23]==0x88 && s[24]==0xac)
        return SPK_P2PKH;
    if (n == 23 && s[0]==0xa9 && s[1]==0x14 && s[22]==0x87)
        return SPK_P2SH;
    if (n == 22 && s[0]==0x00 && s[1]==0x14) return SPK_WITNESS_V0_KEY;
    if (n == 34 && s[0]==0x00 && s[1]==0x20) return SPK_WITNESS_V0_SCRIPT;
    if (n == 34 && s[0]==0x51 && s[1]==0x20) return SPK_WITNESS_V1_TAP;
    if (n == 4 && s[0]==0x51 && s[1]==0x02 && s[2]==0x4e && s[3]==0x73)
        return SPK_ANCHOR;                        /* P2A (Core v28+) */
    /* other witness programs: 1 version op + 1 push of 2..40 bytes */
    if (n >= 4 && n <= 42 && (s[0]==0x00 || (s[0]>=0x51 && s[0]<=0x60)) &&
        s[1] == n-2 && s[1] >= 2 && s[1] <= 40)
        return SPK_WITNESS_UNKNOWN;
    if (n >= 1 && s[0] == 0x6a){                  /* OP_RETURN ... */
        /* Core: NULL_DATA = OP_RETURN followed by push-only */
        if (script_is_pushonly(s+1, n-1)) return SPK_NULLDATA;
        return SPK_NONSTD;
    }
    if ((n == 35 && s[0]==0x21 && s[34]==0xac) ||
        (n == 67 && s[0]==0x41 && s[66]==0xac))
        return SPK_P2PK;
    /* bare multisig: OP_1..OP_3 <pubkeys> OP_1..OP_3 OP_CHECKMULTISIG */
    if (n >= 3 && s[n-1]==0xae && s[0]>=0x51 && s[0]<=0x53 &&
        s[n-2]>=0x51 && s[n-2]<=0x53)
        return SPK_MULTISIG;
    return SPK_NONSTD;
}

/* Core GetDustThreshold + CFeeRate::GetFee (never 0 for a nonzero rate). */
static uint64_t dust_threshold(unsigned long spk_len, int spk_type, uint64_t rate_kvb){
    /* serialized txout size: 8 (value) + compactsize(spk_len) + spk_len */
    uint64_t sz = 8 + (spk_len < 0xfd ? 1 : 3) + spk_len;
    /* MEM-11 (audit 2026-09-03): SPK_ANCHOR belongs in this set. P2A is
     * witness version 1 with a 2-byte program, so Core's IsWitnessProgram
     * returns true for it and GetDustThreshold charges the WITNESS spend size.
     * Leaving it out charged the non-witness size instead: 3000 sat/kvB x 161
     * bytes = 483 sat rather than x 80 = 240. A P2A output between 240 and
     * 482 sat is not dust to Core and was dust here -- and while one dust
     * output is tolerated at standardness, the ephemeral-dust rule then fires
     * on any transaction with a non-zero fee. LN anchor outputs sit squarely
     * in that range, so this node rejected transactions Core accepts. */
    int witness = (spk_type == SPK_WITNESS_V0_KEY || spk_type == SPK_WITNESS_V0_SCRIPT ||
                   spk_type == SPK_WITNESS_V1_TAP || spk_type == SPK_WITNESS_UNKNOWN ||
                   spk_type == SPK_ANCHOR);
    sz += witness ? (32 + 4 + 1 + (107/4) + 4) : (32 + 4 + 1 + 107 + 4);
    uint64_t fee = rate_kvb * sz / 1000;
    if (fee == 0 && rate_kvb > 0) fee = 1;
    return fee;
}

/* Returns NULL if standard, else Core's reason string. */
/* Core MAX_DUST_OUTPUTS_PER_TX. One dust output is permitted at the
 * standardness stage so that EPHEMERAL dust -- dust created and swept inside
 * the same package -- is expressible at all; the two rules that keep it safe
 * (0-fee, and the child must sweep it) live in mpol_add_core, where the fee
 * and the parent are known. */
#define MPOL_MAX_DUST_OUTPUTS 1

/* dust output indices of a transaction, Core GetDust. NULL_DATA outputs are
 * unspendable and so never dust. */
static int mpol_dust_outputs(const mpol_cfg* pol, const unsigned char* tx,
                             unsigned long txlen, const mpol_txmeta* m,
                             uint32_t* out, int cap){
    const unsigned char* p = m->out_start; const unsigned char* end = tx + txlen;
    int ok, n = 0;
    for (unsigned long i = 0; i < m->n_out; i++){
        if (p + 8 > end) break;
        uint64_t v = 0; for (int k=0;k<8;k++) v |= ((uint64_t)p[k])<<(8*k);
        p += 8;
        uint64_t sl = rd_varint(&p, end, &ok); if (!ok || p + sl > end) break;
        int t = classify_spk(p, (unsigned long)sl);
        if (t != SPK_NULLDATA &&
            v < dust_threshold((unsigned long)sl, t, pol->dust_relay_kvb)){
            if (n < cap) out[n] = (uint32_t)i;
            n++;
        }
        p += sl;
    }
    return n;
}

static const char* standard_checks(const mpol_cfg* pol, const unsigned char* tx,
                                   unsigned long txlen, const mpol_txmeta* m,
                                   const unsigned char prev0[32], uint32_t idx0,
                                   int* n_dust_out){
    /* a coinbase is never valid as a pool tx (Core: "coinbase") */
    { int nullprev = 1; for (int i=0;i<32;i++) if (prev0[i]) { nullprev = 0; break; }
      if (nullprev && idx0 == 0xffffffffu) return "coinbase"; }
    if (pol->accept_nonstd) return 0;
    if (m->version < 1 || m->version > 3) return "version";  /* TX_MAX_STANDARD_VERSION 3 */
    if (m->weight > 400000) return "tx-size";                /* MAX_STANDARD_TX_WEIGHT */
    /* inputs: scriptsig size + push-only */
    { const unsigned char* p = m->in_start; const unsigned char* end = tx + txlen;
      int ok;
      for (int i = 0; i < m->n_in; i++){
          p += 36;
          uint64_t sl = rd_varint(&p, end, &ok); if (!ok) return "malformed";
          if (sl > 1650) return "scriptsig-size";            /* MAX_STANDARD_SCRIPTSIG_SIZE */
          if (!script_is_pushonly(p, (unsigned long)sl)) return "scriptsig-not-pushonly";
          p += sl + 4;
      } }
    /* outputs: type / datacarrier budget / dust */
    { const unsigned char* p = m->out_start; const unsigned char* end = tx + txlen;
      int ok; uint64_t datacarrier_used = 0;
      for (unsigned long i = 0; i < m->n_out; i++){
          uint64_t v = 0; for (int k=0;k<8;k++) v |= ((uint64_t)p[k])<<(8*k);
          p += 8;
          uint64_t sl = rd_varint(&p, end, &ok); if (!ok) return "malformed";
          int t = classify_spk(p, (unsigned long)sl);
          if (t == SPK_NONSTD) return "scriptpubkey";
          /* -permitbaremultisig=0: Core stops relaying bare multisig outputs
           * (they are unprunable UTXO bloat). The type stays STANDARD, so the
           * rejection is its own reason rather than "scriptpubkey". */
          if (t == SPK_MULTISIG && !pol->permit_bare_multisig) return "bare-multisig";
          if (t == SPK_NULLDATA){
              datacarrier_used += sl;
              if (datacarrier_used > pol->datacarrier_bytes) return "datacarrier";
          }
          p += sl;
      } }
    /* Dust is counted, not rejected on sight, and the count is checked AFTER
     * the output loop -- both are Core's placement. Rejecting the first dust
     * output inline also reported "dust" for a transaction whose real problem
     * was a later nonstandard output. */
    { uint32_t didx[8];
      int nd = mpol_dust_outputs(pol, tx, txlen, m, didx, 8);
      if (n_dust_out) *n_dust_out = nd;
      if (nd > MPOL_MAX_DUST_OUTPUTS) return "dust"; }
    /* PreChecks' own size floor runs AFTER IsStandardTx in Core, so a tiny
     * tx with a nonstandard output still reports "scriptpubkey". */
    if (m->nonwit_len < 65) return "tx-size-small";          /* MIN_STANDARD_TX_NONWITNESS_SIZE */
    return 0;
}

/* ========================================================================== */
/* graph lookups                                                              */
/* ========================================================================== */
static int find_node(void* st, const unsigned char txid[32]){
    mpol_node* t = mpol_nodes_base(st);
    uint32_t n = *(uint32_t*)((char*)st+16);
    uint32_t guard = 0;
    for (uint32_t i = mpol_node_head(st)[mpol_h_node(st, txid)];
         i != MPOL_IDX_NONE && guard++ <= n; i = mpol_node_next(st)[i])
        if (i < n && memcmp(t[i].txid, txid, 32)==0) return (int)i;
    return -1;
}

/* Collect the DISTINCT in-pool parents of a transaction.
 *
 * MEM-3 (audit 2026-09-03) was that this list was capped at 24 and the
 * surplus dropped SILENTLY, while descendants are discovered only through
 * parent[]. A transaction with 30 in-pool parents was accepted linked to 24
 * of them; replace, evict or expire the 30th and collect_descendant_txids
 * found no child, so the child stayed in the pool spending a now-conflicted
 * output and getblocktemplate included it.
 *
 * Both halves are fixed. The cap is now MPOL_MAX_PARENTS = 63, the real v31
 * cluster limit rather than the pre-v31 chain limit the old comment cited,
 * and the storage is out of line (see MPOL_INLINE_PARENTS) so raising it
 * costs less memory than the old inline array, not more. And `*truncated`
 * is now CONSULTED: the accept path refuses a transaction whose parent list
 * would not fit, instead of storing a short one.
 *
 * `*truncated` may be NULL at the call sites that RE-collect after a
 * removal, where the count can only have shrunk. */
static int mpol_collect_parents(void* st, const unsigned char (*prev)[32],
                                int n_in, int* par_idx, int* truncated){
    int n_par = 0;
    if (truncated) *truncated = 0;
    for (int i = 0; i < n_in; i++){
        int p = find_node(st, prev[i]);
        if (p < 0) continue;
        int seen = 0;
        for (int k = 0; k < n_par; k++) if (par_idx[k] == p){ seen = 1; break; }
        if (seen) continue;
        if (n_par >= MPOL_MAX_PARENTS){ if (truncated) *truncated = 1; break; }
        par_idx[n_par++] = p;
    }
    return n_par;
}

static long find_outreg(void* st, const unsigned char txid[32], uint32_t index,
                        uint64_t* value){
    mpol_out* o = mpol_outreg_base(st);
    uint32_t n = *(uint32_t*)((char*)st+8);
    uint32_t guard = 0;
    for (uint32_t i = mpol_out_head(st)[mpol_h_out(st, txid, index)];
         i != MPOL_IDX_NONE && guard++ <= n; i = mpol_out_next(st)[i])
        if (i < n && o[i].index==index && memcmp(o[i].txid, txid, 32)==0){ *value=o[i].value; return 1; }
    return 0;
}
static int find_claim(void* st, const unsigned char prev[32], uint32_t index){
    mpol_claim* c = mpol_claims_base(st);
    uint32_t n = *(uint32_t*)((char*)st+12);
    uint32_t guard = 0;
    for (uint32_t i = mpol_clm_head(st)[mpol_h_clm(st, prev, index)];
         i != MPOL_IDX_NONE && guard++ <= n; i = mpol_clm_next(st)[i])
        if (i < n && c[i].index==index && memcmp(c[i].prev, prev, 32)==0) return (int)c[i].claimer;
    return -1;
}

/* ========================================================================== */
/* removal machinery (single node; package = node + descendants)              */
/* ========================================================================== */

/* Collect node ci's in-pool descendant TXIDS (self excluded), bounded.
 * Children found by scanning parent links; pops bounded by desc_cnt<=25. */
static int collect_descendant_txids(void* st, int ci,
                                    unsigned char out[][32], int cap){
    mpol_node* t = mpol_nodes_base(st);
    uint32_t n = *(uint32_t*)((char*)st+16);
    uint32_t stack[MPOL_PKG_MAX]; int sp = 0, cnt = 0;
    uint32_t seenidx[MPOL_PKG_MAX]; int nseen = 0;
    stack[sp++] = (uint32_t)ci;
    seenidx[nseen++] = (uint32_t)ci;
    while (sp > 0){
        uint32_t cur = stack[--sp];
        for (uint32_t i = 0; i < n; i++){
            int is_child = 0;
            for (uint32_t k = 0; k < t[i].n_parents; k++)
                if (mpol_par_at(st, &t[i], k) == cur){ is_child = 1; break; }
            if (!is_child) continue;
            int seen = 0;
            for (int k = 0; k < nseen; k++) if (seenidx[k] == i){ seen = 1; break; }
            if (seen) continue;
            if (cnt >= cap || nseen >= MPOL_PKG_MAX || sp >= MPOL_PKG_MAX) return -1;
            memcpy(out[cnt++], t[i].txid, 32);
            seenidx[nseen++] = i;
            stack[sp++] = i;
        }
    }
    return cnt;
}

/* Walk ci's ancestors decrementing their with-descendants aggregates by
 * (one tx, vsz bytes, fee sats). Mark-guarded against diamond recount. */
static void decr_ancestors(void* st, int ci, uint32_t vsz, uint64_t fee){
    mpol_node* t = mpol_nodes_base(st);
    uint32_t n = *(uint32_t*)((char*)st+16);
    static uint8_t seen[1u<<20];
    if (n > (1u<<20)) return;
    memset(seen, 0, n);
    uint32_t stack[512]; int sp = 0;
    for (uint32_t k=0;k<t[ci].n_parents && sp<512;k++){
        uint32_t p = mpol_par_at(st, &t[ci], k);
        if (p < n && !seen[p]){ seen[p]=1; stack[sp++]=p; }
    }
    while (sp){
        uint32_t a = stack[--sp];
        if (t[a].desc_cnt) t[a].desc_cnt--;
        if (t[a].desc_bytes >= vsz) t[a].desc_bytes -= vsz; else t[a].desc_bytes = 0;
        if (t[a].desc_fee >= fee) t[a].desc_fee -= fee; else t[a].desc_fee = 0;
        for (uint32_t k=0;k<t[a].n_parents && sp<512;k++){
            uint32_t p = mpol_par_at(st, &t[a], k);
            if (p < n && !seen[p]){ seen[p]=1; stack[sp++]=p; }
        }
    }
}

/* ---------------------------------------------------------------- MEM-17
 * (audit 2026-09-03) A node's WITH-ANCESTORS aggregates went stale the moment
 * an ancestor left the pool.
 *
 * remove_node cleared a child's parent[k] to 0xFFFFFFFF and decr_ancestors
 * fixed the departing node's ANCESTORS' desc_* -- but nothing touched the
 * DESCENDANTS' anc_cnt/anc_bytes. So after a v3 parent P confirmed, its v3
 * child C still carried anc_cnt == 2 (P plus itself) although it now had no
 * unconfirmed ancestor at all, and C's own v3 child G was refused
 * "TRUC-violation" where Core accepts it (C has 0 mempool ancestors). The
 * same stale count feeds the ordinary ancestor limit at admission
 * ("too-long-mempool-chain"), so a long-lived chain whose head kept
 * confirming looked longer and longer to this node. RPC readers walk the
 * links rather than the counters, which is why getmempoolentry looked right
 * and hid it. Core: UpdateForRemoveFromMempool / UpdateAncestorsOf.
 *
 * Rather than decrement transitively on the way DOWN -- there is no child
 * index, so finding descendants is a sweep -- a survivor's aggregates are
 * RECOMPUTED by walking UP its parent refs, exactly as admission first
 * computed them (anc_cnt = 1 + ancestors, anc_bytes = vsize + their vsizes).
 * Going up is cheap: parents are indexed, and Core's cluster limit bounds an
 * ancestor set at 63, so the linear seen-list below never fills. If it ever
 * did, the count saturates HIGH, which is the refusing direction -- a stale
 * count can only ever over-admit.
 *
 * Both removal paths call the pass, and both skip it when no survivor lost a
 * parent, which is the common case for an RBF eviction (descendants leave
 * with the evicted tx) and keeps the O(survivors) cost off that path. */
#define MPOL_ANC_SEEN_MAX 128
static void mpol_recompute_anc(void* st, uint32_t i){
    mpol_node* t = mpol_nodes_base(st);
    uint32_t n = *(uint32_t*)((char*)st+16);
    uint32_t seen[MPOL_ANC_SEEN_MAX]; int nseen = 0;
    uint32_t stack[MPOL_ANC_SEEN_MAX]; int sp = 0;
    uint64_t cnt = 1, bytes = t[i].size;
    int saturated = 0;
    for (uint32_t k = 0; k < t[i].n_parents; k++){
        uint32_t p = mpol_par_at(st, &t[i], k);
        if (p >= n) continue;                      /* 0xFFFFFFFF: parent is gone */
        if (nseen >= MPOL_ANC_SEEN_MAX){ saturated = 1; break; }
        seen[nseen++] = p; stack[sp++] = p;
    }
    while (sp && !saturated){
        uint32_t a = stack[--sp];
        cnt++; bytes += t[a].size;
        for (uint32_t k = 0; k < t[a].n_parents; k++){
            uint32_t p = mpol_par_at(st, &t[a], k);
            if (p >= n) continue;
            int dup = 0; for (int q = 0; q < nseen; q++) if (seen[q] == p){ dup = 1; break; }
            if (dup) continue;
            if (nseen >= MPOL_ANC_SEEN_MAX){ saturated = 1; break; }
            seen[nseen++] = p; stack[sp++] = p;
        }
    }
    if (saturated){ cnt = 0xFFFFFFFFu; bytes = 0xFFFFFFFFu; }   /* refuse, never over-admit */
    t[i].anc_cnt   = (uint32_t)(cnt   > 0xFFFFFFFFu ? 0xFFFFFFFFu : cnt);
    t[i].anc_bytes = (uint32_t)(bytes > 0xFFFFFFFFu ? 0xFFFFFFFFu : bytes);
}
static void mpol_recompute_anc_all(void* st){
    mpol_node* t = mpol_nodes_base(st);
    uint32_t n = *(uint32_t*)((char*)st+16);
    for (uint32_t i = 0; i < n; i++)
        if (t[i].n_parents) mpol_recompute_anc(st, i);
        /* a node with no parents has anc_cnt 1 / anc_bytes == size already */
}

/* Remove ONE node (by current index): structural delete + graph unlink.
 * Children keep their nodes; their reference to this node is cleared (the
 * parent left the pool -- confirmed or evicted-with-package, in which case
 * the child is being removed in the same sweep anyway). */
static void remove_node(void* st, void* mp, int ci){
    mpol_node* t = mpol_nodes_base(st);
    uint32_t* nptr = (uint32_t*)((char*)st+16);
    unsigned char ct[32]; memcpy(ct, t[ci].txid, 32);
    decr_ancestors(st, ci, (uint32_t)t[ci].size, t[ci].fee);
    mpool_del(mp, ct);
    { uint64_t* pb = (uint64_t*)((char*)st+64);
      if (*pb >= t[ci].raw_len) *pb -= t[ci].raw_len; else *pb = 0; }
    /* MEM-12: every swap-with-last below relocates a SURVIVING entry, so the
     * index has to be told twice -- unlink the entry being dropped, unlink
     * the entry that is about to move, then re-link it at its new slot. Doing
     * the unlinks before either struct is overwritten matters: the unlink
     * hashes the entry's CURRENT key to find its bucket, so once the bytes
     * are copied over, the chain node can no longer be found and the table
     * silently keeps a dangling reference. */
    { mpol_claim* c = mpol_claims_base(st);
      uint32_t* ncl = (uint32_t*)((char*)st+12);
      for (uint32_t i=0;i<*ncl;){
          if (c[i].claimer==(uint32_t)ci){
              uint32_t last_c = *ncl - 1;
              mpol_clm_idx_unlink(st, i);
              if (last_c != i) mpol_clm_idx_unlink(st, last_c);
              c[i]=c[last_c]; (*ncl)--;
              if (last_c != i) mpol_clm_idx_link(st, i);
          } else i++; } }
    { mpol_out* o = mpol_outreg_base(st);
      uint32_t* no = (uint32_t*)((char*)st+8);
      for (uint32_t i=0;i<*no;){
          if (memcmp(o[i].txid,ct,32)==0){
              uint32_t last_o = *no - 1;
              mpol_out_idx_unlink(st, i);
              if (last_o != i) mpol_out_idx_unlink(st, last_o);
              o[i]=o[last_o]; (*no)--;
              if (last_o != i) mpol_out_idx_link(st, i);
          } else i++; } }
    /* clear children's parent references to ci. MEM-17: remember whether
     * any child lost a parent here, so its aggregates get recomputed once
     * the indices are final (bottom of this function). */
    uint32_t orphaned = 0;
    { uint32_t n = *nptr;
      for (uint32_t j=0;j<n;j++)
          for (uint32_t k=0;k<t[j].n_parents;k++)
              if (mpol_par_at(st, &t[j], k)==(uint32_t)ci){
                  mpol_par_set(st, &t[j], k, 0xFFFFFFFFu); orphaned++; } }
    /* MEM-3: hand this node's overflow block back BEFORE the slot is
     * overwritten by the swap below, or the block leaks and the pool bleeds
     * away one entry per removal until it is exhausted -- at which point
     * every transaction with more than MPOL_INLINE_PARENTS parents would be
     * refused. The swap then carries `last`'s own povf into slot ci with the
     * rest of the struct, which is exactly right: the block belongs to the
     * node, and the node has simply moved. */
    mpol_par_release(st, &t[ci]);
    uint32_t last = *nptr - 1;
    /* MEM-12: same two-unlink dance for the node table. */
    mpol_node_idx_unlink(st, (uint32_t)ci);
    if (last != (uint32_t)ci) mpol_node_idx_unlink(st, last);
    t[ci] = t[last];
    (*nptr)--;
    if (last != (uint32_t)ci) mpol_node_idx_link(st, (uint32_t)ci);
    if ((uint32_t)ci != last){
        uint32_t n = *nptr;
        for (uint32_t j=0;j<n;j++)
            for (uint32_t k=0;k<t[j].n_parents;k++)
                if (mpol_par_at(st, &t[j], k)==last)
                    mpol_par_set(st, &t[j], k, (uint32_t)ci);
        { mpol_claim* c = mpol_claims_base(st);
          uint32_t ncl = *(uint32_t*)((char*)st+12);
          for (uint32_t i=0;i<ncl;i++) if (c[i].claimer==last) c[i].claimer=(uint32_t)ci; }
    }
    if (orphaned) mpol_recompute_anc_all(st);      /* MEM-17 */
    if (g_forget_cb) g_forget_cb(ct);
}

/* ==========================================================================
 * MEM-12 (second half): BATCH REMOVAL
 *
 * remove_node is O(n) whatever the lookups cost, because three of its steps
 * are full sweeps rather than lookups: clearing children's parent references
 * to the departing node, renumbering references to the node that swap-with-
 * last moved, and renumbering claims' `claimer`. Indexing find_node,
 * find_outreg and find_claim made ACCEPTS flat and left this untouched --
 * measured, not assumed: with the indices in place, block connect still went
 * 2.3 -> 8.6 -> 17.9 -> 158 ms as the pool grew 10k -> 40k -> 80k -> 260k.
 *
 * mpool_policy_block_connect removes MANY nodes at once -- every transaction
 * the block confirmed, plus any it conflicts with -- and it did so one at a
 * time: m removals each costing O(n), so O(n*m). A 3,000-transaction block
 * against a full 300 MB pool (~750k entries) is on the order of SECONDS,
 * under mp_lock, in the download worker.
 *
 * Removing them together turns that into ONE sweep: O(n + links) total. The
 * whole trick is a single remap array. Compaction assigns every surviving
 * node its new index and every removed node MPOL_IDX_NONE, and then one pass
 * over the survivors' parent lists does BOTH jobs the old code did with two
 * separate sweeps per removal -- a parent that moved is renumbered, a parent
 * that is gone becomes 0xFFFFFFFF -- because "cleared" and "renumbered" are
 * the same operation once the remap says so.
 *
 * Compaction is STABLE (order-preserving), not swap-with-last. That is not
 * cosmetic: the chunk scorer and the cluster walk read the node array in
 * order, and tests pin the resulting eviction order, so reordering survivors
 * would change which transaction gets evicted under pressure.
 *
 * Per-node bookkeeping that is NOT positional -- ancestor decrements, the
 * structural mpool_del, the pool byte counter, the forget callback -- still
 * runs once per removed node, before anything moves, exactly as
 * remove_node does it. Only the POSITIONAL work is batched.
 * ========================================================================== */
/* Batch removal is on by default. The switch exists so the test suite can run
 * the SAME block connect both ways from an identical starting state and
 * compare the resulting pool -- the claim a batch makes is not "it is fast"
 * but "it leaves the pool in exactly the state the per-transaction path
 * would have", and that is worth checking directly rather than inferring from
 * a handful of hand-built cases. It is also the fallback if the scratch
 * cannot be sized: a block connect must not be skippable on an allocation. */
static int g_batch_connect = 1;
void mpool_policy_set_batch_connect(int on){ g_batch_connect = on ? 1 : 0; }

/* Growable scratch, same pattern worst_chunk uses: sized on demand rather
 * than reserved in .bss for every process that links this file. */
static uint8_t*  g_rm_mark;
static uint32_t* g_rm_remap;
static uint32_t  g_rm_cap;
static int mpol_rm_reserve(uint32_t n){
    if (n <= g_rm_cap) return 1;
    uint32_t want = g_rm_cap ? g_rm_cap : 1024;
    while (want < n){ if (want > 0x40000000u){ want = n; break; } want *= 2; }
    uint8_t*  m = realloc(g_rm_mark,  want);
    uint32_t* r = realloc(g_rm_remap, (size_t)want * sizeof *r);
    if (m) g_rm_mark = m;
    if (r) g_rm_remap = r;
    if (!m || !r) return 0;
    g_rm_cap = want;
    return 1;
}

/* Remove every node whose mark byte is set, in one compaction.
 * Returns how many were removed. `mark` is g_rm_mark, valid for n entries. */
static long mpol_remove_marked(void* st, void* mp, uint32_t n){
    mpol_node* t = mpol_nodes_base(st);
    uint8_t* mark = g_rm_mark;
    uint32_t* remap = g_rm_remap;

    /* ---- 1. per-node bookkeeping, while indices are still valid ---- */
    long nremoved = 0;
    for (uint32_t i = 0; i < n; i++){
        if (!mark[i]) continue;
        nremoved++;
        unsigned char ct[32]; memcpy(ct, t[i].txid, 32);
        decr_ancestors(st, (int)i, (uint32_t)t[i].size, t[i].fee);
        mpool_del(mp, ct);
        { uint64_t* pb = (uint64_t*)((char*)st+64);
          if (*pb >= t[i].raw_len) *pb -= t[i].raw_len; else *pb = 0; }
        mpol_par_release(st, &t[i]);       /* MEM-3 overflow block back to the pool */
        if (g_forget_cb) g_forget_cb(ct);
    }
    if (!nremoved) return 0;

    /* ---- 2. claims: drop those a removed node claimed, keep order ---- */
    { mpol_claim* c = mpol_claims_base(st);
      uint32_t* ncl = (uint32_t*)((char*)st+12);
      uint32_t w = 0;
      for (uint32_t i = 0; i < *ncl; i++){
          uint32_t cl = c[i].claimer;
          if (cl < n && mark[cl]) continue;          /* its claimer is leaving */
          if (w != i) c[w] = c[i];
          w++;
      }
      *ncl = w; }

    /* ---- 3. outreg: drop the outputs of removed transactions.
     * The node index still answers, so this is a lookup per entry rather
     * than a scan per removed node. ---- */
    { mpol_out* o = mpol_outreg_base(st);
      uint32_t* no = (uint32_t*)((char*)st+8);
      uint32_t w = 0;
      for (uint32_t i = 0; i < *no; i++){
          int owner = find_node(st, o[i].txid);
          if (owner >= 0 && mark[owner]) continue;
          if (w != i) o[w] = o[i];
          w++;
      }
      *no = w; }

    /* ---- 4. compact the nodes, building the remap ---- */
    uint32_t w = 0;
    for (uint32_t i = 0; i < n; i++){
        if (mark[i]){ remap[i] = MPOL_IDX_NONE; continue; }
        remap[i] = w;
        if (w != i) t[w] = t[i];
        w++;
    }
    *(uint32_t*)((char*)st+16) = w;

    /* ---- 5. ONE pass over the survivors' parent lists. A parent that moved
     * is renumbered; a parent that is gone becomes 0xFFFFFFFF. The old code
     * needed a full sweep for each of those, per removal. ---- */
    uint32_t orphaned = 0;                          /* MEM-17 */
    for (uint32_t i = 0; i < w; i++){
        for (uint32_t k = 0; k < t[i].n_parents; k++){
            uint32_t pv = mpol_par_at(st, &t[i], k);
            if (pv == 0xFFFFFFFFu) continue;         /* already cleared */
            uint32_t nv = (pv < n) ? remap[pv] : MPOL_IDX_NONE;
            if (nv == MPOL_IDX_NONE) orphaned++;
            mpol_par_set(st, &t[i], k, nv == MPOL_IDX_NONE ? 0xFFFFFFFFu : nv);
        }
    }
    /* ---- 6. claims' claimer field follows the same remap ---- */
    { mpol_claim* c = mpol_claims_base(st);
      uint32_t ncl = *(uint32_t*)((char*)st+12);
      for (uint32_t i = 0; i < ncl; i++){
          uint32_t cl = c[i].claimer;
          c[i].claimer = (cl < n && remap[cl] != MPOL_IDX_NONE) ? remap[cl] : cl;
      } }

    /* ---- 7. rebuild the three indices. Every array moved, so patching each
     * chain would cost more than starting again -- and starting again cannot
     * leave a stale link behind, which is the failure mode that matters. ---- */
    { uint32_t nb = mpol_nbuckets(st);
      uint32_t cap = *(uint32_t*)((char*)st+4);
      memset(mpol_node_head(st), 0xFF, (size_t)(nb + cap) * sizeof(uint32_t));
      memset(mpol_out_head(st),  0xFF, (size_t)(nb + cap) * sizeof(uint32_t));
      memset(mpol_clm_head(st),  0xFF, (size_t)(nb + cap) * sizeof(uint32_t));
      for (uint32_t i = 0; i < w; i++) mpol_node_idx_link(st, i);
      { uint32_t no = *(uint32_t*)((char*)st+8);
        for (uint32_t i = 0; i < no; i++) mpol_out_idx_link(st, i); }
      { uint32_t ncl = *(uint32_t*)((char*)st+12);
        for (uint32_t i = 0; i < ncl; i++) mpol_clm_idx_link(st, i); } }

    /* MEM-17: every survivor that lost a parent -- and everything below it --
     * now carries a stale with-ancestors count. One pass, walking up. */
    if (orphaned) mpol_recompute_anc_all(st);

    return nremoved;
}

/* Mark a node and every in-pool DESCENDANT of it, for batch removal.
 * Sweeps to a fixpoint rather than walking children, because there is no
 * child index: a node is a descendant if any of its parents is marked, so
 * repeating the sweep until nothing new is marked closes the set. The round
 * bound is 128 -- twice the 64-transaction cluster limit, so it can never cut
 * a legitimate closure short, and it still terminates if the graph is ever
 * malformed. Only reached when a block actually conflicts with something in
 * the pool, which is the rare case. */
/* TWO MARK LEVELS, and the distinction is the whole correctness of the batch:
 *
 *   1 = this node leaves ALONE. A transaction the block CONFIRMED: its
 *       children are still valid, they just have one fewer unconfirmed
 *       ancestor, and Core keeps them (removeForBlock, not removeRecursive).
 *   2 = this node leaves WITH its descendants. A transaction the block
 *       CONFLICTED with: everything spending its outputs is now unspendable.
 *
 * Propagation follows level 2 only. The first version of this used a single
 * mark and swept "a node is a descendant if any parent is marked", which
 * quietly took the children of every CONFIRMED transaction too -- caught by
 * test_mempool_core_parity's "A's child SURVIVES", which is exactly the case
 * that distinguishes the two removal kinds.
 *
 * A node already marked 1 that turns out to be a descendant of a conflict is
 * upgraded to 2: it is leaving either way, but its own descendants must then
 * follow it. */
static void mpol_mark_with_descendants(void* st, uint32_t n, uint32_t root){
    if (root >= n || g_rm_mark[root] == 2) return;
    g_rm_mark[root] = 2;
    mpol_node* t = mpol_nodes_base(st);
    int changed = 1, rounds = 0;
    while (changed && rounds++ <= 128){
        changed = 0;
        for (uint32_t i = 0; i < n; i++){
            if (g_rm_mark[i] == 2) continue;
            for (uint32_t k = 0; k < t[i].n_parents; k++){
                uint32_t pv = mpol_par_at(st, &t[i], k);
                if (pv < n && g_rm_mark[pv] == 2){ g_rm_mark[i] = 2; changed = 1; break; }
            }
        }
    }
}

/* Remove a tx AND its whole in-pool descendant set (by txid). Returns the
 * number of entries removed (0 if absent). */
long mpool_policy_remove_package(void* st, void* mp, const unsigned char txid[32]){
    int ci = find_node(st, txid);
    if (ci < 0) return 0;
    static unsigned char dts[MPOL_PKG_MAX][32];
    int nd = collect_descendant_txids(st, ci, dts, MPOL_PKG_MAX);
    long removed = 0;
    if (nd > 0){
        for (int k = 0; k < nd; k++){
            int di = find_node(st, dts[k]);
            if (di >= 0){ remove_node(st, mp, di); removed++; }
        }
    }
    ci = find_node(st, txid);
    if (ci >= 0){ remove_node(st, mp, ci); removed++; }
    return removed;
}

/* Confirmed-tx removal (block connect): the tx alone leaves; descendants
 * stay (their parent just confirmed). */
static long remove_confirmed(void* st, void* mp, const unsigned char txid[32]){
    int ci = find_node(st, txid);
    if (ci < 0) return 0;
    remove_node(st, mp, ci);
    return 1;
}

/* ========================================================================== */
/* rolling mempool minimum fee (Core CTxMemPool::GetMinFee semantics)         */
/* ========================================================================== */
#define MPOL_ROLLING_HALFLIFE (60*60*12)

static void floor_bump(void* st, uint64_t satkvb){
    uint64_t* fl = (uint64_t*)((char*)st+48);
    if (satkvb > *fl) *fl = satkvb;
    *(uint64_t*)((char*)st+56) = (uint64_t)time(0);
    *(uint64_t*)((char*)st+80) &= ~MPOL_F_BLOCK_SINCE_BUMP;   /* decay paused */
}

/* dynamic floor with lazy exponential decay -- sat/kvB */
uint64_t mpool_policy_min_fee_ex(void* st, uint64_t incremental_kvb){
    uint64_t* fl = (uint64_t*)((char*)st+48);
    if (*fl == 0) return 0;
    if (!(*(uint64_t*)((char*)st+80) & MPOL_F_BLOCK_SINCE_BUMP)) return *fl;
    uint64_t now = (uint64_t)time(0);
    uint64_t* last = (uint64_t*)((char*)st+56);
    if (now > *last + 10){
        uint64_t halflife = MPOL_ROLLING_HALFLIFE;
        uint64_t used = *(uint64_t*)((char*)st+64);
        uint64_t cap  = *(uint64_t*)((char*)st+72);
        if (cap){
            if (used < cap/4) halflife /= 4;
            else if (used < cap/2) halflife /= 2;
        }
        /* fl /= 2^(elapsed/halflife), integer: whole halvings by shift, the
         * fractional part via a q16 table of 2^(-i/16) -- within ~2% of the
         * exact exponential, monotone, and libm-free. */
        uint64_t elapsed = now - *last;
        uint64_t whole = elapsed / halflife;
        if (whole >= 64) *fl = 0;
        else {
            static const uint32_t q16[16] = {
                65536,62757,60097,57549,55109,52772,50535,48393,
                46341,44376,42495,40694,38968,37316,35734,34219 };
            uint64_t frac16 = (elapsed % halflife) * 16 / halflife;
            *fl = ((*fl >> whole) * q16[frac16]) >> 16;
        }
        *last = now;
        if (*fl < incremental_kvb / 2) *fl = 0;
    }
    return *fl;
}
/* RPC hook shape (single arg): decays at the DEFAULT incrementalrelayfee.
 * Returns sat/kvB (getmempoolinfo divides by 1e8 for BTC/kvB). */
uint64_t mpool_policy_min_fee(void* st){
    return mpool_policy_min_fee_ex(st, 1000);
}

/* block-connect signal: lets the floor decay again (Core sets
 * blockSinceLastRollingFeeBump in removeForBlock) */
static void note_block_connected(void* st){
    *(uint64_t*)((char*)st+80) |= MPOL_F_BLOCK_SINCE_BUMP;
}

/* ========================================================================== */
/* eviction scoring (classic descendant score)                                */
/* ========================================================================== */
/* score(i) = max(own feerate, with-descendants feerate), compared as
 * cross-multiplied fractions. Returns fee/size of the max side. */
static void node_score(const mpol_node* n, uint64_t* fee, uint64_t* size){
    unsigned __int128 own  = (unsigned __int128)n->fee * (n->desc_bytes ? n->desc_bytes : 1);
    unsigned __int128 pkg  = (unsigned __int128)n->desc_fee * (n->size ? n->size : 1);
    if (pkg > own){ *fee = n->desc_fee; *size = n->desc_bytes ? n->desc_bytes : 1; }
    else          { *fee = n->fee;      *size = n->size ? n->size : 1; }
}
static int worst_package(void* st) __attribute__((unused));
static int worst_package(void* st){
    mpol_node* t = mpol_nodes_base(st);
    uint32_t n = *(uint32_t*)((char*)st+16);
    int best = -1; uint64_t bf = 0, bs = 1;
    for (uint32_t i=0;i<n;i++){
        uint64_t f, s; node_score(&t[i], &f, &s);
        if (best < 0 || (unsigned __int128)f * bs < (unsigned __int128)bf * s){
            best = (int)i; bf = f; bs = s;
        }
    }
    return best;
}

/* ---- cluster linearization and the worst chunk (Core v31 TrimToSize) -----
 * Core evicts by CHUNK: every cluster (connected component of the spend
 * graph) has a linearization -- a topological order cut into chunks of
 * non-increasing feerate, a child that pays for its parent sharing the
 * parent's chunk -- and TrimToSize removes the worst chunk of all clusters
 * (GetWorstMainChunk), setting the floor to that chunk's feerate plus the
 * incremental relay fee. Per-leaf eviction scored a child by its own
 * descendant package, so a cheap parent whose child paid for it could be
 * kept while a better-paying single transaction was evicted -- the wrong
 * transaction under load. The linearization here is the ancestor-set
 * greedy (best ancestor-set feerate first, bumped chunks merged), which is
 * Core's own pre-cluster ordering and optimal for the chains and small
 * trees that dominate real pools; Core's exact search only differs on
 * pathological wide clusters. Clusters larger than CHUNK_MAX_CLUSTER fall
 * back to the per-leaf score for that cluster alone. */
#define CHUNK_MAX_CLUSTER 128
typedef struct { uint32_t idx[CHUNK_MAX_CLUSTER]; int n; uint64_t fee, size; } mpol_chunk;

/* the connected component containing node `seed` (indices), via parent links
 * in both directions using a caller-built child adjacency */
static int cluster_members(void* st, uint32_t seed, const uint32_t* child_head, const uint32_t* child_next,
                           uint32_t* stamp_mark, uint32_t stamp, uint32_t* out, int cap){
    mpol_node* t = mpol_nodes_base(st);
    int n = 0, sp = 0; uint32_t stack[CHUNK_MAX_CLUSTER + 1];
    stamp_mark[seed] = stamp; stack[sp++] = seed;
    while (sp > 0){
        uint32_t cur = stack[--sp];
        if (n >= cap) return -1;
        out[n++] = cur;
        for (uint32_t k = 0; k < t[cur].n_parents; k++){
            uint32_t pp = mpol_par_at(st, &t[cur], k);
            if (pp == 0xFFFFFFFFu || stamp_mark[pp] == stamp) continue;
            if (sp >= CHUNK_MAX_CLUSTER) return -1;
            stamp_mark[pp] = stamp; stack[sp++] = pp;
        }
        for (uint32_t c = child_head[cur]; c != 0xFFFFFFFFu; c = child_next[c]){
            if (stamp_mark[c] == stamp) continue;
            if (sp >= CHUNK_MAX_CLUSTER) return -1;
            stamp_mark[c] = stamp; stack[sp++] = c;
        }
    }
    return n;
}

/* the LAST chunk of the cluster's linearization (its worst): ancestor-set
 * greedy over the members, chunks merged while a later one pays more */
static int cluster_last_chunk(void* st, const uint32_t* mem, int n, mpol_chunk* out){
    mpol_node* t = mpol_nodes_base(st);
    unsigned char done[CHUNK_MAX_CLUSTER]; memset(done, 0, sizeof done);
    mpol_chunk chunks[CHUNK_MAX_CLUSTER]; int nch = 0;
    int left = n;
    while (left > 0){
        /* for every undone member, the feerate of its undone ancestor set */
        int best = -1; uint64_t bf = 0, bs = 1; uint32_t bestset[CHUNK_MAX_CLUSTER]; int bestn = 0;
        for (int m = 0; m < n; m++){
            if (done[m]) continue;
            /* ancestor set within the cluster (undone only) */
            unsigned char inset[CHUNK_MAX_CLUSTER]; memset(inset, 0, sizeof inset);
            uint32_t stk[CHUNK_MAX_CLUSTER]; int sp = 0; inset[m] = 1; stk[sp++] = (uint32_t)m;
            uint64_t f = 0, sz = 0; int cnt = 0;
            while (sp > 0){
                int cur = (int)stk[--sp];
                f += t[mem[cur]].fee; sz += t[mem[cur]].size; cnt++;
                for (uint32_t k = 0; k < t[mem[cur]].n_parents; k++){
                    uint32_t pp = mpol_par_at(st, &t[mem[cur]], k);
                    if (pp == 0xFFFFFFFFu) continue;
                    for (int q = 0; q < n; q++) if (mem[q] == pp && !done[q] && !inset[q]){ inset[q] = 1; stk[sp++] = (uint32_t)q; }
                }
            }
            if (sz == 0) sz = 1;
            if (best < 0 || (unsigned __int128)f * bs > (unsigned __int128)bf * sz){
                best = m; bf = f; bs = sz; bestn = 0;
                for (int q = 0; q < n; q++) if (inset[q]) bestset[bestn++] = (uint32_t)q;
            }
        }
        if (best < 0) break;
        mpol_chunk* c = &chunks[nch++];
        c->n = 0; c->fee = bf; c->size = bs;
        for (int q = 0; q < bestn; q++){ done[bestset[q]] = 1; c->idx[c->n++] = mem[bestset[q]]; }
        left -= bestn;
        /* merge backwards while this chunk pays more than the one before it */
        while (nch >= 2){
            mpol_chunk* a = &chunks[nch-2]; mpol_chunk* b = &chunks[nch-1];
            if ((unsigned __int128)b->fee * a->size > (unsigned __int128)a->fee * b->size){
                for (int q = 0; q < b->n && a->n < CHUNK_MAX_CLUSTER; q++) a->idx[a->n++] = b->idx[q];
                a->fee += b->fee; a->size += b->size; nch--;
            } else break;
        }
    }
    if (nch == 0) return 0;
    *out = chunks[nch-1];
    return 1;
}

/* The worst chunk across all clusters: 1 with *out filled, 0 if the pool is
 * empty. Clusters beyond CHUNK_MAX_CLUSTER contribute their per-leaf worst
 * (the old score) as a one-member chunk. */
/* MEM-6: `excl`/`n_excl` name transactions the caller is ABOUT to remove.
 * Any chunk containing one of them is skipped, so the answer is the worst
 * chunk that would still be there afterwards. Skipping errs upward -- the
 * reported chunk is never cheaper than the truth -- which makes a caller
 * using this for an early refusal strictly more permissive, never less.
 * worst_chunk() passes NULL and behaves exactly as before. */
static int worst_chunk_excl(void* st, mpol_chunk* out,
                            const unsigned char (*excl)[32], int n_excl){
    mpol_node* t = mpol_nodes_base(st);
    uint32_t n = *(uint32_t*)((char*)st+16);
    if (n == 0) return 0;
    /* MEM-2 (audit 2026-09-03): the working arrays GROW; they no longer cap
     * the evictor at 64K entries.
     *
     * These were `static uint32_t child_head[65536] ...` with `if (n > 65536)
     * return 0;` in front. The structural pool and the policy graph are sized
     * for ~1M entries (mempool_cfg.c sizes slots to blob_cap/512 -- 1,048,576
     * for the default 300 MB maxmempool), so the evictor hard-failed at a
     * sixteenth of the pool's capacity. At ~400 raw bytes per transaction the
     * pool holds more than 64K entries at ~26 MB, long before the blob is
     * full.
     *
     * What that produced: mpool_put returns 2 when fill + txlen > blob_cap,
     * and `fill` only shrinks in mpool_compact, which the accept path calls
     * only AFTER a successful eviction. So once the blob filled, worst_chunk
     * returned 0, the accept loop reported "mempool full" and returned, and
     * every subsequent accept at ANY feerate failed. No eviction, no
     * compaction, no floor_bump -- getmempoolinfo went on reporting
     * mempoolminfee 0 while rejecting everything. Recovery needed n to fall
     * back to 65,536 through confirmation or the 336-hour expiry, and the
     * low-fee filler that causes it is exactly what does not confirm. An
     * attacker reaches it for the price of 300 MB at the 0.1 sat/vB floor,
     * because the floor never rises until an eviction happens.
     *
     * Growing on demand rather than sizing to a compile-time maximum: the
     * arrays are 12 bytes per entry together, so a 1M-entry pool costs 12 MB
     * -- worth allocating when the pool actually gets there, not worth
     * reserving in .bss for every process that links this file (bitcoin_cli
     * links it too). A failed grow degrades exactly the way the old ceiling
     * did, which is the honest fallback: the caller's `worst_chunk() == 0`
     * arm is still there. */
    static uint32_t *child_head, *child_next, *mark;
    static uint32_t work_cap;
    if (n > work_cap){
        uint32_t want = work_cap ? work_cap : 65536;
        while (want < n){
            if (want > 0x80000000u){ want = n; break; }   /* no overflow on the doubling */
            want *= 2;
        }
        uint32_t* nh = realloc(child_head, (size_t)want * sizeof *nh);
        uint32_t* nn = realloc(child_next, (size_t)want * sizeof *nn);
        uint32_t* nm = realloc(mark,       (size_t)want * sizeof *nm);
        /* Keep whichever grew: realloc'ing the survivors on a partial failure
         * would leak the ones that succeeded, and the arrays are independent. */
        if (nh) child_head = nh;
        if (nn) child_next = nn;
        if (nm) mark       = nm;
        if (!nh || !nn || !nm) return 0;                  /* as before: caller reports "mempool full" */
        work_cap = want;
    }
    for (uint32_t i = 0; i < n; i++){ child_head[i] = 0xFFFFFFFFu; child_next[i] = 0xFFFFFFFFu; mark[i] = 0; }
    for (uint32_t i = 0; i < n; i++)
        for (uint32_t k = 0; k < t[i].n_parents; k++){
            uint32_t pp = mpol_par_at(st, &t[i], k);
            if (pp == 0xFFFFFFFFu || pp >= n) continue;
            child_next[i] = child_head[pp]; child_head[pp] = i;   /* a node may be pushed once per parent link: harmless for the walk */
        }
    int have = 0; mpol_chunk best; best.n = 0; best.fee = 0; best.size = 1;
    uint32_t stamp = 1;
    static uint32_t mem[CHUNK_MAX_CLUSTER + 1];
    for (uint32_t i = 0; i < n; i++){
        if (mark[i]) continue;
        stamp++;
        int cn = cluster_members(st, i, child_head, child_next, mark, stamp, mem, CHUNK_MAX_CLUSTER);
        mpol_chunk c;
        if (cn < 0){
            /* too wide: per-leaf worst inside this cluster, marks already set for the visited part */
            int w = (int)i; uint64_t wf, ws; node_score(&t[i], &wf, &ws);
            c.n = 1; c.idx[0] = (uint32_t)w; c.fee = wf; c.size = ws;
        } else if (!cluster_last_chunk(st, mem, cn, &c)) continue;
        if (n_excl > 0){
            int hit = 0;
            for (int q = 0; q < c.n && !hit; q++)
                for (int e = 0; e < n_excl; e++)
                    if (!memcmp(t[c.idx[q]].txid, excl[e], 32)){ hit = 1; break; }
            if (hit) continue;
        }
        if (!have || (unsigned __int128)c.fee * best.size < (unsigned __int128)best.fee * c.size){ best = c; have = 1; }
    }
    if (have) *out = best;
    return have;
}
static int worst_chunk(void* st, mpol_chunk* out){
    return worst_chunk_excl(st, out, NULL, 0);
}

/* ========================================================================== */
/* ADD: atomic policy gate + structural store + bookkeeping                   */
/* ========================================================================== */
/* The txids this add REPLACED, for submitpackage's replaced-transactions.
 * The eviction set is built inside the RBF check and was then used and
 * discarded, so an accepted replacement could not say what it displaced --
 * Core reports exactly this list, so the information has to survive the
 * call. Reset at the top of every add: a stale list would credit one
 * transaction with a previous transaction's replacements. */
static unsigned char _mpol_replaced[MPOL_MAX_REPLACEMENTS + MPOL_PKG_MAX][32];
static int _mpol_replaced_n;

int mpol_last_replaced(unsigned char* out, int cap){
    int n = _mpol_replaced_n < cap ? _mpol_replaced_n : cap;
    if (out && n > 0) memcpy(out, _mpol_replaced, (size_t)n * 32);
    return n;
}

static long mpol_add_core(mpol_cfg* pol, void* st, void* mp,
                          const unsigned char* tx, unsigned long txlen,
                          const unsigned char txid[32], void* utxo,
                          int commit, unsigned long long* fee_out,
                          unsigned long long* vsize_out){
    static unsigned char prev[MPOL_MAX_IN][32];
    static uint32_t idx[MPOL_MAX_IN], seq[MPOL_MAX_IN];
    mpol_txmeta meta;
    _mpol_replaced_n = 0;
    int n_in = parse_tx(tx, txlen, prev, idx, seq, &meta);
    if (n_in <= 0){ _mpol_last_reason = "malformed transaction"; return 0; }
    uint64_t vsize = meta.vsize;

    /* ---- bytespersigop: the sigop-adjusted virtual size ---------------------
     * Core does not keep a "real" vsize and adjust it at the fee check. The
     * ADJUSTED figure *is* the entry's size -- CTxMemPoolEntry::GetTxSize() is
     * GetVirtualTransactionSize(weight, sigOpCost, nBytesPerSigOp) -- so it is
     * what the fee floors, the replacement arithmetic, the ancestor and
     * descendant byte budgets, eviction, mining and getmempoolentry all see.
     * Computing it once, here, is what makes those agree; adjusting only the
     * fee floor (which is what this file used to do) left a sigop-dense
     * transaction paying Core's price on entry while occupying a smaller
     * footprint than Core in every limit that came after.
     *
     * Core's formula exactly: ceil(max(weight, sigop_cost * bytespersigop) / 4).
     * The max is taken on the WEIGHT scale and the rounding happens once, at
     * the end. Taking it after dividing -- max(ceil(weight/4), sigops*bps/4) --
     * rounds the sigop term down and undercharges by a byte whenever
     * sigop_cost * bytespersigop is not a multiple of 4.
     *
     * The count is consumed HERE, on every path. It arrives through a global
     * that the caller parks before the call (daemon/tx_accept.c's prechecks,
     * which is where the UTXO view needed to count P2SH and witness sigops is
     * already open), and this function has eight rejection paths between here
     * and the old clearing site. A transaction rejected on any of them used to
     * leave its count parked, and the NEXT transaction -- a different one,
     * possibly with no sigops at all -- was then priced as though it carried
     * them. Reading and clearing in the same breath is what makes that
     * impossible rather than merely unlikely. */
    { uint64_t sigops_x = mpol_pending_sigops;
      mpol_pending_sigops = 0;
      if (sigops_x){
          uint64_t adj_w = meta.weight;
          uint64_t sw = sigops_x * mpol_bytes_per_sigop;
          if (sw > adj_w) adj_w = sw;
          vsize = (adj_w + 3) / 4;
      } }
    /* Published HERE, before any rejection can return: a package member that
     * fails only on fee still contributes its size to the package total, and
     * the caller has no other way to learn the sigop-adjusted figure -- the
     * structural walker that hands it a vsize cannot count sigops, which need
     * the UTXO view. */
    if (vsize_out) *vsize_out = (unsigned long long)vsize;

    /* --- standardness (Core IsStandardTx order: before fees) --------------- */
    int n_dust = 0;
    { const char* r = standard_checks(pol, tx, txlen, &meta, prev[0], idx[0], &n_dust);
      if (r){ _mpol_last_reason = r; return 0; } }

    /* --- duplicate check (before fee resolution: Core's order) ------------- */
    if (find_node(st, txid) >= 0){ _mpol_last_reason = "txn-already-in-mempool"; return 0; }
    if (mpool_get(mp, txid, &(unsigned long){0}) != NULL){
        _mpol_last_reason = "txn-already-in-mempool"; return 0; }

    /* --- fee: resolve inputs (mempool outreg first, then confirmed set) ---- */
    unsigned long long sum_in = 0;
    int unconf_in[MPOL_MAX_IN]; int n_unconf = 0;
    for (int i=0;i<n_in;i++){
        uint64_t v = 0;
        if (find_outreg(st, prev[i], idx[i], &v)) { sum_in += v; unconf_in[n_unconf++] = i; continue; }
        unsigned long long val; const unsigned char* sp; unsigned long sl;
        if (!utxo || mempool_resolve_confirmed_utxo(utxo, prev[i], idx[i], &val, &sp, &sl)!=1){
            _mpol_last_reason = "bad-txns-inputs-missingorspent"; return 0; }
        sum_in += val;
    }
    if (sum_in < meta.sum_out){ _mpol_last_reason = "bad-txns-in-belowout"; return 0; }
    uint64_t fee = sum_in - meta.sum_out;
    if (fee_out) *fee_out = (unsigned long long)fee;

    /* ---- ephemeral dust (Core PreCheckEphemeralTx / CheckEphemeralSpends) --
     * Dust is normally refused because it costs more to spend than it is
     * worth, and left in the UTXO set forever. Core carves out one case: dust
     * that is created and swept inside the same package never reaches the
     * UTXO set, and that is how an anchor output for fee-bumping is possible
     * at all. Two rules keep the carve-out safe, and they only work together:
     *
     *   1. a transaction carrying dust must pay ZERO fee, so a miner has no
     *      incentive to mine it ALONE and strand the dust; and
     *   2. a child must sweep every dust output of its unconfirmed parents,
     *      so the only way the parent gets mined is together with the child
     *      that cleans up after it.
     *
     * Drop rule 1 and dust becomes profitable to strand; drop rule 2 and the
     * dust survives in the UTXO set exactly as before. */
    if (!pol->accept_nonstd){
        if (n_dust > 0 && fee != 0){
            /* Core's reject reason is the bare "dust"; the explanation ("tx
             * with dust output must be 0-fee") is its debug string. */
            _mpol_last_reason = "dust"; return 0;
        }
        /* rule 2: every dust output of every UNCONFIRMED parent must be spent
         * by this transaction. A confirmed parent's dust is already in the
         * UTXO set and is not this transaction's problem. */
        for (int i = 0; i < n_in; i++){
            int dup = 0;
            for (int k = 0; k < i; k++) if (!memcmp(prev[k], prev[i], 32)){ dup = 1; break; }
            if (dup) continue;                      /* parent already handled */
            unsigned long plen = 0;
            const unsigned char* ptx = mpool_get(mp, prev[i], &plen);
            if (!ptx || !plen) continue;            /* not an unconfirmed parent */
            mpol_txmeta pm;
            static unsigned char pprev[MPOL_MAX_IN][32];
            static uint32_t pidx[MPOL_MAX_IN], pseq[MPOL_MAX_IN];
            if (parse_tx(ptx, plen, pprev, pidx, pseq, &pm) <= 0) continue;
            uint32_t didx[8];
            int nd = mpol_dust_outputs(pol, ptx, plen, &pm, didx, 8);
            for (int d = 0; d < nd && d < 8; d++){
                int swept = 0;
                for (int k = 0; k < n_in && !swept; k++)
                    if (!memcmp(prev[k], prev[i], 32) && idx[k] == didx[d]) swept = 1;
                if (!swept){ _mpol_last_reason = "missing-ephemeral-spends"; return 0; }
            }
        }
    }

    /* ---- fee floors, over the PACKAGE aggregate when one is in effect ----
     * Core evaluates a package member against the package's EFFECTIVE
     * FEERATE, which is what lets a child pay for a parent that could never
     * get in alone (CPFP). Outside a package g_pkg_vsize is 0 and these are
     * exactly the single-transaction checks they always were.
     * These are the ONLY two checks a package may relax: a transaction that
     * fails anything else is invalid or non-standard on its own terms, and no
     * amount of fee from a child changes that. */
    { uint64_t eff_fee   = g_pkg_vsize ? g_pkg_fee   : fee;
      uint64_t eff_vsize = g_pkg_vsize ? g_pkg_vsize : vsize;
      /* min relay floor over VSIZE (Core "min relay fee not met"). vsize is
       * already the sigop-adjusted size -- see the top of this function. */
      /* MEM-16 (audit 2026-09-03): this was `eff_fee * 1000 < eff_vsize *
       * rate`, which is fee < rate*vsize/1000 computed EXACTLY -- i.e. a
       * ceiling. Core's CFeeRate::GetFee truncates and only then floors at 1:
       *
       *     nFee = nSatoshisPerK * num_bytes / 1000;
       *     if (nFee == 0 && num_bytes != 0 && nSatoshisPerK > 0) nFee = 1;
       *
       * At minrelaytxfee 100 sat/kvB and vsize 115 that is 11 sat for Core
       * and was 12 here, so this node refused to relay transactions Core
       * relays. The dynamic floor immediately below ALREADY used Core's
       * rounding, so the two floors disagreed with each other -- which is the
       * clearest sign this was an oversight rather than a choice. */
      { uint64_t need = (uint64_t)pol->relay_fee_rate * eff_vsize / 1000;
        if (need == 0 && eff_vsize != 0 && pol->relay_fee_rate > 0) need = 1;
        if (eff_fee < need){
            _mpol_last_reason = "min relay fee not met"; return 0; } }
      /* dynamic floor (sat/kvB, rolling decay) -- Core "mempool min fee not met" */
      uint64_t fl = mpool_policy_min_fee_ex(st, pol->incremental_fee);
      if (fl > 0){
          uint64_t need = fl * eff_vsize / 1000;
          if (need == 0) need = 1;
          if (eff_fee < need){ _mpol_last_reason = "mempool min fee not met"; return 0; }
      } }

    /* --- conflicts + RBF (Core ReplacementChecks / classic BIP125) --------- */
    int n_conf = 0;
    uint32_t conf_claimers[MPOL_MAX_IN];
    for (int i=0;i<n_in;i++){
        int cl = find_claim(st, prev[i], idx[i]);
        if (cl >= 0){
            int seen = 0; for (int k=0;k<n_conf;k++) if (conf_claimers[k]==(uint32_t)cl) seen=1;
            if (!seen && n_conf < MPOL_MAX_IN) conf_claimers[n_conf++] = (uint32_t)cl;
        }
    }
    static unsigned char evict_set[MPOL_MAX_REPLACEMENTS + MPOL_PKG_MAX][32];
    int n_evict = 0;
    /* Fees of everything this transaction would remove. Hoisted out of the
     * conflict block below because TRUC sibling eviction can add to the set
     * later, and Core prices the whole to-be-replaced set together. */
    uint64_t removed_fees = 0;
    if (n_conf > 0){
        mpol_node* t = mpol_nodes_base(st);
        /* rule 1 (classic; skipped under fullrbf): each REPLACED tx must
         * signal BIP125 (any input nSequence < 0xfffffffe). Inherited
         * signaling simplified away -- see header. */
        if (!pol->rbf_enabled){
            for (int k=0;k<n_conf;k++){
                unsigned long clen = 0;
                const unsigned char* ctx = mpool_get(mp, t[conf_claimers[k]].txid, &clen);
                int signals = 0;
                if (ctx){
                    static unsigned char cprev[MPOL_MAX_IN][32];
                    static uint32_t cidx[MPOL_MAX_IN], cseq[MPOL_MAX_IN];
                    mpol_txmeta cm;
                    int cn = parse_tx(ctx, clen, cprev, cidx, cseq, &cm);
                    for (int i=0;i<cn;i++) if (cseq[i] < 0xfffffffeu) signals = 1;
                }
                if (!signals){ _mpol_last_reason = "txn-mempool-conflict"; return 0; }
            }
        }
        /* build the full eviction set: conflicts + their descendants */
        for (int k=0;k<n_conf;k++){
            int ci = (int)conf_claimers[k];
            if (n_evict >= MPOL_MAX_REPLACEMENTS){
                _mpol_last_reason = "too many potential replacements"; return 0; }
            memcpy(evict_set[n_evict++], t[ci].txid, 32);
            removed_fees += t[ci].fee;
            static unsigned char dts[MPOL_PKG_MAX][32];
            int nd = collect_descendant_txids(st, ci, dts, MPOL_PKG_MAX);
            if (nd < 0){ _mpol_last_reason = "too many potential replacements"; return 0; }
            for (int d=0; d<nd; d++){
                int dup = 0;
                for (int e=0;e<n_evict;e++) if (!memcmp(evict_set[e], dts[d], 32)){ dup=1; break; }
                if (dup) continue;
                if (n_evict >= MPOL_MAX_REPLACEMENTS){
                    _mpol_last_reason = "too many potential replacements"; return 0; }
                int di = find_node(st, dts[d]);
                if (di >= 0) removed_fees += mpol_nodes_base(st)[di].fee;
                memcpy(evict_set[n_evict++], dts[d], 32);
            }
        }
        /* disjointness (Core EntriesAndTxidsDisjoint): the replacement must
         * not spend an output OF anything it evicts */
        for (int i=0;i<n_in;i++)
            for (int e=0;e<n_evict;e++)
                if (!memcmp(prev[i], evict_set[e], 32)){
                    _mpol_last_reason = "bad-txns-spends-conflicting-tx"; return 0; }
        /* rule 2 (classic): no NEW unconfirmed inputs -- every unconfirmed
         * input must already be double-spent (claimed) by a conflict; an
         * unclaimed unconfirmed input is new. */
        for (int u=0;u<n_unconf;u++){
            int i = unconf_in[u];
            if (find_claim(st, prev[i], idx[i]) < 0){
                _mpol_last_reason = "replacement-adds-unconfirmed"; return 0; }
        }
        /* ---- MEM-7 (audit 2026-09-03): Core's PaysMoreThanConflicts ----
         *
         * Rules 3+4 below are ABSOLUTE-fee rules: pay everything you evict,
         * plus a bit more. On their own they let a replacement that is far
         * WORSE for a miner win. The audit's example: T is 200 vB paying
         * 2,000 sat (10 sat/vB); R is 100,000 vB -- the standard maximum --
         * paying 102,000 sat, which is 1.02 sat/vB. R pays more in total, so
         * rules 3+4 passed, T was evicted, and 100 kvB of 1 sat/vB traffic
         * was relayed in place of a 200 vB transaction at ten times the
         * feerate. That is miner-incentive-incompatible and Core has rejected
         * it in every version: PaysMoreThanConflicts pre-v31, and the
         * feerate-diagram check under the v31 cluster mempool.
         *
         * Core compares the replacement's feerate against EACH DIRECT
         * conflict's, not against the eviction set as a whole (rbf.cpp
         * iterates iters_conflicting), and rejects unless it is strictly
         * greater. Descendants are covered by rules 3+4's absolute total.
         *
         * Cross-multiplied so there is no division and no rounding: the
         * comparison fee/vsize > c.fee/c.size becomes fee*c.size >
         * c.fee*vsize. Both fees are satoshi counts under MAX_MONEY and both
         * sizes are under 100,000, so the products cannot overflow 64 bits.
         * A conflict recorded with size 0 would make the comparison
         * meaningless, so it is treated as unreplaceable rather than as
         * infinitely cheap. */
        for (int k=0;k<n_conf;k++){
            const mpol_node* c = &t[conf_claimers[k]];
            if (c->size == 0 ||
                (unsigned long long)fee * c->size <= (unsigned long long)c->fee * vsize){
                _mpol_last_reason = "insufficient fee";   /* Core's own reason string */
                return 0;
            }
        }
        /* rules 3+4 (Core PaysForRBF): pay all replaced fees, and the
         * increment must cover the replacement's own vsize at the
         * incremental relay rate ("insufficient fee"). */
        if (fee < removed_fees){ _mpol_last_reason = "insufficient fee"; return 0; }
        { uint64_t need = pol->incremental_fee * vsize / 1000;
          if (need == 0) need = 1;
          if (fee - removed_fees < need){ _mpol_last_reason = "insufficient fee"; return 0; } }
    }

    /* --- ancestor / descendant limits (vsize budgets) ---------------------- */
    uint32_t cap = *(uint32_t*)((char*)st+4);
    mpol_node* t = mpol_nodes_base(st);
    uint32_t ntx_now = *(uint32_t*)((char*)st+16);
    if (ntx_now >= cap){ _mpol_last_reason = "mempool full"; return 0; }

    uint32_t* mark = (uint32_t*)((char*)st + MPOL_HDR);
    uint32_t stamp = *(uint32_t*)((char*)st+20) + 1;
    if (stamp == 0xFFFFFFFFu) stamp = 1;
    *(uint32_t*)((char*)st+20) = stamp;

    int par_idx[MPOL_MAX_IN]; int n_par = 0;
    /* ---- MEM-1 (audit 2026-09-03): Core's finality prechecks -------------
     * PreChecks rejects !CheckFinalTxAtTip ("non-final") and
     * !CheckSequenceLocks ("non-BIP68-final"), evaluated against the NEXT
     * block's height and the tip's median time past (BIP113). Placed here,
     * before the transaction is linked into the graph and before any
     * eviction can run, so a refusal costs nothing and mutates nothing.
     *
     * The arithmetic is daemon/seqlocks.h -- the same functions the
     * block-connect path uses (VAL-4) -- so admission and connection cannot
     * disagree. A mempool that admits what the block path rejects fills the
     * pool with transactions that can never confirm and then hands them to
     * getblocktemplate. */
    if (g_seq_next_height >= 0){
        int any_nonfinal = 0;
        for (int i = 0; i < n_in; i++)
            if (seq[i] != VAL_SEQUENCE_FINAL){ any_nonfinal = 1; break; }

        if (!val_is_final((unsigned long)meta.locktime, any_nonfinal,
                          g_seq_next_height, g_seq_tip_mtp)){
            _mpol_last_reason = "non-final";
            return 0;
        }

        /* BIP68 needs each input's prevout CREATION HEIGHT, which this layer
         * does not resolve itself. When the embedder supplies no height
         * resolver the rule is skipped rather than guessed -- guessing would
         * mean inventing a confirmation depth, which is the one number the
         * rule turns on. */
        if (g_seq_csv_active && g_seq_height_fn && meta.version >= 2){
            long long min_height = -1, min_time = -1;
            int evaluable = 1;
            for (int i = 0; i < n_in; i++){
                if (seq[i] & VAL_SEQ_DISABLE) continue;
                unsigned long long coin_h = 0;
                if (g_seq_height_fn(prev[i], idx[i], &coin_h) != 1){
                    /* an unconfirmed (in-mempool) parent has no height: Core
                     * uses the NEXT block's height for those, since that is
                     * where the parent would confirm. */
                    coin_h = (unsigned long long)g_seq_next_height;
                }
                if (seq[i] & VAL_SEQ_TYPE){
                    /* time-based locks need the MTP at the coin's height,
                     * which this layer cannot read. Refuse to evaluate
                     * rather than approximate it with the tip's. */
                    evaluable = 0; break;
                }
                long long cand = val_seq_min_height((unsigned long)coin_h, seq[i]);
                if (cand > min_height) min_height = cand;
            }
            if (evaluable &&
                !val_seq_locks_ok(min_height, min_time,
                                  g_seq_next_height, g_seq_tip_mtp)){
                _mpol_last_reason = "non-BIP68-final";
                return 0;
            }
        }
    }

    /* ---- MEM-3: more in-pool parents than can exist in a legal cluster ----
     *
     * Now that the cap is the REAL limit -- v31 allows a 64-transaction
     * cluster, so at most 63 distinct direct parents -- overflowing it means
     * the transaction could not form a legal cluster anyway, and Core would
     * refuse it at the cluster-count check. Refusing here is therefore not a
     * relay divergence, which is what made the same refusal wrong while the
     * cap was 24 (that rejected shapes Core accepts, and failed this
     * project's own "cluster of exactly 64 accepted" case).
     *
     * The point is that the list is never silently SHORTENED again: parent[]
     * is the only record of the graph, so a dropped link made a child
     * invisible to every descendant walk, and the child survived its
     * parent's eviction spending an output that no longer existed. */
    { int truncated = 0;
      n_par = mpol_collect_parents(st, prev, n_in, par_idx, &truncated);
      if (truncated){
          /* Core's string, and the accurate one: more than 63 DISTINCT direct
           * in-pool parents means the cluster containing this transaction has
           * at least 65 members, so the cluster-count check below is the rule
           * it actually violates -- this refusal simply reaches the same
           * verdict earlier, before a parent list that cannot be recorded in
           * full is built. Reporting "too-long-mempool-chain" here (as the
           * first draft did) changed the reason on the existing
           * "a child joining 64 independent parents is refused" case, whose
           * point is precisely that the CLUSTER limit is what catches it. */
          _mpol_last_reason = "too-large-cluster";
          return 0;
      }
      /* MEM-3 + MEM-6: if this transaction will need an overflow block,
       * establish NOW that one is available. The reservation itself happens
       * at the store site, which is AFTER the RBF evictions in step 1a --
       * failing there would destroy the transactions this one conflicts
       * with and then refuse it, which is precisely the atomicity defect
       * MEM-6 fixed. Between this check and the reservation the only pool
       * traffic is remove_node RELEASING blocks, so availability can improve
       * but never worsen: the check is sound, not merely optimistic. */
      if ((uint32_t)n_par > MPOL_INLINE_PARENTS &&
          *(uint32_t*)((char*)st+88) == MPOL_OVF_NONE){
          _mpol_last_reason = "too-long-mempool-chain";
          return 0;
      } }

    uint32_t anc_list[MPOL_MAX_IN + 32]; uint32_t n_anc = 0;
    uint32_t stack[MPOL_MAX_IN + 16]; int sp = 0;
    for (int k=0;k<n_par;k++){
        uint32_t p = (uint32_t)par_idx[k];
        if (mark[p] != stamp){ mark[p] = stamp; stack[sp++] = p; }
    }
    while (sp > 0){
        uint32_t cur = stack[--sp];
        anc_list[n_anc++] = cur;
        mpol_node* cn = &t[cur];
        for (uint32_t k=0; k<cn->n_parents; k++){
            uint32_t gp = mpol_par_at(st, cn, k);
            if (gp != 0xFFFFFFFFu && mark[gp] != stamp){
                mark[gp] = stamp; stack[sp++] = gp;
            }
        }
    }
    uint64_t anc_cnt = 1 + (uint64_t)n_anc;
    uint64_t anc_bytes = vsize;
    for (uint32_t k=0;k<n_anc;k++) anc_bytes += t[anc_list[k]].size;

    /* Core v31 accepts by CLUSTER: the connected component this tx joins may
     * not exceed 64 transactions / 101 kvB (too-large-cluster). Our
     * ancestor/descendant limits miss wide shapes (64 independent parents,
     * one child = cluster 65 with anc_cnt 64). BFS over the union of the
     * parents' clusters, bounded: the walk stops the moment it exceeds the
     * limits. Children are found by scanning parent links, the same pattern
     * collect_descendant_txids uses; the visited set caps at 65 nodes.
     * An RBF replacement is measured against the cluster AS IT WILL BE:
     * members of the eviction set (the conflicts and their descendants,
     * removed if this tx is accepted) are invisible to the walk -- Core's
     * cluster check likewise runs on the post-replacement diagram. Before
     * this, a replacement joining a full cluster it was itself thinning
     * was refused for the size it was about to free. */
    if (n_par > 0){
        enum { CLUSTER_LIMIT = 64, CLUSTER_SIZE_LIMIT = 101000 };
        mpol_node* t = mpol_nodes_base(st);
        uint32_t nn = *(uint32_t*)((char*)st+16);
        uint32_t seen[CLUSTER_LIMIT + 1]; int nseen = 0;
        uint32_t bfs[CLUSTER_LIMIT + 1]; int sp = 0;
        uint64_t cl_bytes = 0; int too_big = 0;
        #define MPOL_CL_EVICTED(ix) ({ int _ev = 0; \
            for (int _e = 0; _e < n_evict; _e++) { \
                if (!memcmp(t[ix].txid, evict_set[_e], 32)){ _ev = 1; break; } } _ev; })
        /* seed from EVERY in-pool parent, not the MPOL_MAX_PARENTS(24)-capped
         * par_idx: a 64-input child is exactly the wide shape this exists
         * to refuse */
        for (int i = 0; i < n_in && !too_big; i++){
            int p = find_node(st, prev[i]);
            if (p < 0) continue;
            if (MPOL_CL_EVICTED((uint32_t)p)) continue;  /* cannot happen (a tx may not spend what it evicts) -- belt */
            uint32_t pi = (uint32_t)p; int dup = 0;
            for (int q = 0; q < nseen; q++) if (seen[q] == pi){ dup = 1; break; }
            if (dup) continue;
            if (nseen >= CLUSTER_LIMIT){ too_big = 1; break; }
            seen[nseen++] = pi; bfs[sp++] = pi; cl_bytes += t[pi].size;
        }
        while (sp > 0 && !too_big){
            uint32_t cur = bfs[--sp];
            for (uint32_t i = 0; i < nn && !too_big; i++){
                int linked = 0;
                for (uint32_t k = 0; k < t[i].n_parents; k++) if (mpol_par_at(st, &t[i], k) == cur){ linked = 1; break; }
                if (!linked) for (uint32_t k = 0; k < t[cur].n_parents; k++) if (mpol_par_at(st, &t[cur], k) == i){ linked = 1; break; }
                if (!linked) continue;
                if (MPOL_CL_EVICTED(i)) continue;        /* leaves the pool if this tx is accepted */
                int dup = 0;
                for (int q = 0; q < nseen; q++) if (seen[q] == i){ dup = 1; break; }
                if (dup) continue;
                if (nseen >= CLUSTER_LIMIT){ too_big = 1; break; }
                seen[nseen++] = (uint32_t)i; bfs[sp++] = (uint32_t)i; cl_bytes += t[i].size;
            }
        }
        if (too_big || (uint64_t)nseen + 1 > CLUSTER_LIMIT || cl_bytes + vsize > CLUSTER_SIZE_LIMIT){
            _mpol_last_reason = "too-large-cluster"; return 0;
        }
        #undef MPOL_CL_EVICTED
    }
    if (anc_cnt > pol->max_anc){ _mpol_last_reason = "too-long-mempool-chain"; return 0; }
    if (anc_bytes > pol->max_anc_bytes){ _mpol_last_reason = "too-long-mempool-chain"; return 0; }
    for (uint32_t k=0;k<n_anc;k++){
        mpol_node* a = &t[anc_list[k]];
        if ((uint64_t)a->desc_cnt + 1 > pol->max_desc){
            _mpol_last_reason = "too-long-mempool-chain"; return 0; }
        if ((uint64_t)a->desc_bytes + vsize > pol->max_desc_bytes){
            _mpol_last_reason = "too-long-mempool-chain"; return 0; }
    }

    /* --- BIP431 TRUC topology (Core SingleTRUCChecks) ----------------------
     * Runs for EVERY transaction, not only v3 ones: half of these rules are
     * about what a non-TRUC transaction may not spend. Skipped wholesale
     * under -acceptnonstdtxn, like the rest of policy.
     *
     * Core reports every one of these as the single reject reason
     * "TRUC-violation" and carries the specific rule in a debug string, so
     * that is the reason surfaced here too -- a caller diffing reject-reason
     * against Core must see the same token.
     *
     * These are measured against the SIGOP-ADJUSTED vsize, as Core measures
     * them: vsize carries the adjustment from the top of this function, so a
     * sigop-dense transaction meets the TRUC size caps on the same figure Core
     * uses. (Until 2026-09-03 only the fee floors were adjusted and these caps
     * saw the plain BIP141 vsize, which was marginally more permissive than
     * Core for exactly those transactions.) */
    if (!pol->accept_nonstd){
        const int is_truc = (meta.version == TRUC_VERSION);

        /* A parent may be in the MEMPOOL or, during package validation, be
         * another member of the same package -- Core counts both, and only
         * counting mempool parents makes every one of these rules a no-op
         * inside a package. */
        int pkg_par[MPOL_MAX_IN]; int n_pkg_par = 0;
        for (int i=0;i<n_in && g_pkg_n;i++){
            if (find_node(st, prev[i]) >= 0) continue;      /* counted as a mempool parent */
            int m = mpol_pkg_find(prev[i]);
            if (m < 0) continue;
            int dup = 0;
            for (int k=0;k<n_pkg_par;k++) if (pkg_par[k]==m){ dup = 1; break; }
            if (!dup && n_pkg_par < MPOL_MAX_IN) pkg_par[n_pkg_par++] = m;
        }
        /* the version of an in-package parent, read from its own bytes */
        #define PKG_VER(mi) ((uint32_t)(g_pkg_tx[mi][0] | (g_pkg_tx[mi][1]<<8) | \
                             (g_pkg_tx[mi][2]<<16) | ((uint32_t)g_pkg_tx[mi][3]<<24)))

        /* inheritance, both directions, from both sources */
        for (int k=0;k<n_par;k++)
            if (is_truc != (t[par_idx[k]].version == TRUC_VERSION)){
                _mpol_last_reason = "TRUC-violation"; return 0; }
        for (int k=0;k<n_pkg_par;k++)
            if (is_truc != (PKG_VER(pkg_par[k]) == TRUC_VERSION)){
                _mpol_last_reason = "TRUC-violation"; return 0; }

        if (is_truc){
            if (vsize > TRUC_MAX_VSIZE){ _mpol_last_reason = "TRUC-violation"; return 0; }
            if (n_par + n_pkg_par + 1 > TRUC_ANCESTOR_LIMIT){
                _mpol_last_reason = "TRUC-violation"; return 0; }
            const int has_parent = (n_par + n_pkg_par) > 0;
            if (has_parent){
                if (vsize > TRUC_CHILD_MAX_VSIZE){
                    _mpol_last_reason = "TRUC-violation"; return 0; }
            }
            if (n_par > 0){
                const mpol_node* pn = &t[par_idx[0]];
                /* anc_cnt includes the parent itself, so >1 means the parent
                 * already has an ancestor of its own */
                if ((uint64_t)pn->anc_cnt + n_pkg_par + 1 > TRUC_ANCESTOR_LIMIT){
                    _mpol_last_reason = "TRUC-violation"; return 0; }
                /* the parent gets exactly one child. An existing child that
                 * THIS transaction is replacing does not count against the
                 * limit -- otherwise a TRUC child could never be fee-bumped,
                 * which is the entire purpose of the topology. */
                int child_replaced = 0;
                for (int e=0; e<n_evict && !child_replaced; e++){
                    int ei = find_node(st, evict_set[e]);
                    if (ei < 0) continue;
                    for (uint32_t q=0; q<t[ei].n_parents; q++)
                        if (mpol_par_at(st, &t[ei], q) == (uint32_t)par_idx[0]){ child_replaced = 1; break; }
                }
                /* desc_cnt includes the parent itself */
                if ((uint64_t)pn->desc_cnt + 1 > TRUC_DESCENDANT_LIMIT && !child_replaced){
                    /* SIBLING EVICTION -- the second return value of Core's
                     * SingleTRUCChecks, applied by MemPoolAccept.
                     *
                     * The parent already has a child, and this transaction
                     * does not double-spend it, so ordinary RBF cannot reach
                     * it: nothing conflicts. Core still offers the swap, and
                     * for a good reason. A TRUC parent's whole promise is that
                     * its fee can be raised through its one child; if that
                     * child sits at a low feerate, without sibling eviction
                     * the only party who can ever rescue the parent is
                     * whoever owns that child. That is the pin the topology
                     * was meant to abolish.
                     *
                     * Offered ONLY in the narrow shape Core insists on,
                     * because anything wider needs a rule for CHOOSING which
                     * descendant dies and Core deliberately has none: the
                     * parent must have exactly itself and one child, and that
                     * child exactly itself and the parent. Reorgs can leave
                     * wider shapes behind and those are still refused. Package
                     * contexts are excluded as well -- Core allows this only
                     * for a single transaction (m_allow_sibling_eviction), and
                     * the in-package sibling case is caught by the walk below. */
                    int evicted_sibling = 0;
                    if (g_pkg_n <= 1 && pn->desc_cnt == 2){
                        static unsigned char sibs[MPOL_PKG_MAX][32];
                        int nsib = collect_descendant_txids(st, par_idx[0], sibs, MPOL_PKG_MAX);
                        int si = (nsib == 1) ? find_node(st, sibs[0]) : -1;
                        if (si >= 0 && t[si].anc_cnt == 2){
                            /* The sibling joins the to-be-replaced set and the
                             * ORDINARY replacement arithmetic decides, which is
                             * exactly what Core does. Note what is NOT asked of
                             * it: BIP125 signalling. Core skips that check here
                             * and says why -- a TRUC transaction can only have a
                             * non-signalling descendant through a reorg. */
                            if (n_evict >= MPOL_MAX_REPLACEMENTS){
                                _mpol_last_reason = "too many potential replacements"; return 0; }
                            uint64_t total_removed = removed_fees + t[si].fee;
                            uint64_t need = pol->incremental_fee * vsize / 1000;
                            if (need == 0) need = 1;
                            if (fee < total_removed){
                                _mpol_last_reason = "insufficient fee"; return 0; }
                            if (fee - total_removed < need){
                                _mpol_last_reason = "insufficient fee"; return 0; }
                            memcpy(evict_set[n_evict++], t[si].txid, 32);
                            removed_fees = total_removed;
                            evicted_sibling = 1;
                        }
                    }
                    if (!evicted_sibling){
                        _mpol_last_reason = "TRUC-violation"; return 0; }
                }
            }
            /* Within a package, the sibling and grandchild cases have no
             * mempool entries to read: they have to be found by walking the
             * other members' inputs. */
            if (has_parent && g_pkg_n > 1){
                const unsigned char* ptxid = n_par > 0 ? t[par_idx[0]].txid
                                                       : g_pkg_txid[pkg_par[0]];
                for (int m = 0; m < g_pkg_n; m++){
                    if (!memcmp(g_pkg_txid[m], txid, 32)) continue;      /* ourselves */
                    mpol_txmeta om;
                    static unsigned char oprev[MPOL_MAX_IN][32];
                    static uint32_t oidx[MPOL_MAX_IN], oseq[MPOL_MAX_IN];
                    int on = parse_tx(g_pkg_tx[m], g_pkg_len[m], oprev, oidx, oseq, &om);
                    for (int q = 0; q < on; q++){
                        /* a second child of our parent: descendant limit */
                        if (!memcmp(oprev[q], ptxid, 32)){
                            _mpol_last_reason = "TRUC-violation"; return 0; }
                        /* a child of OURS, while we already have a parent:
                         * that would be three generations */
                        if (!memcmp(oprev[q], txid, 32)){
                            _mpol_last_reason = "TRUC-violation"; return 0; }
                    }
                }
            }
        }
        #undef PKG_VER
    }

    /* ================= commit ============================================ */
    if (!commit) return 1;

    /* ---- MEM-4 (audit 2026-09-03): refuse rather than register nothing ---
     *
     * The claims and outreg tables have one slot per NODE but hold one entry
     * per INPUT and per OUTPUT. With the pool sized at ~1M nodes the claims
     * table fills once the pool holds ~1M inputs, which is roughly 400-500K
     * ordinary transactions -- well inside a 300 MB raw pool, since Core's
     * 300 MB is DynamicMemoryUsage (~3x serialized) and this pool holds
     * roughly 3x Core's count.
     *
     * Both insertion loops used to test `if (n < cap)` and, when full,
     * silently do nothing. The consequences differ and only one is
     * conservative:
     *   * claims full -> the transaction's inputs are never registered, so
     *     find_claim misses them. A LATER transaction spending the same
     *     output finds no conflict and is accepted: two conflicting
     *     transactions in the pool, both relayed, both eligible for the
     *     block template, which does not check conflicts. An invalid block.
     *   * outreg full -> children are rejected as missing-inputs, which is
     *     merely wrong rather than dangerous, but silently breaks CPFP.
     *
     * Checked at the COMMIT BOUNDARY: after every policy rule has had its
     * say, so a transaction that is also non-standard or TRUC-invalid still
     * reports THAT reason rather than "mempool full" (an earlier placement
     * did exactly that and broke test_truc_policy's "an oversized v3 tx is
     * refused"), and before anything is stored or linked, so a refusal costs
     * nothing -- the same placement MEM-5 needed. "mempool full" is
     * Core's reason for an admission that cannot be housed, and it is
     * honest: the pool genuinely has no room left to register this
     * transaction safely.
     *
     * This does not RESIZE the tables, which is the audit's other half and a
     * capacity-tuning change to a MAP_SHARED region. It closes the
     * correctness hole: the node can no longer accept a transaction it has
     * not registered. */
    {
        uint32_t cap_    = *(uint32_t*)((char*)st+4);
        uint32_t n_out_r = *(uint32_t*)((char*)st+8);   /* outreg entries used */
        uint32_t n_clm   = *(uint32_t*)((char*)st+12);  /* claims  entries used */
        if ((uint64_t)n_clm + (uint64_t)n_in > (uint64_t)cap_ ||
            (uint64_t)n_out_r + (uint64_t)meta.n_out > (uint64_t)cap_){
            _mpol_last_reason = "mempool full";
            return 0;
        }
    }


    /* ---- MEM-6 (audit 2026-09-03): decide "mempool full" BEFORE evicting ----
     *
     * This file's header claims "Accept is atomic: on any policy failure both
     * the structural mempool and this state are untouched." Step 1a broke
     * that claim: it removed every conflict (and its descendants) and
     * recorded them in _mpol_replaced, and only THEN did step 1b call
     * mpool_put, which can return 2 on a byte-full pool and end in
     * "mempool full" with nothing stored. The replaced transactions were
     * gone, the replacement was not in, and submitpackage still reported
     * `replaced-transactions` for an accept that never happened. Because RBF
     * needs signing authority over the original's inputs, the practical
     * victim is a two-party construction -- an LN counterparty's commitment
     * dropped from this node while Core nodes keep it.
     *
     * The check is deliberately CONSERVATIVE: it can only turn an accept that
     * was already doomed into an earlier refusal, never refuse something that
     * would have succeeded.
     *
     *  - It runs only when the incoming bytes do not fit even after crediting
     *    every byte the eviction set would free. If they do fit, mpool_put
     *    cannot return 2 and there is nothing to pre-empt.
     *  - It compacts first, so MEM-13's dead bytes are not mistaken for a
     *    full pool.
     *  - It refuses only if the worst chunk is NOT itself in the eviction
     *    set. If the worst chunk is one of the conflicts, the loop in 1b
     *    would evict it as part of this replacement and could then succeed,
     *    so refusing here would be a new false reject. */
    if (n_evict > 0){
        /* bitcoin_mempool.asm's documented layout: +24 blob_cap, +32 fill.
         * daemon/reorg.c reads the same fields the same way. */
        unsigned char* mm = (unsigned char*)mp;
        unsigned long long blob_cap = 0, fill = 0;
        memcpy(&blob_cap, mm + 24, 8);
        memcpy(&fill,     mm + 32, 8);
        unsigned long long freed = 0;
        for (int e = 0; e < n_evict; e++){
            int ei2 = find_node(st, evict_set[e]);
            if (ei2 >= 0) freed += mpol_nodes_base(st)[ei2].raw_len;
        }
        if (fill + txlen > blob_cap + freed){
            mpool_compact(mp);
            memcpy(&fill, mm + 32, 8);
        }
        if (fill + txlen > blob_cap + freed){
            /* The chunk 1b's loop would score AFTER this replacement's own
             * evictions -- so the eviction set is excluded. Scoring without
             * that exclusion would usually name one of the conflicts itself
             * (a transaction being replaced is typically the cheapest thing
             * in the pool), and comparing against something we are about to
             * delete answers the wrong question. */
            mpol_chunk wc;
            if (!worst_chunk_excl(st, &wc, (const unsigned char (*)[32])evict_set, n_evict)
                || wc.n == 0){
                /* Nothing left to evict once the conflicts are gone, and the
                 * replacement still does not fit. */
                _mpol_last_reason = "mempool full"; return 0;
            }
            uint64_t ws2 = wc.size ? wc.size : 1;
            if ((unsigned __int128)fee * ws2 <= (unsigned __int128)wc.fee * vsize){
                /* The same verdict 1b would reach, reached WITHOUT having
                 * destroyed the transactions this one conflicts with. */
                floor_bump(st, wc.fee * 1000 / ws2 + pol->incremental_fee);
                _mpol_last_reason = "mempool full";
                return 0;
            }
        }
    }

    /* 1a. RBF eviction (packages: conflicts + descendants, snapshotted) */
    for (int e=0;e<n_evict;e++){
        int ci = find_node(st, evict_set[e]);
        if (ci >= 0) remove_node(st, mp, ci);
        /* recorded whether or not the node was still present: it is in the
         * eviction set because this transaction conflicts with it */
        if (_mpol_replaced_n < (int)(sizeof _mpol_replaced / 32))
            memcpy(_mpol_replaced[_mpol_replaced_n++], evict_set[e], 32);
    }
    /* the eviction may have invalidated the ancestor INDEX list; parents are
     * re-found below by txid via prev[] when linking, so recompute par_idx. */
    if (n_evict){
        t = mpol_nodes_base(st);
        int n_par_before = n_par;
        n_par = mpol_collect_parents(st, prev, n_in, par_idx, 0);
        /* MEM-5 (audit 2026-09-03): the eviction must not have removed one of
         * THIS transaction's parents. worst_chunk is scored over the existing
         * graph, which does not yet contain the incoming transaction, so a
         * high-feerate child arriving at a byte-full pool could evict the very
         * parent it spends: the child was then stored with n_parents = 0, its
         * fee computed from that parent's output value, spending an output
         * present in neither the UTXO set nor the mempool. GBT includes it
         * (every registered ancestor is "present") and peers orphan it.
         *
         * Core adds the transaction to the pool FIRST and trims with it
         * included, so {parent, child} is scored as one chunk, then returns
         * "mempool full" if the transaction itself was trimmed. Rejecting here
         * reaches the same outcome from the other direction, without
         * restructuring the accept path around a speculative insert. */
        if (n_par < n_par_before){
            _mpol_last_reason = "mempool full";
            return 0;
        }
        /* re-collect ancestors for the desc-aggregate bump below */
        stamp = *(uint32_t*)((char*)st+20) + 1;
        if (stamp == 0xFFFFFFFFu) stamp = 1;
        *(uint32_t*)((char*)st+20) = stamp;
        n_anc = 0; sp = 0;
        for (int k=0;k<n_par;k++){
            uint32_t p = (uint32_t)par_idx[k];
            if (mark[p] != stamp){ mark[p] = stamp; stack[sp++] = p; }
        }
        while (sp > 0){
            uint32_t cur = stack[--sp];
            anc_list[n_anc++] = cur;
            for (uint32_t k=0; k<t[cur].n_parents; k++){
                uint32_t gp = mpol_par_at(st, &t[cur], k);
                if (gp != 0xFFFFFFFFu && mark[gp] != stamp){
                    mark[gp] = stamp; stack[sp++] = gp;
                }
            }
        }
    }

    /* 1b. store; on a full pool, TrimToSize by descendant package (Core):
     * evict argmin of max(own, package) feerate WITH its descendants; floor
     * = removed package feerate + incrementalrelayfee. If the incoming tx
     * itself would be the worst, reject it as "mempool full". */
    { long put = mpool_put(mp, txid, tx, txlen);
      if (put == 2){
          /* ---- MEM-13 (audit 2026-09-03): reclaim dead bytes BEFORE scoring ----
           *
           * mpool_del leaves the removed transaction's bytes in the blob and
           * does not move `fill`; only daemon/mempool_compact.c reclaims them,
           * and it was called ONLY from inside the eviction loop below --
           * after an eviction had already happened. Removals that are not
           * evictions (remove_confirmed at every block connect, expiry, RBF)
           * therefore left the blob permanently "full" of bytes nothing
           * referenced.
           *
           * The consequence is a spurious eviction plus a floor bump: once
           * fill has ever reached blob_cap, blocks can confirm away most of
           * the pool and `put` still returns 2, so the next accept scored the
           * worst chunk, evicted it (or refused the newcomer) and called
           * floor_bump -- raising mempoolminfee for 12+ hours -- while the
           * space it needed was already free.
           *
           * Compacting on the FIRST 2 and retrying costs one compaction on a
           * path that was about to do one anyway, and the eviction loop below
           * is entered only if the pool is genuinely full. */
          mpool_compact(mp);
          put = mpool_put(mp, txid, tx, txlen);
      }
      while (put == 2){
          /* Core v31: evict the worst CHUNK of all clusters, not the worst leaf */
          mpol_chunk wc;
          if (!worst_chunk(st, &wc) || wc.n == 0){ _mpol_last_reason = "mempool full"; return 0; }
          uint64_t wf = wc.fee, ws = wc.size ? wc.size : 1;
          /* incoming loses if its feerate <= the worst chunk's feerate */
          if ((unsigned __int128)fee * ws <= (unsigned __int128)wf * vsize){
              floor_bump(st, wf * 1000 / ws + pol->incremental_fee);
              _mpol_last_reason = "mempool full";
              return 0;
          }
          unsigned char wt[CHUNK_MAX_CLUSTER][32]; int wn = wc.n;
          for (int q = 0; q < wn; q++) memcpy(wt[q], mpol_nodes_base(st)[wc.idx[q]].txid, 32);
          floor_bump(st, wf * 1000 / ws + pol->incremental_fee);
          for (int q = 0; q < wn; q++) mpool_policy_remove_package(st, mp, wt[q]);   /* descendants live in the chunk too; a gone txid is a no-op */
          /* MEM-5 (audit 2026-09-03): the chunk just evicted must not have
           * contained one of THIS transaction's parents -- and the check has
           * to happen BEFORE mpool_put, or the transaction ends up stored in
           * the structural pool while the policy layer refuses it, which is
           * worse than the bug.
           *
           * worst_chunk is scored over the EXISTING graph, which does not yet
           * contain the incoming transaction. So a high-feerate child
           * arriving at a byte-full pool can evict the very parent it spends:
           * par_idx is then recomputed from what is left, and the child is
           * stored with n_parents = 0, its fee computed from the parent's
           * output value, spending an output present in neither the UTXO set
           * nor the mempool. getblocktemplate includes it (every REGISTERED
           * ancestor is present) and peers orphan it.
           *
           * Core adds the transaction FIRST and trims with it included, so
           * {parent, child} is scored as one chunk, then returns "mempool
           * full" if the transaction was itself trimmed. Rejecting reaches
           * the same end state without restructuring the accept path around
           * a speculative insert. The parent stays evicted either way, which
           * is what Core does too. */
          { int n_par_before = n_par;
            n_par = mpol_collect_parents(st, prev, n_in, par_idx, 0);
            if (n_par < n_par_before){
                mpool_compact(mp);
                _mpol_last_reason = "mempool full";
                return 0;
            } }
          mpool_compact(mp);
          put = mpool_put(mp, txid, tx, txlen);
      }
      if (put != 1){ _mpol_last_reason = "mempool store failed"; return 0; }
      *(uint64_t*)((char*)st+64) += txlen;   /* pool raw-byte accounting */
      /* trimming may have shifted node indices: recompute parent/ancestor
       * lists one more time before linking */
      t = mpol_nodes_base(st);
      n_par = mpol_collect_parents(st, prev, n_in, par_idx, 0);
      stamp = *(uint32_t*)((char*)st+20) + 1;
      if (stamp == 0xFFFFFFFFu) stamp = 1;
      *(uint32_t*)((char*)st+20) = stamp;
      n_anc = 0; sp = 0;
      for (int k=0;k<n_par;k++){
          uint32_t p = (uint32_t)par_idx[k];
          if (mark[p] != stamp){ mark[p] = stamp; stack[sp++] = p; }
      }
      while (sp > 0){
          uint32_t cur = stack[--sp];
          anc_list[n_anc++] = cur;
          for (uint32_t k=0; k<t[cur].n_parents; k++){
              uint32_t gp = mpol_par_at(st, &t[cur], k);
              if (gp != 0xFFFFFFFFu && mark[gp] != stamp){
                  mark[gp] = stamp; stack[sp++] = gp;
              }
          }
      }
    }

    /* 2. outreg entries for outputs */
    {
        const unsigned char* p = meta.out_start;
        mpol_out* o = mpol_outreg_base(st);
        uint32_t cap_ = *(uint32_t*)((char*)st+4);
        int ok;
        for (unsigned long i=0;i<meta.n_out;i++){
            uint64_t v=0; for(int k=0;k<8;k++) v|=((uint64_t)p[k])<<(8*k);
            p += 8;
            uint64_t sl = rd_varint(&p, tx+txlen, &ok);
            p += sl;
            uint32_t no_idx = *(uint32_t*)((char*)st+8);
            if (no_idx < cap_){
                memcpy(o[no_idx].txid, txid, 32);
                o[no_idx].index = (uint32_t)i;
                o[no_idx].value = v;
                (*((uint32_t*)((char*)st+8)))++;
                mpol_out_idx_link(st, no_idx);          /* MEM-12 */
            }
        }
    }

    /* 3. claims for each input */
    {
        mpol_claim* c = mpol_claims_base(st);
        uint32_t cap_ = *(uint32_t*)((char*)st+4);
        uint32_t myidx = *(uint32_t*)((char*)st+16);
        for (int i=0;i<n_in;i++){
            uint32_t nc = *(uint32_t*)((char*)st+12);
            if (nc < cap_){
                memcpy(c[nc].prev, prev[i], 32);
                c[nc].index = idx[i];
                c[nc].claimer = myidx;
                (*((uint32_t*)((char*)st+12)))++;
                mpol_clm_idx_link(st, nc);              /* MEM-12 */
            }
        }
    }

    /* 4. tx node */
    {
        mpol_node* t2 = mpol_nodes_base(st);
        uint32_t myidx = *(uint32_t*)((char*)st+16);
        memcpy(t2[myidx].txid, txid, 32);
        t2[myidx].size = vsize;
        t2[myidx].raw_len = txlen;
        t2[myidx].fee = fee;
        t2[myidx].desc_fee = fee;
        t2[myidx].anc_cnt = (uint32_t)anc_cnt;
        t2[myidx].anc_bytes = (uint32_t)anc_bytes;
        t2[myidx].desc_cnt = 1;
        t2[myidx].desc_bytes = (uint32_t)vsize;
        t2[myidx].version = meta.version;
        /* MEM-3: reserve an overflow block BEFORE recording anything. The
         * slot was memset to zero by state_init, so povf must be set to
         * MPOL_OVF_NONE explicitly -- 0 is a valid block index. On
         * exhaustion the transaction is refused rather than stored with a
         * short parent list, which is the whole point of the finding. */
        t2[myidx].povf = MPOL_OVF_NONE;
        t2[myidx].n_parents = 0;
        if (!mpol_par_reserve(st, &t2[myidx], (uint32_t)n_par)){
            /* Distinct from the cluster refusal above: this is a RESOURCE
             * limit of this implementation, not a rule the transaction
             * breaks. The pool is sized so that reaching it means an
             * extraordinary number of many-parent transactions are resident
             * at once. Refusing is still the right answer -- the alternative
             * is the silent short parent list this whole finding is about --
             * but the reason should not claim the transaction is malformed. */
            _mpol_last_reason = "too-long-mempool-chain";
            return 0;
        }
        t2[myidx].n_parents = (uint32_t)n_par;
        for (uint32_t k=0;k<MPOL_INLINE_PARENTS;k++)
            t2[myidx].parent[k] = 0xFFFFFFFFu;
        for (int k=0;k<n_par && k<MPOL_MAX_PARENTS;k++)
            mpol_par_set(st, &t2[myidx], (uint32_t)k, (uint32_t)par_idx[k]);
        (*((uint32_t*)((char*)st+16)))++;
        mpol_node_idx_link(st, myidx);                  /* MEM-12: after the
                                                         * count, so the slot
                                                         * is live when the
                                                         * chain names it */
        for (uint32_t k=0;k<n_anc;k++){
            t2[anc_list[k]].desc_cnt++;
            t2[anc_list[k]].desc_bytes += (uint32_t)vsize;
            t2[anc_list[k]].desc_fee   += fee;
        }
    }

    /* 5. fee estimator EMA (sat/kvB over vsize) */
    {
        uint64_t x = fee * 1000 / (vsize ? vsize : 1);
        uint64_t* est = (uint64_t*)((char*)st+24);
        int64_t delta = (int64_t)x - (int64_t)*est;
        *est = *est + (delta >> 2);
        (*((uint64_t*)((char*)st+32)))++;
        *((uint64_t*)((char*)st+40)) += txlen;
    }

    _mpol_last_reason = "accepted";
    return 1;
}

long mpool_policy_add(mpol_cfg* pol, void* st, void* mp,
                      const unsigned char* tx, unsigned long txlen,
                      const unsigned char txid[32], void* utxo){
    return mpol_add_core(pol, st, mp, tx, txlen, txid, utxo, 1, NULL, NULL);
}

long mpool_policy_test(mpol_cfg* pol, void* st, void* mp,
                       const unsigned char* tx, unsigned long txlen,
                       const unsigned char txid[32], void* utxo,
                       unsigned long long* fee_out,
                       unsigned long long* vsize_out){
    if (fee_out) *fee_out = 0;
    if (vsize_out) *vsize_out = 0;
    return mpol_add_core(pol, st, mp, tx, txlen, txid, utxo, 0, fee_out, vsize_out);
}

/* ========================================================================== */
/* block-connect reconciliation (Core removeForBlock + removeConflicts)       */
/* ========================================================================== */
/* bitcoin_tx.asm / bitcoin_hash.asm -- WEAK so binaries that use only the
 * admission surface (several policy unit tests) still link without
 * bitcoin_tx.o; block_connect refuses at runtime if they are absent. The
 * daemon always links them. */
extern int  tx_parse(unsigned char info[64], const unsigned char* p, unsigned long cap)
    __attribute__((weak));
/* RETURNS int (1 ok / 0 malformed) -- bitcoin_tx.asm's .fail path is
 * `xor eax, eax`. This was declared void here and in daemon/reorg.c, which
 * made that failure structurally invisible to both callers: on a malformed
 * transaction they would have carried on with an unwritten txid buffer. */
extern int tx_txid(unsigned char out[32], const unsigned char* tx, unsigned long len,
                   unsigned char* scratch, unsigned long scratch_cap)
    __attribute__((weak));

/* Every txid a connected block carries is reported here (tx_accept keeps a
 * rolling set of them: a tx that arrives over p2p after it confirmed is
 * "already known", not an orphan -- Core's m_recent_confirmed_transactions). */
static void (*mpol_confirmed_hook)(const unsigned char*) = 0;
void mpool_policy_set_confirmed_hook(void (*fn)(const unsigned char*)){ mpol_confirmed_hook = fn; }
long mpool_policy_block_connect(void* st, void* mp,
                                const unsigned char* block, unsigned long blen){
    if (!tx_parse || !tx_txid) return -1;
    if (!st || *(uint32_t*)st != MPOL_MAGIC || blen < 81) return -1;
    const unsigned char* p = block + 80;
    const unsigned char* end = block + blen;
    int ok;
    uint64_t ntx = rd_varint(&p, end, &ok);
    if (!ok) return -1;
    long removed = 0;
    static unsigned char scratch[1<<20];

    /* ---- MEM-12 (second half): mark everything, then remove it ONCE ----
     *
     * This used to call remove_confirmed (and, on a conflict,
     * mpool_policy_remove_package) per transaction, each O(n), giving O(n*m)
     * for an m-transaction block. Marking first and compacting once is
     * O(n + links) for the whole block.
     *
     * If the scratch cannot be sized the old per-transaction path still
     * works, so the fallback is the previous behaviour rather than a
     * failure -- a block connect must not be skippable on an allocation. */
    uint32_t n_nodes = *(uint32_t*)((char*)st+16);
    int batch = (n_nodes > 0) && g_batch_connect && mpol_rm_reserve(n_nodes);
    if (batch) memset(g_rm_mark, 0, n_nodes);

    for (uint64_t j = 0; j < ntx; j++){
        unsigned char info[64];
        if (tx_parse(info, p, (unsigned long)(end - p)) != 1) break;
        uint64_t txlen; memcpy(&txlen, info, 8);
        unsigned char txid[32];
        /* a txid we could not compute must not be used to evict anything */
        if (tx_txid(txid, p, (unsigned long)txlen, scratch, sizeof scratch) != 1) break;
        if (mpol_confirmed_hook) mpol_confirmed_hook(txid);
        if (j > 0){
            /* the confirmed tx leaves alone; txs CONFLICTING with its spends
             * leave with their descendants */
            int self_ci = -1;
            if (batch){
                self_ci = find_node(st, txid);
                if (self_ci >= 0) g_rm_mark[self_ci] = 1;   /* confirmed: alone */
            } else {
                removed += remove_confirmed(st, mp, txid);
            }
            static unsigned char cprev[MPOL_MAX_IN][32];
            static uint32_t cidx[MPOL_MAX_IN], cseq[MPOL_MAX_IN];
            mpol_txmeta cm;
            int cn = parse_tx(p, (unsigned long)txlen, cprev, cidx, cseq, &cm);
            for (int i = 0; i < cn; i++){
                int cl = find_claim(st, cprev[i], cidx[i]);
                if (cl >= 0){
                    if (batch){
                        /* A CONFIRMED transaction claims its own inputs, so
                         * find_claim answers with the transaction itself --
                         * which is not a conflict, it is the very transaction
                         * the block confirmed. The per-transaction path never
                         * saw this because remove_confirmed had already
                         * deleted those claims by the time it looked; the
                         * batch defers every removal, so the claim is still
                         * there and has to be recognised.
                         *
                         * Missing it marked the confirmed transaction as a
                         * conflict ROOT, which took its children with it --
                         * caught by test_mempool_core_parity's
                         * "A's child SURVIVES". Nothing is lost by skipping:
                         * the accept path allows at most one claimer per
                         * outpoint, so if this transaction is the claimer,
                         * no other in-pool transaction is. */
                        if (cl != self_ci)
                            mpol_mark_with_descendants(st, n_nodes, (uint32_t)cl);
                    } else {
                        unsigned char ct[32];
                        memcpy(ct, mpol_nodes_base(st)[cl].txid, 32);
                        removed += mpool_policy_remove_package(st, mp, ct);
                    }
                }
            }
        }
        p += txlen;
    }
    if (batch) removed += mpol_remove_marked(st, mp, n_nodes);
    /* MEM-10: Core resets m_recent_rejects on every new block, because a
     * block can make a previously-invalid transaction valid -- its missing
     * input just confirmed -- and a stale "no" would stop us ever fetching
     * it. Weakly referenced so the tools that link this file without the
     * serve path still build. */
    { extern void serve_rejects_clear(void) __attribute__((weak));
      if (serve_rejects_clear) serve_rejects_clear(); }
    note_block_connected(st);
    return removed;
}

/* ========================================================================== */
/* expiry (Core CTxMemPool::Expire: expired txs leave WITH descendants)       */
/* ========================================================================== */
/* The caller (daemon/mempool_cfg.c) knows arrival times; it hands txids in. */
long mpool_policy_expire_one(void* st, void* mp, const unsigned char txid[32]){
    return mpool_policy_remove_package(st, mp, txid);
}

/* ---- RPC read helpers ----------------------------------------------------- */
long mpool_policy_entry(void* st, const unsigned char txid[32],
                        unsigned long long* fee, unsigned long long* size){
    if (!st || *(uint32_t*)st != MPOL_MAGIC) return 0;
    mpol_node* t = mpol_nodes_base(st);
    uint32_t n = *(uint32_t*)((char*)st+16);
    for (uint32_t i = n; i > 0; i--){
        if (!memcmp(t[i-1].txid, txid, 32)){
            if (fee)  *fee  = t[i-1].fee;
            if (size) *size = t[i-1].size;   /* vsize (Core reports vsize) */
            return 1;
        }
    }
    return 0;
}

#include "mempool_entry.h"

static int mpe_seen(unsigned char set[][32], int n, const unsigned char* txid){
    for (int i=0;i<n;i++) if (!memcmp(set[i],txid,32)) return 1;
    return 0;
}

/* Record a tx's exact BIP141 sigop cost (x4 units) after acceptance.
 * tx_accept.c computes it with the prevout scripts in hand (P2SH redeem +
 * witness portions need them); the GBT template reads it back through
 * mpool_policy_entry_info. Caller holds mp_lock. (mining-polish graft,
 * re-attached at the 2026-08-27 policy-parity merge.) */
/* fee estimation (daemon/fee_estimator.c): Core tracks a tx only when it
 * has no in-mempool parents and was not submitted as part of a package. */
long mpool_policy_n_parents(void* st, const unsigned char txid[32]){
    if (!st || *(uint32_t*)st != MPOL_MAGIC) return -1;
    mpol_node* t = mpol_nodes_base(st);
    uint32_t n = *(uint32_t*)((char*)st+16);
    for (uint32_t i = n; i > 0; i--)
        if (!memcmp(t[i-1].txid, txid, 32)) return (long)t[i-1].n_parents;
    return -1;
}
int mpol_in_package_context(void){ return g_pkg_n > 0; }

long mpool_policy_set_sigops(void* st, const unsigned char txid[32], unsigned int cost){
    if (!st || *(uint32_t*)st != MPOL_MAGIC) return 0;
    mpol_node* t = mpol_nodes_base(st);
    uint32_t n = *(uint32_t*)((char*)st+16);
    for (uint32_t i = n; i > 0; i--)
        if (!memcmp(t[i-1].txid, txid, 32)){ t[i-1].sigop_cost = cost; return 1; }
    return 0;
}

long mpool_policy_entry_info(void* st, const unsigned char txid[32], mp_entry_info* out){
    if (!st || *(uint32_t*)st != MPOL_MAGIC || !out) return 0;
    mpol_node* t = mpol_nodes_base(st);
    uint32_t n = *(uint32_t*)((char*)st+16);
    long self = -1;
    for (uint32_t i = n; i > 0; i--)
        if (!memcmp(t[i-1].txid, txid, 32)){ self = (long)(i-1); break; }
    if (self < 0) return 0;
    memset(out, 0, sizeof *out);
    out->fee  = t[self].fee;
    out->size = t[self].size;
    out->sigop_cost = t[self].sigop_cost;   /* mining-polish graft: template
                                               reads the accept-time cost back */

    for (uint32_t k=0; k<t[self].n_parents && out->n_depends<MPE_MAX_SET; k++){
        uint32_t p = mpol_par_at(st, &t[self], k);
        if (p >= n) continue;
        if (!mpe_seen(out->depends, out->n_depends, t[p].txid))
            memcpy(out->depends[out->n_depends++], t[p].txid, 32);
    }
    for (uint32_t i=0; i<n && out->n_spentby<MPE_MAX_SET; i++){
        if ((long)i == self) continue;
        for (uint32_t k=0; k<t[i].n_parents; k++)
            if (mpol_par_at(st, &t[i], k) == (uint32_t)self){
                if (!mpe_seen(out->spentby, out->n_spentby, t[i].txid))
                    memcpy(out->spentby[out->n_spentby++], t[i].txid, 32);
                break;
            }
    }
    { uint32_t stack[MPE_MAX_SET]; int sp=0;
      memcpy(out->anc[out->n_anc++], t[self].txid, 32); out->anc_fee = t[self].fee;
      out->anc_size = t[self].size;          /* mining-polish graft: package
                                                vsize over the enumerated set */
      stack[sp++] = (uint32_t)self;
      while (sp > 0){
          uint32_t cur = stack[--sp];
          for (uint32_t k=0; k<t[cur].n_parents; k++){
              uint32_t p = mpol_par_at(st, &t[cur], k);
              if (p >= n || mpe_seen(out->anc, out->n_anc, t[p].txid)) continue;
              if (out->n_anc >= MPE_MAX_SET) break;
              memcpy(out->anc[out->n_anc++], t[p].txid, 32);
              out->anc_fee += t[p].fee;
              out->anc_size += t[p].size;
              if (sp < MPE_MAX_SET) stack[sp++] = p;
          }
      } }
    { uint32_t stack[MPE_MAX_SET]; int sp=0;
      memcpy(out->desc[out->n_desc++], t[self].txid, 32); out->desc_fee = t[self].fee;
      stack[sp++] = (uint32_t)self;
      while (sp > 0){
          uint32_t cur = stack[--sp];
          for (uint32_t i=0; i<n; i++){
              if (mpe_seen(out->desc, out->n_desc, t[i].txid)) continue;
              int child = 0;
              for (uint32_t k=0; k<t[i].n_parents; k++)
                  if (mpol_par_at(st, &t[i], k) == cur){ child = 1; break; }
              if (!child) continue;
              if (out->n_desc >= MPE_MAX_SET) break;
              memcpy(out->desc[out->n_desc++], t[i].txid, 32);
              out->desc_fee += t[i].fee;
              if (sp < MPE_MAX_SET) stack[sp++] = i;
          }
      } }
    return 1;
}

/* ==========================================================================
 * PACKAGE policy -- context-free checks (Core policy/packages.cpp).
 *
 * These are the checks that need no chain state: they look only at the
 * transactions handed in together. Everything stateful (in-package parent
 * resolution, package feerate) is layered on top elsewhere; this is the part
 * that can be settled by reading the bytes.
 *
 * Lives here rather than in a new file so it reuses parse_tx -- the same
 * walker the single-transaction policy path uses. A second parser is how a
 * package and a lone transaction start disagreeing about what a transaction
 * IS, which is exactly the class of bug this module exists to avoid.
 *
 * Reason strings are Core's, verbatim, so a caller can diff them.
 * ========================================================================== */
#define PKG_MAX_COUNT   25
#define PKG_MAX_WEIGHT  404000

/* 1 = well formed. 0 = not, with *reason set to Core's exact string.
 * txids_out (optional, n*32 bytes) receives each transaction's txid in wire
 * order and vsize_out (optional, n entries) each transaction's BIP141 vsize,
 * so a caller that needs them does not walk the package a second time. */
int mpol_package_well_formed(const unsigned char* const* txs,
                             const unsigned long* lens, int n,
                             unsigned char* txids_out,
                             unsigned long long* vsize_out, const char** reason){
    static const char* dummy; if (!reason) reason = &dummy;
    *reason = "";
    if (n <= 0){ *reason = "package-not-sorted"; return 0; }   /* nothing sane to say */
    /* tx_txid is weak here (targets link this file without bitcoin_tx.o). No
     * txids means no duplicate or topology check, and answering "well formed"
     * without having run them would be a lie. */
    if (!tx_txid){ *reason = "package-checks-unavailable"; return 0; }
    if (n > PKG_MAX_COUNT){ *reason = "package-too-many-transactions"; return 0; }

    static unsigned char txid[PKG_MAX_COUNT][32];
    static unsigned char prev[MPOL_MAX_IN][32];
    static uint32_t idx[MPOL_MAX_IN], seq[MPOL_MAX_IN];
    /* every input of every tx, kept for the conflict and topology passes */
    static unsigned char all_prev[PKG_MAX_COUNT][MPOL_MAX_IN][32];
    static uint32_t all_idx[PKG_MAX_COUNT][MPOL_MAX_IN];
    static int all_n[PKG_MAX_COUNT];

    unsigned long long total_weight = 0;
    static unsigned char scratch[1 << 20];
    for (int i = 0; i < n; i++){
        mpol_txmeta m;
        int n_in = parse_tx(txs[i], lens[i], prev, idx, seq, &m);
        /* A malformed member is not a package-policy failure -- Core would
         * have rejected it in CheckTransaction long before this. Say what is
         * true rather than inventing a package reason for it. */
        if (n_in <= 0){ *reason = "package-contains-unparseable-transaction"; return 0; }
        total_weight += m.weight;
        all_n[i] = n_in;
        for (int k = 0; k < n_in; k++){ memcpy(all_prev[i][k], prev[k], 32); all_idx[i][k] = idx[k]; }
        if (tx_txid(txid[i], txs[i], lens[i], scratch, sizeof scratch) != 1){
            *reason = "package-contains-unparseable-transaction"; return 0; }
        if (txids_out) memcpy(txids_out + (size_t)i * 32, txid[i], 32);
        /* BIP141 vsize from the SAME walker the fee floors are charged
         * against -- deriving it a second way is how a package and a lone
         * transaction start disagreeing about what a transaction costs. */
        if (vsize_out) vsize_out[i] = m.vsize;
    }

    /* A single transaction reports its own weight violation, not a package
     * one -- Core is explicit that this reads better for the caller. */
    if (n > 1 && total_weight > PKG_MAX_WEIGHT){ *reason = "package-too-large"; return 0; }

    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (!memcmp(txid[i], txid[j], 32)){ *reason = "package-contains-duplicates"; return 0; }

    /* TOPOLOGY: parents must precede children. Core keeps a set of "this tx
     * and everything after it" and fails if an input names anything in it --
     * note the current tx's OWN txid is still present while its inputs are
     * checked, so a transaction spending itself is caught here too. */
    for (int i = 0; i < n; i++)
        for (int k = 0; k < all_n[i]; k++)
            for (int j = i; j < n; j++)          /* j starts at i, deliberately */
                if (!memcmp(all_prev[i][k], txid[j], 32)){ *reason = "package-not-sorted"; return 0; }

    /* CONFLICTS: no two transactions may spend the same outpoint. Inputs are
     * compared ACROSS transactions only -- Core batch-adds each tx's inputs
     * after checking it, precisely so a duplicate input WITHIN one tx is not
     * reported here; that is a consensus error (bad-txns-inputs-duplicate)
     * and belongs to CheckTransaction. Comparing one input at a time would
     * silently relabel it. */
    for (int i = 0; i < n; i++)
        for (int k = 0; k < all_n[i]; k++)
            for (int j = 0; j < i; j++)
                for (int q = 0; q < all_n[j]; q++)
                    if (all_idx[i][k] == all_idx[j][q] &&
                        !memcmp(all_prev[i][k], all_prev[j][q], 32)){
                        *reason = "conflict-in-package"; return 0; }
    return 1;
}
