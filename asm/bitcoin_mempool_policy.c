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
 * KNOWN DELTAS, stated (LOG.md): TRUC/v3 topology rules, package relay,
 * ephemeral anchors, sibling eviction are not implemented; Core v31's
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
#define MPOL_MAX_PARENTS  24      /* direct in-pool parents tracked per node.
                                   * Core allows up to limitancestorcount(25)-1
                                   * distinct direct parents; 24 covers it. */
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
                                   * capped at max_desc (25) by admission, so
                                   * 128 is comfortable headroom */

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
 *              (Core blockSinceLastRollingFeeBump; decay gate)          */
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
    uint32_t parent[MPOL_MAX_PARENTS];
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

/* an optional "forget this txid" callback (daemon/mempool_cfg.c clears its
 * arrival-time table with it); NULL in the standalone tests */
static void (*g_forget_cb)(const unsigned char txid[32]) = 0;
void mpool_policy_set_forget_cb(void (*fn)(const unsigned char*)){ g_forget_cb = fn; }

/* ========================================================================== */
/* public API                                                                 */
/* ========================================================================== */

size_t mpool_policy_state_size(unsigned n){
    return MPOL_HDR + (size_t)4*n + (size_t)n*sizeof(mpol_out)
           + (size_t)n*sizeof(mpol_claim) + (size_t)n*sizeof(mpol_node);
}

void mpool_policy_state_init(void* st, unsigned n){
    memset(st, 0, mpool_policy_state_size(n));
    *(uint32_t*)st = MPOL_MAGIC;
    *(uint32_t*)((char*)st+4) = n;
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

static uint64_t rd_varint(const unsigned char** p, const unsigned char* end, int* ok){
    const unsigned char* b = *p; *ok = 0;
    if (b >= end) return 0;
    unsigned char f = *b++;
    uint64_t v;
    if (f < 0xfd) v = f;
    else if (f == 0xfd){ if (end-b < 2) return 0; v = (uint64_t)b[0]|((uint64_t)b[1]<<8); b += 2; }
    else if (f == 0xfe){ if (end-b < 4) return 0; v=0; for(int i=0;i<4;i++) v|=(uint64_t)b[i]<<(8*i); b += 4; }
    else { if (end-b < 8) return 0; v=0; for(int i=0;i<8;i++) v|=(uint64_t)b[i]<<(8*i); b += 8; }
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
    m->nonwit_len = m->is_segwit ? (txlen - 2 - wit_len) : txlen;
    m->weight = m->nonwit_len * 3 + txlen;
    m->vsize  = (m->weight + 3) / 4;
    m->n_in = (int)n_in;
    return (int)n_in;
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
    int witness = (spk_type == SPK_WITNESS_V0_KEY || spk_type == SPK_WITNESS_V0_SCRIPT ||
                   spk_type == SPK_WITNESS_V1_TAP || spk_type == SPK_WITNESS_UNKNOWN);
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
    for (uint32_t i=0;i<n;i++) if (memcmp(t[i].txid, txid, 32)==0) return (int)i;
    return -1;
}
static long find_outreg(void* st, const unsigned char txid[32], uint32_t index,
                        uint64_t* value){
    mpol_out* o = mpol_outreg_base(st);
    uint32_t n = *(uint32_t*)((char*)st+8);
    for (uint32_t i=0;i<n;i++)
        if (o[i].index==index && memcmp(o[i].txid, txid, 32)==0){ *value=o[i].value; return 1; }
    return 0;
}
static int find_claim(void* st, const unsigned char prev[32], uint32_t index){
    mpol_claim* c = mpol_claims_base(st);
    uint32_t n = *(uint32_t*)((char*)st+12);
    for (uint32_t i=0;i<n;i++)
        if (c[i].index==index && memcmp(c[i].prev, prev, 32)==0) return (int)c[i].claimer;
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
                if (t[i].parent[k] == cur){ is_child = 1; break; }
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
        uint32_t p = t[ci].parent[k];
        if (p < n && !seen[p]){ seen[p]=1; stack[sp++]=p; }
    }
    while (sp){
        uint32_t a = stack[--sp];
        if (t[a].desc_cnt) t[a].desc_cnt--;
        if (t[a].desc_bytes >= vsz) t[a].desc_bytes -= vsz; else t[a].desc_bytes = 0;
        if (t[a].desc_fee >= fee) t[a].desc_fee -= fee; else t[a].desc_fee = 0;
        for (uint32_t k=0;k<t[a].n_parents && sp<512;k++){
            uint32_t p = t[a].parent[k];
            if (p < n && !seen[p]){ seen[p]=1; stack[sp++]=p; }
        }
    }
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
    { mpol_claim* c = mpol_claims_base(st);
      uint32_t* ncl = (uint32_t*)((char*)st+12);
      for (uint32_t i=0;i<*ncl;){ if (c[i].claimer==(uint32_t)ci){ c[i]=c[*ncl-1]; (*ncl)--; } else i++; } }
    { mpol_out* o = mpol_outreg_base(st);
      uint32_t* no = (uint32_t*)((char*)st+8);
      for (uint32_t i=0;i<*no;){ if (memcmp(o[i].txid,ct,32)==0){ o[i]=o[*no-1]; (*no)--; } else i++; } }
    /* clear children's parent references to ci */
    { uint32_t n = *nptr;
      for (uint32_t j=0;j<n;j++)
          for (uint32_t k=0;k<t[j].n_parents;k++)
              if (t[j].parent[k]==(uint32_t)ci) t[j].parent[k]=0xFFFFFFFFu; }
    uint32_t last = *nptr - 1;
    t[ci] = t[last];
    (*nptr)--;
    if ((uint32_t)ci != last){
        uint32_t n = *nptr;
        for (uint32_t j=0;j<n;j++)
            for (uint32_t k=0;k<t[j].n_parents;k++)
                if (t[j].parent[k]==last) t[j].parent[k]=(uint32_t)ci;
        { mpol_claim* c = mpol_claims_base(st);
          uint32_t ncl = *(uint32_t*)((char*)st+12);
          for (uint32_t i=0;i<ncl;i++) if (c[i].claimer==last) c[i].claimer=(uint32_t)ci; }
    }
    if (g_forget_cb) g_forget_cb(ct);
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
                          int commit, unsigned long long* fee_out){
    static unsigned char prev[MPOL_MAX_IN][32];
    static uint32_t idx[MPOL_MAX_IN], seq[MPOL_MAX_IN];
    mpol_txmeta meta;
    _mpol_replaced_n = 0;
    int n_in = parse_tx(tx, txlen, prev, idx, seq, &meta);
    if (n_in <= 0){ _mpol_last_reason = "malformed transaction"; return 0; }
    uint64_t vsize = meta.vsize;

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
      /* min relay floor over VSIZE (Core "min relay fee not met") */
      if (eff_fee * 1000 < eff_vsize * pol->relay_fee_rate){      /* both sides sat/kvB-scaled */
          _mpol_last_reason = "min relay fee not met"; return 0; }
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
        uint64_t removed_fees = 0;
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
    for (int i=0;i<n_in;i++){
        if (n_par >= MPOL_MAX_PARENTS) break;
        int p = find_node(st, prev[i]);
        int seen = 0; for (int k=0;k<n_par;k++) if (par_idx[k]==p) seen=1;
        if (p>=0 && !seen) par_idx[n_par++] = p;
    }

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
            uint32_t gp = cn->parent[k];
            if (gp != 0xFFFFFFFFu && mark[gp] != stamp){
                mark[gp] = stamp; stack[sp++] = gp;
            }
        }
    }
    uint64_t anc_cnt = 1 + (uint64_t)n_anc;
    uint64_t anc_bytes = vsize;
    for (uint32_t k=0;k<n_anc;k++) anc_bytes += t[anc_list[k]].size;

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
     * KNOWN DELTA, stated rather than hidden: Core measures these against
     * the SIGOP-ADJUSTED vsize, and this layer only has the BIP141 vsize at
     * add time (sigop cost is recorded after the fact). The two differ only
     * for sigop-dense transactions, where Core's figure is the larger, so
     * this is marginally more permissive there -- never less. */
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
                        if (t[ei].parent[q] == (uint32_t)par_idx[0]){ child_replaced = 1; break; }
                }
                /* desc_cnt includes the parent itself */
                if ((uint64_t)pn->desc_cnt + 1 > TRUC_DESCENDANT_LIMIT && !child_replaced){
                    /* Core would additionally consider evicting the sibling
                     * under RBF rules (sibling eviction) and accepting this
                     * one; that is not implemented here, so a second child
                     * is refused. Strictly more conservative than Core:
                     * nothing is accepted that Core would reject. */
                    _mpol_last_reason = "TRUC-violation"; return 0;
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
        n_par = 0;
        for (int i=0;i<n_in;i++){
            if (n_par >= MPOL_MAX_PARENTS) break;
            int p = find_node(st, prev[i]);
            int seen = 0; for (int k=0;k<n_par;k++) if (par_idx[k]==p) seen=1;
            if (p>=0 && !seen) par_idx[n_par++] = p;
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
                uint32_t gp = t[cur].parent[k];
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
      while (put == 2){
          int w = worst_package(st);
          if (w < 0){ _mpol_last_reason = "mempool full"; return 0; }
          uint64_t wf, ws; node_score(&mpol_nodes_base(st)[w], &wf, &ws);
          /* incoming loses if its feerate <= the worst package's score */
          if ((unsigned __int128)fee * ws <= (unsigned __int128)wf * vsize){
              floor_bump(st, wf * 1000 / ws + pol->incremental_fee);
              _mpol_last_reason = "mempool full";
              return 0;
          }
          unsigned char wt[32]; memcpy(wt, mpol_nodes_base(st)[w].txid, 32);
          floor_bump(st, wf * 1000 / ws + pol->incremental_fee);
          mpool_policy_remove_package(st, mp, wt);
          mpool_compact(mp);
          put = mpool_put(mp, txid, tx, txlen);
      }
      if (put != 1){ _mpol_last_reason = "mempool store failed"; return 0; }
      *(uint64_t*)((char*)st+64) += txlen;   /* pool raw-byte accounting */
      /* trimming may have shifted node indices: recompute parent/ancestor
       * lists one more time before linking */
      t = mpol_nodes_base(st);
      n_par = 0;
      for (int i=0;i<n_in;i++){
          if (n_par >= MPOL_MAX_PARENTS) break;
          int p = find_node(st, prev[i]);
          int seen = 0; for (int k=0;k<n_par;k++) if (par_idx[k]==p) seen=1;
          if (p>=0 && !seen) par_idx[n_par++] = p;
      }
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
              uint32_t gp = t[cur].parent[k];
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
        t2[myidx].n_parents = (uint32_t)n_par;
        t2[myidx].version = meta.version;
        for (int k=0;k<MPOL_MAX_PARENTS;k++)
            t2[myidx].parent[k] = 0xFFFFFFFFu;
        for (int k=0;k<n_par && k<MPOL_MAX_PARENTS;k++)
            t2[myidx].parent[k] = (uint32_t)par_idx[k];
        (*((uint32_t*)((char*)st+16)))++;
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
    return mpol_add_core(pol, st, mp, tx, txlen, txid, utxo, 1, NULL);
}

long mpool_policy_test(mpol_cfg* pol, void* st, void* mp,
                       const unsigned char* tx, unsigned long txlen,
                       const unsigned char txid[32], void* utxo,
                       unsigned long long* fee_out){
    if (fee_out) *fee_out = 0;
    return mpol_add_core(pol, st, mp, tx, txlen, txid, utxo, 0, fee_out);
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
    for (uint64_t j = 0; j < ntx; j++){
        unsigned char info[64];
        if (tx_parse(info, p, (unsigned long)(end - p)) != 1) return removed;
        uint64_t txlen; memcpy(&txlen, info, 8);
        unsigned char txid[32];
        /* a txid we could not compute must not be used to evict anything */
        if (tx_txid(txid, p, (unsigned long)txlen, scratch, sizeof scratch) != 1) return removed;
        if (j > 0){
            /* the confirmed tx leaves alone; txs CONFLICTING with its spends
             * leave with their descendants */
            removed += remove_confirmed(st, mp, txid);
            static unsigned char cprev[MPOL_MAX_IN][32];
            static uint32_t cidx[MPOL_MAX_IN], cseq[MPOL_MAX_IN];
            mpol_txmeta cm;
            int cn = parse_tx(p, (unsigned long)txlen, cprev, cidx, cseq, &cm);
            for (int i = 0; i < cn; i++){
                int cl = find_claim(st, cprev[i], cidx[i]);
                if (cl >= 0){
                    unsigned char ct[32];
                    memcpy(ct, mpol_nodes_base(st)[cl].txid, 32);
                    removed += mpool_policy_remove_package(st, mp, ct);
                }
            }
        }
        p += txlen;
    }
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
        uint32_t p = t[self].parent[k];
        if (p >= n) continue;
        if (!mpe_seen(out->depends, out->n_depends, t[p].txid))
            memcpy(out->depends[out->n_depends++], t[p].txid, 32);
    }
    for (uint32_t i=0; i<n && out->n_spentby<MPE_MAX_SET; i++){
        if ((long)i == self) continue;
        for (uint32_t k=0; k<t[i].n_parents; k++)
            if (t[i].parent[k] == (uint32_t)self){
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
              uint32_t p = t[cur].parent[k];
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
                  if (t[i].parent[k] == cur){ child = 1; break; }
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
