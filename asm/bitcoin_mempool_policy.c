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
#define MPOL_PKG_MAX     128      /* descendant-set walk bound: desc_cnt is
                                   * capped at max_desc (25) by admission, so
                                   * 128 is comfortable headroom */

static const char* _mpol_last_reason = "accepted";

/* ---------------- config (pol): caller fills via mpool_policy_init --------- */
typedef struct {
    uint64_t relay_fee_rate;   /* min relay feerate, sat per vbyte (int) */
    uint32_t max_anc, max_anc_bytes;    /* counts; vsize budgets */
    uint32_t max_desc, max_desc_bytes;
    uint32_t rbf_enabled;      /* == Core mempoolfullrbf: replacement allowed
                                  without the replaced tx signaling BIP125.
                                  0 => replaced tx must signal (classic). */
    uint32_t accept_nonstd;    /* Core -acceptnonstdtxn: skip standardness */
    uint64_t incremental_fee;  /* incrementalrelayfee, sat/kvB */
    uint64_t dust_relay_kvb;   /* -dustrelayfee, sat/kvB (Core default 3000) */
    uint64_t datacarrier_bytes;/* -datacarriersize budget (Core v31: 100000) */
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
    pol->incremental_fee = relay_fee_rate * 1000;   /* sat/kvB */
    pol->dust_relay_kvb  = 3000;                    /* Core DUST_RELAY_TX_FEE */
    pol->datacarrier_bytes = 100000;                /* Core v31 default */
}

void mpool_policy_set_incremental(void* polv, unsigned long long satvb){
    mpol_cfg* pol = (mpol_cfg*)polv;
    if (satvb > 0) pol->incremental_fee = satvb * 1000;
}
void mpool_policy_set_dust(void* polv, unsigned long long satkvb){
    ((mpol_cfg*)polv)->dust_relay_kvb = satkvb;
}
void mpool_policy_set_datacarrier(void* polv, unsigned long long bytes){
    ((mpol_cfg*)polv)->datacarrier_bytes = bytes;
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
static const char* standard_checks(const mpol_cfg* pol, const unsigned char* tx,
                                   unsigned long txlen, const mpol_txmeta* m,
                                   const unsigned char prev0[32], uint32_t idx0){
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
          if (t == SPK_NULLDATA){
              datacarrier_used += sl;
              if (datacarrier_used > pol->datacarrier_bytes) return "datacarrier";
          } else if (t != SPK_ANCHOR){
              /* dust: unspendable outputs (NULL_DATA) skip; P2A is exempt in
               * Core only as an EPHEMERAL dust carrier (out of scope) --
               * treat it like any spendable output for the threshold. */
              if (v < dust_threshold((unsigned long)sl, t, pol->dust_relay_kvb))
                  return "dust";
          } else {
              if (v < dust_threshold((unsigned long)sl, t, pol->dust_relay_kvb))
                  return "dust";
          }
          p += sl;
      } }
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
static long mpol_add_core(mpol_cfg* pol, void* st, void* mp,
                          const unsigned char* tx, unsigned long txlen,
                          const unsigned char txid[32], void* utxo,
                          int commit, unsigned long long* fee_out){
    static unsigned char prev[MPOL_MAX_IN][32];
    static uint32_t idx[MPOL_MAX_IN], seq[MPOL_MAX_IN];
    mpol_txmeta meta;
    int n_in = parse_tx(tx, txlen, prev, idx, seq, &meta);
    if (n_in <= 0){ _mpol_last_reason = "malformed transaction"; return 0; }
    uint64_t vsize = meta.vsize;

    /* --- standardness (Core IsStandardTx order: before fees) --------------- */
    { const char* r = standard_checks(pol, tx, txlen, &meta, prev[0], idx[0]);
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

    /* min relay floor over VSIZE (Core "min relay fee not met") */
    if (fee < vsize * pol->relay_fee_rate){
        _mpol_last_reason = "min relay fee not met"; return 0; }
    /* dynamic floor (sat/kvB, rolling decay) -- Core "mempool min fee not met" */
    { uint64_t fl = mpool_policy_min_fee_ex(st, pol->incremental_fee);
      if (fl > 0){
          uint64_t need = fl * vsize / 1000;
          if (need == 0) need = 1;
          if (fee < need){ _mpol_last_reason = "mempool min fee not met"; return 0; }
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

    /* ================= commit ============================================ */
    if (!commit) return 1;

    /* 1a. RBF eviction (packages: conflicts + descendants, snapshotted) */
    for (int e=0;e<n_evict;e++){
        int ci = find_node(st, evict_set[e]);
        if (ci >= 0) remove_node(st, mp, ci);
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
extern void tx_txid(unsigned char out[32], const unsigned char* tx, unsigned long len,
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
        tx_txid(txid, p, (unsigned long)txlen, scratch, sizeof scratch);
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
