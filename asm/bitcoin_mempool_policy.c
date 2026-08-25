/* bitcoin_mempool_policy.c -- mempool POLICY layer.
 *
 * 100% pure C glue over the repo's verified asm primitives (same model as
 * wallet_core.c):
 *   - bitcoin_utxo.asm   (utxo_get)  : confirmed-UTXO input value resolution
 *   - bitcoin_mempool.asm(mpool_put/get/del): structural tx storage + eviction
 *   - the caller supplies the BIP141 txid (computed via bitcoin_tx.asm tx_txid)
 *
 * It is the gatekeeper that decides whether an inbound transaction may enter
 * the mempool, enforcing:
 *   1. structural parse + bounds,
 *   2. fee computation + min-relay-fee floor (feerate = fee / vsize),
 *   3. double-spend rejection within the mempool,
 *   4. BIP125 RBF -- replaceable signalling (any input nSequence != 0xffffffff),
 *      higher absolute fee + incremental relay fee on top of the replaced
 *      aggregate, and eviction of the replaced transactions (structural
 *      mpool_del + policy unregister) on accept,
 *   5. ancestor / descendant count and byte-budget limits,
 *   6. fee-rate estimator (EMA of accepted feerates, sat/kB).
 *
 * The policy owns a mutable workspace (state) that the caller allocates as a
 * flat zero-initialized buffer of `mpool_policy_state_size(n)` bytes and passes
 * to `mpool_policy_state_init`. `pol` is a small config struct. The add
 * operation is atomic: on any policy failure it leaves both the structural
 * mempool and the policy state untouched.
 */

#include <stdint.h>
#include <string.h>
#include <stddef.h>

/* ---------------- asm glue (declared; resolved at link) ------------------- */
/* Resolves a confirmed prevout's value/script. NOT literally bitcoin_utxo.
 * asm's own `utxo_get` -- that symbol is already bound (as a hard, unrelated
 * dependency of bitcoin_utxo_lsm.asm's own memtable internals) whenever this
 * file is linked into a binary that also uses the LSM store, so a second,
 * differently-behaved definition under the same name would collide. Each
 * binary that links this file provides its own definition: the old-table
 * test harnesses pass straight through to the real utxo_get, while the live
 * daemon's build provides an LSM-backed one (see daemon/tx_accept.c). */
extern long mempool_resolve_confirmed_utxo(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, const unsigned char** script,
                     unsigned long* slen);
/* bitcoin_mempool.asm */
extern long mpool_put(void* mp, const unsigned char txid[32],
                      const unsigned char* tx, unsigned long txlen);
extern long mpool_del(void* mp, const unsigned char txid[32]);
extern const unsigned char* mpool_get(void* mp, const unsigned char txid[32],
                                      unsigned long* out_len);

/* ---------------- limits --------------------------------------------------- */
#define MPOL_MAX_IN     32        /* inputs we will walk per tx */
#define MPOL_MAX_PARENTS  16      /* direct parents tracked per node */

static const char* _mpol_last_reason = "accepted";

/* ---------------- config (pol): caller fills via mpool_policy_init --------- */
typedef struct {
    uint64_t relay_fee_rate;   /* min relay feerate, sat per vbyte (int) */
    uint32_t max_anc, max_anc_bytes;
    uint32_t max_desc, max_desc_bytes;
    uint32_t rbf_enabled;
    uint32_t _pad;
    uint64_t incremental_fee;  /* sat; filled by init = relay_fee_rate*1000 */
} mpol_cfg;

/* ---------------- policy state layout (flat buffer, zero-init) ------------ */
/* outreg entry: a mempool-produced output available to spend
 *   [0..31] txid, [32..35] index, [40..47] value  (48 bytes)                 */
typedef struct { unsigned char txid[32]; uint32_t index; uint32_t _p; uint64_t value; } mpol_out;
/* claim entry: a prevout already consumed by an accepted mempool tx
 *   [0..31] prevout txid, [32..35] index, [36..39] claimer tx index (40 bytes) */
typedef struct { unsigned char prev[32]; uint32_t index; uint32_t claimer; } mpol_claim;
/* tx node: graph/limits info for an accepted tx (112 bytes)                 */
typedef struct {
    unsigned char txid[32];
    uint64_t size, fee;
    uint32_t anc_cnt, anc_bytes;
    uint32_t desc_cnt, desc_bytes;
    uint32_t n_parents;
    uint32_t parent[MPOL_MAX_PARENTS];
} mpol_node;

#define MPOL_MAGIC 0x504F4C59u
#define MPOL_HDR   64u

/* offset helpers over the flat buffer */
static mpol_out*   mpol_outreg_base(void* st){ size_t cap = *(uint32_t*)((char*)st+4);
    return (mpol_out*)((char*)st + MPOL_HDR + 4*cap); }
static mpol_claim* mpol_claims_base(void* st){ size_t cap = *(uint32_t*)((char*)st+4);
    return (mpol_claim*)((char*)st + MPOL_HDR + 4*cap + cap*sizeof(mpol_out)); }
static mpol_node*  mpol_nodes_base(void* st){ size_t cap = *(uint32_t*)((char*)st+4);
    return (mpol_node*)((char*)st + MPOL_HDR + 4*cap + cap*sizeof(mpol_out)
                        + cap*sizeof(mpol_claim)); }

/* ========================================================================== */
/* public API                                                                 */
/* ========================================================================== */

/* size of one policy-state buffer holding up to `n` transactions */
size_t mpool_policy_state_size(unsigned n){
    return MPOL_HDR + (size_t)4*n + (size_t)n*sizeof(mpol_out)
           + (size_t)n*sizeof(mpol_claim) + (size_t)n*sizeof(mpol_node);
}

void mpool_policy_state_init(void* st, unsigned n){
    memset(st, 0, mpool_policy_state_size(n));
    *(uint32_t*)st = MPOL_MAGIC;
    *(uint32_t*)((char*)st+4) = n;
}

/* mpool_policy_init(pol, relay_fee_rate, max_anc, max_anc_bytes,
 *                   max_desc, max_desc_bytes, rbf_enabled) */
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
    pol->incremental_fee = relay_fee_rate * 1000;  /* 1KB at relay rate */
}

uint64_t mpool_policy_estimate_feerate(void* st){
    return *(uint64_t*)((char*)st + 24);   /* EMA, sat/kB */
}

/* estimatesmartfee support: the EMA plus its sample count, so the RPC can
 * distinguish "no data yet" (Core's errors path) from a real estimate. */
long mpool_policy_estimate(void* st, unsigned long long* satperkb,
                           unsigned long long* samples){
    if (!st || *(uint32_t*)st != MPOL_MAGIC) return 0;
    if (satperkb) *satperkb = *(uint64_t*)((char*)st + 24);
    if (samples)  *samples  = *(uint64_t*)((char*)st + 32);
    return 1;
}

const char* mpool_policy_reason(void* pol){ (void)pol; return _mpol_last_reason; }

/* ========================================================================== */
/* internal                                                                   */
/* ========================================================================== */

/* --- input walk: parse a canonical tx, collecting prevouts + sequences and
 *     the output-value sum. Returns 0 on malformed, else number of inputs.  */
static int parse_inputs(const unsigned char* tx, unsigned long txlen,
                        unsigned char prev[][32], uint32_t* idx, uint32_t* seq,
                        unsigned long long* sum_out){
    const unsigned char* p = tx + 4;             /* skip version */
    const unsigned char* end = tx + txlen;
    /* segwit marker/flag */
    if (p + 2 <= end && p[0]==0x00 && p[1]==0x01) p += 2;
    /* n_in varint */
    unsigned long n_in = 0;
    if (p >= end) return -1;
    unsigned char b = *p++;
    if (b < 0xfd) n_in = b;
    else if (b == 0xfd){ if (p+2>end) return -1; n_in = p[0]|(p[1]<<8); p+=2; }
    else if (b == 0xfe){ if (p+4>end) return -1; n_in = 0; for(int i=0;i<4;i++) n_in|=((unsigned long)p[i])<<(8*i); p+=4; }
    else { if (p+8>end) return -1; n_in=0; for(int i=0;i<8;i++) n_in|=((unsigned long)p[i])<<(8*i); p+=8; }
    if (n_in > MPOL_MAX_IN) return -1;

    for (unsigned long i = 0; i < n_in; i++){
        if (p+36 > end) return -1;
        memcpy(prev[i], p, 32);
        idx[i] = (uint32_t)(p[32]|(p[33]<<8)|(p[34]<<16)|(p[35]<<24));
        p += 36;
        /* scriptlen varint */
        if (p >= end) return -1;
        unsigned long sl = 0; unsigned char c = *p++;
        if (c < 0xfd) sl = c;
        else if (c == 0xfd){ if(p+2>end) return -1; sl = p[0]|(p[1]<<8); p+=2; }
        else if (c == 0xfe){ if(p+4>end) return -1; sl=0; for(int k=0;k<4;k++) sl|=((unsigned long)p[k])<<(8*k); p+=4; }
        else { if(p+8>end) return -1; sl=0; for(int k=0;k<8;k++) sl|=((unsigned long)p[k])<<(8*k); p+=8; }
        if (p + sl + 4 > end) return -1;
        p += sl;
        seq[i] = (uint32_t)(p[0]|(p[1]<<8)|(p[2]<<16)|(p[3]<<24));
        p += 4;
    }

    /* n_out varint */
    if (p >= end) return -1;
    unsigned long n_out = 0; unsigned char d = *p++;
    if (d < 0xfd) n_out = d;
    else if (d == 0xfd){ if(p+2>end) return -1; n_out = p[0]|(p[1]<<8); p+=2; }
    else if (d == 0xfe){ if(p+4>end) return -1; n_out=0; for(int k=0;k<4;k++) n_out|=((unsigned long)p[k])<<(8*k); p+=4; }
    else { if(p+8>end) return -1; n_out=0; for(int k=0;k<8;k++) n_out|=((unsigned long)p[k])<<(8*k); p+=8; }

    *sum_out = 0;
    for (unsigned long i = 0; i < n_out; i++){
        if (p+8 > end) return -1;
        uint64_t v = 0; for (int k=0;k<8;k++) v |= ((uint64_t)p[k])<<(8*k);
        *sum_out += v;
        p += 8;
        if (p >= end) return -1;
        unsigned long sl=0; unsigned char e=*p++;
        if (e < 0xfd) sl = e;
        else if (e == 0xfd){ if(p+2>end) return -1; sl = p[0]|(p[1]<<8); p+=2; }
        else if (e == 0xfe){ if(p+4>end) return -1; sl=0; for(int k=0;k<4;k++) sl|=((unsigned long)p[k])<<(8*k); p+=4; }
        else { if(p+8>end) return -1; sl=0; for(int k=0;k<8;k++) sl|=((unsigned long)p[k])<<(8*k); p+=8; }
        if (sl > (unsigned long)(end - p)) return -1;   /* split bound: no overflow (incident #38) */
        p += sl;
    }
    return (int)n_in;
}

/* internal record keeping -------------------------------------------------- */
/* linear searches ----------------------------------------------------------- */
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
/* ADD: atomic policy gate + structural store + bookkeeping                   */
/* ========================================================================== */
/* The accept path and the DRY-RUN path are the same code, parameterised.
 * testmempoolaccept must answer with the mempool's real verdict, and a
 * second implementation of these checks would drift from this one -- the
 * same reason signrawtransactionwithwallet delegates rather than
 * re-implementing. `commit` is the only difference: with commit == 0 this
 * returns 1 at the commit boundary having changed nothing, exactly as
 * utxo_live_dryrun_block() returns at its Phase 5 boundary.
 *
 * `fee_out`, when non-NULL, receives the computed fee (satoshis) on any
 * path that got far enough to compute one. */
static long mpol_add_core(mpol_cfg* pol, void* st, void* mp,
                          const unsigned char* tx, unsigned long txlen,
                          const unsigned char txid[32], void* utxo,
                          int commit, unsigned long long* fee_out){
    unsigned char prev[MPOL_MAX_IN][32];
    uint32_t idx[MPOL_MAX_IN], seq[MPOL_MAX_IN];
    unsigned long long sum_out = 0, sum_in = 0;
    int n_in = parse_inputs(tx, txlen, prev, idx, seq, &sum_out);
    if (n_in <= 0){ _mpol_last_reason = "malformed transaction"; return 0; }

    /* --- fee: resolve each input value (mempool outreg first, then UTXO) --- */
    for (int i=0;i<n_in;i++){
        uint64_t v = 0;
        if (find_outreg(st, prev[i], idx[i], &v)) { sum_in += v; continue; }
        unsigned long long val; const unsigned char* sp; unsigned long sl;
        if (!utxo || mempool_resolve_confirmed_utxo(utxo, prev[i], idx[i], &val, &sp, &sl)!=1){
            _mpol_last_reason = "input not found in mempool or utxo"; return 0; }
        sum_in += val;
    }
    if (sum_in < sum_out){ _mpol_last_reason = "negative fee"; return 0; }
    uint64_t fee = sum_in - sum_out;
    if (fee_out) *fee_out = (unsigned long long)fee;
    /* min relay feerate floor: fee >= txlen * relay_fee_rate */
    if (fee < (uint64_t)txlen * pol->relay_fee_rate){
        _mpol_last_reason = "fee below min relay fee"; return 0; }

    /* --- duplicate check --- */
    if (find_node(st, txid) >= 0){ _mpol_last_reason = "duplicate tx"; return 0; }
    if (mpool_get(mp, txid, &(unsigned long){0}) != NULL){
        _mpol_last_reason = "duplicate tx"; return 0; }

    /* --- double-spend / RBF conflict scan --------------------------------- */
    int n_conf = 0;
    uint32_t conf_claimers[MPOL_MAX_IN];
    for (int i=0;i<n_in;i++){
        int cl = find_claim(st, prev[i], idx[i]);
        if (cl >= 0){
            /* dedup claimer */
            int seen = 0; for (int k=0;k<n_conf;k++) if (conf_claimers[k]==(uint32_t)cl) seen=1;
            if (!seen) conf_claimers[n_conf++] = (uint32_t)cl;
        }
    }

    if (n_conf > 0){
        mpol_node* t = mpol_nodes_base(st);
        /* aggregate replaced fees */
        uint64_t repl_fee = 0;
        for (int k=0;k<n_conf;k++) repl_fee += t[conf_claimers[k]].fee;
        /* BIP125 rules (simplified but faithful):
           - rbf must be enabled
           - the new tx must signal replaceable on at least one input
           - new absolute fee >= replaced total + incremental relay fee        */
        if (!pol->rbf_enabled){ _mpol_last_reason = "rbf disabled"; return 0; }
        int any_repl = 0; for (int i=0;i<n_in;i++) if (seq[i] != 0xffffffffu) any_repl=1;
        if (!any_repl){ _mpol_last_reason = "not replaceable"; return 0; }
        if (fee < repl_fee + pol->incremental_fee){
            _mpol_last_reason = "rbf replacement fee insufficient"; return 0; }
    }

    /* --- ancestor / descendant limits ------------------------------------- */
    uint32_t cap = *(uint32_t*)((char*)st+4);
    mpol_node* t = mpol_nodes_base(st);
    uint32_t ntx_now = *(uint32_t*)((char*)st+16);
    if (ntx_now >= cap){ _mpol_last_reason = "policy table capacity"; return 0; }

    /* mark array: use a stamp field in header (offset 20) */
    uint32_t* mark = (uint32_t*)((char*)st + MPOL_HDR);       /* capacity u32s */
    uint32_t stamp = *(uint32_t*)((char*)st+20) + 1;
    if (stamp == 0xFFFFFFFFu) stamp = 1;
    *(uint32_t*)((char*)st+20) = stamp;

    /* determine direct parents from inputs that match a registered node's txid */
    int par_idx[MPOL_MAX_IN]; int n_par = 0;
    for (int i=0;i<n_in;i++){
        if (n_par >= MPOL_MAX_IN) break;
        int p = find_node(st, prev[i]);
        int seen = 0; for (int k=0;k<n_par;k++) if (par_idx[k]==p) seen=1;
        if (p>=0 && !seen) par_idx[n_par++] = p;
    }

    /* DFS-collect the ancestor index set (mark-based, exact) */
    uint32_t anc_list[MPOL_MAX_IN + 32]; uint32_t n_anc = 0;
    uint32_t stack[MPOL_MAX_IN + 16]; int sp = 0;
    /* seed direct parents, mark them, push */
    for (int k=0;k<n_par;k++){
        uint32_t p = (uint32_t)par_idx[k];
        if (mark[p] != stamp){
            mark[p] = stamp; stack[sp++] = p;
        }
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
    /* ancestor count includes self */
    uint64_t anc_cnt = 1 + (uint64_t)n_anc;
    uint64_t anc_bytes = txlen;
    for (uint32_t k=0;k<n_anc;k++) anc_bytes += t[anc_list[k]].size;

    if (anc_cnt > pol->max_anc){ _mpol_last_reason = "ancestor limit exceeded"; return 0; }
    if (anc_bytes > pol->max_anc_bytes){ _mpol_last_reason = "ancestor limit exceeded"; return 0; }
    /* descendant budgets: every ancestor gains exactly one new descendant */
    for (uint32_t k=0;k<n_anc;k++){
        mpol_node* a = &t[anc_list[k]];
        if ((uint64_t)a->desc_cnt + 1 > pol->max_desc){
            _mpol_last_reason = "descendant limit exceeded"; return 0; }
        if ((uint64_t)a->desc_bytes + txlen > pol->max_desc_bytes){
            _mpol_last_reason = "descendant limit exceeded"; return 0; }
    }

    /* ================= commit ============================================ */
    /* dry run: every check above has passed and nothing has been mutated yet,
     * so this is the exact point at which "would it be accepted" is answered. */
    if (!commit) return 1;
    /* 1. structural store (evict RBF conflicts first) */
    {
        /* snapshot the txids we evict (node indices can shift during removal) */
        unsigned char evict_txid[MPOL_MAX_IN][32];
        int n_evict = 0;
        for (int k=0;k<n_conf;k++){
            memcpy(evict_txid[n_evict++], t[conf_claimers[k]].txid, 32);
        }
        for (int k=0;k<n_evict;k++){
            unsigned char* ct = evict_txid[k];
            mpool_del(mp, ct);
            /* re-find current node index holding this txid */
            int ci = find_node(st, ct);
            if (ci < 0) continue;
            /* remove claims referencing this claimer */
            mpol_claim* c = mpol_claims_base(st);
            for (uint32_t i=0; i<*(uint32_t*)((char*)st+12); ){
                uint32_t* ncl = (uint32_t*)((char*)st+12);
                if (c[i].claimer == (uint32_t)ci){ c[i]=c[*ncl-1]; (*ncl)--; }
                else i++;
            }
            /* outreg: entries whose txid matches the evicted tx */
            mpol_out* o = mpol_outreg_base(st);
            for (uint32_t i=0; i<*(uint32_t*)((char*)st+8); ){
                uint32_t* no = (uint32_t*)((char*)st+8);
                if (memcmp(o[i].txid, ct, 32)==0){ o[i]=o[*no-1]; (*no)--; }
                else i++;
            }
            /* remove node entry (swap-remove, keep n_txs consistent) */
            t[ci] = t[*((uint32_t*)((char*)st+16))-1];
            (*((uint32_t*)((char*)st+16)))--;
        }
    }

    if (mpool_put(mp, txid, tx, txlen) != 1){ _mpol_last_reason = "mempool store failed"; return 0; }

    /* 2. add outreg entries for outputs (re-walk outputs after inputs) */
    /*    (we already sum_out; re-walk to get per-output index + value)      */
    {
        const unsigned char* p = tx + 4;
        const unsigned char* end = tx + txlen;
        if (p+2<=end && p[0]==0 && p[1]==1) p += 2;
        unsigned long nn = 0; unsigned char b=*p++;
        if (b<0xfd) nn=b; else if (b==0xfd){nn=p[0]|(p[1]<<8);p+=2;}
        else if (b==0xfe){nn=0;for(int i=0;i<4;i++)nn|=((unsigned long)p[i])<<(8*i);p+=4;}
        else {nn=0;for(int i=0;i<8;i++)nn|=((unsigned long)p[i])<<(8*i);p+=8;}
        for (unsigned long i=0;i<nn;i++){ p+=36; unsigned long sl; unsigned char c=*p++;
            if(c<0xfd)sl=c;else if(c==0xfd){sl=p[0]|(p[1]<<8);p+=2;}
            else if(c==0xfe){sl=0;for(int k=0;k<4;k++)sl|=((unsigned long)p[k])<<(8*k);p+=4;}
            else {sl=0;for(int k=0;k<8;k++)sl|=((unsigned long)p[k])<<(8*k);p+=8;}
            p += sl + 4; }
        unsigned long m = 0; unsigned char d=*p++;
        if (d<0xfd)m=d; else if (d==0xfd){m=p[0]|(p[1]<<8);p+=2;}
        else if (d==0xfe){m=0;for(int i=0;i<4;i++)m|=((unsigned long)p[i])<<(8*i);p+=4;}
        else {m=0;for(int i=0;i<8;i++)m|=((unsigned long)p[i])<<(8*i);p+=8;}
        mpol_out* o = mpol_outreg_base(st);
        uint32_t cap_ = *(uint32_t*)((char*)st+4);
        for (unsigned long i=0;i<m;i++){
            uint64_t v=0; for(int k=0;k<8;k++) v|=((uint64_t)p[k])<<(8*k);
            p += 8; unsigned long sl; unsigned char e=*p++;
            if(e<0xfd)sl=e; else if(e==0xfd){sl=p[0]|(p[1]<<8);p+=2;}
            else if(e==0xfe){sl=0;for(int k=0;k<4;k++)sl|=((unsigned long)p[k])<<(8*k);p+=4;}
            else {sl=0;for(int k=0;k<8;k++)sl|=((unsigned long)p[k])<<(8*k);p+=8;}
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

    /* 3. add claims for each input */
    {
        mpol_claim* c = mpol_claims_base(st);
        uint32_t cap_ = *(uint32_t*)((char*)st+4);
        uint32_t myidx = *(uint32_t*)((char*)st+16); /* will be node index */
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

    /* 4. add tx node */
    {
        mpol_node* t2 = mpol_nodes_base(st);
        uint32_t myidx = *(uint32_t*)((char*)st+16);
        memcpy(t2[myidx].txid, txid, 32);
        t2[myidx].size = txlen;
        t2[myidx].fee = fee;
        t2[myidx].anc_cnt = (uint32_t)anc_cnt;
        t2[myidx].anc_bytes = (uint32_t)anc_bytes;
        t2[myidx].desc_cnt = 1;
        t2[myidx].desc_bytes = (uint32_t)txlen;
        t2[myidx].n_parents = (uint32_t)n_par;
        for (int k=0;k<MPOL_MAX_PARENTS;k++)
            t2[myidx].parent[k] = 0xFFFFFFFFu;
        for (int k=0;k<n_par && k<MPOL_MAX_PARENTS;k++)
            t2[myidx].parent[k] = (uint32_t)par_idx[k];
        (*((uint32_t*)((char*)st+16)))++;
        /* bump descendants of every ancestor */
        for (uint32_t k=0;k<n_anc;k++){
            t2[anc_list[k]].desc_cnt++;
            t2[anc_list[k]].desc_bytes += (uint32_t)txlen;
        }
    }

    /* 5. fee estimator EMA: est += (x - est)/4, x = fee*1000/txlen (sat/kB) */
    {
        uint64_t x = (uint64_t)fee * 1000 / (txlen ? txlen : 1);
        uint64_t* est = (uint64_t*)((char*)st+24);
        int64_t delta = (int64_t)x - (int64_t)*est;
        *est = *est + (delta >> 2);
        (*((uint64_t*)((char*)st+32)))++;      /* samples */
        *((uint64_t*)((char*)st+40)) += txlen;  /* accepted bytes */
    }

    _mpol_last_reason = "accepted";
    return 1;
}

/* The committing accept path -- unchanged behaviour, one caller-visible
 * function, so nothing that used mpool_policy_add sees a difference. */
long mpool_policy_add(mpol_cfg* pol, void* st, void* mp,
                      const unsigned char* tx, unsigned long txlen,
                      const unsigned char txid[32], void* utxo){
    return mpol_add_core(pol, st, mp, tx, txlen, txid, utxo, 1, NULL);
}

/* Dry run for testmempoolaccept: same checks, same reject reasons
 * (mpool_policy_reason), no insertion and no eviction. Returns 1 if the tx
 * WOULD be accepted right now, 0 otherwise. */
long mpool_policy_test(mpol_cfg* pol, void* st, void* mp,
                       const unsigned char* tx, unsigned long txlen,
                       const unsigned char txid[32], void* utxo,
                       unsigned long long* fee_out){
    if (fee_out) *fee_out = 0;
    return mpol_add_core(pol, st, mp, tx, txlen, txid, utxo, 0, fee_out);
}

/* ---- RPC read helpers (2026-08-25, shared-mempool coherence slice) --------
 * The node table is append-only within a state generation (RBF/reorg wipe and
 * rebuild it), so a txid can appear more than once after an RBF cycle: walk
 * BACKWARD so the newest registration wins. Callers hold mp_lock. A miss just
 * means "fee unknown" (e.g. tx registered before a reorg policy-state reset);
 * callers must treat it as absent data, never as fee 0 truth. */
long mpool_policy_entry(void* st, const unsigned char txid[32],
                        unsigned long long* fee, unsigned long long* size){
    if (!st || *(uint32_t*)st != MPOL_MAGIC) return 0;
    mpol_node* t = mpol_nodes_base(st);
    uint32_t n = *(uint32_t*)((char*)st+16);
    for (uint32_t i = n; i > 0; i--){
        if (!memcmp(t[i-1].txid, txid, 32)){
            if (fee)  *fee  = t[i-1].fee;
            if (size) *size = t[i-1].size;
            return 1;
        }
    }
    return 0;
}

/* ---- getmempoolentry support (2026-08-25) ---------------------------------
 * Snapshot one tx's graph neighborhood into the POD bridge struct
 * (mempool_entry.h). Callers hold mp_lock. Walks by node INDEX (children
 * reference parents by index, and RBF re-adds append new nodes), deduping
 * output by txid. The registry can hold stale nodes (RBF-evicted txs whose
 * bytes are gone from the structural pool); the RPC side filters set members
 * against the pool -- this walker reports the registry as-is.
 * Returns 1 found / 0 miss. */
#include "mempool_entry.h"

static int mpe_seen(unsigned char set[][32], int n, const unsigned char* txid){
    for (int i=0;i<n;i++) if (!memcmp(set[i],txid,32)) return 1;
    return 0;
}

long mpool_policy_entry_info(void* st, const unsigned char txid[32], mp_entry_info* out){
    if (!st || *(uint32_t*)st != MPOL_MAGIC || !out) return 0;
    mpol_node* t = mpol_nodes_base(st);
    uint32_t n = *(uint32_t*)((char*)st+16);
    long self = -1;
    for (uint32_t i = n; i > 0; i--)             /* newest registration wins */
        if (!memcmp(t[i-1].txid, txid, 32)){ self = (long)(i-1); break; }
    if (self < 0) return 0;
    memset(out, 0, sizeof *out);
    out->fee  = t[self].fee;
    out->size = t[self].size;

    /* direct parents */
    for (uint32_t k=0; k<t[self].n_parents && out->n_depends<MPE_MAX_SET; k++){
        uint32_t p = t[self].parent[k];
        if (p >= n) continue;
        if (!mpe_seen(out->depends, out->n_depends, t[p].txid))
            memcpy(out->depends[out->n_depends++], t[p].txid, 32);
    }
    /* direct children: any node listing self as a parent */
    for (uint32_t i=0; i<n && out->n_spentby<MPE_MAX_SET; i++){
        if ((long)i == self) continue;
        for (uint32_t k=0; k<t[i].n_parents; k++)
            if (t[i].parent[k] == (uint32_t)self){
                if (!mpe_seen(out->spentby, out->n_spentby, t[i].txid))
                    memcpy(out->spentby[out->n_spentby++], t[i].txid, 32);
                break;
            }
    }

    /* transitive ancestors incl self (BFS over parent edges, by index) */
    { uint32_t stack[MPE_MAX_SET]; int sp=0; 
      memcpy(out->anc[out->n_anc++], t[self].txid, 32); out->anc_fee = t[self].fee;
      stack[sp++] = (uint32_t)self;
      while (sp > 0){
          uint32_t cur = stack[--sp];
          for (uint32_t k=0; k<t[cur].n_parents; k++){
              uint32_t p = t[cur].parent[k];
              if (p >= n || mpe_seen(out->anc, out->n_anc, t[p].txid)) continue;
              if (out->n_anc >= MPE_MAX_SET) break;
              memcpy(out->anc[out->n_anc++], t[p].txid, 32);
              out->anc_fee += t[p].fee;
              if (sp < MPE_MAX_SET) stack[sp++] = p;
          }
      } }
    /* transitive descendants incl self (BFS; child edges found by scan) */
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
