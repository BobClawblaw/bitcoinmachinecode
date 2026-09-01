/* daemon/tx_accept.c -- inbound tx acceptance for the live serve daemon's
 * forked-per-connection children (bitcoin_serve.asm's node_serve_loop).
 *
 * Each inbound connection is its OWN process. It gets a READ-ONLY snapshot
 * of the confirmed UTXO set via ONE utxo_lsm_reload() at connection start,
 * rebuilt from whatever the download worker (the sole live writer, see
 * daemon/utxo_live.c) has already published to disk -- no shared memory, no
 * new cross-process synchronization, since utxo_lsm_reload is already
 * implemented and tested for exactly this "rebuild an in-memory view from
 * disk" case. Table/blob/tomb/manifest/scratch buffers are plain malloc'd
 * (NOT the file-backed mmap daemon/utxo_live.c uses for its own persistent
 * state) -- this snapshot is throwaway, per-connection, private memory that
 * must never be shared across the forked siblings or with the writer.
 *
 * mempool_resolve_confirmed_utxo is the function bitcoin_mempool_policy.c /
 * bitcoin_txval_modern.c call to resolve a prevout (see their own externs'
 * comments for why it isn't literally named utxo_get: that symbol is
 * already bound, in this same binary, to bitcoin_utxo_lsm.asm's own
 * unrelated memtable-internal use of bitcoin_utxo.asm). It ignores its own
 * `u` parameter and reads this file's own per-connection snapshot instead
 * -- mpool_policy_add/txval_modern are called with a placeholder `utxo`
 * argument accordingly (see tx_accept_validate below).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <stdint.h>
#include "log_ts.h"
#include "node_config.h"

typedef unsigned char u8;
typedef unsigned long u64;
typedef unsigned int u32;

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_reload(void* lst, void* u);
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index,
                         unsigned long long* value, unsigned long* height, unsigned long* is_coinbase,
                         const u8** script, unsigned long* slen);

/* Must mirror bitcoin_utxo_lsm.asm's state struct exactly (168 bytes) --
 * same layout daemon/utxo_live.c and daemon/build_utxo.c mirror. */
struct lsm_state {
    long log_fd, idx_fd;
    u64 log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap;
    u64 next_run_no;
    void* tomb_hash_buf; u64 tomb_hash_mask; /* LSM-owned, see bitcoin_utxo_lsm.asm */
};
#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536

/* Matches daemon/utxo_live.c's own live-daemon sizing -- the reader's
 * memtable just needs to be big enough to replay whatever the writer's
 * WAL currently holds; using the same constants keeps that automatic. */
#define TXACC_SLOTS_LOG2   16
#define TXACC_BLOB_BYTES   (64UL<<20)
#define TXACC_MANIFEST_CAP 256

static void* g_table = 0;
static struct lsm_state g_lst;
static int   g_ready = 0;

/* Incident #48: an injected LIVE resolver replaces the snapshot below.
 * The snapshot (utxo_lsm_reload of the datadir) is only coherent while
 * nothing writes the LSM -- true in a short-lived inbound serve child,
 * FALSE in the download worker, whose own utxo_live writer mutates the
 * same files continuously: within minutes lookups returned misses and
 * garbage script lengths ("prevout script too large" floods) and the
 * mempool starved. The worker injects utxo_live_resolve (the same
 * process's writer state, coherent by construction); when set, the
 * snapshot machinery is never even allocated. */
typedef long (*txacc_resolver_t)(const u8 txid[32], unsigned long index,
                                 unsigned long long* value, unsigned long* height,
                                 unsigned long* is_coinbase, const u8** script,
                                 unsigned long* slen);
static txacc_resolver_t g_resolver = 0;
void tx_accept_set_resolver(txacc_resolver_t fn){ g_resolver = fn; }

/* The height the NEXT block would have -- anchors script flags and the
 * coinbase-maturity rule for admission. The worker updates it at boot and
 * at the new-block choke point. Zero = unknown: validation still runs with
 * far-future flags (every deployed soft fork active -- correct for any
 * present-day tx), but a COINBASE spend is refused outright, because
 * maturity cannot be judged without a tip. Fail closed, loudly rare. */
static long g_next_height = 0;
void tx_accept_set_tip(long tip){ g_next_height = tip + 1; }
/* Fee estimation's "chainstate is current" (Core IsCurrentForFeeEstimation):
 * the tip's block time within MAX_FEE_ESTIMATION_TIP_AGE (3 h) and the tip
 * no more than one block behind the best header. The worker feeds the tip
 * time from each connected block; -1 for best_header means "unknown"
 * (the tip-age test alone then decides). */
static long g_tip_time = 0, g_best_header = -1;
void tx_accept_set_tip_time(long tip_time, long best_header){ g_tip_time = tip_time; g_best_header = best_header; }
int tx_accept_chainstate_current(void){
    long tip = g_next_height - 1;
    if (g_tip_time <= 0) return 0;
    if (g_tip_time < (long)time(NULL) - 3L * 3600L) return 0;
    if (g_best_header >= 0 && tip < g_best_header - 1) return 0;
    return 1;
}
/* fee-estimator hooks -- WEAK no-ops here; daemon/fee_hooks.c's strong
 * definitions win in the daemon (see that file). */
__attribute__((weak)) void fest_on_accept(const unsigned char* txid, unsigned long long fee, unsigned long long vsize, long height, int valid){ (void)txid; (void)fee; (void)vsize; (void)height; (void)valid; }
__attribute__((weak)) void fest_on_confirmed(const unsigned char* txid){ (void)txid; }
__attribute__((weak)) void fest_on_block_begin(long height){ (void)height; }
__attribute__((weak)) void fest_on_block_end(void){}
__attribute__((weak)) void fest_shutdown_flush(void){}   /* main.c calls it at worker shutdown */
static void* g_pol_state_for_fees;   /* set once the policy state exists (tx_policy_init) */
static void txacc_fee_note(const unsigned char* txid){
    extern long mpool_policy_entry(void*, const unsigned char*, unsigned long long*, unsigned long long*);
    extern long mpool_policy_n_parents(void*, const unsigned char*);
    extern int  mpol_in_package_context(void);
    unsigned long long fee = 0, vsize = 0;
    if (!g_pol_state_for_fees || mpool_policy_entry(g_pol_state_for_fees, txid, &fee, &vsize) != 1) return;
    int valid = tx_accept_chainstate_current()
             && mpool_policy_n_parents(g_pol_state_for_fees, txid) == 0
             && !mpol_in_package_context();
    fest_on_accept(txid, fee, vsize, g_next_height - 1, valid);
}

/* tx_dispatch_init(void) -> 1 ok / 0 failed. Called once per connection,
 * at node_serve_loop entry. A failure here disables tx validation for this
 * connection (see tx_accept_validate) but must not take the connection
 * down -- relay/serving of blocks and everything else keeps working. */
int tx_dispatch_init(void){
    if (g_resolver){ g_ready = 1; return 1; }   /* live resolver: no snapshot */

    /* SIZE THE SNAPSHOT TO THE WAL IT MUST HOLD, not to a constant.
     *
     * This replays utxo.dat -- the writer's current, unflushed WAL generation
     * -- into a private memtable. TXACC_SLOTS_LOG2 (2^16) is right for the
     * steady-state generation the writer keeps small precisely so this stays
     * cheap. It is wrong the moment the writer has been in BULK mode: a
     * far-behind catch-up lets the generation grow to ~500k live entries,
     * and if the process dies mid-catch-up (a crash, or a kill), that is the
     * WAL the next boot finds.
     *
     * Observed 2026-08-31 (signet, 81.5 MB WAL): the 2^16 table jammed solid
     * after 65,536 puts, the replay returned -2 -- which the old check
     * `r != -1` treated as READY -- and the recount that follows then looked
     * up ~8.7M run-resident keys, each absent from the jammed table, each
     * probe a full 65,536-slot lap: 99.9% CPU, no I/O, indefinitely. The
     * node never got past "[boot] tx-validation snapshot". Had it finished,
     * the snapshot would have been missing 7/8 of the set.
     *
     * Records are at least DEL_SIZE (44) bytes, so wal_bytes/44 bounds the
     * entries from above; size for 3/4 fill and round to a power of two,
     * never below the steady-state size. Scripts live in the blob and are a
     * subset of the WAL's bytes, so the WAL size bounds that too. The
     * bulk-shaped worst case is ~200 MB of table + the WAL again for the
     * blob, inherited copy-on-write by children -- acceptable, and it only
     * ever happens when the writer itself is already holding a 1 GB blob. */
    unsigned long slots = 1UL << TXACC_SLOTS_LOG2;
    u64 blob_cap = TXACC_BLOB_BYTES;
    long wal_bytes = -1;
    { struct stat st; if (stat("utxo.dat", &st) == 0) wal_bytes = (long)st.st_size; }
    if (wal_bytes > 0){
        u64 max_entries = (u64)wal_bytes / 44 + 1;
        u64 want = max_entries * 4 / 3 + 1;
        while (slots < want && slots < (1UL << 24)) slots <<= 1;
        if ((u64)wal_bytes + (16UL<<20) > blob_cap) blob_cap = (u64)wal_bytes + (16UL<<20);
    }
    if (slots > (1UL << TXACC_SLOTS_LOG2))
        fprintf(stderr, "[tx_accept] WAL is %ld bytes -- sizing the validation snapshot at 2^%d slots, "
                        "%llu MB blob (the writer was bulk-sized when it last wrote)\n",
                wal_bytes, __builtin_ctzl(slots), (unsigned long long)(blob_cap >> 20));

    u64 fill_threshold = (u64)slots * 3 / 4;
    u64 op_threshold    = (u64)slots * 2;
    u64 tomb_cap         = op_threshold;
    u64 desc_cap         = (u64)slots * 3;
    u64 scratch_cap       = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    u64 manifest_cap       = TXACC_MANIFEST_CAP;

    long ustruct = utxo_struct_size(slots);
    g_table = malloc((size_t)ustruct);
    void* blob = malloc((size_t)blob_cap);
    void* tomb_buf = malloc((size_t)(tomb_cap*36));
    void* manifest_buf = malloc((size_t)(manifest_cap*16));
    void* scratch_buf = malloc((size_t)scratch_cap);
    if (!g_table || !blob || !tomb_buf || !manifest_buf || !scratch_buf){
        fprintf(stderr, "[tx_accept] malloc failed\n");
        return 0;
    }
    utxo_init(g_table, slots, blob, blob_cap);

    memset(&g_lst, 0, sizeof g_lst);
    g_lst.op_threshold = op_threshold;
    g_lst.fill_threshold = fill_threshold;
    g_lst.tomb_buf = tomb_buf; g_lst.tomb_cap = tomb_cap;
    g_lst.manifest_buf = manifest_buf; g_lst.manifest_cap = manifest_cap;
    g_lst.scratch_buf = scratch_buf; g_lst.scratch_cap = scratch_cap;

    /* A brand new connection on a store that has no manifest/WAL yet
     * (never-flushed, or genuinely empty) still needs utxo_lsm_reload, not
     * utxo_lsm_init -- reload correctly handles "nothing to replay" (see
     * daemon/utxo_live.c's own init logic and its header comment for the
     * bug this exact assumption caused there before it was fixed). */
    long r = utxo_lsm_reload(&g_lst, g_table);
    /* ANY negative return is a failure. -2 is "memtable too small for the WAL
     * tail" (incident #32), and `r != -1` used to count it as ready -- which
     * means a snapshot known to be missing entries would have been served. */
    g_ready = (r >= 0);
    if (!g_ready){
        fprintf(stderr, "[tx_accept] utxo_lsm_reload failed (%ld)%s\n", r,
                r == -2 ? " -- memtable too small for the WAL tail" : "");
        return 0;
    }
    /* Cross-check against the WRITER's own live count, persisted in the first
     * qword of its memtable map. The replay must reproduce it exactly; if it
     * does not, this snapshot is wrong and must not validate anyone's
     * transactions. Absent map (first boot) -> nothing to check against. */
    { int fd = open("utxo_lsm_table.map", O_RDONLY);
      if (fd >= 0){
          unsigned long long writer_n = 0;
          if (read(fd, &writer_n, 8) == 8){
              extern long utxo_count(void*);
              long mine = utxo_count(g_table);
              if ((unsigned long long)mine != writer_n){
                  fprintf(stderr, "[tx_accept] snapshot replayed %ld live entries but the writer "
                                  "holds %llu -- REFUSING to serve a wrong snapshot\n", mine, writer_n);
                  g_ready = 0;
              }
          }
          close(fd);
      } }
    return g_ready;
}

/* ---- package overlay ------------------------------------------------------
 * The transactions of the package currently being validated, so a child can
 * resolve a parent that is not in the mempool yet. Set for the duration of
 * ONE package validation by the worker (single-threaded for this) and
 * ALWAYS cleared afterwards: a stale entry here would let an unrelated
 * transaction resolve an input against a package member that was never
 * accepted, which is a way to admit something spending a non-existent coin.
 * txacc_package_overlay(NULL,NULL,NULL,0) is the reset. */
#define TXACC_PKG_MAX 25
static const u8*    g_pkg_tx[TXACC_PKG_MAX];
static unsigned long g_pkg_len[TXACC_PKG_MAX];
static u8            g_pkg_txid[TXACC_PKG_MAX][32];
static int           g_pkg_n = 0;
void txacc_package_overlay(const u8* const* txs, const unsigned long* lens,
                           const u8* txids, int n){
    if (n > TXACC_PKG_MAX) n = TXACC_PKG_MAX;
    g_pkg_n = (n > 0 && txs && lens && txids) ? n : 0;
    for (int i = 0; i < g_pkg_n; i++){
        g_pkg_tx[i] = txs[i]; g_pkg_len[i] = lens[i];
        memcpy(g_pkg_txid[i], txids + (size_t)i * 32, 32);
    }
}

/* Resolve an outpoint against the in-package parents. 1 = found. Shared by
 * BOTH resolvers below: the script verifier's and the one mempool policy uses
 * for fees. Putting it in only one of them is a trap -- the child would then
 * verify but fail fee computation with bad-txns-inputs-missingorspent, which
 * is what happened the first time this was wired. */
static int txacc_tx_output(const u8* tx, unsigned long txlen, u32 index,
                           u64* value, const u8** spk, unsigned long* spklen);
static int txacc_pkg_resolve(const u8 outpoint[32], u32 index,
                             u64* value, const u8** spk, unsigned long* spklen){
    for (int pi = 0; pi < g_pkg_n; pi++){
        if (memcmp(g_pkg_txid[pi], outpoint, 32)) continue;
        return txacc_tx_output(g_pkg_tx[pi], g_pkg_len[pi], index, value, spk, spklen);
    }
    return 0;
}

/* mempool_resolve_confirmed_utxo: see bitcoin_mempool_policy.c's and
 * bitcoin_txval_modern.c's own externs for the full rationale. `u` is
 * unused -- this always reads the per-connection snapshot above.
 *
 * height/is_coinbase (2026-08-19, Stage D): discarded here on purpose --
 * this function's own public contract (value/script/slen) is used by
 * mempool policy and modern-tx validation elsewhere and is intentionally
 * left unchanged; coinbase maturity enforcement is a BLOCK-validation
 * concern (apply_block_inner), not mempool admission, in this pass. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** script,
                                    unsigned long* slen){
    (void)u;
    unsigned long height, is_coinbase;
    /* in-package parents first: during a package dry run the parent is not in
     * the mempool or the chain yet, and this is the resolver mempool policy
     * charges fees through. DIVERGENCE, deliberate and confined to the dry
     * run: a parent resolved here looks CONFIRMED to the policy, so ancestor
     * limits are not charged across it while fees are being computed. The
     * commit pass inserts the parent first, so the child's ancestor
     * accounting there is the real one. */
    if (g_pkg_n){
        u64 pv; const u8* ps; unsigned long psl;
        if (txacc_pkg_resolve(txid, (u32)index, &pv, &ps, &psl)){
            *value = pv; *script = ps; *slen = psl; return 1;
        }
    }
    if (g_resolver) return g_resolver(txid, index, value, &height, &is_coinbase, script, slen);
    if (!g_ready) return 0;
    return utxo_lsm_get(&g_lst, g_table, txid, (u32)index, value, &height, &is_coinbase, script, slen);
}

/* ---- mempool policy + whole-tx validation dispatcher ---- */
extern void   mpool_policy_init(void* pol, unsigned long long relay_fee_rate,
                                unsigned max_anc, unsigned max_anc_bytes,
                                unsigned max_desc, unsigned max_desc_bytes,
                                unsigned rbf_enabled);
extern size_t mpool_policy_state_size(unsigned n);
extern void   mpool_policy_state_init(void* st, unsigned n);
extern long   mpool_count(void* mp);
extern void   mempool_note_accept(const unsigned char txid[32]); /* daemon/mempool_cfg.c */
/* daemon/zmq_notify.c. Staged on BOTH accept paths, right beside
 * mempool_note_accept, because those two calls together are what "this node
 * now holds this transaction" MEANS -- a notification fired from anywhere
 * else could announce a transaction the mempool does not actually hold. A
 * no-op when ZMQ is unconfigured, and safe in the serve children. */
extern void   zmqn_tx_accepted(const unsigned char txid[32], const unsigned char* tx,
                               unsigned long txlen);
extern long   mpool_policy_add(void* pol, void* st, void* mp,
                               const u8* tx, unsigned long txlen,
                               const u8 txid[32], void* utxo);
extern const char* mpool_policy_reason(void* pol);
extern int    txval_modern(const u8* tx, long txlen, void* utxo);
extern const char* txval_modern_reason(void);

/* ---- script verification: the CONSENSUS verifier, not a second one -------
 * Admission now runs tx_verify_mempool (daemon/tx_verify.c) -- the exact
 * replay-proven engine block connection uses: legacy scripts, P2SH, all
 * witness v0 shapes, full BIP341/342 taproot (annex, script-path),
 * maturity, everything -- through a resolver that sees the confirmed set
 * PLUS unconfirmed mempool parents. bitcoin_txval_modern.c (the previous,
 * partial mempool verifier: no legacy arm, key-path-only taproot, three
 * first-contact incidents in one day) stays only for its vector tests. */
typedef int (*txv_resolve_fn)(void* ctx, const u8 outpoint[36], u32 index,
                              u64* value, u64* height, u64* is_coinbase,
                              const u8** spk, unsigned long* spklen);
extern int tx_verify_mempool(const u8* tx, u64 txlen, long next_height,
                             txv_resolve_fn rf, void* rctx, const char** reason);
extern const u8* mpool_get(void* mp, const u8 txid[32], unsigned long* out_len);

/* bounded compactsize -- the same split-bound discipline mv_parse settled
 * on (incident #37): reads never pass `end`, callers use subtraction-form
 * bounds that cannot wrap. */
static u64 txacc_varint(const u8** p, const u8* end, u64* consumed){
    const u8* b = *p; *consumed = 0;
    if (b >= end) return 0;
    u8 f = *b++;
    u64 v;
    if (f < 0xfd) v = f;
    else if (f == 0xfd){ if (end - b < 2) return 0; v = (u64)b[0] | ((u64)b[1]<<8); b += 2; }
    else if (f == 0xfe){ if (end - b < 4) return 0; v = 0; for (int i=0;i<4;i++) v |= (u64)b[i]<<(8*i); b += 4; }
    else { if (end - b < 8) return 0; v = 0; for (int i=0;i<8;i++) v |= (u64)b[i]<<(8*i); b += 8; }
    *consumed = (u64)(b - *p); *p = b;
    return v;
}

/* Extract output `index` of a raw transaction: value + script pointer into
 * the caller's buffer. Returns 1/0. Minimal wire walk -- inputs skipped,
 * witness never reached (outputs precede it). */
static int txacc_tx_output(const u8* tx, unsigned long txlen, u32 index,
                           u64* value, const u8** spk, unsigned long* spklen){
    const u8* p = tx + 4; const u8* end = tx + txlen;
    if (txlen < 10) return 0;
    if (p + 2 <= end && p[0] == 0x00 && p[1] == 0x01) p += 2;   /* segwit marker */
    u64 cc, nin = txacc_varint(&p, end, &cc); if (!cc || !nin) return 0;
    for (u64 i = 0; i < nin; i++){
        if (p + 36 > end) return 0;
        p += 36;
        u64 sl = txacc_varint(&p, end, &cc); if (!cc) return 0;
        if ((u64)(end - p) < sl + 4) return 0;
        p += sl + 4;
    }
    u64 nout = txacc_varint(&p, end, &cc); if (!cc || index >= nout) return 0;
    for (u64 i = 0; i < nout; i++){
        if (p + 8 > end) return 0;
        u64 v = 0; for (int k = 0; k < 8; k++) v |= (u64)p[k] << (8*k);
        p += 8;
        u64 sl = txacc_varint(&p, end, &cc); if (!cc || (u64)(end - p) < sl) return 0;
        if (i == index){ *value = v; *spk = p; *spklen = (unsigned long)sl; return 1; }
        p += sl;
    }
    return 0;
}

/* Resolve one outpoint for the verifier: live/snapshot confirmed set first,
 * then an unconfirmed MEMPOOL PARENT (Core resolves admission against
 * view+mempool; a parent that is itself in the pool is a legitimate spend
 * source -- ancestor limits are the policy layer's job and already
 * enforced there). A mempool parent is by definition not a coinbase. */
static int txacc_resolve_verify(void* mp_area, const u8 outpoint[36], u32 index,
                                u64* value, u64* height, u64* is_coinbase,
                                const u8** spk, unsigned long* spklen){
    unsigned long long v; unsigned long hh, cb, sl; const u8* sc;
    if (g_resolver){
        if (g_resolver(outpoint, index, &v, &hh, &cb, &sc, &sl) == 1){
            *value = v; *height = hh; *is_coinbase = cb; *spk = sc; *spklen = sl;
            return 1;
        }
    } else if (g_ready){
        unsigned long long v2; unsigned long h2, c2;
        if (utxo_lsm_get(&g_lst, g_table, outpoint, index, &v2, &h2, &c2, spk, spklen) == 1){
            *value = v2; *height = h2; *is_coinbase = c2;
            return 1;
        }
    }
    /* ---- in-package parents -------------------------------------------
     * A package is validated before any of it is in the mempool, so a child
     * spending a parent from the same package would otherwise resolve to
     * nothing and report missing-inputs. Core resolves in-package parents
     * exactly like mempool ones; this layer sits immediately before the
     * mempool lookup and is EMPTY outside a package submission. */
    if (g_pkg_n){
        u64 pv; const u8* ps; unsigned long psl;
        if (txacc_pkg_resolve(outpoint, index, &pv, &ps, &psl)){
            *value = pv; *height = (u64)(g_next_height > 0 ? g_next_height : 0);
            *is_coinbase = 0; *spk = ps; *spklen = psl;
            return 1;
        }
    }
    unsigned long plen = 0;
    const u8* ptx = mpool_get(mp_area, outpoint, &plen);
    if (ptx){
        u64 pv; const u8* ps; unsigned long psl;
        if (txacc_tx_output(ptx, plen, index, &pv, &ps, &psl)){
            *value = pv; *height = (u64)(g_next_height > 0 ? g_next_height : 0);
            *is_coinbase = 0; *spk = ps; *spklen = psl;
            return 1;
        }
    }
    return 0;
}

/* ---- exact BIP141 sigop cost (Core GetTransactionSigOpCost) ---------------
 * legacy (scriptSig+outputs, inaccurate-20 multisig) x4, plus P2SH redeem
 * (accurate) x4, plus witness sigops x1 (P2WPKH=1, P2WSH=accurate count of
 * the last witness item; v1+ taproot = 0), resolving each prevout script the
 * same way the verifier does (confirmed set, then mempool parents). Computed
 * ONCE at accept time and stored in the policy registry
 * (mpool_policy_set_sigops) so getblocktemplate reports Core's number, not a
 * lower bound. Returns the cost, or -1 if a prevout cannot be resolved
 * (callers skip the stamp; the template then falls back to legacy x4). */
extern long tx_legacy_sigops(const u8*, unsigned long);
extern long script_sigops_accurate(const u8*, unsigned long);
extern long mpool_policy_set_sigops(void*, const u8 txid[32], unsigned int);

static int sgc_last_push(const u8* sc, unsigned long sl, const u8** out, unsigned long* outl){
    const u8* p = sc; const u8* end = sc + sl;
    const u8* last = 0; unsigned long lastl = 0;
    while (p < end){
        u8 op = *p++;
        unsigned long n;
        if (op <= 0x4b) n = op;
        else if (op == 0x4c){ if (p >= end) return 0; n = *p++; }
        else if (op == 0x4d){ if (p+2 > end) return 0; n = (unsigned long)p[0] | ((unsigned long)p[1]<<8); p += 2; }
        else if (op == 0x4e){ if (p+4 > end) return 0; n = (unsigned long)p[0]|((unsigned long)p[1]<<8)|((unsigned long)p[2]<<16)|((unsigned long)p[3]<<24); p += 4; }
        else if (op <= 0x60) { last = p; lastl = 0; continue; }  /* OP_1NEGATE/OP_N: not data we need */
        else return 0;                                            /* not push-only */
        if ((unsigned long)(end - p) < n) return 0;
        last = p; lastl = n; p += n;
    }
    if (!last) return 0;
    *out = last; *outl = lastl;
    return 1;
}

static long sgc_witness_sigops(int wver, const u8* prog, unsigned long proglen,
                               const u8* wit_last, unsigned long wit_lastl){
    if (wver == 0){
        if (proglen == 20) return 1;                              /* P2WPKH */
        if (proglen == 32 && wit_last)                            /* P2WSH  */
            return script_sigops_accurate(wit_last, wit_lastl);
        return 0;
    }
    return 0;                                                     /* v1+ */
}

static long txacc_sigop_cost(void* mp_area, const u8* tx, unsigned long txlen){
    const u8* p = tx; const u8* end = tx + txlen;
    if (txlen < 10) return -1;
    p += 4;
    int segwit = (end - p >= 2 && p[0] == 0x00 && p[1] == 0x01);
    if (segwit) p += 2;
    unsigned cc; u64 nin = txacc_varint(&p, end, &cc); if (!cc || nin == 0 || nin > 100000) return -1;
    struct { const u8* prev; u32 idx; const u8* ss; unsigned long ssl; } in[512];
    if (nin > 512) return -1;                                     /* far above standardness */
    for (u64 i = 0; i < nin; i++){
        if ((unsigned long)(end - p) < 36) return -1;
        in[i].prev = p; memcpy(&in[i].idx, p+32, 4); p += 36;
        u64 sl = txacc_varint(&p, end, &cc); if (!cc || (u64)(end-p) < sl) return -1;
        in[i].ss = p; in[i].ssl = (unsigned long)sl; p += sl;
        if ((unsigned long)(end - p) < 4) return -1;
        p += 4;
    }
    u64 nout = txacc_varint(&p, end, &cc); if (!cc) return -1;
    for (u64 i = 0; i < nout; i++){
        if ((unsigned long)(end - p) < 8) return -1;
        p += 8;
        u64 sl = txacc_varint(&p, end, &cc); if (!cc || (u64)(end-p) < sl) return -1;
        p += sl;
    }
    /* witness stacks: remember each input's LAST item (the witnessScript) */
    const u8* wlast[512]; unsigned long wlastl[512];
    for (u64 i = 0; i < nin; i++){ wlast[i] = 0; wlastl[i] = 0; }
    if (segwit){
        for (u64 i = 0; i < nin; i++){
            u64 nitem = txacc_varint(&p, end, &cc); if (!cc) return -1;
            for (u64 k = 0; k < nitem; k++){
                u64 il = txacc_varint(&p, end, &cc); if (!cc || (u64)(end-p) < il) return -1;
                wlast[i] = p; wlastl[i] = (unsigned long)il; p += il;
            }
        }
    }

    long cost = tx_legacy_sigops(tx, txlen) * 4;
    for (u64 i = 0; i < nin; i++){
        u64 v, h, cb; const u8* spk; unsigned long spkl;
        if (!txacc_resolve_verify(mp_area, in[i].prev, in[i].idx, &v, &h, &cb, &spk, &spkl))
            return -1;
        int is_p2sh = (spkl == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87);
        const u8* red = 0; unsigned long redl = 0;
        if (is_p2sh && in[i].ssl &&
            sgc_last_push(in[i].ss, in[i].ssl, &red, &redl) && red)
            cost += script_sigops_accurate(red, redl) * 4;
        /* witness program: direct, or via the P2SH redeem */
        const u8* ws = spk; unsigned long wsl = spkl;
        if (is_p2sh){ ws = red; wsl = redl; }
        if (ws && wsl >= 4 && wsl <= 42 &&
            (ws[0] == 0x00 || (ws[0] >= 0x51 && ws[0] <= 0x60)) &&
            (unsigned long)ws[1] + 2 == wsl && ws[1] >= 2 && ws[1] <= 40){
            int wver = ws[0] == 0x00 ? 0 : ws[0] - 0x50;
            cost += sgc_witness_sigops(wver, ws + 2, ws[1], wlast[i], wlastl[i]);
        }
    }
    return cost;
}

/* ---- Core v30/v31 sigop and witness standardness (policy, mempool-only) ----
 * Checked BEFORE script verification, like Core's PreChecks: the transaction
 * never needs to be executable for these verdicts.
 *   - MAX_TX_LEGACY_SIGOPS (2,500, v30): legacy-counted sigops across all
 *     input scriptSigs and output scriptPubKeys;
 *   - MAX_STANDARD_TX_SIGOPS_COST (16,000): the accurate BIP141 cost the
 *     sigop walker already computes (needs prevouts);
 *   - IsWitnessStandard: P2WSH witness stack <= 100 items of <= 80 bytes
 *     with a witnessScript <= 3,600; tapscript script-path stack elements
 *     <= 80 bytes (annex handling is conservative: annexed inputs are not
 *     judged). Non-static: tests/test_policy_v31.c drives them directly. */
long txacc_legacy_sigops(const u8* tx, unsigned long txlen){
    extern long script_sigops(const u8* script, unsigned long len);
    const u8* p = tx; const u8* end = tx + txlen;
    if (txlen < 10) return -1;
    p += 4;
    int segwit = (end - p >= 2 && p[0] == 0x00 && p[1] == 0x01);
    if (segwit) p += 2;
    unsigned cc; u64 nin = txacc_varint(&p, end, &cc); if (!cc) return -1;
    long total = 0;
    for (u64 i = 0; i < nin; i++){
        if ((unsigned long)(end - p) < 36) return -1;
        p += 36;
        u64 sl = txacc_varint(&p, end, &cc); if (!cc || (u64)(end-p) < sl) return -1;
        total += script_sigops(p, (unsigned long)sl);
        p += sl;
        if ((unsigned long)(end - p) < 4) return -1;
        p += 4;
    }
    u64 nout = txacc_varint(&p, end, &cc); if (!cc) return -1;
    for (u64 i = 0; i < nout; i++){
        if ((unsigned long)(end - p) < 8) return -1;
        p += 8;
        u64 sl = txacc_varint(&p, end, &cc); if (!cc || (u64)(end-p) < sl) return -1;
        total += script_sigops(p, (unsigned long)sl);
        p += sl;
    }
    return total;
}
const char* txacc_witness_standard(void* mp_area, const u8* tx, unsigned long txlen){
    const u8* p = tx; const u8* end = tx + txlen;
    if (txlen < 10) return 0;
    p += 4;
    int segwit = (end - p >= 2 && p[0] == 0x00 && p[1] == 0x01);
    if (!segwit) return 0;
    p += 2;
    unsigned cc; u64 nin = txacc_varint(&p, end, &cc); if (!cc || nin == 0 || nin > 512) return 0;
    struct { const u8* prev; u32 idx; const u8* ss; unsigned long ssl; } in[512];
    for (u64 i = 0; i < nin; i++){
        if ((unsigned long)(end - p) < 36) return 0;
        in[i].prev = p; memcpy(&in[i].idx, p+32, 4); p += 36;
        u64 sl = txacc_varint(&p, end, &cc); if (!cc || (u64)(end-p) < sl) return 0;
        in[i].ss = p; in[i].ssl = (unsigned long)sl; p += sl;
        if ((unsigned long)(end - p) < 4) return 0;
        p += 4;
    }
    u64 nout = txacc_varint(&p, end, &cc); if (!cc) return 0;
    for (u64 i = 0; i < nout; i++){
        if ((unsigned long)(end - p) < 8) return 0;
        p += 8;
        u64 sl = txacc_varint(&p, end, &cc); if (!cc || (u64)(end-p) < sl) return 0;
        p += sl;
    }
    for (u64 i = 0; i < nin; i++){
        u64 nitem = txacc_varint(&p, end, &cc); if (!cc) return 0;
        unsigned long len_last = 0, max_excl_last = 0, max_excl_last2 = 0;
        u8 last_first = 0;
        for (u64 k = 0; k < nitem; k++){
            u64 il = txacc_varint(&p, end, &cc); if (!cc || (u64)(end-p) < il) return 0;
            if (k + 1 < nitem && (unsigned long)il > max_excl_last)  max_excl_last  = (unsigned long)il;
            if (k + 2 < nitem && (unsigned long)il > max_excl_last2) max_excl_last2 = (unsigned long)il;
            if (k + 1 == nitem){ len_last = (unsigned long)il; last_first = il ? p[0] : 0; }
            p += il;
        }
        if (nitem == 0) continue;
        u64 v; unsigned long h, cb, spkl; const u8* spk;
        if (!txacc_resolve_verify(mp_area, in[i].prev, in[i].idx, &v, &h, &cb, &spk, &spkl))
            continue;                        /* unresolvable inputs fail later anyway */
        int is_p2sh = (spkl == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87);
        const u8* ws = spk; unsigned long wsl = spkl;
        if (is_p2sh && in[i].ssl){
            const u8* red = 0; unsigned long redl = 0;
            if (sgc_last_push(in[i].ss, in[i].ssl, &red, &redl) && red){ ws = red; wsl = redl; }
        }
        if (wsl == 34 && ws[0] == 0x00 && ws[1] == 0x20){            /* P2WSH */
            if (len_last > 3600)    return "bad-witness-nonstandard";  /* MAX_STANDARD_P2WSH_SCRIPT_SIZE */
            if (nitem - 1 > 100)    return "bad-witness-nonstandard";  /* MAX_STANDARD_P2WSH_STACK_ITEMS */
            if (max_excl_last > 80) return "bad-witness-nonstandard";  /* MAX_STANDARD_P2WSH_STACK_ITEM_SIZE */
        } else if (!is_p2sh && spkl == 34 && spk[0] == 0x51 && spk[1] == 0x20){   /* P2TR */
            /* Core policy.cpp IsWitnessStandard, taproot branch, verbatim:
             * an annex (>= 2 items, last non-empty and starting 0x50) is
             * nonstandard while no semantics are defined for it; a script
             * path (>= 2 items after that) pops control block and script,
             * and IF the leaf is tapscript (control[0] & 0xfe == 0xc0)
             * every REMAINING item is capped at 80 bytes
             * (MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE). Key path: no rule.
             * Zero items is consensus-invalid; Core refuses it here too. */
            if (nitem == 0) return "bad-witness-nonstandard";
            if (nitem >= 2 && len_last > 0 && last_first == 0x50)
                return "bad-witness-nonstandard";               /* annex */
            if (nitem >= 2){
                if (len_last == 0) return "bad-witness-nonstandard"; /* empty control block */
                if ((last_first & 0xfe) == 0xc0 && max_excl_last2 > 80)
                    return "bad-witness-nonstandard";
            }
        }
    }
    return 0;
}
/* the pre-script policy gate; returns NULL ok / reason. Also parks the sigop
 * cost for the policy layer's bytespersigop-adjusted feerate. */
static const char* txacc_prechecks(void* mp_area, const u8* tx, unsigned long txlen){
    extern void mpool_policy_set_pending_sigops(unsigned long long);
    long lc = txacc_legacy_sigops(tx, txlen);
    if (lc > 2500) return "bad-txns-legacy-sigops";              /* MAX_TX_LEGACY_SIGOPS, Core v30 */
    long sc = txacc_sigop_cost(mp_area, tx, txlen);
    if (sc > 16000) return "bad-txns-too-many-sigops";           /* MAX_STANDARD_TX_SIGOPS_COST */
    const char* wr = txacc_witness_standard(mp_area, tx, txlen);
    if (wr) return wr;
    mpool_policy_set_pending_sigops(sc > 0 ? (unsigned long long)sc : 0ULL);
    return 0;
}
/* One entry for all three accept paths. Returns 1 ok, else 0 with *rout. */
static int txacc_script_verify(void* mp_area, const u8* tx, unsigned long txlen,
                               const char** rout){
    /* g_next_height == 0: use a far-future height so every deployed soft
     * fork's flags are active (strictest rules -- correct for admission);
     * the resolver+maturity interplay is safe because a coinbase spend
     * cannot prove maturity against an unknown tip and the verifier's
     * conf = next_height - uheight then goes hugely positive -- so guard
     * coinbase spends here instead, fail-closed. */
    long nh = g_next_height > 0 ? g_next_height : (1L << 30);
    static __thread const char* r;
    r = 0;
    if (tx_verify_mempool(tx, (u64)txlen, nh, (txv_resolve_fn)txacc_resolve_verify,
                          mp_area, &r) == 1)
        return 1;
    *rout = r ? r : "script verification failed";
    return 0;
}

/* Live-daemon policy defaults, matching Bitcoin Core's own standard mempool
 * relay policy defaults reasonably closely: 1 sat/vbyte min relay feerate,
 * ~101KB ancestor/descendant byte budgets at 25 count each, BIP125 RBF
 * enabled. Not tuned/load-tested against real mainnet traffic yet -- a
 * reasonable, documented starting point (task #49). */
#define TXACC_RELAY_FEE_RATE   100ULL   /* sat/kvB: Core v30 DEFAULT_MIN_RELAY_TX_FEE (0.1 sat/vB) */
#define TXACC_MAX_ANC          25u
#define TXACC_MAX_ANC_BYTES    101000u
#define TXACC_MAX_DESC         25u
#define TXACC_MAX_DESC_BYTES   101000u
#define TXACC_RBF_ENABLED      1u
#define TXACC_POLICY_STATE_N   4096u

static u8   g_pol[128];
static void* g_pol_state = 0;
static int   g_pol_ready = 0;

/* Shared-mempool coherence (daemon/mempool_cfg.c): when the mempool region is
 * the MAP_SHARED pre-fork one, the POLICY state (fee/ancestor registry) is a
 * shared pre-fork region too, and every mutation must hold the cross-process
 * lock. Both are no-ops / null in the static per-process fallback. */
extern void* mp_ext_polstate;
extern unsigned long mp_ext_polstate_n;
extern void mp_lock(void);
extern void mp_unlock(void);

/* tx_policy_init(void) -> 1 ok / 0 failed. Called once per connection
 * alongside tx_dispatch_init. */
/* stamp the registry after a successful accept (holds mp_lock briefly) */
static void txacc_note_sigops(void* mp_area, const u8 txid[32], const u8* tx, unsigned long txlen){
    long c = txacc_sigop_cost(mp_area, tx, txlen);
    if (c < 0) return;                 /* unresolvable: leave 0 (fallback) */
    mp_lock();
    mpool_policy_set_sigops(g_pol_state, txid, (unsigned int)c);
    mp_unlock();
}

static void txacc_note_confirmed(const unsigned char* txid);   /* defined with the recently-confirmed set below */
int tx_policy_init(void){
    /* config-driven where Core exposes the knob (defaults match Core's own);
     * falls back to the compiled defaults if the config layer is absent (a
     * standalone test that never calls node_config_load). */
    extern node_config_t g_cfg;
    unsigned long long relay = g_cfg.minrelaytxfee_satkvb > 0 ? (unsigned long long)g_cfg.minrelaytxfee_satkvb : TXACC_RELAY_FEE_RATE;   /* sat/kvB */
    unsigned anc  = g_cfg.limitancestorcount   > 0 ? (unsigned)g_cfg.limitancestorcount   : TXACC_MAX_ANC;
    unsigned ancb = g_cfg.limitancestorsize_kvb> 0 ? (unsigned)(g_cfg.limitancestorsize_kvb*1000) : TXACC_MAX_ANC_BYTES;
    unsigned dsc  = g_cfg.limitdescendantcount > 0 ? (unsigned)g_cfg.limitdescendantcount : TXACC_MAX_DESC;
    unsigned dscb = g_cfg.limitdescendantsize_kvb>0? (unsigned)(g_cfg.limitdescendantsize_kvb*1000): TXACC_MAX_DESC_BYTES;
    unsigned rbf  = g_cfg.mempoolfullrbf ? 1u : 0u;
    mpool_policy_init(g_pol, relay, anc, ancb, dsc, dscb, rbf);
    g_pol_state_for_fees = g_pol_state;
    { extern void mpool_policy_set_confirmed_hook(void (*)(const unsigned char*));
      mpool_policy_set_confirmed_hook(txacc_note_confirmed); }
    { extern void mpool_policy_set_incremental(void*, unsigned long long);
      extern void mpool_policy_set_dust(void*, unsigned long long);
      extern void mpool_policy_set_datacarrier(void*, unsigned long long);
      extern void mpool_policy_set_acceptnonstd(void*, unsigned);
      extern void mpool_policy_set_baremultisig(void*, unsigned);
      if (g_cfg.incrementalrelayfee_satkvb > 0)
          mpool_policy_set_incremental(g_pol, (unsigned long long)g_cfg.incrementalrelayfee_satkvb);   /* sat/kvB */
      if (g_cfg.dustrelayfee_satkvb > 0)
          mpool_policy_set_dust(g_pol, (unsigned long long)g_cfg.dustrelayfee_satkvb);
      /* datacarrier=0 == a zero budget: every OP_RETURN output rejected as
       * "datacarrier" (Core reports "scriptpubkey" for that shape -- close
       * enough to be honest, stated here). */
      mpool_policy_set_datacarrier(g_pol, g_cfg.datacarrier
          ? (unsigned long long)g_cfg.datacarriersize : 0ULL);
      if (g_cfg.acceptnonstdtxn) mpool_policy_set_acceptnonstd(g_pol, 1);
      /* -permitbaremultisig: getmempoolinfo has always REPORTED this as 1
       * while nothing could change it. It is a real gate now. */
      mpool_policy_set_baremultisig(g_pol, g_cfg.permitbaremultisig ? 1u : 0u); }
    if (mp_ext_polstate){
        /* shared, already mpool_policy_state_init'd once pre-fork -- adopting
         * it (NOT re-initing) is what keeps fee bookkeeping coherent across
         * the worker, inbound children, and the parent's RPC thread. */
        g_pol_state = mp_ext_polstate;
        g_pol_ready = 1;
        return 1;
    }
    size_t sz = mpool_policy_state_size(TXACC_POLICY_STATE_N);
    g_pol_state = malloc(sz);
    if (!g_pol_state){ fprintf(stderr, "[tx_accept] policy state malloc failed\n"); return 0; }
    mpool_policy_state_init(g_pol_state, TXACC_POLICY_STATE_N);
    g_pol_ready = 1;
    return 1;
}

/* tx_accept_validate(mp_area, txid, tx, txlen) -> 1 accepted+stored in the
 * structural mempool, 0 rejected. Called from bitcoin_serve.asm's .do_tx
 * in place of its previous unconditional mpool_put. Fails open to "reject"
 * (not "accept") if either init step above didn't succeed -- refusing to
 * relay/store an unvalidated tx is the safe direction to fail in.
 *
 * ORDER MATTERS: txval_modern runs FIRST, deliberately. mpool_policy_add's
 * own accept path already calls mpool_put itself as its final step
 * (confirmed directly in bitcoin_mempool_policy.c) -- there is no separate
 * explicit mpool_put call here, and no public API to unregister a tx from
 * mpool_policy_add's own internal ancestor/descendant graph state (only the
 * structural mpool_del, which wouldn't clean up that bookkeeping). Running
 * txval_modern (pure signature/structural validation against the confirmed
 * UTXO set only -- no policy/mempool dependency) BEFORE mpool_policy_add
 * means a signature failure never triggers the policy accept+insert in the
 * first place, avoiding the need for any such rollback entirely. Slightly
 * more expensive than rejecting cheap policy failures first (an occasional
 * wasted signature-verification pass on a tx that would also have failed
 * fee/dedup checks), a correctness-over-throughput tradeoff worth revisiting
 * once this is under real traffic (task #49). */
/* ---- P2P-path log summarizer -------------------------------------------
 * The relay drain feeds hundreds of transactions a minute through here, and
 * a per-transaction log line for each one turned the production log into an
 * unreadable reject firehose the first day real relay traffic flowed (the
 * majority class, "input not found in utxo", is ordinary out-of-order relay
 * -- children of unconfirmed parents this node has no orphan pool for --
 * exactly the churn Core hides behind -debug=mempoolrej). One summary line
 * per window keeps the same information legible; the most recent
 * NON-routine reject reason is carried in the line so a new failure class
 * is still visible without the flood. The sendrawtransaction path
 * (tx_accept_validate_reason) keeps full per-tx logging: user-submitted
 * transactions are rare and each one matters. */
/* ---- recently confirmed (Core's m_recent_confirmed_transactions) ----------
 * A transaction delivered over p2p AFTER the block carrying it was applied
 * fails input resolution ("already-spent") and used to be parked as an orphan
 * -- a slot wasted for two minutes and a parent request the peer cannot
 * satisfy. Block connect records every txid the block carried in this rolling
 * set; the relay path answers "already known" (-27) for them. 64K entries of
 * an 8-byte prefix covers ~25 recent blocks' worth of transactions. */
#define TXACC_RECENT_CONF (1u << 16)
static u8 g_recent_conf[TXACC_RECENT_CONF][8];
static unsigned g_recent_conf_w;
static void txacc_note_confirmed(const unsigned char* txid){
    memcpy(g_recent_conf[g_recent_conf_w % TXACC_RECENT_CONF], txid, 8); g_recent_conf_w++;
    fest_on_confirmed(txid);                       /* fee estimation: confirmed in the block being connected */
}
static int txacc_recently_confirmed(const u8* txid){
    unsigned n = g_recent_conf_w < TXACC_RECENT_CONF ? g_recent_conf_w : TXACC_RECENT_CONF;
    for (unsigned i = 0; i < n; i++) if (!memcmp(g_recent_conf[i], txid, 8)) return 1;
    return 0;
}
#define TXACC_LOG_WINDOW_SECS 30
static struct {
    long acc, rej_missing, rej_invalid, rej_policy, known_conf;
    long t0;
    char last_invalid[96];
} g_alog;
static void txacc_log_tick(void* mp_area){
    long now = (long)time(NULL);
    if (!g_alog.t0){ g_alog.t0 = now; return; }
    if (now - g_alog.t0 < TXACC_LOG_WINDOW_SECS) return;
    if (g_alog.acc || g_alog.rej_missing || g_alog.rej_invalid || g_alog.rej_policy || g_alog.known_conf)
        fprintf(stderr, "[tx_accept] last %lds: +%ld accepted (mempool %ld) | rejected: %ld missing-inputs, %ld invalid%s%s%s, %ld policy | %ld already confirmed\n",
                now - g_alog.t0, g_alog.acc, mpool_count(mp_area),
                g_alog.rej_missing, g_alog.rej_invalid,
                g_alog.last_invalid[0] ? " (last: \"" : "",
                g_alog.last_invalid[0] ? g_alog.last_invalid : "",
                g_alog.last_invalid[0] ? "\")" : "",
                g_alog.rej_policy, g_alog.known_conf);
    memset(&g_alog, 0, sizeof g_alog);
    g_alog.t0 = now;
}

long tx_accept_validate(void* mp_area, const u8 txid[32], const u8* tx, unsigned long txlen){
    if (!g_ready || !g_pol_ready) return 0;
    txacc_log_tick(mp_area);
    void* placeholder_utxo = (void*)1; /* never dereferenced: mempool_resolve_confirmed_utxo ignores it */
    { const char* pre = txacc_prechecks(mp_area, tx, txlen);
      if (pre) return 0; }
    {
        const char* r = 0;
        if (!txacc_script_verify(mp_area, tx, txlen, &r)){
            if (r && strstr(r, "missing/already-spent")) g_alog.rej_missing++;
            else {
                g_alog.rej_invalid++;
                snprintf(g_alog.last_invalid, sizeof g_alog.last_invalid, "%s", r ? r : "?");
            }
            return 0;
        }
    }
    mp_lock();
    long padd = mpool_policy_add(g_pol, g_pol_state, mp_area, tx, txlen, txid, placeholder_utxo);
    if (padd == 1) txacc_fee_note(txid);           /* fee estimation, under the same lock */
    mp_unlock();
    if (padd != 1){
        g_alog.rej_policy++;
        return 0;
    }
    g_alog.acc++;
    txacc_note_sigops(mp_area, txid, tx, txlen);
    /* Stamp arrival so -mempoolexpiry can evict it later. The mempool slot
     * format has no timestamp field, so this parallel record is what makes
     * expiry possible without changing the slot layout. */
    mempool_note_accept(txid);
    zmqn_tx_accepted(txid, tx, txlen);
    return 1;
}

/* The two -- and only two -- policy verdicts a package may overturn, in
 * Core's words. Exported so the relay drain and the submitpackage path
 * cannot drift apart on what "reconsiderable" means. */
/* Live entries in the validation snapshot, or -1 before/without one. For the
 * test that pins tx_dispatch_init's sizing against a WAL larger than the
 * steady-state table. */
long txacc_snapshot_count(void){
    extern long utxo_count(void*);
    return (g_ready && g_table) ? utxo_count(g_table) : -1;
}

int txacc_fee_reconsiderable(const char* reason){
    return reason && (!strcmp(reason, "min relay fee not met") ||
                      !strcmp(reason, "mempool min fee not met"));
}

/* tx_accept_validate_p2p: the RELAY path's entry. Same verdict classes as
 * tx_accept_validate_reason (1 accept, -25 missing inputs, -26 other) so
 * the orphan pool can class its parks -- but it logs through the 30-second
 * SUMMARY, never per transaction. The drain briefly used _reason directly
 * for the -25 class and silently brought the per-tx reject firehose back;
 * per-tx lines belong to user submissions only.
 *
 * One extra class the RPC entries do not need: -28, "reconsiderable". Core
 * splits a fee-only failure (TX_RECONSIDERABLE: min relay fee not met, or
 * mempool min fee not met) out of the general reject class precisely because
 * it is the one verdict a CPFP child can overturn -- everything else is
 * final, and no amount of fee from a descendant makes an invalid parent
 * valid. Those are the same two strings txsub_package already treats as
 * rescuable, kept in one place here. Collapsing them into -26, as this used
 * to, is what made 1p1c relay impossible: the drain could not tell a parent
 * worth re-submitting inside a package from one worth discarding. */
long tx_accept_validate_p2p(void* mp_area, const u8 txid[32], const u8* tx,
                            unsigned long txlen){
    if (!g_ready || !g_pol_ready) return -26;
    txacc_log_tick(mp_area);
    if (txacc_recently_confirmed(txid)){ g_alog.known_conf++; return -27; }   /* already in a block: not an orphan */
    void* placeholder_utxo = (void*)1;
    { const char* pre = txacc_prechecks(mp_area, tx, txlen);
      if (pre){ g_alog.rej_policy++; return -26; } }
    {
        const char* r = 0;
        if (!txacc_script_verify(mp_area, tx, txlen, &r)){
            if (r && strstr(r, "missing/already-spent")){ g_alog.rej_missing++; return -25; }
            g_alog.rej_invalid++;
            snprintf(g_alog.last_invalid, sizeof g_alog.last_invalid, "%s", r ? r : "?");
            return -26;
        }
    }
    mp_lock();
    long padd = mpool_policy_add(g_pol, g_pol_state, mp_area, tx, txlen, txid, placeholder_utxo);
    if (padd == 1) txacc_fee_note(txid);           /* fee estimation, under the same lock */
    mp_unlock();
    if (padd != 1){
        g_alog.rej_policy++;
        const char* r = mpool_policy_reason(g_pol);
        if (r && txacc_fee_reconsiderable(r)) return -28;
        return -26;
    }
    g_alog.acc++;
    txacc_note_sigops(mp_area, txid, tx, txlen);
    mempool_note_accept(txid);
    zmqn_tx_accepted(txid, tx, txlen);
    return 1;
}

/* tx_accept_validate_reason: like tx_accept_validate but surfaces the reject
 * reason (for sendrawtransaction) and returns a Core RPC error code instead of
 * a bare 0. Returns 1 on accept, or negative: -4 not-initialized, -22 decode,
 * -25 missing inputs, -26 policy/consensus reject, -27 already known. The
 * reason string is copied into `reason` (best-effort; empty on accept). Shares
 * the same g_pol/g_pol_state/g_ready state as tx_accept_validate. */
long tx_accept_validate_reason(void* mp_area, const u8 txid[32], const u8* tx,
                               unsigned long txlen, char* reason, unsigned long rcap){
    if (reason && rcap) reason[0] = 0;
    if (!g_ready || !g_pol_ready){ if (reason && rcap) snprintf(reason, rcap, "mempool not initialized"); return -4; }
    void* placeholder_utxo = (void*)1;
    { const char* pre = txacc_prechecks(mp_area, tx, txlen);
      if (pre){ if (reason && rcap) snprintf(reason, rcap, "%s", pre); return -26; } }
    {
        const char* r = 0;
        if (!txacc_script_verify(mp_area, tx, txlen, &r)){
            if (reason && rcap) snprintf(reason, rcap, "%s", r ? r : "mandatory-script-verify-flag-failed");
            /* missing-inputs is ORDINARY: out-of-order relay, and every
             * mempool.dat reload's first pass (7,243 lines in 40 s after
             * deploy `h` -- it read like a meltdown while the reload ended
             * "5007 accepted, 0 rejected"). One line per 5 s; the 30 s
             * summary carries the count. Real invalidity stays per-tx. */
            if (r && (strstr(r, "missing") || strstr(r, "inputs-spent"))){
                /* no per-event line at all: with steady mainnet churn the
                 * 5s mute still guaranteed a line every 5 seconds forever
                 * (2026-08-31, operator: "wtf is that spam"). The 30s
                 * summary's missing-inputs count is the record. */
                return -25;
            }
            fprintf(stderr, "[tx_accept] reject (txval): %s\n", r ? r : "");
            return -26;
        }
    }
    mp_lock();
    long padd = mpool_policy_add(g_pol, g_pol_state, mp_area, tx, txlen, txid, placeholder_utxo);
    if (padd == 1) txacc_fee_note(txid);           /* fee estimation, under the same lock */
    mp_unlock();
    if (padd != 1){
        const char* r = mpool_policy_reason(g_pol);
        if (reason && rcap) snprintf(reason, rcap, "%s", r ? r : "policy rejected");
        { static long pol_last, pol_muted;              /* 1/min: informative but not a metronome */
          long now = (long)time(NULL);
          if (now - pol_last >= 60){
              fprintf(stderr, "[tx_accept] reject (policy): %s%s\n", r ? r : "",
                      pol_muted ? " (repeats muted; the 30s summary counts them)" : "");
              pol_last = now; pol_muted = 1;
          } }
        if (r && strstr(r, "already")) return -27;
        if (r && (strstr(r, "missing") || strstr(r, "inputs-spent"))) return -25;
        return -26;
    }
    txacc_note_sigops(mp_area, txid, tx, txlen);
    mempool_note_accept(txid);
    zmqn_tx_accepted(txid, tx, txlen);
    return 1;
}

/* tx_accept_test_reason: would this tx be accepted RIGHT NOW? Runs the same
 * consensus/script validation and the same mempool policy checks as
 * tx_accept_validate_reason, but stops at the policy commit boundary
 * (mpool_policy_test) so nothing is inserted, nothing is evicted, and no
 * fee-estimation sample is recorded. Behind testmempoolaccept.
 *
 * Sharing the implementation is the point: an answer from a second,
 * parallel copy of these rules would be an answer about a mempool this node
 * does not have. *fee_out (satoshis) is filled when the fee was computed. */
long tx_accept_test_reason(void* mp_area, const u8 txid[32], const u8* tx,
                           unsigned long txlen, char* reason, unsigned long rcap,
                           unsigned long long* fee_out){
    extern long mpool_policy_test(void*, void*, void*, const unsigned char*, unsigned long,
                                  const unsigned char*, void*, unsigned long long*);
    if (reason && rcap) reason[0] = 0;
    if (fee_out) *fee_out = 0;
    if (!g_ready || !g_pol_ready){ if (reason && rcap) snprintf(reason, rcap, "mempool not initialized"); return -4; }
    void* placeholder_utxo = (void*)1;
    { const char* pre = txacc_prechecks(mp_area, tx, txlen);
      if (pre){ if (reason && rcap) snprintf(reason, rcap, "%s", pre); return -26; } }
    {
        const char* r = 0;
        if (!txacc_script_verify(mp_area, tx, txlen, &r)){
            if (reason && rcap) snprintf(reason, rcap, "%s", r ? r : "mandatory-script-verify-flag-failed");
            if (r && (strstr(r, "missing") || strstr(r, "inputs-spent"))) return -25;
            return -26;
        }
    }
    mp_lock();
    long pt = mpool_policy_test(g_pol, g_pol_state, mp_area, tx, txlen, txid,
                                placeholder_utxo, fee_out);
    mp_unlock();
    if (pt != 1){
        const char* r = mpool_policy_reason(g_pol);
        if (reason && rcap) snprintf(reason, rcap, "%s", r ? r : "policy rejected");
        if (r && strstr(r, "already")) return -27;
        if (r && (strstr(r, "missing") || strstr(r, "inputs-spent"))) return -25;
        return -26;
    }
    return 1;
}

/* tx_accept_block_connect: the download worker's per-block mempool
 * reconciliation (Core removeForBlock + removeConflicts + the rolling-fee
 * decay gate), called from main.c's new-block choke point with the raw
 * block bytes. Holds the cross-process pool lock. No-op until the shared
 * pool + policy state exist. */
long tx_accept_block_connect_h(void* mp_area, const unsigned char* block,
                               unsigned long blen, long height){
    extern long mpool_policy_block_connect(void*, void*, const unsigned char*, unsigned long);
    if (!g_pol_ready || !g_pol_state || !mp_area) return 0;
    mp_lock();
    /* fee estimation: roll the block counters first; the policy's confirmed
     * hook then books each mined tx (txacc_note_confirmed), and the forget
     * callback books conflicts as "left unconfirmed" */
    fest_on_block_begin(height);
    long r = mpool_policy_block_connect(g_pol_state, mp_area, block, blen);
    fest_on_block_end();
    mp_unlock();
    return r;
}
long tx_accept_block_connect(void* mp_area, const unsigned char* block,
                             unsigned long blen){
    return tx_accept_block_connect_h(mp_area, block, blen, g_next_height);
}

/* serve_idx_topup: WEAK default. bitcoin_serve.asm calls this at the top of
 * getdata handling to fold in heights index.dat has gained since boot; the
 * real one lives in daemon/main.c, where ht_idx does. Several test targets
 * link bitcoin_serve.o WITHOUT main.c -- the same reason
 * log_block_stored_inbound lives in this file -- and for them "no new
 * heights" is the honest answer, since nothing is appending any.
 * A strong definition anywhere in the link overrides this one. */
__attribute__((weak)) long serve_idx_topup(void){ return 0; }

/* WEAK defaults for the serve-path callbacks that live outside this file, so
 * targets linking bitcoin_serve.o without daemon/main.c or
 * daemon/serve_cfilters.c still resolve them. A strong definition anywhere
 * in the link wins. */
__attribute__((weak)) long serve_height_of_hash(const unsigned char hash[32]){
    (void)hash; return -1;
}
__attribute__((weak)) int serve_cfilters(int fd, int kind,
                                         const unsigned char* pl, unsigned long plen){
    (void)fd; (void)kind; (void)pl; (void)plen; return 0;
}
__attribute__((weak)) long serve_getaddr(int fd, int wants_v2){
    (void)fd; (void)wants_v2; return 0;
}

/* log_block_stored_inbound(hash32, height, bytes): called from
 * bitcoin_serve.asm's .do_block, the ONLY place a peer-pushed block
 * (unsolicited, or in response to our own .do_inv-triggered getdata) is
 * written to disk -- previously silent entirely. The outbound download
 * worker's own writes are logged separately (main.c's do_outbound_sync).
 * hash32 is wire-order; block explorers/RPC display it byte-reversed, so
 * print that convention (short form: last 8 wire bytes = first 8 displayed). */
void log_block_stored_inbound(const u8 hash32[32], long height, long bytes, const u8* block){
    static const char hexd[]="0123456789abcdef";
    char hs[17];
    for(int k=0;k<8;k++){ u8 b=hash32[31-k]; hs[k*2]=hexd[b>>4]; hs[k*2+1]=hexd[b&0xf]; }
    hs[16]=0;
    /* tx count: CompactSize varint right after the 80-byte header, matching
     * tx_parse's own decode (mirrored here rather than pulled in from
     * daemon/utxo_walk.h to avoid its u8/u64/u32 typedefs colliding with
     * the ones already declared at the top of this file). */
    u64 ntx = 0;
    if (bytes > 81) {
        u8 c = block[80];
        if (c < 0xfd) ntx = c;
        else if (c == 0xfd && bytes >= 83) ntx = (u64)block[81] | ((u64)block[82]<<8);
        else if (c == 0xfe && bytes >= 85) { u32 v; memcpy(&v, block+81, 4); ntx = v; }
        else if (c == 0xff && bytes >= 89) memcpy(&ntx, block+81, 8);
    }
    fprintf(stderr,"[block] stored height=%ld hash=%s.. bytes=%ld tx=%llu (inbound relay)\n",
            height, hs, bytes, (unsigned long long)ntx);
}
