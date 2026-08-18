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
#include <stdint.h>
#include "log_ts.h"

typedef unsigned char u8;
typedef unsigned long u64;
typedef unsigned int u32;

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_reload(void* lst, void* u);
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index,
                         unsigned long long* value, const u8** script, unsigned long* slen);

/* Must mirror bitcoin_utxo_lsm.asm's state struct exactly (152 bytes) --
 * same layout daemon/utxo_live.c and daemon/build_utxo.c mirror. */
struct lsm_state {
    long log_fd, idx_fd;
    u64 log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap;
    u64 next_run_no;
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

/* tx_dispatch_init(void) -> 1 ok / 0 failed. Called once per connection,
 * at node_serve_loop entry. A failure here disables tx validation for this
 * connection (see tx_accept_validate) but must not take the connection
 * down -- relay/serving of blocks and everything else keeps working. */
int tx_dispatch_init(void){
    unsigned long slots = 1UL << TXACC_SLOTS_LOG2;
    u64 blob_cap = TXACC_BLOB_BYTES;
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
    g_ready = (r != -1);
    if (!g_ready) fprintf(stderr, "[tx_accept] utxo_lsm_reload failed\n");
    return g_ready;
}

/* mempool_resolve_confirmed_utxo: see bitcoin_mempool_policy.c's and
 * bitcoin_txval_modern.c's own externs for the full rationale. `u` is
 * unused -- this always reads the per-connection snapshot above. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** script,
                                    unsigned long* slen){
    (void)u;
    if (!g_ready) return 0;
    return utxo_lsm_get(&g_lst, g_table, txid, (u32)index, value, script, slen);
}

/* ---- mempool policy + whole-tx validation dispatcher ---- */
extern void   mpool_policy_init(void* pol, unsigned long long relay_fee_rate,
                                unsigned max_anc, unsigned max_anc_bytes,
                                unsigned max_desc, unsigned max_desc_bytes,
                                unsigned rbf_enabled);
extern size_t mpool_policy_state_size(unsigned n);
extern void   mpool_policy_state_init(void* st, unsigned n);
extern long   mpool_policy_add(void* pol, void* st, void* mp,
                               const u8* tx, unsigned long txlen,
                               const u8 txid[32], void* utxo);
extern const char* mpool_policy_reason(void* pol);
extern int    txval_modern(const u8* tx, long txlen, void* utxo);
extern const char* txval_modern_reason(void);

/* Live-daemon policy defaults, matching Bitcoin Core's own standard mempool
 * relay policy defaults reasonably closely: 1 sat/vbyte min relay feerate,
 * ~101KB ancestor/descendant byte budgets at 25 count each, BIP125 RBF
 * enabled. Not tuned/load-tested against real mainnet traffic yet -- a
 * reasonable, documented starting point (task #49). */
#define TXACC_RELAY_FEE_RATE   1ULL
#define TXACC_MAX_ANC          25u
#define TXACC_MAX_ANC_BYTES    101000u
#define TXACC_MAX_DESC         25u
#define TXACC_MAX_DESC_BYTES   101000u
#define TXACC_RBF_ENABLED      1u
#define TXACC_POLICY_STATE_N   4096u

static u8   g_pol[128];
static void* g_pol_state = 0;
static int   g_pol_ready = 0;

/* tx_policy_init(void) -> 1 ok / 0 failed. Called once per connection
 * alongside tx_dispatch_init. */
int tx_policy_init(void){
    mpool_policy_init(g_pol, TXACC_RELAY_FEE_RATE, TXACC_MAX_ANC, TXACC_MAX_ANC_BYTES,
                      TXACC_MAX_DESC, TXACC_MAX_DESC_BYTES, TXACC_RBF_ENABLED);
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
long tx_accept_validate(void* mp_area, const u8 txid[32], const u8* tx, unsigned long txlen){
    if (!g_ready || !g_pol_ready) return 0;
    void* placeholder_utxo = (void*)1; /* never dereferenced: mempool_resolve_confirmed_utxo ignores it */
    if (!txval_modern(tx, (long)txlen, placeholder_utxo)){
        fprintf(stderr, "[tx_accept] reject (txval): %s\n", txval_modern_reason());
        return 0;
    }
    if (mpool_policy_add(g_pol, g_pol_state, mp_area, tx, txlen, txid, placeholder_utxo) != 1){
        fprintf(stderr, "[tx_accept] reject (policy): %s\n", mpool_policy_reason(g_pol));
        return 0;
    }
    return 1;
}

/* log_block_stored_inbound(hash32, height, bytes): called from
 * bitcoin_serve.asm's .do_block, the ONLY place a peer-pushed block
 * (unsolicited, or in response to our own .do_inv-triggered getdata) is
 * written to disk -- previously silent entirely. The outbound download
 * worker's own writes are logged separately (main.c's do_outbound_sync).
 * hash32 is wire-order; block explorers/RPC display it byte-reversed, so
 * print that convention (short form: last 8 wire bytes = first 8 displayed). */
void log_block_stored_inbound(const u8 hash32[32], long height, long bytes){
    static const char hexd[]="0123456789abcdef";
    char hs[17];
    for(int k=0;k<8;k++){ u8 b=hash32[31-k]; hs[k*2]=hexd[b>>4]; hs[k*2+1]=hexd[b&0xf]; }
    hs[16]=0;
    fprintf(stderr,"[block] stored height=%ld hash=%s.. bytes=%ld (inbound relay)\n", height, hs, bytes);
}
