/* Standalone end-to-end test for daemon/tx_accept.c's REAL pipeline against
 * the LSM UTXO backend: tx_dispatch_init (utxo_lsm_reload snapshot) ->
 * mempool_resolve_confirmed_utxo -> mpool_policy_add -> txval_modern ->
 * tx_accept_validate's accept/reject decision -> mpool_put/mpool_get.
 *
 * This is NOT covered by tests/test_mempool_accept_modern.c (which calls
 * mpool_policy_add/txval_modern directly against the OLD bitcoin_utxo.asm
 * backend via its own passthrough shim, never touching utxo_lsm_* or
 * tx_accept.c's own dispatcher/ordering logic at all).
 *
 * Run in a throwaway dir: seeds ONE confirmed prevout into a fresh LSM
 * store via utxo_lsm_put, closes it, then drives the exact same connection-
 * entry sequence bitcoin_serve.asm now uses (tx_dispatch_init + tx_policy_
 * init, both reading the just-seeded on-disk state), then:
 *   1. a genuine valid spend -> tx_accept_validate must accept, and the tx
 *      must actually be found in the mempool afterward (mpool_get).
 *   2. the same tx with a corrupted witness signature -> must reject, and
 *      -- the actual point of this test's ordering check -- must NOT be
 *      left sitting in the mempool (proving tx_accept.c's txval-before-
 *      policy ordering fix actually avoids the phantom-mempool-entry bug
 *      an insert-then-fail ordering would have caused).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "modern_spend.h"

typedef unsigned char u8;
typedef unsigned long u64;
typedef unsigned int u32;

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index, u64 value, u64 height, u64 is_coinbase, const u8* script, u32 slen);
extern void utxo_lsm_close(void* lst);
extern const u8* mpool_get(void* mp, const u8 txid[32], unsigned long* out_len);

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

extern int  tx_dispatch_init(void);
extern int  tx_policy_init(void);
extern long tx_accept_validate(void* mp_area, const u8 txid[32], const u8* tx, unsigned long txlen);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);

/* mirrors bitcoin_serve.asm's own mp_area sizing */
static u8 mp_area[40 + 1024*48 + 8];
static u8 mp_blob[2<<20];
extern void mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);

static int g_fails = 0, g_checks = 0;
static void ck(const char* name, int cond){
    g_checks++;
    if (cond) printf("  ok  %s\n", name);
    else { g_fails++; printf("  FAIL %s\n", name); }
}

static void seed_utxos(const msend_t** specs, int n){
    unsigned long slots = 1UL<<16;
    long ustruct = utxo_struct_size(slots);
    void* table = malloc((size_t)ustruct);
    void* blob = malloc(64UL<<20);
    utxo_init(table, slots, blob, 64UL<<20);
    struct lsm_state lst; memset(&lst, 0, sizeof lst);
    u64 op_th = slots*2, fill_th = slots*3/4, tomb_cap = op_th, desc_cap = slots*3;
    u64 scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    lst.op_threshold = op_th; lst.fill_threshold = fill_th;
    lst.tomb_buf = malloc(tomb_cap*36); lst.tomb_cap = tomb_cap;
    lst.manifest_buf = malloc(256*16); lst.manifest_cap = 256;
    lst.scratch_buf = malloc(scratch_cap); lst.scratch_cap = scratch_cap;
    if (utxo_lsm_init(&lst) != 1) { fprintf(stderr, "seed: utxo_lsm_init failed\n"); exit(1); }
    for (int i=0;i<n;i++){
        const msend_t* s = specs[i];
        long r = utxo_lsm_put(&lst, table, s->txid, 0, s->prev_amount, 0, 0, s->prev_spk, (u32)s->prev_spklen);
        if (r != 1) { fprintf(stderr, "seed: utxo_lsm_put(%s) returned %ld\n", s->name, r); exit(1); }
    }
    utxo_lsm_close(&lst);
}

int main(void){
    char tmpl[] = "/tmp/txacceptXXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) { perror("mkdtemp"); return 1; }
    if (chdir(dir)) { perror("chdir"); return 1; }

    const msend_t* s = &modern_spends[0];    /* p2wpkh_0 -- used for the valid-accept case */
    const msend_t* s2 = &modern_spends[1];   /* p2wpkh_1 -- a DISTINCT fixture for the corruption
                                               * case, since BIP141 txid excludes witness data, so
                                               * corrupting modern_spends[0]'s own witness signature
                                               * would still compute the SAME txid as its valid
                                               * form -- reusing it would make "not left in the
                                               * mempool" spuriously find the valid tx's own entry. */
    const msend_t* seeds[2] = { s, s2 };
    seed_utxos(seeds, 2);

    if (!tx_dispatch_init()) { fprintf(stderr, "tx_dispatch_init failed\n"); return 1; }
    if (!tx_policy_init()) { fprintf(stderr, "tx_policy_init failed\n"); return 1; }
    mpool_init(mp_area, 1024, mp_blob, sizeof mp_blob);

    u8 txid[32], tbuf[4096];
    if (!tx_txid(txid, s->tx, (unsigned long)s->txlen, tbuf, sizeof tbuf)) {
        fprintf(stderr, "tx_txid failed\n"); return 1;
    }

    printf("== valid spend through the real tx_accept_validate pipeline ==\n");
    long acc = tx_accept_validate(mp_area, txid, s->tx, (unsigned long)s->txlen);
    ck("valid tx accepted", acc == 1);
    unsigned long mlen = 0;
    const u8* found = mpool_get(mp_area, txid, &mlen);
    ck("accepted tx is actually stored in the mempool", found != NULL && mlen == (unsigned long)s->txlen);

    printf("\n== corrupted-signature spend must reject AND not leave a phantom mempool entry ==\n");
    static u8 badtx[1024];
    memcpy(badtx, s2->tx, s2->txlen);
    int badtxlen = s2->txlen;
    /* locate the witness signature by its own known bytes (from modern_
     * spend.h's wit[0]/witlen[0]) rather than assuming a fixed DER length
     * byte -- that varies per signature (R/S leading-zero-byte padding). */
    int found_sig = -1;
    const u8* sig0 = s2->wit[0]; int sig0len = s2->witlen[0];
    for (int k = 0; k + sig0len <= badtxlen; k++){
        if (memcmp(badtx+k, sig0, sig0len) == 0){ found_sig = k; break; }
    }
    ck("located p2wpkh sig for corruption", found_sig >= 0);
    if (found_sig >= 0) badtx[found_sig+6] ^= 0x01;

    u8 badtxid[32];
    tx_txid(badtxid, badtx, (unsigned long)badtxlen, tbuf, sizeof tbuf);
    long acc2 = tx_accept_validate(mp_area, badtxid, badtx, (unsigned long)badtxlen);
    ck("corrupted-sig tx rejected", acc2 == 0);
    unsigned long mlen2 = 0;
    const u8* found2 = mpool_get(mp_area, badtxid, &mlen2);
    ck("rejected tx is NOT left in the mempool", found2 == NULL);

    printf("\n%s (%d checks, %d failures)\n", g_fails==0 ? "ALL PASS" : "SOME FAILED", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
