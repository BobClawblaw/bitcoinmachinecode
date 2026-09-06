/* tests/test_coinstats_bulk_seed.c -- the coinstats index does NOT fold per
 * coin during bulk catch-up; it seeds once from a walk at caught-up.
 *
 * The finding (docs/audits/UTXO_INLINE_BUILD_PERF_SCOPE.md, 2026-09-06): on
 * a fresh sync the index was seeded at height 0 and then folded every
 * created output and every spent input through bitcoin_muhash.asm on the
 * connect thread -- ~6.4 billion elements at 1.66 us, the same order as the
 * entire bulk phase. The fix leaves the index invalid while utxo_live is
 * bulk-sized and seeds it from ONE walk of the set at the moment the loop
 * downshifts to steady state.
 *
 * Driven through the REAL connect path (utxo_live_catchup over a mined
 * chain: 150 coinbases, then blocks spending matured OP_TRUE coinbases with
 * empty scriptSigs), with the real observers installed exactly as
 * daemon/main.c installs them:
 *
 *   1. bulk mode: the fold counter is 0 at the moment the caught-up hook
 *      fires (nothing folded across the whole catch-up), coinstats.dat is
 *      ABSENT until then (the RPC cannot serve a stale record), and the
 *      seed folds exactly the set size;
 *   2. the seeded digest and counters equal an independent full walk;
 *   3. negative control -- today's path (steady state, seeded at boot):
 *      every created output AND every spent input is folded (200 elements
 *      for a 160-coin set), the caught-up hook never fires, and the digest
 *      is the SAME as the bulk-mode seed's. Same answer, 200 folds vs 0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long store_init(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  pow_check(const u8 hdr[80]);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
extern void merkle_root(u8 out[32], u8* hashes, long n);

extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_count(void);
extern long utxo_live_applied_height(void);
extern void utxo_live_close(void);
extern void* utxo_live_lst(void);
extern void* utxo_live_table(void);
extern void utxo_live_test_set_bulk_mode(int on);
extern int  utxo_live_bulk_mode(void);
typedef void (*coin_fn)(const u8*, u32, u64, u64, u64, const u8*, unsigned long);
extern void utxo_live_set_coinstats(coin_fn, coin_fn, void (*)(const char*), void (*)(long));
extern void utxo_live_set_coinstats_caught_up(void (*)(void*, void*, long));
extern void undo_set_coin_observer(coin_fn);
extern long utxo_lsm_walk(void* lst, void* u, void* cb, void* ctx);

extern void csi_on_add(const u8*, u32, u64, u64, u64, const u8*, unsigned long);
extern void csi_on_remove(const u8*, u32, u64, u64, u64, const u8*, unsigned long);
extern void csi_invalidate(const char*);
extern void csi_commit(long);
extern int  csi_boot(long);
extern int  csi_seed_from_walk(void*, void*, long);
extern void csi_defer_to_caught_up(void);
extern void csi_on_caught_up(void*, void*, long);
extern int  csi_deferred(void);
extern int  csi_valid(void);
extern int  csi_read_live(long*, unsigned char[32], u64*, u64*, u64*);
extern long csi_file_height(void);
extern u64  csi_test_fold_count(void);

extern void utxo_stats_init(void* st, unsigned long want_muhash, unsigned long excl_genesis);
extern void utxo_stats_add(void* st, const u8 key36[36], unsigned long value,
                           unsigned long code, const u8* script, unsigned long slen);
extern void utxo_stats_finalize(void* st);

/* never reached (no mempool here); bitcoin_mempool_policy.c resolves it */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_coinstats_bulk_seed: unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got == exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
static void ckm(const char* l, int cond){
    if (cond) printf("PASS %s\n", l); else { printf("FAIL %s\n", l); failures++; }
}

static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for (int i = 0; i < 8; i++) p[i] = (u8)(v >> (8*i)); }
static u8 g_txid_scratch[1<<12];

#define CB_TX_LEN 65
static long mk_coinbase_tx(u8* tx, u32 tag){
    u8* q = tx;
    put32(q,1); q+=4; *q++ = 1; memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4; put32(q,0xffffffffu); q+=4;
    *q++ = 1; put64(q, 50000000ULL); q+=8; *q++ = 1; *q++ = 0x51; put32(q,0); q+=4;
    return q - tx;
}

/* Coinbase + nspend txs, tx_j spending spend_txids[j]:0 (empty scriptSig
 * against OP_1 -- valid) into one OP_1 output. Same shape as
 * tests/test_utxo_crash_recovery.c. */
static long mk_and_mine(u8* raw, u8 hash[32], const u8 prev[32],
                        const u8 (*spend_txids)[32], int nspend,
                        u32 tag, u32 tstamp, u8 cb_txid_out[32]){
    u8 txbuf[8][128]; long txlen[8];
    u8 leaves[8*32];
    txlen[0] = mk_coinbase_tx(txbuf[0], tag);
    tx_txid(leaves, txbuf[0], (unsigned long)txlen[0], g_txid_scratch, sizeof g_txid_scratch);
    memcpy(cb_txid_out, leaves, 32);
    for (int j = 0; j < nspend; j++){
        u8* q = txbuf[j+1];
        put32(q,1); q+=4; *q++ = 1;
        memcpy(q, spend_txids[j], 32); q+=32; put32(q,0); q+=4;
        *q++ = 0;                                   /* empty scriptSig */
        put32(q,0xffffffffu); q+=4;
        *q++ = 1; put64(q, 40000000ULL); q+=8; *q++ = 1; *q++ = 0x51;
        put32(q,0); q+=4;
        txlen[j+1] = q - txbuf[j+1];
        tx_txid(leaves + 32*(j+1), txbuf[j+1], (unsigned long)txlen[j+1], g_txid_scratch, sizeof g_txid_scratch);
    }
    u8 root[32];
    if (nspend == 0) memcpy(root, leaves, 32); else merkle_root(root, leaves, nspend+1);
    u8* o = raw;
    put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, root, 32); o+=32;
    put32(o, tstamp); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
    *o++ = (u8)(nspend+1);
    for (int j = 0; j <= nspend; j++){ memcpy(o, txbuf[j], (size_t)txlen[j]); o += txlen[j]; }
    long len = o - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

#define NCB     150      /* coinbase-only heights 0..149 */
#define NSPENDB 10       /* heights 150..159: coinbase + 2 spends of matured coinbases */
#define NBLK    (NCB + NSPENDB)
#define ADDS    (NCB + NSPENDB * 3)   /* 180 created outputs */
#define REMOVES (NSPENDB * 2)         /* 20 spent inputs */
#define SETSIZE (ADDS - REMOVES)      /* 160 live coins */

static u8 store_buf[4096];
static u8 cb_txids[NBLK][32];

/* mine the SAME chain into the store in the current directory */
static void build_chain(void){
    memset(store_buf, 0, sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    u8 prev[32]; memset(prev, 0, 32);
    for (long h = 0; h < NBLK; h++){
        u8 raw[1024], hash[32];
        int ns = 0; u8 sp[2][32];
        if (h >= NCB){ ns = 2; memcpy(sp[0], cb_txids[2*(h-NCB)], 32); memcpy(sp[1], cb_txids[2*(h-NCB)+1], 32); }
        long len = mk_and_mine(raw, hash, prev, sp, ns, 0x30000000u + (u32)h, 1700000000u + (u32)h * 600u, cb_txids[h]);
        long r = store_append(store_buf, hash, raw, len);
        if (r != h){ printf("FAIL store_append h=%ld got=%ld\n", h, r); failures++; }
        memcpy(prev, hash, 32);
    }
}

static void walk_digest(unsigned char out[32], u64* txouts, u64* amount, u64* bogo){
    static u8 st[512] __attribute__((aligned(16)));
    utxo_stats_init(st, 1, 0);
    long n = utxo_lsm_walk(utxo_live_lst(), utxo_live_table(), (void*)utxo_stats_add, st);
    if (n < 0){ fprintf(stderr, "walk failed\n"); exit(1); }
    utxo_stats_finalize(st);
    memcpy(out, st + 64, 32);
    memcpy(txouts, st + 0, 8); memcpy(amount, st + 8, 8); memcpy(bogo, st + 16, 8);
}

/* the caught-up hook, instrumented: what had been folded when it fired? */
static int  hook_fired;
static long hook_height;
static u64  folds_at_hook;
static long file_height_at_hook;
static void instrumented_caught_up(void* lst, void* u, long h){
    hook_fired++; hook_height = h;
    folds_at_hook = csi_test_fold_count();
    file_height_at_hook = csi_file_height();
    csi_on_caught_up(lst, u, h);
}

static void install_observers(void){
    utxo_live_set_coinstats(csi_on_add, csi_on_remove, csi_invalidate, csi_commit);
    undo_set_coin_observer(csi_on_remove);
    utxo_live_set_coinstats_caught_up(instrumented_caught_up);
}

int main(void){
    tt_isolate();

    printf("== 1: bulk mode -- nothing folds during the catch-up; seed at caught-up ==\n");
    if (mkdir("bulk", 0755) || chdir("bulk")){ perror("bulk dir"); return 1; }
    build_chain();
    ck("utxo_live_init", utxo_live_init("."), 1);
    utxo_live_test_set_bulk_mode(1);
    install_observers();
    csi_defer_to_caught_up();                       /* what main.c does when utxo_live_bulk_mode() */
    ckm("index is deferred and invalid before the catch-up", csi_deferred() == 1 && csi_valid() == 0);
    ck("no coinstats.dat while deferred (nothing stale to serve)", csi_file_height(), -1);
    u64 f0 = csi_test_fold_count();
    long applied = utxo_live_catchup(store_buf);
    ck("catch-up applied every block", applied, NBLK);
    ck("live set size", utxo_live_count(), SETSIZE);
    ck("the caught-up hook fired exactly once", hook_fired, 1);
    ck("...at the applied height", hook_height, NBLK - 1);
    /* sampled when the hook fired; if it never fired, everything folded so
     * far was folded DURING the catch-up */
    u64 folds_during = (hook_fired ? folds_at_hook : csi_test_fold_count()) - f0;
    ck("FOLDS DURING THE BULK CATCH-UP (the finding: was 200)", (long)folds_during, 0);
    ck("coinstats.dat still absent when the hook fired", file_height_at_hook, -1);
    ck("the seed walk folded exactly the set size", (long)(csi_test_fold_count() - folds_at_hook), SETSIZE);
    ckm("downshifted to steady state", utxo_live_bulk_mode() == 0);
    ckm("index valid and no longer deferred", csi_valid() == 1 && csi_deferred() == 0);
    long h; unsigned char d_bulk[32]; u64 tx, amt, bg;
    ck("live read", csi_read_live(&h, d_bulk, &tx, &amt, &bg), 1);
    ck("index height == applied height", h, NBLK - 1);
    ck("index txouts", (long)tx, SETSIZE);
    ck("coinstats.dat committed at the applied height", csi_file_height(), NBLK - 1);

    printf("\n== 2: the seeded state equals an independent full walk ==\n");
    unsigned char d_ref[32]; u64 rtx, ramt, rbg;
    walk_digest(d_ref, &rtx, &ramt, &rbg);
    ckm("DIGEST equals the walk", memcmp(d_bulk, d_ref, 32) == 0);
    ckm("counters equal the walk", tx == rtx && amt == ramt && bg == rbg);
    utxo_live_close();

    printf("\n== 3: negative control -- today's path folds every coin inline ==\n");
    if (chdir("..") || mkdir("steady", 0755) || chdir("steady")){ perror("steady dir"); return 1; }
    build_chain();
    ck("utxo_live_init", utxo_live_init("."), 1);
    utxo_live_test_set_bulk_mode(0);
    hook_fired = 0;
    install_observers();
    ck("csi_boot: no file -> seed", csi_boot(utxo_live_applied_height()), 0);
    ck("seed at boot (empty set)", csi_seed_from_walk(utxo_live_lst(), utxo_live_table(), utxo_live_applied_height()), 1);
    u64 f1 = csi_test_fold_count();
    applied = utxo_live_catchup(store_buf);
    ck("catch-up applied every block", applied, NBLK);
    ck("control: every created output and spent input folded inline", (long)(csi_test_fold_count() - f1), ADDS + REMOVES);
    ck("control: the caught-up hook never fires in steady state", hook_fired, 0);
    unsigned char d_inline[32];
    ck("live read", csi_read_live(&h, d_inline, &tx, &amt, &bg), 1);
    ck("index height == applied height", h, NBLK - 1);
    ckm("SAME digest as the bulk-mode seed", memcmp(d_inline, d_bulk, 32) == 0);
    ckm("same counters", tx == rtx && amt == ramt && bg == rbg);
    utxo_live_close();

    printf("\n%s (%d failures)\n", failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
