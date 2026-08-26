/* tests/test_mempool_consensus_verify.c -- mempool admission now runs the
 * CONSENSUS verifier (tx_verify_mempool) through a resolver that sees the
 * confirmed set plus unconfirmed mempool parents. The capabilities that
 * unlocks, each pinned here with REAL signed transactions (wallet_send_tx's
 * legacy P2PKH signer -- the exact class the old partial validator refused
 * as "unsupported prevout script type"):
 *
 *   1. a legacy P2PKH spend is ACCEPTED (the missing verify arm);
 *   2. a spend of an UNCONFIRMED MEMPOOL PARENT is accepted (child of #1's
 *      tx, whose outputs exist nowhere in the UTXO set);
 *   3. an unknown outpoint rejects with the missing-inputs class (-25);
 *   4. coinbase maturity is enforced against the tip: the same signed spend
 *      rejects at 51 confirmations and accepts at 201.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned long u64l;
typedef unsigned int u32;

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index,
                         unsigned long long value, unsigned long long height,
                         unsigned long long is_coinbase, const u8* script, u32 slen);
extern void utxo_lsm_close(void* lst);
extern const u8* mpool_get(void* mp, const u8 txid[32], unsigned long* out_len);
extern void mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern int  tx_dispatch_init(void);
extern int  tx_policy_init(void);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
extern long tx_accept_validate(void* mp_area, const u8 txid[32], const u8* tx, unsigned long len);
extern long tx_accept_validate_reason(void* mp_area, const u8 txid[32], const u8* tx,
                                      unsigned long len, char* reason, unsigned long rcap);
extern void tx_accept_set_tip(long tip);
extern long wallet_send_tx(unsigned char* out_tx, long cap,
                           const unsigned char toutid[][32], const unsigned long* tidx,
                           const unsigned long long* tval, unsigned long n,
                           const unsigned char to_h160[20],
                           unsigned long long amount, unsigned long long fee,
                           const unsigned char priv_be[32], unsigned long locktime);
extern void wallet_key_h160(unsigned char h[20], const unsigned char priv_be[32]);
extern void wallet_make_p2pkh_script(unsigned char script[25], const unsigned char priv_be[32]);

struct lsm_state {
    long log_fd, idx_fd;
    unsigned long long log_len, ckpt_log_off, ckpt_n;
    unsigned long long op_count, op_threshold, fill_threshold;
    void* tomb_buf; unsigned long long tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; unsigned long long manifest_cap, manifest_n;
    void* scratch_buf; unsigned long long scratch_cap;
    unsigned long long next_run_no;
    void* tomb_hash_buf; unsigned long long tomb_hash_mask;
};
#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536

static u8 mp_area[40 + 1024*48 + 8];
static u8 mp_blob[2<<20];
static int g_fails = 0, g_checks = 0;
static void ck(const char* name, int cond){
    g_checks++;
    if (cond) printf("  ok  %s\n", name);
    else { g_fails++; printf("  FAIL %s\n", name); }
}

/* seed the on-disk LSM with P2PKH coins (value/height/coinbase per entry) */
typedef struct { const u8* txid; u32 idx; unsigned long long val, height, cb; const u8* spk; } seed_t;
static void seed_utxos(const seed_t* s, int n){
    unsigned long slots = 1UL<<16;
    void* table = malloc((size_t)utxo_struct_size(slots));
    void* blob = malloc(64UL<<20);
    utxo_init(table, slots, blob, 64UL<<20);
    struct lsm_state lst; memset(&lst, 0, sizeof lst);
    unsigned long long op_th = slots*2, tomb_cap = op_th, desc_cap = slots*3;
    lst.op_threshold = op_th; lst.fill_threshold = slots*3/4;
    lst.tomb_buf = malloc(tomb_cap*36); lst.tomb_cap = tomb_cap;
    lst.manifest_buf = malloc(256*16); lst.manifest_cap = 256;
    lst.scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    lst.scratch_buf = malloc(lst.scratch_cap);
    if (utxo_lsm_init(&lst) != 1){ fprintf(stderr, "lsm init failed\n"); exit(1); }
    for (int i=0;i<n;i++)
        if (utxo_lsm_put(&lst, table, s[i].txid, s[i].idx, s[i].val, s[i].height,
                         s[i].cb, s[i].spk, 25) != 1){ fprintf(stderr,"seed failed\n"); exit(1); }
    utxo_lsm_close(&lst);
}

int main(void){
    tt_isolate();

    u8 priv[32], dpriv[32], cpriv[32];
    for (int i=0;i<32;i++){ priv[i]=(u8)(0xaa+i); dpriv[i]=(u8)(0x55+i); cpriv[i]=(u8)(0x11+i); }
    u8 scr[25], cscr[25], to_h[20];
    wallet_make_p2pkh_script(scr, priv);       /* coin 1 pays priv's P2PKH */
    wallet_make_p2pkh_script(cscr, cpriv);     /* coinbase coin pays cpriv */
    wallet_key_h160(to_h, dpriv);              /* destination = dpriv */

    static u8 tidA[32]; memset(tidA, 0xA1, 32);
    static u8 tidCB[32]; memset(tidCB, 0xC0, 32);
    seed_t seeds[] = {
        { tidA,  0, 10000000ULL, 200, 0, scr  },   /* ordinary P2PKH coin */
        { tidCB, 0, 10000000ULL, 100, 1, cscr },   /* COINBASE coin at h=100 */
    };
    seed_utxos(seeds, 2);

    if (!tx_dispatch_init()){ fprintf(stderr, "tx_dispatch_init failed\n"); return 1; }
    if (!tx_policy_init()){ fprintf(stderr, "tx_policy_init failed\n"); return 1; }
    mpool_init(mp_area, 1024, mp_blob, sizeof mp_blob);
    tx_accept_set_tip(500);                    /* both coins deeply confirmed */

    static u8 scratch[1<<20];
    static u8 tx1[4096], tx2[4096], txm[4096], txcb[4096];

    printf("== 1: legacy P2PKH spend accepted (the missing verify arm) ==\n");
    long n1;
    {
        unsigned long long tval[1] = { 10000000ULL };
        unsigned long tidx[1] = { 0 };
        u8 (*tid)[32] = (u8(*)[32])tidA;
        n1 = wallet_send_tx(tx1, sizeof tx1, tid, tidx, tval, 1, to_h,
                            6000000ULL, 10000ULL, priv, 0);
        ck("signed legacy tx produced", n1 > 0);
        u8 id1[32]; tx_txid(id1, tx1, (unsigned long)n1, scratch, sizeof scratch);
        ck("ACCEPTED into the mempool", tx_accept_validate(mp_area, id1, tx1, (unsigned long)n1) == 1);
        unsigned long ml=0; ck("...and pooled", mpool_get(mp_area, id1, &ml) != NULL);
    }

    printf("\n== 2: spend of an UNCONFIRMED mempool parent accepted ==\n");
    {
        u8 id1[32]; tx_txid(id1, tx1, (unsigned long)n1, scratch, sizeof scratch);
        /* tx1's output 0 pays to_h (dpriv's P2PKH), amount 6,000,000 --
         * that coin exists ONLY in the mempool */
        unsigned long long tval[1] = { 6000000ULL };
        unsigned long tidx[1] = { 0 };
        long n2 = wallet_send_tx(tx2, sizeof tx2, (u8(*)[32])id1, tidx, tval, 1,
                                 to_h, 5000000ULL, 10000ULL, dpriv, 0);
        ck("signed child tx produced", n2 > 0);
        u8 id2[32]; tx_txid(id2, tx2, (unsigned long)n2, scratch, sizeof scratch);
        ck("child of a mempool parent ACCEPTED",
           tx_accept_validate(mp_area, id2, tx2, (unsigned long)n2) == 1);
    }

    printf("\n== 3: unknown outpoint -> missing-inputs class (-25) ==\n");
    {
        static u8 tidZ[32]; memset(tidZ, 0xEE, 32);
        unsigned long long tval[1] = { 10000000ULL };
        unsigned long tidx[1] = { 0 };
        long nm = wallet_send_tx(txm, sizeof txm, (u8(*)[32])tidZ, tidx, tval, 1,
                                 to_h, 6000000ULL, 10000ULL, priv, 0);
        ck("signed orphan produced", nm > 0);
        u8 idm[32]; tx_txid(idm, txm, (unsigned long)nm, scratch, sizeof scratch);
        char reason[128];
        long r = tx_accept_validate_reason(mp_area, idm, txm, (unsigned long)nm,
                                           reason, sizeof reason);
        ck("rejected as missing inputs (-25)", r == -25);
        ck("...with the resolve-stage reason", strstr(reason, "missing/already-spent") != NULL);
    }

    printf("\n== 4: coinbase maturity anchored on the tip ==\n");
    {
        unsigned long long tval[1] = { 10000000ULL };
        unsigned long tidx[1] = { 0 };
        long nc = wallet_send_tx(txcb, sizeof txcb, (u8(*)[32])tidCB, tidx, tval, 1,
                                 to_h, 6000000ULL, 10000ULL, cpriv, 0);
        ck("signed coinbase spend produced", nc > 0);
        u8 idc[32]; tx_txid(idc, txcb, (unsigned long)nc, scratch, sizeof scratch);
        char reason[128];
        tx_accept_set_tip(150);   /* conf at next height 151 - 100 = 51 < 100 */
        long r = tx_accept_validate_reason(mp_area, idc, txcb, (unsigned long)nc,
                                           reason, sizeof reason);
        ck("immature spend rejected", r != 1);
        ck("...as immature", strstr(reason, "immature") != NULL);
        tx_accept_set_tip(300);   /* conf 201 >= 100 */
        ck("mature spend accepted",
           tx_accept_validate(mp_area, idc, txcb, (unsigned long)nc) == 1);
    }

    printf("\n%s (%d checks, %d failures)\n", g_fails==0 ? "ALL PASS" : "SOME FAILED",
           g_checks, g_fails);
    return g_fails ? 1 : 0;
}
