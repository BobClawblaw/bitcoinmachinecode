/* test_taproot_parallel_arena -- the fixture PERF_SCOPE.md section 14.7 asks
 * for by name:
 *
 *   "The block that a wrong shared arena would break first is one where two
 *    transactions with DIFFERENT input counts verify concurrently; a fixture
 *    with that shape specifically, not just 'a busy block'."
 *
 * Taproot inputs used to be verified in a sequential pass, one transaction at
 * a time, against a scratch arena rebuilt per transaction. They now ride the
 * worker pool alongside every other shape, reading one per-BLOCK arena whose
 * per-transaction descriptor is (po/am/sp/ns offsets + nin). Every way of
 * getting that wrong -- a stale descriptor index, a shared write cursor, a
 * worker rebuilding into the arena, an off-by-one in the packed scriptPubKey
 * array -- makes one transaction hash another transaction's bytes or another
 * transaction's input count. The result is a CORRUPTED SIGHASH: silent, no
 * error, no bounds violation, just a verdict that disagrees with Core.
 *
 * Transactions that all have the SAME input count hide most of that: the
 * arrays are the same size, so a wrong base offset still lands on a
 * plausibly-shaped record. So the fixture (tests/taproot_arena_vec.h, from
 * validation/fetch_taproot_arena.py) is real mainnet taproot transactions
 * chosen to span as many DISTINCT input counts as block 825,000 offers, and
 * this test drives them at each other in three shapes:
 *
 *   1  PAIRWISE. Every ordered pair of fixture transactions with DIFFERENT
 *      input counts, as a two-transaction block. This is the literal minimal
 *      case section 14.7 names.
 *   2  INTERLEAVED. All of them, ordered largest-nin against smallest-nin and
 *      replicated until there is enough work to occupy the whole pool, run
 *      repeatedly -- because the bug is scheduling-dependent and one run can
 *      get lucky.
 *   3  REJECT. Each transaction's taproot witness corrupted in turn inside
 *      the interleaved block, requiring the block to be rejected AND
 *      fail_tx_index to name exactly that transaction. That is the
 *      false-accept direction, which is the one that matters.
 *
 * Ground truth is Bitcoin Core: every transaction here is one Core accepted
 * into its chain at height 825,000, with the amounts and scriptPubKeys Core
 * itself reports for their prevouts. The blocks assembled below are synthetic
 * (a transaction may appear more than once), which is inside
 * tx_verify_block_connect_all's documented contract -- duplicate-outpoint
 * detection is the CALLER's whole-block check, and this file is the caller.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
#include "taproot_arena_vec.h"

typedef struct { const u8* ptr; u64 len; u8 txid[32]; u32 pn_in; } block_tx_t;
extern int tx_verify_block_connect(const u8* tx, u64 txlen, long height,
                                   const u8 block_hash32[32], void* lst, void* u,
                                   const char** reason);
extern int tx_verify_block_connect_all(const block_tx_t* txs, u64 ntx, long height,
                                       const u8 block_hash32[32], void* lst, void* u, void* bx,
                                       u64* fail_tx_index, const char** reason);
extern void block_hash(u8 out[32], const u8 hdr[80]);

/* ---- prevout table ------------------------------------------------------ */
typedef struct { u8 key[36]; u64 value; u32 spklen; u8 spk[128]; } prev_t;
static prev_t g_prev[TAV_NPREV];
static long g_nprev;
static int prev_cmp(const void* a, const void* b){ return memcmp(a, b, 36); }

long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index,
                  u64* value, u64* height, u64* coinbase,
                  const u8** spk, unsigned long* spklen){
    (void)lst; (void)u;
    static u8 scratch[128];
    u8 key[36]; memcpy(key, txid, 32); memcpy(key+32, &index, 4);
    prev_t* e = bsearch(key, g_prev, g_nprev, sizeof(prev_t), prev_cmp);
    if (!e) return 0;
    memset(scratch, 0xEE, sizeof scratch);
    memcpy(scratch, e->spk, e->spklen);
    *value = e->value; *height = 1; *coinbase = 0;
    *spk = scratch; *spklen = e->spklen;
    return 1;
}
long bidx_get(void* bx, u32 tx_index, const u8 txid[32], u32 index,
              u64* value, u64* height, u64* coinbase,
              const u8** spk, unsigned long* spklen){
    (void)bx;(void)tx_index;(void)txid;(void)index;(void)value;(void)height;(void)coinbase;(void)spk;(void)spklen;
    return -1;
}
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk, unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr,"unexpected mempool_resolve_confirmed_utxo\n"); abort();
}

static int hx(const char* h, u8* out, long cap){ long n=0; for(; h[0]&&h[1]&&n<cap; h+=2,n++){ unsigned v; sscanf(h,"%2x",&v); out[n]=(u8)v; } return (int)n; }

/* ---- the assembled block ------------------------------------------------ */
#define MAX_COPIES 64
#define MAX_BLK    (24<<20)
static u8  g_blk[MAX_BLK];
static u64 g_blen;
static block_tx_t g_txs[1 + MAX_COPIES*TAV_NTX];
static u64 g_ntx;
static u64 g_txoff[1 + MAX_COPIES*TAV_NTX];   /* byte offset of each tx in g_blk */
static u8  g_bh[32];

/* Decoded fixture transactions, kept once so the block can be reassembled. */
static u8* g_txbytes[TAV_NTX];
static long g_txlen[TAV_NTX];
static u8* g_cb; static long g_cblen;

/* order[]: fixture indices, largest-nin against smallest-nin. */
static unsigned g_order[TAV_NTX];

static void put_cs(u8** d, u64 n){
    if (n < 0xfd) { *(*d)++ = (u8)n; return; }
    if (n <= 0xffff){ *(*d)++ = 0xfd; *(*d)++ = (u8)n; *(*d)++ = (u8)(n>>8); return; }
    *(*d)++ = 0xfe; for (int i=0;i<4;i++) *(*d)++ = (u8)(n>>(8*i));
}

/* Assemble a block from `list` (fixture indices), `copies` times over. */
static void build(const unsigned* list, u64 nlist, int copies){
    u8* d = g_blk;
    hx(TAV_HEADER_HEX, d, 80); d += 80;
    u64 ntx = 1 + nlist*(u64)copies;
    put_cs(&d, ntx);
    g_ntx = 0;
    g_txoff[g_ntx] = (u64)(d - g_blk);
    memcpy(d, g_cb, g_cblen);
    g_txs[g_ntx].ptr = d; g_txs[g_ntx].len = (u64)g_cblen; g_txs[g_ntx].pn_in = 1;
    memset(g_txs[g_ntx].txid, 0, 32);
    d += g_cblen; g_ntx++;
    for (int c=0;c<copies;c++){
        for (u64 i=0;i<nlist;i++){
            unsigned f = list[i];
            g_txoff[g_ntx] = (u64)(d - g_blk);
            memcpy(d, g_txbytes[f], (size_t)g_txlen[f]);
            g_txs[g_ntx].ptr = d; g_txs[g_ntx].len = (u64)g_txlen[f];
            g_txs[g_ntx].pn_in = TAV_TX[f].nin;
            memset(g_txs[g_ntx].txid, 0, 32);
            d += g_txlen[f]; g_ntx++;
        }
    }
    g_blen = (u64)(d - g_blk);
}

/* Which fixture index does assembled tx t hold? (t >= 1) */
static unsigned slot_fixture(const unsigned* list, u64 nlist, u64 t){
    return list[(t-1) % nlist];
}

int main(void){
    long fails = 0;

    /* ---- load prevouts ---- */
    for (u64 i=0;i<TAV_NPREV;i++){
        prev_t* e = &g_prev[g_nprev++];
        u8 disp[32]; hx(TAV_PREV[i].txid_hex, disp, 32);
        for (int k=0;k<32;k++) e->key[k] = disp[31-k];      /* display -> wire */
        u32 idx = TAV_PREV[i].index; memcpy(e->key+32, &idx, 4);
        e->value = TAV_PREV[i].value;
        e->spklen = (u32)hx(TAV_PREV[i].spk_hex, e->spk, sizeof e->spk);
    }
    qsort(g_prev, g_nprev, sizeof(prev_t), prev_cmp);

    /* ---- decode the fixture transactions ---- */
    g_cblen = (long)strlen(TAV_COINBASE_HEX)/2;
    g_cb = malloc((size_t)g_cblen); hx(TAV_COINBASE_HEX, g_cb, g_cblen);
    u64 sum_nin = 0;
    for (u64 i=0;i<TAV_NTX;i++){
        g_txlen[i] = (long)strlen(TAV_TX[i].tx_hex)/2;
        g_txbytes[i] = malloc((size_t)g_txlen[i]);
        hx(TAV_TX[i].tx_hex, g_txbytes[i], g_txlen[i]);
        sum_nin += TAV_TX[i].nin;
    }

    /* ---- the fixture must actually have the shape this test is about ---- */
    {
        unsigned seen[64]; int ns = 0;
        for (u64 i=0;i<TAV_NTX;i++){
            int dup = 0;
            for (int k=0;k<ns;k++) if (seen[k] == TAV_TX[i].nin) dup = 1;
            if (!dup && ns < 64) seen[ns++] = TAV_TX[i].nin;
        }
        printf("fixture: %d transactions, %d distinct input counts, %llu inputs total\n",
               (int)TAV_NTX, ns, (unsigned long long)sum_nin);
        if (ns < 8){
            printf("FAIL: fixture degraded to %d distinct input counts (need >= 8)\n", ns);
            fails++;
        }
    }

    /* ---- interleave order: largest against smallest ---- */
    {
        unsigned by_nin[TAV_NTX];
        for (u64 i=0;i<TAV_NTX;i++) by_nin[i] = (unsigned)i;
        for (u64 a=0;a<TAV_NTX;a++) for (u64 b=a+1;b<TAV_NTX;b++)
            if (TAV_TX[by_nin[b]].nin > TAV_TX[by_nin[a]].nin){
                unsigned t = by_nin[a]; by_nin[a] = by_nin[b]; by_nin[b] = t;
            }
        u64 lo = 0, hi = TAV_NTX-1, o = 0;
        while (lo <= hi){
            g_order[o++] = by_nin[lo];
            if (lo != hi) g_order[o++] = by_nin[hi];
            lo++; if (hi == 0) break; hi--;
        }
    }

    u8 hdr[80]; hx(TAV_HEADER_HEX, hdr, 80);
    block_hash(g_bh, hdr);
    {   /* the header must really be block 825,000's -- the taproot flag
         * schedule and Core's one by-hash exception both key off this */
        u8 want[32], disp[32]; hx(TAV_BLOCK_HASH, disp, 32);
        for (int k=0;k<32;k++) want[k] = disp[31-k];
        if (memcmp(want, g_bh, 32) != 0){ printf("FAIL: header hash mismatch\n"); fails++; }
    }

    /* ---- 1: PAIRWISE, every ordered pair with different input counts ---- */
    {
        long pairs = 0, bad = 0;
        for (u64 a=0;a<TAV_NTX;a++) for (u64 b=0;b<TAV_NTX;b++){
            if (a == b || TAV_TX[a].nin == TAV_TX[b].nin) continue;
            unsigned list[2] = { (unsigned)a, (unsigned)b };
            build(list, 2, 1);
            u64 ft = ~0ull; const char* why = "?";
            if (tx_verify_block_connect_all(g_txs, g_ntx, TAV_HEIGHT, g_bh,
                                            NULL, NULL, NULL, &ft, &why) != 1){
                if (bad < 5) printf("  FAIL 1: pair nin=%u,%u REJECTED tx=%llu: %s\n",
                                    TAV_TX[a].nin, TAV_TX[b].nin, (unsigned long long)ft, why);
                bad++;
            }
            pairs++;
        }
        printf("  1  pairwise blocks    %ld ordered pairs, different input counts   %s\n",
               pairs, bad?"FAIL":"ok");
        fails += bad;
    }

    /* ---- 2: INTERLEAVED, replicated, repeated ---- */
    int copies = 1;
    while (copies < MAX_COPIES && sum_nin*(u64)copies < 4096) copies++;
    {
        long bad = 0;
        const int REPEATS = 25;
        build(g_order, TAV_NTX, copies);
        for (int r=0;r<REPEATS;r++){
            u64 ft = ~0ull; const char* why = "?";
            if (tx_verify_block_connect_all(g_txs, g_ntx, TAV_HEIGHT, g_bh,
                                            NULL, NULL, NULL, &ft, &why) != 1){
                printf("  FAIL 2: run %d REJECTED tx=%llu: %s\n", r, (unsigned long long)ft, why);
                bad++; break;
            }
        }
        printf("  2  interleaved block  %llu tx (%d copies), %llu inputs, x%d runs   %s\n",
               (unsigned long long)(g_ntx-1), copies,
               (unsigned long long)(sum_nin*(u64)copies), REPEATS, bad?"FAIL":"ok");
        fails += bad;
    }

    /* ---- 3: REJECT -- every fixture tx, in the first and the last copy ---- */
    {
        long bad = 0, done = 0;
        build(g_order, TAV_NTX, copies);
        for (u64 t=1; t<g_ntx; t++){
            /* only the first and last copy of each fixture tx, to keep this
             * proportional: 2 * TAV_NTX whole-block verifications */
            u64 slot = (t-1) / TAV_NTX;
            if (slot != 0 && slot != (u64)copies-1) continue;
            unsigned f = slot_fixture(g_order, TAV_NTX, t);
            u64 co = g_txoff[t] + TAV_TX[f].corrupt_off;
            u8 save = g_blk[co]; g_blk[co] ^= 0x01;
            u64 ft = ~0ull; const char* why = "?";
            int r = tx_verify_block_connect_all(g_txs, g_ntx, TAV_HEIGHT, g_bh,
                                                NULL, NULL, NULL, &ft, &why);
            g_blk[co] = save;
            if (r != 0){
                if (bad < 5) printf("  FAIL 3: block ACCEPTED with tx %llu (nin=%u) corrupted\n",
                                    (unsigned long long)t, TAV_TX[f].nin);
                bad++;
            } else if (ft != t){
                if (bad < 5) printf("  FAIL 3: corrupted tx %llu (nin=%u), blamed tx %llu (%s)\n",
                                    (unsigned long long)t, TAV_TX[f].nin, (unsigned long long)ft, why);
                bad++;
            } else if (strncmp(why, "p2tr", 4) != 0){
                if (bad < 5) printf("  FAIL 3: tx %llu rejected for the wrong reason: %s\n",
                                    (unsigned long long)t, why);
                bad++;
            }
            done++;
        }
        printf("  3  reject in place    %ld corrupted tx, fail_tx_index exact   %s\n",
               done, bad?"FAIL":"ok");
        fails += bad;
    }

    /* ---- 4: the single-transaction entry point, accept and reject ---- */
    {
        long bad = 0;
        for (u64 i=0;i<TAV_NTX;i++){
            const char* why = "?";
            if (tx_verify_block_connect(g_txbytes[i], (u64)g_txlen[i], TAV_HEIGHT,
                                        g_bh, NULL, NULL, &why) != 1){
                if (bad < 5) printf("  FAIL 4: tx nin=%u REJECTED: %s\n", TAV_TX[i].nin, why);
                bad++;
            }
            u8* c = &g_txbytes[i][TAV_TX[i].corrupt_off];
            u8 save = *c; *c ^= 0x01;
            why = "?";
            int r = tx_verify_block_connect(g_txbytes[i], (u64)g_txlen[i], TAV_HEIGHT,
                                            g_bh, NULL, NULL, &why);
            *c = save;
            if (r != 0 || strncmp(why, "p2tr", 4) != 0){
                if (bad < 5) printf("  FAIL 4: tx nin=%u corrupted -> %d (%s)\n",
                                    TAV_TX[i].nin, r, why);
                bad++;
            }
        }
        printf("  4  single-tx path     %d tx, accept and corrupted-reject   %s\n",
               (int)TAV_NTX, bad?"FAIL":"ok");
        fails += bad;
    }

    if (fails){ printf("TESTS FAILED (%ld failures)\n", fails); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n");
    return 0;
}
