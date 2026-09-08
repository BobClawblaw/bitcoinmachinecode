/* tests/test_coinstats_hist_build.c -- the coinstats history builder over a
 * synthetic four-block chain, checked two ways: every height's block_info
 * and counters against hand-computed values (Core's rules: the genesis
 * coinbase never enters the set, an OP_RETURN output is unspendables.scripts,
 * unclaimed rewards per block), and the MuHash at the tip against a direct
 * fold of the surviving coins -- which exercises the builder's removal
 * algebra (the denominator) and its bookkeeping end to end. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "../daemon/coinstats_hist_fmt.h"
#include "test_tmpdir.h"
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
extern long store_init(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void store_rd_init(void* st);
extern int  tx_txid(void* out, const void* tx, unsigned long txlen, void* buf, unsigned long buflen);
extern void utxo_stats_init(void* st, unsigned long want_muhash, unsigned long excl_genesis);
extern void utxo_stats_add(void* st, const u8* key36, u64 value, u64 code, const u8* script, unsigned long slen);
extern void muhash_finalize(unsigned char out[32], const void* acc);
extern int  csi_hist_query(long h, int want_digest, csi_hist_out_t* o);
extern long csi_hist_first(void), csi_hist_last(void);
static int failures = 0;
static void ck(const char* l, int cond){ if (cond) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); failures++; } }
static u8 store_buf[4096];
typedef struct { u64 value; const u8* script; int slen; } outspec;
/* version | nin (coinbase or one prevout) | nout outputs | locktime; no witness */
static long mk_tx(u8* p, int tag, const u8* prev_txid, u32 prev_vout, const outspec* outs, int nout){
    u8* s = p; *p++ = 1; *p++ = 0; *p++ = 0; *p++ = (u8)tag; *p++ = 1;
    if (prev_txid){ memcpy(p, prev_txid, 32); p += 32; memcpy(p, &prev_vout, 4); p += 4; }
    else { memset(p, 0, 32); p += 32; memset(p, 0xff, 4); p += 4; }
    *p++ = 0; memset(p, 0xff, 4); p += 4;
    *p++ = (u8)nout;
    for (int i = 0; i < nout; i++){ memcpy(p, &outs[i].value, 8); p += 8; *p++ = (u8)outs[i].slen; memcpy(p, outs[i].script, (size_t)outs[i].slen); p += outs[i].slen; }
    memset(p, 0, 4); p += 4; return p - s;
}
static void p2wpkh(u8* spk, u8 fill){ spk[0] = 0x00; spk[1] = 0x14; memset(spk + 2, fill, 20); }
int main(void){
    char tool[4096]; if (!getcwd(tool, sizeof tool - 48)) return 1; strcat(tool, "/daemon/bmc_build_coinstats_hist");
    tt_isolate();
    memset(store_buf, 0, sizeof store_buf); ck("store_init", store_init(store_buf) == 1);
    static u8 blk[4][8192]; long blen[4]; u8 hash[4][32]; static u8 scratch[16384]; u8 txid[6][32];
    u8 G[22], A[22], B[22]; p2wpkh(G, 0x01); p2wpkh(A, 0x11); p2wpkh(B, 0x22); u8 nulldata[3] = {0x6a, 0x01, 0xaa};
    for (int h = 0; h < 4; h++){ memset(blk[h], 0xA0 + h, 80); memset(hash[h], 0xB0 + h, 32); }
    #define BTC(x) ((u64)((x) * 100000000.0 + 0.5))
    /* block 0: a coinbase of 50 to G -- the genesis rule: never in the set */
    { outspec o[1] = {{BTC(50), G, 22}}; blk[0][80] = 1; long l = mk_tx(blk[0] + 81, 0, 0, 0, o, 1); blen[0] = 81 + l; tx_txid(txid[0], blk[0] + 81, l, scratch, sizeof scratch); }
    /* block 1: coinbase 50 to A */
    { outspec o[1] = {{BTC(50), A, 22}}; blk[1][80] = 1; long l = mk_tx(blk[1] + 81, 1, 0, 0, o, 1); blen[1] = 81 + l; tx_txid(txid[1], blk[1] + 81, l, scratch, sizeof scratch); }
    /* block 2: coinbase 50 to B; tx spends block 1's coinbase (50) -> 30 to A, 19.999 to B, 0.001 OP_RETURN */
    { outspec cb[1] = {{BTC(50), B, 22}}; outspec o[3] = {{BTC(30), A, 22}, {BTC(19.999), B, 22}, {BTC(0.001), nulldata, 3}};
      blk[2][80] = 2; long la = mk_tx(blk[2] + 81, 2, 0, 0, cb, 1); long lb = mk_tx(blk[2] + 81 + la, 3, txid[1], 0, o, 3); blen[2] = 81 + la + lb;
      tx_txid(txid[2], blk[2] + 81, la, scratch, sizeof scratch); tx_txid(txid[3], blk[2] + 81 + la, lb, scratch, sizeof scratch); }
    /* block 3: coinbase 50.3 to B (0.2 of subsidy + fee unclaimed); tx spends tx3:0 (30) -> 29.5 to B (fee 0.5) */
    { outspec cb[1] = {{BTC(50.3), B, 22}}; outspec o[1] = {{BTC(29.5), B, 22}};
      blk[3][80] = 2; long la = mk_tx(blk[3] + 81, 4, 0, 0, cb, 1); long lb = mk_tx(blk[3] + 81 + la, 5, txid[3], 0, o, 1); blen[3] = 81 + la + lb;
      tx_txid(txid[4], blk[3] + 81, la, scratch, sizeof scratch); tx_txid(txid[5], blk[3] + 81 + la, lb, scratch, sizeof scratch); }
    for (int h = 0; h < 4; h++) ck("store_append", store_append(store_buf, hash[h], blk[h], blen[h]) == h);
    store_rd_init(store_buf);
    { char cmd[4300]; snprintf(cmd, sizeof cmd, "BMC_CHAIN=regtest %s . 3 2 2>/dev/null", tool); ck("builder ran to height 3 with two workers", system(cmd) == 0); }
    ck("rows cover 0..3", csi_hist_first() == 0 && csi_hist_last() == 3);
    csi_hist_out_t o;
    ck("h0: the genesis coinbase never enters the set: txouts 0, amount 0; genesis 50, unclaimed 0", csi_hist_query(0, 0, &o) == 1 && o.txouts == 0 && o.amount == 0 && o.d_genesis == BTC(50) && o.d_unclaimed == 0 && o.subsidy == BTC(50));
    ck("h1: 1 coin, 50 BTC; coinbase 50, unclaimed 0", csi_hist_query(1, 0, &o) == 1 && o.txouts == 1 && o.amount == BTC(50) && o.d_coinbase == BTC(50) && o.d_prevout == 0 && o.d_unclaimed == 0);
    ck("h2: 3 coins, 99.999 BTC; prevout_spent 50, coinbase 50, new_outputs 49.999, scripts 0.001, unclaimed 0",
       csi_hist_query(2, 0, &o) == 1 && o.txouts == 3 && o.amount == BTC(99.999) && o.d_prevout == BTC(50) && o.d_coinbase == BTC(50) && o.d_new_ex_cb == BTC(49.999) && o.d_scripts == BTC(0.001) && o.d_unclaimed == 0);
    ck("h3: 4 coins, 149.799 BTC; prevout_spent 30, coinbase 50.3, new_outputs 29.5, unclaimed 0.2",
       csi_hist_query(3, 1, &o) == 1 && o.txouts == 4 && o.amount == BTC(149.799) && o.d_prevout == BTC(30) && o.d_coinbase == BTC(50.3) && o.d_new_ex_cb == BTC(29.5) && o.d_unclaimed == BTC(0.2) && o.digest_valid);
    /* the MuHash at the tip against a direct fold of the four surviving coins */
    { static u8 st[512] __attribute__((aligned(16))); utxo_stats_init(st, 1, 0); u8 key[36]; u32 v;
      memcpy(key, txid[2], 32); v = 0; memcpy(key + 32, &v, 4); utxo_stats_add(st, key, BTC(50), (2ULL << 1) | 1, B, 22);       /* block 2 coinbase */
      memcpy(key, txid[3], 32); v = 1; memcpy(key + 32, &v, 4); utxo_stats_add(st, key, BTC(19.999), (2ULL << 1) | 0, B, 22);   /* tx3:1 */
      memcpy(key, txid[4], 32); v = 0; memcpy(key + 32, &v, 4); utxo_stats_add(st, key, BTC(50.3), (3ULL << 1) | 1, B, 22);     /* block 3 coinbase */
      memcpy(key, txid[5], 32); v = 0; memcpy(key + 32, &v, 4); utxo_stats_add(st, key, BTC(29.5), (3ULL << 1) | 0, B, 22);     /* tx5:0 */
      u8 want[32]; muhash_finalize(want, st + 96);
      ck("the digest at height 3 equals a direct fold of the surviving coins (numerator x denominator^-1 == the set)", !memcmp(want, o.digest, 32));
      csi_hist_out_t o2; csi_hist_query(2, 1, &o2);
      ck("the digest at height 2 differs from height 3's", memcmp(o2.digest, o.digest, 32) != 0); }
    printf("%s (%d failure(s))\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
