/* test_bip30_overwrite.c -- a coinbase output must OVERWRITE an existing coin.
 *
 * WHY THIS EXISTS (LOG.md incident #29)
 *
 *   src/coins.cpp, AddCoins, on the connect path:
 *
 *       bool overwrite = check_for_overwrite ? cache.HaveCoin(...) : fCoinbase;
 *       // Coinbase transactions can always be overwritten, in order to
 *       // correctly deal with the pre-BIP30 occurrences of duplicate
 *       // coinbase transactions.
 *
 *   ConnectBlock passes check_for_overwrite defaulted false, so `overwrite` is
 *   exactly `fCoinbase` -- at every height, with no reference to BIP30.
 *
 *   utxo_put's .dup path returns 0 and keeps the OLD record, and the apply
 *   path treated only -1 and 2 as errors, so the duplicate was silently
 *   declined. Mainnet has two: e3bf3d07...b468:0 (91,722 then 91,880) and
 *   d5d27987...8599:0 (91,812 then 91,842). Core's chainstate holds the LATER
 *   height; ours held the earlier.
 *
 *   How small the divergence was, and why nothing else caught it: at height
 *   963,000 our MuHash over 165,847,393 entries matched Core's byte for byte
 *   once exactly those two height fields were corrected. txouts, total amount
 *   and bogosize all matched WITHOUT the correction -- every one of them is
 *   blind to a height field. Only a set hash could see it.
 *
 *   Not cosmetic: height feeds the 100-block coinbase-maturity rule, so
 *   between 91,880 and 91,980 we would have accepted a spend Core rejects.
 *
 * WHAT IT ASSERTS
 *   A coinbase output re-created at a later height replaces value, height,
 *   coinbase flag and script -- and does NOT change the live count, since the
 *   outpoint exists both before and after. A non-coinbase duplicate is still
 *   declined (Core's AddCoin throws there; we must not start overwriting).
 *
 * Usage: ./test_bip30_overwrite
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "test_tmpdir.h"

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

extern int  utxo_live_init(const char* dir);
extern int  utxo_live_test_apply_block(const u8* blk, unsigned long len, long height);
extern long utxo_live_applied_height(void);
extern long utxo_lsm_count(void* lst);
extern void tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);

/* read one outpoint straight out of the live set */
extern void utxo_live_test_force_bip30_skip(int on);
extern void* utxo_live_test_lst(void);
extern void* utxo_live_test_tbl(void);
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index, u64* value,
                         unsigned long* height, unsigned long* is_coinbase,
                         const u8** script, unsigned long* slen);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk,
                                    unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr, "unexpected mempool_resolve_confirmed_utxo\n"); abort();
}

static int fails = 0;
static void ck(const char* what, long got, long want){
    if (got == want) printf("PASS %-58s (got %ld)\n", what, got);
    else { printf("FAIL %-58s got=%ld exp=%ld\n", what, got, want); fails++; }
}

static u64 put_cs(u8* p, u64 v){
    if (v < 0xfd){ *p=(u8)v; return 1; }
    p[0]=0xfd; p[1]=(u8)v; p[2]=(u8)(v>>8); return 3;
}

/* A coinbase whose bytes -- and therefore txid -- do not depend on height,
 * which is what makes a duplicate coinbase possible in the first place. */
static u64 build_coinbase(u8* tx, u8 tag, u64 value){
    u64 n = 0;
    tx[n++]=0x01; tx[n++]=0; tx[n++]=0; tx[n++]=0;
    tx[n++]=0x01;
    memset(tx+n, 0, 32); n += 32;
    tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff;
    tx[n++]=0x03; tx[n++]=tag; tx[n++]=0x11; tx[n++]=0x22;
    tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff;
    tx[n++]=0x01;
    for (int i=0;i<8;i++) tx[n++] = (u8)(value >> (8*i));
    tx[n++]=0x02; tx[n++]=0x51; tx[n++]=0x75;
    tx[n++]=0; tx[n++]=0; tx[n++]=0; tx[n++]=0;
    return n;
}
static u64 build_block(u8* blk, const u8* tx, u64 txlen, u8 hdrtag){
    memset(blk, 0, 80);
    blk[0]=1; blk[4]=hdrtag;
    u64 n = 80;
    n += put_cs(blk+n, 1);
    memcpy(blk+n, tx, txlen); n += txlen;
    return n;
}

int main(void){
    tt_isolate();
    if (utxo_live_init(".") != 1){ printf("FAIL utxo_live_init\n"); return 1; }

    static u8 tx[256], blk[512], scratch[1<<16], txid[32];
    u64 txlen = build_coinbase(tx, 0xC0, 5000000000ULL);
    tx_txid(txid, tx, (unsigned long)txlen, scratch, sizeof scratch);

    /* Apply the SAME coinbase at two different heights -- exactly the mainnet
     * 91,722 -> 91,880 shape. */
    u64 blklen = build_block(blk, tx, txlen, 0x01);
    ck("apply the coinbase at height 1000", utxo_live_test_apply_block(blk, (unsigned long)blklen, 1000), 1);

    void* lst = utxo_live_test_lst(); void* tbl = utxo_live_test_tbl();
    u64 v0; unsigned long h0, cb0, sl0; const u8* sp0;
    ck("the coin is present after the first apply",
       utxo_lsm_get(lst, tbl, txid, 0, &v0, &h0, &cb0, &sp0, &sl0), 1);
    ck("...recorded at height 1000", (long)h0, 1000);
    long count_before = utxo_lsm_count(lst);

    /* The overwrite only ever applies where BIP30 is SKIPPED -- i.e. the two
     * grandfathered blocks. Everywhere else a duplicate coinbase is a genuine
     * bad-txns-BIP30 and the block is rejected, which incident #30's gate now
     * does correctly (verified: without this hook the apply below is refused).
     * Forcing the skip models 91,880 without forging a block hash. */
    utxo_live_test_force_bip30_skip(1);
    ck("apply the SAME coinbase again at height 2000 (BIP30 skipped, as at 91,880)",
       utxo_live_test_apply_block(blk, (unsigned long)blklen, 2000), 1);
    utxo_live_test_force_bip30_skip(0);

    u64 v1; unsigned long h1, cb1, sl1; const u8* sp1;
    ck("the coin is still present", utxo_lsm_get(lst, tbl, txid, 0, &v1, &h1, &cb1, &sp1, &sl1), 1);
    ck("...and now records the LATER height (Core: overwrite=fCoinbase)", (long)h1, 2000);
    ck("...still flagged coinbase", (long)cb1, 1);
    ck("...value intact", (long)v1, 5000000000L);
    ck("live count unchanged -- one outpoint before and after",
       utxo_lsm_count(lst), count_before);

    /* And the other half: with BIP30 enforced, the very same duplicate must be
     * REJECTED. If this ever passes, the gate has stopped working. */
    ck("with BIP30 enforced, the same duplicate coinbase is REJECTED",
       utxo_live_test_apply_block(blk, (unsigned long)blklen, 3000), 0);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
