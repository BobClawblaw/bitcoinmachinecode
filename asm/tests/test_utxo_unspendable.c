/* test_utxo_unspendable.c -- provably-unspendable outputs never enter the set.
 *
 * WHY THIS EXISTS (Core parity, 2026-08-23)
 *
 *   src/coins.cpp, AddCoin:
 *
 *       if (coin.out.scriptPubKey.IsUnspendable()) return;
 *
 *   IsUnspendable() is (size() > 0 && spk[0] == OP_RETURN) || size() > 10000.
 *   Core NEVER writes such an output to its chainstate, at any height. Until
 *   2026-08-23 our apply path stored every output, so the live set carried
 *   ~252M entries Core does not have (~419M raw vs Core's ~166M txouts at tip
 *   963,762) and was only comparable to Core through bitcoin_utxo_stats.asm's
 *   read-time filter. daemon/utxo_live.c's live_on_output (and build_utxo.c's
 *   on_output) now apply the same shared filter at WRITE time.
 *
 * WHAT IT ASSERTS
 *   utxo_script_unspendable matches Core's IsUnspendable on the boundary
 *   cases, a block whose coinbase mixes spendable and OP_RETURN outputs lands
 *   with ONLY the spendable ones present, and the live count counts what Core
 *   would count.
 *
 * Usage: ./test_utxo_unspendable
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
extern long utxo_lsm_count(void* lst);
extern long utxo_script_unspendable(const u8* script, unsigned long slen);
extern void tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
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
    if (got == want) printf("PASS %-62s (got %ld)\n", what, got);
    else { printf("FAIL %-62s got=%ld exp=%ld\n", what, got, want); fails++; }
}

static u64 put_cs(u8* p, u64 v){
    if (v < 0xfd){ *p=(u8)v; return 1; }
    p[0]=0xfd; p[1]=(u8)v; p[2]=(u8)(v>>8); return 3;
}

/* A coinbase with FOUR outputs:
 *   0: spendable   51 75            (OP_TRUE OP_DROP shape the other tests use)
 *   1: OP_RETURN   6a 04 de ad be ef
 *   2: spendable   51 75
 *   3: bare OP_RETURN, zero value   6a          (the classic burn shape)     */
static u64 build_coinbase(u8* tx, u8 tag){
    u64 n = 0;
    tx[n++]=0x01; tx[n++]=0; tx[n++]=0; tx[n++]=0;           /* version */
    tx[n++]=0x01;                                            /* 1 input */
    memset(tx+n, 0, 32); n += 32;                            /* null prevout */
    tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff;  /* index -1 */
    tx[n++]=0x03; tx[n++]=tag; tx[n++]=0x11; tx[n++]=0x22;   /* scriptSig */
    tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff;  /* sequence */
    tx[n++]=0x04;                                            /* 4 outputs */
    u64 v0 = 2500000000ULL;                                  /* out 0 */
    for (int i=0;i<8;i++) tx[n++] = (u8)(v0 >> (8*i));
    tx[n++]=0x02; tx[n++]=0x51; tx[n++]=0x75;
    u64 v1 = 1500000000ULL;                                  /* out 1: OP_RETURN, carries value */
    for (int i=0;i<8;i++) tx[n++] = (u8)(v1 >> (8*i));
    tx[n++]=0x06; tx[n++]=0x6a; tx[n++]=0x04;
    tx[n++]=0xde; tx[n++]=0xad; tx[n++]=0xbe; tx[n++]=0xef;
    u64 v2 = 1000000000ULL;                                  /* out 2 */
    for (int i=0;i<8;i++) tx[n++] = (u8)(v2 >> (8*i));
    tx[n++]=0x02; tx[n++]=0x51; tx[n++]=0x75;
    for (int i=0;i<8;i++) tx[n++] = 0;                       /* out 3: 0 sat */
    tx[n++]=0x01; tx[n++]=0x6a;
    tx[n++]=0; tx[n++]=0; tx[n++]=0; tx[n++]=0;              /* locktime */
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

    /* ---- the filter itself, on Core's IsUnspendable boundaries ---- */
    static u8 big[10002];
    memset(big, 0x51, sizeof big);                 /* OP_TRUE filler, not OP_RETURN */
    u8 opret1[1] = { 0x6a };
    u8 opret2[2] = { 0x6a, 0x00 };
    u8 p2pk_ish[2] = { 0x51, 0x75 };
    ck("bare OP_RETURN (1 byte) is unspendable",   utxo_script_unspendable(opret1, 1), 1);
    ck("OP_RETURN + payload is unspendable",       utxo_script_unspendable(opret2, 2), 1);
    ck("empty script is SPENDABLE (Core: size()>0 required)", utxo_script_unspendable(opret1, 0), 0);
    ck("ordinary script is spendable",             utxo_script_unspendable(p2pk_ish, 2), 0);
    ck("exactly 10000 bytes is spendable (limit is exclusive)", utxo_script_unspendable(big, 10000), 0);
    ck("10001 bytes is unspendable (> MAX_SCRIPT_SIZE)",        utxo_script_unspendable(big, 10001), 1);

    /* ---- write-time behavior through the real apply path ---- */
    if (utxo_live_init(".") != 1){ printf("FAIL utxo_live_init\n"); return 1; }

    static u8 tx[512], blk[1024], scratch[1<<16], txid[32];
    u64 txlen = build_coinbase(tx, 0xC1);
    tx_txid(txid, tx, (unsigned long)txlen, scratch, sizeof scratch);
    u64 blklen = build_block(blk, tx, txlen, 0x01);

    void* lst = utxo_live_test_lst(); void* tbl = utxo_live_test_tbl();
    long count0 = utxo_lsm_count(lst);
    ck("apply a block whose coinbase mixes spendable and OP_RETURN outputs",
       utxo_live_test_apply_block(blk, (unsigned long)blklen, 1000), 1);

    u64 v; unsigned long h, cb, sl; const u8* sp;
    ck("out 0 (spendable) is present",   utxo_lsm_get(lst, tbl, txid, 0, &v, &h, &cb, &sp, &sl), 1);
    ck("out 1 (OP_RETURN + payload) is ABSENT -- Core never stores it",
       utxo_lsm_get(lst, tbl, txid, 1, &v, &h, &cb, &sp, &sl), 0);
    ck("out 2 (spendable) is present",   utxo_lsm_get(lst, tbl, txid, 2, &v, &h, &cb, &sp, &sl), 1);
    ck("out 3 (bare OP_RETURN burn) is ABSENT",
       utxo_lsm_get(lst, tbl, txid, 3, &v, &h, &cb, &sp, &sl), 0);
    ck("live count grew by exactly the 2 outputs Core would count",
       utxo_lsm_count(lst) - count0, 2);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
