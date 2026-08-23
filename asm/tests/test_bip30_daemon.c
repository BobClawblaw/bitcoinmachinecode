/* test_bip30_daemon.c -- BIP30 in the DAEMON's apply path, not in a shim.
 *
 * WHY THIS EXISTS
 *
 *   BIP30 already had a differential against Core (validation/bip30_diff.py,
 *   replaying real mainnet blocks 0..91,900) and a smoke test
 *   (tests/test_bip30). Both passed. Both drove tests/bip30_shim.c -- which
 *   IMPLEMENTS the rule itself and is not linked into daemon/bitcoind. The
 *   daemon had no BIP30 check at all: daemon/tx_verify.c's utxo_lsm_get calls
 *   are all prevout lookups for inputs being SPENT, utxo_live.c's
 *   duplicate-outpoint pass is an IN-BLOCK double-spend guard (a different
 *   rule), and utxo_lsm_put's "already present" return was discarded by
 *   `if (r == -1 || r == 2) ctx->fatal = 1;`.
 *
 *   So a block creating an outpoint that already existed unspent was ACCEPTED
 *   by this node and rejected by Core as "bad-txns-BIP30" -- a false accept,
 *   i.e. a chain split, at any height where Core enforces. LOG.md incident
 *   #30. This file tests the path bitcoind actually runs.
 *
 * WHAT IT ASSERTS
 *
 *   1. The GATE. Core does not enforce BIP30 everywhere, and over-enforcing
 *      would false-REJECT real blocks, so the height/hash arithmetic is
 *      asserted directly rather than inferred:
 *        - the two grandfathered duplicate-coinbase blocks (91,842 / 91,880)
 *          skip, but ONLY when the block hash matches too;
 *        - a wrong hash at those heights still enforces;
 *        - <= BIP34Height enforces; >= BIP34_IMPLIES_BIP30_LIMIT enforces.
 *
 *   2. The DETECTION, end to end through utxo_live's real apply path: a block
 *      containing a transaction whose txid already exists as an unspent coin
 *      is REJECTED. The duplicate is genuine -- the transaction is built
 *      first, its real txid computed, and THAT txid seeded into the live set,
 *      so the collision is a true (txid, vout) match rather than a fixture.
 *
 *   3. The CONTROL. The same block, with nothing seeded, is not rejected by
 *      this check -- otherwise "reject everything" would pass part 2.
 *
 * Usage: ./test_bip30_daemon
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
extern int  utxo_live_test_seed(const u8 txid[32], u32 index, u64 value,
                                const u8* spk, u32 spklen);
extern int  utxo_live_test_bip30_enforced(long height, const u8 hash32[32]);
extern void tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);

/* Harness stub, same convention as tests/test_segwit_real.c and
 * tests/test_scriptnum_bool.c: bitcoin_txval_modern.c references this for the
 * mempool-acceptance path, which a block-connect test never reaches. */
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

/* Core display hex, reversed to this codebase's internal order. */
static const u8 H91842[32] = { 0xec,0xca,0xe0,0x00,0xe3,0xc8,0xe4,0xe0,0x93,0x93,0x63,0x60,
                               0x43,0x1f,0x3b,0x76,0x03,0xc5,0x63,0xc1,0xff,0x61,0x81,0x39,
                               0x0a,0x4d,0x0a,0x00,0x00,0x00,0x00,0x00 };
static const u8 H91880[32] = { 0x21,0xd7,0x7c,0xcb,0x4c,0x08,0x38,0x6a,0x04,0xac,0x01,0x96,
                               0xae,0x10,0xf6,0xa1,0xd2,0xc2,0xa3,0x77,0x55,0x8c,0xa1,0x90,
                               0xf1,0x43,0x07,0x00,0x00,0x00,0x00,0x00 };
static const u8 HOTHER[32] = { 0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,
                               0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,
                               0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99 };

/* ---- a minimal, well-formed coinbase-only block ------------------------ */
static u64 put_cb(u8* p, u64 v){                 /* compact size */
    if (v < 0xfd){ *p = (u8)v; return 1; }
    if (v <= 0xffff){ p[0]=0xfd; p[1]=(u8)v; p[2]=(u8)(v>>8); return 3; }
    p[0]=0xfe; p[1]=(u8)v; p[2]=(u8)(v>>8); p[3]=(u8)(v>>16); p[4]=(u8)(v>>24); return 5;
}

/* Builds the coinbase tx into `tx`, returns its length. `tag` varies the
 * scriptSig so different calls produce different txids. */
static u64 build_coinbase(u8* tx, u8 tag){
    u64 n = 0;
    tx[n++]=0x01; tx[n++]=0x00; tx[n++]=0x00; tx[n++]=0x00;      /* version 1 */
    tx[n++]=0x01;                                                 /* 1 input   */
    memset(tx+n, 0, 32); n += 32;                                 /* null prevout */
    tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff;
    tx[n++]=0x04; tx[n++]=tag; tx[n++]=0x11; tx[n++]=0x22; tx[n++]=0x33;  /* scriptSig */
    tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff;       /* sequence  */
    tx[n++]=0x01;                                                 /* 1 output  */
    u64 val = 5000000000ULL;
    for (int i=0;i<8;i++) tx[n++] = (u8)(val >> (8*i));
    tx[n++]=0x02; tx[n++]=0x51; tx[n++]=0x75;                     /* OP_1 OP_DROP */
    tx[n++]=0x00; tx[n++]=0x00; tx[n++]=0x00; tx[n++]=0x00;       /* locktime  */
    return n;
}

/* Wraps one tx in an 80-byte header + varint(1). The header is not checked
 * for PoW by this path, only parsed. */
static u64 build_block(u8* blk, const u8* tx, u64 txlen, u8 hdrtag){
    memset(blk, 0, 80);
    blk[0] = 1; blk[4] = hdrtag;          /* version + a byte of "prev hash" */
    u64 n = 80;
    n += put_cb(blk+n, 1);
    memcpy(blk+n, tx, txlen); n += txlen;
    return n;
}

int main(void){
    tt_isolate();

    printf("--- part 1: the enforcement gate (height/hash arithmetic) ---\n");
    ck("91842 with its real hash -> SKIP (grandfathered)",
       utxo_live_test_bip30_enforced(91842, H91842), 0);
    ck("91880 with its real hash -> SKIP (grandfathered)",
       utxo_live_test_bip30_enforced(91880, H91880), 0);
    ck("91842 with a DIFFERENT hash -> enforce",
       utxo_live_test_bip30_enforced(91842, HOTHER), 1);
    ck("91880 with a DIFFERENT hash -> enforce",
       utxo_live_test_bip30_enforced(91880, HOTHER), 1);
    ck("91842's hash at the WRONG height -> enforce",
       utxo_live_test_bip30_enforced(91880, H91842), 1);
    ck("height 1 -> enforce",            utxo_live_test_bip30_enforced(1, HOTHER), 1);
    ck("height 227931 (BIP34Height) -> enforce (no ancestor above it)",
       utxo_live_test_bip30_enforced(227931, HOTHER), 1);
    ck("height 1983702 (resume limit) -> enforce",
       utxo_live_test_bip30_enforced(1983702, HOTHER), 1);
    ck("height 2000000 -> enforce",      utxo_live_test_bip30_enforced(2000000, HOTHER), 1);
    /* With no store handle the BIP34-ancestor arm is unresolvable, and the
     * gate must fall back to ENFORCE -- over-enforcing can only reject a
     * block no real chain contains; under-enforcing is a chain split. */
    ck("height 500000 with no store handle -> enforce (safe fallback)",
       utxo_live_test_bip30_enforced(500000, HOTHER), 1);

    printf("\n--- part 2: detection through the real apply path ---\n");
    if (utxo_live_init(".") != 1){ printf("FAIL utxo_live_init\n"); return 1; }

    static u8 tx[256], blk[512], scratch[1<<16], txid[32];
    u64 txlen = build_coinbase(tx, 0xAA);
    tx_txid(txid, tx, (unsigned long)txlen, scratch, sizeof scratch);

    /* Seed the coinbase's OWN txid:0 as an unspent coin, so applying the
     * block that creates it is a genuine BIP30 violation. */
    static const u8 spk[3] = { 0x51, 0x75, 0x00 };
    ck("seed (txid,0) as unspent", utxo_live_test_seed(txid, 0, 12345, spk, 2), 1);

    u64 blklen = build_block(blk, tx, txlen, 0x01);
    ck("block re-creating that outpoint at h=1000 -> REJECTED",
       utxo_live_test_apply_block(blk, (unsigned long)blklen, 1000), 0);

    printf("\n--- part 3: control -- the same shape with no collision ---\n");
    static u8 tx2[256], blk2[512];
    u64 tx2len  = build_coinbase(tx2, 0xBB);        /* different scriptSig => different txid */
    u64 blk2len = build_block(blk2, tx2, tx2len, 0x02);
    ck("block creating a FRESH outpoint at h=1000 -> not rejected by BIP30",
       utxo_live_test_apply_block(blk2, (unsigned long)blk2len, 1000), 1);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
