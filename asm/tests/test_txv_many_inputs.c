/* tests/test_txv_many_inputs.c -- a transaction with 24,000 inputs, the most
 * a 4,000,000-weight block can carry (41 bytes per input, counted four
 * times), must connect. tx_verify.c held its per-input table in a fixed
 * 20,000-entry array and answered "input count out of bounds" above it,
 * rejecting a valid block -- the same class as the 2,048-entry BIP68 ledger
 * that rejected mainnet 880,338 the same night (2026-09-09). Core's tx.vin is
 * a vector; the table is sized to the transaction now.
 *
 * Block 150 spends a matured coinbase into 24,000 OP_TRUE outputs (240 KB,
 * well inside the weight limit); block 151 spends all of them in ONE
 * transaction with empty scriptSigs (984 KB base, 3.94 MWU) -- OP_TRUE with an
 * empty scriptSig is a valid spend and costs no sigops. Both blocks must
 * apply, and the set must hold exactly the coins the arithmetic says.
 * Usage: ./test_txv_many_inputs */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "test_tmpdir.h"
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long long u64;
extern long store_init(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  pow_check(const u8 hdr[80]);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
extern void sha256d(u8 out[32], const void* msg, long len);
extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_count(void);
extern long utxo_live_applied_height(void);
extern const char* utxo_live_last_reject(void);
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index, u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen; abort(); }
static int failures = 0;
static void ck(const char* l, long got, long exp){ if (got == exp) printf("PASS %s (got %ld)\n", l, got); else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; } }
static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for (int i = 0; i < 8; i++) p[i] = (u8)(v >> (8*i)); }
static u8* g_scratch; static const unsigned long SCRATCH = 4u << 20;
static long coinbase_tx(u8* q0, u32 tag){
    u8* q = q0; put32(q,1); q+=4; *q++ = 1; memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4; put32(q,0xffffffffu); q+=4; *q++ = 1; put64(q, 50000000ULL); q+=8; *q++ = 1; *q++ = 0x51; put32(q,0); q+=4;
    return q - q0;
}
static void merkle2(u8 out[32], const u8 a[32], const u8 b[32]){ u8 pair[64]; memcpy(pair, a, 32); memcpy(pair+32, b, 32); sha256d(out, pair, 64); }
/* header + varint + txs; mined at the regtest floor */
static long assemble(u8* raw, u8 hash[32], const u8 prev[32], u32 tstamp, const u8* tx0, long l0, const u8* tx1, long l1){
    u8 id0[32], id1[32], root[32]; tx_txid(id0, tx0, (unsigned long)l0, g_scratch, SCRATCH);
    if (tx1){ tx_txid(id1, tx1, (unsigned long)l1, g_scratch, SCRATCH); merkle2(root, id0, id1); } else memcpy(root, id0, 32);
    u8* o = raw; put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, root, 32); o+=32; put32(o, tstamp); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
    *o++ = tx1 ? 2 : 1; memcpy(o, tx0, (size_t)l0); o += l0; if (tx1){ memcpy(o, tx1, (size_t)l1); o += l1; }
    u32 nonce = 0; while (!pow_check(raw)){ nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw); return o - raw;
}
static u8 store_buf[4096];
int main(void){
    tt_isolate(); g_scratch = malloc(SCRATCH);
    memset(store_buf, 0, sizeof store_buf); ck("store_init", store_init(store_buf), 1); ck("utxo_live_init", utxo_live_init("."), 1);
    const unsigned N = 24000;
    u8 prev[32]; memset(prev, 0, 32); u8 cb0_txid[32]; u8 cb[128]; long cbl;
    static u8 raw_small[512];
    for (long h = 0; h < 150; h++){ u8 hash[32]; cbl = coinbase_tx(cb, 0x50000000u + (u32)h);
        if (h == 0) tx_txid(cb0_txid, cb, (unsigned long)cbl, g_scratch, SCRATCH);
        long len = assemble(raw_small, hash, prev, 1800000000u + (u32)h, cb, cbl, 0, 0);
        if (store_append(store_buf, hash, raw_small, len) != h){ printf("FAIL store_append h=%ld\n", h); failures++; }
        memcpy(prev, hash, 32); }
    ck("150 coinbase blocks applied", utxo_live_catchup(store_buf), 150);
    long base_count = utxo_live_count();
    /* block 150: coinbase 0's 0.5 BTC -> 24,000 outputs of 2,000 sat to OP_TRUE */
    u8* fan = malloc(64 + (size_t)N * 10); u8* q = fan; put32(q,1); q+=4; *q++ = 1; memcpy(q, cb0_txid, 32); q+=32; put32(q, 0); q+=4; *q++ = 0; put32(q, 0xffffffffu); q+=4;
    *q++ = 0xfd; *q++ = (u8)(N & 0xff); *q++ = (u8)(N >> 8);
    for (unsigned i = 0; i < N; i++){ put64(q, 2000ULL); q+=8; *q++ = 1; *q++ = 0x51; }
    put32(q, 0); q+=4; long fanl = q - fan; u8 fan_txid[32]; tx_txid(fan_txid, fan, (unsigned long)fanl, g_scratch, SCRATCH);
    u8* raw = malloc(2u << 20); u8 hash[32]; cbl = coinbase_tx(cb, 0x50000000u + 150);
    long len = assemble(raw, hash, prev, 1800000150u, cb, cbl, fan, fanl);
    ck("block 150 (the 24,000-output fan-out) stored at 150", store_append(store_buf, hash, raw, len), 150); memcpy(prev, hash, 32);
    ck("block 150 applied", utxo_live_catchup(store_buf), 1);
    ck("the set grew by the 24,000 outputs plus the coinbase, minus the coin spent", utxo_live_count() - base_count, (long)N + 1 - 1);
    /* block 151: ONE transaction spending all 24,000 with empty scriptSigs */
    u8* big = malloc(64 + (size_t)N * 41); q = big; put32(q,1); q+=4; *q++ = 0xfd; *q++ = (u8)(N & 0xff); *q++ = (u8)(N >> 8);
    for (unsigned i = 0; i < N; i++){ memcpy(q, fan_txid, 32); q+=32; put32(q, i); q+=4; *q++ = 0; put32(q, 0xffffffffu); q+=4; }
    *q++ = 1; put64(q, 40000000ULL); q+=8; *q++ = 1; *q++ = 0x51; put32(q, 0); q+=4; long bigl = q - big;
    printf("the 24,000-input transaction is %ld bytes (%ld weight units in a %ld-byte block)\n", bigl, bigl * 4, bigl + 200);
    cbl = coinbase_tx(cb, 0x50000000u + 151);
    len = assemble(raw, hash, prev, 1800000151u, cb, cbl, big, bigl);
    ck("block 151 (the 24,000-input spend) stored at 151", store_append(store_buf, hash, raw, len), 151);
    long applied = utxo_live_catchup(store_buf);
    if (applied != 1) printf("  reject reason: %s\n", utxo_live_last_reject() ? utxo_live_last_reject() : "(none)");
    ck("block 151 applied: a 24,000-input transaction connects (Core has no input cap; neither do we)", applied, 1);
    ck("applied height is 151", utxo_live_applied_height(), 151);
    ck("the set: the 24,000 coins are gone, their spend's output and the coinbase are in", utxo_live_count() - base_count, 2);
    /* the single-transaction verifier (the mempool's path) parses the same
     * transaction: its per-input table was a fixed 20,000 and answered "input
     * count out of bounds" above it -- Core's tx.vin is a vector */
    { extern int txv_test_parse(const u8* tx, u64 txlen, u64* out_nin, const char** reason);
      u64 nin = 0; const char* why = ""; int rc = txv_test_parse(big, (u64)bigl, &nin, &why);
      if (rc != 1) printf("  parse reason: %s\n", why);
      ck("the single-transaction parser takes 24,000 inputs too (no fixed table)", rc == 1 && nin == N, 1); }
    printf("%s (%d failure(s))\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
