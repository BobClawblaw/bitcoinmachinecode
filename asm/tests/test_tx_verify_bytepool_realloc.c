/* tests/test_tx_verify_bytepool_realloc.c -- regression test for a real
 * production bug in daemon/tx_verify.c's g_spk_pool (bytepool_alloc), found
 * 2026-08-20 while investigating a recurring "legacy script verification
 * failed" rejection at real mainnet height 184390 that survived a *fresh*
 * from-scratch UTXO rebuild (ruling out on-disk corruption).
 *
 * Root cause: tx_verify_block_connect_all's Phase 1 resolve loop called
 * bytepool_alloc() once per input, in block order, and stored the RAW
 * POINTER it returned directly in txvb_in_t.spk. bytepool_alloc grows its
 * backing buffer via realloc() when a block's cumulative prevout-script
 * bytes exceed current capacity -- and realloc() is free to relocate the
 * whole buffer. When a LATER input in the same block triggered that
 * relocation, every pointer already handed out to EARLIER inputs in that
 * same loop silently dangled: those entries kept pointing into freed (or
 * reused) memory, so Phase 2's verification read garbage scriptPubKey bytes
 * for them instead of the correct, already-proven-resolved script -- a
 * classic dangling-pointer bug, confirmed via double-read production
 * diagnostics showing correct data at resolve time and corrupted data at
 * verify time for the exact same input.
 *
 * The fix (this commit) changes txvb_in_t.spk from a raw pointer into a
 * stable byte OFFSET (spk_off) into g_spk_pool, resolved to an address only
 * at use time (after Phase 1 has finished growing the pool for this block).
 * An offset survives relocation; a raw pointer captured mid-growth does not.
 *
 * This test forces that exact relocation deterministically: it mines 10
 * blocks whose sole coinbase output script is ~9000 bytes (a chain of
 * harmless data pushes ending in OP_1 -- a valid, if unusual, legacy
 * scriptPubKey; well under TXV_SPK_CAP=10000 and under
 * MAX_SCRIPT_ELEMENT_SIZE=520 per individual push), then spends all 10 of
 * those big outputs in a single later block. Ten inputs * ~9000 bytes each
 * is ~90000 bytes total -- comfortably more than g_spk_pool's 65536-byte
 * initial capacity, guaranteeing bytepool_alloc's realloc() fires partway
 * through that block's Phase 1 loop, after several EARLIER big-script
 * inputs have already been resolved and copied into the (about to move)
 * pool. Under the pre-fix pointer-based code this reliably corrupts one or
 * more of those earlier inputs' cached scriptPubKey, causing their legacy
 * script verification to fail against garbage bytes and the whole block to
 * be wrongly REJECTED. Under the fix, the block must ACCEPT.
 *
 * Verified (before writing this comment) that this test FAILS against the
 * pre-fix pointer-returning bytepool_alloc (via `git stash` of just the fix)
 * and PASSES cleanly with the fix in place -- same "prove the bug, then
 * prove the fix" discipline as tests/test_compact_manifest_order.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

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
extern void utxo_live_close(void);

/* Never actually reached (every prevout here is already confirmed on
 * chain), but bitcoin_mempool_policy.c's object resolves this extern --
 * same stub as tests/test_cross_tx_verify.c. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_tx_verify_bytepool_realloc: unexpected call to mempool_resolve_confirmed_utxo\n");
    abort();
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}

static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
static u8* put_cs(u8* p, u64 v){
    if (v < 0xfd) { *p++ = (u8)v; return p; }
    if (v <= 0xffff) { *p++ = 0xfd; *p++=(u8)v; *p++=(u8)(v>>8); return p; }
    *p++ = 0xfe; put32(p, (u32)v); return p+4;
}

static u8 g_txid_scratch[1<<14];

/* A large-but-valid legacy scriptPubKey: repeated 71-byte data pushes
 * (opcode=70 + 70 filler bytes -- well under the 520-byte MAX_SCRIPT_
 * ELEMENT_SIZE, and pure data pushes never count toward MAX_OPS_PER_SCRIPT),
 * terminated by a single OP_1. With an empty scriptSig, execution leaves
 * [chunk0, chunk1, ..., 1] on the stack -- top item truthy, script succeeds.
 * Not P2SH-shaped, so CLEANSTACK (which this codebase only enforces
 * alongside P2SH, see bitcoin_scriptverify.c) does not apply to the
 * multiple leftover data-push items. */
static u32 build_big_legacy_spk(u8* out, u32 target_len){
    u8* q = out;
    u32 written = 0;
    u8 filler = 0xA5;
    while (written + 71 <= target_len - 1) {
        *q++ = 70;
        for (int i=0;i<70;i++) *q++ = (u8)(filler ^ i);
        written += 71;
    }
    *q++ = 0x51; /* OP_1 */
    return (u32)(q - out);
}

/* Mines a single-coinbase block whose coinbase output script is exactly
 * out_spk[0..out_spk_len). Mirrors the mk_and_mine convention already
 * established in tests/test_cross_tx_verify.c / test_apply_block_rollback.c
 * (single coinbase tx, minimum difficulty), just with a caller-supplied
 * (possibly large) output script instead of a hardcoded 1-byte OP_1. */
static long mk_and_mine_bigspk(u8* raw, u8 hash[32], const u8 prev[32], u32 tag, u32 tstamp,
                               const u8* out_spk, u32 out_spk_len, u8 txid_out[32]){
    u8 tx[16384];
    u8* q = tx;
    put32(q,1); q+=4;
    *q++ = 1;
    memset(q,0,32); q+=32;
    put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4;
    put32(q,0xffffffffu); q+=4;
    *q++ = 1;
    put64(q, 50000000ULL); q+=8;
    q = put_cs(q, out_spk_len);
    memcpy(q, out_spk, out_spk_len); q += out_spk_len;
    put32(q,0); q+=4;
    long txlen = q - tx;
    if (!tx_txid(txid_out, tx, (unsigned long)txlen, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (bigspk coinbase)\n"); failures++;
    }

    u8* o = raw;
    put32(o,1); o+=4;
    memcpy(o, prev, 32); o+=32;
    memcpy(o, txid_out, 32); o+=32;
    put32(o, tstamp); o+=4;
    put32(o, 0x207fffffu); o+=4;
    put32(o, 0); o+=4;
    *o++ = 1;
    memcpy(o, tx, (size_t)txlen); o += txlen;
    long len = o - raw;

    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

/* Ordinary coinbase-only block, plain 1-byte OP_1 output -- used for filler
 * blocks to buy maturity, same shape as test_cross_tx_verify.c's mk_and_mine. */
static long mk_and_mine_plain(u8* raw, u8 hash[32], const u8 prev[32], u32 tag, u32 tstamp){
    u8 spk = 0x51;
    u8 dummy_txid[32];
    return mk_and_mine_bigspk(raw, hash, prev, tag, tstamp, &spk, 1, dummy_txid);
}

/* Single-input (empty scriptSig), single-output (OP_1) spend of an
 * arbitrary earlier output -- same convention as test_cross_tx_verify.c's
 * build_spend. */
static long build_spend(u8* out, const u8 prev_txid[32], u32 prev_index, u8 txid[32]){
    u8* q = out;
    put32(q,1); q+=4;
    *q++ = 1;
    memcpy(q, prev_txid, 32); q+=32; put32(q, prev_index); q+=4;
    *q++ = 0;
    put32(q,0xffffffffu); q+=4;
    *q++ = 1;
    put64(q, 40000000ULL); q+=8;
    *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long len = q - out;
    if (!tx_txid(txid, out, (unsigned long)len, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (spend)\n"); failures++;
    }
    return len;
}

static void merkle_root(u8 out[32], u8 (*txids)[32], int n){
    if (n == 1) { memcpy(out, txids[0], 32); return; }
    static u8 level[64][32];
    memcpy(level, txids, (size_t)n*32);
    int cnt = n;
    while (cnt > 1){
        int next = 0;
        u8 pair[64];
        for (int i=0;i<cnt;i+=2){
            memcpy(pair, level[i], 32);
            if (i+1 < cnt) memcpy(pair+32, level[i+1], 32);
            else memcpy(pair+32, level[i], 32);
            sha256d(level[next], pair, 64);
            next++;
        }
        cnt = next;
    }
    memcpy(out, level[0], 32);
}

static long assemble_and_mine(u8* raw, u8 hash[32], const u8 prev[32], u32 tstamp,
                              u8 (*tx_bufs)[512], long* tx_lens, u8 (*txids)[32], int ntx){
    u8 root[32];
    merkle_root(root, txids, ntx);
    u8* o = raw;
    put32(o,1); o+=4;
    memcpy(o, prev, 32); o+=32;
    memcpy(o, root, 32); o+=32;
    put32(o, tstamp); o+=4;
    put32(o, 0x207fffffu); o+=4;
    put32(o, 0); o+=4;
    *o++ = (u8)ntx;
    for (int i=0;i<ntx;i++){ memcpy(o, tx_bufs[i], (size_t)tx_lens[i]); o += tx_lens[i]; }
    long len = o - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

static u8 store_buf[4096];

#define NBIG 10

int main(void){
    tt_isolate();
    memset(store_buf,0,sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);

    u8 prev[32]; memset(prev,0,32);
    u8 big_txid[NBIG][32];
    u32 h = 0;

    /* Heights 0..9: NBIG blocks, each with a single ~9000-byte legacy
     * coinbase output script. 10 * ~9000 = ~90000 bytes total, comfortably
     * past g_spk_pool's 65536-byte initial capacity. */
    for (int i=0;i<NBIG;i++){
        u8 spk[9200];
        u32 spklen = build_big_legacy_spk(spk, 9000);
        u8 raw[16384], hash[32];
        long len = mk_and_mine_bigspk(raw, hash, prev, 0x60000000u+(u32)i, 1800000000u+h, spk, spklen, big_txid[i]);
        long r = store_append(store_buf, hash, raw, len);
        if (r != h) { printf("FAIL store_append bigspk h=%u got=%ld\n", h, r); failures++; }
        memcpy(prev, hash, 32);
        h++;
    }

    /* Heights 10..129: 120 plain filler blocks, enough that every big-spk
     * output above (created at heights 0..9) is well past the 100-block
     * coinbase maturity rule by the time we spend it. */
    for (int i=0;i<120;i++){
        u8 raw[256], hash[32];
        long len = mk_and_mine_plain(raw, hash, prev, 0x61000000u+(u32)i, 1800000000u+h);
        long r = store_append(store_buf, hash, raw, len);
        if (r != h) { printf("FAIL store_append filler h=%u got=%ld\n", h, r); failures++; }
        memcpy(prev, hash, 32);
        h++;
    }

    long applied1 = utxo_live_catchup(store_buf);
    ck("bigspk + filler chain catch-up applied every block cleanly", applied1, (long)h);
    long count_base = utxo_live_count();

    /* One block spending all NBIG big-script outputs -- forces
     * bytepool_alloc's realloc() to fire mid-loop, after several earlier
     * big-script inputs have already been resolved this block. */
    {
        enum { NTX = NBIG + 1 };
        u8 tx_bufs[NTX][512]; long tx_lens[NTX]; u8 txids[NTX][32];
        u8 cb[64]; u8* q = cb;
        put32(q,1); q+=4; *q++=1; memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
        *q++=4; put32(q,0x62000000u); q+=4; put32(q,0xffffffffu); q+=4;
        *q++=1; put64(q,50000000ULL); q+=8; *q++=1; *q++=0x51; put32(q,0); q+=4;
        tx_lens[0] = q - cb; memcpy(tx_bufs[0], cb, (size_t)tx_lens[0]);
        tx_txid(txids[0], tx_bufs[0], (unsigned long)tx_lens[0], g_txid_scratch, sizeof g_txid_scratch);

        for (int i=0;i<NBIG;i++){
            tx_lens[1+i] = build_spend(tx_bufs[1+i], big_txid[i], 0, txids[1+i]);
        }

        u8 raw[8192], hash[32];
        long len = assemble_and_mine(raw, hash, prev, 1800000000u+h, tx_bufs, tx_lens, txids, NTX);
        long r = store_append(store_buf, hash, raw, len);
        if (r != (long)h) { printf("FAIL store_append (spend block) got=%ld\n", r); failures++; }
    }

    long applied2 = utxo_live_catchup(store_buf);
    ck("block spending all 10 big-script prevouts -> ACCEPTED (no dangling-pointer corruption)", applied2, 1);
    ck("applied_height advanced by exactly one block", utxo_live_applied_height(), (long)h);
    /* net delta: +1 (this block's coinbase + 10 new OP_1 outputs created,
     * minus the 10 big-script outputs spent) */
    ck("live count reflects the accepted block", utxo_live_count(), count_base + 1);

    utxo_live_close();
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
