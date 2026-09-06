/* tests/test_connect_reject.c -- 3.3 of docs/audits/UTXO_INLINE_CONNECT_SCOPE.md
 * (2026-09-06): a block that fails to CONNECT is REJECTED, not fatal.
 *
 * Core marks a block whose ConnectBlock fails BLOCK_FAILED_VALID and moves
 * on. This node used to stop the catch-up ("[utxo_live] FATAL: apply_block
 * failed") and retry the same block from the checkpoint for ever, with the
 * block still in the archive. Now, for a VALIDATION failure only
 * (UTXO_FAIL_REJECT -- never a store error), utxo_live_catchup calls the
 * reject hook the worker registers, which is the operator's invalidateblock
 * path (chain_invalidate_block in daemon/reorg.c): invalid.dat mark,
 * archive truncated to the parent through the reorg module's disconnect,
 * headers.dat rolled back to the failed height. Then the chain moves on.
 *
 * Chain: heights 0..149 coinbase-only (real PoW at min difficulty, real
 * merkle roots), mirrored into headers.dat the way the daemon's header
 * store holds them. Height 150 is a POISON block: coinbase + a tx spending
 * an outpoint that does not exist (a made-up txid) -- tx_verify's "input
 * references a missing/already-spent UTXO", the missing-input class Core
 * rejects with bad-txns-inputs-missingorspent. Heights 151..152 are valid
 * blocks on top of it, stored but never connectable: the never-connected
 * tail the truncate must drop without trying to unapply.
 *
 * Phase 1 -- NEGATIVE CONTROL, the pre-3.3 path (no hook registered): the
 *   catch-up returns -1 with kind consensus-reject, the applied height sits
 *   at 149, the archive keeps 152, no mark, halted flag clear; a retry fails
 *   the same way (stuck).
 * Phase 2 -- the 3.3 path (the real chain_invalidate_block as the hook):
 *   the catch-up returns >= 0 with the rejected height reported; the
 *   poison hash is in invalid.dat (re-read from the FILE, not the in-memory
 *   set); the archive is at 149; headers.dat has 150 records (0..149); the
 *   applied height is 149; the node is not halted.
 * Phase 3 -- a valid block at 150 from "another source" connects normally.
 * Phase 4 -- the burst guard: a second poison within 100 blocks of the
 *   first is NOT auto-invalidated (a lying store rejects everything); it
 *   falls back to the retry path with the archive and the mark set intact.
 *
 * Watched to FAIL before the change: built against utxo_live_catchup with
 * the reject-hook call removed, Phase 2's "rejected height reported",
 * "archive truncated to 149", "poison hash in invalid.dat" and "headers.dat
 * rolled back to 150 records" all fail (the block stays, -1, no mark).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"
#include "../daemon/invalid_set.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long store_init(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  pow_check(const u8 hdr[80]);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
extern void sha256d(u8 out[32], const void* msg, long len);

extern int  hst_init(void* hst);
extern int  hst_reload(void* hst);
extern long hst_append(void* hst, const u8 hdr[80], const u8 hash[32]);
extern long hst_count(void* hst);

extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_count(void);
extern long utxo_live_applied_height(void);
extern long utxo_live_last_fail_kind(void);
extern const char* utxo_live_last_reject(void);
extern long utxo_live_halted(void);
extern long utxo_live_call_rejected_height(void);
extern long utxo_live_last_rejected_height(void);
extern long utxo_live_rejected_count(void);
extern void utxo_live_set_reject_fn(long (*fn)(void*, long, const u8[32], const char*));
extern void utxo_live_close(void);
extern void* utxo_live_lst(void);
extern void* utxo_live_table(void);
extern long utxo_lsm_get(void* lst, void* tbl, const u8 txid[32], u32 index, u64* value,
                         u64* height, u64* coinbase, const u8** script, unsigned long* slen);

extern long chain_invalidate_block(void* st, long h, const u8 hash[32]);
extern long reorg_chainwork_open(void* st);
extern long reorg_chainwork_sync(void* st, long max_blocks);

/* bitcoin_mempool_policy.c resolves confirmed prevouts through this hook;
 * same definition as test_reorg.c (never reached here). */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u;
    u64 h_unused, cb_unused;
    return utxo_lsm_get(utxo_live_lst(), utxo_live_table(), txid, (u32)index, value, &h_unused, &cb_unused, script, slen);
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}

static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
static u8 g_txid_scratch[1<<12];

/* 65-byte coinbase paying 0.5 BTC to OP_1 (spendable, mature after 100). */
static long mk_coinbase(u8* tx, u8 txid[32], u32 tag){
    u8* q = tx;
    put32(q,1); q+=4;
    *q++ = 1;
    memset(q,0,32); q+=32;
    put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4;
    put32(q,0xffffffffu); q+=4;
    *q++ = 1;
    put64(q, 50000000ULL); q+=8;
    *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long len = q - tx;
    if (!tx_txid(txid, tx, (unsigned long)len, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (coinbase)\n"); failures++;
    }
    return len;
}

static long finish_block(u8* raw, u8 hash[32], const u8 prev[32], const u8 root[32], u32 tstamp,
                         const u8* const* txs, const long* lens, int ntx){
    u8* o = raw;
    put32(o,1); o+=4;
    memcpy(o, prev, 32); o+=32;
    memcpy(o, root, 32); o+=32;
    put32(o, tstamp); o+=4;
    put32(o, 0x207fffffu); o+=4;
    put32(o, 0); o+=4;
    *o++ = (u8)ntx;
    for (int i = 0; i < ntx; i++){ memcpy(o, txs[i], (size_t)lens[i]); o += lens[i]; }
    long len = o - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

/* coinbase-only block */
static long mk_and_mine(u8* raw, u8 hash[32], const u8 prev[32], u32 tag, u32 tstamp){
    u8 cb[80], cb_txid[32];
    long cblen = mk_coinbase(cb, cb_txid, tag);
    const u8* txs[1] = { cb }; long lens[1] = { cblen };
    return finish_block(raw, hash, prev, cb_txid, tstamp, txs, lens, 1);   /* 1 tx: root = txid */
}

/* coinbase + tx1 spending `bogus_txid:0`, an outpoint that does not exist.
 * Root over 2 leaves = sha256d(cb || tx1). */
static long mk_and_mine_poison(u8* raw, u8 hash[32], const u8 prev[32], const u8 bogus_txid[32],
                               u32 tag, u32 tstamp){
    u8 cb[80], cb_txid[32];
    long cblen = mk_coinbase(cb, cb_txid, tag);
    u8 tx1[128], tx1_txid[32];
    u8* q = tx1;
    put32(q,1); q+=4;
    *q++ = 1;
    memcpy(q, bogus_txid, 32); q+=32; put32(q,0); q+=4;   /* prevout: nonexistent */
    *q++ = 0;                        /* scriptSig len 0 */
    put32(q,0xffffffffu); q+=4;
    *q++ = 1;
    put64(q, 40000000ULL); q+=8;
    *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long tx1len = q - tx1;
    if (!tx_txid(tx1_txid, tx1, (unsigned long)tx1len, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (tx1)\n"); failures++;
    }
    u8 pair[64], root[32];
    memcpy(pair, cb_txid, 32); memcpy(pair+32, tx1_txid, 32); sha256d(root, pair, 64);
    const u8* txs[2] = { cb, tx1 }; long lens[2] = { cblen, tx1len };
    return finish_block(raw, hash, prev, root, tstamp, txs, lens, 2);
}

static u8 store_buf[4096];
static u8 hst[4096];

static long headers_count(void){
    static u8 h2[4096];
    if (hst_init(h2) != 1) return -1;
    struct stat sb;
    if (stat("headers.dat", &sb) == 0 && sb.st_size >= 112) hst_reload(h2);
    return hst_count(h2);
}

/* the hook the worker registers is main.c's dl_reject_block, which is
 * chain_invalidate_block + peer scoring; the chain half is what is tested */
static int g_hook_calls = 0;
static long reject_via_chain(void* st, long h, const u8 hash[32], const char* reason){
    g_hook_calls++;
    printf("  hook: height %ld reason=%s\n", h, reason ? reason : "(null)");
    return chain_invalidate_block(st, h, hash);
}

static void append_and_mirror(long h, const u8* raw, long len, const u8 hash[32]){
    long r = store_append(store_buf, hash, raw, len);
    if (r != h) { printf("FAIL store_append h=%ld got=%ld\n", h, r); failures++; }
    if (hst_append(hst, raw, hash) < 0) { printf("FAIL hst_append h=%ld\n", h); failures++; }
    if (reorg_chainwork_sync(store_buf, 0) < 0) { printf("FAIL chainwork sync h=%ld\n", h); failures++; }
}

int main(void){
    tt_isolate();
    memset(store_buf,0,sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    ck("reorg_chainwork_open (chainwork.dat, kept in lockstep with index.dat as the daemon does)",
       reorg_chainwork_open(store_buf), 1);
    ck("hst_init (headers.dat mirror)", hst_init(hst), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);

    long n1 = 150;
    u8 prev[32]; memset(prev,0,32);
    u8 hash149[32];
    for (long h=0; h<n1; h++){
        u8 raw[256], hash[32];
        long len = mk_and_mine(raw, hash, prev, 0x50000000u+(u32)h, 1800000000u+(u32)h);
        append_and_mirror(h, raw, len, hash);
        memcpy(prev, hash, 32);
    }
    memcpy(hash149, prev, 32);
    ck("clean chain 0..149 connects", utxo_live_catchup(store_buf), n1);
    ck("applied height 149", utxo_live_applied_height(), n1-1);
    long count_before = utxo_live_count();

    /* the poison block at 150 + two valid blocks on top of it */
    u8 poison_hash[32];
    {
        u8 bogus[32]; for (int i=0;i<32;i++) bogus[i] = (u8)(0xA5 ^ i);
        u8 raw[512];
        long len = mk_and_mine_poison(raw, poison_hash, prev, bogus, 0x60000000u, 1800100000u);
        append_and_mirror(150, raw, len, poison_hash);
        memcpy(prev, poison_hash, 32);
        for (long h=151; h<=152; h++){
            u8 raw2[256], hash[32];
            long len2 = mk_and_mine(raw2, hash, prev, 0x50000000u+(u32)h, 1800100000u+(u32)h);
            append_and_mirror(h, raw2, len2, hash);
            memcpy(prev, hash, 32);
        }
    }
    ck("archive tip 152 (poison at 150, two blocks above it)", (long)*(int*)(store_buf+24), 152);
    ck("headers.dat holds 153 records", headers_count(), 153);

    /* ---- Phase 1: NEGATIVE CONTROL -- no hook = the pre-3.3 node ---- */
    printf("\n-- phase 1: no reject hook (pre-3.3 path)\n");
    long r1 = utxo_live_catchup(store_buf);
    ck("pre-3.3: catch-up fails the call (-1)", r1, -1);
    ck("pre-3.3: failure kind is consensus-reject (1)", utxo_live_last_fail_kind(), 1);
    ck("pre-3.3: the reject names the missing input",
       strstr(utxo_live_last_reject(), "missing") != NULL, 1);
    ck("pre-3.3: applied height stuck at 149", utxo_live_applied_height(), 149);
    ck("pre-3.3: the poison block stays in the archive (tip 152)", (long)*(int*)(store_buf+24), 152);
    ck("pre-3.3: no rejection reported", utxo_live_call_rejected_height(), -1);
    { struct stat sb; ck("pre-3.3: no invalid.dat written", stat("invalid.dat", &sb) == 0, 0); }
    ck("pre-3.3: not halted (a reject is not a store error)", utxo_live_halted(), 0);
    ck("pre-3.3: a retry fails the same way (stuck for ever)", utxo_live_catchup(store_buf), -1);
    ck("pre-3.3: UTXO count unchanged by the failed attempts", utxo_live_count(), count_before);

    /* ---- Phase 2: the 3.3 path ---- */
    printf("\n-- phase 2: reject hook = chain_invalidate_block\n");
    utxo_live_set_reject_fn(reject_via_chain);
    long r2 = utxo_live_catchup(store_buf);
    ck("3.3: the catch-up call does not fail (>= 0)", r2 >= 0, 1);
    ck("3.3: the hook ran once", g_hook_calls, 1);
    ck("3.3: rejected height 150 reported for this call", utxo_live_call_rejected_height(), 150);
    ck("3.3: last rejected height 150", utxo_live_last_rejected_height(), 150);
    ck("3.3: rejected count 1", utxo_live_rejected_count(), 1);
    ck("3.3: applied height stays at the parent, 149", utxo_live_applied_height(), 149);
    ck("3.3: archive truncated to 149 (poison + the never-connected 151..152 dropped)",
       (long)*(int*)(store_buf+24), 149);
    ck("3.3: headers.dat rolled back to 150 records (0..149)", headers_count(), 150);
    ck("3.3: poison hash marked in the in-memory set", invset_has(poison_hash), 1);
    invset_clear();
    ck("3.3: invalid.dat on disk holds exactly one mark", invset_load("invalid.dat"), 1);
    ck("3.3: ... and it is the poison hash", invset_has(poison_hash), 1);
    ck("3.3: not halted", utxo_live_halted(), 0);
    ck("3.3: UTXO count unchanged (nothing above 149 was ever applied)", utxo_live_count(), count_before);
    ck("3.3: a further catch-up call is a clean no-op (tip == applied)", utxo_live_catchup(store_buf), 0);
    ck("3.3: ... reporting no rejection", utxo_live_call_rejected_height(), -1);

    /* ---- Phase 3: a valid block at 150 from another source connects ---- */
    printf("\n-- phase 3: a valid sibling at 150\n");
    {
        u8 raw[256], hash[32];
        long len = mk_and_mine(raw, hash, hash149, 0x70000000u, 1800200000u);
        append_and_mirror(150, raw, len, hash);
        ck("sibling is not the poison block", memcmp(hash, poison_hash, 32) != 0, 1);
    }
    ck("3.3: the sibling connects (1 block applied)", utxo_live_catchup(store_buf), 1);
    ck("3.3: applied height 150", utxo_live_applied_height(), 150);
    ck("3.3: no rejection this call", utxo_live_call_rejected_height(), -1);
    ck("3.3: UTXO count grew by the sibling's coinbase", utxo_live_count(), count_before + 1);

    /* ---- Phase 4: the burst guard ---- */
    printf("\n-- phase 4: a second poison within 100 blocks is NOT auto-invalidated\n");
    {
        u8 bogus[32]; for (int i=0;i<32;i++) bogus[i] = (u8)(0x3C ^ i);
        u8 raw[512], hash[32];
        u8 prev150[32];
        { static u8 blk[1<<16]; extern long store_read_at(void*, unsigned long, void*, long);
          long l = store_read_at(store_buf, 150, blk, sizeof blk); ck("read block 150 back", l >= 80, 1);
          block_hash(prev150, blk); }
        long len = mk_and_mine_poison(raw, hash, prev150, bogus, 0x61000000u, 1800300000u);
        append_and_mirror(151, raw, len, hash);
        ck("second poison appended at 151", (long)*(int*)(store_buf+24), 151);
    }
    long r4 = utxo_live_catchup(store_buf);
    ck("guard: the call fails (-1) instead of invalidating", r4, -1);
    ck("guard: kind consensus-reject", utxo_live_last_fail_kind(), 1);
    ck("guard: the hook did NOT run again", g_hook_calls, 1);
    ck("guard: no rejection reported for this call", utxo_live_call_rejected_height(), -1);
    ck("guard: archive keeps 151 (nothing truncated)", (long)*(int*)(store_buf+24), 151);
    ck("guard: applied height 150", utxo_live_applied_height(), 150);
    ck("guard: rejected count still 1", utxo_live_rejected_count(), 1);
    invset_clear();
    ck("guard: invalid.dat still holds exactly one mark", invset_load("invalid.dat"), 1);
    ck("guard: not halted", utxo_live_halted(), 0);

    utxo_live_set_reject_fn(NULL);
    utxo_live_close();
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
