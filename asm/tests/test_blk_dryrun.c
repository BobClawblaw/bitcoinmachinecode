/* tests/test_blk_dryrun.c -- utxo_live_dryrun_block: the submitblock connect
 * step's safety gate. The dry run executes the SAME verification phases the
 * real apply does (parse, witness commitment, BIP30, in-block dup, full
 * script verify) and stops at the Phase 5 boundary -- the first mutation.
 * Three properties proven on a real synthetic chain (the
 * test_apply_block_rollback fixture):
 *   PURITY    a clean dry run changes NOTHING (count, applied height).
 *   REASONS   a rejecting dry run reports the reject reason and also
 *             changes nothing.
 *   COHERENCE the exact block a dry run passed then APPLIES cleanly
 *             through the normal store_append + catch-up pipeline -- the
 *             property the connect step's correctness argument rests on.
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
extern long utxo_live_dryrun_block(const u8* blockbuf, u64 blocklen, long height);
extern const char* utxo_live_last_reject(void);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u;(void)txid;(void)index;(void)value;(void)script;(void)slen;
    fprintf(stderr, "test_blk_dryrun: unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
static u8 g_txid_scratch[1<<12];

static long mk_coinbase(u8* tx, u8 txid[32], u32 tag){
    u8* q = tx;
    put32(q,1); q+=4; *q++ = 1;
    memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4; put32(q,0xffffffffu); q+=4;
    *q++ = 1; put64(q, 50000000ULL); q+=8; *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long n = q - tx;
    tx_txid(txid, tx, (unsigned long)n, g_txid_scratch, sizeof g_txid_scratch);
    return n;
}
static long mk_and_mine(u8* raw, u8 hash[32], const u8 prev[32], u32 tag, u32 tstamp){
    /* 80, not 64: the hand-built coinbase is 65 bytes -- a 64-byte buffer
     * overflowed by one byte, and where that byte landed depended on the
     * BINARY's stack layout (adding any code moved it). Found because this
     * test's layout put the clobber inside the tx bytes AFTER the txid was
     * computed: merkle != embedded tx -> the spend referenced a key the
     * store never had. test_apply_block_rollback had the same latent bug
     * and passed by layout luck. */
    u8 tx[80], txid[32];
    long txlen = mk_coinbase(tx, txid, tag);
    u8* o = raw;
    put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, txid, 32); o+=32;
    put32(o, tstamp); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
    *o++ = 1; memcpy(o, tx, (size_t)txlen); o += txlen;
    long len = o - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}
/* coinbase + one spend of `spend_txid:0` (OP_1 prevout, empty scriptSig --
 * valid); poison=1 swaps the spend's prevout for a NONEXISTENT txid so the
 * script-verify phase rejects (missing UTXO), exercising the reason path. */
static long mk_and_mine_spend(u8* raw, u8 hash[32], const u8 prev[32],
                              const u8 spend_txid[32], u32 tag, u32 tstamp, int poison){
    u8 cb[80], cb_txid[32];   /* 65-byte coinbase: 64 overflowed by one */
    long cblen = mk_coinbase(cb, cb_txid, tag);
    u8 tx1[128], tx1_txid[32];
    u8* q = tx1;
    put32(q,1); q+=4; *q++ = 1;
    memcpy(q, spend_txid, 32); if (poison) q[0] ^= 0xFF; q+=32; put32(q,0); q+=4;
    *q++ = 0; put32(q,0xffffffffu); q+=4;
    *q++ = 1; put64(q, 40000000ULL); q+=8; *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long tx1len = q - tx1;
    tx_txid(tx1_txid, tx1, (unsigned long)tx1len, g_txid_scratch, sizeof g_txid_scratch);
    u8 pair[64], root[32];
    memcpy(pair, cb_txid, 32); memcpy(pair+32, tx1_txid, 32); sha256d(root, pair, 64);
    u8* o = raw;
    put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, root, 32); o+=32;
    put32(o, tstamp); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
    *o++ = 2;
    memcpy(o, cb, (size_t)cblen); o += cblen;
    memcpy(o, tx1, (size_t)tx1len); o += tx1len;
    long len = o - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}


/* VAL-4: coinbase + one spend of `spend_txid:0`, with the spend's nLockTime
 * and nSequence chosen by the caller. Mirrors mk_and_mine_spend exactly apart
 * from those two fields, so a rejection can only be about finality. */
static long mk_and_mine_locktime(u8* raw, u8 hash[32], const u8 prev[32],
                                 const u8 spend_txid[32], u32 tag, u32 tstamp,
                                 u32 locktime, u32 sequence){
    u8 cb[80], cb_txid[32];
    long cblen = mk_coinbase(cb, cb_txid, tag);
    u8 tx1[128], tx1_txid[32];
    u8* q = tx1;
    put32(q,1); q+=4; *q++ = 1;
    memcpy(q, spend_txid, 32); q+=32; put32(q,0); q+=4;
    *q++ = 0; put32(q, sequence); q+=4;
    *q++ = 1; put64(q, 40000000ULL); q+=8; *q++ = 1; *q++ = 0x51;
    put32(q, locktime); q+=4;
    long tx1len = q - tx1;
    tx_txid(tx1_txid, tx1, (unsigned long)tx1len, g_txid_scratch, sizeof g_txid_scratch);
    u8 pair[64], root[32];
    memcpy(pair, cb_txid, 32); memcpy(pair+32, tx1_txid, 32); sha256d(root, pair, 64);
    u8* o = raw;
    put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, root, 32); o+=32;
    put32(o, tstamp); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
    *o++ = 2;
    memcpy(o, cb, (size_t)cblen); o += cblen;
    memcpy(o, tx1, (size_t)tx1len); o += tx1len;
    long len = o - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

/* VAL-4/BIP68: coinbase + one spend with a chosen tx nVersion and input
 * nSequence. Identical to mk_and_mine_locktime apart from those two fields,
 * so a rejection can only be about relative finality. nLockTime stays 0,
 * which short-circuits IsFinalTx and keeps the two halves of VAL-4
 * independent -- otherwise a BIP68 test could pass on the nLockTime rule. */
static long mk_and_mine_seq(u8* raw, u8 hash[32], const u8 prev[32],
                            const u8 spend_txid[32], u32 tag, u32 tstamp,
                            u32 version, u32 sequence){
    u8 cb[80], cb_txid[32];
    long cblen = mk_coinbase(cb, cb_txid, tag);
    u8 tx1[128], tx1_txid[32];
    u8* q = tx1;
    put32(q, version); q+=4; *q++ = 1;
    memcpy(q, spend_txid, 32); q+=32; put32(q,0); q+=4;
    *q++ = 0; put32(q, sequence); q+=4;
    *q++ = 1; put64(q, 40000000ULL); q+=8; *q++ = 1; *q++ = 0x51;
    put32(q, 0); q+=4;                       /* nLockTime 0 */
    long tx1len = q - tx1;
    tx_txid(tx1_txid, tx1, (unsigned long)tx1len, g_txid_scratch, sizeof g_txid_scratch);
    u8 pair[64], root[32];
    memcpy(pair, cb_txid, 32); memcpy(pair+32, tx1_txid, 32); sha256d(root, pair, 64);
    u8* o = raw;
    put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, root, 32); o+=32;
    put32(o, tstamp); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
    *o++ = 2;
    memcpy(o, cb, (size_t)cblen); o += cblen;
    memcpy(o, tx1, (size_t)tx1len); o += tx1len;
    long len = o - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

/* VAL-3 (audit 2026-09-03): a block whose STRIPPED size exceeds
 * MAX_BLOCK_WEIGHT/4. Core's CheckBlock rejects
 * GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR >
 * MAX_BLOCK_WEIGHT as "bad-blk-length"; this node had no size or weight rule
 * at all on the connect path -- the only 4,000,000 in the tree was the P2P
 * frame cap and GBT -- so a miner could produce a block accepted here and
 * rejected by Core, which is a chain split.
 *
 * Built non-segwit on purpose. For a witness-free block total == stripped, so
 * weight == 4*stripped and the length rule fires first, exactly as Core
 * orders CheckBlock before ContextualCheckBlock. The distinct bad-blk-weight
 * arm needs witness bytes with segwit active, which this fixture chain (early
 * heights, mainnet params) cannot express; its arithmetic is pinned instead
 * by test_val_read_tx's stripped-length vectors, which are checked against
 * Core's own size/weight numbers.
 *
 * The bulk is one enormous coinbase output script. Consensus caps scriptSig
 * at 100 bytes but places no limit on an output script's length at block
 * level (MAX_SCRIPT_SIZE applies when a script is EXECUTED), so this is a
 * structurally valid block that is simply too big. */
static long mk_and_mine_oversize(u8* raw, u8 hash[32], const u8 prev[32],
                                 u32 tag, u32 tstamp, unsigned long spk_len){
    u8* q = raw + 80;
    *q++ = 1;                                     /* ntx = 1 */
    u8* txstart = q;
    put32(q,1); q+=4;
    *q++ = 1;                                     /* 1 input */
    memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4; put32(q,0xffffffffu); q+=4;
    *q++ = 1;                                     /* 1 output */
    put64(q, 50000000ULL); q+=8;
    /* CompactSize(spk_len), then that many OP_NOP bytes */
    *q++ = 0xfe; put32(q, (u32)spk_len); q+=4;
    memset(q, 0x61, spk_len); q += spk_len;       /* OP_NOP filler */
    put32(q,0); q+=4;                             /* locktime */
    long txlen = (long)(q - txstart);

    u8 txid[32];
    static u8 big_scratch[1 << 21];
    tx_txid(txid, txstart, (unsigned long)txlen, big_scratch, sizeof big_scratch);

    put32(raw,1);
    memcpy(raw+4, prev, 32);
    memcpy(raw+36, txid, 32);                     /* merkle root == the one txid */
    put32(raw+68, tstamp); put32(raw+72, 0x207fffffu); put32(raw+76, 0);
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return (long)(q - raw);
}

static u8 store_buf[4096];

int main(void){
    tt_isolate();
    memset(store_buf,0,sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);

    long n1 = 150;
    u8 prev[32]; memset(prev,0,32);
    u8 height0_txid[32];
    u8 height1_txid[32];   /* VAL-4: a coinbase output the earlier spend does NOT consume */
    for (long h=0; h<n1; h++){
        u8 raw[256], hash[32];
        long len = mk_and_mine(raw, hash, prev, 0x50000000u+(u32)h, 1800000000u+(u32)h);
        if (store_append(store_buf, hash, raw, len) != h){ printf("FAIL append h=%ld\n",h); failures++; }
        if (h==0) memcpy(height0_txid, raw+36, 32);
        if (h==1) memcpy(height1_txid, raw+36, 32);
        memcpy(prev, hash, 32);
    }
    ck("catch-up applied 0..149", utxo_live_catchup(store_buf), n1);
    long count0 = utxo_live_count();
    long applied0 = utxo_live_applied_height();
    ck("applied height 149", applied0, n1-1);

    /* ---- PURITY: dry-run of a VALID next block mutates nothing ---- */
    static u8 valid[512]; u8 vhash[32];
    long vlen = mk_and_mine_spend(valid, vhash, prev, height0_txid, 0x60000000u, 1800100000u, 0);
    ck("dry run of the valid block -> 1", utxo_live_dryrun_block(valid, (u64)vlen, n1), 1);
    ck("PURITY: UTXO count unchanged after clean dry run", utxo_live_count(), count0);
    ck("PURITY: applied height unchanged", utxo_live_applied_height(), applied0);

    /* ---- REASONS: dry-run of a bad-spend block rejects + mutates nothing ---- */
    { static u8 bad[512]; u8 bhash[32];
      long blen = mk_and_mine_spend(bad, bhash, prev, height0_txid, 0x61000000u, 1800100001u, 1);
      ck("dry run of the missing-input block -> 0", utxo_live_dryrun_block(bad, (u64)blen, n1), 0);
      const char* rr = utxo_live_last_reject();
      printf("reject reason: [%s]\n", rr ? rr : "(null)");
      ck("reject reason captured (non-empty)", rr && rr[0] ? 1 : 0, 1);
      ck("UTXO count unchanged after rejecting dry run", utxo_live_count(), count0);
      ck("applied height unchanged after rejecting dry run", utxo_live_applied_height(), applied0); }

    /* ---- COHERENCE: the dry-run-passed block then APPLIES cleanly ---- */
    ck("store_append(valid) at 150", store_append(store_buf, vhash, valid, vlen), n1);
    ck("catch-up applies the dry-run-passed block", utxo_live_catchup(store_buf), 1);
    ck("applied height now 150", utxo_live_applied_height(), n1);
    /* net UTXO change: +1 coinbase out, -1 spent height-0 out, +1 tx1 out */
    ck("UTXO count = before + 1", utxo_live_count(), count0 + 1);

    /* ---- VAL-4: a NON-FINAL transaction makes the block invalid ----
     * Core's ContextualCheckBlock rejects any tx that is not IsFinalTx(tx,
     * nHeight, nLockTimeCutoff) with "bad-txns-nonfinal". This node had the
     * CLTV/CSV script OPCODES but never the transaction-level rule, so a
     * block carrying a valid-signature tx with a future nLockTime and a
     * non-final nSequence was accepted here and rejected by Core: a split
     * with no invalid signature anywhere in it.
     *
     * Finality needs BOTH halves to fail, and the test pins both directions:
     *   - future nLockTime + non-final nSequence  -> non-final, rejected;
     *   - future nLockTime + nSequence 0xffffffff -> FINAL, accepted (this
     *     is the arm that catches an implementation that rejects on
     *     nLockTime alone, which would refuse a great many real mainnet
     *     transactions);
     *   - nLockTime 0 + non-final nSequence       -> FINAL, accepted.
     * Only the first is a rejection, and a test that checked it alone would
     * pass against a rule that is far too aggressive. */
    { static u8 nf[512]; u8 nfhash[32];
      long h_next = utxo_live_applied_height() + 1;
      long count_before = utxo_live_count();

      /* height-based nLockTime in the FUTURE (well under LOCKTIME_THRESHOLD,
       * so it is read as a height), with a non-final sequence */
      long nflen = mk_and_mine_locktime(nf, nfhash, prev, height1_txid,
                                        0x80000000u, 1800300000u,
                                        (u32)(h_next + 100), 0xfffffffeu);
      ck("VAL-4 non-final tx (future nLockTime + non-final nSequence) -> 0",
         utxo_live_dryrun_block(nf, (u64)nflen, h_next), 0);
      { const char* rr = utxo_live_last_reject();
        printf("VAL-4 reject reason: [%s]\n", rr ? rr : "(null)");
        ck("VAL-4 reason is bad-txns-nonfinal",
           rr && !strcmp(rr, "bad-txns-nonfinal"), 1); }
      ck("VAL-4 nothing applied", utxo_live_count(), count_before);

      /* same future nLockTime, but every input FINAL -> Core accepts */
      long finlen = mk_and_mine_locktime(nf, nfhash, prev, height1_txid,
                                         0x81000000u, 1800300001u,
                                         (u32)(h_next + 100), 0xffffffffu);
      { long r = utxo_live_dryrun_block(nf, (u64)finlen, h_next);
        if (r != 1) printf("      (reason: %s)\n", utxo_live_last_reject());
        ck("VAL-4 future nLockTime with FINAL sequences is still valid", r, 1); }

      /* nLockTime 0 short-circuits: non-final sequence is irrelevant */
      long z = mk_and_mine_locktime(nf, nfhash, prev, height1_txid,
                                    0x82000000u, 1800300002u, 0u, 0xfffffffeu);
      { long r = utxo_live_dryrun_block(nf, (u64)z, h_next);
        if (r != 1) printf("      (reason: %s)\n", utxo_live_last_reject());
        ck("VAL-4 nLockTime 0 is final regardless of nSequence", r, 1); } }

    /* ---- VAL-4 (BIP68 half): the ACTIVATION GATE ----
     * BIP68 applies only at or after CSVHeight -- 419,328 on mainnet -- and
     * this fixture chain runs at height ~150. So what can be proved HERE is
     * the gate, not the rule: below CSVHeight nothing is enforced, however
     * large the relative lock. That is the false-reject direction, and it is
     * the one that matters at this height: enforcing BIP68 early would reject
     * pre-BIP68 mainnet history outright.
     *
     * The arithmetic the rule performs above CSVHeight is pinned separately,
     * against hand-computed values from the BIP, in tests/test_bip68_locks.c.
     * Building a 419k-block fixture to reach three lines of arithmetic would
     * be theatre; saying so is better than a test that looks end-to-end and
     * silently exercises nothing.
     *
     * All four are ACCEPTS. A version of this that expected a rejection
     * passed for the wrong reason during development -- the transaction was
     * refused for a spent prevout, not for BIP68 -- which is why every case
     * here prints the reject reason when it fails. */
    { static u8 sq[512]; u8 sqhash[32];
      long h_next = utxo_live_applied_height() + 1;

      struct { u32 version; u32 seq; const char* what; } cases[] = {
        { 2u, 1000u,                 "v2, 1000-block relative lock" },
        { 2u, 10u,                   "v2, 10-block relative lock" },
        { 1u, 1000u,                 "v1 (BIP68 keys on nVersion >= 2)" },
        { 2u, 0x80000000u | 1000u,   "v2 with the DISABLE flag set" },
      };
      for (unsigned ci = 0; ci < sizeof cases / sizeof cases[0]; ci++){
          long n = mk_and_mine_seq(sq, sqhash, prev, height1_txid,
                                   0x90000000u + (ci << 24), 1800400000u + ci,
                                   cases[ci].version, cases[ci].seq);
          long r = utxo_live_dryrun_block(sq, (u64)n, h_next);
          if (r != 1) printf("      (reason: %s)\n", utxo_live_last_reject());
          char lbl[160];
          snprintf(lbl, sizeof lbl,
                   "VAL-4 below CSVHeight BIP68 is not enforced: %s", cases[ci].what);
          ck(lbl, r, 1);
      } }

    /* ---- VAL-3: an oversized block is refused, and changes nothing ---- */
    { static u8 big[1200000]; u8 bhash[32];
      /* 1,000,600 bytes of output script puts the stripped size just over
       * MAX_BLOCK_WEIGHT/4 = 1,000,000, so 4*stripped > 4,000,000. */
      long blen = mk_and_mine_oversize(big, bhash, prev, 0x70000000u, 1800200000u, 1000600UL);
      printf("oversize block: %ld bytes serialized (weight %ld)\n", blen, 4*blen);
      long count_before = utxo_live_count();
      long applied_before = utxo_live_applied_height();
      ck("VAL-3 dry run of the oversized block -> 0",
         utxo_live_dryrun_block(big, (u64)blen, utxo_live_applied_height()+1), 0);
      const char* rr = utxo_live_last_reject();
      printf("VAL-3 reject reason: [%s]\n", rr ? rr : "(null)");
      ck("VAL-3 reason is a SIZE rule, not something incidental",
         rr && (!strcmp(rr,"bad-blk-length") || !strcmp(rr,"bad-blk-weight")), 1);
      ck("VAL-3 UTXO count unchanged", utxo_live_count(), count_before);
      ck("VAL-3 applied height unchanged", utxo_live_applied_height(), applied_before); }

    /* and a block just UNDER the limit must still be accepted, so the rule
     * is a limit rather than a blanket refusal of large blocks */
    { static u8 ok[1200000]; u8 ohash[32];
      long olen = mk_and_mine_oversize(ok, ohash, prev, 0x71000000u, 1800200001u, 900000UL);
      printf("under-limit block: %ld bytes (weight %ld)\n", olen, 4*olen);
      ck("VAL-3 a large-but-legal block still passes the size rules",
         utxo_live_dryrun_block(ok, (u64)olen, utxo_live_applied_height()+1), 1); }

    utxo_live_close();
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
