/* tests/test_con_block_class.c -- CON-1 / CON-3 / CON-4 (audit 2026-10-23):
 * how a block that fails the connect checks is CLASSIFIED.
 *
 * A REJECT invalidates the block's hash (the reject hook: invalid.dat,
 * archive truncate, headers rollback). A MUTATION only drops the bytes and
 * fetches them again. Core files every failure a peer can cause without
 * proof of work -- anything in the witness bytes, which the header does not
 * commit to -- as BLOCK_MUTATED or as a deserialization failure, and neither
 * ever marks the hash. So:
 *
 *   CON-1 (a) junk witness bytes pushing a real block over 4,000,000 weight:
 *             Core runs CheckWitnessMalleation BEFORE bad-blk-weight, so the
 *             block is mutated (bad-witness-merkle-match), not overweight.
 *         (b) a coinbase with the segwit marker and an empty witness stack:
 *             Core's deserializer throws "Superfluous witness record" --
 *             mutated, not a refusal.
 *         (c) a coinbase nonce whose length is encoded non-canonically
 *             (fd 20 00): Core's ReadCompactSize throws -- mutated.
 *         and the true refusal still stands: a block that is overweight AS
 *         COMMITTED is REJECTED bad-blk-weight.
 *   CON-3     a transaction with zero outputs (coinbase or not) is rejected
 *             bad-txns-vout-empty (consensus/tx_check.cpp), as committed data.
 *   CON-4     a non-coinbase transaction carrying the 00 01 marker with every
 *             stack empty, in a block whose commitment covers exactly those
 *             bytes (what a miner would have to produce): Core cannot
 *             deserialize it -- mutated; it was accepted.
 *
 * Fixture: test_val_connect's (150 regtest coinbase-only blocks, segwit
 * active from 0), except that height 0's coinbase pays P2WSH(OP_TRUE), so a
 * witness spend of it is valid; every case is a dry run of block 150 =
 * coinbase + one spend of that output.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
extern void sha256_full(u8 out[32], const void* msg, long len);
extern int chainparams_select(const char* name);

extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_count(void);
extern long utxo_live_applied_height(void);
extern void utxo_live_close(void);
extern long utxo_live_dryrun_block(const u8* blockbuf, u64 blocklen, long height);
extern const char* utxo_live_last_reject(void);
extern long utxo_live_last_mutated(void);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u;(void)txid;(void)index;(void)value;(void)script;(void)slen;
    fprintf(stderr, "test_con_block_class: unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
/* expect a refusal with `reason`, classified mutated (1) or reject (0) */
static void ck_fail(const char* l, long r, const char* reason, long mutated){
    const char* rr = utxo_live_last_reject();
    long m = utxo_live_last_mutated();
    if (r == 0 && rr && !strcmp(rr, reason) && m == mutated)
        printf("PASS %s (reason=[%s] %s)\n", l, rr, m ? "MUTATED" : "REJECT");
    else { printf("FAIL %s r=%ld reason=[%s] %s, want r=0 [%s] %s\n", l, r, rr ? rr : "(null)",
                  m ? "MUTATED" : "REJECT", reason, mutated ? "MUTATED" : "REJECT"); failures++; }
}
static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
static u8* put_cs(u8* q, u64 v){
    if (v < 0xfd){ *q++ = (u8)v; return q; }
    if (v <= 0xffff){ *q++ = 0xfd; *q++ = (u8)v; *q++ = (u8)(v>>8); return q; }
    *q++ = 0xfe; put32(q, (u32)v); return q + 4;
}
static u8 g_txid_scratch[1<<12];

static int cscript_height(long h, u8* ss){
    if (h >= 1 && h <= 16){ ss[0] = (u8)(0x50 + h); return 1; }
    u8 num[6]; int nn = 0; u64 vn = (u64)h;
    while (vn){ num[nn++] = (u8)(vn & 0xff); vn >>= 8; }
    if (num[nn-1] & 0x80) num[nn++] = 0;
    ss[0] = (u8)nn;
    for (int i=0;i<nn;i++) ss[1+i] = num[i];
    return 1 + nn;
}

static u8 g_wsh_spk[34];   /* 00 20 sha256(51) */
/* Coinbase at height h. commit == NULL: legacy form, one OP_TRUE output
 * (nout_zero: no outputs at all). commit != NULL: segwit form with a second
 * output carrying the BIP141 commitment, and a witness for input 0 shaped by
 * wit: 0 = one 32-byte zero nonce (valid), 1 = zero items (marker, empty
 * stack), 2 = one 32-byte nonce with its length encoded fd 20 00. */
enum { CBW_NONCE = 0, CBW_EMPTY = 1, CBW_NONCANON = 2 };
static long mk_coinbase(u8* tx, u8 txid[32], long h, const u8* commit, int wit, int nout_zero, int pay_wsh){
    u8* q = tx;
    put32(q,1); q+=4;
    if (commit){ *q++ = 0x00; *q++ = 0x01; }
    *q++ = 1;
    memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
    u8 ss[8]; int ssn = cscript_height(h, ss);
    for (; ssn < 6; ssn++) ss[ssn] = (u8)(0x11 + ssn);
    *q++ = (u8)ssn; memcpy(q, ss, (size_t)ssn); q += ssn;
    put32(q,0xffffffffu); q+=4;
    if (nout_zero) *q++ = 0;
    else {
        *q++ = commit ? 2 : 1;
        put64(q, 50000000ULL); q+=8;
        if (pay_wsh){ *q++ = 34; memcpy(q, g_wsh_spk, 34); q += 34; }
        else { *q++ = 1; *q++ = 0x51; }
        if (commit){
            put64(q, 0); q+=8; *q++ = 38;
            *q++ = 0x6a; *q++ = 0x24; *q++ = 0xaa; *q++ = 0x21; *q++ = 0xa9; *q++ = 0xed;
            memcpy(q, commit, 32); q += 32;
        }
    }
    if (commit){
        if (wit == CBW_NONCE){ *q++ = 1; *q++ = 32; memset(q, 0, 32); q += 32; }
        else if (wit == CBW_EMPTY){ *q++ = 0; }
        else { *q++ = 1; *q++ = 0xfd; *q++ = 32; *q++ = 0; memset(q, 0, 32); q += 32; }
    }
    put32(q,0); q+=4;
    long n = q - tx;
    tx_txid(txid, tx, (unsigned long)n, g_txid_scratch, sizeof g_txid_scratch);
    return n;
}
/* 1-in spend of prev:0 (the P2WSH(OP_TRUE) output). wit_len < 0: legacy
 * form; wit_len == 0: the 00 01 marker with an empty stack (superfluous);
 * wit_len > 0: the witness [wit_len-1 bytes of 0x5a junk if > 1] [51] --
 * the witness script last. nout_zero: no outputs. */
static long mk_spend(u8* tx, u8 txid[32], const u8 prev[32], long wit_len, int nout_zero){
    u8* q = tx;
    put32(q,1); q+=4;
    if (wit_len >= 0){ *q++ = 0x00; *q++ = 0x01; }
    *q++ = 1;
    memcpy(q, prev, 32); q+=32; put32(q,0); q+=4;
    *q++ = 0; put32(q,0xffffffffu); q+=4;
    if (nout_zero) *q++ = 0;
    else { *q++ = 1; put64(q, 40000000ULL); q+=8; *q++ = 1; *q++ = 0x51; }
    if (wit_len == 0) *q++ = 0;
    else if (wit_len == 1){ *q++ = 1; *q++ = 1; *q++ = 0x51; }
    else if (wit_len > 1){ *q++ = 2; q = put_cs(q, (u64)(wit_len-1)); memset(q, 0x5a, (size_t)(wit_len-1)); q += wit_len-1;
                           *q++ = 1; *q++ = 0x51; }
    put32(q,0); q+=4;
    long n = q - tx;
    tx_txid(txid, tx, (unsigned long)n, g_txid_scratch, sizeof g_txid_scratch);
    return n;
}
/* BIP141 commitment over [coinbase(=0), sp]: sha256d(sha256d(0^32||wtxid)||0^32) */
static void commitment_for(u8 out[32], const u8* sp, long splen){
    u8 pair[64], root[32], buf[64];
    memset(pair, 0, 32); sha256d(pair + 32, sp, splen);
    sha256d(root, pair, 64);
    memcpy(buf, root, 32); memset(buf + 32, 0, 32);
    sha256d(out, buf, 64);
}
static long assemble(u8* raw, const u8 prev[32], long height,
                     const u8* cb, long cblen, const u8 cbtxid[32],
                     const u8* sp, long splen, const u8 sptxid[32]){
    u8 pair[64], root[32];
    memcpy(pair, cbtxid, 32); memcpy(pair+32, sptxid, 32); sha256d(root, pair, 64);
    u8* p = raw;
    put32(p,0x20000000u); p+=4; memcpy(p, prev, 32); p+=32; memcpy(p, root, 32); p+=32;
    put32(p, 1800000000u + (u32)height); p+=4; put32(p, 0x207fffffu); p+=4; put32(p,0); p+=4;
    *p++ = 2;
    memcpy(p, cb, (size_t)cblen); p += cblen;
    memcpy(p, sp, (size_t)splen); p += splen;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    return p - raw;
}

static u8 store_buf[4096];
#define BIG_WIT 4000000L
static u8 g_blk[BIG_WIT + 4096];
static u8 g_sp[BIG_WIT + 1024];

int main(void){
    tt_isolate();
    ck("select regtest", chainparams_select("regtest"), 1);
    memset(store_buf,0,sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);
    { u8 one = 0x51; g_wsh_spk[0] = 0x00; g_wsh_spk[1] = 0x20; sha256_full(g_wsh_spk + 2, &one, 1); }

    long n1 = 150;
    u8 prev[32]; memset(prev,0,32);
    u8 h0_cbtxid[32]; memset(h0_cbtxid,0,32);
    u8 h1_cbtxid[32]; memset(h1_cbtxid,0,32);   /* pays OP_TRUE: a legacy spend of it is valid */
    for (long h=0; h<n1; h++){
        u8 raw[320], hash[32], cb[160], txid[32];
        long txlen = mk_coinbase(cb, txid, h, NULL, 0, 0, h == 0);
        if (h==0) memcpy(h0_cbtxid, txid, 32);
        if (h==1) memcpy(h1_cbtxid, txid, 32);
        u8* o = raw;
        put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, txid, 32); o+=32;
        put32(o, 1800000000u+(u32)h); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
        *o++ = 1; memcpy(o, cb, (size_t)txlen); o += txlen;
        long len = o - raw;
        u32 nonce=0; while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
        block_hash(hash, raw);
        if (store_append(store_buf, hash, raw, len) != h){ printf("FAIL append h=%ld\n",h); failures++; }
        memcpy(prev, hash, 32);
    }
    ck("catch-up applied 150 blocks", utxo_live_catchup(store_buf), n1);
    long count0 = utxo_live_count();

    u8 cb[256], cbtxid[32], sptxid[32], commit[32];
    long cblen, splen, blen;

    /* BASELINE: a segwit block with a valid commitment and a P2WSH
     * witness spend dry-runs clean (proves the fixture's commitment math). */
    splen = mk_spend(g_sp, sptxid, h0_cbtxid, 1, 0);
    commitment_for(commit, g_sp, splen);
    cblen = mk_coinbase(cb, cbtxid, n1, commit, CBW_NONCE, 0, 0);
    blen = assemble(g_blk, prev, n1, cb, cblen, cbtxid, g_sp, splen, sptxid);
    ck("baseline segwit block with commitment dry-runs clean", utxo_live_dryrun_block(g_blk, (u64)blen, n1), 1);

    /* CON-1 (a): the same block, the spend's witness item grown to 4 MB by
     * a peer (txid, merkle root and block hash unchanged; the commitment
     * still covers the 1-item witness). Weight > 4,000,000. */
    {
        u8 small_commit[32]; memcpy(small_commit, commit, 32);
        u8 tid[32];
        splen = mk_spend(g_sp, tid, h0_cbtxid, BIG_WIT, 0);
        ck("CON-1 fixture: junk witness keeps the txid", memcmp(tid, sptxid, 32), 0);
        cblen = mk_coinbase(cb, cbtxid, n1, small_commit, CBW_NONCE, 0, 0);
        blen = assemble(g_blk, prev, n1, cb, cblen, cbtxid, g_sp, splen, sptxid);
        ck_fail("CON-1 (a) junk witness over 4M weight is MUTATED, not bad-blk-weight",
                utxo_live_dryrun_block(g_blk, (u64)blen, n1), "bad-witness-merkle-match", 1);

        /* the true refusal: the commitment covers the 4 MB witness, i.e.
         * the block is overweight as mined */
        commitment_for(commit, g_sp, splen);
        cblen = mk_coinbase(cb, cbtxid, n1, commit, CBW_NONCE, 0, 0);
        blen = assemble(g_blk, prev, n1, cb, cblen, cbtxid, g_sp, splen, sptxid);
        ck_fail("CON-1 overweight as committed is still REJECTED bad-blk-weight",
                utxo_live_dryrun_block(g_blk, (u64)blen, n1), "bad-blk-weight", 0);
    }

    /* CON-1 (b): coinbase with the marker but an empty witness stack */
    splen = mk_spend(g_sp, sptxid, h0_cbtxid, 1, 0);
    commitment_for(commit, g_sp, splen);
    cblen = mk_coinbase(cb, cbtxid, n1, commit, CBW_EMPTY, 0, 0);
    blen = assemble(g_blk, prev, n1, cb, cblen, cbtxid, g_sp, splen, sptxid);
    ck_fail("CON-1 (b) coinbase marker + empty stack is MUTATED",
            utxo_live_dryrun_block(g_blk, (u64)blen, n1), "block-decode-failed", 1);

    /* CON-1 (c): coinbase nonce length encoded fd 20 00 */
    cblen = mk_coinbase(cb, cbtxid, n1, commit, CBW_NONCANON, 0, 0);
    blen = assemble(g_blk, prev, n1, cb, cblen, cbtxid, g_sp, splen, sptxid);
    ck_fail("CON-1 (c) non-canonical nonce length is MUTATED",
            utxo_live_dryrun_block(g_blk, (u64)blen, n1), "block-decode-failed", 1);

    /* CON-4: tx1 carries 00 01 + an empty stack, and the commitment covers
     * exactly those bytes (a miner-made block) */
    splen = mk_spend(g_sp, sptxid, h1_cbtxid, 0, 0);
    commitment_for(commit, g_sp, splen);
    cblen = mk_coinbase(cb, cbtxid, n1, commit, CBW_NONCE, 0, 0);
    blen = assemble(g_blk, prev, n1, cb, cblen, cbtxid, g_sp, splen, sptxid);
    ck_fail("CON-4 superfluous witness record on tx1 (commitment matching) is MUTATED",
            utxo_live_dryrun_block(g_blk, (u64)blen, n1), "block-decode-failed", 1);

    /* CON-3: zero-output transactions */
    splen = mk_spend(g_sp, sptxid, h1_cbtxid, -1, 1);
    cblen = mk_coinbase(cb, cbtxid, n1, NULL, 0, 0, 0);
    blen = assemble(g_blk, prev, n1, cb, cblen, cbtxid, g_sp, splen, sptxid);
    ck_fail("CON-3 zero-output tx1 is REJECTED bad-txns-vout-empty",
            utxo_live_dryrun_block(g_blk, (u64)blen, n1), "bad-txns-vout-empty", 0);
    splen = mk_spend(g_sp, sptxid, h1_cbtxid, -1, 0);
    cblen = mk_coinbase(cb, cbtxid, n1, NULL, 0, 1, 0);
    blen = assemble(g_blk, prev, n1, cb, cblen, cbtxid, g_sp, splen, sptxid);
    ck_fail("CON-3 zero-output coinbase is REJECTED bad-txns-vout-empty",
            utxo_live_dryrun_block(g_blk, (u64)blen, n1), "bad-txns-vout-empty", 0);

    /* PURITY + COHERENCE */
    ck("UTXO count unchanged", utxo_live_count(), count0);
    ck("applied height unchanged", utxo_live_applied_height(), n1 - 1);
    splen = mk_spend(g_sp, sptxid, h0_cbtxid, 1, 0);
    commitment_for(commit, g_sp, splen);
    cblen = mk_coinbase(cb, cbtxid, n1, commit, CBW_NONCE, 0, 0);
    blen = assemble(g_blk, prev, n1, cb, cblen, cbtxid, g_sp, splen, sptxid);
    { u8 bh[32]; block_hash(bh, g_blk);
      ck("store_append valid segwit block", store_append(store_buf, bh, g_blk, blen), n1); }
    ck("catch-up applies it", utxo_live_catchup(store_buf), 1);
    ck("applied height now 150", utxo_live_applied_height(), n1);

    utxo_live_close();
    printf("\n%s (%d failures)\n", failures ? "CON_BLOCK_CLASS FAILED" : "CON_BLOCK_CLASS PASSED", failures);
    return failures ? 1 : 0;
}
