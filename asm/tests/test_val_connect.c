/* tests/test_val_connect.c -- VAL-1 / VAL-2 (audit 2026-09-03): the
 * block-connect value rules. Regression gate for the coinbase consensus
 * rules (bad-cb-missing / -length / -height, bad-txns-prevout-null) and
 * ConnectBlock's money ledger (per-output & per-tx MAX_MONEY,
 * in >= out, cb_out <= subsidy + fees, bad-cb-amount).
 *
 * Fixture (test_blk_dryrun shape): 150 mined coinbase-only blocks under
 * chainparams regtest (BIP34 from height 1, halving 150, PoW retarget not
 * armed), then BLOCK 150 built per case: coinbase + one OP_TRUE spend of
 * height-0's coinbase output (50 BTC in). Every reject asserts Core's exact
 * reason. Mutations are either value-field overwrites or length-preserving
 * byte patches -- the declared vs emitted lengths ALWAYS agree, so only the
 * rule under test can fire (a desynchronized length byte gets the block
 * rejected by the parse-consistency machinery with no reason set: that is
 * the WRONG assertion to make).
 *
 * Negative control: revert the Phase 0.15 / 0.5 / 4.5 checks in
 * daemon/utxo_live.c and every FAIL case below dry-runs clean (returns 1).
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
extern int chainparams_select(const char* name);

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
    fprintf(stderr, "test_val_connect: unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
static void ck_reason(const char* l, const char* want){
    const char* rr = utxo_live_last_reject();
    if (rr && !strcmp(rr, want)) printf("PASS %s (reason=[%s])\n", l, rr);
    else { printf("FAIL %s reason=[%s] want=[%s]\n", l, rr?rr:"(null)", want); failures++; }
}
static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
static u8 g_txid_scratch[1<<12];

/* CScript(h) minimal, mirroring daemon/utxo_live.c val_build_height_push
 * byte-for-byte: h in 1..16 -> OP_1..OP_16 (1 byte); else
 * [n][LE bytes][0x00 pad if high bit set] (n = byte count). For h=150=0x96
 * that is the 3-byte push [0x02][0x96][0x00]; h=99=0x63 is [0x01][0x63].
 * Returns the CScript length written to ss. */
static int cscript_height(long h, u8* ss){
    if (h >= 1 && h <= 16){ ss[0] = (u8)(0x50 + h); return 1; }
    u8 num[6]; int nn = 0; u64 vn = (u64)(h < 0 ? 0 : h);
    if (vn == 0) num[nn++] = 0;
    while (vn){ num[nn++] = (u8)(vn & 0xff); vn >>= 8; }
    if (num[nn-1] & 0x80) num[nn++] = 0;
    ss[0] = (u8)nn;
    for (int i=0;i<nn;i++) ss[1+i] = num[i];
    return 1 + nn;
}

/* Build a coinbase with an EXPLICIT scriptSig (declared len == emitted len,
 * always). */
static long mk_coinbase_ss(u8* tx, u8 txid[32], const u8* ss, int ssn, u64 value){
    u8* q = tx;
    put32(q,1); q+=4; *q++ = 1;                        /* version, n_in=1 */
    memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4; /* null prevout */
    *q++ = (u8)ssn; memcpy(q, ss, (size_t)ssn); q += ssn;   /* scriptSig */
    put32(q,0xffffffffu); q+=4;                        /* sequence */
    *q++ = 1; put64(q, value); q+=8;                   /* n_out=1, value */
    *q++ = 1; *q++ = 0x51;                             /* OP_TRUE spk */
    put32(q,0); q+=4;                                  /* locktime */
    long n = q - tx;
    tx_txid(txid, tx, (unsigned long)n, g_txid_scratch, sizeof g_txid_scratch);
    return n;
}
/* BIP34-valid coinbase at height h: height push + filler to 6 bytes total,
 * paying value. */
static long mk_coinbase_h(u8* tx, u8 txid[32], long h, u64 value){
    u8 ss[8]; int ssn = cscript_height(h, ss);
    for (; ssn < 6; ssn++) ss[ssn] = (u8)(0x11 + ssn);
    return mk_coinbase_ss(tx, txid, ss, ssn, value);
}
/* 1-in 1-out OP_TRUE spend: prevout spend_prev:0 (empty scriptSig, seq
 * final), output v to OP_TRUE. */
static long mk_spend(u8* tx, u8 txid[32], const u8 spend_prev[32], u64 v){
    u8* q = tx;
    put32(q,1); q+=4; *q++ = 1;
    memcpy(q, spend_prev, 32); q+=32; put32(q,0); q+=4;
    *q++ = 0; put32(q,0xffffffffu); q+=4;
    *q++ = 1; put64(q, v); q+=8; *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long n = q - tx;
    tx_txid(txid, tx, (unsigned long)n, g_txid_scratch, sizeof g_txid_scratch);
    return n;
}

typedef struct { long cb_at, sp_at, len; } bko_t;
/* coinbase scriptSig length byte / content start offsets within the cb tx */
#define CB_SSLEN_OFF   (4+1+32+4)
#define CB_SS_OFF      (CB_SSLEN_OFF + 1)
/* full block builder: coinbase scriptSig overridable (NULL -> valid h push) */
static long build_block(u8* raw, u8 hash[32], const u8 prev[32], long height,
                        const u8 h0_cbtxid[32], u64 cb_value, u64 spend_out,
                        const u8* cb_ss, int cb_ssn, bko_t* o){
    u8 cb[96], cbtxid[32], sp[96], sptxid[32];
    long cblen = cb_ss ? mk_coinbase_ss(cb, cbtxid, cb_ss, cb_ssn, cb_value)
                       : mk_coinbase_h(cb, cbtxid, height, cb_value);
    long splen = mk_spend(sp, sptxid, h0_cbtxid, spend_out);
    u8 pair[64], root[32];
    memcpy(pair, cbtxid, 32); memcpy(pair+32, sptxid, 32); sha256d(root, pair, 64);
    u8* p = raw;
    put32(p,1); p+=4; memcpy(p, prev, 32); p+=32; memcpy(p, root, 32); p+=32;
    put32(p, 1800000000u + (u32)height); p+=4; put32(p, 0x207fffffu); p+=4; put32(p,0); p+=4;
    *p++ = 2;
    o->cb_at = p - raw; memcpy(p, cb, (size_t)cblen); p += cblen;
    o->sp_at = p - raw; memcpy(p, sp, (size_t)splen); p += splen;
    o->len = p - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return o->len;
}

static u8 store_buf[4096];

int main(void){
    tt_isolate();
    ck("select regtest", chainparams_select("regtest"), 1);
    memset(store_buf,0,sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);

    long n1 = 150;
    u8 prev[32]; memset(prev,0,32);
    u8 h0_cbtxid[32]; memset(h0_cbtxid,0,32);
    for (long h=0; h<n1; h++){
        u8 raw[256], hash[32], cb[96], txid[32];
        long txlen = mk_coinbase_h(cb, txid, h, 50000000ULL);
        if (h==0) memcpy(h0_cbtxid, txid, 32);
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

    static u8 blk[512]; u8 bhash[32]; bko_t o;
    long blen;

    /* BASELINE: valid block dry-runs clean (regtest h=150: subsidy 0 since
     * 150/150=1 halving -> 5e9>>1 = 2.5e9; fees 10e6... log confirms
     * subsidy+fees = 2,510,000,000 >= cb 50,000,000). */
    blen = build_block(blk, bhash, prev, n1, h0_cbtxid, 50000000ULL, 40000000ULL, NULL, 0, &o);
    ck("valid block dry-runs clean", utxo_live_dryrun_block(blk, (u64)blen, n1), 1);

    /* VAL-2 inflated coinbase (1,000,000 BTC > subsidy + fees) */
    blen = build_block(blk, bhash, prev, n1, h0_cbtxid, 100000000000000ULL, 40000000ULL, NULL, 0, &o);
    ck("inflated coinbase rejected", utxo_live_dryrun_block(blk, (u64)blen, n1), 0);
    ck_reason("reason bad-cb-amount", "bad-cb-amount");

    /* VAL-2 spend pays 60 BTC from a 50 BTC input */
    blen = build_block(blk, bhash, prev, n1, h0_cbtxid, 50000000ULL, 6000000000ULL, NULL, 0, &o);
    ck("spend exceeding input rejected", utxo_live_dryrun_block(blk, (u64)blen, n1), 0);
    ck_reason("reason bad-txns-in-belowout", "bad-txns-in-belowout");

    /* VAL-2 spend output beyond MAX_MONEY (0x8000... = negative CAmount) */
    blen = build_block(blk, bhash, prev, n1, h0_cbtxid, 50000000ULL, 0x8000000000000000ULL, NULL, 0, &o);
    ck("out-of-range output rejected", utxo_live_dryrun_block(blk, (u64)blen, n1), 0);
    ck_reason("reason bad-txns-vout-toolarge", "bad-txns-vout-toolarge");

    /* VAL-1 null prevout in a non-coinbase tx: the TRUE null outpoint is
     * hash==0 && index==0xFFFFFFFF; patch both fields (lengths preserved,
     * merkle/PoW untouched). */
    blen = build_block(blk, bhash, prev, n1, h0_cbtxid, 50000000ULL, 40000000ULL, NULL, 0, &o);
    memset(blk + o.sp_at + 4 + 1, 0, 32);
    put32(blk + o.sp_at + 4 + 1 + 32, 0xffffffffu);
    ck("null prevout in tx1 rejected", utxo_live_dryrun_block(blk, (u64)blen, n1), 0);
    ck_reason("reason bad-txns-prevout-null", "bad-txns-prevout-null");

    /* VAL-1 coinbase scriptSig too short: a genuinely 1-byte scriptSig
     * (built consistently; bad-cb-length is checked before bad-cb-height so
     * the [0x01] content encodes nothing). */
    {
        u8 ss1[1] = { 0x01 };
        blen = build_block(blk, bhash, prev, n1, h0_cbtxid, 50000000ULL, 40000000ULL, ss1, 1, &o);
        ck("1-byte coinbase scriptSig rejected", utxo_live_dryrun_block(blk, (u64)blen, n1), 0);
        ck_reason("reason bad-cb-length", "bad-cb-length");
    }

    /* VAL-1 BIP34: well-formed coinbase whose push encodes the WRONG height
     * (99, not 150) -- CScript(99) = [0x01][0x63], length-consistent. */
    {
        u8 ss99[6]; int n99 = cscript_height(99, ss99);
        for (; n99 < 6; n99++) ss99[n99] = (u8)(0x11 + n99);
        blen = build_block(blk, bhash, prev, n1, h0_cbtxid, 50000000ULL, 40000000ULL, ss99, 6, &o);
        ck("wrong BIP34 height rejected", utxo_live_dryrun_block(blk, (u64)blen, n1), 0);
        ck_reason("reason bad-cb-height", "bad-cb-height");
    }

    /* VAL-1 coinbase WITHOUT a height push at all (extranonce-only,
     * pre-BIP34 shape; regtest gates BIP34 from height 1) */
    {
        u8 ssx[6] = { 0x03, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };   /* push 3 bytes: not the height */
        blen = build_block(blk, bhash, prev, n1, h0_cbtxid, 50000000ULL, 40000000ULL, ssx, 6, &o);
        ck("no-height-push coinbase rejected", utxo_live_dryrun_block(blk, (u64)blen, n1), 0);
        ck_reason("reason bad-cb-height (no push)", "bad-cb-height");
    }

    /* VAL-1 coinbase with a NON-null prevout (point at some other outpoint:
     * hash preserved from h0's coinbase, index 0 -- a real existing coin). */
    blen = build_block(blk, bhash, prev, n1, h0_cbtxid, 50000000ULL, 40000000ULL, NULL, 0, &o);
    memcpy(blk + o.cb_at + 4 + 1, h0_cbtxid, 32);
    ck("coinbase with real prevout rejected", utxo_live_dryrun_block(blk, (u64)blen, n1), 0);
    ck_reason("reason bad-cb-missing", "bad-cb-missing");

    /* ---- SCR-6 (audit 2026-09-03): block sigop budget. A spend tx whose
     * OUTPUT script is 1001 OP_CHECKMULTISIG bytes: the inaccurate legacy
     * count charges 20 each = 20020, times WITNESS_SCALE_FACTOR 4 = 80080 >
     * MAX_BLOCK_SIGOPS_COST (80,000). The output script is only CREATED (never
     * executed), so the spend itself stays valid and every earlier gate
     * passes -- the sigop budget is the only reason to refuse. Pre-fix there
     * is no budget at all and the block dry-runs clean (the negative control). */
    {
        /* build coinbase (valid h push) + a spend whose output script is fat.
         * Mirrors build_block's layout exactly; only tx1's output script and
         * the merkle root change. */
        u8 cb[96], cbtxid[32];
        long cblen = mk_coinbase_h(cb, cbtxid, n1, 50000000ULL);
        u8 sp[2048], sptxid[32];
        u8* q = sp;
        put32(q,1); q+=4; *q++ = 1;                       /* version, 1 input */
        memcpy(q, h0_cbtxid, 32); q+=32; put32(q,0); q+=4;/* prevout = h0 cb:0 */
        *q++ = 0; put32(q,0xffffffffu); q+=4;             /* empty scriptSig, seq */
        *q++ = 1; put64(q, 40000000ULL); q+=8;            /* 1 output, value */
        *q++ = 0xfd; *q++ = 0xe9; *q++ = 0x03;            /* script len 1001 (0x03e9) LE16 */
        memset(q, 0xae, 1001); q += 1001;                 /* 1001 OP_CHECKMULTISIG */
        put32(q,0); q+=4;                                 /* locktime */
        long splen = q - sp;
        tx_txid(sptxid, sp, (unsigned long)splen, g_txid_scratch, sizeof g_txid_scratch);
        u8 pair[64], root[32];
        memcpy(pair, cbtxid, 32); memcpy(pair+32, sptxid, 32); sha256d(root, pair, 64);
        static u8 fat[4096];
        u8* p = fat;
        put32(p,1); p+=4; memcpy(p, prev, 32); p+=32; memcpy(p, root, 32); p+=32;
        put32(p, 1800000000u+(u32)n1); p+=4; put32(p,0x207fffffu); p+=4; put32(p,0); p+=4;
        *p++ = 2; memcpy(p, cb, (size_t)cblen); p += cblen;
        memcpy(p, sp, (size_t)splen); p += splen;
        long flen = p - fat;
        u32 nonce=0; while (!pow_check(fat)) { nonce++; put32(fat+76, nonce); }
        u8 fhash[32]; block_hash(fhash, fat);
        ck("SCR-6: block with 80,080 sigop-cost rejected",
           utxo_live_dryrun_block(fat, (u64)flen, n1), 0);
        ck_reason("reason bad-blk-sigops", "bad-blk-sigops");
    }

    /* PURITY: every reject above mutated nothing */
    ck("UTXO count unchanged", utxo_live_count(), count0);
    ck("applied height unchanged", utxo_live_applied_height(), n1 - 1);

    /* COHERENCE: a valid block still APPLIES through catch-up */
    blen = build_block(blk, bhash, prev, n1, h0_cbtxid, 50000000ULL, 40000000ULL, NULL, 0, &o);
    ck("store_append valid block", store_append(store_buf, bhash, blk, blen), n1);
    ck("catch-up applies it", utxo_live_catchup(store_buf), 1);
    ck("applied height now 150", utxo_live_applied_height(), n1);

    utxo_live_close();
    printf("\n%s (%d failures)\n", failures ? "VAL_CONNECT FAILED" : "VAL_CONNECT PASSED", failures);
    return failures ? 1 : 0;
}
