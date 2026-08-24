/* test_rpc_chain.c -- blockchain-query / node-status RPCs (asm/rpc_chain.c)
 * driven in-process through rpc_dispatch() against a synthetic archive.
 *
 * The archive is built in a throwaway temp dir with the REAL store primitives
 * (store_init/store_append -> index.dat + blk00000.dat), so the RPC module
 * reads exactly what bitcoin_rpcd would read from a datadir:
 *   height 0: the real mainnet genesis block (known hash / merkle / header hex
 *             act as an oracle for the renderers);
 *   height 1, 2: one legacy coinbase each;
 *   height 3: a SEGWIT coinbase (witness reserved value), a legacy spend with
 *             a DER signature + pubkey scriptSig (exercises Core's [ALL]
 *             sighash decode in scriptSig.asm), and a P2WPKH spend with a
 *             2-item witness (exercises txinwitness, wtxid != txid,
 *             strippedsize/weight).
 * chainwork.dat is deliberately absent so the computed fallback is covered;
 * expected values are the well-known genesis-era constants (0x100010001 per
 * block at difficulty 1).
 *
 * Every expected string below is Core's own rendering for that field.
 */
#include "../rpc_json.h"
#include "../rpc_commands.h"
#include "../rpc_chain.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "test_tmpdir.h"

extern int  store_init(void* st);
extern long store_append(void* st, const unsigned char* hash32, const void* blk, long len);
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void merkle_root(unsigned char out[32], void* hashes, unsigned long n);

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }
static void ck_str(const char* l, const char* got, const char* want){
    int c = got && want && !strcmp(got, want);
    printf("%s %s\n", c ? "ok  :" : "FAIL:", l);
    if (!c){ printf("      got : [%s]\n      want: [%s]\n", got ? got : "(null)", want ? want : "(null)"); fails++; }
}
static const char* S(const rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o, k) : NULL; return v ? v->str : NULL; }
static rj_val* G(const rj_val* o, const char* k){ return o ? rj_obj_get(o, k) : NULL; }

static int hx(unsigned char* out, const char* h){ size_t n = strlen(h)/2; for (size_t i = 0; i < n; i++){ unsigned v; sscanf(h+2*i, "%2x", &v); out[i] = (unsigned char)v; } return (int)n; }
static void tohex(char* out, const unsigned char* b, size_t n){ for (size_t i = 0; i < n; i++) sprintf(out+2*i, "%02x", b[i]); out[2*n] = 0; }
static void tohex_rev(char* out, const unsigned char* b, size_t n){ for (size_t i = 0; i < n; i++) sprintf(out+2*i, "%02x", b[n-1-i]); out[2*n] = 0; }

/* ---- rpc call helper ---- */
static rpc_wallet g_w;
static rj_val* call(const char* method, const char* params_json, long* ec, const char** em){
    rj_val* params = params_json ? rj_parse(params_json, strlen(params_json)) : NULL;
    rj_val* res = NULL; *ec = 0; *em = NULL;
    int ok = rpc_dispatch(method, params, &g_w, &res, ec, em);
    if (params) rj_free(params);
    if (!ok){ if (res) rj_free(res); return NULL; }
    return res;
}
static void expect_err(const char* label, const char* method, const char* params, long code, const char* msg){
    long ec; const char* em; rj_val* r = call(method, params, &ec, &em);
    int c = r == NULL && ec == code && em && !strcmp(em, msg);
    printf("%s %s\n", c ? "ok  :" : "FAIL:", label);
    if (!c){ printf("      got : code=%ld msg=[%s]%s\n      want: code=%ld msg=[%s]\n", ec, em ? em : "(null)", r ? " (got a result)" : "", code, msg); fails++; }
    if (r) rj_free(r);
}

/* ---- tx builders ---- */
static size_t put_u32(unsigned char* p, unsigned v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; return 4; }
static size_t put_u64(unsigned char* p, unsigned long long v){ for (int i = 0; i < 8; i++) p[i] = (unsigned char)(v >> (8*i)); return 8; }
static unsigned char P2PKH[25] = {0x76,0xa9,0x14, 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x01,0x02,0x03,0x04,0x05, 0x88,0xac};
static unsigned char P2WPKH[22] = {0x00,0x14, 0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0,0xb1,0xb2,0xb3,0xb4};
static unsigned char P2TR[34]   = {0x51,0x20, 0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf,0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf,0xe0};
static unsigned char SIG[71];   /* strict-DER 0x30 0x44 02 20 r 02 20 s + 0x01 (SIGHASH_ALL) */
static unsigned char PUB[33];

static size_t coinbase_legacy(unsigned char* o, unsigned height){
    size_t n = 0;
    n += put_u32(o+n, 1); o[n++] = 1;
    memset(o+n, 0, 32); n += 32; n += put_u32(o+n, 0xffffffffu);
    o[n++] = 2; o[n++] = 0x01; o[n++] = (unsigned char)height;   /* scriptSig: push1 <height> */
    n += put_u32(o+n, 0xffffffffu);
    o[n++] = 1; n += put_u64(o+n, 5000000000ULL); o[n++] = 25; memcpy(o+n, P2PKH, 25); n += 25;
    n += put_u32(o+n, 0);
    return n;
}
/* segwit coinbase: marker/flag, 1 in, 1 out (P2WPKH), witness = [32 zero bytes] */
static size_t coinbase_segwit(unsigned char* o){
    size_t n = 0;
    n += put_u32(o+n, 1); o[n++] = 0; o[n++] = 1; o[n++] = 1;
    memset(o+n, 0, 32); n += 32; n += put_u32(o+n, 0xffffffffu);
    o[n++] = 2; o[n++] = 0x01; o[n++] = 0x03;
    n += put_u32(o+n, 0xffffffffu);
    o[n++] = 1; n += put_u64(o+n, 5000000000ULL); o[n++] = 22; memcpy(o+n, P2WPKH, 22); n += 22;
    o[n++] = 1; o[n++] = 32; memset(o+n, 0, 32); n += 32;
    n += put_u32(o+n, 0);
    return n;
}
static size_t legacy_spend(unsigned char* o, const unsigned char prev[32]){
    size_t n = 0;
    n += put_u32(o+n, 1); o[n++] = 1;
    memcpy(o+n, prev, 32); n += 32; n += put_u32(o+n, 0);
    o[n++] = 1 + 71 + 1 + 33; o[n++] = 71; memcpy(o+n, SIG, 71); n += 71; o[n++] = 33; memcpy(o+n, PUB, 33); n += 33;
    n += put_u32(o+n, 0xffffffffu);
    o[n++] = 1; n += put_u64(o+n, 4999000000ULL); o[n++] = 22; memcpy(o+n, P2WPKH, 22); n += 22;
    n += put_u32(o+n, 0);
    return n;
}
/* P2WPKH spend, version 2, witness [sig, pubkey]. *stripped gets the
 * no-witness serialization (for the independent txid check). */
static size_t segwit_spend(unsigned char* o, const unsigned char prev[32], unsigned char* stripped, size_t* slen){
    size_t n = 0, s = 0;
    n += put_u32(o+n, 2); s += put_u32(stripped+s, 2);
    o[n++] = 0; o[n++] = 1;
    o[n++] = 1; stripped[s++] = 1;
    memcpy(o+n, prev, 32); n += 32; memcpy(stripped+s, prev, 32); s += 32;
    n += put_u32(o+n, 0); s += put_u32(stripped+s, 0);
    o[n++] = 0; stripped[s++] = 0;
    n += put_u32(o+n, 0xfffffffeu); s += put_u32(stripped+s, 0xfffffffeu);
    o[n++] = 1; stripped[s++] = 1;
    n += put_u64(o+n, 1000); s += put_u64(stripped+s, 1000);
    o[n++] = 34; memcpy(o+n, P2TR, 34); n += 34; stripped[s++] = 34; memcpy(stripped+s, P2TR, 34); s += 34;
    o[n++] = 2; o[n++] = 71; memcpy(o+n, SIG, 71); n += 71; o[n++] = 33; memcpy(o+n, PUB, 33); n += 33;
    n += put_u32(o+n, 0); s += put_u32(stripped+s, 0);
    *slen = s;
    return n;
}
static void make_header(unsigned char* h, const unsigned char prev[32], const unsigned char merkle[32], unsigned t){
    put_u32(h, 1); memcpy(h+4, prev, 32); memcpy(h+36, merkle, 32); put_u32(h+68, t); put_u32(h+72, 0x1d00ffffu); put_u32(h+76, 0);
}

static const char* GENESIS_HEX =
"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
"0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
static const char* GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
static const char* GENESIS_MERKLE = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

static unsigned char g_st[4096];
static char g_hash[4][65];         /* display-order block hashes */
static char g_cb_txid[4][65];      /* display-order coinbase txids */
static char g_tx1_txid[65], g_tx2_txid[65], g_tx2_wtxid[65];
static unsigned char g_tx1[512], g_tx2[512]; static size_t g_tx1_len, g_tx2_len, g_tx2_stripped;
static size_t g_blk3_len, g_blk3_stripped;

static void build_archive(void){
    memset(g_st, 0, sizeof g_st);
    if (store_init(g_st) != 1){ printf("FAIL store_init\n"); exit(1); }
    unsigned char blk[2048]; unsigned char hash[32], prev[32];
    /* genesis */
    int glen = hx(blk, GENESIS_HEX);
    block_hash(hash, blk);
    tohex_rev(g_hash[0], hash, 32);
    ck_str("genesis header hashes to the known mainnet hash", g_hash[0], GENESIS_HASH);
    if (store_append(g_st, hash, blk, glen) < 0){ printf("FAIL append 0\n"); exit(1); }
    memcpy(prev, hash, 32);
    { unsigned char id[32]; sha256d(id, blk + 81, (unsigned long)(glen - 81)); tohex_rev(g_cb_txid[0], id, 32); }
    /* blocks 1, 2: single legacy coinbase */
    for (unsigned h = 1; h <= 2; h++){
        unsigned char tx[256]; size_t tl = coinbase_legacy(tx, h);
        unsigned char id[32]; sha256d(id, tx, tl); tohex_rev(g_cb_txid[h], id, 32);
        make_header(blk, prev, id, 1231006505u + 600u*h);
        blk[80] = 1; memcpy(blk + 81, tx, tl);
        block_hash(hash, blk); tohex_rev(g_hash[h], hash, 32);
        if (store_append(g_st, hash, blk, (long)(81 + tl)) < 0){ printf("FAIL append %u\n", h); exit(1); }
        memcpy(prev, hash, 32);
    }
    /* block 3: segwit coinbase + legacy spend + segwit spend */
    {
        unsigned char cb[256]; size_t cbl = coinbase_segwit(cb);
        unsigned char cb_stripped[256]; size_t cbs = 0;
        /* stripped coinbase: drop marker/flag and the witness section */
        memcpy(cb_stripped, cb, 4); cbs = 4; memcpy(cb_stripped+cbs, cb+6, cbl - 6 - 4 - 34); cbs += cbl - 6 - 4 - 34; memcpy(cb_stripped+cbs, cb+cbl-4, 4); cbs += 4;
        unsigned char ids[3][32];
        sha256d(ids[0], cb_stripped, cbs); tohex_rev(g_cb_txid[3], ids[0], 32);
        unsigned char prev1[32]; { char tmp[65]; strcpy(tmp, g_cb_txid[1]); unsigned char d[32]; hx(d, tmp); for (int i = 0; i < 32; i++) prev1[i] = d[31-i]; }
        g_tx1_len = legacy_spend(g_tx1, prev1);
        sha256d(ids[1], g_tx1, g_tx1_len); tohex_rev(g_tx1_txid, ids[1], 32);
        unsigned char stripped[512]; size_t sl;
        g_tx2_len = segwit_spend(g_tx2, ids[1], stripped, &sl); g_tx2_stripped = sl;
        sha256d(ids[2], stripped, sl); tohex_rev(g_tx2_txid, ids[2], 32);
        { unsigned char w[32]; sha256d(w, g_tx2, g_tx2_len); tohex_rev(g_tx2_wtxid, w, 32); }
        unsigned char leaves[3][32]; memcpy(leaves, ids, sizeof leaves);
        unsigned char merkle[32]; merkle_root(merkle, leaves, 3);
        make_header(blk, prev, merkle, 1231006505u + 1800u);
        size_t n = 80; blk[n++] = 3;
        memcpy(blk+n, cb, cbl); n += cbl; memcpy(blk+n, g_tx1, g_tx1_len); n += g_tx1_len; memcpy(blk+n, g_tx2, g_tx2_len); n += g_tx2_len;
        g_blk3_len = n; g_blk3_stripped = 81 + cbs + g_tx1_len + sl;
        block_hash(hash, blk); tohex_rev(g_hash[3], hash, 32);
        if (store_append(g_st, hash, blk, (long)n) < 0){ printf("FAIL append 3\n"); exit(1); }
    }
}

static int g_stopped = 0;
static void on_stop(void){ g_stopped = 1; }

int main(void){
    /* deterministic sig/pubkey bytes satisfying strict DER + compressed-prefix checks */
    SIG[0]=0x30; SIG[1]=0x44; SIG[2]=0x02; SIG[3]=0x20; for (int i = 0; i < 32; i++) SIG[4+i] = (unsigned char)(0x11 + i);
    SIG[36]=0x02; SIG[37]=0x20; for (int i = 0; i < 32; i++) SIG[38+i] = (unsigned char)(0x51 + i); SIG[70]=0x01;
    PUB[0]=0x02; for (int i = 1; i < 33; i++) PUB[i] = (unsigned char)(0x80 + i);

    tt_isolate();
    memset(&g_w, 0, sizeof g_w);
    build_archive();
    rpc_chain_set_stop_handler(on_stop);

    /* ---- before open: chain methods report warmup, others untouched ---- */
    expect_err("getblockcount before open -> -28", "getblockcount", "[]", -28, "Loading block index...");
    ck("rpc_chain_open", rpc_chain_open(NULL) == 1);
    ck("rpc_known_method(getblock)", rpc_known_method("getblock") == 1);
    expect_err("unknown method still -32601", "getchaintips", "[]", -32601, "Method not found");

    long ec; const char* em; rj_val* r;

    /* ---- getblockcount / getbestblockhash / getblockhash ---- */
    r = call("getblockcount", "[]", &ec, &em); ck_str("getblockcount", r ? r->str : NULL, "3"); rj_free(r);
    r = call("getbestblockhash", "[]", &ec, &em); ck_str("getbestblockhash == hash[3]", r ? r->str : NULL, g_hash[3]); rj_free(r);
    r = call("getblockhash", "[0]", &ec, &em); ck_str("getblockhash 0 == genesis", r ? r->str : NULL, GENESIS_HASH); rj_free(r);
    r = call("getblockhash", "[3]", &ec, &em); ck_str("getblockhash(getblockcount) == getbestblockhash", r ? r->str : NULL, g_hash[3]); rj_free(r);
    expect_err("getblockhash 4 out of range", "getblockhash", "[4]", -8, "Block height out of range");
    expect_err("getblockhash -1 out of range", "getblockhash", "[-1]", -8, "Block height out of range");

    /* ---- getblockheader ---- */
    { char p[128]; snprintf(p, sizeof p, "[\"%s\"]", GENESIS_HASH);
      r = call("getblockheader", p, &ec, &em);
      ck("getblockheader genesis returns object", r && r->typ == RJ_OBJ);
      ck_str("hdr.hash", S(r,"hash"), GENESIS_HASH);
      ck_str("hdr.confirmations", S(r,"confirmations"), "4");
      ck_str("hdr.height", S(r,"height"), "0");
      ck_str("hdr.version", S(r,"version"), "1");
      ck_str("hdr.versionHex", S(r,"versionHex"), "00000001");
      ck_str("hdr.merkleroot", S(r,"merkleroot"), GENESIS_MERKLE);
      ck_str("hdr.time", S(r,"time"), "1231006505");
      ck_str("hdr.mediantime", S(r,"mediantime"), "1231006505");
      ck_str("hdr.nonce", S(r,"nonce"), "2083236893");
      ck_str("hdr.bits", S(r,"bits"), "1d00ffff");
      ck_str("hdr.target", S(r,"target"), "00000000ffff0000000000000000000000000000000000000000000000000000");
      ck_str("hdr.difficulty", S(r,"difficulty"), "1");
      ck_str("hdr.chainwork (computed fallback)", S(r,"chainwork"), "0000000000000000000000000000000000000000000000000000000100010001");
      ck_str("hdr.nTx", S(r,"nTx"), "1");
      ck("hdr: genesis has no previousblockhash", G(r,"previousblockhash") == NULL);
      ck_str("hdr.nextblockhash == hash[1]", S(r,"nextblockhash"), g_hash[1]);
      /* key order must be Core's */
      ck_str("hdr first key", r && r->nmembers ? r->members[0].key : NULL, "hash");
      ck_str("hdr key[1]", r && r->nmembers > 1 ? r->members[1].key : NULL, "confirmations");
      rj_free(r);
      snprintf(p, sizeof p, "[\"%s\", false]", GENESIS_HASH);
      r = call("getblockheader", p, &ec, &em);
      ck_str("getblockheader verbose=false == raw header hex", r ? r->str : NULL,
             "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c");
      rj_free(r);
      snprintf(p, sizeof p, "[\"%s\"]", g_hash[3]);
      r = call("getblockheader", p, &ec, &em);
      ck_str("tip hdr.confirmations", S(r,"confirmations"), "1");
      ck_str("tip hdr.previousblockhash == hash[2]", S(r,"previousblockhash"), g_hash[2]);
      ck("tip hdr has no nextblockhash", G(r,"nextblockhash") == NULL);
      ck_str("tip hdr.mediantime (median of 4 times = index 2)", S(r,"mediantime"), "1231007705");
      ck_str("tip hdr.chainwork", S(r,"chainwork"), "0000000000000000000000000000000000000000000000000000000400040004");
      ck_str("tip hdr.nTx", S(r,"nTx"), "3");
      rj_free(r);
    }
    expect_err("getblockheader unknown hash", "getblockheader", "[\"0000000000000000000000000000000000000000000000000000000000000001\"]", -5, "Block not found");
    expect_err("getblockheader bad length", "getblockheader", "[\"abc\"]", -8, "parameter 1 must be of length 64 (not 3, for 'abc')");
    expect_err("getblockheader non-hex", "getblockheader", "[\"zz00000000000000000000000000000000000000000000000000000000000000\"]", -8, "parameter 1 must be hexadecimal string (not 'zz00000000000000000000000000000000000000000000000000000000000000')");

    /* ---- getblock ---- */
    { char p[128]; snprintf(p, sizeof p, "[\"%s\", 0]", GENESIS_HASH);
      r = call("getblock", p, &ec, &em);
      ck_str("getblock genesis verbosity 0 == raw hex", r ? r->str : NULL, GENESIS_HEX); rj_free(r);
      snprintf(p, sizeof p, "[\"%s\"]", GENESIS_HASH);
      r = call("getblock", p, &ec, &em);
      ck_str("getblock v1 strippedsize", S(r,"strippedsize"), "285");
      ck_str("getblock v1 size", S(r,"size"), "285");
      ck_str("getblock v1 weight", S(r,"weight"), "1140");
      rj_val* cb = G(r,"coinbase_tx");
      ck_str("coinbase_tx.version", S(cb,"version"), "1");
      ck_str("coinbase_tx.locktime", S(cb,"locktime"), "0");
      ck_str("coinbase_tx.sequence", S(cb,"sequence"), "4294967295");
      ck_str("coinbase_tx.coinbase", S(cb,"coinbase"), "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73");
      ck("coinbase_tx has no witness (legacy)", G(cb,"witness") == NULL);
      rj_val* tx = G(r,"tx");
      ck("getblock v1 tx is array of 1", tx && tx->typ == RJ_ARR && tx->nitems == 1);
      ck_str("getblock v1 tx[0] == genesis coinbase txid", tx && tx->nitems ? tx->items[0]->str : NULL, GENESIS_MERKLE);
      rj_free(r);
      snprintf(p, sizeof p, "[\"%s\", 2]", GENESIS_HASH);
      r = call("getblock", p, &ec, &em);
      tx = G(r,"tx"); rj_val* t0 = tx && tx->nitems ? tx->items[0] : NULL;
      ck_str("v2 tx[0].txid", S(t0,"txid"), GENESIS_MERKLE);
      ck_str("v2 tx[0].hash == txid (legacy)", S(t0,"hash"), GENESIS_MERKLE);
      ck_str("v2 tx[0].size", S(t0,"size"), "204");
      ck_str("v2 tx[0].vsize", S(t0,"vsize"), "204");
      ck_str("v2 tx[0].weight", S(t0,"weight"), "816");
      rj_val* vin = G(t0,"vin"); rj_val* in0 = vin && vin->nitems ? vin->items[0] : NULL;
      ck("v2 coinbase vin has 'coinbase' not 'txid'", in0 && G(in0,"coinbase") && !G(in0,"txid"));
      ck_str("v2 coinbase vin.sequence", S(in0,"sequence"), "4294967295");
      rj_val* vout = G(t0,"vout"); rj_val* o0 = vout && vout->nitems ? vout->items[0] : NULL;
      ck_str("v2 vout[0].value", S(o0,"value"), "50.00000000");
      ck_str("v2 vout[0].n", S(o0,"n"), "0");
      rj_val* spk = G(o0,"scriptPubKey");
      ck_str("v2 spk.asm (pubkey OP_CHECKSIG)", S(spk,"asm"), "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f OP_CHECKSIG");
      ck_str("v2 spk.type", S(spk,"type"), "pubkey");
      ck("v2 spk: pubkey type carries no address (Core)", G(spk,"address") == NULL);
      ck("v2 tx[0].hex present", S(t0,"hex") != NULL && strlen(S(t0,"hex")) == 408);
      rj_free(r);
    }
    /* block 3: segwit shapes */
    { char p[128]; snprintf(p, sizeof p, "[\"%s\", 1]", g_hash[3]);
      r = call("getblock", p, &ec, &em);
      char want[32];
      snprintf(want, sizeof want, "%zu", g_blk3_len); ck_str("blk3 size", S(r,"size"), want);
      snprintf(want, sizeof want, "%zu", g_blk3_stripped); ck_str("blk3 strippedsize", S(r,"strippedsize"), want);
      snprintf(want, sizeof want, "%zu", g_blk3_stripped*3 + g_blk3_len); ck_str("blk3 weight", S(r,"weight"), want);
      rj_val* cb = G(r,"coinbase_tx");
      ck_str("blk3 coinbase_tx.witness (reserved value)", S(cb,"witness"), "0000000000000000000000000000000000000000000000000000000000000000");
      rj_val* tx = G(r,"tx");
      ck("blk3 v1 has 3 txids", tx && tx->nitems == 3);
      ck_str("blk3 v1 tx[0] == segwit coinbase txid (independent sha256d of stripped)", tx && tx->nitems ? tx->items[0]->str : NULL, g_cb_txid[3]);
      ck_str("blk3 v1 tx[1] == legacy spend txid", tx && tx->nitems > 1 ? tx->items[1]->str : NULL, g_tx1_txid);
      ck_str("blk3 v1 tx[2] == segwit spend txid", tx && tx->nitems > 2 ? tx->items[2]->str : NULL, g_tx2_txid);
      rj_free(r);
      snprintf(p, sizeof p, "[\"%s\", 2]", g_hash[3]);
      r = call("getblock", p, &ec, &em);
      tx = G(r,"tx");
      rj_val* t1 = tx && tx->nitems > 1 ? tx->items[1] : NULL;
      rj_val* t2 = tx && tx->nitems > 2 ? tx->items[2] : NULL;
      ck_str("v2 tx[1].txid == v1 txid", S(t1,"txid"), g_tx1_txid);
      ck_str("v2 tx[2].txid == v1 txid", S(t2,"txid"), g_tx2_txid);
      ck_str("v2 tx[2].hash == wtxid (!= txid)", S(t2,"hash"), g_tx2_wtxid);
      ck("v2 tx[2].hash differs from txid", S(t2,"hash") && S(t2,"txid") && strcmp(S(t2,"hash"), S(t2,"txid")) != 0);
      snprintf(want, sizeof want, "%zu", g_tx2_len); ck_str("v2 tx[2].size", S(t2,"size"), want);
      snprintf(want, sizeof want, "%zu", g_tx2_stripped*3 + g_tx2_len); ck_str("v2 tx[2].weight", S(t2,"weight"), want);
      snprintf(want, sizeof want, "%zu", (g_tx2_stripped*3 + g_tx2_len + 3)/4); ck_str("v2 tx[2].vsize", S(t2,"vsize"), want);
      ck_str("v2 tx[2].version", S(t2,"version"), "2");
      rj_val* vin2 = G(t2,"vin"); rj_val* i2 = vin2 && vin2->nitems ? vin2->items[0] : NULL;
      ck_str("v2 tx[2].vin[0].txid == tx1 txid", S(i2,"txid"), g_tx1_txid);
      ck_str("v2 tx[2].vin[0].sequence", S(i2,"sequence"), "4294967294");
      rj_val* wit = G(i2,"txinwitness");
      ck("v2 tx[2] txinwitness has 2 items", wit && wit->typ == RJ_ARR && wit->nitems == 2);
      { char sighex[143]; tohex(sighex, SIG, 71); ck_str("txinwitness[0] == sig hex", wit && wit->nitems ? wit->items[0]->str : NULL, sighex); }
      ck_str("v2 tx[2].vout[0].value (1000 sat)", S(G(t2,"vout") && G(t2,"vout")->nitems ? G(t2,"vout")->items[0] : NULL, "value"), "0.00001000");
      ck_str("v2 tx[2] spk.type taproot", S(G(G(t2,"vout")->items[0],"scriptPubKey"),"type"), "witness_v1_taproot");
      /* legacy spend: scriptSig asm with Core's sighash decode */
      rj_val* vin1 = G(t1,"vin"); rj_val* i1 = vin1 && vin1->nitems ? vin1->items[0] : NULL;
      { char want_asm[400]; char sighex[143], pubhex[67]; tohex(sighex, SIG, 70); tohex(pubhex, PUB, 33);
        snprintf(want_asm, sizeof want_asm, "%s[ALL] %s", sighex, pubhex);
        ck_str("v2 tx[1].vin[0].scriptSig.asm decodes [ALL]", S(G(i1,"scriptSig"),"asm"), want_asm); }
      ck("v2 tx[1] has no txinwitness", G(i1,"txinwitness") == NULL);
      ck_str("v2 tx[1].vout[0].scriptPubKey.type", S(G(G(t1,"vout")->items[0],"scriptPubKey"),"type"), "witness_v0_keyhash");
      ck("v2 tx[1].vout[0] has address", S(G(G(t1,"vout")->items[0],"scriptPubKey"),"address") != NULL);
      /* consistency with decoderawtransaction on the same raw hex */
      { const char* hexs = S(t1,"hex"); char p2[1200]; snprintf(p2, sizeof p2, "[\"%s\"]", hexs ? hexs : "");
        rj_val* d = call("decoderawtransaction", p2, &ec, &em);
        ck_str("decoderawtransaction(tx[1].hex).vin[0].txid matches", S(G(d,"vin") && G(d,"vin")->nitems ? G(d,"vin")->items[0] : NULL, "txid"), S(i1,"txid"));
        ck_str("decoderawtransaction(tx[1].hex).vout[0].value matches", S(G(d,"vout") && G(d,"vout")->nitems ? G(d,"vout")->items[0] : NULL, "value"), S(G(t1,"vout")->items[0],"value"));
        rj_free(d); }
      rj_free(r);
    }
    expect_err("getblock unknown hash", "getblock", "[\"0000000000000000000000000000000000000000000000000000000000000001\"]", -5, "Block not found");

    /* ---- getblockchaininfo ---- */
    r = call("getblockchaininfo", "[]", &ec, &em);
    ck_str("chaininfo.chain", S(r,"chain"), "main");
    ck_str("chaininfo.blocks", S(r,"blocks"), "3");
    ck_str("chaininfo.headers", S(r,"headers"), "3");
    ck_str("chaininfo.bestblockhash", S(r,"bestblockhash"), g_hash[3]);
    ck_str("chaininfo.bits", S(r,"bits"), "1d00ffff");
    ck_str("chaininfo.difficulty", S(r,"difficulty"), "1");
    ck_str("chaininfo.verificationprogress", S(r,"verificationprogress"), "1");
    ck_str("chaininfo.initialblockdownload (2009 tip)", S(r,"initialblockdownload"), "1");
    ck_str("chaininfo.chainwork", S(r,"chainwork"), "0000000000000000000000000000000000000000000000000000000400040004");
    ck_str("chaininfo.pruned", S(r,"pruned"), "0");
    ck("chaininfo.size_on_disk > 0", S(r,"size_on_disk") && atol(S(r,"size_on_disk")) > 0);
    ck("chaininfo.warnings is empty array", G(r,"warnings") && G(r,"warnings")->typ == RJ_ARR && G(r,"warnings")->nitems == 0);
    ck_str("chaininfo first key", r && r->nmembers ? r->members[0].key : NULL, "chain");
    rj_free(r);

    /* ---- getrawtransaction ---- */
    { char p[256];
      snprintf(p, sizeof p, "[\"%s\", 0, \"%s\"]", g_tx1_txid, g_hash[3]);
      r = call("getrawtransaction", p, &ec, &em);
      { char want[1100]; tohex(want, g_tx1, g_tx1_len); ck_str("getrawtransaction v0 with blockhash == raw hex", r ? r->str : NULL, want); }
      rj_free(r);
      snprintf(p, sizeof p, "[\"%s\", true, \"%s\"]", g_tx2_txid, g_hash[3]);
      r = call("getrawtransaction", p, &ec, &em);
      ck("getrawtransaction verbose (bool) returns object", r && r->typ == RJ_OBJ);
      ck_str("grt.in_active_chain", S(r,"in_active_chain"), "1");
      ck_str("grt first key is in_active_chain", r && r->nmembers ? r->members[0].key : NULL, "in_active_chain");
      ck_str("grt.txid", S(r,"txid"), g_tx2_txid);
      ck_str("grt.blockhash", S(r,"blockhash"), g_hash[3]);
      ck_str("grt.confirmations", S(r,"confirmations"), "1");
      ck_str("grt.time", S(r,"time"), "1231008305");
      ck_str("grt.blocktime", S(r,"blocktime"), "1231008305");
      ck("grt: blockhash comes after hex (Core TxToJSON order)", r && r->nmembers > 5 && !strcmp(r->members[r->nmembers-5].key, "hex") && !strcmp(r->members[r->nmembers-4].key, "blockhash") && !strcmp(r->members[r->nmembers-1].key, "blocktime"));
      rj_free(r);
      snprintf(p, sizeof p, "[\"%s\", 1, \"%s\"]", g_tx1_txid, g_hash[1]);
      expect_err("getrawtransaction wrong block", "getrawtransaction", p, -5, "No such transaction found in the provided block. Use gettransaction for wallet transactions.");
      snprintf(p, sizeof p, "[\"%s\"]", g_tx1_txid);
      expect_err("getrawtransaction without blockhash (no txindex/mempool)", "getrawtransaction", p, -5, "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries. Use gettransaction for wallet transactions.");
      snprintf(p, sizeof p, "[\"%s\", 1, \"%s\"]", g_tx1_txid, "0000000000000000000000000000000000000000000000000000000000000001");
      expect_err("getrawtransaction unknown blockhash", "getrawtransaction", p, -5, "Block hash not found");
      snprintf(p, sizeof p, "[\"%s\", 1, \"%s\"]", GENESIS_MERKLE, GENESIS_HASH);
      expect_err("getrawtransaction genesis coinbase", "getrawtransaction", p, -5, "The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved");
      expect_err("getrawtransaction bad txid length", "getrawtransaction", "[\"ab\"]", -8, "parameter 1 must be of length 64 (not 2, for 'ab')");
    }

    /* ---- decodescript (pure; no archive needed) ---- */
    {
        char p[512];
        char H20[41], H32[65]; memset(H20,'1',40); H20[40]=0; memset(H32,'1',64); H32[64]=0;
        char PKC[67], PKU[131];                                  /* 33B / 65B, exact lengths */
        PKC[0]='0'; PKC[1]='2'; memset(PKC+2,'a',64); PKC[66]=0; /* 02 || 32 bytes */
        PKU[0]='0'; PKU[1]='4'; memset(PKU+2,'b',128); PKU[130]=0; /* 04 || 64 bytes */
        /* P2PKH spk: pubkeyhash, wraps to p2sh and p2wpkh-in-p2sh */
        snprintf(p, sizeof p, "[\"76a914%s88ac\"]", H20);
        rj_val* r = call("decodescript", p, &ec, &em);
        ck_str("ds P2PKH type", S(r,"type"), "pubkeyhash");
        ck_str("ds P2PKH desc (addr + checksum)", S(r,"desc"), "addr(12ZEw5Hcv1hTb6YUQJ69y1V7uhcoDz92PH)#krj9j7v6");
        ck("ds P2PKH has p2sh", S(r,"p2sh") != NULL);
        ck("ds P2PKH has segwit", G(r,"segwit") != NULL);
        ck_str("ds P2PKH segwit type", S(G(r,"segwit"),"type"), "witness_v0_keyhash");
        ck("ds P2PKH segwit p2sh-segwit", S(G(r,"segwit"),"p2sh-segwit") != NULL);
        rj_free(r);
        /* P2SH spk: scripthash cannot be re-wrapped */
        snprintf(p, sizeof p, "[\"a914%s87\"]", H20);
        r = call("decodescript", p, &ec, &em);
        ck_str("ds P2SH type", S(r,"type"), "scripthash");
        ck("ds P2SH no p2sh", S(r,"p2sh") == NULL);
        ck("ds P2SH no segwit", G(r,"segwit") == NULL);
        rj_free(r);
        /* 1-of-2 multisig, all compressed: wraps to p2sh + p2wsh */
        snprintf(p, sizeof p, "[\"5121%s21%s52ae\"]", PKC, PKC);
        r = call("decodescript", p, &ec, &em);
        ck_str("ds multisig(C) type", S(r,"type"), "multisig");
        ck("ds multisig(C) has p2sh", S(r,"p2sh") != NULL);
        ck("ds multisig(C) has segwit", G(r,"segwit") != NULL);
        ck_str("ds multisig(C) segwit type", S(G(r,"segwit"),"type"), "witness_v0_scripthash");
        rj_free(r);
        /* 1-of-2 multisig with an uncompressed key: p2sh yes, segwit NO */
        snprintf(p, sizeof p, "[\"5121%s41%s52ae\"]", PKC, PKU);
        r = call("decodescript", p, &ec, &em);
        ck_str("ds multisig(U) type", S(r,"type"), "multisig");
        ck("ds multisig(U) has p2sh", S(r,"p2sh") != NULL);
        ck("ds multisig(U) NO segwit (uncompressed key)", G(r,"segwit") == NULL);
        rj_free(r);
        /* <32-byte push> OP_CHECKSIGADD -> not wrappable at all */
        snprintf(p, sizeof p, "[\"20%sba\"]", H32);
        r = call("decodescript", p, &ec, &em);
        ck_str("ds OP_CHECKSIGADD type", S(r,"type"), "nonstandard");
        ck("ds OP_CHECKSIGADD no p2sh", S(r,"p2sh") == NULL);
        rj_free(r);
        /* empty script */
        r = call("decodescript", "[\"\"]", &ec, &em);
        ck_str("ds empty type", S(r,"type"), "nonstandard");
        ck_str("ds empty asm", S(r,"asm"), "");
        rj_free(r);
    }

    /* ---- validateaddress (pure; exercises the rpc_commands.c JSON builder) ---- */
    {
        rj_val* r = call("validateaddress", "[\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"]", &ec, &em);
        ck("va P2WPKH valid", S(r,"isvalid") && !strcmp(S(r,"isvalid"),"1"));
        ck_str("va P2WPKH scriptPubKey", S(r,"scriptPubKey"), "0014751e76e8199196d454941c45d1b3a323f1433bd6");
        ck_str("va P2WPKH isscript", S(r,"isscript"), "0");
        ck_str("va P2WPKH iswitness", S(r,"iswitness"), "1");
        ck_str("va P2WPKH witness_version", S(r,"witness_version"), "0");
        ck_str("va P2WPKH witness_program", S(r,"witness_program"), "751e76e8199196d454941c45d1b3a323f1433bd6");
        ck("va has NO ischange (Core validateaddress omits it)", G(r,"ischange") == NULL);
        rj_free(r);
        /* P2WSH: witness_program must be the 32-byte program, not a truncated h160 (regression) */
        r = call("validateaddress", "[\"bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3\"]", &ec, &em);
        ck_str("va P2WSH isscript", S(r,"isscript"), "1");
        ck_str("va P2WSH witness_program", S(r,"witness_program"), "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262");
        rj_free(r);
        /* P2TR: isscript true, witness_version 1 */
        r = call("validateaddress", "[\"bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr\"]", &ec, &em);
        ck_str("va P2TR isscript", S(r,"isscript"), "1");
        ck_str("va P2TR witness_version", S(r,"witness_version"), "1");
        rj_free(r);
        /* P2SH: script, not witness */
        r = call("validateaddress", "[\"3P14159f73E4gFr7JterCCQh9QjiTjiZrG\"]", &ec, &em);
        ck_str("va P2SH isscript", S(r,"isscript"), "1");
        ck_str("va P2SH iswitness", S(r,"iswitness"), "0");
        rj_free(r);
        /* uppercase bech32 is normalised to lowercase (canonical) */
        r = call("validateaddress", "[\"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4\"]", &ec, &em);
        ck_str("va normalises to lowercase", S(r,"address"), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        rj_free(r);
        /* invalid -> isvalid:false, no address */
        r = call("validateaddress", "[\"notanaddress\"]", &ec, &em);
        ck_str("va invalid isvalid", S(r,"isvalid"), "0");
        ck("va invalid has no address", G(r,"address") == NULL);
        rj_free(r);
    }

    /* ---- createmultisig (pure; known answers from Bitcoin Core) ---- */
    {
        /* Core's own help-example keys */
        const char* K1 = "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd";
        const char* K2 = "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626";
        const char* REDEEM =
            "522103789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd"
            "2103dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a6162652ae";
        char p[400];
        /* legacy 2-of-2 -> P2SH */
        snprintf(p, sizeof p, "[2, [\"%s\",\"%s\"]]", K1, K2);
        rj_val* r = call("createmultisig", p, &ec, &em);
        ck_str("cms legacy address", S(r,"address"), "3QsFXpFJf2ZY6GLWVoNFFd2xSDwdS713qX");
        ck_str("cms legacy redeemScript", S(r,"redeemScript"), REDEEM);
        ck_str("cms legacy descriptor", S(r,"descriptor"),
               "sh(multi(2,03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd,"
               "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626))#4djp057k");
        rj_free(r);
        /* bech32 2-of-2 -> P2WSH */
        snprintf(p, sizeof p, "[2, [\"%s\",\"%s\"], \"bech32\"]", K1, K2);
        r = call("createmultisig", p, &ec, &em);
        ck_str("cms bech32 address", S(r,"address"), "bc1q0jnggjwnn22a4ywxc2pcw86c0d6tghqkgk3hlryrxl7nmxkylmnq6smlx3");
        rj_free(r);
        /* p2sh-segwit 1-of-2 -> P2SH-P2WSH */
        snprintf(p, sizeof p, "[1, [\"%s\",\"%s\"], \"p2sh-segwit\"]", K1, K2);
        r = call("createmultisig", p, &ec, &em);
        ck_str("cms p2sh-segwit address", S(r,"address"), "3EAkC7eViWC6z2KGXNLVHy6AXio96jkQJv");
        rj_free(r);
        /* error paths (Core's codes) */
        snprintf(p, sizeof p, "[0, [\"%s\"]]", K1);
        expect_err("cms required<1", "createmultisig", p, -8, "a multisignature address must require at least one key to redeem");
        snprintf(p, sizeof p, "[3, [\"%s\",\"%s\"]]", K1, K2);
        expect_err("cms not enough keys", "createmultisig", p, -8, "not enough keys supplied (got 2 keys, but need at least 3 to redeem)");
        snprintf(p, sizeof p, "[1, [\"%s\"], \"bech32m\"]", K1);
        expect_err("cms bech32m rejected", "createmultisig", p, -5, "createmultisig cannot create bech32m multisig addresses");
        expect_err("cms invalid key", "createmultisig", "[1, [\"deadbeef\"]]", -5, "Invalid public key: deadbeef");
    }

    /* ---- uptime / stop ---- */
    r = call("uptime", "[]", &ec, &em); ck("uptime is a non-negative number", r && r->typ == RJ_NUM && atol(r->str) >= 0); rj_free(r);
    r = call("stop", "[]", &ec, &em); ck_str("stop reply", r ? r->str : NULL, "Bitcoin Machine Code stopping"); rj_free(r);
    ck("stop invoked the handler", g_stopped == 1);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
