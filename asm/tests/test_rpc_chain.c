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
#include "../rpc_node.h"      /* rpc_mempool_hooks (the CPFP-selection section) */
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
extern long store_read_at(void* st, unsigned long h, void* out, long cap);
extern int  tx_txid(void* out, const void* tx, unsigned long txlen, void* buf, unsigned long buflen);

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

/* bitcoin_mempool_policy.c resolves confirmed prevouts through this hook;
 * the CPFP section's single-table bitcoin_utxo.asm fixture passes through
 * (same stub shape as tests/test_mempool_policy.c). */
extern long utxo_get(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, unsigned long* height,
                     unsigned long* is_coinbase, const unsigned char** script,
                     unsigned long* slen);
long mempool_resolve_confirmed_utxo(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, const unsigned char** script,
                     unsigned long* slen){
    unsigned long h_unused, cb_unused;
    return utxo_get(u, txid, index, value, &h_unused, &cb_unused, script, slen);
}
/* display-order hex of a wire hash (local copy; rpc_chain.c's is static) */
static void trc_hex_rev(char* out, const unsigned char* b, size_t n){
    for (size_t i = 0; i < n; i++){
        static const char* hd = "0123456789abcdef";
        out[2*i]   = hd[b[n-1-i] >> 4];
        out[2*i+1] = hd[b[n-1-i] & 15];
    }
    out[2*n] = 0;
}

/* ---- build a txid index over the fixture archive ------------------------
 * Written here rather than by invoking daemon/build_tx_index so the test
 * stays hermetic, but in the SAME format the builder emits -- if the two
 * ever disagree the reader will reject this file and the assertions below
 * fail, which is the point.
 *
 * Heights up to base_to land in the sorted base txindex.dat; heights above
 * it are APPENDED UNSORTED to txindex.tail, the daemon-maintained tail
 * format (daemon/tx_index_tail.c). Splitting the fixture this way makes
 * every later by-txid assertion exercise BOTH lookup paths: the coinbase
 * txids resolve through the base, the height-3 spends through the tail,
 * and the byte-identity check proves the two render identically. */
static void build_fixture_txindex(long base_to, long tip){
    typedef struct { unsigned char pre[8]; unsigned int h, off, len; } rec_t;
    static rec_t recs[64]; int n = 0;
    for (long h = 0; h <= tip; h++){
        static unsigned char blk[4096];
        long blen = store_read_at(g_st, (unsigned long)h, blk, sizeof blk);
        if (blen < 81) continue;
        const unsigned char* p = blk + 80;
        unsigned long ntx = *p++;                 /* fixture blocks: < 0xfd txs */
        for (unsigned long t = 0; t < ntx && n < 64; t++){
            const unsigned char* s0 = p;
            p += 4;
            int sw = (p[0] == 0x00 && p[1] == 0x01);
            if (sw) p += 2;
            unsigned long nin = *p++;
            for (unsigned long i = 0; i < nin; i++){
                p += 36; unsigned long sl = *p++; p += sl + 4;
            }
            unsigned long nout = *p++;
            for (unsigned long i = 0; i < nout; i++){
                p += 8; unsigned long sl = *p++; p += sl;
            }
            if (sw){
                for (unsigned long i = 0; i < nin; i++){
                    unsigned long items = *p++;
                    for (unsigned long k = 0; k < items; k++){ unsigned long il = *p++; p += il; }
                }
            }
            p += 4;
            unsigned int len = (unsigned int)(p - s0);
            unsigned char txid[32]; static unsigned char scr[4096];
            if (tx_txid(txid, s0, len, scr, sizeof scr) != 1) continue;
            memcpy(recs[n].pre, txid, 8);
            recs[n].h = (unsigned int)h;
            recs[n].off = (unsigned int)(s0 - blk);
            recs[n].len = len;
            n++;
        }
    }
    { /* heights above base_to: unsorted 20-byte records in the tail file */
        FILE* tf = fopen("txindex.tail", "wb");
        int kept = 0;
        for (int i = 0; i < n; i++){
            if (recs[i].h <= (unsigned int)base_to){ recs[kept++] = recs[i]; continue; }
            unsigned char r[20];
            memcpy(r, recs[i].pre, 8);
            for (int b = 0; b < 4; b++) r[8+b]  = (unsigned char)(recs[i].h   >> (8*b));
            for (int b = 0; b < 4; b++) r[12+b] = (unsigned char)(recs[i].off >> (8*b));
            for (int b = 0; b < 4; b++) r[16+b] = (unsigned char)(recs[i].len >> (8*b));
            fwrite(r, 1, 20, tf);
        }
        fclose(tf);
        n = kept;
    }
    for (int i = 1; i < n; i++){                  /* sort by prefix */
        rec_t k = recs[i]; int j = i - 1;
        while (j >= 0 && memcmp(recs[j].pre, k.pre, 8) > 0){ recs[j+1] = recs[j]; j--; }
        recs[j+1] = k;
    }
    FILE* f = fopen("txindex.dat", "wb");
    unsigned char hdr[48]; memset(hdr, 0, sizeof hdr);
    fwrite(hdr, 1, 48, f);
    for (int i = 0; i < n; i++){
        unsigned char r[20];
        memcpy(r, recs[i].pre, 8);
        for (int b = 0; b < 4; b++) r[8+b]  = (unsigned char)(recs[i].h   >> (8*b));
        for (int b = 0; b < 4; b++) r[12+b] = (unsigned char)(recs[i].off >> (8*b));
        for (int b = 0; b < 4; b++) r[16+b] = (unsigned char)(recs[i].len >> (8*b));
        fwrite(r, 1, 20, f);
    }
    unsigned long long sparse_off = 48 + (unsigned long long)n * 20;
    unsigned char sp[16];                          /* one sample: record 0 */
    memcpy(sp, recs[0].pre, 8);
    for (int b = 0; b < 8; b++) sp[8+b] = (unsigned char)(48ULL >> (8*b));
    fwrite(sp, 1, 16, f);
    memcpy(hdr, "BMCTXIDX", 8);
    for (int b = 0; b < 8; b++) hdr[8+b]  = (unsigned char)((unsigned long long)n >> (8*b));
    for (int b = 0; b < 8; b++) hdr[16+b] = (unsigned char)(sparse_off >> (8*b));
    for (int b = 0; b < 8; b++) hdr[24+b] = (unsigned char)(1ULL >> (8*b));
    for (int b = 0; b < 4; b++) hdr[32+b] = 0;
    for (int b = 0; b < 4; b++) hdr[36+b] = (unsigned char)((unsigned int)base_to >> (8*b));
    fseek(f, 0, SEEK_SET); fwrite(hdr, 1, 48, f);
    fclose(f);
    printf("      (fixture txindex: %d base records + tail)\n", n);
}

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

/* gettxoutsetinfo stub reader: fixed numbers; height 3 = the fixture tip so
 * bestblock can be cross-checked against getbestblockhash. */
static int g_usi_stub_busy = 0;
static long usi_stub_run(int want_muhash, void* outv, char* msg, unsigned long mcap){
    struct { long height; unsigned long long txouts, bogosize, total_amount;
             unsigned char muhash[32]; int muhash_valid; } *o = outv;
    if (g_usi_stub_busy){ if (msg&&mcap) snprintf(msg,mcap,"UTXO set is being written (stub)"); return 0; }
    o->height = 3; o->txouts = 12345; o->bogosize = 999;
    o->total_amount = 12345678900ULL;
    for (int i=0;i<32;i++) o->muhash[i] = (unsigned char)i;
    o->muhash_valid = want_muhash;
    return 1;
}

/* scantxoutset stub scanner: reports one hit for the FIRST target spk at
 * height 2, scan height 3 (the fixture tip, so bestblock/blockhash resolve). */
static long scan_stub_run(const unsigned char* spks, const unsigned int* spklens, int nspk,
                          void* hitsv, long hits_cap, long* hits_n,
                          long* out_height, unsigned long long* out_scanned,
                          unsigned long long* out_total, int* out_overflow,
                          char* msg, unsigned long mcap){
    (void)hits_cap; (void)msg; (void)mcap;
    struct { unsigned char txid[32]; unsigned int vout;
             unsigned long long value; unsigned long long height; int coinbase;
             unsigned char spk[128]; unsigned int spklen; } *hits = hitsv;
    if (nspk < 1) return -1;
    memset(hits[0].txid, 0x77, 32);
    hits[0].vout = 7;
    hits[0].value = 123456;
    hits[0].height = 2;
    hits[0].coinbase = 0;
    hits[0].spklen = spklens[0];
    memcpy(hits[0].spk, spks, spklens[0]);
    *hits_n = 1; *out_height = 3; *out_scanned = 150;
    *out_total = 123456; *out_overflow = 0;
    return 1;
}

int main(void){
    /* deterministic sig/pubkey bytes satisfying strict DER + compressed-prefix checks */
    SIG[0]=0x30; SIG[1]=0x44; SIG[2]=0x02; SIG[3]=0x20; for (int i = 0; i < 32; i++) SIG[4+i] = (unsigned char)(0x11 + i);
    SIG[36]=0x02; SIG[37]=0x20; for (int i = 0; i < 32; i++) SIG[38+i] = (unsigned char)(0x51 + i); SIG[70]=0x01;
    PUB[0]=0x02; for (int i = 1; i < 33; i++) PUB[i] = (unsigned char)(0x80 + i);

    tt_isolate();
    memset(&g_w, 0, sizeof g_w);
    build_archive();
    rpc_chain_set_stop_handler(on_stop);

    /* ---- before open: chain methods report warmup, but PURE util methods
     * (decodescript/createmultisig/getdescriptorinfo) work without the chain
     * open, matching Core -- they need no chain state. ---- */
    expect_err("getblockcount before open -> -28", "getblockcount", "[]", -28, "Loading block index...");
    { long bec; const char* bem;
      rj_val* rr = call("decodescript", "[\"76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac\"]", &bec, &bem);
      ck("decodescript works before chain open (not -28)", rr && rr->typ==RJ_OBJ && S(rr,"type")); rj_free(rr);
      rr = call("getdescriptorinfo", "[\"addr(1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9)\"]", &bec, &bem);
      ck("getdescriptorinfo works before chain open", rr && rr->typ==RJ_OBJ && S(rr,"checksum")); rj_free(rr);
      /* getindexinfo: no optional indexes on this node -> {} (Core-exact for a
       * node with no txindex/coinstatsindex/blockfilterindex), served pre-open. */
      rr = call("getindexinfo", "[]", &bec, &bem);
      ck("getindexinfo -> empty object (no indexes)", rr && rr->typ==RJ_OBJ && rr->nitems==0); rj_free(rr);
      rr = call("getindexinfo", "[\"txindex\"]", &bec, &bem);
      ck("getindexinfo(filter) -> empty object", rr && rr->typ==RJ_OBJ && rr->nitems==0); rj_free(rr);
      /* Core does not type-check the arg -- a non-string still yields {} (live-verified). */
      rr = call("getindexinfo", "[123]", &bec, &bem);
      ck("getindexinfo(non-string) -> empty object (Core-lenient)", rr && rr->typ==RJ_OBJ && rr->nitems==0); rj_free(rr); }
    ck("rpc_chain_open", rpc_chain_open(NULL) == 1);
    ck("rpc_known_method(getblock)", rpc_known_method("getblock") == 1);
    expect_err("unknown method still -32601", "nosuchrpcmethod", "[]", -32601, "Method not found");

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
      /* Write undo_3.dat so getblock v2 can compute fees from spent prevout
       * values (block 3 is height 3). Two spends, in block order:
       *   tx[1] legacy_spend: 1 input worth 50.0 BTC  -> fee 0.01 (out 49.99)
       *   tx[2] segwit_spend: 1 input worth 49.99 BTC -> fee 49.98999 (out 1000 sat)
       * Record: txid[32] idx(u32) value(u64@36) height(u32) is_coinbase(u8@48) slen(u16@49) */
      { unsigned char rec[102]; memset(rec, 0, sizeof rec);
        put_u64(rec+36, 5000000000ULL);      /* record 0 value */
        put_u64(rec+51+36, 4999000000ULL);   /* record 1 value */
        FILE* uf = fopen("undo_3.dat", "wb");
        ck("undo_3.dat opened", uf != NULL);
        if (uf){ fwrite(rec, 1, 102, uf); fclose(uf); }
      }
      snprintf(p, sizeof p, "[\"%s\", 2]", g_hash[3]);
      r = call("getblock", p, &ec, &em);
      tx = G(r,"tx");
      rj_val* t1 = tx && tx->nitems > 1 ? tx->items[1] : NULL;
      rj_val* t2 = tx && tx->nitems > 2 ? tx->items[2] : NULL;
      ck("v2 coinbase tx[0] has no fee (Core parity)", tx && tx->nitems ? G(tx->items[0],"fee") == NULL : 0);
      ck_str("v2 tx[1].fee (0.01 from undo)", S(t1,"fee"), "0.01000000");
      ck_str("v2 tx[2].fee (49.98999 from undo)", S(t2,"fee"), "49.98999000");
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

    /* ---- getdescriptorinfo / deriveaddresses (descriptor engine) ----
     * Ground truth captured from bitcoin-cli getdescriptorinfo/deriveaddresses
     * on the BIP32 test-vector-1 master xpub (seed 000102..0f). */
    {
      const char* XP = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
      char p[400];
      /* getdescriptorinfo: canonical descriptor, checksum, flags */
      snprintf(p, sizeof p, "[\"wpkh(%s/0/*)\"]", XP);
      r = call("getdescriptorinfo", p, &ec, &em);
      ck_str("gdi checksum", S(r,"checksum"), "wvk84d79");
      { char want[420]; snprintf(want, sizeof want, "wpkh(%s/0/*)#wvk84d79", XP);
        ck_str("gdi canonical descriptor", S(r,"descriptor"), want); }
      ck_str("gdi isrange", S(r,"isrange"), "1");
      ck_str("gdi issolvable", S(r,"issolvable"), "1");
      ck_str("gdi hasprivatekeys", S(r,"hasprivatekeys"), "0");
      rj_free(r);
      /* bad checksum rejected with Core's exact message */
      snprintf(p, sizeof p, "[\"wpkh(%s/0/*)#00000000\"]", XP);
      expect_err("gdi bad checksum", "getdescriptorinfo", p, -5,
                 "Provided checksum '00000000' does not match computed checksum 'wvk84d79'");
      /* invalid key rejected */
      expect_err("gdi invalid key", "getdescriptorinfo", "[\"wpkh(notakey)\"]", -5, "key 'notakey' is not valid");

      /* deriveaddresses: wpkh ranged [0,2] -> Core's addresses */
      snprintf(p, sizeof p, "[\"wpkh(%s/0/*)#wvk84d79\", [0,2]]", XP);
      r = call("deriveaddresses", p, &ec, &em);
      ck("da wpkh returns 3 addrs", r && r->typ == RJ_ARR && r->nitems == 3);
      ck_str("da wpkh [0]", r&&r->nitems>0?r->items[0]->str:NULL, "bc1qp5wfcq48h6d63wyy9qz0awtpfqwwv4sma86mhz");
      ck_str("da wpkh [1]", r&&r->nitems>1?r->items[1]->str:NULL, "bc1qrfxr69jqnhwufxgkqgcdep9prq4j4vuw2wyg0v");
      ck_str("da wpkh [2]", r&&r->nitems>2?r->items[2]->str:NULL, "bc1qhvd6suvqzjcu9pxjhrwhtrlj85ny3n2mqql5w4");
      rj_free(r);
      /* pkh ranged, single-int range 3 -> indices 0..3 (4 addresses) */
      snprintf(p, sizeof p, "[\"pkh(%s/0/*)#xgqkr0nt\", 3]", XP);
      r = call("deriveaddresses", p, &ec, &em);
      ck("da pkh single-int range -> 4 addrs", r && r->typ == RJ_ARR && r->nitems == 4);
      ck_str("da pkh [0]", r&&r->nitems>0?r->items[0]->str:NULL, "12CL4K2eVqj7hQTix7dM7CVHCkpP17Pry3");
      ck_str("da pkh [2]", r&&r->nitems>2?r->items[2]->str:NULL, "1J4LVanjHMu3JkXbVrahNuQCTGCRRgfWWx");
      rj_free(r);
      /* sh(wpkh) ranged [0,2] */
      snprintf(p, sizeof p, "[\"sh(wpkh(%s/0/*))#knyhj9av\", [0,2]]", XP);
      r = call("deriveaddresses", p, &ec, &em);
      ck_str("da sh(wpkh) [0]", r&&r->nitems>0?r->items[0]->str:NULL, "3AfyxhpBVVLmBR4ZYX2onGzRqjv5QZ7FqD");
      ck_str("da sh(wpkh) [2]", r&&r->nitems>2?r->items[2]->str:NULL, "3EZQk4F8GURH5sqVMLTFisD17yNeKa7Dfs");
      rj_free(r);
      /* fixed non-ranged path -> single address, no range arg */
      snprintf(p, sizeof p, "[\"wpkh(%s/44/5)#u9t23g20\"]", XP);
      r = call("deriveaddresses", p, &ec, &em);
      ck("da fixed -> 1 addr", r && r->typ == RJ_ARR && r->nitems == 1);
      ck_str("da fixed [0]", r&&r->nitems>0?r->items[0]->str:NULL, "bc1q0k2xl6ppmegpnxl7qvday08x0fyhv2k22vdea9");
      rj_free(r);
      /* error parity: missing checksum, range mismatches, pk() has no address */
      snprintf(p, sizeof p, "[\"wpkh(%s/0/*)\", [0,1]]", XP);
      expect_err("da missing checksum", "deriveaddresses", p, -5, "Missing checksum");
      snprintf(p, sizeof p, "[\"wpkh(%s/0/*)#wvk84d79\"]", XP);
      expect_err("da ranged needs range", "deriveaddresses", p, -8, "Range must be specified for a ranged descriptor");
      snprintf(p, sizeof p, "[\"wpkh(%s/44/5)#u9t23g20\", [0,1]]", XP);
      expect_err("da unranged rejects range", "deriveaddresses", p, -8, "Range should not be specified for an un-ranged descriptor");
      expect_err("da pk has no address", "deriveaddresses",
                 "[\"pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#gn28ywm7\"]",
                 -5, "Descriptor does not have a corresponding address");

      /* addr()/raw() descriptors (audit gap, incident-#44 pattern) -- verified
       * vs oracle: getdescriptorinfo issolvable=false, deriveaddresses returns
       * the address itself. */
      r = call("getdescriptorinfo", "[\"addr(1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9)\"]", &ec, &em);
      ck_str("gdi addr() checksum", S(r,"checksum"), "gxt8zcpx");
      ck_str("gdi addr() issolvable=false", S(r,"issolvable"), "0");
      ck_str("gdi addr() isrange=false", S(r,"isrange"), "0");
      rj_free(r);
      r = call("deriveaddresses", "[\"addr(1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9)#gxt8zcpx\"]", &ec, &em);
      ck_str("da addr() returns the address", r&&r->typ==RJ_ARR&&r->nitems?r->items[0]->str:NULL, "1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9");
      rj_free(r);
      r = call("getdescriptorinfo", "[\"raw(76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac)\"]", &ec, &em);
      ck("gdi raw() issolvable=false", S(r,"issolvable") && !strcmp(S(r,"issolvable"),"0"));
      rj_free(r);
    }

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

    /* ---- getchaintips (active tip only; no forks persisted) ---- */
    {
        rj_val* r = call("getchaintips", "[]", &ec, &em);
        ck("getchaintips is a 1-entry array", r && r->typ == RJ_ARR && r->nitems == 1);
        rj_val* t0 = (r && r->nitems) ? r->items[0] : 0;
        ck_str("chaintip status active", S(t0,"status"), "active");
        ck_str("chaintip branchlen 0", S(t0,"branchlen"), "0");
        ck("chaintip has height + hash", S(t0,"height") && S(t0,"hash"));
        rj_free(r);
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

    /* ---- getblockstats (block-only fields; the synthetic archive has no undo,
     * so fee/feerate/utxo_size_inc keys are omitted -- as against a pruned node).
     * The full field set is oracle-verified live; here we regression the
     * block-only computation on synthetic block 3 (segwit cb + legacy spend +
     * segwit spend). ins=2, outs=3, total_out=4999000000+1000, subsidy=50 BTC. */
    { char p[128];
      snprintf(p, sizeof p, "[%d]", 3);
      r = call("getblockstats", p, &ec, &em);
      ck_str("gbs height", S(r,"height"), "3");
      ck_str("gbs txs", S(r,"txs"), "3");
      ck_str("gbs ins (non-coinbase)", S(r,"ins"), "2");
      ck_str("gbs outs", S(r,"outs"), "3");
      ck_str("gbs total_out (non-coinbase)", S(r,"total_out"), "4999001000");
      ck_str("gbs subsidy @ h3", S(r,"subsidy"), "5000000000");
      ck_str("gbs utxo_increase = outs-ins", S(r,"utxo_increase"), "1");
      ck_str("gbs swtxs (segwit spend only)", S(r,"swtxs"), "1");
      ck_str("gbs blockhash", S(r,"blockhash"), g_hash[3]);
      /* undo_3.dat (written by the fee test above) is present, so the fee fields
       * ARE computed: prevout values 5000000000, 4999000000 vs outputs
       * 4999000000, 1000 -> fees 1000000 and 4998999000. */
      ck_str("gbs totalfee", S(r,"totalfee"), "4999999000");
      ck_str("gbs maxfee", S(r,"maxfee"), "4998999000");
      ck_str("gbs minfee", S(r,"minfee"), "1000000");
      ck_str("gbs avgfee = totalfee/(txs-1)", S(r,"avgfee"), "2499999500");
      ck("gbs feerate_percentiles present (undo available)", G(r,"feerate_percentiles") != NULL);
      rj_free(r);
      /* by blockhash must equal by height */
      snprintf(p, sizeof p, "[\"%s\"]", g_hash[3]);
      rj_val* r2 = call("getblockstats", p, &ec, &em);
      ck_str("gbs by-hash height matches", S(r2,"height"), "3");
      ck_str("gbs by-hash total_out matches", S(r2,"total_out"), "4999001000");
      rj_free(r2);
      expect_err("gbs height out of range", "getblockstats", "[999]", -8, "Target block height out of range");
    }

    /* ---- getnetworkhashps / getmininginfo (chainwork from the header fallback,
     * which is block_work-correct). Exact values are oracle-verified live; here
     * we regress the plumbing, error parity, and getmininginfo shape. ---- */
    {
      r = call("getnetworkhashps", "[]", &ec, &em);
      ck("getnetworkhashps returns a positive number", r && r->typ == RJ_NUM && atof(r->str) > 0.0); rj_free(r);
      r = call("getnetworkhashps", "[120,3]", &ec, &em);
      ck("getnetworkhashps by height returns a number", r && r->typ == RJ_NUM); rj_free(r);
      expect_err("gnh nblocks=0 rejected", "getnetworkhashps", "[0]", -8, "Invalid nblocks. Must be a positive number or -1.");
      expect_err("gnh height out of range", "getnetworkhashps", "[120, 999]", -8, "Block does not exist at specified height");

      r = call("getmininginfo", "[]", &ec, &em);
      ck_str("mininginfo.blocks", S(r,"blocks"), "3");
      ck_str("mininginfo.chain", S(r,"chain"), "main");
      ck("mininginfo.bits present (8 hex)", S(r,"bits") && strlen(S(r,"bits")) == 8);
      ck("mininginfo.difficulty present", G(r,"difficulty") != NULL);
      ck("mininginfo.networkhashps present", G(r,"networkhashps") != NULL);
      ck_str("mininginfo.pooledtx", S(r,"pooledtx"), "0");
      ck("mininginfo.warnings is an array", G(r,"warnings") && G(r,"warnings")->typ == RJ_ARR);
      rj_free(r);
    }

    /* ---- getblocktemplate (BIP22/23): deterministic frame on the fixture
     * chain (tip=3, next height 4, no injected mempool -> empty template).
     * The empty-template default_witness_commitment is a CONSTANT --
     * sha256d(0^32 || 0^32) behind the aa21a9ed tag -- frozen from an
     * independent reference computation. Retarget vectors likewise frozen
     * from an arith_uint256-faithful reference (incl clamp + pow-limit). ---- */
    {
      expect_err("gbt without rules -> Core's segwit-rule error", "getblocktemplate", "[{}]",
                 -8, "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})");
      expect_err("gbt no params -> same error", "getblocktemplate", "[]",
                 -8, "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})");
      r = call("getblocktemplate", "[{\"rules\":[\"segwit\"]}]", &ec, &em);
      ck("gbt dispatched", r && r->typ == RJ_OBJ);
      ck_str("gbt.height (tip+1)", S(r,"height"), "4");
      ck_str("gbt.version", S(r,"version"), "536870912");
      ck_str("gbt.coinbasevalue = 50 BTC subsidy (no fees)", S(r,"coinbasevalue"), "5000000000");
      ck_str("gbt.sigoplimit", S(r,"sigoplimit"), "80000");
      ck_str("gbt.weightlimit", S(r,"weightlimit"), "4000000");
      ck_str("gbt.sizelimit", S(r,"sizelimit"), "4000000");
      ck_str("gbt.noncerange", S(r,"noncerange"), "00000000ffffffff");
      ck("gbt.transactions empty (no pool injected)",
         G(r,"transactions") && G(r,"transactions")->typ == RJ_ARR && G(r,"transactions")->nitems == 0);
      ck_str("gbt.default_witness_commitment (empty-template constant)",
             S(r,"default_witness_commitment"),
             "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9");
      { rj_val* rls = G(r,"rules");
        ck("gbt.rules [csv, !segwit, taproot]", rls && rls->typ==RJ_ARR && rls->nitems==3
           && !strcmp(rls->items[0]->str,"csv") && !strcmp(rls->items[1]->str,"!segwit")
           && !strcmp(rls->items[2]->str,"taproot")); }
      ck("gbt.mutable has time/transactions/prevblock",
         G(r,"mutable") && G(r,"mutable")->typ==RJ_ARR && G(r,"mutable")->nitems==3);
      /* cross-checks against sibling RPCs on the same fixture */
      { rj_val* bb = call("getbestblockhash", "[]", &ec, &em);
        ck("gbt.previousblockhash == getbestblockhash", bb && S(r,"previousblockhash")
           && !strcmp(S(r,"previousblockhash"), bb->str));
        rj_free(bb); }
      { rj_val* bh = call("getblockheader", "[\"tip\"]", &ec, &em); (void)bh; if (bh) rj_free(bh); }
      { rj_val* mi = call("getmininginfo", "[]", &ec, &em);
        ck("gbt.bits == tip bits (not a retarget height)",
           mi && S(mi,"bits") && S(r,"bits") && !strcmp(S(r,"bits"), S(mi,"bits")));
        rj_free(mi); }
      { long mt = atol(S(r,"mintime") ? S(r,"mintime") : "0");
        long ct = atol(S(r,"curtime") ? S(r,"curtime") : "0");
        ck("gbt.curtime >= mintime > 0", mt > 0 && ct >= mt); }
      ck("gbt.longpollid = prevhash+counter",
         S(r,"longpollid") && strlen(S(r,"longpollid")) > 64
         && !strncmp(S(r,"longpollid"), S(r,"previousblockhash"), 64));
      rj_free(r);

      /* ---- ancestor-package (CPFP) selection: a real 3-tx pool ----
       * Slot order is M, P, C (M FIRST). The old parents-first slot-order
       * emitter returned [M, P, C]; Core's addPackageTxs must return
       * [P, C, M]: the package {P,C} (fee 5500 over ~122B, ~45 sat/B)
       * outscores standalone M (~24 sat/B), and C lifts its cheap parent P
       * (~8 sat/B alone) in with it. Fees are proven through coinbasevalue
       * (subsidy 5e9 + 7000) and the child's depends[] points at P. */
      {
        extern void   mpool_init(void*, unsigned long, void*, unsigned long);
        extern long   mpool_count(void*);
        extern const unsigned char* mpool_get(void*, const unsigned char*, unsigned long*);
        extern void   utxo_init(void*, unsigned long, void*, unsigned long);
        extern long   utxo_put(void*, const unsigned char*, unsigned long,
                               unsigned long long, unsigned long, unsigned long,
                               const unsigned char*, unsigned long);
        extern void   mpool_policy_state_init(void*, unsigned);
        extern void   mpool_policy_init(void*, unsigned long long, unsigned, unsigned,
                                        unsigned, unsigned, unsigned);
        extern long   mpool_policy_add(void*, void*, void*, const unsigned char*,
                                       unsigned long, const unsigned char*, void*);
        extern long   mpool_policy_entry(void*, const unsigned char*,
                                         unsigned long long*, unsigned long long*);
        struct mp_entry_info;
        extern long   mpool_policy_entry_info(void*, const unsigned char*, struct mp_entry_info*);
        extern void   sha256d(unsigned char*, const void*, unsigned long);

        static unsigned char pol[128], stbuf[1<<20];
        static unsigned char mp[40 + 4096*48 + 8], mblob[1<<20];
        static unsigned char ux[40 + 4096*48 + 8], ublob[1<<16];
        memset(stbuf, 0, sizeof stbuf);
        mpool_policy_init(pol, 1, 25, 101000, 25, 101000, 1);
        /* the CPFP fixtures below are synthetic ~61-byte legacy txs --
         * deliberately non-standard (tx-size-small, empty scriptSig); run
         * under Core's own regtest escape hatch (-acceptnonstdtxn) so this
         * section keeps testing PACKAGE SELECTION, not IsStandardTx (same
         * treatment as tests/test_mempool_evict.c). */
        { extern void mpool_policy_set_acceptnonstd(void*, unsigned);
          mpool_policy_set_acceptnonstd(pol, 1); }
        mpool_policy_state_init(stbuf, 256);
        mpool_init(mp, 4096, mblob, sizeof mblob);
        utxo_init(ux, 4096, ublob, sizeof ublob);

        /* two confirmed prevouts */
        unsigned char prevM[32], prevP[32];
        memset(prevM, 0xAA, 32); memset(prevP, 0xBB, 32);
        utxo_put(ux, prevM, 0, 100000ULL, 1, 0, (const unsigned char*)"\x51", 1);
        utxo_put(ux, prevP, 0, 100000ULL, 1, 0, (const unsigned char*)"\x51", 1);

        /* minimal legacy tx: ver|1in(prev,idx,emptySS)|1out(val,OP_TRUE)|lock */
        unsigned char txM[64], txP[64], txC[64];
        unsigned char idM[32], idP[32], idC[32];
        #define MKTX(buf, id, prev, pidx, val) do{ \
            unsigned char* q = (buf); \
            memcpy(q, "\x01\x00\x00\x00", 4); q += 4; \
            *q++ = 1; memcpy(q, (prev), 32); q += 32; \
            unsigned v_ = (pidx); memcpy(q, &v_, 4); q += 4; \
            *q++ = 0; memcpy(q, "\xff\xff\xff\xff", 4); q += 4; \
            *q++ = 1; unsigned long long a_ = (val); memcpy(q, &a_, 8); q += 8; \
            *q++ = 1; *q++ = 0x51; \
            memcpy(q, "\x00\x00\x00\x00", 4); q += 4; \
            sha256d((id), (buf), (unsigned long)(q - (buf))); }while(0)
        MKTX(txM, idM, prevM, 0, 98500ULL);   /* fee 1500 */
        MKTX(txP, idP, prevP, 0, 99500ULL);   /* fee  500 */
        MKTX(txC, idC, idP,   0, 94500ULL);   /* fee 5000, spends P:0 */

        /* slot order: M FIRST, then P, then C */
        ck("cpfp: M accepted", mpool_policy_add(pol, stbuf, mp, txM, 61, idM, ux) == 1);
        ck("cpfp: P accepted", mpool_policy_add(pol, stbuf, mp, txP, 61, idP, ux) == 1);
        ck("cpfp: C accepted", mpool_policy_add(pol, stbuf, mp, txC, 61, idC, ux) == 1);

        rpc_mempool_hooks h; memset(&h, 0, sizeof h);
        h.mp = mp; h.polstate = stbuf;
        h.count = mpool_count; h.get = mpool_get;
        h.pol_entry = mpool_policy_entry;
        h.pol_entry_info = mpool_policy_entry_info;
        h.sha256d = sha256d;
        rpc_chain_set_mempool(&h, NULL);

        r = call("getblocktemplate", "[{\"rules\":[\"segwit\"]}]", &ec, &em);
        ck("cpfp gbt dispatched", r && r->typ == RJ_OBJ);
        rj_val* txs2 = G(r, "transactions");
        ck("cpfp: all 3 selected", txs2 && txs2->typ == RJ_ARR && txs2->nitems == 3);
        if (txs2 && txs2->nitems == 3){
            char hP[65], hC[65], hM[65];
            trc_hex_rev(hP, idP, 32); trc_hex_rev(hC, idC, 32); trc_hex_rev(hM, idM, 32);
            const char* t0 = rj_obj_get(txs2->items[0], "txid")->str;
            const char* t1 = rj_obj_get(txs2->items[1], "txid")->str;
            const char* t2 = rj_obj_get(txs2->items[2], "txid")->str;
            ck("cpfp order[0] = P (cheap parent, lifted by its child)", !strcmp(t0, hP));
            ck("cpfp order[1] = C (the paying child)",                  !strcmp(t1, hC));
            ck("cpfp order[2] = M (standalone middle feerate LAST)",    !strcmp(t2, hM));
            rj_val* dep = rj_obj_get(txs2->items[1], "depends");
            ck("cpfp C.depends = [1] (P's 1-based index)",
               dep && dep->typ == RJ_ARR && dep->nitems == 1 && !strcmp(dep->items[0]->str, "1"));
        }
        ck_str("cpfp coinbasevalue = subsidy + 7000 fees", S(r,"coinbasevalue"), "5000007000");
        rj_free(r);

        /* restore the empty pool for the sections below */
        { rpc_mempool_hooks h0; memset(&h0, 0, sizeof h0);
          rpc_chain_set_mempool(&h0, NULL); }
      }

      /* retarget KATs (frozen reference vectors) */
      ck("retarget same timespan keeps bits", rpc_chain_retarget(0x1d00ffff, 1209600) == 0x1d00ffff);
      ck("retarget half timespan halves target", rpc_chain_retarget(0x1d00ffff, 604800) == 0x1c7fff80);
      ck("retarget double timespan capped at pow limit", rpc_chain_retarget(0x1d00ffff, 2419200) == 0x1d00ffff);
      ck("retarget clamps timespan to /4", rpc_chain_retarget(0x1d00ffff, 1) == 0x1c3fffc0);
      ck("retarget modern bits, faster blocks", rpc_chain_retarget(0x1702905c, 1100000) == 0x170254e3);
      ck("retarget modern bits, slower blocks", rpc_chain_retarget(0x1702905c, 1300000) == 0x1702c169);
    }

    /* ---- gettxoutsetinfo: dispatch + shape over an injected STUB reader
     * (the real reader is the tool-derived daemon/utxo_setinfo_rpc.c, whose
     * numbers get their proof at the parity capstone against both the
     * standalone tool and the Core oracle). ---- */
    {
      extern void rpc_chain_set_utxosetinfo(long (*)(int, void*, char*, unsigned long));
      /* no reader injected -> unavailable */
      { long e0; const char* m0; rj_val* r0 = NULL;
        rj_val* p0 = rj_parse("[]", 2);
        int rc0 = rpc_chain_dispatch("gettxoutsetinfo", p0, &r0, &e0, &m0);
        ck("gettxoutsetinfo without a reader -> unavailable", rc0==0 && e0==-1);
        rj_free(r0); rj_free(p0); }
      rpc_chain_set_utxosetinfo(usi_stub_run);
      r = call("gettxoutsetinfo", "[]", &ec, &em);
      ck("usi default (muhash) dispatched", r && r->typ == RJ_OBJ);
      ck_str("usi.height", S(r,"height"), "3");
      ck_str("usi.txouts", S(r,"txouts"), "12345");
      ck_str("usi.bogosize", S(r,"bogosize"), "999");
      ck_str("usi.total_amount", S(r,"total_amount"), "123.45678900");
      ck("usi.muhash present (64 hex)", S(r,"muhash") && strlen(S(r,"muhash"))==64);
      { rj_val* bb = call("getbestblockhash", "[]", &ec, &em);
        ck("usi.bestblock == header hash at reported height (tip=3 here)",
           bb && S(r,"bestblock") && !strcmp(S(r,"bestblock"), bb->str));
        rj_free(bb); }
      rj_free(r);
      r = call("gettxoutsetinfo", "[\"none\"]", &ec, &em);
      ck("usi none -> muhash absent", r && rj_obj_get(r,"muhash")==NULL && S(r,"txouts"));
      rj_free(r);
      expect_err("usi hash_serialized_3 -> honest refusal", "gettxoutsetinfo",
                 "[\"hash_serialized_3\"]", -8,
                 "hash_serialized_3 hash type not implemented (this node computes muhash)");
      expect_err("usi bad hash_type -> Core message shape", "gettxoutsetinfo",
                 "[\"bogus\"]", -8, "'bogus' is not a valid hash_type");
      g_usi_stub_busy = 1;
      { long e1; const char* m1; rj_val* r1 = NULL;
        rj_val* p1 = rj_parse("[]", 2);
        int rc1 = rpc_chain_dispatch("gettxoutsetinfo", p1, &r1, &e1, &m1);
        ck("usi busy reader -> -1 with the busy message",
           rc1==0 && e1==-1 && m1 && strstr(m1,"being written"));
        rj_free(r1); rj_free(p1); }
      g_usi_stub_busy = 0;
      rpc_chain_set_utxosetinfo(0);
    }

    /* ---- scantxoutset: dispatch + shape over an injected STUB scanner (the
     * real scanner shares the tool-derived reader TU; its numbers get their
     * proof at the parity capstone -- oracle target frozen: the Counterparty
     * burn address, 3135 unspents / 2130.99791495 BTC at oracle h=964017).
     * Synchronous scans: status -> null, abort -> false (Core's no-scan
     * answers, oracle-verified). ---- */
    {
      extern void rpc_chain_set_utxoscan(long (*)(const unsigned char*, const unsigned int*,
                    int, void*, long, long*, long*, unsigned long long*, unsigned long long*,
                    int*, char*, unsigned long));
      r = call("scantxoutset", "[\"status\"]", &ec, &em);
      ck("scan status (no scan) -> null", r && r->typ == RJ_NULL); rj_free(r);
      r = call("scantxoutset", "[\"abort\"]", &ec, &em);
      ck("scan abort (no scan) -> false", r && r->typ == RJ_BOOL && r->str[0]=='0'); rj_free(r);
      expect_err("scan bad action -> Core message", "scantxoutset", "[\"frobnicate\"]",
                 -8, "Invalid action 'frobnicate'");
      expect_err("scan start without scanobjects -> -8", "scantxoutset", "[\"start\"]",
                 -8, "scanobjects argument is required for the start action");
      { long e0; const char* m0; rj_val* r0=NULL;
        rj_val* p0 = rj_parse("[\"start\", [\"addr(1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9)\"]]", 55);
        (void)p0; if (p0) rj_free(p0);
        /* no scanner injected -> unavailable */
        const char* pj0 = "[\"start\", [\"addr(1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9)\"]]";
        p0 = rj_parse(pj0, strlen(pj0)); r0=NULL;
        int rc0 = rpc_chain_dispatch("scantxoutset", p0, &r0, &e0, &m0);
        ck("scan start without a scanner -> unavailable", rc0==0 && e0==-1);
        rj_free(r0); rj_free(p0); }
      rpc_chain_set_utxoscan(scan_stub_run);
      { const char* pj1 = "[\"start\", [\"addr(1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9)\"]]";
        rj_val* p1 = rj_parse(pj1, strlen(pj1)); r = NULL;
        int rc1 = rpc_chain_dispatch("scantxoutset", p1, &r, &ec, &em);
        ck("scan start dispatched", rc1==1 && r && r->typ==RJ_OBJ);
        ck("scan success true", r && rj_obj_get(r,"success") && rj_obj_get(r,"success")->str[0]=='1');
        ck_str("scan txouts", S(r,"txouts"), "150");
        ck_str("scan height (from runner)", S(r,"height"), "3");
        ck_str("scan total_amount", S(r,"total_amount"), "0.00123456");
        { rj_val* u1 = rj_obj_get(r,"unspents");
          ck("scan one unspent", u1 && u1->typ==RJ_ARR && u1->nitems==1);
          rj_val* e1 = (u1 && u1->nitems) ? u1->items[0] : NULL;
          ck("unspent txid/vout/amount", e1 && S(e1,"txid") && strlen(S(e1,"txid"))==64
             && S(e1,"vout") && !strcmp(S(e1,"vout"),"7")
             && S(e1,"amount") && !strcmp(S(e1,"amount"),"0.00123456"));
          ck("unspent scriptPubKey hex matches the target",
             e1 && S(e1,"scriptPubKey") && !strcmp(S(e1,"scriptPubKey"),
             "76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac"));
          ck("unspent desc = addr(...)#checksum (inferred)",
             e1 && S(e1,"desc") && !strncmp(S(e1,"desc"),"addr(1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9)#",41));
          ck("unspent coinbase false + height 2", e1 && rj_obj_get(e1,"coinbase")
             && rj_obj_get(e1,"coinbase")->str[0]=='0' && S(e1,"height") && !strcmp(S(e1,"height"),"2"));
          ck("unspent confirmations = scanh - h + 1 = 2",
             e1 && S(e1,"confirmations") && !strcmp(S(e1,"confirmations"),"2"));
          ck("unspent blockhash present (64 hex)", e1 && S(e1,"blockhash") && strlen(S(e1,"blockhash"))==64); }
        rj_free(r); rj_free(p1); }
      expect_err("scan invalid descriptor -> Core message shape", "scantxoutset",
                 "[\"start\", [\"notadesc\"]]", -5, "'notadesc' is not a valid descriptor function");
      rpc_chain_set_utxoscan(0);
    }

    /* ==== the rest of Core's Blockchain category (2026-08-25) ==========
     * The fixture is 4 blocks: genesis (1 tx) + heights 1,2 (1 tx each) +
     * height 3 (3 txs) = 6 transactions total. */

    /* ---- getchainstates: exactly one chainstate, always ---- */
    r = call("getchainstates", "[]", &ec, &em);
    ck("getchainstates -> object", r && r->typ == RJ_OBJ);
    ck_str("getchainstates headers", S(r,"headers"), "3");
    { rj_val* csa = r ? rj_obj_get(r,"chainstates") : NULL;
      ck("exactly one chainstate (no snapshot support, so never two)",
         csa && csa->typ == RJ_ARR && csa->nitems == 1);
      rj_val* cs = (csa && csa->nitems) ? csa->items[0] : NULL;
      ck_str("chainstate blocks", cs ? S(cs,"blocks") : NULL, "3");
      ck_str("chainstate bestblockhash agrees with getbestblockhash",
             cs ? S(cs,"bestblockhash") : NULL, g_hash[3]);
      ck_str("chainstate validated", cs ? S(cs,"validated") : NULL, "1");
      /* Core's coin-cache byte fields describe a LevelDB + coin cache this
       * node does not have; they must be absent, not zero. */
      ck("coins_db_cache_bytes is omitted, not zeroed",
         cs && rj_obj_get(cs,"coins_db_cache_bytes") == NULL);
      ck("coins_tip_cache_bytes is omitted, not zeroed",
         cs && rj_obj_get(cs,"coins_tip_cache_bytes") == NULL); }
    rj_free(r);

    /* ---- getdeploymentinfo: heights come from the GENERATED header, so
     * this asserts the node reports what its script-flag path enforces ---- */
    r = call("getdeploymentinfo", "[]", &ec, &em);
    ck("getdeploymentinfo -> object", r && r->typ == RJ_OBJ);
    ck_str("getdeploymentinfo hash is the tip", S(r,"hash"), g_hash[3]);
    ck_str("getdeploymentinfo height is the tip", S(r,"height"), "3");
    { rj_val* dep = r ? rj_obj_get(r,"deployments") : NULL;
      ck("Core's five buried deployments, no more", dep && dep->nmembers == 5);
      rj_val* seg = dep ? rj_obj_get(dep,"segwit") : NULL;
      ck_str("segwit type is buried", seg ? S(seg,"type") : NULL, "buried");
      ck_str("segwit height is the generated SFC_HEIGHT_SEGWIT",
             seg ? S(seg,"height") : NULL, "481824");
      ck_str("segwit is NOT active at fixture height 3",
             seg ? S(seg,"active") : NULL, "0");
      rj_val* b34 = dep ? rj_obj_get(dep,"bip34") : NULL;
      ck_str("bip34 height is the generated SFC_HEIGHT_BIP34",
             b34 ? S(b34,"height") : NULL, "227931"); }
    { rj_val* sf = r ? rj_obj_get(r,"script_flags") : NULL;
      /* at height 4 only the unconditional flags apply */
      ck("script_flags at a pre-activation height is exactly P2SH + TAPROOT",
         sf && sf->typ == RJ_ARR && sf->nitems == 2 &&
         !strcmp(sf->items[0]->str, "P2SH") && !strcmp(sf->items[1]->str, "TAPROOT")); }
    rj_free(r);
    /* the blockhash argument selects a different block */
    { char pj[96]; snprintf(pj, sizeof pj, "[\"%s\"]", g_hash[1]);
      r = call("getdeploymentinfo", pj, &ec, &em);
      ck_str("getdeploymentinfo(blockhash) reports that block", S(r,"height"), "1");
      rj_free(r); }
    expect_err("getdeploymentinfo on an unknown hash -> -5", "getdeploymentinfo",
               "[\"00000000000000000000000000000000000000000000000000000000deadbeef\"]",
               -5, "Block not found");

    /* ---- getchaintxstats ---- */
    r = call("getchaintxstats", "[]", &ec, &em);
    ck("getchaintxstats -> object", r && r->typ == RJ_OBJ);
    ck_str("window_final_block_height", S(r,"window_final_block_height"), "3");
    /* the fixture is shorter than the 4320-block default, so the window
     * clamps to the chain */
    ck_str("window clamps to the chain length", S(r,"window_block_count"), "3");
    ck_str("window_tx_count counts heights 1..3 = 1+1+3", S(r,"window_tx_count"), "5");
    ck_str("txcount is the CUMULATIVE count including genesis", S(r,"txcount"), "6");
    ck("txrate present when the window has a positive interval",
       rj_obj_get(r,"txrate") != NULL);
    rj_free(r);
    { /* an explicit window */
      r = call("getchaintxstats", "[1]", &ec, &em);
      ck_str("window=1 counts only the tip block's 3 txs", S(r,"window_tx_count"), "3");
      rj_free(r); }
    { /* window 0: Core emits no window_tx_count/txrate for an empty window */
      r = call("getchaintxstats", "[0]", &ec, &em);
      ck_str("window=0 -> window_block_count 0", S(r,"window_block_count"), "0");
      ck("window=0 emits no txrate", r && rj_obj_get(r,"txrate") == NULL);
      rj_free(r); }
    expect_err("a window past the chain -> -8", "getchaintxstats", "[9999]", -8,
               "Invalid block count: should be between 0 and the block's height - 1");

    /* ---- verifychain ----
     * The fixture's synthetic headers carry bits 0x1d00ffff with nonce 0, so
     * they have no valid proof of work. That makes level 1 the sharpest test
     * available here: it must return FALSE. A level-1 check that returned
     * true on these blocks would not be checking anything. */
    r = call("verifychain", "[0,4]", &ec, &em);
    ck_str("verifychain level 0 (readable) -> true", r ? r->str : NULL, "1");
    rj_free(r);
    r = call("verifychain", "[1,4]", &ec, &em);
    ck_str("verifychain level 1 -> FALSE (synthetic headers have no valid PoW)",
           r ? r->str : NULL, "0");
    rj_free(r);
    r = call("verifychain", "[2,4]", &ec, &em);
    ck_str("verifychain level 2 -> false (no undo data in the fixture)",
           r ? r->str : NULL, "0");
    rj_free(r);
    { long e3; const char* m3; rj_val* r3 = call("verifychain", "[3,4]", &e3, &m3);
      ck("verifychain level 3 REFUSES rather than returning a downgraded true",
         r3 == NULL && e3 == -1 && m3 && strstr(m3, "checklevel 0-2"));
      rj_free(r3); }
    { long e4; const char* m4; rj_val* r4 = call("verifychain", "[]", &e4, &m4);
      ck("bare verifychain (Core default level 3) refuses too, naming the range",
         r4 == NULL && e4 == -1 && m4 && strstr(m4, "checklevel 2 or lower"));
      rj_free(r4); }
    expect_err("verifychain level 9 -> -8", "verifychain", "[9]", -8,
               "Invalid checklevel: must be 0-4");

    /* ---- waitfor* : satisfied conditions return immediately ---- */
    r = call("waitforblockheight", "[1,1000]", &ec, &em);
    ck("waitforblockheight below the tip returns at once",
       r && r->typ == RJ_OBJ);
    ck_str("...reporting the current tip height", S(r,"height"), "3");
    ck_str("...and its hash", S(r,"hash"), g_hash[3]);
    rj_free(r);
    { char pj[96]; snprintf(pj, sizeof pj, "[\"%s\",1000]", g_hash[3]);
      r = call("waitforblock", pj, &ec, &em);
      ck("waitforblock on the CURRENT tip hash returns at once", r && r->typ == RJ_OBJ);
      ck_str("...with that height", S(r,"height"), "3");
      rj_free(r); }
    { /* nothing will arrive; the short timeout must expire and return the
       * current tip, which is Core's own on-timeout behaviour */
      r = call("waitfornewblock", "[100]", &ec, &em);
      ck("waitfornewblock times out and returns the current tip",
         r && r->typ == RJ_OBJ);
      ck_str("...at the unchanged height", S(r,"height"), "3");
      rj_free(r); }
    expect_err("waitforblockheight with no height -> -8", "waitforblockheight", "[]",
               -8, "waitforblockheight requires a height");

    /* ---- the refusals name what is missing ---- */
    /* savemempool/importmempool left this list on 2026-08-27: they are real
     * and dispatched by rpc_node.c now, so a call reaching THIS table would
     * mean the node dispatcher had stopped claiming them. */
    { struct { const char* m; const char* needle; } R[] = {
        {"preciousblock", "fork choice"}, {"pruneblockchain", "fork choice"} };
      int all = 1;
      for (unsigned i = 0; i < sizeof R / sizeof *R; i++){
          long e; const char* m; rj_val* rr = call(R[i].m, "[]", &e, &m);
          if (!(rr == NULL && e == -1 && m && strstr(m, R[i].needle))){
              printf("      (%s: ec=%ld em=%s)\n", R[i].m, e, m ? m : "(null)");
              all = 0;
          }
          rj_free(rr);
      }
      ck("every unsupported Blockchain method errors with the reason named", all);
      /* and the two that moved are NOT claimed by the chain table any more */
      ck("savemempool/importmempool are no longer chain-table refusals",
         rpc_chain_dispatch("savemempool", NULL, &(rj_val*){0}, &(long){0}, &(const char*){0}) == -1);
      ck("rpc_known_method covers them too",
         rpc_known_method("dumptxoutset") && rpc_known_method("getchainstates") &&
         rpc_known_method("waitforblock") && rpc_known_method("verifychain")); }

    /* ---- getblockfilter / scanblocks / getdescriptoractivity ----
     * The builder itself is Core-byte-validated in test_block_filter.c; here
     * the RPC plumbing is checked on the fixture chain. Height 0 is the REAL
     * mainnet genesis block, and genesis needs no undo data (its coinbase
     * spends nothing), so its filter must come out as Core's own 017fa880
     * even with no undo reader attached. */
    { char pj[96]; snprintf(pj, sizeof pj, "[\"%s\"]", g_hash[0]);
      r = call("getblockfilter", pj, &ec, &em);
      ck("getblockfilter serves the genesis block", r && r->typ == RJ_OBJ);
      ck_str("genesis filter is BYTE-IDENTICAL to Core's", S(r,"filter"), "017fa880");
      /* the header chains from genesis and cannot be computed without every
       * prior filter -- it must be ABSENT, never fabricated */
      ck("no filter header is fabricated", r && rj_obj_get(r,"header") == NULL);
      rj_free(r); }
    { /* any other height needs undo data; none is attached here, and the
       * refusal must say WHY a filter without it would be wrong */
      char pj[96]; snprintf(pj, sizeof pj, "[\"%s\"]", g_hash[2]);
      long e2; const char* m2; rj_val* r2 = call("getblockfilter", pj, &e2, &m2);
      ck("a non-genesis block without undo data is refused",
         r2 == NULL && e2 == -1 && m2 && strstr(m2, "undo"));
      ck("...explaining that a filter missing elements would mislead",
         r2 == NULL && m2 && strstr(m2, "missing elements"));
      rj_free(r2); }
    { long e2; const char* m2;
      rj_val* r2 = call("getblockfilter",
          "[\"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f\",\"exotic\"]",
          &e2, &m2);
      ck("an unknown filtertype -> -5", r2 == NULL && e2 == -5);
      rj_free(r2); }

    /* scanblocks: the genesis coinbase pays the well-known P2PK output;
     * scan for it by raw() descriptor and genesis must be the ONLY hit */
    { const char* GEN_SPK =
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
        "b649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac";
      char pj[400];
      snprintf(pj, sizeof pj, "[\"start\",[\"raw(%s)\"],0,3]", GEN_SPK);
      r = call("scanblocks", pj, &ec, &em);
      ck("scanblocks start runs", r && r->typ == RJ_OBJ);
      ck_str("scanned the requested range", S(r,"to_height"), "3");
      { rj_val* rb = r ? rj_obj_get(r,"relevant_blocks") : NULL;
        ck("exactly one relevant block", rb && rb->typ == RJ_ARR && rb->nitems == 1);
        ck_str("...and it is genesis", (rb && rb->nitems) ? rb->items[0]->str : NULL, g_hash[0]); }
      ck("the result carries the exact-scan divergence note",
         r && S(r,"note") && strstr(S(r,"note"), "within the scanned range"));
      rj_free(r);
      /* status/abort answer Core's idle shapes */
      r = call("scanblocks", "[\"status\"]", &ec, &em);
      ck("scanblocks status -> null (scans are synchronous)", r && r->typ == RJ_NULL);
      rj_free(r);
      r = call("scanblocks", "[\"abort\"]", &ec, &em);
      ck("scanblocks abort -> false", r && r->typ == RJ_BOOL && r->str[0] == '0');
      rj_free(r);
      /* getdescriptoractivity over genesis reports the receive */
      snprintf(pj, sizeof pj, "[[\"%s\"],[\"raw(%s)\"]]", g_hash[0], GEN_SPK);
      r = call("getdescriptoractivity", pj, &ec, &em);
      ck("getdescriptoractivity runs", r && r->typ == RJ_OBJ);
      { rj_val* a = r ? rj_obj_get(r,"activity") : NULL;
        rj_val* a0 = (a && a->nitems) ? a->items[0] : NULL;
        ck("one receive activity entry", a && a->nitems == 1 && a0);
        ck_str("...typed receive", a0 ? S(a0,"type") : NULL, "receive");
        ck_str("...with the 50 BTC amount", a0 ? S(a0,"amount") : NULL, "50.00000000");
        ck_str("...at height 0", a0 ? S(a0,"height") : NULL, "0"); }
      rj_free(r); }

    /* ---- submitheader ----
     * A header the node already has is a no-op returning null, exactly as
     * Core answers. Anything else is refused rather than answered with the
     * null that would mean "accepted". ---- */
    { char gh[161]; memcpy(gh, GENESIS_HEX, 160); gh[160] = 0;
      char pj[200]; snprintf(pj, sizeof pj, "[\"%s\"]", gh);
      long e; const char* m; rj_val* r2 = call("submitheader", pj, &e, &m);
      ck("submitheader on a header we already have -> null",
         r2 && r2->typ == RJ_NULL);
      rj_free(r2);
      /* flip a byte of the nonce: a well-formed header we do not have */
      gh[159] = (gh[159] == 'c') ? 'd' : 'c';
      snprintf(pj, sizeof pj, "[\"%s\"]", gh);
      r2 = call("submitheader", pj, &e, &m);
      ck("an unknown header is REFUSED, not silently accepted",
         r2 == NULL && e == -1 && m && strstr(m, "download worker"));
      rj_free(r2); }
    expect_err("submitheader on short hex -> Core's -22", "submitheader",
               "[\"0011\"]", -22, "Block header decode failed");
    expect_err("submitheader on non-hex -> -22", "submitheader",
               "[\"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"]",
               -22, "Block header decode failed");

    /* ---- getrawtransaction by TXID ALONE, via the txid index ----
     * Without an index this had to refuse, which is the single most likely
     * thing to break an application swapping this node in for Core. ---- */
    { /* before the index exists, the refusal names what is missing */
      char pj[96]; snprintf(pj, sizeof pj, "[\"%s\"]", g_tx1_txid);
      long e2; const char* m2; rj_val* r2 = call("getrawtransaction", pj, &e2, &m2);
      ck("with no index, getrawtransaction by txid refuses and says why",
         r2 == NULL && e2 == -5 && m2 && strstr(m2, "txindex"));
      rj_free(r2); }

    build_fixture_txindex(2, 3);   /* base covers 0..2; height 3 lives in the TAIL */
    /* no reopen needed: txi_open latches on success, so the index is picked
     * up on the next lookup -- which is also what an operator building the
     * index against a running node needs. */

    { /* every fixture transaction must now resolve by txid alone, and the
       * bytes must be IDENTICAL to what the blockhash path returns */
      const char* ids[] = { g_cb_txid[1], g_cb_txid[2], g_tx1_txid, g_tx2_txid };
      const char* blks[] = { g_hash[1], g_hash[2], g_hash[3], g_hash[3] };
      int all = 1, same = 1;
      for (int i = 0; i < 4; i++){
          char pj[96]; snprintf(pj, sizeof pj, "[\"%s\"]", ids[i]);
          rj_val* a = call("getrawtransaction", pj, &ec, &em);
          char pj2[200]; snprintf(pj2, sizeof pj2, "[\"%s\",0,\"%s\"]", ids[i], blks[i]);
          rj_val* b = call("getrawtransaction", pj2, &ec, &em);
          if (!a || !a->str){ all = 0; printf("      (no index hit for %.16s)\n", ids[i]); }
          else if (!b || !b->str || strcmp(a->str, b->str)) same = 0;
          rj_free(a); rj_free(b);
      }
      ck("every fixture tx resolves by txid alone", all);
      ck("...and byte-identically to the blockhash path (one render path)", same); }

    { /* verbosity 1 through the index carries the block context */
      char pj[96]; snprintf(pj, sizeof pj, "[\"%s\",1]", g_tx2_txid);
      r = call("getrawtransaction", pj, &ec, &em);
      ck("verbosity 1 via the index returns an object", r && r->typ == RJ_OBJ);
      ck_str("...with the txid", S(r,"txid"), g_tx2_txid);
      ck_str("...and the blockhash the index resolved", S(r,"blockhash"), g_hash[3]);
      ck("...and in_active_chain", r && S(r,"in_active_chain"));
      rj_free(r); }

    { /* a txid the index does not hold: the error must say the index is
       * PARTIAL and name its range -- "not found" from a partial index is a
       * different fact from "not found" on the whole chain */
      long e2; const char* m2;
      rj_val* r2 = call("getrawtransaction",
                        "[\"00000000000000000000000000000000000000000000000000000000deadbeef\"]",
                        &e2, &m2);
      ck("an unindexed txid reports the index's COVERED RANGE",
         r2 == NULL && e2 == -5 && m2 && strstr(m2, "covers heights"));
      rj_free(r2); }

    { /* getindexinfo now REPORTS the index, and reports it as synced only
       * when it actually reaches the tip */
      r = call("getindexinfo", "[]", &ec, &em);
      rj_val* ti = r ? rj_obj_get(r, "txindex") : NULL;
      ck("getindexinfo reports the txindex once built", ti && ti->typ == RJ_OBJ);
      ck_str("...with the height it covers", ti ? S(ti,"best_block_height") : NULL, "3");
      ck_str("...and synced, since it reaches the tip", ti ? S(ti,"synced") : NULL, "1");
      rj_free(r);
      r = call("getindexinfo", "[\"txindex\"]", &ec, &em);
      ck("getindexinfo(txindex) filters to it", r && rj_obj_get(r,"txindex"));
      rj_free(r);
      r = call("getindexinfo", "[\"nosuch\"]", &ec, &em);
      ck("getindexinfo(unknown) -> {}", r && r->typ == RJ_OBJ && r->nmembers == 0);
      rj_free(r); }

    /* ---- uptime / stop ---- */
    r = call("uptime", "[]", &ec, &em); ck("uptime is a non-negative number", r && r->typ == RJ_NUM && atol(r->str) >= 0); rj_free(r);
    r = call("stop", "[]", &ec, &em); ck_str("stop reply", r ? r->str : NULL, "Bitcoin Machine Code stopping"); rj_free(r);
    ck("stop invoked the handler", g_stopped == 1);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
