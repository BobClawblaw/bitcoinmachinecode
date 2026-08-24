/* test_txv_dispatch_diff.c -- bitcoin_txv_dispatch.asm vs tx_verify.c's
 * txvb_verify_one / legacy_tx_view.
 *
 * WHY THIS EXISTS
 *   Phase 2 slice 8: the dispatch decides which verifier judges an input
 *   and builds that verifier's argument list; legacy_tx_view decides which
 *   BYTES legacy sighashing sees. Both sides call the same C leaves
 *   (sv_verify_witness_v0 / sv_verify_script) and the proven slice-7 twin
 *   for taproot, so the differential drives shapes where a marshaling
 *   mistake flips the verdict or the reason:
 *     - LEGACY accept (OP_TRUE spk) and reject (OP_0 spk), on plain AND
 *       segwit-marked txs (the latter exercising legacy_tx_view's strip on
 *       both sides -- a wrong view changes nothing for these scripts, so
 *       the view is ALSO compared directly, pointer-vs-bytes);
 *     - WV0 P2WSH accept (witnessScript = OP_TRUE, program = its sha256)
 *       -- a real end-to-end accept through the whole marshal -- plus
 *       P2WSH hash-mismatch and P2WPKH garbage-sig rejects, and both
 *       wprog resolutions (wrapped pointer vs native spk offset);
 *     - P2TR: descriptor-not-built, and garbage witness shapes against a
 *       real slice-7 descriptor (same pools handed to both sides);
 *     - WPASS: unconditional accept.
 *
 * Usage: ./test_txv_dispatch_diff
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64;
typedef struct { u8* buf; u64 cap; u64 used; } bytepool_t;
typedef struct { u64 po_off, am_off, sp_off, ns_off, nslen, nin; } tapagg_t;
typedef struct {
    u64 tx_index;
    u32 local_idx;
    const u8* tx_ptr; u64 tx_len;
    const u8* outpoint;
    const u8* scriptSig; u32 scriptSiglen;
    const u8** wit; u32* witlen; u32 nwit; u32 wit_off;
    const u8* wprog; u32 wproglen; u8 wrapped;
    u32 wprog_off;
    u64 value;
    u64 spk_off; u32 spklen;
    u64 tap_desc;
    u8  shape;
} txvb_in_t;
typedef void (*tapin_fn)(void* ctx, u64 k, const u8** outpoint, u64* value,
                         const u8** spk, u32* spklen);

extern int  txv_test_verify_one(const u8* tx, u64 txlen, txvb_in_t* in,
                                unsigned long long flags, u8* work, unsigned long workcap,
                                const bytepool_t* spk_pool, const bytepool_t* tap_pool,
                                const tapagg_t* tapdesc, const char** reason);
extern long txvb_verify_one_asm(const u8* tx, u64 txlen, txvb_in_t* in,
                                u64 flags, u8* work, u64 workcap,
                                const bytepool_t* spk_pool, const bytepool_t* tap_pool,
                                const tapagg_t* tapdesc, const char** reason);
extern const u8* legacy_tx_view_asm(const u8* tx, u64 txlen, u64* out_len);
extern long strip_witness(const u8* tx, int64_t txlen, u8* out, long cap);
extern int  txv_test_tapagg_build(bytepool_t*, tapagg_t*, tapin_fn, void*,
                                  u64, const u8*, u64, const char**);
extern void sha256_full(u8 out[32], const void* in, int64_t len);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk,
                                    unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr, "unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static long fails = 0, compared = 0;
static void ckd(const char* what, int cond){
    compared++;
    if (!cond){ if (fails < 30) printf("FAIL %s\n", what); fails++; }
}

#define FLAGS ((1ULL<<11)|(1ULL<<17)|(1ULL<<0))   /* WITNESS|TAPROOT|P2SH */

/* one shared read-only spk pool; dispatch never writes it */
static bytepool_t spkp;
static u64 put_spk(const u8* s, u32 n){
    u64 off = spkp.used;
    memcpy(spkp.buf + off, s, n); spkp.used += n;
    return off;
}

static u8 workc[1<<20], worka[1<<20];

static void diff_case(const char* nm, const u8* tx, u64 txlen, txvb_in_t* in,
                      const bytepool_t* tapp, const tapagg_t* td){
    txvb_in_t ic = *in, ia = *in;
    const char *rc_ = "", *ra_ = "";
    int  c = txv_test_verify_one(tx, txlen, &ic, FLAGS, workc, sizeof workc, &spkp, tapp, td, &rc_);
    long a = txvb_verify_one_asm(tx, txlen, &ia, FLAGS, worka, sizeof worka, &spkp, tapp, td, &ra_);
    compared++;
    if (c != (int)a){ if (fails < 30) printf("FAIL %s: rc %d vs %ld\n", nm, c, a); fails++; return; }
    if (!c && strcmp(rc_, ra_)){ if (fails < 30) printf("FAIL %s: reason '%s' vs '%s'\n", nm, rc_, ra_); fails++; }
}

/* minimal legacy tx (1-in/1-out) and a segwit-marked variant of it */
static u64 mk_plain(u8* o){
    u64 n = 0;
    o[n++]=1;o[n++]=0;o[n++]=0;o[n++]=0;
    o[n++]=1; for (int k=0;k<36;k++) o[n++]=(u8)k;
    o[n++]=0; o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;
    o[n++]=1; for (int k=0;k<8;k++) o[n++]=0; o[n++]=1; o[n++]=0x51;
    o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=0;
    return n;
}
static u64 mk_segwit(u8* o){
    u64 n = 0;
    o[n++]=1;o[n++]=0;o[n++]=0;o[n++]=0; o[n++]=0x00; o[n++]=0x01;
    o[n++]=1; for (int k=0;k<36;k++) o[n++]=(u8)k;
    o[n++]=0; o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;
    o[n++]=1; for (int k=0;k<8;k++) o[n++]=0; o[n++]=1; o[n++]=0x51;
    o[n++]=1; o[n++]=1; o[n++]=0xaa;                     /* one witness item */
    o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=0;
    return n;
}

typedef struct { u8 op[36]; u64 v; u8 spk[64]; u32 sl; } inrec_t;
static void get_in(void* ctxv, u64 k, const u8** op, u64* v, const u8** spk, u32* sl){
    inrec_t* r = &((inrec_t*)ctxv)[k];
    *op = r->op; *v = r->v; *spk = r->spk; *sl = r->sl;
}

int main(void){
    spkp.buf = malloc(1<<16); spkp.cap = 1<<16; spkp.used = 0;
    static u8 txp[256], txs[256], stripped_ref[256];
    u64 np = mk_plain(txp), ns = mk_segwit(txs);

    /* ---- legacy_tx_view direct comparison ---- */
    {
        u64 la = 0;
        const u8* va = legacy_tx_view_asm(txp, np, &la);
        ckd("view: plain tx returned unchanged", va == txp && la == np);
        long want = strip_witness(txs, (int64_t)ns, stripped_ref, sizeof stripped_ref);
        va = legacy_tx_view_asm(txs, ns, &la);
        ckd("view: segwit tx stripped to the reference bytes",
            want > 0 && (long)la == want && va != txs && memcmp(va, stripped_ref, (size_t)want) == 0);
        ckd("view: tiny buffer returns input", legacy_tx_view_asm(txp, 5, &la) == txp && la == 5);
    }

    /* ---- LEGACY shape: accept and reject, plain and segwit-marked ---- */
    {
        static u8 spk_true[1] = {0x51}, spk_false[1] = {0x00};
        txvb_in_t in; memset(&in, 0, sizeof in);
        in.scriptSig = txp; in.scriptSiglen = 0;   /* empty scriptSig */
        in.shape = 0; in.spklen = 1;
        in.spk_off = put_spk(spk_true, 1);
        diff_case("legacy accept / plain", txp, np, &in, 0, 0);
        diff_case("legacy accept / segwit-marked", txs, ns, &in, 0, 0);
        in.spk_off = put_spk(spk_false, 1);
        diff_case("legacy reject / plain", txp, np, &in, 0, 0);
        diff_case("legacy reject / segwit-marked", txs, ns, &in, 0, 0);
    }

    /* ---- WV0: p2wsh accept + rejects, both wprog resolutions ---- */
    {
        static u8 wscript[1] = {0x51};
        static u8 prog[32]; sha256_full(prog, wscript, 1);
        const u8* items[2] = { wscript, 0 };
        u32 lens[2] = { 1, 0 };
        txvb_in_t in; memset(&in, 0, sizeof in);
        in.shape = 4; in.wproglen = 32; in.nwit = 1;
        in.wit = items; in.witlen = lens;
        /* wrapped-style: wprog is a direct pointer */
        in.wprog = prog; in.wrapped = 1;
        diff_case("p2wsh accept / wrapped ptr", txp, np, &in, 0, 0);
        /* native-style: program lives inside the spk copy, offset resolution */
        u8 spk34[34]; spk34[0]=0x00; spk34[1]=0x20; memcpy(spk34+2, prog, 32);
        in.wprog = 0; in.wprog_off = 2; in.wrapped = 0;
        in.spklen = 34; in.spk_off = put_spk(spk34, 34);
        diff_case("p2wsh accept / native offset", txp, np, &in, 0, 0);
        /* hash mismatch -> p2wsh reject reason */
        spk34[2] ^= 1;
        in.spk_off = put_spk(spk34, 34);
        diff_case("p2wsh hash-mismatch reject", txp, np, &in, 0, 0);
        /* p2wpkh with garbage witness -> its own reason */
        static u8 sig[72], pub[33];
        memset(sig, 0x30, sizeof sig); memset(pub, 0x02, sizeof pub);
        const u8* it2[2] = { sig, pub };
        u32 l2[2] = { 72, 33 };
        u8 prog20[20]; memset(prog20, 0x44, 20);
        in.wproglen = 20; in.nwit = 2; in.wit = it2; in.witlen = l2;
        in.wprog = prog20; in.wrapped = 1;
        diff_case("p2wpkh garbage-sig reject", txs, ns, &in, 0, 0);
    }

    /* ---- P2TR: not-built, then garbage shapes against a real descriptor ---- */
    {
        static inrec_t recs[2];
        for (int k=0;k<2;k++){
            memset(recs[k].op, 0x21+k, 36);
            recs[k].v = 7777+k; recs[k].sl = 34;
            recs[k].spk[0]=0x51; recs[k].spk[1]=0x20;
            for (int b=0;b<32;b++) recs[k].spk[2+b]=(u8)(b*3+k);
        }
        bytepool_t tapp; memset(&tapp, 0, sizeof tapp);
        tapagg_t td[1]; const char* r0="";
        int b = txv_test_tapagg_build(&tapp, &td[0], get_in, recs, 2, txs, ns, &r0);
        ckd("tap descriptor build for dispatch stage", b == 1);
        txvb_in_t in; memset(&in, 0, sizeof in);
        in.shape = 3; in.spklen = 34;
        in.spk_off = put_spk(recs[0].spk, 34);
        in.tap_desc = ~0ull;
        diff_case("p2tr descriptor-not-built", txs, ns, &in, &tapp, td);
        static u8 sig64[64]; memset(sig64, 0x5a, 64);
        const u8* w1[1] = { sig64 }; u32 wl1[1] = { 64 };
        in.tap_desc = 0; in.nwit = 1; in.wit = w1; in.witlen = wl1; in.local_idx = 0;
        diff_case("p2tr keypath garbage sig", txs, ns, &in, &tapp, td);
        in.local_idx = 1;
        diff_case("p2tr keypath garbage sig / input 1", txs, ns, &in, &tapp, td);
    }

    /* ---- WPASS ---- */
    {
        txvb_in_t in; memset(&in, 0, sizeof in);
        in.shape = 5;
        diff_case("wpass unconditional accept", txp, np, &in, 0, 0);
        in.shape = 9;                                 /* default arm */
        diff_case("unknown shape passes (default arm)", txp, np, &in, 0, 0);
    }

    printf("compared %ld dispatch cases; %ld mismatch(es)\n", compared, fails);
    printf("%s (%ld failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
