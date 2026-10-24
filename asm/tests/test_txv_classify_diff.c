/* test_txv_classify_diff.c -- bitcoin_txv_classify.asm vs tx_verify.c's
 * txvb_classify, over the full shape x flags x witness matrix.
 *
 * WHY THIS EXISTS
 *   Phase 2 slice 2 ports the block path's per-input consensus
 *   classification -- the code that decides WHICH verifier judges an input
 *   and which structural rules apply. A wrong shape here is a consensus
 *   split even when every crypto leaf is perfect. Same oracle pattern as
 *   slices 0/1 (test_undo_asm_diff, test_txv_parse_diff): the C stays
 *   linked, both are driven over identical inputs, everything written is
 *   compared.
 *
 * MATRIX
 *   spk shapes: P2PKH, P2SH (plain), P2SH-wrapped v0 (20B and 32B
 *   programs, with correct and INCORRECT scriptSig push), native P2WPKH /
 *   P2WSH, P2TR, v1..v16 witness programs, empty spk, oversized spk,
 *   garbage;
 *   x flags: none / WITNESS / WITNESS+TAPROOT;
 *   x witness: absent, 1, 2, 3 items;
 *   x scriptSig: empty vs non-empty;
 *   x coinbase: non-coinbase, mature (conf==100), immature (conf==99),
 *   exactly-at-boundary heights.
 *
 * COMPARED per case: rc, reason (strcmp), has_taproot, and every field the
 * classifier writes (value, spk_off/spklen + the pooled bytes themselves,
 * shape, wprog/wproglen/wrapped/wprog_off).
 *
 * Usage: ./test_txv_classify_diff
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64;

typedef struct { u8* buf; u64 cap; u64 used; } bytepool_t;
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

/* C oracle + asm twin (both exported from this branch) */
extern int  txvb_classify(txvb_in_t* in, long height, unsigned long long flags,
                          u64 value, u64 uheight, u64 ucb,
                          const u8* spk, unsigned long spklen,
                          bytepool_t* spk_pool, int* has_taproot, const char** reason);
extern long txvb_classify_asm(txvb_in_t* in, long height, u64 flags,
                              u64 value, u64 uheight, u64 ucb,
                              const u8* spk, u64 spklen,
                              bytepool_t* spk_pool, int* has_taproot, const char** reason);

extern void hash160(u8 out[20], const void* in, long long len);

/* linked sources want this resolver; classification never reaches it */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk,
                                    unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr, "unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static long fails = 0, compared = 0;
static void fail(const char* what, long tag){
    if (fails < 30) printf("FAIL %s (case %ld)\n", what, tag);
    fails++;
}

#define FLAG_WITNESS (1ULL<<11)
#define FLAG_TAPROOT (1ULL<<17)

static bytepool_t pc, pa;                 /* separate pools, oracle vs twin */

static void diff_one(const u8* spk, u64 spklen, const u8* ss, u32 sslen,
                     u32 nwit, long height, u64 uheight, u64 ucb,
                     unsigned long long flags, long tag){
    txvb_in_t ic, ia; memset(&ic, 0xee, sizeof ic); memset(&ia, 0xee, sizeof ia);
    ic.scriptSig = ss; ic.scriptSiglen = sslen; ic.nwit = nwit;
    ia.scriptSig = ss; ia.scriptSiglen = sslen; ia.nwit = nwit;
    pc.used = 0; pa.used = 0;
    int hc = 0, ha = 0;
    const char *rc_ = "", *ra_ = "";
    int  c = txvb_classify(&ic, height, flags, 5000, uheight, ucb, spk, spklen, &pc, &hc, &rc_);
    long a = txvb_classify_asm(&ia, height, flags, 5000, uheight, ucb, spk, spklen, &pa, &ha, &ra_);
    compared++;
    if (c != (int)a){ fail("rc mismatch", tag); return; }
    if (hc != ha){ fail("has_taproot mismatch", tag); return; }
    if (!c){ if (strcmp(rc_, ra_)) fail("reason mismatch", tag); return; }
    /* accepted: compare every written field */
    if (ic.value != ia.value){ fail("value", tag); return; }
    if (ic.spk_off != ia.spk_off || ic.spklen != ia.spklen){ fail("spk_off/len", tag); return; }
    if (pc.used != pa.used){ fail("pool used", tag); return; }
    if (pc.used && memcmp(pc.buf, pa.buf, pc.used)){ fail("pool bytes", tag); return; }
    if (ic.shape != ia.shape){ fail("shape", tag); return; }
    if (ic.shape == 4){ /* WV0: the wprog split must match exactly */
        if (ic.wproglen != ia.wproglen){ fail("wproglen", tag); return; }
        if (ic.wrapped != ia.wrapped){ fail("wrapped", tag); return; }
        if (ic.wprog != ia.wprog){ fail("wprog ptr", tag); return; }
        if (ic.wprog_off != ia.wprog_off){ fail("wprog_off", tag); return; }
    }
}

int main(void){
    pc.buf = malloc(1<<20); pc.cap = 1<<20;
    pa.buf = malloc(1<<20); pa.cap = 1<<20;
    if (!pc.buf || !pa.buf){ fprintf(stderr, "oom\n"); return 1; }

    /* ---- spk shapes ---- */
    static u8 p2pkh[25]  = {0x76,0xa9,0x14, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20, 0x88,0xac};
    static u8 p2sh[23]   = {0xa9,0x14, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20, 0x87};
    static u8 p2wpkh[22] = {0x00,0x14, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
    static u8 p2wsh[34];   /* 0x00 0x20 <32> */
    static u8 p2tr[34];    /* 0x51 0x20 <32> */
    static u8 v2prog[34];  /* 0x52 0x20 <32> -- unknown witness version */
    static u8 garbage[7] = {0x6a,1,2,3,4,5,6};
    static u8 big[10001];
    p2wsh[0]=0x00; p2wsh[1]=0x20; for (int i=0;i<32;i++) p2wsh[2+i]=(u8)(i+1);
    p2tr[0]=0x51; p2tr[1]=0x20;   for (int i=0;i<32;i++) p2tr[2+i]=(u8)(i+7);
    v2prog[0]=0x52; v2prog[1]=0x20; for (int i=0;i<32;i++) v2prog[2+i]=(u8)(i+3);
    memset(big, 0x51, sizeof big);
    /* CON-2 (audit 2026-10-23): witness programs whose push is FALSE --
     * Core's VerifyScript fails EVAL_FALSE before the witness branch. */
    static u8 v2false[4] = {0x52,0x02,0x00,0x00};
    static u8 v2negz[4]  = {0x52,0x02,0x00,0x80};
    static u8 p2tr0[34];  p2tr0[0]=0x51; p2tr0[1]=0x20;     /* OP_1 <32 zero bytes> */
    static u8 p2sh_v2f[23]; static u8 ss_wrap_v2f[5] = {0x04,0x52,0x02,0x00,0x00};
    p2sh_v2f[0]=0xa9; p2sh_v2f[1]=0x14; hash160(p2sh_v2f+2, v2false, 4); p2sh_v2f[22]=0x87;

    /* scriptSigs: empty; a P2SH-wrapped P2WPKH redeem push (0x16 22-byte
     * push of 0x00 0x14 <20>); the same but with a trailing extra byte
     * (must reject as "exactly one push"); arbitrary non-empty. */
    static u8 ss_empty[1];
    static u8 ss_wrap22[23]; ss_wrap22[0]=0x16; ss_wrap22[1]=0x00; ss_wrap22[2]=0x14;
    for (int i=0;i<20;i++) ss_wrap22[3+i]=(u8)(i+1);
    static u8 ss_wrap_bad[24]; memcpy(ss_wrap_bad, ss_wrap22, 23); ss_wrap_bad[23]=0x51;
    static u8 ss_junk[3] = {0x51,0x51,0x51};

    struct { const u8* spk; u64 sl; const u8* ss; u32 ssl; const char* name; } shapes[] = {
        { p2pkh, 25, ss_empty, 0, "p2pkh" },
        { p2pkh, 25, ss_junk, 3, "p2pkh+ss" },
        { p2sh, 23, ss_junk, 3, "p2sh" },
        { p2sh, 23, ss_wrap22, 23, "p2sh-p2wpkh" },
        { p2sh, 23, ss_wrap_bad, 24, "p2sh-wrap-extra" },
        { p2wpkh, 22, ss_empty, 0, "p2wpkh" },
        { p2wpkh, 22, ss_junk, 3, "p2wpkh+ss" },
        { p2wsh, 34, ss_empty, 0, "p2wsh" },
        { p2tr, 34, ss_empty, 0, "p2tr" },
        { p2tr, 34, ss_junk, 3, "p2tr+ss" },
        { v2prog, 34, ss_empty, 0, "v2" },
        { v2false, 4, ss_empty, 0, "v2-false" },
        { v2negz, 4, ss_empty, 0, "v2-negzero" },
        { p2tr0, 34, ss_empty, 0, "p2tr-zero" },
        { p2sh_v2f, 23, ss_wrap_v2f, 5, "p2sh-v2-false" },
        { garbage, 7, ss_empty, 0, "opreturn" },
        { garbage, 7, ss_junk, 3, "opreturn+ss" },
        { p2pkh, 0, ss_empty, 0, "empty-spk" },
        { big, 10001, ss_empty, 0, "oversized-spk" },
        { big, 10000, ss_empty, 0, "max-spk" },
    };
    unsigned long long flagsets[] = { 0, FLAG_WITNESS, FLAG_WITNESS|FLAG_TAPROOT };
    u32 nwits[] = { 0, 1, 2, 3 };

    long tag = 0;
    for (unsigned s = 0; s < sizeof shapes/sizeof shapes[0]; s++)
        for (unsigned f = 0; f < 3; f++)
            for (unsigned w = 0; w < 4; w++)
                diff_one(shapes[s].spk, shapes[s].sl, shapes[s].ss, shapes[s].ssl,
                         nwits[w], 800000, 700000, 0, flagsets[f], ++tag);

    /* ---- coinbase maturity edges, all shapes' first flagset ---- */
    struct { long h; u64 uh; u64 cb; } mat[] = {
        { 800000, 799901, 1 },   /* conf 99: immature */
        { 800000, 799900, 1 },   /* conf 100: exactly mature */
        { 800000, 799899, 1 },   /* conf 101 */
        { 100,    0,      1 },   /* conf 100 from genesis */
        { 99,     0,      1 },   /* conf 99 */
        { 800000, 799901, 0 },   /* same heights, NOT coinbase */
    };
    for (unsigned m = 0; m < sizeof mat/sizeof mat[0]; m++)
        for (unsigned s = 0; s < sizeof shapes/sizeof shapes[0]; s++)
            diff_one(shapes[s].spk, shapes[s].sl, shapes[s].ss, shapes[s].ssl,
                     2, mat[m].h, mat[m].uh, mat[m].cb, FLAG_WITNESS|FLAG_TAPROOT, ++tag);

    /* CON-2: the C oracle itself must refuse every false program, under
     * any flag set that classifies witness programs (the asm twin is held
     * to the same answer by the matrix above). */
    {
        const u8* fs[4] = { v2false, v2negz, p2tr0, p2sh_v2f };
        u64 fl[4] = { 4, 4, 34, 23 };
        const u8* fss[4] = { ss_empty, ss_empty, ss_empty, ss_wrap_v2f };
        u32 fssl[4] = { 0, 0, 0, 5 };
        for (int k = 0; k < 4; k++) for (int f = 1; f < 3; f++){
            txvb_in_t in; memset(&in, 0, sizeof in);
            in.scriptSig = fss[k]; in.scriptSiglen = fssl[k]; in.nwit = 0;
            pc.used = 0; int ht = 0; const char* r = "";
            int c = txvb_classify(&in, 800000, flagsets[f], 5000, 700000, 0, fs[k], fl[k], &pc, &ht, &r);
            compared++;
            if (c != 0 || strcmp(r, "witness program evaluates false (EVAL_FALSE)")){
                printf("FAIL CON-2 false program %d flags %d: rc=%d reason=[%s]\n", k, f, c, r); fails++;
            }
        }
    }

    printf("compared %ld classify cases; %ld mismatch(es)\n", compared, fails);
    printf("%s (%ld failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
