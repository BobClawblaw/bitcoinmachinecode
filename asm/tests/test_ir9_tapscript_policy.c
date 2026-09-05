/* tests/test_ir9_tapscript_policy.c -- IR-9 (INTERP_REVIEW_2026-09-05):
 * mempool policy flags must reach a TAPSCRIPT leaf.
 *
 * taproot_verify_input hard-coded st.flags = CLTV|CSV and tx_verify.c's
 * TXV_SHAPE_P2TR arm did not forward `flags` (the WV0 and LEGACY arms do), so
 * TXV_MEMPOOL_POLICY_FLAGS never reached script_eval for a tapscript leaf:
 * MINIMALDATA and DISCOURAGE_OP_SUCCESS were dead for mempool tapscript,
 * although tx_verify.c documented bitcoin_interp.asm:457 as the enforcement
 * site (SCR-9's closure -- this is a defect in that closure).
 *
 * Driven end to end through tx_verify_mempool vs tx_verify_at_height with a
 * real script-path spend (leaf hash, merkle root, tweak, parity-correct
 * control block), no signatures needed:
 *
 *   leaf A : 0x01 0x01 OP_DROP OP_1   non-minimal push of 1 -> MINIMALDATA
 *   leaf B : OP_SUCCESS80 (0x50)      -> DISCOURAGE_OP_SUCCESS
 *
 * Both are consensus-VALID (block path must accept), both are non-standard
 * (mempool path must reject), and -acceptnonstdtxn restores acceptance.
 * Watched to FAIL against the unfixed tree: the mempool ACCEPTED both. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
typedef unsigned char u8; typedef unsigned long long u64; typedef unsigned int u32;

typedef int (*rf_t)(void*, const u8[36], u32, u64*, u64*, u64*, const u8**, unsigned long*);
extern int  tx_verify_at_height(const u8*, u64, long, rf_t, void*, const char**);
extern int  tx_verify_mempool(const u8*, u64, long, rf_t, void*, const char**);
extern void txv_set_mempool_standard(int on);
extern int  tx_dispatch_init(void);
extern void scalar_to_pubkey(u8 out33[33], const u8 priv[32]);
extern int  tap_leaf_hash(u8 out[32], u32 leafver, const u8* script, u64 slen);
extern int  tap_merkle_root(u8 out[32], const u8* leaf, u32 have, const u8* control, u64 clen);
extern long taproot_tweak_pubkey(u8* out_x, const u8* internal_x, const u8* merkle_root);

static int fails = 0, checks = 0;
static void ck(const char* label, int cond, const char* reason){
    checks++;
    if (cond) printf("ok  : %s\n", label);
    else { printf("FAIL: %s  (reason: %s)\n", label, reason ? reason : ""); fails++; }
}

/* the P2TR prevout the resolver hands back */
static u8 g_spk[34];
static int resolve_p2tr(void* ctx, const u8 outpoint[36], u32 index, u64* value, u64* height,
                        u64* is_cb, const u8** spk, unsigned long* spklen){
    (void)ctx; (void)outpoint; (void)index;
    *value = 100000; *height = 800000; *is_cb = 0; *spk = g_spk; *spklen = 34; return 1;
}

/* segwit tx: 1 input spending the P2TR prevout, 1 OP_1 output, witness [leaf, ctrl] */
static u64 build_tx(u8* o, const u8* leaf, u32 leaflen, const u8 ctrl[33]){
    u8* p = o;
    *p++=2; *p++=0; *p++=0; *p++=0;            /* version 2 */
    *p++=0x00; *p++=0x01;                      /* segwit marker+flag */
    *p++=1;                                    /* 1 input */
    memset(p, 0x42, 32); p += 32; *p++=0; *p++=0; *p++=0; *p++=0;   /* outpoint */
    *p++=0;                                    /* empty scriptSig */
    *p++=0xff; *p++=0xff; *p++=0xff; *p++=0xff;
    *p++=1;                                    /* 1 output */
    u64 v = 90000; memcpy(p, &v, 8); p += 8;
    *p++=1; *p++=0x51;                         /* OP_1 */
    *p++=2;                                    /* witness: 2 items */
    *p++=(u8)leaflen; memcpy(p, leaf, leaflen); p += leaflen;
    *p++=33; memcpy(p, ctrl, 33); p += 33;
    *p++=0; *p++=0; *p++=0; *p++=0;            /* locktime */
    return (u64)(p - o);
}

static void run_leaf(const char* nm, const u8* leaf, u32 leaflen, const u8* ipk,
                     const char* want_mempool_reason){
    u8 ctrl[33]; ctrl[0] = 0xc0; memcpy(ctrl+1, ipk, 32);
    u8 lh[32], mr[32], q[32]; long tw;
    if (tap_leaf_hash(lh, 0xc0, leaf, leaflen) != 1 || tap_merkle_root(mr, lh, 1, ctrl, 33) != 1 ||
        (tw = taproot_tweak_pubkey(q, ipk, mr)) < 1){ printf("FAIL: %s fixture\n", nm); fails++; return; }
    ctrl[0] = 0xc0 | (tw == 2);                /* BIP341 parity bit */
    g_spk[0]=0x51; g_spk[1]=0x20; memcpy(g_spk+2, q, 32);
    static u8 tx[512]; u64 tl = build_tx(tx, leaf, leaflen, ctrl);
    const char* r = ""; char lbl[160];

    r = ""; int cons = tx_verify_at_height(tx, tl, 900000, resolve_p2tr, NULL, &r);
    snprintf(lbl, sizeof lbl, "%s: consensus (block flags) ACCEPTS", nm);  ck(lbl, cons == 1, r);

    txv_set_mempool_standard(1);
    r = ""; int mp = tx_verify_mempool(tx, tl, 900000, resolve_p2tr, NULL, &r);
    snprintf(lbl, sizeof lbl, "%s: mempool (standard flags) REJECTS", nm);  ck(lbl, mp == 0, r);
    if (mp == 0 && want_mempool_reason){
        snprintf(lbl, sizeof lbl, "%s: mempool reason is '%s'", nm, want_mempool_reason);
        ck(lbl, r && strstr(r, want_mempool_reason) != NULL, r);
    }

    txv_set_mempool_standard(0);               /* -acceptnonstdtxn */
    r = ""; int ns = tx_verify_mempool(tx, tl, 900000, resolve_p2tr, NULL, &r);
    snprintf(lbl, sizeof lbl, "%s: mempool with acceptnonstdtxn ACCEPTS", nm);  ck(lbl, ns == 1, r);
    txv_set_mempool_standard(1);
}

int main(void){
    tx_dispatch_init();
    static u8 priv[32]; for (int i = 0; i < 32; i++) priv[i] = (u8)(i + 11);
    static u8 pub33[33]; scalar_to_pubkey(pub33, priv);
    const u8* ipk = pub33 + 1;

    static const u8 leafA[4] = { 0x01, 0x01, 0x75, 0x51 };   /* non-minimal push, DROP, OP_1 */
    static const u8 leafB[1] = { 0x50 };                     /* OP_SUCCESS80 */
    run_leaf("IR-9 leaf A (non-minimal push)", leafA, 4, ipk, NULL);
    run_leaf("IR-9 leaf B (OP_SUCCESSx)",      leafB, 1, ipk, "OP_SUCCESSx discouraged");

    /* control: a MINIMAL leaf is accepted everywhere (proves the policy path
     * does not simply reject every tapscript) */
    static const u8 leafC[1] = { 0x51 };
    {
        u8 ctrl[33]; ctrl[0]=0xc0; memcpy(ctrl+1, ipk, 32);
        u8 lh[32], mr[32], q[32]; long tw;
        if (tap_leaf_hash(lh, 0xc0, leafC, 1)==1 && tap_merkle_root(mr, lh, 1, ctrl, 33)==1 && (tw=taproot_tweak_pubkey(q, ipk, mr))>=1){
            ctrl[0] = 0xc0 | (tw == 2);
            g_spk[0]=0x51; g_spk[1]=0x20; memcpy(g_spk+2, q, 32);
            static u8 tx[512]; u64 tl = build_tx(tx, leafC, 1, ctrl);
            const char* r = "";
            ck("control: minimal OP_1 leaf, consensus accepts", tx_verify_at_height(tx, tl, 900000, resolve_p2tr, NULL, &r)==1, r);
            r = ""; ck("control: minimal OP_1 leaf, mempool accepts", tx_verify_mempool(tx, tl, 900000, resolve_p2tr, NULL, &r)==1, r);
        } else { printf("FAIL: control fixture\n"); fails++; }
    }
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
