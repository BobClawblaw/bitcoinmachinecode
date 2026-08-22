/* tests/test_taproot_exception_block.c -- permanent regression for LOG.md
 * incident #22: taproot rules applied at the ONE block Core exempts by hash.
 *
 * WHAT BROKE. The live replay stopped dead at height 692,261 with
 * "REJECT h=692261 tx=193: p2tr empty witness". Transaction
 * b10c007c60e14f9d087e0291d4d0c7869697c6681d979c6639dbd960792b4d41 spends
 * four real witness_v1_taproot outputs carrying NO witness at all -- invalid
 * under the taproot rules, valid without them. Block 692,261's hash,
 * 0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad, is
 * exactly Core's Taproot `script_flag_exception` (kernel/chainparams.cpp):
 * GetBlockScriptFlags leaves P2SH|WITNESS|TAPROOT on for EVERY block and then
 * overrides THAT ONE HASH down to P2SH|WITNESS. Our script_flags_for_block()
 * computed that correctly the whole time; the two P2TR dispatch sites in
 * daemon/tx_verify.c ignored the flags they had already computed and applied
 * taproot rules unconditionally. A FALSE REJECT (0719525 gates both sites).
 *
 * WHY tests/test_script_flags DID NOT CATCH IT, and what this closes.
 * test_script_flags covers the flag SCHEDULE 13/13 -- including this very
 * exception and a near-miss hash that must NOT trigger it -- and it passed
 * throughout the bug, because it only ever asks "what does
 * script_flags_for_block RETURN". Nothing asked whether the verifier then
 * OBEYED the answer. The gap was between computing the flags and consulting
 * them, so the only test that can close it has to run the real transaction
 * through the real verification entry points and compare the verdict at the
 * exception hash against the verdict at a hash that is not the exception.
 *
 * WHAT THIS DRIVES. The real mainnet transaction, with its four real prevout
 * scriptPubKeys and amounts seeded, through BOTH block-connection entry
 * points -- tx_verify_block_connect (the per-transaction path) and
 * tx_verify_block_connect_all (the block-wide parallel path). The bug was
 * present at BOTH dispatch sites; a test hitting only one would have missed
 * half of it, and a later regression could come back in either.
 *
 *   [1,2] real exception hash, height 692261 -> ACCEPT.
 *   [3,4] block 692262's REAL hash, same height, same transaction -> REJECT
 *         with "p2tr empty witness". This is the half that proves the GATE,
 *         not merely that acceptance happens: if the gate were wired the
 *         wrong way round, or always off, this would accept too.
 *   [5,6] a NEAR-MISS hash (the exception hash with one byte flipped), same
 *         height -> REJECT. The override must key on the whole 32 bytes.
 *   [7,8] an ordinary post-activation P2TR key-path spend at its own real
 *         block -> ACCEPT, and
 *  [9,10] the same spend with one Schnorr signature byte flipped -> REJECT.
 *         Together these are what stops "make the gate always off" from
 *         passing this file: taproot really is enforced everywhere else.
 *
 * Fixtures are baked by validation/fetch_taproot_exception.py (small, so no
 * oracle is needed at test time). Like tests/test_txvb_wprog_stable.c this
 * supplies its own utxo_lsm_get instead of standing up an LSM, so the test
 * touches no files at all -- it also chdir()s into a fresh temp directory so
 * it can never write into the working tree's shared index.dat/blk00000.dat.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "taproot_exception_vec.h"

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

typedef struct { const u8* ptr; u64 len; u8 txid[32]; u32 pn_in; } block_tx_t;
extern int tx_verify_block_connect(const u8* tx, u64 txlen, long height, const u8 bh[32],
                                   void* lst, void* u, const char** reason);
extern int tx_verify_block_connect_all(const block_tx_t* txs, u64 ntx, long height,
                                       const u8 block_hash32[32], void* lst, void* u, void* bx,
                                       u64* fail_tx_index, const char** reason);

/* ---------------- prevout table + the store the verifier resolves against --- */
typedef struct { u8 key[36]; u64 value; u32 spklen; u8 spk[256]; } prev_t;
static prev_t g_prev[TAPEXC_NPREV + TAPNORM_NPREV];
static long   g_nprev;

long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index,
                  u64* value, u64* height, u64* coinbase,
                  const u8** spk, unsigned long* spklen){
    (void)lst; (void)u;
    static u8 scratch[256];
    u8 key[36]; memcpy(key, txid, 32); memcpy(key+32, &index, 4);
    for (long i=0;i<g_nprev;i++){
        if (memcmp(key, g_prev[i].key, 36) != 0) continue;
        memcpy(scratch, g_prev[i].spk, g_prev[i].spklen);
        *value = g_prev[i].value; *height = 1; *coinbase = 0;
        *spk = scratch; *spklen = g_prev[i].spklen;
        return 1;
    }
    return 0;
}
/* bx is always NULL below (no chained spends in these one-transaction blocks). */
long bidx_get(void* bx, u32 tx_index, const u8 txid[32], u32 index,
              u64* value, u64* height, u64* coinbase,
              const u8** spk, unsigned long* spklen){
    (void)bx;(void)tx_index;(void)txid;(void)index;(void)value;(void)height;(void)coinbase;
    (void)spk;(void)spklen; return -1;
}
/* bitcoin_txval_modern.c's mempool-path resolver -- never reached here. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk, unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr,"unexpected mempool_resolve_confirmed_utxo\n"); abort();
}

/* ------------------------------------------------------------------ helpers */
static int nib(int c){
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
}
static long hx(const char* h, u8* o, long cap){
    long n=0;
    for(; n<cap; h+=2, n++){ int a=nib(h[0]); if(a<0) break; int b=nib(h[1]); if(b<0) break;
                             o[n]=(u8)((a<<4)|b); }
    return n;
}
/* RPC/display hex -> this codebase's internal (wire) byte order. */
static void hash_from_rpc(const char* rpc_hex, u8 out[32]){
    u8 disp[32]; hx(rpc_hex, disp, 32);
    for (int i=0;i<32;i++) out[i] = disp[31-i];
}
static void seed(const tapexc_prevout_t* p, unsigned n){
    for (unsigned k=0;k<n;k++){
        prev_t* e = &g_prev[g_nprev++];
        u8 disp[32]; hx(p[k].txid_hex, disp, 32);
        for (int b=0;b<32;b++) e->key[b] = disp[31-b];        /* wire order */
        u32 idx = p[k].index; memcpy(e->key+32, &idx, 4);
        e->value = p[k].value;
        e->spklen = (u32)hx(p[k].spk_hex, e->spk, (long)sizeof e->spk);
    }
}
static u64 rd_cs(const u8** p){ u64 v=**p; (*p)++; if(v<0xfd) return v;
    if(v==0xfd){ v=(*p)[0]|((u64)(*p)[1]<<8); *p+=2; return v; }
    if(v==0xfe){ v=(*p)[0]|((u64)(*p)[1]<<8)|((u64)(*p)[2]<<16)|((u64)(*p)[3]<<24); *p+=4; return v; }
    v=0; for(int i=0;i<8;i++) v|=(u64)(*p)[i]<<(8*i); *p+=8; return v; }
static u32 tx_nin(const u8* p){
    p += 4; if (p[0]==0x00 && p[1]==0x01) p += 2;
    return (u32)rd_cs(&p);
}

static int fails=0, checks=0;
static void ck(const char* n, int cond, const char* detail){
    checks++; printf("%s %s\n", cond?"  ok  ":"  FAIL", n);
    if(!cond){ fails++; if(detail) printf("        got: %s\n", detail); }
}

/* Drive one transaction through BOTH block-connection entry points at the
 * given height/hash. want==1 accept, want==0 reject; want_reason (may be
 * NULL) must be the exact rejection reason from both paths. */
static void drive_both(const char* label, const u8* tx, u64 txlen, const u8* cb, u64 cblen,
                       long height, const u8 bh[32], int want, const char* want_reason){
    char nm[256], det[320];

    const char* reason = "(unset)";
    int r1 = tx_verify_block_connect(tx, txlen, height, bh, NULL, NULL, &reason);
    snprintf(nm, sizeof nm, "%s -- tx_verify_block_connect %s", label, want?"ACCEPTS":"REJECTS");
    snprintf(det, sizeof det, "r=%d reason=\"%s\"", r1, r1?"(accepted)":reason);
    ck(nm, r1==want, det);
    if (!want && want_reason && r1==0){
        snprintf(nm, sizeof nm, "%s -- ... with reason \"%s\"", label, want_reason);
        snprintf(det, sizeof det, "\"%s\"", reason);
        ck(nm, strcmp(reason, want_reason)==0, det);
    }

    block_tx_t txs[2];
    txs[0].ptr = cb; txs[0].len = cblen; txs[0].pn_in = tx_nin(cb); memset(txs[0].txid, 0, 32);
    txs[1].ptr = tx; txs[1].len = txlen; txs[1].pn_in = tx_nin(tx); memset(txs[1].txid, 0, 32);
    u64 fail_tx = ~0ull; const char* reason2 = "(unset)";
    int r2 = tx_verify_block_connect_all(txs, 2, height, bh, NULL, NULL, NULL, &fail_tx, &reason2);
    snprintf(nm, sizeof nm, "%s -- tx_verify_block_connect_all %s", label, want?"ACCEPTS":"REJECTS");
    snprintf(det, sizeof det, "r=%d tx=%llu reason=\"%s\"", r2,
             (unsigned long long)fail_tx, r2?"(accepted)":reason2);
    ck(nm, r2==want, det);
    if (!want && want_reason && r2==0){
        snprintf(nm, sizeof nm, "%s -- ... with reason \"%s\" at tx 1", label, want_reason);
        snprintf(det, sizeof det, "\"%s\" at tx %llu", reason2, (unsigned long long)fail_tx);
        ck(nm, strcmp(reason2, want_reason)==0 && fail_tx==1, det);
    }
}

static u8 g_exc_tx[4096], g_exc_cb[4096], g_norm_tx[4096], g_norm_cb[4096];

int main(void){
    /* never write into the working tree (shared index.dat/blk00000.dat) */
    char tmpl[]="/tmp/tapexcXXXXXX"; char* d=mkdtemp(tmpl);
    if(!d || chdir(d)){ perror("tmpdir"); return 1; }

    seed(TAPEXC_PREVS,  TAPEXC_NPREV);
    seed(TAPNORM_PREVS, TAPNORM_NPREV);

    u64 exc_len  = (u64)hx(TAPEXC_TX_HEX,        g_exc_tx,  (long)sizeof g_exc_tx);
    u64 exc_cbl  = (u64)hx(TAPEXC_COINBASE_HEX,  g_exc_cb,  (long)sizeof g_exc_cb);
    u64 norm_len = (u64)hx(TAPNORM_TX_HEX,       g_norm_tx, (long)sizeof g_norm_tx);
    u64 norm_cbl = (u64)hx(TAPNORM_COINBASE_HEX, g_norm_cb, (long)sizeof g_norm_cb);

    u8 bh_exc[32], bh_other[32], bh_near[32], bh_norm[32];
    hash_from_rpc(TAPEXC_BLOCKHASH_RPC,       bh_exc);
    hash_from_rpc(TAPEXC_OTHER_BLOCKHASH_RPC, bh_other);
    hash_from_rpc(TAPNORM_BLOCKHASH_RPC,      bh_norm);
    memcpy(bh_near, bh_exc, 32); bh_near[17] ^= 0x01;   /* one bit off the exception */

    printf("incident #22 regression: the taproot script_flag_exception block\n");
    printf("  height %ld, block %s\n", TAPEXC_HEIGHT, TAPEXC_BLOCKHASH_RPC);
    printf("  tx     %s (%llu B, %u taproot prevouts, no witness at all)\n\n",
           TAPEXC_TXID, (unsigned long long)exc_len, TAPEXC_NPREV);

    /* 1,2 -- Core's exception: taproot OFF for this one hash, so a witnessless
     * spend of four witness-v1 outputs is VALID. */
    drive_both("exception block (taproot overridden off)",
               g_exc_tx, exc_len, g_exc_cb, exc_cbl, TAPEXC_HEIGHT, bh_exc, 1, NULL);

    /* 3,4 -- the SAME transaction at the SAME height under a real, different
     * mainnet block hash: taproot is on, so this must be rejected. This is
     * what proves the gating rather than blanket acceptance. */
    drive_both("same tx, same height, block 692262's real hash",
               g_exc_tx, exc_len, g_exc_cb, exc_cbl, TAPEXC_HEIGHT, bh_other, 0,
               "p2tr empty witness");

    /* 5,6 -- near miss: the exception hash with a single bit flipped must not
     * trigger the override (the same property test_script_flags pins for the
     * flag word, now pinned for the VERDICT). */
    drive_both("same tx, exception hash with one bit flipped",
               g_exc_tx, exc_len, g_exc_cb, exc_cbl, TAPEXC_HEIGHT, bh_near, 0,
               "p2tr empty witness");

    /* 7,8 -- an ordinary key-path P2TR spend at an ordinary block still
     * verifies: the gate is not stuck off. */
    drive_both("ordinary P2TR key-path spend at its own block",
               g_norm_tx, norm_len, g_norm_cb, norm_cbl, TAPNORM_HEIGHT, bh_norm, 1, NULL);

    /* 9,10 -- ... and taproot signature checking is genuinely RUNNING there:
     * flip one Schnorr signature byte and it must reject. Without this a
     * "gate always off" regression would sail through 7,8. */
    g_norm_tx[TAPNORM_SIG_BYTE_OFF] ^= 0x01;
    drive_both("ordinary P2TR spend with one Schnorr byte flipped",
               g_norm_tx, norm_len, g_norm_cb, norm_cbl, TAPNORM_HEIGHT, bh_norm, 0, NULL);
    g_norm_tx[TAPNORM_SIG_BYTE_OFF] ^= 0x01;

    printf("\n%s (%d/%d)\n", fails?"TESTS FAILED":"ALL PASS", checks-fails, checks);
    return fails?1:0;
}
