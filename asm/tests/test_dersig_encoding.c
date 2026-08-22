/* tests/test_dersig_encoding.c -- permanent regression for the BIP66/DERSIG
 * consensus gap: the strict signature-encoding rule script_flags_for_block()
 * computed and nothing on the block-connect path ever consulted.
 *
 * WHAT WAS BROKEN. script_flags_for_block() sets SCRIPT_VERIFY_DERSIG (bit 2)
 * for every block at height >= 363,725, exactly like Core's
 * GetBlockScriptFlags. The bit was threaded all the way into
 * script_state.flags and then read by nothing: every CHECKSIG/CHECKMULTISIG
 * went straight to der_parse_sig (bitcoin_script.asm), which is deliberately
 * TOLERANT of non-minimal DER at every height because pre-BIP66 mainnet
 * history needs it to be. Above the activation height this node therefore
 * ACCEPTED signatures Core REJECTS -- a chain split, and unlike LOG.md
 * incident #22 (a false REJECT) this one was a false ACCEPT.
 *
 * The same shape as #22, and the same reason the existing tests all passed:
 * tests/test_script_flags asks only what script_flags_for_block RETURNS.
 * Nothing asked whether the verifier then OBEYED the answer.
 *
 * WHY THE VECTORS LOOK LIKE THIS. There is no live symptom to reproduce:
 * Core-valid history after 363,725 contains only strict-DER signatures, so no
 * replay will ever reach the bug. The trigger has to be constructed. Each
 * post-BIP66 fixture is therefore a REAL mainnet transaction plus a variant
 * with ONE redundant leading 0x00 byte prepended to the R value of one
 * signature. That padding changes neither R's numeric value nor any sighash
 * preimage (the legacy sighash substitutes the scriptCode for the spending
 * input's scriptSig; BIP143 never hashes the witness), so the padded
 * signature still verifies cryptographically -- the ONLY thing wrong with it
 * is its encoding. Core confirms exactly that: it accepts the padded
 * transaction at a pre-BIP66 height and rejects it at a post-BIP66 one, which
 * is asserted in the generator and mirrored here.
 *
 * WHAT THIS DRIVES.
 *   - all three block-connect dispatch shapes: P2PKH (interp_checksig via
 *     sv_verify_script), P2SH multisig (interp_checkmultisig) and P2WPKH
 *     (interp_checksig under SIGVERSION_WITNESS_V0 via sv_verify_witness_v0);
 *   - through BOTH entry points, tx_verify_block_connect and
 *     tx_verify_block_connect_all -- incident #22 was present at both dispatch
 *     sites and a test covering one would have missed half of it;
 *   - in BOTH directions: reject at/above 363,725, accept below it, with the
 *     activation boundary pinned at the two real blocks 363,724 and 363,725;
 *   - two REAL pre-BIP66 mainnet transactions whose signatures are already
 *     non-strict (h149,850: R with a redundant leading zero; h152,841: R a
 *     negative DER INTEGER). They must still verify at their own heights.
 *     Those are the ~363,000 blocks of history a naive "just be strict" fix
 *     would have broken;
 *   - and a direct der_sig_strict() sweep against Core's own
 *     IsValidSignatureEncoding verdicts, one vector per clause.
 *
 * Fixtures baked by validation/fetch_dersig_vectors.py, every accept/reject
 * asserted against Bitcoin Core at generation time. Like
 * tests/test_taproot_exception_block.c this supplies its own utxo_lsm_get
 * instead of standing up an LSM, and chdir()s into a fresh temp directory, so
 * it never touches the working tree's shared index.dat/blk00000.dat.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "dersig_vec.h"

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

typedef struct { const u8* ptr; u64 len; u8 txid[32]; u32 pn_in; } block_tx_t;
extern int tx_verify_block_connect(const u8* tx, u64 txlen, long height, const u8 bh[32],
                                   void* lst, void* u, const char** reason);
extern int tx_verify_block_connect_all(const block_tx_t* txs, u64 ntx, long height,
                                       const u8 block_hash32[32], void* lst, void* u, void* bx,
                                       u64* fail_tx_index, const char** reason);
extern int der_sig_strict(const u8* sig, unsigned long siglen);

/* ---------------- prevout table + the store the verifier resolves against --- */
typedef struct { u8 key[36]; u64 value; u32 spklen; u8 spk[256]; } prev_t;
static prev_t g_prev[16];
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
static void seed(const dersig_prevout_t* p, unsigned n){
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
 * given height/hash. want==1 accept, want==0 reject. */
static void drive_both(const char* label, const u8* tx, u64 txlen, const u8* cb, u64 cblen,
                       long height, const u8 bh[32], int want){
    char nm[256], det[320];

    const char* reason = "(unset)";
    int r1 = tx_verify_block_connect(tx, txlen, height, bh, NULL, NULL, &reason);
    snprintf(nm, sizeof nm, "%s -- tx_verify_block_connect %s", label, want?"ACCEPTS":"REJECTS");
    snprintf(det, sizeof det, "r=%d reason=\"%s\"", r1, r1?"(accepted)":reason);
    ck(nm, r1==want, det);

    block_tx_t txs[2];
    txs[0].ptr = cb; txs[0].len = cblen; txs[0].pn_in = tx_nin(cb); memset(txs[0].txid, 0, 32);
    txs[1].ptr = tx; txs[1].len = txlen; txs[1].pn_in = tx_nin(tx); memset(txs[1].txid, 0, 32);
    u64 fail_tx = ~0ull; const char* reason2 = "(unset)";
    int r2 = tx_verify_block_connect_all(txs, 2, height, bh, NULL, NULL, NULL, &fail_tx, &reason2);
    snprintf(nm, sizeof nm, "%s -- tx_verify_block_connect_all %s", label, want?"ACCEPTS":"REJECTS");
    snprintf(det, sizeof det, "r=%d tx=%llu reason=\"%s\"", r2,
             (unsigned long long)fail_tx, r2?"(accepted)":reason2);
    ck(nm, r2==want, det);
    if (!want && r2==0){
        snprintf(nm, sizeof nm, "%s -- ... and it is tx 1 that fails", label);
        snprintf(det, sizeof det, "tx %llu", (unsigned long long)fail_tx);
        ck(nm, fail_tx==1, det);
    }
}

/* One fixture: original + (optionally) R-padded transaction, its block, and
 * the coinbase tx_verify_block_connect_all requires at index 0. */
typedef struct {
    const char* name;
    long height; const char* blockhash;
    const char* tx_hex; const char* pad_hex; const char* cb_hex;
    const dersig_prevout_t* prevs; unsigned nprev;
} fixture_t;

static u8 g_tx[8192], g_pad[8192], g_cb[8192];
static u64 g_txl, g_padl, g_cbl;
static u8  g_bh[32];

static void load(const fixture_t* f){
    g_nprev = 0;
    seed(f->prevs, f->nprev);
    g_txl = (u64)hx(f->tx_hex, g_tx, (long)sizeof g_tx);
    g_cbl = (u64)hx(f->cb_hex, g_cb, (long)sizeof g_cb);
    g_padl = f->pad_hex ? (u64)hx(f->pad_hex, g_pad, (long)sizeof g_pad) : 0;
    hash_from_rpc(f->blockhash, g_bh);
}

int main(void){
    /* never write into the working tree (shared index.dat/blk00000.dat) */
    char tmpl[]="/tmp/dersigXXXXXX"; char* d=mkdtemp(tmpl);
    if(!d || chdir(d)){ perror("tmpdir"); return 1; }

    printf("BIP66/DERSIG: strict signature encoding, computed and never consulted\n");
    printf("  activation height %ld (Core CMainParams BIP66Height)\n\n", DERSIG_ACTIVATION_HEIGHT);

    /* ---------------------------------------------------------------- 1 */
    printf("-- der_sig_strict() vs Core's IsValidSignatureEncoding --\n");
    for (int i=0;i<DSENC_N;i++){
        u8 s[128]; long n = hx(DSENC[i].sig_hex, s, (long)sizeof s);
        int got = der_sig_strict(s, (unsigned long)n);
        char nm[256], det[64];
        snprintf(nm, sizeof nm, "%s -> %s", DSENC[i].name, DSENC[i].core_ok?"valid":"invalid");
        snprintf(det, sizeof det, "der_sig_strict=%d", got);
        ck(nm, got == DSENC[i].core_ok, det);
    }

    static const fixture_t LEG = { "P2PKH", DSLEG_HEIGHT, DSLEG_BLOCKHASH_RPC,
        DSLEG_TX_HEX, DSLEG_PAD_HEX, DSLEG_COINBASE_HEX, DSLEG_PREVS, DSLEG_NPREV };
    static const fixture_t MS  = { "P2SH multisig", DSMS_HEIGHT, DSMS_BLOCKHASH_RPC,
        DSMS_TX_HEX, DSMS_PAD_HEX, DSMS_COINBASE_HEX, DSMS_PREVS, DSMS_NPREV };
    static const fixture_t W0  = { "P2WPKH", DSW0_HEIGHT, DSW0_BLOCKHASH_RPC,
        DSW0_TX_HEX, DSW0_PAD_HEX, DSW0_COINBASE_HEX, DSW0_PREVS, DSW0_NPREV };
    static const fixture_t PRE0 = { "h149850", DSPRE0_HEIGHT, DSPRE0_BLOCKHASH_RPC,
        DSPRE0_TX_HEX, NULL, DSPRE0_COINBASE_HEX, DSPRE0_PREVS, DSPRE0_NPREV };
    static const fixture_t PRE1 = { "h152841", DSPRE1_HEIGHT, DSPRE1_BLOCKHASH_RPC,
        DSPRE1_TX_HEX, NULL, DSPRE1_COINBASE_HEX, DSPRE1_PREVS, DSPRE1_NPREV };

    /* ---------------------------------------------------------------- 2 */
    printf("\n-- post-BIP66: an R-padded signature must be REJECTED, at every shape --\n");
    const fixture_t* post[3] = { &LEG, &MS, &W0 };
    for (int i=0;i<3;i++){
        const fixture_t* f = post[i];
        char lbl[128];
        load(f);
        snprintf(lbl, sizeof lbl, "%s h%ld, real transaction", f->name, f->height);
        drive_both(lbl, g_tx, g_txl, g_cb, g_cbl, f->height, g_bh, 1);
        snprintf(lbl, sizeof lbl, "%s h%ld, R-padded signature", f->name, f->height);
        drive_both(lbl, g_pad, g_padl, g_cb, g_cbl, f->height, g_bh, 0);
    }

    /* ---------------------------------------------------------------- 3 */
    printf("\n-- pre-BIP66: the SAME padded bytes must be ACCEPTED (the gate) --\n");
    /* If this half is missing, "always be strict" passes section 2 and breaks
     * every block below the activation height -- the false-reject failure mode
     * incident #22 actually shipped. The block hash is a real mainnet one. */
    {
        u8 pbh[32]; hash_from_rpc(DSPRE_BLOCKHASH_RPC, pbh);
        load(&LEG);
        drive_both("P2PKH R-padded, re-hosted at a real pre-BIP66 block",
                   g_pad, g_padl, g_cb, g_cbl, DSPRE_HEIGHT, pbh, 1);
        drive_both("P2PKH unmodified, re-hosted at the same pre-BIP66 block",
                   g_tx, g_txl, g_cb, g_cbl, DSPRE_HEIGHT, pbh, 1);
        load(&MS);
        drive_both("P2SH multisig R-padded, re-hosted pre-BIP66",
                   g_pad, g_padl, g_cb, g_cbl, DSPRE_HEIGHT, pbh, 1);
    }

    /* ---------------------------------------------------------------- 4 */
    printf("\n-- the activation boundary itself, at the two real blocks --\n");
    {
        u8 off[32], on[32];
        hash_from_rpc(DSBOUND_OFF_BLOCKHASH_RPC, off);
        hash_from_rpc(DSBOUND_ON_BLOCKHASH_RPC, on);
        load(&LEG);
        drive_both("P2PKH R-padded at height 363724 (one below activation)",
                   g_pad, g_padl, g_cb, g_cbl, DSBOUND_OFF_HEIGHT, off, 1);
        drive_both("P2PKH R-padded at height 363725 (activation)",
                   g_pad, g_padl, g_cb, g_cbl, DSBOUND_ON_HEIGHT, on, 0);
    }

    /* ---------------------------------------------------------------- 5 */
    printf("\n-- real pre-BIP66 mainnet history must still verify --\n");
    {
        const fixture_t* pre[2] = { &PRE0, &PRE1 };
        u8 modern[32]; hash_from_rpc(DSLEG_BLOCKHASH_RPC, modern);
        for (int i=0;i<2;i++){
            const fixture_t* f = pre[i];
            char lbl[160];
            load(f);
            snprintf(lbl, sizeof lbl, "REAL non-strict mainnet tx %s at its own block", f->name);
            drive_both(lbl, g_tx, g_txl, g_cb, g_cbl, f->height, g_bh, 1);
            /* ... and it really is non-strict: move it above the activation
             * height and the very same bytes must now be rejected. */
            snprintf(lbl, sizeof lbl, "the same tx %s re-hosted at h%ld", f->name, DSLEG_HEIGHT);
            drive_both(lbl, g_tx, g_txl, g_cb, g_cbl, DSLEG_HEIGHT, modern, 0);
        }
    }

    printf("\n%s (%d/%d)\n", fails?"TESTS FAILED":"ALL PASS", checks-fails, checks);
    return fails?1:0;
}
