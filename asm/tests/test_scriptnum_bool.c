/* tests/test_scriptnum_bool.c -- permanent regression for LOG.md incident #28:
 * the numeric opcodes' boolean results carried the OPERAND's upper bits.
 *
 * WHAT BROKE. The live replay stopped dead at height 792,980 with
 * "REJECT h=792980 tx=2941: p2wsh script verification failed". Transaction
 * c85311c12c70351948bf15c76963c9e5ae54831733bfa267692888b780a70876 is a P2WSH
 * 1-of-7 built out of CHECKSIG + OP_ADD rather than OP_CHECKMULTISIG: seven
 * OP_CHECKSIGs (six of them fed a deliberately EMPTY signature, one fed the
 * real one), their booleans summed with OP_ADD, and a tail of
 *
 *   OP_IF <400000> OP_CHECKLOCKTIMEVERIFY OP_0NOTEQUAL OP_ELSE OP_0 OP_ENDIF
 *   OP_ADD OP_2 OP_EQUAL
 *
 * 400000 is 0x061A80. bitcoin_interp.asm's `.mo6` computed OP_0NOTEQUAL as
 * `test r14,r14 / setnz r14b` with r14 STILL HOLDING THE OPERAND -- and SETcc
 * writes only the low 8 bits, so 0x061A80 came back as 0x061A01 = 400129
 * instead of 1. OP_ADD then gave 400130 and the OP_2 OP_EQUAL was false. The
 * script error was a plain SCRIPT_ERR_EVAL_FALSE: nothing aborted, the
 * arithmetic was simply wrong.
 *
 * The same shape was in ELEVEN handlers -- OP_NOT, OP_0NOTEQUAL, OP_BOOLAND,
 * OP_BOOLOR, OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN,
 * OP_GREATERTHAN, OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL -- wrong for every
 * operand of magnitude >= 256 and for every negative operand, right by
 * accident for 0..255. (OP_WITHIN writes SETcc the same way but ANDs against a
 * register it zeroed first, which masks the answer back to 0/1. Correct, but
 * only by construction, so it is swept here too.)
 *
 * WHY IT IS NOT ONLY A FALSE REJECT. The bug cuts both ways and the other way
 * is worse: `<256> OP_NOT` pushed 256, which is TRUE, where Core pushes 0; and
 * `<256> <512> OP_NUMEQUALVERIFY` left 256 on the stack, which OP_VERIFY
 * happily accepted, where Core fails the script. So this node would have
 * accepted scripts Core rejects -- a chain split with no symptom. Any fix that
 * merely makes block 792,980 pass leaves that half open, which is why the
 * sweep below is loaded in BOTH directions from Core's own verdicts.
 *
 * WHAT THIS DRIVES, at BOTH block-connection entry points -- the
 * per-transaction tx_verify_block_connect and the block-wide parallel
 * tx_verify_block_connect_all. Incident #22 was present at both dispatch
 * sites; a test covering one would have missed half of it.
 *
 *   [1,2]   the real mainnet transaction at its real height and block hash
 *           -> ACCEPT. This is the assertion the replay was stuck on.
 *   [3,4]   the same transaction with one byte of its ONE real signature
 *           flipped -> REJECT. Without this, "accept everything" would pass.
 *   [5..8]  a sweep of SNB_NVEC pure-arithmetic P2WSH scripts across the
 *           255/256 and 0/-1 boundaries, each carrying Bitcoin Core's own
 *           verdict, asserted in both directions at both entry points.
 *
 * Fixtures are baked by validation/fetch_scriptnum_bool.py, which asks Core
 * for every verdict before emitting it; the test itself needs no oracle. Like
 * tests/test_taproot_exception_block.c it supplies its own utxo_lsm_get rather
 * than standing up an LSM, and chdir()s into a fresh temp directory so it can
 * never write into the working tree.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "scriptnum_bool_vec.h"

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

typedef struct { const u8* ptr; u64 len; u8 txid[32]; u32 pn_in; } block_tx_t;
extern int tx_verify_block_connect(const u8* tx, u64 txlen, long height, const u8 bh[32],
                                   void* lst, void* u, const char** reason);
extern int tx_verify_block_connect_all(const block_tx_t* txs, u64 ntx, long height,
                                       const u8 block_hash32[32], void* lst, void* u, void* bx,
                                       u64* fail_tx_index, const char** reason);
extern void sha256_full(u8* out, const void* msg, int64_t len);

/* ------------- prevout table the verifier resolves against ---------------- */
typedef struct { u8 key[36]; u64 value; u32 spklen; u8 spk[256]; } prev_t;
static prev_t g_prev[2];        /* [0] the real prevout, [1] the synthetic one */
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
long bidx_get(void* bx, u32 tx_index, const u8 txid[32], u32 index,
              u64* value, u64* height, u64* coinbase,
              const u8** spk, unsigned long* spklen){
    (void)bx;(void)tx_index;(void)txid;(void)index;(void)value;(void)height;(void)coinbase;
    (void)spk;(void)spklen; return -1;
}
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
static void hash_from_rpc(const char* rpc_hex, u8 out[32]){
    u8 disp[32]; hx(rpc_hex, disp, 32);
    for (int i=0;i<32;i++) out[i] = disp[31-i];
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

static u8 g_cb[4096]; static u64 g_cblen;
static long g_height; static u8 g_bh[32];

/* One transaction through ONE entry point. which==0 tx_verify_block_connect,
 * which==1 tx_verify_block_connect_all (with the real coinbase as txs[0], as
 * that path requires). Returns 1 accept / 0 reject; *why gets the reason. */
static int drive(int which, const u8* tx, u64 txlen, const char** why){
    *why = "(unset)";
    if (which == 0)
        return tx_verify_block_connect(tx, txlen, g_height, g_bh, NULL, NULL, why);
    block_tx_t txs[2];
    txs[0].ptr = g_cb; txs[0].len = g_cblen; txs[0].pn_in = tx_nin(g_cb); memset(txs[0].txid,0,32);
    txs[1].ptr = tx;   txs[1].len = txlen;   txs[1].pn_in = tx_nin(tx);   memset(txs[1].txid,0,32);
    u64 fail_tx = ~0ull;
    return tx_verify_block_connect_all(txs, 2, g_height, g_bh, NULL, NULL, NULL, &fail_tx, why);
}
static const char* ENTRY[2] = { "tx_verify_block_connect", "tx_verify_block_connect_all" };

/* ---- the synthetic spending transaction the sweep vectors ride in.
 * Byte-for-byte what validation/fetch_scriptnum_bool.py's synth_tx() built
 * when it asked Core for each verdict; the SNB_SYNTH_* constants are emitted
 * into the header precisely so these two builders cannot drift. ---- */
static u8 g_synth[512]; static u8 g_synth_spk[34];
static u64 build_synth(const u8* script, u32 slen){
    u8 pt[32]; hx(SNB_SYNTH_PREV_TXID_HEX, pt, 32);
    u8 ospk[64]; long ospklen = hx(SNB_SYNTH_OUT_SPK_HEX, ospk, (long)sizeof ospk);
    g_synth_spk[0]=0x00; g_synth_spk[1]=0x20; sha256_full(g_synth_spk+2, script, (int64_t)slen);
    u8* p = g_synth;
    *p++=0x02; *p++=0x00; *p++=0x00; *p++=0x00;      /* version 2 */
    *p++=0x00; *p++=0x01;                            /* marker, flag */
    *p++=0x01; memcpy(p, pt, 32); p+=32;             /* 1 input */
    u32 n = SNB_SYNTH_PREV_N;   memcpy(p,&n,4); p+=4;
    *p++=0x00;                                       /* empty scriptSig */
    u32 sq = SNB_SYNTH_SEQ;     memcpy(p,&sq,4); p+=4;
    *p++=0x01;                                       /* 1 output */
    u64 ov = SNB_SYNTH_OUT_VALUE; memcpy(p,&ov,8); p+=8;
    *p++=(u8)ospklen; memcpy(p, ospk, (size_t)ospklen); p+=ospklen;
    *p++=0x01;                                       /* 1 witness item */
    if (slen < 0xfd) *p++=(u8)slen;
    else { *p++=0xfd; *p++=(u8)(slen&0xff); *p++=(u8)(slen>>8); }
    memcpy(p, script, slen); p+=slen;
    u32 lt = SNB_SYNTH_LOCKTIME; memcpy(p,&lt,4); p+=4;
    return (u64)(p - g_synth);
}

static u8 g_tx[4096];

int main(void){
    char tmpl[]="/tmp/snboolXXXXXX"; char* d=mkdtemp(tmpl);
    if(!d || chdir(d)){ perror("tmpdir"); return 1; }

    g_height = SNB_HEIGHT;
    hash_from_rpc(SNB_BLOCKHASH_RPC, g_bh);
    g_cblen = (u64)hx(SNB_COINBASE_HEX, g_cb, (long)sizeof g_cb);
    u64 txlen = (u64)hx(SNB_TX_HEX, g_tx, (long)sizeof g_tx);

    /* [0] the real prevout */
    { prev_t* e = &g_prev[g_nprev++];
      u8 disp[32]; hx(SNB_PREV_TXID, disp, 32);
      for (int b=0;b<32;b++) e->key[b] = disp[31-b];          /* wire order */
      u32 idx = SNB_PREV_N; memcpy(e->key+32, &idx, 4);
      e->value = SNB_PREV_VALUE;
      e->spklen = (u32)hx(SNB_PREV_SPK, e->spk, (long)sizeof e->spk); }
    /* [1] the synthetic prevout; its scriptPubKey is rewritten per vector */
    { prev_t* e = &g_prev[g_nprev++];
      hx(SNB_SYNTH_PREV_TXID_HEX, e->key, 32);                /* already wire order */
      u32 idx = SNB_SYNTH_PREV_N; memcpy(e->key+32, &idx, 4);
      e->value = SNB_SYNTH_VALUE; e->spklen = 34; }

    printf("incident #28 regression: SETcc left the operand's upper bits in the result\n");
    printf("  height %ld, block %s\n", (long)SNB_HEIGHT, SNB_BLOCKHASH_RPC);
    printf("  tx %d  %s\n", SNB_TX_INDEX, SNB_TXID);
    printf("  P2WSH 1-of-7 CHECKSIG+OP_ADD threshold, tail <400000> CLTV OP_0NOTEQUAL\n\n");

    char nm[256], det[320];

    /* [1,2] the real transaction must be ACCEPTED at both entry points. */
    for (int w=0; w<2; w++){
        const char* why;
        int r = drive(w, g_tx, txlen, &why);
        snprintf(nm,sizeof nm,"real block %ld tx %d -- %s ACCEPTS", (long)SNB_HEIGHT,
                 SNB_TX_INDEX, ENTRY[w]);
        snprintf(det,sizeof det,"r=%d reason=\"%s\"", r, r?"(accepted)":why);
        ck(nm, r==1, det);
    }
    /* [3,4] ... and signature checking is really RUNNING: flip one byte of the
     * one real signature and both paths must reject, with the exact reason
     * string the replay reported, so a regression is recognisable from the
     * log line alone. */
    for (int w=0; w<2; w++){
        g_tx[SNB_SIG_BYTE_OFF] ^= 0x01;
        const char* why;
        int r = drive(w, g_tx, txlen, &why);
        g_tx[SNB_SIG_BYTE_OFF] ^= 0x01;
        snprintf(nm,sizeof nm,"... one signature byte flipped -- %s REJECTS \"p2wsh script verification failed\"",
                 ENTRY[w]);
        snprintf(det,sizeof det,"r=%d reason=\"%s\"", r, r?"(accepted)":why);
        ck(nm, r==0 && strcmp(why, "p2wsh script verification failed")==0, det);
    }

    /* [5..8] the sweep, in both directions, at both entry points. */
    int naccept=0, nreject=0;
    for (int i=0;i<SNB_NVEC;i++){ if (SNB_VECS[i].core_ok) naccept++; else nreject++; }
    printf("\n  sweep: %d pure-arithmetic P2WSH scripts, %d Core ACCEPTS / %d Core REJECTS\n",
           SNB_NVEC, naccept, nreject);
    for (int w=0; w<2; w++){
        int bad_reject=0, bad_accept=0, shown=0;
        for (int i=0;i<SNB_NVEC;i++){
            u8 script[64];
            u32 slen = (u32)hx(SNB_VECS[i].script_hex, script, (long)sizeof script);
            u64 slen_tx = build_synth(script, slen);       /* also fills g_synth_spk */
            memcpy(g_prev[1].spk, g_synth_spk, 34);
            const char* why;
            int r = drive(w, g_synth, slen_tx, &why);
            if (r == SNB_VECS[i].core_ok) continue;
            if (SNB_VECS[i].core_ok) bad_reject++; else bad_accept++;
            if (shown++ < 12)
                printf("        %-34s %s : we %s, Core %s%s%s\n",
                       SNB_VECS[i].label, SNB_VECS[i].script_hex,
                       r?"ACCEPT":"REJECT", SNB_VECS[i].core_ok?"ACCEPTS":"REJECTS",
                       r?"":" -- reason: ", r?"":why);
        }
        snprintf(nm,sizeof nm,"sweep -- %s: no FALSE REJECT (%d Core-valid scripts)",
                 ENTRY[w], naccept);
        snprintf(det,sizeof det,"%d false rejects", bad_reject);
        ck(nm, bad_reject==0, det);
        snprintf(nm,sizeof nm,"sweep -- %s: no FALSE ACCEPT (%d Core-invalid scripts)",
                 ENTRY[w], nreject);
        snprintf(det,sizeof det,"%d false accepts", bad_accept);
        ck(nm, bad_accept==0, det);
    }

    printf("\n%s (%d/%d)\n", fails?"TESTS FAILED":"ALL PASS", checks-fails, checks);
    return fails?1:0;
}
