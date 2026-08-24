/* test_svs_drv_diff.c -- bitcoin_scriptverify_drv.asm vs bitcoin_scriptverify.c's
 * sv_verify_script.
 *
 * Phase 2 slice 10: the legacy/P2SH driver. Both twins drive the SAME
 * sv_run_v with the SAME legacy checksig hook, so the differential
 * isolates: push-only enforcement (both gates), the scriptSig/scriptPubKey
 * eval sequence, the P2SH snapshot/restore discipline, redeem extraction
 * and re-run, the truth checks, and CLEANSTACK. Exact SCRIPT_ERR_* codes
 * compared on every case. (INVALID_STACK_OPERATION and the rl>20000
 * PUSH_SIZE arm are unreachable through real evals -- the spk eval fails
 * first -- and ride on inspection, noted here so the gap is explicit.)
 *
 * Usage: ./test_svs_drv_diff
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64;

extern int  sv_verify_script(const u8* ss, unsigned long ssl, const u8* spk, unsigned long spl,
                             u64 flags, unsigned long nIn, const u8* tx, unsigned long txlen,
                             u8* work, unsigned long workcap);
extern long sv_verify_script_asm(const u8* ss, u64 ssl, const u8* spk, u64 spl,
                                 u64 flags, u64 nIn, const u8* tx, u64 txlen,
                                 u8* work, u64 workcap);
extern void hash160(u8 out[20], const void* in, long long len);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk,
                                    unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr, "unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static long fails = 0, compared = 0;
#define P2SH (1ULL<<0)
#define PUSHONLY (1ULL<<5)
#define CLEAN (1ULL<<8)
static u8 workc[1<<20], worka[1<<20];
static u8 txb[128]; static u64 txl;

static void diff(const char* nm, const u8* ss, u64 ssl, const u8* spk, u64 spl, u64 flags){
    int  c = sv_verify_script(ss, ssl, spk, spl, flags, 0, txb, txl, workc, sizeof workc);
    long a = sv_verify_script_asm(ss, ssl, spk, spl, flags, 0, txb, txl, worka, sizeof worka);
    compared++;
    if (c != (int)a){ if (fails < 30) printf("FAIL %s: %d vs %ld\n", nm, c, a); fails++; }
}

static u64 mk_tx(u8* o){
    u64 n = 0;
    o[n++]=1;o[n++]=0;o[n++]=0;o[n++]=0;
    o[n++]=1; for (int k=0;k<36;k++) o[n++]=(u8)k;
    o[n++]=0; o[n++]=0xfe;o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;
    o[n++]=1; for (int k=0;k<8;k++) o[n++]=0; o[n++]=1; o[n++]=0x51;
    o[n++]=0x77;o[n++]=0;o[n++]=0;o[n++]=0;
    return n;
}

int main(void){
    txl = mk_tx(txb);
    static u8 e[1];
    static u8 op1[1] = {0x51}, op0[1] = {0x00};

    /* legacy accepts / rejects, with and without CLEANSTACK */
    diff("empty ss + OP_TRUE spk", e, 0, op1, 1, P2SH);
    diff("empty ss + OP_0 spk (eval-false)", e, 0, op0, 1, P2SH);
    diff("OP_TRUE ss + empty spk", op1, 1, e, 0, P2SH);
    { static u8 ss2[2] = {0x51, 0x51};
      diff("2-deep stack, no cleanstack flag", ss2, 2, op1, 1, P2SH);
      diff("2-deep stack, cleanstack", ss2, 2, op1, 1, P2SH|CLEAN); }
    { static u8 nonpush[2] = {0x51, 0x87};   /* OP_EQUAL: not a push */
      diff("pushonly flag rejects op in ss", nonpush, 2, op1, 1, P2SH|PUSHONLY);
      diff("no pushonly flag allows it", nonpush, 2, op1, 1, P2SH); }

    /* P2SH: real redeem accept, wrong-hash reject, non-push ss reject */
    { static u8 redeem[1] = {0x51};
      u8 h[20]; hash160(h, redeem, 1);
      static u8 spk[23]; spk[0]=0xa9; spk[1]=0x14; spk[22]=0x87;
      memcpy(spk+2, h, 20);
      static u8 ss[2] = {0x01, 0x51};        /* push the 1-byte redeem */
      diff("p2sh OP_TRUE redeem accept", ss, 2, spk, 23, P2SH|CLEAN);
      diff("p2sh redeem, no p2sh flag (plain eval)", ss, 2, spk, 23, 0);
      spk[2] ^= 1;
      diff("p2sh hash mismatch", ss, 2, spk, 23, P2SH);
      spk[2] ^= 1;
      /* redeem leaving 2 elements: cleanstack fires after the redeem run */
      static u8 redeem2[2] = {0x51, 0x51};
      u8 h2[20]; hash160(h2, redeem2, 2);
      static u8 spk2[23]; spk2[0]=0xa9; spk2[1]=0x14; spk2[22]=0x87;
      memcpy(spk2+2, h2, 20);
      static u8 ss2[3] = {0x02, 0x51, 0x51};
      diff("p2sh redeem 2-deep + cleanstack", ss2, 3, spk2, 23, P2SH|CLEAN);
      diff("p2sh redeem 2-deep, no cleanstack", ss2, 3, spk2, 23, P2SH);
      /* redeem that evals false */
      static u8 redeem0[1] = {0x00};
      u8 h0[20]; hash160(h0, redeem0, 1);
      static u8 spk0[23]; spk0[0]=0xa9; spk0[1]=0x14; spk0[22]=0x87;
      memcpy(spk0+2, h0, 20);
      static u8 ss0[2] = {0x01, 0x00};
      diff("p2sh redeem evals false", ss0, 2, spk0, 23, P2SH);
      /* non-push scriptSig against a P2SH spk: SIG_PUSHONLY from BIP16 gate */
      static u8 ssop[3] = {0x01, 0x51, 0x87};
      diff("p2sh non-push ss (bip16 gate)", ssop, 3, spk, 23, P2SH); }

    /* extra stack context under the redeem (args consumed by it) */
    { static u8 redeem[2] = {0x75, 0x51};    /* OP_DROP OP_TRUE */
      u8 h[20]; hash160(h, redeem, 2);
      static u8 spk[23]; spk[0]=0xa9; spk[1]=0x14; spk[22]=0x87;
      memcpy(spk+2, h, 20);
      static u8 ss[5] = {0x01, 0xaa, 0x02, 0x75, 0x51};  /* arg + redeem push */
      diff("p2sh redeem consumes an arg", ss, 5, spk, 23, P2SH|CLEAN); }

    printf("compared %ld legacy-driver cases; %ld mismatch(es)\n", compared, fails);
    printf("%s (%ld failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
