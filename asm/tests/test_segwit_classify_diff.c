/* test_segwit_classify_diff.c -- bitcoin_segwit_classify.asm vs
 * bitcoin_witness_v0.c's sv_classify_segwit / sv_witness_program.
 *
 * WHY THIS EXISTS
 *   Phase 2 slice 3. sv_classify_segwit is the BIP141 fork in the road:
 *   its verdict (native / wrapped / malleated / legacy) picks the verifier
 *   AND enforces Core's "scriptSig must be exactly one minimal direct push
 *   of the redeemScript" rule. A divergence here is a consensus split on
 *   real P2SH-P2WPKH/P2WSH spends -- ~half of all segwit-era inputs.
 *
 * WHAT IT COMPARES
 *   rc, *wrapped, and (when a program is found) version/proglen and the
 *   prog POINTER (both parse the same buffers). Corpus: the full
 *   deliberate matrix (all versions 0..16, all program lengths 2..40,
 *   malformed program shapes, every scriptSig push form including
 *   PUSHDATA1/2/4-wrapped redeems, hash mismatches, truncations) plus
 *   20,000 seeded-random scriptSigs against a real P2SH spk.
 *
 * Usage: ./test_segwit_classify_diff
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64;

extern int  sv_witness_program(const u8* s, u32 n, u32* version, const u8** prog, u32* proglen);
extern long sv_witness_program_asm(const u8* s, u64 n, u32* version, const u8** prog, u32* proglen);
extern int  sv_classify_segwit(const u8* spk, u32 spl, const u8* ss, u32 ssl,
                               u32* version, const u8** prog, u32* proglen, int* wrapped);
extern long sv_classify_segwit_asm(const u8* spk, u64 spl, const u8* ss, u64 ssl,
                                   u32* version, const u8** prog, u32* proglen, int* wrapped);
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

static void diff_wp(const u8* s, u32 n, long tag){
    u32 vc=7, va=7, plc=7, pla=7; const u8 *pc_=0, *pa_=0;
    int  c = sv_witness_program(s, n, &vc, &pc_, &plc);
    long a = sv_witness_program_asm(s, n, &va, &pa_, &pla);
    compared++;
    if (c != (int)a){ fail("wp rc", tag); return; }
    if (c && (vc != va || plc != pla || pc_ != pa_)) fail("wp outputs", tag);
}

static void diff_cls(const u8* spk, u32 spl, const u8* ss, u32 ssl, long tag){
    u32 vc=7, va=7, plc=7, pla=7; const u8 *pc_=0, *pa_=0; int wc=7, wa=7;
    int  c = sv_classify_segwit(spk, spl, ss, ssl, &vc, &pc_, &plc, &wc);
    long a = sv_classify_segwit_asm(spk, spl, ss, ssl, &va, &pa_, &pla, &wa);
    compared++;
    if (c != (int)a){ fail("cls rc", tag); return; }
    if (wc != wa){ fail("cls wrapped", tag); return; }
    if (c > 0 && (vc != va || plc != pla || pc_ != pa_)) fail("cls outputs", tag);
}

static u64 rs = 0x5eeded5eeded5ULL;
static u64 rnd(void){ rs ^= rs<<13; rs ^= rs>>7; rs ^= rs<<17; return rs; }

int main(void){
    static u8 s[64], spk[64], ss[600], redeem[64];
    long tag = 0;

    /* ---- 1. sv_witness_program: exhaustive version x length sweep ---- */
    for (int v = 0; v <= 17; v++){                 /* 17: one past OP_16 */
        for (u32 n = 0; n <= 44; n++){
            memset(s, 0xab, sizeof s);
            s[0] = v == 0 ? 0x00 : (u8)(0x50 + v);
            s[1] = (u8)(n >= 2 ? n - 2 : 0);
            diff_wp(s, n, ++tag);
            s[1] ^= 1;                             /* wrong length byte */
            diff_wp(s, n, ++tag);
        }
    }
    { u8 bad[6] = {0x50, 4, 1,2,3,4}; diff_wp(bad, 6, ++tag);   /* 0x50 invalid */
      bad[0] = 0x4f; diff_wp(bad, 6, ++tag);                    /* OP_1NEGATE invalid */
      bad[0] = 0x01; diff_wp(bad, 6, ++tag); }                  /* direct push invalid */

    /* ---- 2. wrapped spends: correct, malleated, mismatched ---- */
    struct { u8 ver; u8 plen; } progs[] = { {0,20}, {0,32}, {1,32}, {16,2}, {0,40} };
    for (unsigned pi = 0; pi < sizeof progs/sizeof progs[0]; pi++){
        u8 rl = (u8)(2 + progs[pi].plen);
        redeem[0] = progs[pi].ver == 0 ? 0x00 : (u8)(0x50 + progs[pi].ver);
        redeem[1] = progs[pi].plen;
        for (int i = 0; i < progs[pi].plen; i++) redeem[2+i] = (u8)(i + pi + 1);
        u8 h[20]; hash160(h, redeem, rl);
        spk[0]=0xa9; spk[1]=0x14; memcpy(spk+2, h, 20); spk[22]=0x87;

        /* exact single direct push: -> 2 (wrapped) */
        ss[0] = rl; memcpy(ss+1, redeem, rl);
        diff_cls(spk, 23, ss, (u32)(1+rl), ++tag);
        /* trailing extra opcode: -> -1 (malleated) */
        ss[1+rl] = 0x51;
        diff_cls(spk, 23, ss, (u32)(2+rl), ++tag);
        /* leading extra push then redeem: -> -1 */
        u8 ss2[600]; ss2[0]=0x01; ss2[1]=0xaa; ss2[2]=rl; memcpy(ss2+3, redeem, rl);
        diff_cls(spk, 23, ss2, (u32)(3+rl), ++tag);
        /* PUSHDATA1-wrapped redeem: -> -1 (not a minimal direct push) */
        ss2[0]=0x4c; ss2[1]=rl; memcpy(ss2+2, redeem, rl);
        diff_cls(spk, 23, ss2, (u32)(2+rl), ++tag);
        /* PUSHDATA2-wrapped redeem */
        ss2[0]=0x4d; ss2[1]=rl; ss2[2]=0; memcpy(ss2+3, redeem, rl);
        diff_cls(spk, 23, ss2, (u32)(3+rl), ++tag);
        /* PUSHDATA4-wrapped redeem */
        ss2[0]=0x4e; ss2[1]=rl; ss2[2]=0; ss2[3]=0; ss2[4]=0; memcpy(ss2+5, redeem, rl);
        diff_cls(spk, 23, ss2, (u32)(5+rl), ++tag);
        /* hash mismatch: flip one spk hash byte -> -1 */
        spk[5] ^= 1;
        ss[0] = rl; memcpy(ss+1, redeem, rl);
        diff_cls(spk, 23, ss, (u32)(1+rl), ++tag);
        spk[5] ^= 1;
        /* redeem that is NOT a witness program: -> 0 (plain P2SH) */
        u8 nr[5] = {0x03, 0x51, 0x52, 0x53, 0};   /* push of 3 non-program bytes */
        u8 h2[20]; hash160(h2, nr+1, 3);
        u8 spk2[23]; spk2[0]=0xa9; spk2[1]=0x14; memcpy(spk2+2, h2, 20); spk2[22]=0x87;
        diff_cls(spk2, 23, nr, 4, ++tag);
        /* non-push-only scriptSig over P2SH: -> 0 */
        u8 np[3] = {0x51, 0x87, 0x51};             /* OP_EQUAL is not a push */
        diff_cls(spk, 23, np, 3, ++tag);
        /* empty scriptSig: -> 0 */
        diff_cls(spk, 23, ss, 0, ++tag);
        /* truncated pushdata forms: -> 0 */
        u8 tr1[1] = {0x4c}; diff_cls(spk, 23, tr1, 1, ++tag);
        u8 tr2[2] = {0x4d, 0x05}; diff_cls(spk, 23, tr2, 2, ++tag);
        u8 tr3[4] = {0x4e, 1, 0, 0}; diff_cls(spk, 23, tr3, 4, ++tag);
        u8 tr4[2] = {0x0a, 0x01}; diff_cls(spk, 23, tr4, 2, ++tag); /* short direct */
    }

    /* ---- 3. native programs + non-witness spks through classify ---- */
    { u8 nspk[42];
      for (int v = 0; v <= 16; v++){
          nspk[0] = v == 0 ? 0x00 : (u8)(0x50 + v);
          nspk[1] = 20; memset(nspk+2, 0x33, 20);
          diff_cls(nspk, 22, ss, 0, ++tag);
          nspk[1] = 32; memset(nspk+2, 0x44, 32);
          diff_cls(nspk, 34, ss, 0, ++tag);
      }
      u8 pkh[25] = {0x76,0xa9,0x14, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20, 0x88,0xac};
      diff_cls(pkh, 25, ss, 0, ++tag);
      diff_cls(pkh, 0, ss, 0, ++tag);
    }

    /* ---- 4. seeded fuzz: random scriptSigs against a real P2SH spk ---- */
    { u8 rl = 22;
      redeem[0]=0x00; redeem[1]=20; for (int i=0;i<20;i++) redeem[2+i]=(u8)(i*3+1);
      u8 h[20]; hash160(h, redeem, rl);
      spk[0]=0xa9; spk[1]=0x14; memcpy(spk+2, h, 20); spk[22]=0x87;
      for (int c = 0; c < 20000; c++){
          u32 ssl = (u32)(rnd() % 80);
          for (u32 i = 0; i < ssl; i++){
              u64 r = rnd();
              /* bias toward push opcodes so the loop body gets exercised,
               * with occasional raw bytes for the reject paths */
              ss[i] = (r & 3) ? (u8)(r % 0x62) : (u8)r;
          }
          /* sometimes splice the true redeem push at a random offset */
          if ((rnd() & 7) == 0 && ssl + 1 + rl < sizeof ss){
              ss[ssl] = rl; memcpy(ss+ssl+1, redeem, rl); ssl += 1 + rl;
          }
          diff_cls(spk, 23, ss, ssl, ++tag);
      }
    }

    printf("compared %ld classification cases; %ld mismatch(es)\n", compared, fails);
    printf("%s (%ld failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
