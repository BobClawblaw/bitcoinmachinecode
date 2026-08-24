/* test_wv0_drv_diff.c -- bitcoin_witness_v0_drv.asm vs bitcoin_witness_v0.c's
 * sv_verify_witness_v0.
 *
 * WHY THIS EXISTS
 *   Phase 2 slice 9: the witness-v0 driver decides which script runs, over
 *   which initial stack, and applies ExecuteWitnessScript's structural
 *   rules. Both twins drive the SAME sv_run_v with the SAME checksig hook,
 *   so the differential isolates the driver: shape selection, the sha256
 *   program check, the implied-P2WPKH script build, stack fill, sv_ctx
 *   fill (incl. the locktime context), and the cleanstack/truth epilogue.
 *   Exact SCRIPT_ERR_* codes are compared on every case.
 *
 * CASES
 *   P2WSH accept (OP_TRUE witnessScript); multi-item initial stacks (data
 *   actually consumed by the script); CLEANSTACK and EVAL_FALSE shapes;
 *   PUSH_SIZE at the 520/521 boundary; STACK_SIZE at 1000/1001 initial
 *   items; program-hash mismatch; empty witness; wrong program lengths
 *   (0/2/19/21/31/33/40); P2WPKH with garbage signature material (deep
 *   interpreter reject, code compared exactly); nwit != 2 for P2WPKH.
 *
 * Usage: ./test_wv0_drv_diff
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64;

extern int  sv_verify_witness_v0(const u8* prog, u32 proglen,
                                 const u8* const* wit, const u32* witlen, u32 nwit,
                                 u64 amount, u64 flags, unsigned long nIn,
                                 const u8* tx, unsigned long txlen,
                                 u8* work, unsigned long workcap);
extern long sv_verify_witness_v0_asm(const u8* prog, u32 proglen,
                                     const u8* const* wit, const u32* witlen, u32 nwit,
                                     u64 amount, u64 flags, u64 nIn,
                                     const u8* tx, u64 txlen,
                                     u8* work, u64 workcap);
extern void sha256_full(u8 out[32], const void* in, int64_t len);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk,
                                    unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr, "unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static long fails = 0, compared = 0;

#define FLAGS ((1ULL<<11)|(1ULL<<0))     /* WITNESS|P2SH */
static u8 workc[1<<20], worka[1<<20];
static u8 txbuf[256]; static u64 txlen;

static void diff(const char* nm, const u8* prog, u32 pl,
                 const u8* const* wit, const u32* witlen, u32 nwit, u64 amount){
    int  c = sv_verify_witness_v0(prog, pl, wit, witlen, nwit, amount,
                                  FLAGS, 0, txbuf, txlen, workc, sizeof workc);
    long a = sv_verify_witness_v0_asm(prog, pl, wit, witlen, nwit, amount,
                                      FLAGS, 0, txbuf, txlen, worka, sizeof worka);
    compared++;
    if (c != (int)a){
        if (fails < 30) printf("FAIL %s: err %d vs %ld\n", nm, c, a);
        fails++;
    }
}

static u64 mk_tx(u8* o){
    u64 n = 0;
    o[n++]=1;o[n++]=0;o[n++]=0;o[n++]=0;
    o[n++]=1; for (int k=0;k<36;k++) o[n++]=(u8)k;
    o[n++]=0; o[n++]=0xfe;o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;
    o[n++]=1; for (int k=0;k<8;k++) o[n++]=0; o[n++]=1; o[n++]=0x51;
    o[n++]=0x33;o[n++]=0;o[n++]=0;o[n++]=0;
    return n;
}

int main(void){
    txlen = mk_tx(txbuf);
    u8 prog32[32], prog20[20];

    /* ---- P2WSH: accept and structural shapes ---- */
    { static u8 wscript[1] = {0x51};             /* OP_TRUE */
      sha256_full(prog32, wscript, 1);
      const u8* w[1] = { wscript }; u32 l[1] = { 1 };
      diff("p2wsh OP_TRUE accept", prog32, 32, w, l, 1, 5000); }
    { /* script consumes an initial item: <x> OP_DROP OP_TRUE over stack [item] */
      static u8 ws[3] = {0x75, 0x51, 0};         /* OP_DROP OP_TRUE */
      sha256_full(prog32, ws, 2);
      static u8 item[4] = {1,2,3,4};
      const u8* w[2] = { item, ws }; u32 l[2] = { 4, 2 };
      diff("p2wsh consumes initial stack", prog32, 32, w, l, 2, 5000); }
    { /* cleanstack: script leaves 2 elements */
      static u8 ws[3] = {0x51, 0x51, 0};         /* OP_TRUE OP_TRUE */
      sha256_full(prog32, ws, 2);
      const u8* w[1] = { ws }; u32 l[1] = { 2 };
      diff("p2wsh cleanstack violation", prog32, 32, w, l, 1, 5000); }
    { /* eval-false: OP_0 */
      static u8 ws[1] = {0x00};
      sha256_full(prog32, ws, 1);
      const u8* w[1] = { ws }; u32 l[1] = { 1 };
      diff("p2wsh eval-false", prog32, 32, w, l, 1, 5000); }
    { /* push-size boundary: initial items of 520 and 521 bytes */
      static u8 big[521]; memset(big, 7, sizeof big);
      static u8 ws[3] = {0x75, 0x51, 0};
      sha256_full(prog32, ws, 2);
      const u8* w[2] = { big, ws }; u32 l[2] = { 520, 2 };
      diff("p2wsh 520-byte item ok-path", prog32, 32, w, l, 2, 5000);
      l[0] = 521;
      diff("p2wsh 521-byte item push-size", prog32, 32, w, l, 2, 5000); }
    { /* stack-size: 1000 vs 1001 initial items (script is item #n+1) */
      enum { N = 1001 };
      static const u8* w[N+1]; static u32 l[N+1];
      static u8 tiny[1] = {9};
      static u8 ws[1] = {0x51};
      sha256_full(prog32, ws, 1);
      for (int i = 0; i < N; i++){ w[i] = tiny; l[i] = 1; }
      w[N] = ws; l[N] = 1;
      diff("p2wsh 1001 initial items stack-size", prog32, 32, w, l, N+1, 5000);
      /* 1000 initial items passes the size gate (then fails cleanstack --
       * compared exactly, whatever the code) */
      w[N-1] = ws; l[N-1] = 1;
      diff("p2wsh 1000 initial items", prog32, 32, w, l, N, 5000); }
    { /* program hash mismatch */
      static u8 ws[1] = {0x51};
      sha256_full(prog32, ws, 1); prog32[0] ^= 1;
      const u8* w[1] = { ws }; u32 l[1] = { 1 };
      diff("p2wsh hash mismatch", prog32, 32, w, l, 1, 5000);
      prog32[0] ^= 1; }
    { /* empty witness */
      diff("p2wsh empty witness", prog32, 32, 0, 0, 0, 5000); }

    /* ---- wrong program lengths ---- */
    { static u8 p[40]; memset(p, 3, sizeof p);
      static u8 d[1] = {0x51};
      const u8* w[1] = { d }; u32 l[1] = { 1 };
      u32 lens[] = { 0, 2, 19, 21, 31, 33, 40 };
      for (unsigned i = 0; i < sizeof lens/sizeof lens[0]; i++)
          diff("wrong program length", p, lens[i], w, l, 1, 5000); }

    /* ---- P2WPKH ---- */
    { memset(prog20, 0x42, 20);
      static u8 sig[72], pub[33];
      memset(sig, 0x30, sizeof sig); memset(pub, 0x02, sizeof pub);
      const u8* w[2] = { sig, pub }; u32 l[2] = { 72, 33 };
      diff("p2wpkh garbage sig deep reject", prog20, 20, w, l, 2, 5000);
      diff("p2wpkh nwit=1", prog20, 20, w, l, 1, 5000);
      const u8* w3[3] = { sig, pub, pub }; u32 l3[3] = { 72, 33, 33 };
      diff("p2wpkh nwit=3", prog20, 20, w3, l3, 3, 5000);
      /* empty items where sig/pub should be */
      const u8* we[2] = { sig, pub }; u32 le[2] = { 0, 0 };
      diff("p2wpkh empty sig+pub", prog20, 20, we, le, 2, 5000); }

    printf("compared %ld wv0-driver cases; %ld mismatch(es)\n", compared, fails);
    printf("%s (%ld failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
