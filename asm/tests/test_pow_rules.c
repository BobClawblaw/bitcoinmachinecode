/* tests/test_pow_rules.c -- the shared nBits rule engine
 * (bitcoin_pow_rules.c), hermetic.
 *
 * The REAL proof is validation/pow_replay.c over the full mainnet (964,251
 * heights, 478 boundaries, zero mismatches) and testnet4 (149,954 heights,
 * 101,009 min-difficulty blocks, 16,491 walk-backs, zero mismatches)
 * header mirrors -- run 2026-08-27, LOG.md. This suite test locks the
 * per-branch semantics hermetically so a regression cannot land unnoticed:
 *
 *   1. regtest / fPowNoRetargeting: expected == parent's bits, always;
 *   2. mainnet off-boundary: expected == parent's bits;
 *   3. boundary retarget: exact arith (x4 cap, /4 cap, powLimit cap,
 *      and the 2015-gap window measurement);
 *   4. testnet min-difficulty: the 20-minute exception, the walk-back to
 *      the last real-difficulty block, the walk-back stopping at a period
 *      boundary;
 *   5. BIP94: the boundary retarget bases on the FIRST block of the period;
 *   6. pow_check_bits: match/mismatch/unevaluable trichotomy.
 */
#include <stdio.h>
#include <string.h>
#include "../bitcoin_pow_rules.h"

typedef unsigned char u8;
typedef unsigned int u32;

#define MAXH 4200
static u8 g_hdr[MAXH][80];
static long g_n;

static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void set_hdr(long h, u32 time, u32 bits){ memset(g_hdr[h],0,80); put32(g_hdr[h]+68,time); put32(g_hdr[h]+72,bits); if(h>=g_n) g_n=h+1; }
static int get_hdr(void* ctx, long h, u8 out[80]){ (void)ctx; if(h<0||h>=g_n) return 0; memcpy(out,g_hdr[h],80); return 1; }

static int fails=0;
static void ck(const char* l,int c){ if(c) printf("  ok  %s\n",l); else { printf("  FAIL %s\n",l); fails++; } }

#define MAIN_LIM 0x1d00ffffu
#define REG_LIM  0x207fffffu

int main(void){
    printf("== 1: fPowNoRetargeting (regtest) ==\n");
    g_n=0; set_hdr(0, 1000, REG_LIM); set_hdr(1, 1600, 0x207ffffe);
    ck("expected == parent bits at any height",
       pow_expected_bits(1, 2000, get_hdr,0, 1,0,0,REG_LIM) == REG_LIM &&
       pow_expected_bits(2, 9999, get_hdr,0, 1,0,0,REG_LIM) == 0x207ffffe);

    printf("\n== 2: mainnet off-boundary ==\n");
    g_n=0; for(long h=0;h<10;h++) set_hdr(h, 1000+600*h, 0x1b0404cb);
    ck("expected == parent bits off-boundary",
       pow_expected_bits(5, 0, get_hdr,0, 0,0,0,MAIN_LIM) == 0x1b0404cb);

    printf("\n== 3: boundary retarget arithmetic ==\n");
    /* on-schedule window: 2015 gaps of exactly 600s -> timespan 1209000,
     * ratio 1209000/1209600 -- expected = retarget(base, ts) exactly */
    g_n=0; for(long h=0;h<2016;h++) set_hdr(h, 1000+600*h, 0x1b0404cb);
    u32 want = pow_retarget_bits(0x1b0404cb, 600*2015, MAIN_LIM);
    ck("on-schedule boundary == pow_retarget_bits(base, 2015 gaps)",
       pow_expected_bits(2016, 0, get_hdr,0, 0,0,0,MAIN_LIM) == want && want != 0);
    /* clamp x4: absurdly slow window */
    g_n=0; set_hdr(0, 0, 0x1b0404cb);
    for(long h=1;h<2016;h++) set_hdr(h, (u32)(h*100000), 0x1b0404cb);
    u32 slow = pow_expected_bits(2016, 0, get_hdr,0, 0,0,0,MAIN_LIM);
    ck("slow window clamps at 4x (== retarget with ts=4T)",
       slow == pow_retarget_bits(0x1b0404cb, 4*1209600L, MAIN_LIM));
    /* clamp /4: instant window */
    g_n=0; for(long h=0;h<2016;h++) set_hdr(h, 1000, 0x1b0404cb);
    u32 fast = pow_expected_bits(2016, 0, get_hdr,0, 0,0,0,MAIN_LIM);
    ck("instant window clamps at 1/4 (== retarget with ts=T/4)",
       fast == pow_retarget_bits(0x1b0404cb, 1209600L/4, MAIN_LIM));
    /* powLimit cap: easiest-possible base slowed 4x pins at the limit */
    g_n=0; set_hdr(0, 0, MAIN_LIM);
    for(long h=1;h<2016;h++) set_hdr(h, (u32)(h*100000), MAIN_LIM);
    ck("powLimit cap holds",
       pow_expected_bits(2016, 0, get_hdr,0, 0,0,0,MAIN_LIM) == MAIN_LIM);

    printf("\n== 4: testnet min-difficulty rules ==\n");
    /* chain: boundary block 0 real bits, 1..3 real, 4..6 min-diff, ask 7 */
    g_n=0;
    u32 real = 0x1c7fffff;
    set_hdr(0, 1000, real);
    for(long h=1;h<=3;h++) set_hdr(h, 1000+600*h, real);
    for(long h=4;h<=6;h++) set_hdr(h, 1000+600*h, MAIN_LIM);
    ck("20-min exception: late block -> powLimit",
       pow_expected_bits(7, 1000+600*6 + 1201, get_hdr,0, 0,1,1,MAIN_LIM) == MAIN_LIM);
    ck("prompt block walks back past the min-diff run to the real bits",
       pow_expected_bits(7, 1000+600*6 + 600, get_hdr,0, 0,1,1,MAIN_LIM) == real);
    /* walk-back stops at a period boundary: make EVERYTHING from the
     * boundary onward min-diff; the boundary block's own bits win */
    g_n=0;
    for(long h=0;h<2016;h++) set_hdr(h, 1000+600*h, real);
    set_hdr(2016, 1000+600*2016, MAIN_LIM);   /* boundary block, min-diff */
    for(long h=2017;h<=2020;h++) set_hdr(h, 1000+600*h, MAIN_LIM);
    ck("walk-back stops AT the period boundary (returns its bits)",
       pow_expected_bits(2021, 1000+600*2020 + 600, get_hdr,0, 0,1,0,MAIN_LIM) == MAIN_LIM);

    printf("\n== 5: BIP94 boundary base ==\n");
    /* first block of window carries REAL bits; the last carries min-diff.
     * BIP94 bases the retarget on the first (real); classic on the last. */
    g_n=0;
    set_hdr(0, 0, real);
    for(long h=1;h<2015;h++) set_hdr(h, (u32)(600*h), real);
    set_hdr(2015, 600*2015, MAIN_LIM);        /* last of window: min-diff */
    u32 bip94   = pow_expected_bits(2016, 0, get_hdr,0, 0,1,1,MAIN_LIM);
    u32 classic = pow_expected_bits(2016, 0, get_hdr,0, 0,1,0,MAIN_LIM);
    ck("BIP94 bases on the first block's REAL bits",
       bip94 == pow_retarget_bits(real, 600*2015, MAIN_LIM));
    ck("classic would have based on the (min-diff) last block -- differs",
       classic == pow_retarget_bits(MAIN_LIM, 600*2015, MAIN_LIM) && classic != bip94);

    printf("\n== 6: pow_check_bits trichotomy ==\n");
    g_n=0; for(long h=0;h<10;h++) set_hdr(h, 1000+600*h, 0x1b0404cb);
    u8 hdr[80]; memcpy(hdr, g_hdr[5], 80);
    ck("match -> 1",    pow_check_bits(5, hdr, get_hdr,0, 0,0,0,MAIN_LIM) == 1);
    put32(hdr+72, 0x1b0404cc);
    ck("mismatch -> 0", pow_check_bits(5, hdr, get_hdr,0, 0,0,0,MAIN_LIM) == 0);
    ck("missing ancestor -> -1", pow_check_bits(50, hdr, get_hdr,0, 0,0,0,MAIN_LIM) == -1);
    ck("genesis is never evaluated -> 1", pow_check_bits(0, hdr, get_hdr,0, 0,0,0,MAIN_LIM) == 1);

    printf("\n%s (%d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails);
    return fails?1:0;
}
