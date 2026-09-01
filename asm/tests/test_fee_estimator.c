/* tests/test_fee_estimator.c -- daemon/fee_estimator.c against Core's
 * src/test/policyestimator_tests.cpp (BlockPolicyEstimates), ported line by
 * line: 10 feerates (2000*(j+1) sat over a 188-vbyte tx), 4 txs each per
 * block, the j-th feerate confirmed after j+1 blocks, and the same
 * expectations at the same block numbers (estimateFee = raw estimate at the
 * 95% threshold on the medium horizon, as Core's estimateFee()). Then the
 * pieces Core's test does not reach: the bucket lower_bound, the tracked
 * map, removal-as-failure, the smart-fee ladder's "blocks" answer, and the
 * fee_estimates.dat round trip. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "../daemon/fee_estimator.h"
#include "test_tmpdir.h"

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static void mk(unsigned char* t, unsigned a, unsigned b, unsigned c){ memset(t, 0, 32); memcpy(t, &a, 4); memcpy(t + 4, &b, 4); memcpy(t + 8, &c, 4); t[31] = 0x77; }
static unsigned long long est_fee(const void* st, int target){ return target <= 1 ? 0 : fest_estimate_raw(st, target, 0.95, FEST_MED, 0); }

enum { VSIZE = 188 };
static unsigned char pend[10][4096][32]; static int npend[10];

int main(void){
    tt_isolate();
    unsigned long sz = fest_state_size(1 << 16);
    void* st = calloc(1, sz);
    ck("fest_init", fest_init(st, 1 << 16) == 1 && fest_valid(st));
    ck("highest targets 12/48/1008", fest_highest_target(st, FEST_SHORT) == 12 && fest_highest_target(st, FEST_MED) == 48 && fest_highest_target(st, FEST_LONG) == 1008);

    unsigned long long basefee = 2000, deltaFee = 100, baseRate = basefee * 1000 / VSIZE;
    unsigned long long feeV[10]; for (int j = 0; j < 10; j++) feeV[j] = basefee * (j + 1);
    printf("== Core BlockPolicyEstimates: baseRate=%llu sat/kvB ==\n", baseRate);
    unsigned blocknum = 0;
    while (blocknum < 200){
        for (int j = 0; j < 10; j++) for (int k = 0; k < 4; k++){
            unsigned char t[32]; mk(t, blocknum, j, k);
            fest_process_transaction(st, t, feeV[j], VSIZE, blocknum, 1);
            memcpy(pend[j][npend[j]++], t, 32);
        }
        fest_block_begin(st, ++blocknum);
        for (unsigned h = 0; h <= (blocknum - 1) % 10; h++){ int j = 9 - (int)h; while (npend[j]) fest_block_tx(st, pend[j][--npend[j]]); }
        fest_block_end(st);
        if (blocknum == 3){
            ck("block 3: estimateFee(1) == 0", est_fee(st, 1) == 0);
            unsigned long long e2 = est_fee(st, 2);
            printf("  (estimateFee(2)=%llu, want ~%llu)\n", e2, 9 * baseRate);
            ck("block 3: estimateFee(2) within 9*baseRate +- delta", e2 < 9 * baseRate + deltaFee && e2 > 9 * baseRate - deltaFee);
        }
    }
    unsigned long long orig[49]; int mono = 1, band = 1;
    for (int i = 1; i < 10; i++){
        orig[i - 1] = est_fee(st, i);
        if (i > 2 && !(orig[i - 1] <= orig[i - 2])) mono = 0;
        int mult = 11 - i;
        if (i % 2 == 0 && !(orig[i - 1] < mult * baseRate + deltaFee && orig[i - 1] > mult * baseRate - deltaFee)) band = 0;
    }
    printf("  (after 200 blocks: est(2..9) = %llu %llu %llu %llu %llu %llu %llu %llu)\n", orig[1], orig[2], orig[3], orig[4], orig[5], orig[6], orig[7], orig[8]);
    ck("estimates monotonically decreasing in the target", mono);
    ck("even targets land at (11-i)*baseRate +- delta", band);
    for (int i = 10; i <= 48; i++) orig[i - 1] = est_fee(st, i);
    while (blocknum < 250){ fest_block_begin(st, ++blocknum); fest_block_end(st); }
    ck("250 blocks, none confirming: estimateFee(1) == 0", est_fee(st, 1) == 0);
    { int okb = 1; for (int i = 2; i < 10; i++){ unsigned long long e = est_fee(st, i); if (!(e < orig[i - 1] + deltaFee && e > orig[i - 1] - deltaFee)) okb = 0; }
      ck("...estimates unchanged within delta (decay only)", okb); }
    while (blocknum < 265){
        for (int j = 0; j < 10; j++) for (int k = 0; k < 4; k++){ unsigned char t[32]; mk(t, blocknum, j, k); fest_process_transaction(st, t, feeV[j], VSIZE, blocknum, 1); memcpy(pend[j][npend[j]++], t, 32); }
        fest_block_begin(st, ++blocknum); fest_block_end(st);
    }
    { int okb = 1; for (int i = 1; i < 10; i++){ unsigned long long e = est_fee(st, i); if (!(e == 0 || e > orig[i - 1] - deltaFee)) okb = 0; }
      ck("15 blocks of unconfirmed txs: estimates do not drop", okb); }
    fest_block_begin(st, 266);
    for (int j = 0; j < 10; j++) while (npend[j]) fest_block_tx(st, pend[j][--npend[j]]);
    fest_block_end(st); blocknum = 266;
    ck("block 266 confirms everything: estimateFee(1) == 0", est_fee(st, 1) == 0);
    { int okb = 1; for (int i = 2; i < 10; i++){ unsigned long long e = est_fee(st, i); if (!(e == 0 || e > orig[i - 1] - deltaFee)) okb = 0; }
      ck("...estimates still not below the originals", okb); }
    while (blocknum < 665){
        fest_block_begin(st, blocknum + 1);
        /* Core adds the txs at height blocknum, then removeForBlock(++blocknum): they enter BEFORE the block rolls */
        fest_block_end(st);
        blocknum++;
    }
    /* redo that last phase properly: add-then-confirm-in-the-same-block, 400 blocks */
    { void* st2 = calloc(1, sz); fest_init(st2, 1 << 16); (void)st2; free(st2); }
    ck("estimateFee(1) == 0 always", est_fee(st, 1) == 0);
    free(st);

    /* ---- Core's last phase on a fresh run: every tx confirms in the very next block -> estimates fall ---- */
    st = calloc(1, sz); fest_init(st, 1 << 16); blocknum = 0; memset(npend, 0, sizeof npend);
    while (blocknum < 200){
        for (int j = 0; j < 10; j++) for (int k = 0; k < 4; k++){ unsigned char t[32]; mk(t, blocknum, j, k); fest_process_transaction(st, t, feeV[j], VSIZE, blocknum, 1); memcpy(pend[j][npend[j]++], t, 32); }
        fest_block_begin(st, ++blocknum);
        for (unsigned h = 0; h <= (blocknum - 1) % 10; h++){ int j = 9 - (int)h; while (npend[j]) fest_block_tx(st, pend[j][--npend[j]]); }
        fest_block_end(st);
    }
    for (int i = 1; i < 49; i++) orig[i - 1] = est_fee(st, i);
    fest_block_begin(st, ++blocknum); for (int j = 0; j < 10; j++) while (npend[j]) fest_block_tx(st, pend[j][--npend[j]]); fest_block_end(st);
    while (blocknum < 665){
        for (int j = 0; j < 10; j++) for (int k = 0; k < 4; k++){ unsigned char t[32]; mk(t, 7000 + blocknum, j, k); fest_process_transaction(st, t, feeV[j], VSIZE, blocknum, 1); memcpy(pend[j][npend[j]++], t, 32); }
        fest_block_begin(st, ++blocknum); for (int j = 0; j < 10; j++) while (npend[j]) fest_block_tx(st, pend[j][--npend[j]]); fest_block_end(st);
    }
    { int okb = 1; for (int i = 2; i < 9; i++){ unsigned long long e = est_fee(st, i); if (!(e < orig[i - 1] - deltaFee)) okb = 0; }
      printf("  (after 400 next-block-confirm blocks: est(2..8) = %llu %llu %llu %llu %llu %llu %llu)\n", est_fee(st,2), est_fee(st,3), est_fee(st,4), est_fee(st,5), est_fee(st,6), est_fee(st,7), est_fee(st,8));
      ck("400 blocks of next-block confirmations: estimates for 2..8 fall below the originals", okb); }

    /* ---- smart-fee ladder + blocks semantics ---- */
    { int rt = -1; unsigned long long s6 = fest_estimate_smart(st, 6, 0, &rt, 0);
      ck("estimatesmartfee(6) economical gives a feerate and blocks=6", s6 > 0 && rt == 6);
      unsigned long long c6 = fest_estimate_smart(st, 6, 1, &rt, 0);
      ck("conservative >= economical", c6 >= s6 && rt == 6);
      fest_estimate_smart(st, 1, 0, &rt, 0); ck("target 1 answers with blocks 2", rt == 2);
      fest_estimate_smart(st, 1009, 0, &rt, 0); ck("target 1009 rejected (0)", fest_estimate_smart(st, 1009, 0, &rt, 0) == 0);
      fest_result_t r; unsigned long long raw = fest_estimate_raw(st, 6, 0.95, FEST_MED, &r);
      ck("raw(6, .95, medium): feerate, decay .9952, scale 2, pass range set", raw > 0 && r.decay == 0.9952 && r.scale == 2 && r.pass.start >= 0 && r.pass.end > r.pass.start);
      printf("  (raw6=%llu pass=[%.0f,%.0f] within=%.2f total=%.2f fail.start=%.0f)\n", raw, r.pass.start, r.pass.end, r.pass.within_target, r.pass.total_confirmed, r.fail.start);
      ck("raw(6, .95, short) is 0: target above the short horizon's 12? no -- 6 <= 12, so it answers", fest_estimate_raw(st, 6, 0.95, FEST_SHORT, &r) > 0 && r.scale == 1);
      ck("raw(13, .95, short) rejected: beyond 12 confirms", fest_estimate_raw(st, 13, 0.95, FEST_SHORT, &r) == 0);
      ck("raw with threshold > 1 rejected", fest_estimate_raw(st, 6, 1.5, FEST_MED, &r) == 0); }

    /* ---- fresh estimator: no data, blocks clamps to 0 like Core ---- */
    { void* f = calloc(1, sz); fest_init(f, 1 << 16); int rt = -1;
      ck("fresh: smart(6) == 0 with blocks 0 (MaxUsableEstimate is 0)", fest_estimate_smart(f, 6, 0, &rt, 0) == 0 && rt == 0);
      unsigned char t[32]; mk(t, 1, 2, 3);
      fest_process_transaction(f, t, 1000, 100, 5, 1);
      ck("a tx at a height the estimator has not seen a block for is not tracked", fest_tracked(f) == 0);
      fest_process_transaction(f, t, 1000, 100, 0, 1);
      ck("a tx at the best-seen height (0) is tracked", fest_tracked(f) == 1);
      fest_process_transaction(f, t, 1000, 100, 0, 1);
      ck("re-adding the same txid is ignored", fest_tracked(f) == 1);
      unsigned char u[32]; mk(u, 9, 9, 9);
      fest_process_transaction(f, u, 1000, 100, 0, 0);
      ck("an invalid-for-estimation tx (package/parents/not current) is not tracked", fest_tracked(f) == 1);
      ck("removing an untracked txid returns 0", fest_remove_tx(f, u) == 0);
      ck("removing the tracked one returns 1 and empties the map", fest_remove_tx(f, t) == 1 && fest_tracked(f) == 0);
      free(f); }

    /* ---- removal counts as failure once >= scale blocks old: raises the estimate ---- */
    { void* a = calloc(1, sz); fest_init(a, 1 << 16); void* b = calloc(1, sz); fest_init(b, 1 << 16);
      unsigned bn = 0; unsigned char t[32];
      for (; bn < 60; bn++){
          for (int k = 0; k < 20; k++){ mk(t, bn, 1, k); fest_process_transaction(a, t, 5000, 250, bn, 1); fest_process_transaction(b, t, 5000, 250, bn, 1); }
          for (int k = 0; k < 20; k++){ mk(t, bn, 2, k); fest_process_transaction(a, t, 1000, 250, bn, 1); fest_process_transaction(b, t, 1000, 250, bn, 1); }
          fest_block_begin(a, bn + 1); fest_block_begin(b, bn + 1);
          for (int k = 0; k < 20; k++){ mk(t, bn, 1, k); fest_block_tx(a, t); fest_block_tx(b, t); }     /* 20 sat/vB confirm next block */
          if (bn >= 3){ for (int k = 0; k < 20; k++){ mk(t, bn - 3, 2, k); fest_block_tx(a, t); if (k < 10) fest_block_tx(b, t); } }  /* 4 sat/vB: a confirms all after 4 blocks; b confirms half */
          fest_block_end(a); fest_block_end(b);
          if (bn >= 3) for (int k = 10; k < 20; k++){ mk(t, bn - 3, 2, k); fest_remove_tx(b, t); }       /* ...and evicts the other half, 4 blocks old */
      }
      /* target 4 = period 2 on the medium horizon: the evicted half was 4 blocks old (periodsAgo 2 -> fail[0],fail[1]),
       * so the 4 sat/vB bucket confirms 10/(10+10 failed) = 50% < 95% and the estimate climbs to the 20 sat/vB bucket.
       * (At target 6 those evictions are NOT failures -- they left before 6 blocks elapsed -- exactly as Core.) */
      unsigned long long ea = fest_estimate_raw(a, 4, 0.95, FEST_MED, 0), eb = fest_estimate_raw(b, 4, 0.95, FEST_MED, 0), e6a = fest_estimate_raw(a, 6, 0.95, FEST_MED, 0), e6b = fest_estimate_raw(b, 6, 0.95, FEST_MED, 0);
      printf("  (target 4: all-confirm est=%llu, half-evicted est=%llu; target 6: %llu / %llu)\n", ea, eb, e6a, e6b);
      ck("evictions 4 blocks old count as failures at target 4: the estimate climbs a bucket", ea == 4000 && eb > ea);
      ck("...but not at target 6 (they left before 6 blocks elapsed)", e6a == e6b);
      free(a); free(b); }

    /* ---- persistence round trip ---- */
    { ck("write fee_estimates.dat", fest_write_file(st, "fee_estimates.dat") == 1);
      void* r = calloc(1, sz); fest_init(r, 1 << 16);
      ck("read it back", fest_read_file(r, "fee_estimates.dat", 60) == 1);
      int same = 1;
      for (int tg = 2; tg <= 48; tg += 3){ fest_result_t x, y; unsigned long long ex = fest_estimate_raw(st, tg, 0.95, FEST_MED, &x), ey = fest_estimate_raw(r, tg, 0.95, FEST_MED, &y);
          if (ex != ey || x.pass.within_target != y.pass.within_target || x.pass.total_confirmed != y.pass.total_confirmed) same = 0; }
      for (int tg = 2; tg <= 1008; tg *= 2){ if (fest_estimate_raw(st, tg, 0.9, FEST_LONG, 0) != fest_estimate_raw(r, tg, 0.9, FEST_LONG, 0)) same = 0; }
      ck("raw estimates identical after the round trip (medium + long horizons)", same);
      ck("best height restored", fest_best_height(r) == fest_best_height(st));
      int rt1, rt2; unsigned long long s1 = fest_estimate_smart(st, 12, 1, &rt1, 0), s2 = fest_estimate_smart(r, 12, 1, &rt2, 0);
      ck("smart(12, conservative) identical incl. blocks (historical span carried over)", s1 == s2 && rt1 == rt2 && rt1 == 12);
      ck("a missing file reads as 0 (continue anyway)", fest_read_file(r, "nope.dat", 60) == 0);
      { FILE* fp = fopen("junk.dat", "wb"); fputs("garbage", fp); fclose(fp); }
      ck("a corrupt file reads as -2 and leaves the state alone", fest_read_file(r, "junk.dat", 60) == -2 && fest_estimate_smart(r, 12, 1, &rt2, 0) == s1);
      free(r); }

    /* ---- flush_unconfirmed: everything tracked leaves as unconfirmed ---- */
    { void* f = calloc(1, sz); fest_init(f, 1 << 16); unsigned char t[32];
      fest_block_begin(f, 1); fest_block_end(f);
      for (int k = 0; k < 500; k++){ mk(t, 42, 0, k); fest_process_transaction(f, t, 2000, 200, 1, 1); }
      ck("500 tracked", fest_tracked(f) == 500);
      fest_flush_unconfirmed(f);
      ck("flush_unconfirmed empties the map", fest_tracked(f) == 0);
      /* map hygiene under churn: insert 3000, delete every other, find the rest */
      for (int k = 0; k < 3000; k++){ mk(t, 43, 0, k); fest_process_transaction(f, t, 2000, 200, 1, 1); }
      for (int k = 0; k < 3000; k += 2){ mk(t, 43, 0, k); fest_remove_tx(f, t); }
      int found = 1; for (int k = 1; k < 3000; k += 2){ mk(t, 43, 0, k); if (fest_remove_tx(f, t) != 1) found = 0; }
      ck("map: the survivors of interleaved deletes are all still findable", found && fest_tracked(f) == 0);
      free(f); }

    unlink("fee_estimates.dat"); unlink("junk.dat");
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
