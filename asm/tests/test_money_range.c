/* tests/test_money_range.c -- the consensus money range (audit finding 5b).
 *
 * Core's CheckTransaction rejects, in this order:
 *     txout.nValue < 0            -> bad-txns-vout-negative
 *     txout.nValue > MAX_MONEY    -> bad-txns-vout-toolarge
 *     running total out of range  -> bad-txns-txouttotal-toolarge
 * (CVE-2010-5139: the value-overflow bug that printed 184 billion BTC.)
 *
 * This tree had NO money-range check at all before this. The dangerous half
 * is not the rejections but the ACCEPTANCES: a check that is too strict
 * rejects a transaction already in the chain, which is a consensus split, not
 * a bug report. So every rejection here is paired with the largest value that
 * must still be accepted, and tests/live_money_range_chain.sh replays real
 * mainnet transactions through the same parser.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern int mv_test_parse(const uint8_t* tx, long txlen, uint32_t* wl0_out);

/* Same stub tests/test_mv_parse_bounds.c uses: mv_parse never consults the
 * UTXO set, so resolution is irrelevant to what is under test here. */
long mempool_resolve_confirmed_utxo(void* u, const uint8_t* t, unsigned long i,
    unsigned long long* v, const uint8_t** sp, unsigned long* sl){
    (void)u;(void)t;(void)i;(void)v;(void)sp;(void)sl; return 0; }

#define MAX_MONEY 2100000000000000ULL

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

/* Build a minimal legacy tx: 1 input, `nout` outputs with the given values,
 * each paying a 1-byte script. Returns the length. */
static long build_tx(uint8_t* b, const uint64_t* vals, int nout){
    long n = 0;
    b[n++]=1; b[n++]=0; b[n++]=0; b[n++]=0;              /* version */
    b[n++]=1;                                            /* 1 input */
    memset(b+n, 0x11, 32); n += 32;                      /* prevout hash */
    b[n++]=0; b[n++]=0; b[n++]=0; b[n++]=0;              /* prevout index */
    b[n++]=0;                                            /* empty scriptSig */
    b[n++]=0xff; b[n++]=0xff; b[n++]=0xff; b[n++]=0xff;  /* sequence */
    b[n++]=(uint8_t)nout;                                /* output count */
    for (int i = 0; i < nout; i++){
        for (int k = 0; k < 8; k++) b[n++] = (uint8_t)(vals[i] >> (8*k));
        b[n++]=1; b[n++]=0x51;                           /* scriptPubKey OP_1 */
    }
    b[n++]=0; b[n++]=0; b[n++]=0; b[n++]=0;              /* locktime */
    return n;
}

static int parse_vals(const uint64_t* vals, int nout){
    static uint8_t buf[4096];
    long n = build_tx(buf, vals, nout);
    return mv_test_parse(buf, n, 0);
}

int main(void){
    printf("== ordinary amounts are accepted ==\n");
    { uint64_t v[] = {0}; ck("a zero-value output parses", parse_vals(v, 1) == 1); }
    { uint64_t v[] = {5000000000ULL}; ck("a 50 BTC coinbase-sized output parses", parse_vals(v, 1) == 1); }
    { uint64_t v[] = {1, 2, 3, 4}; ck("several small outputs parse", parse_vals(v, 4) == 1); }

    printf("== the per-output cap ==\n");
    { uint64_t v[] = {MAX_MONEY};
      ck("exactly MAX_MONEY in one output is ACCEPTED", parse_vals(v, 1) == 1); }
    { uint64_t v[] = {MAX_MONEY + 1};
      ck("MAX_MONEY + 1 is rejected", parse_vals(v, 1) == 0); }
    { uint64_t v[] = {0x7fffffffffffffffULL};
      ck("INT64_MAX is rejected", parse_vals(v, 1) == 0); }
    { uint64_t v[] = {0x8000000000000000ULL};
      ck("a Core-NEGATIVE value (bit 63 set) is rejected", parse_vals(v, 1) == 0); }
    { uint64_t v[] = {0xffffffffffffffffULL};
      ck("all-ones is rejected", parse_vals(v, 1) == 0); }

    printf("== the running total ==\n");
    /* Each output is individually legal; only the sum is not. Without the
     * running check these would all pass. */
    { uint64_t v[] = {MAX_MONEY/2, MAX_MONEY/2};
      ck("two halves summing to MAX_MONEY are ACCEPTED", parse_vals(v, 2) == 1); }
    { uint64_t v[] = {MAX_MONEY, 1};
      ck("MAX_MONEY + 1 satoshi across two outputs is rejected", parse_vals(v, 2) == 0); }
    { uint64_t v[] = {MAX_MONEY/2 + 1, MAX_MONEY/2 + 1};
      ck("two legal halves that overshoot are rejected", parse_vals(v, 2) == 0); }
    { uint64_t v[] = {MAX_MONEY, MAX_MONEY, MAX_MONEY};
      ck("three max outputs are rejected", parse_vals(v, 3) == 0); }

    printf("== the CVE-2010-5139 shape ==\n");
    /* The original overflow: two outputs each just under 2^63 so the signed
     * sum wraps negative. Both are individually above MAX_MONEY here, so the
     * per-output check stops it first -- as it does in Core. */
    { uint64_t v[] = {0x7ffffffffffffff0ULL, 0x7ffffffffffffff0ULL};
      ck("the value-overflow pair is rejected", parse_vals(v, 2) == 0); }

    printf("== the boundary is exact ==\n");
    { uint64_t a[] = {MAX_MONEY - 1}; uint64_t b[] = {MAX_MONEY}; uint64_t c[] = {MAX_MONEY + 1};
      ck("MAX_MONEY-1 accepted", parse_vals(a, 1) == 1);
      ck("MAX_MONEY   accepted", parse_vals(b, 1) == 1);
      ck("MAX_MONEY+1 rejected", parse_vals(c, 1) == 0); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
