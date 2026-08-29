/* tests/test_rpc_amount.c -- BTC amount parsing bounds (audit finding 5a).
 *
 * `rpc_amount_to_sat` reads unauthenticated JSON-RPC input. Before this fix
 * the whole-number part accumulated without a bound, so ~19 digits overflowed
 * a signed long long -- undefined behaviour, and in practice a wrap to a
 * negative or arbitrary value that had nonetheless "parsed successfully".
 *
 * The interesting cases are the ones a naive fix gets wrong: rejecting the
 * overflow but also rejecting the largest legal amount, or saturating to
 * MAX_MONEY instead of refusing (an unrepresentable amount is a malformed
 * request, not a request for the maximum).
 */
#include <stdio.h>
#include <string.h>

extern long long rpc_amount_to_sat(const char* s);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static void eq(const char* in, long long want){
    long long got = rpc_amount_to_sat(in);
    char l[160];
    snprintf(l, sizeof l, "\"%s\" -> %lld", in, want);
    if (got == want) printf("  ok  %s\n", l);
    else { printf("  FAIL %s (got %lld)\n", l, got); fails++; }
}

int main(void){
    printf("== ordinary amounts still parse ==\n");
    eq("0", 0);
    eq("1", 100000000LL);
    eq("0.00000001", 1);
    eq("1.5", 150000000LL);
    eq("0.1", 10000000LL);
    eq("12.34567891", 1234567891LL);

    printf("== the money ceiling ==\n");
    eq("21000000", 2100000000000000LL);            /* exactly MAX_MONEY: legal */
    eq("20999999.99999999", 2099999999999999LL);
    eq("21000000.00000001", -1);                   /* one satoshi over */
    eq("21000001", -1);

    printf("== overflow is refused, not wrapped ==\n");
    /* Each of these overflowed signed 64-bit before the bound. The failure
     * mode that matters is a NEGATIVE or arbitrary positive result being
     * returned as if it had parsed. */
    eq("9223372036854775807", -1);                 /* LLONG_MAX */
    eq("9223372036854775808", -1);                 /* LLONG_MAX + 1 */
    eq("18446744073709551616", -1);                /* 2^64 */
    eq("99999999999999999999", -1);
    eq("184467440737095516160000000000", -1);

    printf("== no input produces a negative satoshi count other than the -1 error ==\n");
    { const char* probes[] = {
        "9223372036854775807", "92233720368547758079", "1844674407370955161",
        "18446744073709551615", "21000000.00000002", "999999999999999999999999",
        "0.99999999", "21000000", "20999999.99999998" };
      int bad = 0;
      for (unsigned i = 0; i < sizeof probes/sizeof probes[0]; i++){
          long long v = rpc_amount_to_sat(probes[i]);
          if (v < -1 || (v > 0 && v > 2100000000000000LL)){
              printf("        \"%s\" produced %lld\n", probes[i], v);
              bad++;
          }
      }
      ck("every probe is either a valid in-range amount or exactly -1", bad == 0); }

    printf("== malformed input is still rejected ==\n");
    eq("-1", -1);
    eq("", -1);
    eq("abc", -1);
    eq("1.2.3", -1);
    eq("1.000000001", -1);                         /* 9 fractional digits */
    eq("1 ", -1);
    eq(".", -1);

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
