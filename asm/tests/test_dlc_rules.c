/* tests/test_dlc_rules.c -- the header phase's chain-selection rule: the
 * pool's announced height is the second-highest claim (one liar cannot move
 * it), and a fetched chain is refused only when it ends more than
 * DLC_HDR_BEHIND_MAX below it (2026-09-09: a stuck peer's stale branch, 4,500
 * blocks short, was taken as THE chain and the bench ended on it). */
#include <stdio.h>
#include "../daemon/dlc_rules.h"
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
int main(void){
    long a[] = {966132, 966131, 966130, 961640, 966132};
    ck("announced = the median claim (966131 of five)", dlc_announced_height(a, 5) == 966131);
    long b[] = {969817, 966063, 966060, 966062};
    ck("one peer claiming 969,817 does not move it: 966062 (the lower median)", dlc_announced_height(b, 4) == 966062);
    /* run 19 (2026-09-09 11:48Z): TWO peers claimed above the tip and the second-highest
     * rule refused every honest chain at 966,200 -- eight candidates, a minute each */
    long r19[] = {970195, 970195, 966200, 966200, 966199, 966200, 966198, 940000, 966200, 966197};
    ck("two liars above the tip do not move it: the median is an honest height (966200)", dlc_announced_height(r19, 10) == 966200);
    ck("... and the honest chain at 966,200 does not fall short of it", !dlc_chain_falls_short(966200, dlc_announced_height(r19, 10)));
    long c[] = {966100};
    ck("a single claim is the announced height", dlc_announced_height(c, 1) == 966100);
    long d[] = {0, 0, -1};
    ck("no claims: 0 (nothing to compare against)", dlc_announced_height(d, 3) == 0);
    long e[] = {0, 966100, 0, 966090, 966095};
    ck("unclaimed entries are ignored in the median", dlc_announced_height(e, 5) == 966095);
    ck("a chain 4,493 short of 966,132 falls short", dlc_chain_falls_short(961639, 966132));
    ck("a chain 144 short is accepted (peers a few blocks apart are normal)", !dlc_chain_falls_short(966132 - 144, 966132));
    ck("a chain 145 short is refused", dlc_chain_falls_short(966132 - 145, 966132));
    ck("a chain at or above the announced height is accepted", !dlc_chain_falls_short(966140, 966132));
    ck("with no announced height nothing falls short", !dlc_chain_falls_short(5, 0));
    printf("%s (%d failure(s))\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
