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
    ck("announced = the second-highest claim (966132 twice: 966132)", dlc_announced_height(a, 5) == 966132);
    long b[] = {969817, 966063, 966060, 966062};
    ck("one peer claiming 969,817 does not move it: 966063", dlc_announced_height(b, 4) == 966063);
    long c[] = {966100};
    ck("a single claim is the announced height", dlc_announced_height(c, 1) == 966100);
    long d[] = {0, 0, -1};
    ck("no claims: 0 (nothing to compare against)", dlc_announced_height(d, 3) == 0);
    ck("a chain 4,493 short of 966,132 falls short", dlc_chain_falls_short(961639, 966132));
    ck("a chain 144 short is accepted (peers a few blocks apart are normal)", !dlc_chain_falls_short(966132 - 144, 966132));
    ck("a chain 145 short is refused", dlc_chain_falls_short(966132 - 145, 966132));
    ck("a chain at or above the announced height is accepted", !dlc_chain_falls_short(966140, 966132));
    ck("with no announced height nothing falls short", !dlc_chain_falls_short(5, 0));
    printf("%s (%d failure(s))\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
