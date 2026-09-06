/* tests/test_stale_tip.c -- CC-6: one extra outbound when the tip is stale. */
#include <stdio.h>
#include "stale_tip.h"
static int checks, fails;
static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }
int main(void){
    long now = 1000000000L, H = 900000L;
    printf("== rule: tip older than 30 min, caught up -> +1 outbound ==\n");
    ok(stale_tip_extra_outbound(now, now-31*60, H, H, 1)==1, "31 min old, at best header: extra = 1");
    ok(stale_tip_extra_outbound(now, now-31*60, H, H+1, 1)==1, "31 min old, one behind best header (normal lag): extra = 1");
    ok(stale_tip_extra_outbound(now, now-29*60, H, H, 1)==0, "29 min old: extra = 0");
    ok(stale_tip_extra_outbound(now, now-30*60, H, H, 1)==0, "exactly 30 min: extra = 0 (strictly older)");
    printf("== not during initial block download ==\n");
    ok(stale_tip_extra_outbound(now, now-5*3600, H, H+500, 1)==0, "5 h old but 500 behind best header: catching up, extra = 0");
    ok(stale_tip_extra_outbound(now, now-5*3600, H, -1, 1)==1, "no best header known (fresh boot at tip): tip age decides");
    printf("== no tip yet ==\n");
    ok(stale_tip_extra_outbound(now, 0, H, H, 1)==0, "tip_time 0: extra = 0");
    printf("== negative control: the switch off ==\n");
    ok(stale_tip_extra_outbound(now, now-5*3600, H, H, 0)==0, "control: disabled, 5 h stale, extra = 0 (the pre-CC-6 behaviour)");
    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
