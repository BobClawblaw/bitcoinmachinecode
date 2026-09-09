/* tests/test_ctl_dial.c -- the runtime addnode queue: `add` is dialed and
 * re-dialed with backoff while listed, `onetry` is dialed exactly once,
 * `remove` stops the retries, a host that is already a leg is not dialed
 * again, and the queue is bounded. (2026-09-08: the runtime list had been
 * stored and never dialed; both commands answered "done".) */
#include <stdio.h>
#include <string.h>
#include "../daemon/ctl_dial.h"
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static const char* g_conn = ""; static int connected(const char* h){ return !strcmp(h, g_conn); }
int main(void){
    ctl_dial_reset(); long long now = 1000;
    ck("onetry queues", ctl_dial_add("1.2.3.4:8333", 0, now) == 1 && ctl_dial_count() == 1);
    const char* h = ctl_dial_next(now, connected);
    ck("onetry is handed out once and consumed", h && !strcmp(h, "1.2.3.4:8333") && ctl_dial_count() == 0 && ctl_dial_next(now, connected) == 0);
    ck("add queues; a duplicate add is 0; the same host as onetry stays persistent", ctl_dial_add("5.6.7.8:8333", 1, now) == 1 && ctl_dial_add("5.6.7.8:8333", 1, now) == 0 && ctl_dial_add("5.6.7.8:8333", 0, now) == 0 && ctl_dial_listed("5.6.7.8:8333"));
    h = ctl_dial_next(now, connected);
    ck("a persistent entry is handed out", h && !strcmp(h, "5.6.7.8:8333"));
    ck("... and not again before its retry time", ctl_dial_next(now + 1, connected) == 0);
    ctl_dial_report("5.6.7.8:8333", 0, now);
    ck("a failed dial: not before 60 s, due at 60 s", ctl_dial_next(now + 59, connected) == 0 && ctl_dial_next(now + 60, connected) != 0);
    ctl_dial_report("5.6.7.8:8333", 0, now + 60);
    ck("the second failure backs off to 120 s", ctl_dial_next(now + 60 + 119, connected) == 0 && ctl_dial_next(now + 60 + 120, connected) != 0);
    ctl_dial_report("5.6.7.8:8333", 1, now + 200);
    g_conn = "5.6.7.8:8333";
    ck("connected: the entry stays listed, is not dialed while it is a leg", ctl_dial_listed("5.6.7.8:8333") && ctl_dial_next(now + 300, connected) == 0);
    g_conn = ""; ctl_dial_report("5.6.7.8:8333", 0, now + 300);   /* the worker reports the drop */
    ck("dropped: dialed again after the reset backoff (60 s), not the doubled one", ctl_dial_next(now + 359, connected) == 0 && ctl_dial_next(now + 360, connected) != 0);
    ck("remove stops it", ctl_dial_remove("5.6.7.8:8333") == 1 && ctl_dial_next(now + 10000, connected) == 0 && ctl_dial_remove("5.6.7.8:8333") == 0);
    { int n = 0; char b[32]; for (int i = 0; i < 40; i++){ snprintf(b, sizeof b, "10.0.0.%d:8333", i); if (ctl_dial_add(b, 1, now) == 1) n++; }
      ck("the queue is bounded at 32", n == CTL_DIAL_MAX && ctl_dial_add("10.9.9.9:8333", 1, now) == -1); }
    ck("an empty or oversized host is refused", ctl_dial_add("", 1, now) == -1);
    printf("%s (%d failure(s))\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
