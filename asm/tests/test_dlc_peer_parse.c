/* The boot-time parallel downloader (dlc_*) dials peers from the address
 * pool, whose entries are "ip[:port]". Both of its dial sites parsed them
 * with inet_pton(), which rejects the ":port" suffix -- so from the day the
 * book started carrying ports (2026-08-28), EVERY header try and EVERY chunk
 * dial failed before connecting, silently. Production's boot log read
 * "[dlc] archive already complete through 964471" while the tip was 964,8xx;
 * a fresh signet node read "complete through 0" with 190k blocks to fetch,
 * and fell back to the serial legs at ~6 blocks/s. Restoring the parser gave
 * ~50 blocks/s on the same segment.
 *
 * dlc_parse_peer is static in daemon/main.c; include the TU (the
 * test_dial_budget pattern). */
#include <stdio.h>
#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main

static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c?"ok ":"FAIL", w); if(!c) fails++; }

int main(void){
    unsigned ip; int port;
    printf("== the forms the pool actually produces ==\n");
    ip=0; port=-1;
    ok(dlc_parse_peer("173.201.39.135:38333", &ip, &port) && port == 38333 && ip != 0,
       "ip:port parses, with its port (the form that was rejected)");
    ok(inet_pton(AF_INET, "173.201.39.135:38333", &(unsigned){0}) != 1,
       "  (and inet_pton indeed rejects it -- which is the whole bug)");
    ip=0; port=-1;
    ok(dlc_parse_peer("173.201.39.135", &ip, &port) && port == 0 && ip != 0,
       "a bare ip parses with port 0, meaning 'use the chain default'");
    printf("== what must be refused ==\n");
    ok(!dlc_parse_peer("", &ip, &port), "empty");
    ok(!dlc_parse_peer("not.a.host:8333", &ip, &port), "a hostname (the pool holds addresses)");
    ok(!dlc_parse_peer("[::1]:8333", &ip, &port), "IPv6 (the dlc dialer is IPv4-only, and says so by refusing)");
    printf("\n%s (%d failure%s)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails, fails==1?"":"s");
    return fails ? 1 : 0;
}
