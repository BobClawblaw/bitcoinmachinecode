/* tests/test_rpc_acl.c -- Core's -rpcallowip / -rpcbind rules.
 *
 * The default must not move. With nothing configured the allow list is
 * loopback only, and -rpcbind is ignored -- that is Core's behaviour and it is
 * also this node's behaviour before these options existed, so a regression
 * here would quietly widen a live node's RPC exposure.
 */
#include <stdio.h>
#include <string.h>
#include "../daemon/rpc_acl.h"

static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c?"ok ":"FAIL", w); if(!c) fails++; }

int main(void){
    printf("== with nothing configured, loopback only (Core's base list) ==\n");
    rpc_acl_reset();
    ok(rpc_acl_allows("127.0.0.1"), "127.0.0.1 is allowed");
    ok(rpc_acl_allows("127.0.0.2"), "127.0.0.2 too -- Core allows 127.0.0.0/8, not /32");
    ok(rpc_acl_allows("127.255.255.254"), "and the rest of 127.0.0.0/8");
    ok(rpc_acl_allows("::1"), "::1 is allowed");
    ok(!rpc_acl_allows("192.168.1.5"), "a LAN address is not");
    ok(!rpc_acl_allows("8.8.8.8"), "a public address is not");
    ok(!rpc_acl_allows("::2"), "another v6 address is not");
    ok(rpc_acl_configured() == 0, "and nothing counts as configured");

    printf("== a configured subnet is added, loopback still allowed ==\n");
    rpc_acl_reset();
    ok(rpc_acl_add("192.168.1.0/24"), "192.168.1.0/24 is accepted");
    ok(rpc_acl_configured() == 1, "it counts as configured (this is what ungates rpcbind)");
    ok(rpc_acl_allows("192.168.1.5"), "an address inside it is allowed");
    ok(!rpc_acl_allows("192.168.2.5"), "one outside it is not");
    ok(rpc_acl_allows("127.0.0.1"), "loopback is STILL allowed, never displaced");

    printf("== IPv6 and odd prefixes, via the shared matcher ==\n");
    rpc_acl_reset();
    ok(rpc_acl_add("2001:db8::/32"), "an IPv6 subnet is accepted");
    ok(rpc_acl_allows("2001:db8::5"), "an address inside it is allowed");
    ok(!rpc_acl_allows("2001:db9::5"), "one outside it is not");
    rpc_acl_reset();
    ok(rpc_acl_add("10.0.0.16/28"), "a non-byte-aligned /28 is accepted");
    ok(rpc_acl_allows("10.0.0.31"), "  .31 is inside");
    ok(!rpc_acl_allows("10.0.0.32"), "  .32 is outside");

    printf("== a malformed entry is REFUSED, so startup can abort ==\n");
    rpc_acl_reset();
    ok(!rpc_acl_add("not-an-address"), "a hostname is refused");
    ok(!rpc_acl_add("1.2.3.4/33"), "an impossible prefix is refused");
    ok(!rpc_acl_add(""), "empty is refused");
    ok(rpc_acl_configured() == 0, "and none of them was counted as configured");
    ok(!rpc_acl_allows("1.2.3.4"), "so nothing extra became reachable");

    printf("== an unreset list never fails open ==\n");
    /* If a caller forgets rpc_acl_reset(), the list must still deny, not
     * allow everything -- the direction of that mistake decides whether it is
     * a bug or an incident. */
    ok(rpc_acl_allows("127.0.0.1") && !rpc_acl_allows("8.8.8.8"),
       "a fresh list denies non-loopback rather than allowing all");

    printf("\n%s (%d failure%s)\n", fails?"TESTS FAILED":"ALL TESTS PASSED",
           fails, fails==1?"":"s");
    return fails ? 1 : 0;
}
