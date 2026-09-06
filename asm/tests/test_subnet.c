/* tests/test_subnet.c -- the CIDR matcher shared by -whitelist and the ban list.
 *
 * REGRESSION FIRST. ctl_ban_covers() used to compare dotted-decimal strings,
 * so it matched NOTHING for any prefix that was not a whole number of octets,
 * and nothing at all for IPv6. `setban 2001:db8::/32 add` was accepted,
 * stored and listed -- and never matched a peer. Every case below that a
 * string comparison gets wrong is here on purpose.
 */
#include <stdio.h>
#include <string.h>
#include "../daemon/subnet.h"

static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c?"ok ":"FAIL", w); if(!c) fails++; }
static int cov(const char* net, const char* ip){ return subnet_covers_str(net, ip); }

int main(void){
    printf("== IPv6, which the old matcher could not do at all ==\n");
    ok(cov("2001:db8::/32", "2001:db8::1"),          "2001:db8::1 is in 2001:db8::/32");
    ok(cov("2001:db8::/32", "2001:db8:ffff::9"),     "so is 2001:db8:ffff::9");
    ok(!cov("2001:db8::/32", "2001:db9::1"),         "2001:db9::1 is not");
    ok(cov("::1", "::1"),                            "a bare ::1 host entry matches");
    ok(cov("::1", "[::1]"),                          "and the bracketed spelling");
    ok(!cov("::1", "::2"),                           "::2 does not");
    ok(cov("::/0", "2001:db8::1"),                   "::/0 covers everything v6");

    printf("== prefixes that are NOT a whole number of octets ==\n");
    ok(cov("192.168.1.16/28", "192.168.1.16"),  "/28 lower bound");
    ok(cov("192.168.1.16/28", "192.168.1.31"),  "/28 upper bound");
    ok(!cov("192.168.1.16/28", "192.168.1.32"), "just past a /28");
    ok(!cov("192.168.1.16/28", "192.168.1.15"), "just before a /28");
    ok(cov("10.0.0.0/12", "10.15.255.255"),     "/12 upper bound");
    ok(!cov("10.0.0.0/12", "10.16.0.0"),        "just past a /12");
    ok(cov("172.16.0.0/20", "172.16.15.1"),     "/20 inside");
    ok(!cov("172.16.0.0/20", "172.16.16.1"),    "/20 outside");

    printf("== the byte-aligned cases the old matcher did handle ==\n");
    ok(cov("10.0.0.0/8", "10.1.2.3"),        "/8 inside");
    ok(!cov("10.0.0.0/8", "11.1.2.3"),       "/8 outside");
    ok(cov("192.168.0.0/16", "192.168.9.9"), "/16 inside");
    ok(cov("1.2.3.4/32", "1.2.3.4"),         "/32 exact");
    ok(!cov("1.2.3.4/32", "1.2.3.5"),        "/32 neighbour");
    ok(cov("1.2.3.4", "1.2.3.4"),            "no prefix means a host match");
    ok(cov("0.0.0.0/0", "8.8.8.8"),          "/0 covers everything v4");

    printf("== a sloppy spec is masked, not rejected ==\n");
    ok(cov("10.1.2.3/8", "10.9.9.9"),
       "10.1.2.3/8 means 10.0.0.0/8, as Core's CSubNet does");

    printf("== families never cross ==\n");
    ok(!cov("0.0.0.0/0", "::1"),        "a v4 /0 does not cover a v6 address");
    ok(!cov("::/0", "1.2.3.4"),         "a v6 /0 does not cover a v4 address");
    ok(!cov("::ffff:1.2.3.4", "1.2.3.4"),
       "a v4-mapped v6 entry does not match the bare v4 form");

    printf("== an IPv4 peer string may carry a port ==\n");
    ok(cov("1.2.3.0/24", "1.2.3.4:8333"), "1.2.3.4:8333 is matched by its address");

    printf("== malformed input matches nothing, and says so ==\n");
    subnet_t n;
    ok(!subnet_parse("", &n),                  "empty");
    ok(!subnet_parse("notanaddress", &n),      "a hostname");
    ok(!subnet_parse("1.2.3.4/33", &n),        "an IPv4 prefix over 32");
    ok(!subnet_parse("1.2.3.4/-1", &n),        "a negative prefix");
    ok(!subnet_parse("1.2.3.4/abc", &n),       "a non-numeric prefix");
    ok(!subnet_parse("::1/129", &n),           "an IPv6 prefix over 128");
    ok(!cov("garbage/8", "1.2.3.4"),           "a malformed subnet covers nothing");
    ok(!cov("1.2.3.0/24", "garbage"),          "a malformed address is covered by nothing");

    /* ---- NET-17: what the ban list may and may not hold -------------------
     * ctl_ban_add (daemon/main.c) is gated on subnet_parse, because a key
     * subnet_parse rejects is a key ENFORCEMENT can never match: the entry
     * would sit in the fixed RPC_MAX_BANS list doing nothing, and once that
     * list is full ctl_ban_add returns 0 silently -- so onion violations could
     * crowd out real IP bans.
     *
     * ctl_ban_add itself lives beside main() and cannot be linked into a
     * harness, so what is pinned here is the PROPERTY the gate rests on: the
     * peer descriptors an onion/I2P inbound produces must not parse, and real
     * addresses must. If subnet_parse ever started accepting these, the gate
     * would silently stop gating. */
    ok(!subnet_parse("onion-inbound", &n),     "NET-17: the onion peer descriptor is not a subnet");
    ok(!subnet_parse("i2p-inbound", &n),       "NET-17: the i2p peer descriptor is not a subnet");
    ok(!subnet_parse("vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion", &n),
                                               "NET-17: a base32 onion address is not a subnet");
    ok(subnet_parse("1.2.3.4", &n),            "NET-17: a real IPv4 peer still IS bannable");
    ok(subnet_parse("2001:db8::1", &n),        "NET-17: a real IPv6 peer still IS bannable");
    ok(subnet_parse("1.2.3.0/24", &n),         "NET-17: a real subnet still IS bannable");

    printf("\n%s (%d failure%s)\n", fails?"TESTS FAILED":"ALL TESTS PASSED",
           fails, fails==1?"":"s");
    return fails ? 1 : 0;
}
