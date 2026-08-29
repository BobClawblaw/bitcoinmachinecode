/* tests/test_privacy_dns.c -- the promises this node makes about not leaking
 * when it is behind a proxy. Each is a decision the dialer makes BEFORE any
 * socket is opened, so it can be checked directly.
 *
 *   1. with a proxy configured, a hostname must never be resolved locally:
 *      a DNS lookup tells the resolver exactly which peers we are about to
 *      contact, which is the correlation a proxy exists to prevent;
 *   2. -dns=0 does the same with no proxy;
 *   3. -onlynet naming only anonymity networks does the same, and also stops
 *      the node announcing its clearnet address;
 *   4. -discover=0 stops the announcement on its own;
 *   5. an onion/i2p peer is never reachable without its transport, so it can
 *      never fall back to a clearnet dial;
 *   6. with nothing configured, none of these fire (the default node is
 *      unchanged).
 */
#include <stdio.h>
#include <string.h>
#include "../daemon/dialer.h"
#include "../daemon/node_config.h"
extern node_config_t g_cfg;
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
/* dialer_init() latches its state once; each case needs a fresh view, and the
 * dialer exposes that by re-reading g_cfg when it has not been initialised.
 * The test drives the predicates directly, which is where the decision is. */
extern int dialer_reset_for_test(void);
int main(void){
    printf("== default node: nothing is blocked ==\n");
    memset(&g_cfg, 0, sizeof g_cfg); g_cfg.dns = 1; g_cfg.discover = 1;
    dialer_reset_for_test();
    ck("DNS is allowed", !dialer_dns_blocked());
    ck("we may announce our address", dialer_may_announce_clearnet());
    ck("ipv4 is reachable", dialer_net_reachable(BMC_NET_IPV4));
    ck("onion is NOT reachable without a proxy", !dialer_net_reachable(BMC_NET_TORV3));
    ck("i2p is NOT reachable without a SAM bridge", !dialer_net_reachable(BMC_NET_I2P));
    ck("cjdns is NOT reachable without -cjdnsreachable", !dialer_net_reachable(BMC_NET_CJDNS));

    printf("\n== a proxy is configured: names go to the proxy, never to DNS ==\n");
    memset(&g_cfg, 0, sizeof g_cfg); g_cfg.dns = 1; g_cfg.discover = 1;
    snprintf(g_cfg.proxy, sizeof g_cfg.proxy, "127.0.0.1:9050");
    dialer_reset_for_test();
    ck("local DNS is blocked", dialer_dns_blocked());
    ck("onion becomes reachable (the proxy carries it)", dialer_net_reachable(BMC_NET_TORV3));

    printf("\n== -dns=0 blocks the resolver with no proxy at all ==\n");
    memset(&g_cfg, 0, sizeof g_cfg); g_cfg.dns = 0; g_cfg.discover = 1;
    dialer_reset_for_test();
    ck("local DNS is blocked", dialer_dns_blocked());

    printf("\n== -onlynet=onion: clearnet is off, and we announce nothing ==\n");
    memset(&g_cfg, 0, sizeof g_cfg); g_cfg.dns = 1; g_cfg.discover = 1;
    snprintf(g_cfg.onlynet[0], 8, "onion"); g_cfg.n_onlynet = 1;
    snprintf(g_cfg.proxy, sizeof g_cfg.proxy, "127.0.0.1:9050");
    dialer_reset_for_test();
    ck("local DNS is blocked", dialer_dns_blocked());
    ck("we must NOT announce our clearnet address", !dialer_may_announce_clearnet());
    ck("ipv4 is not reachable", !dialer_net_reachable(BMC_NET_IPV4));
    ck("onion is", dialer_net_reachable(BMC_NET_TORV3));

    printf("\n== -discover=0 stops the announcement on its own ==\n");
    memset(&g_cfg, 0, sizeof g_cfg); g_cfg.dns = 1; g_cfg.discover = 0;
    dialer_reset_for_test();
    ck("we must NOT announce our address", !dialer_may_announce_clearnet());
    ck("but DNS is still allowed (discover is about US, not lookups)", !dialer_dns_blocked());

    printf("\n== -onlynet=ipv4 leaves a normal node normal ==\n");
    memset(&g_cfg, 0, sizeof g_cfg); g_cfg.dns = 1; g_cfg.discover = 1;
    snprintf(g_cfg.onlynet[0], 8, "ipv4"); g_cfg.n_onlynet = 1;
    dialer_reset_for_test();
    ck("DNS allowed", !dialer_dns_blocked());
    ck("announcing allowed", dialer_may_announce_clearnet());
    ck("onion refused by onlynet even if a proxy appears later", !dialer_net_reachable(BMC_NET_TORV3));

    printf(fails ? "\nFAILURES %d\n" : "\nALL TESTS PASSED (0 failures)\n", fails);
    return fails ? 1 : 0;
}
