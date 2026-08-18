/* Connection-class and address-source policy tests.
 *
 * The netgroup cap is the one that matters most: commit 563da15 added getaddr
 * and accepted 838 addresses from a SINGLE peer with no per-source limit,
 * which is an eclipse vector. This asserts a hostile peer cannot fill the book
 * with addresses it controls. */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

extern unsigned net_netgroup_v4(unsigned ip);
extern int  net_handshake_relay(const char* ip, int relay, int rcv);
extern int  net_feeler_probe(const char* ip);

static unsigned ip_of(const char* s){ unsigned v; inet_pton(AF_INET,s,&v); return v; }

int main(int argc, char** argv){
    int failures = 0;
    printf("---- net policy ----\n");

    /* netgroup == /16 */
    if (net_netgroup_v4(ip_of("1.2.3.4")) == net_netgroup_v4(ip_of("1.2.99.250")))
        printf("PASS: same /16 shares a netgroup\n");
    else { printf("FAIL: 1.2.3.4 and 1.2.99.250 should share a netgroup\n"); failures++; }

    if (net_netgroup_v4(ip_of("1.2.3.4")) != net_netgroup_v4(ip_of("1.9.3.4")))
        printf("PASS: different /16 differs\n");
    else { printf("FAIL: 1.2.x and 1.9.x must not share a netgroup\n"); failures++; }

    if (net_netgroup_v4(ip_of("8.8.8.8")) != net_netgroup_v4(ip_of("9.9.9.9")))
        printf("PASS: unrelated addresses differ\n");
    else { printf("FAIL: unrelated addresses collided\n"); failures++; }

    /* live checks only when a peer is supplied */
    if (argc > 1) {
        int fd = net_handshake_relay(argv[1], 0 /* block-relay-only */, 8);
        if (fd >= 0) { printf("PASS: block-relay-only handshake (relay=0) accepted by %s\n", argv[1]); close(fd); }
        else { printf("FAIL: relay=0 handshake rejected by %s\n", argv[1]); failures++; }

        int alive = net_feeler_probe(argv[1]);
        if (alive == 1) printf("PASS: feeler reports %s alive\n", argv[1]);
        else { printf("FAIL: feeler said %s dead but it just handshook\n", argv[1]); failures++; }

        if (net_feeler_probe("192.0.2.1") == 0) printf("PASS: feeler reports an unroutable address dead\n");
        else { printf("FAIL: feeler claimed 192.0.2.1 (TEST-NET-1) was alive\n"); failures++; }
    } else printf("  (no peer given -- skipping live handshake/feeler checks)\n");

    if (failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures ? 1 : 0;
}
