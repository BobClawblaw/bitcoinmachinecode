/* Connection-class and address-source policy tests.
 *
 * The netgroup cap is the one that matters most: commit 563da15 added getaddr
 * and accepted 838 addresses from a SINGLE peer with no per-source limit,
 * which is an eclipse vector. This asserts a hostile peer cannot fill the book
 * with addresses it controls.
 *
 * 2026-11-06: the feeler against a loopback peer, with no argument needed.
 * It handed the pool's "a.b.c.d:port" to inet_pton and failed before dialing
 * (production: 23,687 feelers, 0 alive), and it sent a hand-built
 * /Satoshi:25.0.0/ version with fRelay=1. It now sends the registered
 * builder's version (the daemon's node_make_version) with fRelay=0. */
#define _GNU_SOURCE   /* memmem */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <poll.h>
#include <unistd.h>

extern unsigned net_netgroup_v4(unsigned ip);
extern int  net_handshake_relay(const char* ip, int relay, int rcv);
extern int  net_feeler_probe(const char* ip);
extern void net_policy_set_version(long (*build)(unsigned char* out), unsigned short default_port);
extern int  net_parse_v4(const char* s, unsigned* ip, unsigned short* port);
extern long p2p_write(int,const char*,unsigned,const void*,unsigned);
extern int  p2p_read(int,char[12],void*,unsigned,unsigned*);

static unsigned ip_of(const char* s){ unsigned v; inet_pton(AF_INET,s,&v); return v; }

/* a stand-in for node_make_version: a recognisable agent, fRelay=1 */
static const char TEST_UA[] = "/TestBuilder:9.9.9/";
static long test_builder(unsigned char* out){
    memset(out, 0, 80);
    out[0] = 0x80; out[1] = 0x11; out[2] = 0x01;          /* 70016 */
    out[4] = 0x09;                                         /* services: NETWORK|WITNESS */
    memcpy(out + 72, "\x5a\xa5\x5a\xa5\x01\x02\x03\x04", 8);  /* nonce */
    long o = 80; out[o++] = (unsigned char)strlen(TEST_UA);
    memcpy(out + o, TEST_UA, strlen(TEST_UA)); o += (long)strlen(TEST_UA);
    out[o++] = 0x10; out[o++] = 0x27; out[o++] = 0; out[o++] = 0;   /* start height 10000 */
    out[o++] = 1;                                          /* fRelay */
    return o;
}

/* one-connection loopback peer: records the version it receives, answers verack */
typedef struct { int lfd; int accepted; unsigned char got[600]; unsigned glen; } fake_peer_t;
static void* fake_peer(void* arg){
    fake_peer_t* fp = arg;
    struct pollfd pf = { fp->lfd, POLLIN, 0 };
    if (poll(&pf, 1, 3000) <= 0) return NULL;
    int c = accept(fp->lfd, NULL, NULL); if (c < 0) return NULL;
    fp->accepted = 1;
    struct timeval tv = { 3, 0 }; setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char cmd[12]; unsigned plen = 0;
    if (p2p_read(c, cmd, fp->got, sizeof fp->got, &plen) > 0 && !strncmp(cmd, "version", 7)){
        fp->glen = plen;
        p2p_write(c, "verack", 6, "", 0);
        p2p_read(c, cmd, fp->got + 300, 200, &plen);       /* our verack */
    }
    close(c);
    return NULL;
}
static int listen_lo(unsigned short* port){
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr*)&a, sizeof a) || listen(s, 4)) return -1;
    socklen_t al = sizeof a; getsockname(s, (struct sockaddr*)&a, &al); *port = ntohs(a.sin_port);
    return s;
}

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

    /* "a.b.c.d[:port]" */
    { unsigned ip = 0; unsigned short port = 0;
      net_policy_set_version(NULL, 18444);
      int ok = net_parse_v4("10.1.2.3:38333", &ip, &port) && ip == ip_of("10.1.2.3") && port == 38333;
      ok = ok && net_parse_v4("10.1.2.3", &ip, &port) && port == 18444;     /* a bare address: the chain's default */
      ok = ok && !net_parse_v4("10.1.2.3:", &ip, &port) && !net_parse_v4("10.1.2.3:70000", &ip, &port)
              && !net_parse_v4("10.1.2.3:12x", &ip, &port) && !net_parse_v4("[::1]:8333", &ip, &port) && !net_parse_v4("", &ip, &port);
      if (ok) printf("PASS: addresses parse with and without a port; malformed ones are refused\n");
      else { printf("FAIL: net_parse_v4\n"); failures++; } }

    /* the feeler against a loopback peer */
    { unsigned short port = 0; int lfd = listen_lo(&port);
      if (lfd < 0){ printf("FAIL: no loopback listener\n"); return 1; }
      char target[64]; snprintf(target, sizeof target, "127.0.0.1:%u", (unsigned)port);
      fake_peer_t fp; memset(&fp, 0, sizeof fp); fp.lfd = lfd;
      pthread_t th; pthread_create(&th, NULL, fake_peer, &fp);
      int alive = net_feeler_probe(target);                 /* no builder registered yet */
      pthread_join(th, NULL);
      if (!alive && !fp.accepted) printf("PASS: without a version builder the feeler makes no connection\n");
      else { printf("FAIL: a feeler connected with no version builder (alive=%d accepted=%d)\n", alive, fp.accepted); failures++; }

      net_policy_set_version(test_builder, 18444);
      memset(&fp, 0, sizeof fp); fp.lfd = lfd;
      pthread_create(&th, NULL, fake_peer, &fp);
      alive = net_feeler_probe(target);
      pthread_join(th, NULL);
      if (alive == 1) printf("PASS: the feeler reaches %s (\"a.b.c.d:port\") and reports it alive\n", target);
      else { printf("FAIL: the feeler reported a live loopback peer dead (accepted=%d)\n", fp.accepted); failures++; }
      unsigned char want[600]; long wl = test_builder(want); want[wl - 1] = 0;
      if (fp.glen == (unsigned)wl && !memcmp(fp.got, want, (size_t)wl))
          printf("PASS: it sent the builder's version byte for byte, fRelay=0 (Core: a feeler rejects incoming txs)\n");
      else { printf("FAIL: the version the peer received is not the builder's with fRelay=0 (%u bytes, want %ld; relay byte %d)\n",
                    fp.glen, wl, fp.glen ? fp.got[fp.glen - 1] : -1); failures++; }
      if (fp.glen > 81 && fp.got[80] == strlen(TEST_UA) && !memcmp(fp.got + 81, TEST_UA, strlen(TEST_UA)) && !memmem(fp.got, fp.glen, "Satoshi", 7))
          printf("PASS: its user agent is the builder's, not a /Satoshi:/ one\n");
      else { printf("FAIL: the user agent is not the builder's\n"); failures++; }
      close(lfd); }

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
