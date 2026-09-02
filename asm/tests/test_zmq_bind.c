/* tests/test_zmq_bind.c -- the ZMQ publisher refuses an ambiguous bind
 * (audit 2026-08-29 finding 8).
 *
 * There is NO authentication on a ZMQ publisher: whoever connects,
 * subscribes. the wildcard bind (`tcp:` + `//` + `*:28332`) is the spelling every tutorial uses, and on a
 * node like this one it hands every block and transaction to the whole LAN --
 * a blast radius the operator inherited rather than chose.
 *
 * So `*` is refused and an explicit interface is required. The capability is
 * not removed: 0.0.0.0 still binds everything for anyone who means it. The
 * pairing below is the point -- a check that refused every address would pass
 * the refusal half of this test and be useless.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern int  zmqpub_add(const char* topic, const char* addr);
extern int  zmqpub_active(void);
extern void zmqpub_close(void);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

/* a port nothing else on the box is using */
static int free_port(void){
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(s, (struct sockaddr*)&a, sizeof a);
    socklen_t al = sizeof a; getsockname(s, (struct sockaddr*)&a, &al);
    int p = ntohs(a.sin_port);
    close(s);
    return p;
}

int main(void){
    char addr[64];
    int port = free_port();

    printf("== the wildcard spelling is refused ==\n");
    snprintf(addr, sizeof addr, "tcp://*:%d", port);
    ck("tcp://*:PORT is rejected", zmqpub_add("hashblock", addr) == 0);
    ck("  and no publisher was started", zmqpub_active() == 0);

    printf("== an explicit interface still works ==\n");
    snprintf(addr, sizeof addr, "tcp://127.0.0.1:%d", port);
    ck("tcp://127.0.0.1:PORT is accepted", zmqpub_add("hashblock", addr) == 1);
    ck("  and the publisher is active", zmqpub_active() == 1);
    { /* it really is listening, and only on loopback */
      int s = socket(AF_INET, SOCK_STREAM, 0);
      struct sockaddr_in a; memset(&a, 0, sizeof a);
      a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port);
      inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
      ck("  a subscriber can connect on loopback", connect(s,(struct sockaddr*)&a,sizeof a) == 0);
      close(s); }
    zmqpub_close();

    printf("== 0.0.0.0 is still available for those who mean it ==\n");
    /* The fix must not remove the capability, only the ambiguous spelling. */
    port = free_port();
    snprintf(addr, sizeof addr, "tcp://0.0.0.0:%d", port);
    ck("tcp://0.0.0.0:PORT is accepted", zmqpub_add("rawtx", addr) == 1);
    zmqpub_close();

    printf("== malformed addresses are still rejected ==\n");
    ck("a non-tcp scheme is rejected", zmqpub_add("hashblock", "ipc:///tmp/x") == 0);
    ck("a missing port is rejected", zmqpub_add("hashblock", "tcp://127.0.0.1") == 0);
    ck("a bad host is rejected", zmqpub_add("hashblock", "tcp://not-an-ip:28332") == 0);
    ck("an unknown topic is rejected", zmqpub_add("nosuchtopic", "tcp://127.0.0.1:28332") == 0);

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
