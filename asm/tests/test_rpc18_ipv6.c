/* tests/test_rpc18_ipv6.c -- RPC-18: the RPC listener binds IPv6.
 *
 * It was AF_INET only: `rpcbind=::1` was a startup error, every IPv6
 * -rpcallowip entry was unreachable, and rpc_acl.c's ::1 default could never
 * match anything.
 *
 * The listener is family-aware now, chosen by the CONFIGURED ADDRESS rather
 * than by a flag, and IPV6_V6ONLY is forced on so a v6 socket never accepts
 * v4-mapped peers -- an ACL rule written as 127.0.0.1 must not have to also
 * match ::ffff:127.0.0.1.
 *
 * The opposite half matters as much as the new capability: with no -rpcbind
 * the default MUST still be IPv4 loopback. An existing deployment must not
 * quietly start listening somewhere else because this landed.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../rpc_server.h"

static int fails = 0, checks = 0;
static void ck(const char* label, int cond){
    checks++;
    printf("%s %s\n", cond ? "ok  :" : "FAIL:", label);
    if (!cond) fails++;
}

static int allow_all(const char* ip){ (void)ip; return 1; }

/* Connect to (family, addr, port) and send a minimal unauthenticated POST.
 * Any HTTP response proves the listener is reachable on that family; the
 * status does not matter here (401 is expected without credentials). */
static int reachable(int family, const char* addr, int port){
    int s = socket(family, SOCK_STREAM, 0);
    if (s < 0) return 0;
    struct timeval tv = { 3, 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int rc;
    if (family == AF_INET6){
        struct sockaddr_in6 a; memset(&a, 0, sizeof a);
        a.sin6_family = AF_INET6; a.sin6_port = htons((unsigned short)port);
        inet_pton(AF_INET6, addr, &a.sin6_addr);
        rc = connect(s, (struct sockaddr*)&a, sizeof a);
    } else {
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port);
        inet_pton(AF_INET, addr, &a.sin_addr);
        rc = connect(s, (struct sockaddr*)&a, sizeof a);
    }
    if (rc != 0){ close(s); return 0; }
    const char* req =
        "POST / HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n"
        "Content-Length: 2\r\nConnection: close\r\n\r\n{}";
    if (write(s, req, strlen(req)) < 0){ close(s); return 0; }
    char buf[128] = {0};
    ssize_t n = read(s, buf, sizeof buf - 1);
    close(s);
    return n > 0 && strncmp(buf, "HTTP/1.1", 8) == 0;
}

static int start(const char* bind_addr, int* port_out, char* err, size_t errcap){
    rpc_server_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.port = 0;                    /* ephemeral */
    cfg.user = "u"; cfg.pass = "p";
    cfg.bind_addr = bind_addr;
    cfg.allows = allow_all;
    cfg.threads = 2; cfg.workqueue = 4; cfg.timeout_s = 5;
    err[0] = 0;
    return rpc_server_start(&cfg, port_out, err, errcap);
}

int main(void){
    char err[256]; int port = 0;

    printf("== default (no -rpcbind): IPv4 loopback, unchanged ==\n");
    ck("server starts with no bind address", start(NULL, &port, err, sizeof err) == 0);
    ck("...on a real port", port > 0);
    ck("...reachable over IPv4 loopback", reachable(AF_INET, "127.0.0.1", port));
    ck("...and NOT over IPv6 (it is an AF_INET socket)",
       !reachable(AF_INET6, "::1", port));
    rpc_server_stop();

    printf("\n== RPC-18: rpcbind=::1 ==\n");
    port = 0;
    int rc = start("::1", &port, err, sizeof err);
    ck("RPC-18: rpcbind=::1 is accepted, not a startup error", rc == 0);
    if (rc != 0) printf("      err: %s\n", err);
    ck("...on a real port", port > 0);
    ck("RPC-18: reachable over IPv6 loopback", reachable(AF_INET6, "::1", port));
    /* IPV6_V6ONLY is forced, so the v6 listener must NOT answer on v4 */
    ck("RPC-18: V6ONLY -- the v6 listener does not answer IPv4",
       !reachable(AF_INET, "127.0.0.1", port));
    rpc_server_stop();

    printf("\n== an explicit IPv4 bind still works ==\n");
    port = 0;
    ck("rpcbind=127.0.0.1 starts", start("127.0.0.1", &port, err, sizeof err) == 0);
    ck("...reachable over IPv4", reachable(AF_INET, "127.0.0.1", port));
    rpc_server_stop();

    printf("\n== malformed addresses are refused with ONE clear message ==\n");
    port = 0;
    ck("a malformed IPv6 is refused", start("::nonsense::", &port, err, sizeof err) != 0);
    ck("...naming IPv6, since the value contains ':'",
       strstr(err, "IPv6") != NULL);
    if (!strstr(err, "IPv6")) printf("      err: %s\n", err);
    port = 0;
    ck("a malformed IPv4 is refused", start("999.1.2.3", &port, err, sizeof err) != 0);
    ck("...naming IPv4, and saying how to write an IPv6 address",
       strstr(err, "IPv4") != NULL && strstr(err, "':'") != NULL);
    if (!strstr(err, "IPv4")) printf("      err: %s\n", err);

    printf("\n%s (%d checks, %d failures)\n",
           fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
