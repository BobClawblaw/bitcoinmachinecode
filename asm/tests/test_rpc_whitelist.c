/* tests/test_rpc_whitelist.c -- -rpcwhitelist / -rpcwhitelistdefault /
 * -rpcthreads / -rpcworkqueue / -rpcservertimeout on the REAL server
 * (daemon/bitcoin_rpcd, driven over raw HTTP), 2026-09-01.
 *   1. a whitelisted user may call only the listed methods: others get
 *      HTTP 403 with an empty body, exactly Core's answer;
 *   2. with a whitelist for SOME OTHER user, an unlisted user may call
 *      nothing (Core's rpcwhitelistdefault=1 rule) ...
 *   3. ... unless rpcwhitelistdefault=0;
 *   4. a small pool (2 threads, queue 4) still answers a burst of
 *      sequential requests correctly. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }
static char raw_out[65536];
static int raw_exchange(int port, const char* req){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr*)&a, sizeof a) < 0){ close(fd); return -1; }
    if (write(fd, req, strlen(req)) != (ssize_t)strlen(req)){ close(fd); return -1; }
    size_t got = 0;
    for (;;){ ssize_t n = read(fd, raw_out + got, sizeof raw_out - 1 - got); if (n <= 0) break; got += (size_t)n; if (got >= sizeof raw_out - 1) break; }
    close(fd); raw_out[got] = 0; return (int)got;
}
/* Same request, but with the JSON body given verbatim -- needed for the batch
 * cases below, which are arrays rather than a single method object. */
static void post_body(char* buf, size_t cap, int port, const char* user, const char* pass, const char* body){
    char cred[256]; snprintf(cred, sizeof cred, "%s:%s", user, pass);
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = strlen(cred), o = 0; char b64[512];
    for (size_t i = 0; i < n; i += 3){ unsigned x = (unsigned char)cred[i], y = i+1<n ? (unsigned char)cred[i+1] : 0, z = i+2<n ? (unsigned char)cred[i+2] : 0;
        b64[o++] = tbl[x>>2]; b64[o++] = tbl[((x&3)<<4)|(y>>4)]; b64[o++] = i+1<n ? tbl[((y&15)<<2)|(z>>6)] : '='; b64[o++] = i+2<n ? tbl[z&63] : '='; }
    b64[o] = 0;
    snprintf(buf, cap, "POST / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nAuthorization: Basic %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", port, b64, strlen(body), body);
}
static void post(char* buf, size_t cap, int port, const char* user, const char* pass, const char* method){
    char cred[256]; snprintf(cred, sizeof cred, "%s:%s", user, pass);
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = strlen(cred), o = 0; char b64[512];
    for (size_t i = 0; i < n; i += 3){ unsigned x = (unsigned char)cred[i], y = i+1<n ? (unsigned char)cred[i+1] : 0, z = i+2<n ? (unsigned char)cred[i+2] : 0;
        b64[o++] = tbl[x>>2]; b64[o++] = tbl[((x&3)<<4)|(y>>4)]; b64[o++] = i+1<n ? tbl[((y&15)<<2)|(z>>6)] : '='; b64[o++] = i+2<n ? tbl[z&63] : '='; }
    b64[o] = 0;
    char body[256]; snprintf(body, sizeof body, "{\"jsonrpc\":\"1.0\",\"id\":\"t\",\"method\":\"%s\",\"params\":[]}", method);
    snprintf(buf, cap, "POST / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nAuthorization: Basic %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", port, b64, strlen(body), body);
}
static int status_of(void){ return atoi(raw_out + 9); }
static pid_t spawn(const char* whitelist, const char* wl_default, const char* threads, const char* queue, int* port_out){
    int pout[2]; if (pipe(pout) < 0){ perror("pipe"); _exit(2); }
    pid_t srv = fork();
    if (srv == 0){
        dup2(pout[1], 2); close(pout[0]); close(pout[1]);
        setenv("TEST_RPC_PORT", "0", 1);
        if (whitelist) setenv("TEST_RPC_WHITELIST", whitelist, 1); else unsetenv("TEST_RPC_WHITELIST");
        if (wl_default) setenv("TEST_RPC_WHITELIST_DEFAULT", wl_default, 1); else unsetenv("TEST_RPC_WHITELIST_DEFAULT");
        if (threads) setenv("TEST_RPC_THREADS", threads, 1);
        if (queue) setenv("TEST_RPC_WORKQUEUE", queue, 1);
        char* argv[] = { (char*)"daemon/bitcoin_rpcd", NULL };
        execv(argv[0], argv); _exit(127);
    }
    close(pout[1]);
    char log[65536]; size_t lgot = 0; int port = -1;
    for (;;){ ssize_t n = read(pout[0], log + lgot, sizeof log - 1 - lgot); if (n <= 0) break; lgot += (size_t)n; log[lgot] = 0;
        char* m = strstr(log, "listening on 127.0.0.1:"); if (m){ port = atoi(m + strlen("listening on 127.0.0.1:")); break; } if (lgot >= sizeof log - 1) break; }
    close(pout[0]);
    *port_out = port;
    return srv;
}
static void stop(pid_t srv){ kill(srv, SIGTERM); waitpid(srv, NULL, 0); }
int main(void){
    char req[4096]; int port;
    printf("== 1. whitelisted user: listed methods 200, others 403 ==\n");
    pid_t s = spawn("bitcoin:help,getblockcount", NULL, NULL, NULL, &port);
    ck("server up", port > 0); if (port <= 0) return 1;
    post(req, sizeof req, port, "bitcoin", "bitcoin", "help"); raw_exchange(port, req);
    ck("help (listed) answers 200", status_of() == 200);
    post(req, sizeof req, port, "bitcoin", "bitcoin", "getnewaddress"); raw_exchange(port, req);
    ck("getnewaddress (unlisted) is refused with HTTP 403", status_of() == 403);
    ck("...with an empty body (Core's reply)", strstr(raw_out, "Content-Length: 0") != NULL);
    post(req, sizeof req, port, "bitcoin", "wrongpass", "getblockcount"); raw_exchange(port, req);
    ck("a bad password is still 401 before any whitelist check", status_of() == 401);

    /* RPC-6: the whitelist is applied to EVERY member of a batch, as Core
     * does ("Check authorization for each request's method", httprpc.cpp).
     * The second assertion is the load-bearing one: before batches existed
     * here every array was rejected outright, so wrapping a forbidden method
     * in one was harmless. Now that arrays execute, a whitelist that only
     * looked at the top-level object would let getnewaddress through beside
     * a permitted help. */
    post_body(req, sizeof req, port, "bitcoin", "bitcoin",
              "[{\"method\":\"help\",\"id\":1},{\"method\":\"getblockcount\",\"id\":2}]");
    raw_exchange(port, req);
    ck("a batch of two LISTED methods is allowed through", status_of() == 200);
    post_body(req, sizeof req, port, "bitcoin", "bitcoin",
              "[{\"method\":\"help\",\"id\":1},{\"method\":\"getnewaddress\",\"id\":2}]");
    raw_exchange(port, req);
    ck("an UNLISTED method buried in a batch still gets the whole batch 403",
       status_of() == 403);
    ck("...with an empty body, like the single-request 403",
       strstr(raw_out, "Content-Length: 0") != NULL);
    stop(s);
    printf("== 2. a whitelist for another user locks unlisted users out (rpcwhitelistdefault) ==\n");
    s = spawn("alice:getblockcount", NULL, NULL, NULL, &port);
    ck("server up", port > 0); if (port <= 0) return 1;
    post(req, sizeof req, port, "bitcoin", "bitcoin", "help"); raw_exchange(port, req);
    ck("user without a whitelist gets 403 for everything", status_of() == 403);
    stop(s);
    printf("== 3. rpcwhitelistdefault=0 lets unlisted users through ==\n");
    s = spawn("alice:getblockcount", "0", NULL, NULL, &port);
    ck("server up", port > 0); if (port <= 0) return 1;
    post(req, sizeof req, port, "bitcoin", "bitcoin", "help"); raw_exchange(port, req);
    ck("unlisted user answers 200 with rpcwhitelistdefault=0", status_of() == 200);
    stop(s);
    /* ---- RPC-14: rpcwhitelistdefault=1 with NO rpcwhitelist entries --------
     * Core: g_rpc_whitelist_default is an explicit -rpcwhitelistdefault when
     * given, else "some whitelist exists". With it set to 1 and no entries,
     * NO user has a whitelist, so every user is "not allowed to call any
     * methods" and every request is 403 -- before the body is even parsed.
     *
     * This node returned 1 (allow) from rpc_whitelist_allows the moment the
     * entry count was zero, so the strictest-looking configuration available
     * allowed EVERYTHING. A fail-open on a security control, which is why
     * this INFO finding was worth doing first. */
    printf("== 3b. RPC-14: rpcwhitelistdefault=1 with NO entries denies everyone ==\n");
    s = spawn(NULL, "1", NULL, NULL, &port);
    ck("server up", port > 0); if (port <= 0) return 1;
    post(req, sizeof req, port, "bitcoin", "bitcoin", "help"); raw_exchange(port, req);
    ck("RPC-14: a listed-nowhere user is refused 403, not allowed", status_of() == 403);
    ck("...with an empty body, like Core", strstr(raw_out, "Content-Length: 0") != NULL);
    post(req, sizeof req, port, "bitcoin", "bitcoin", "getblockcount"); raw_exchange(port, req);
    ck("RPC-14: a second method is refused too (it is not per-method)", status_of() == 403);
    /* the 403 must not depend on the body parsing: Core decides before it
     * looks. An unparseable body from this user is still 403, not -32700. */
    { char cred[64] = "bitcoin:bitcoin"; (void)cred;
      char raw[512];
      /* reuse post() for the headers, then overwrite the body with junk */
      post(req, sizeof req, port, "bitcoin", "bitcoin", "help");
      char* bodyp = strstr(req, "\r\n\r\n");
      if (bodyp){
          snprintf(raw, sizeof raw, "%.*s\r\n\r\n", (int)(bodyp - req), req);
          /* Content-Length no longer matches; the server reads what arrives.
           * What matters is that no JSON body follows at all. */
          raw_exchange(port, raw);
          ck("RPC-14: even an EMPTY body from that user is 403, not a parse error",
             status_of() == 403);
          if (status_of() != 403) printf("      got status %d\n", status_of()); }
    }
    stop(s);

    /* THE OPPOSITE HALF: with the default explicitly 0 and no entries, the
     * server must still serve everyone -- the fix must not deny by default. */
    printf("== 3c. rpcwhitelistdefault=0 with no entries still allows ==\n");
    s = spawn(NULL, "0", NULL, NULL, &port);
    ck("server up", port > 0); if (port <= 0) return 1;
    post(req, sizeof req, port, "bitcoin", "bitcoin", "help"); raw_exchange(port, req);
    ck("rpcwhitelistdefault=0 with no entries answers 200", status_of() == 200);
    stop(s);

    /* and with NEITHER set, the historical behaviour is unchanged: no
     * whitelist configured at all means no whitelisting. */
    printf("== 3d. no whitelist and no default: unchanged ==\n");
    s = spawn(NULL, NULL, NULL, NULL, &port);
    ck("server up", port > 0); if (port <= 0) return 1;
    post(req, sizeof req, port, "bitcoin", "bitcoin", "help"); raw_exchange(port, req);
    ck("an unconfigured server still answers 200", status_of() == 200);
    stop(s);

    printf("== 4. a 2-thread pool with a 4-deep queue serves a burst ==\n");
    s = spawn(NULL, NULL, "2", "4", &port);
    ck("server up", port > 0); if (port <= 0) return 1;
    int okn = 0;
    for (int i = 0; i < 20; i++){ post(req, sizeof req, port, "bitcoin", "bitcoin", "help"); raw_exchange(port, req); if (status_of() == 200) okn++; }
    ck("20 sequential requests all answered 200 through the pool", okn == 20);
    stop(s);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
