/* tests/test_rpc_intake.c -- RPC-24 (audit 2026-10-23): the JSON-RPC
 * intake under sockets that dribble their headers.
 *
 * Requests are read on the -rpcthreads intake workers (4 here, Core's
 * default), so four allowed sockets sending a header byte at a time held all
 * of them until the 60 s request deadline (RPC-4's residual). Now one source
 * address reads on at most threads - 1 workers (127.0.0.1 and ::1 exempt:
 * every local client shares them), and the headers must arrive within 15 s.
 * The server runs in this process with a canned rpc_dispatch; the "remote"
 * hosts are 127.0.0.2 and 127.0.0.3, which the exemption does not cover. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../rpc_json.h"
#include "../rpc_server.h"

static int fails = 0, checks = 0;
static void ok(int c, const char* w){ checks++; printf("  %s %s\n", c ? "ok  " : "FAIL", w); if (!c) fails++; }

/* ---- the canned node (what rpc_server.o, rpc_esplora.o and rest.o reach) ---- */
int wallet_validate_address(const char* a, int* t, unsigned char* v, unsigned char h[20], unsigned char p[32]){ (void)a; (void)t; (void)v; (void)h; (void)p; return 0; }
long axt_read_events(int type, const unsigned char hash[32], long min_height,
                     int (*cb)(void*, int, const unsigned char*, unsigned, unsigned long long, unsigned), void* ctx){
    (void)type; (void)hash; (void)min_height; (void)cb; (void)ctx; return 0; }
int rpc_chain_method_lane(const char* m){ (void)m; return 0; }
int rpc_chain_method_lane_p(const char* m, const rj_val* p){ (void)m; (void)p; return 0; }
int rpc_dispatch(const char* method, const rj_val* params, const rpc_wallet* w, rj_val** result, long* ec, const char** em){
    (void)params; (void)w;
    if (!strcmp(method, "getblockcount")){ *result = rj_numf("%d", 7); return 1; }
    *ec = -32601; *em = "Method not found"; return 0;
}
static int allow_all(const char* ip){ (void)ip; return 1; }

static int g_port;
static double now_s(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (double)t.tv_sec + (double)t.tv_nsec / 1e9; }
static int dial_from(const char* src){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in s; memset(&s, 0, sizeof s); s.sin_family = AF_INET; inet_pton(AF_INET, src, &s.sin_addr);
    if (bind(fd, (struct sockaddr*)&s, sizeof s) != 0){ perror("bind source"); close(fd); return -1; }
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = htons((unsigned short)g_port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr*)&a, sizeof a) != 0){ close(fd); return -1; }
    return fd;
}
/* wait up to wait_s for the server to say something; returns its first bytes ("" on silence) */
static void first_words(int fd, double wait_s, char* out, size_t cap){
    out[0] = 0;
    struct pollfd p = { fd, POLLIN, 0 };
    if (poll(&p, 1, (int)(wait_s * 1000)) > 0){ ssize_t k = recv(fd, out, cap - 1, MSG_DONTWAIT); out[k > 0 ? k : 0] = 0; }
}
static volatile int g_stop = 0;
static void* dribbler(void* arg){
    int fd = (int)(long)arg;
    const char* h = "POST / HTTP/1.1\r\nX-Slow: ";
    if (write(fd, h, strlen(h)) < 0) return 0;
    while (!g_stop){ if (send(fd, "a", 1, MSG_NOSIGNAL) != 1) break; struct timespec ts = { 0, 300 * 1000 * 1000 }; nanosleep(&ts, 0); }
    return 0;
}
static int honest_call(const char* src, double wait_s, char* out, size_t cap){
    int fd = dial_from(src); if (fd < 0) return -1;
    const char* body = "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getblockcount\",\"params\":[]}";
    char req[512]; int l = snprintf(req, sizeof req, "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dTpw\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s", strlen(body), body);
    if (write(fd, req, (size_t)l) != l){ close(fd); return -1; }
    first_words(fd, wait_s, out, cap); close(fd);
    return 0;
}

int main(void){
    printf("---- RPC-24: the JSON-RPC intake ----\n");
    setenv("BMC_RPC_REQ_DEADLINE_SECS", "60", 1);           /* the default, stated */
    rpc_server_cfg cfg; memset(&cfg, 0, sizeof cfg);
    cfg.port = 0; cfg.user = "u"; cfg.pass = "p"; cfg.bind_addr = "127.0.0.1"; cfg.allows = allow_all; cfg.threads = 4; cfg.workqueue = 64; cfg.timeout_s = 30;
    char err[256] = ""; int port = 0;
    if (rpc_server_start(&cfg, &port, err, sizeof err) != 0){ printf("  FAIL rpc_server_start: %s\n", err); return 1; }
    g_port = port;
    char buf[4096];
    honest_call("127.0.0.3", 5, buf, sizeof buf);
    ok(strstr(buf, "HTTP/1.1 200") == buf && strstr(buf, "\"result\":7"), "an honest call answers (200, result 7)");

    /* four dribblers from one remote host: three read, the fourth is refused */
    int fd[4]; pthread_t th[4];
    for (int i = 0; i < 4; i++){ fd[i] = dial_from("127.0.0.2"); pthread_create(&th[i], 0, dribbler, (void*)(long)fd[i]); struct timespec ts = { 0, 100 * 1000 * 1000 }; nanosleep(&ts, 0); }
    first_words(fd[3], 2, buf, sizeof buf);
    ok(strstr(buf, "503") && strstr(buf, "Too many connections from this host"), "a fourth dribbling socket from the same host gets 503 at once");
    double t0 = now_s(); honest_call("127.0.0.3", 5, buf, sizeof buf); double took = now_s() - t0;
    ok(strstr(buf, "HTTP/1.1 200") == buf, "with that host's three dribblers reading, another host's call is answered");
    printf("      answered after %.2f s: %.20s\n", took, buf);
    g_stop = 1; for (int i = 0; i < 4; i++){ pthread_join(th[i], 0); close(fd[i]); } g_stop = 0;
    { struct timespec ts = { 0, 500 * 1000 * 1000 }; nanosleep(&ts, 0); }

    /* the local address is exempt from the per-host rule, and the header deadline bounds it */
    int lfd = -1; pthread_t lth;
    { lfd = dial_from("127.0.0.1"); pthread_create(&lth, 0, dribbler, (void*)(long)lfd);
      int extra[3]; pthread_t eth[3];
      for (int i = 0; i < 3; i++){ extra[i] = dial_from("127.0.0.1"); pthread_create(&eth[i], 0, dribbler, (void*)(long)extra[i]); }
      first_words(extra[2], 1.5, buf, sizeof buf);
      ok(buf[0] == 0, "four dribblers from 127.0.0.1 are not refused by the per-host rule (local clients share it)");
      double t1 = now_s(); first_words(lfd, 25, buf, sizeof buf); double waited = now_s() - t1 + 1.5;
      ok(strstr(buf, "408") != NULL && waited < 20, "...and each is cut off by the 15 s header deadline (408), not the 60 s request one");
      printf("      the first answered after %.1f s: %.30s\n", waited, buf);
      g_stop = 1; pthread_join(lth, 0); for (int i = 0; i < 3; i++){ pthread_join(eth[i], 0); close(extra[i]); } close(lfd); g_stop = 0; }

    rpc_server_stop();
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
