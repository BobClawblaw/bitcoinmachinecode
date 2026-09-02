/* tests/test_i2p_inbound.c -- inbound I2P: a SAM STREAM ACCEPT completed on
 * the acceptor thread reaches the serve loop as a ready socket.
 *
 * Core's i2p.cpp accepts inbound I2P streams with SAM "STREAM ACCEPT"; this
 * node did outbound only until 2026-09-01. The acceptor thread sits in
 * STREAM ACCEPT on the dialer's session and hands every completed stream
 * (fd + the caller's .b32.i2p) down a pipe the serve loop polls beside its
 * listeners. Against a fake SAM bridge: the session comes up, the first
 * stream arrives with the peer's identity and its bytes, and the thread
 * re-arms for the next one. Functions are static in daemon/main.c; the TU
 * is included (the test_dial_budget pattern). */
#include <stdio.h>
#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main
#include "i2p_vec.h"                 /* REAL_DEST_B64 / REAL_B32 */
static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c?"ok ":"FAIL", w); if(!c) fails++; }
static int rdline(int fd, char* b, int cap){ int n = 0; char c; while (n < cap - 1 && read(fd, &c, 1) == 1){ if (c == '\n') break; b[n++] = c; } b[n] = 0; return n; }
static void wr(int fd, const char* s){ (void)!write(fd, s, strlen(s)); }
/* one SAM connection: HELLO, then SESSION CREATE (held open) or STREAM ACCEPT */
static void sam_conn(int c, int nth){
    char l[8192];
    if (rdline(c, l, sizeof l) <= 0) return;
    wr(c, "HELLO REPLY RESULT=OK VERSION=3.1\n");
    if (rdline(c, l, sizeof l) <= 0) return;
    if (!strncmp(l, "SESSION CREATE", 14)){
        char msg[8192]; snprintf(msg, sizeof msg, "SESSION STATUS RESULT=OK DESTINATION=%s\n", REAL_DEST_B64);
        wr(c, msg); rdline(c, l, sizeof l); return;          /* stays open for the session's life */
    }
    if (!strncmp(l, "STREAM ACCEPT", 13)){
        if (nth >= 2) sleep(1);                              /* a later caller takes a moment to arrive */
        wr(c, "STREAM STATUS RESULT=OK\n");
        char msg[8192]; snprintf(msg, sizeof msg, "%s\n", REAL_DEST_B64); wr(c, msg);
        char data[64]; snprintf(data, sizeof data, "peer-bytes-%d", nth); wr(c, data);
        sleep(2); return;
    }
}
static void fake_sam(int ls){
    int nth = 0;
    for (int conn = 0; conn < 8; conn++){
        int c = accept(ls, 0, 0); if (c < 0) break;
        pid_t k = fork();
        if (k == 0){ close(ls); sam_conn(c, nth); close(c); _exit(0); }
        close(c); nth++;
    }
    _exit(0);
}
int main(void){
    signal(SIGPIPE, SIG_IGN);
    int ls = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); bind(ls, (struct sockaddr*)&a, sizeof a);
    socklen_t al = sizeof a; getsockname(ls, (struct sockaddr*)&a, &al); listen(ls, 8); int port = ntohs(a.sin_port);
    pid_t sam = fork(); if (sam == 0){ fake_sam(ls); }
    close(ls);
    char td[] = "/tmp/bmc_i2pin_XXXXXX"; if (!mkdtemp(td)){ perror("mkdtemp"); return 1; }
    if (chdir(td) != 0){ perror("chdir"); return 1; }   /* i2p_private_key lands here */
    node_config_load("/nonexistent/bitcoin.conf");
    snprintf(g_cfg.i2psam, sizeof g_cfg.i2psam, "127.0.0.1:%d", port);
    g_cfg.listen = 1; g_cfg.i2pacceptincoming = 1;
    extern int dialer_reset_for_test(void); dialer_reset_for_test();

    printf("== 1. off switches ==\n");
    g_cfg.listen = 0;
    ok(i2p_inbound_start() < 0, "listen=0: no acceptor");
    g_cfg.listen = 1; g_cfg.i2pacceptincoming = 0;
    ok(i2p_inbound_start() < 0, "i2pacceptincoming=0: no acceptor");
    g_cfg.i2pacceptincoming = 1;
    ok(i2p_inbound_start() < 0, "no SAM session yet: no acceptor");

    printf("== 2. the session comes up and the acceptor starts ==\n");
    extern int dialer_init(void); extern int dialer_i2p_ready(void); extern const char* dialer_i2p_b32(void);
    dialer_init();
    ok(dialer_i2p_ready(), "SAM session established against the bridge");
    ok(!strcmp(dialer_i2p_b32(), REAL_B32), "...with our .b32.i2p derived from the destination");
    int rfd = i2p_inbound_start();
    ok(rfd >= 0, "acceptor thread started; the serve loop has a pipe to poll");

    printf("== 3. an inbound stream reaches the loop with the peer's identity and bytes ==\n");
    struct pollfd pf = { rfd, POLLIN, 0 };
    int pr = poll(&pf, 1, 8000);
    ok(pr == 1 && (pf.revents & POLLIN), "the pipe became readable within 8 s");
    i2p_inbound_t m; memset(&m, 0, sizeof m);
    ok(pr == 1 && read(rfd, &m, sizeof m) == (ssize_t)sizeof m, "one record: {fd, b32}");
    ok(m.fd >= 0, "the record carries the stream socket");
    ok(!strcmp(m.b32, REAL_B32), "...and the caller's .b32.i2p (from the destination line)");
    { char buf[64] = {0}; struct pollfd pf2 = { m.fd, POLLIN, 0 }; poll(&pf2, 1, 3000);
      int n = (int)read(m.fd, buf, sizeof buf - 1);
      ok(n > 0 && !strcmp(buf, "peer-bytes-1"), "the socket carries the peer's raw bytes, nothing of SAM's left on it"); }
    if (m.fd >= 0) close(m.fd);

    printf("== 4. the thread re-arms: a second caller is accepted too ==\n");
    pf.revents = 0; pr = poll(&pf, 1, 12000);
    ok(pr == 1, "a second stream arrived");
    memset(&m, 0, sizeof m);
    ok(pr == 1 && read(rfd, &m, sizeof m) == (ssize_t)sizeof m && m.fd >= 0 && !strcmp(m.b32, REAL_B32), "...as its own record");
    { char buf[64] = {0}; struct pollfd pf2 = { m.fd, POLLIN, 0 }; poll(&pf2, 1, 3000);
      int n = (int)read(m.fd, buf, sizeof buf - 1);
      ok(n > 0 && !strcmp(buf, "peer-bytes-2"), "...with its own bytes"); }
    if (m.fd >= 0) close(m.fd);

    kill(sam, SIGKILL); waitpid(sam, NULL, 0);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
