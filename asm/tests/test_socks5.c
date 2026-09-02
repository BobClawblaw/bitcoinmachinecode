/* tests/test_socks5.c -- the SOCKS5 client against a fake proxy that RECORDS
 * every byte it is sent, so the wire format is pinned to Core's Socks5()
 * (netbase.cpp) rather than to whatever this client happens to emit:
 *   greeting 05 01 00 (no creds) / 05 02 00 02 (with creds),
 *   RFC 1929 auth 01 <ulen> user <plen> pass when the proxy picks method 2,
 *   request 05 01 00 03 <len> host <port BE>.
 * Plus: the tunnelled socket really carries bytes end to end, a proxy REP
 * error maps to -3 with the code, a rejected password to -4, and a proxy
 * that never answers to -5 within the timeout. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include "../daemon/socks5.h"
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static int rd(int fd, unsigned char* b, int n){ int g = 0; while (g < n){ int r = (int)read(fd, b + g, (size_t)(n - g)); if (r <= 0) return g; g += r; } return g; }

/* mode: 0 noauth+success, 1 userpass required, 2 REP=5 refused, 3 silent, 4 wrong password */
/* a short write in the fake proxy would break the wire assertions anyway; make it loud */
static void wr(int fd, const void* b, int n){ if (write(fd, b, n) != n) _exit(9); }
static void fake_proxy(int ls, int mode, int report){
    int c = accept(ls, 0, 0); if (c < 0) _exit(1);
    unsigned char b[600]; int n;
    n = rd(c, b, 2); if (n != 2){ _exit(2); }
    int nm = b[1]; n = rd(c, b + 2, nm); wr(report, b, 2 + nm);          /* greeting as sent */
    if (mode == 3){ sleep(3); _exit(0); }
    unsigned char sel[2] = { 5, (unsigned char)(mode == 1 || mode == 4 ? 2 : 0) };
    wr(c, sel, 2);
    if (mode == 1 || mode == 4){
        n = rd(c, b, 2); int ul = b[1]; n = rd(c, b + 2, ul + 1); int pl = b[2 + ul]; n = rd(c, b + 3 + ul, pl);
        wr(report, b, 3 + ul + pl);                                       /* auth as sent */
        unsigned char ar[2] = { 1, (unsigned char)(mode == 4 ? 1 : 0) }; wr(c, ar, 2);
        if (mode == 4) _exit(0);
    }
    n = rd(c, b, 5); int hl = b[4]; n = rd(c, b + 5, hl + 2); wr(report, b, 5 + hl + 2); /* request as sent */
    unsigned char rep[10] = { 5, (unsigned char)(mode == 2 ? 5 : 0), 0, 1, 0,0,0,0, 0,0 };
    wr(c, rep, 10);
    if (mode == 2) _exit(0);
    /* tunnel: echo whatever arrives, prefixed with '>' */
    n = rd(c, b, 5); if (n == 5){ unsigned char o[6] = {'>'}; memcpy(o + 1, b, 5); wr(c, o, 6); }
    close(c); _exit(0);
}
static int listen_lo(int* port){
    int ls = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); bind(ls, (struct sockaddr*)&a, sizeof a);
    socklen_t al = sizeof a; getsockname(ls, (struct sockaddr*)&a, &al); listen(ls, 2); *port = ntohs(a.sin_port); return ls;
}
static int run_case(int mode, const char* user, const char* pass, unsigned char* wire, int* wl, int* rep){
    int port, rp[2]; if (pipe(rp)) return -1; int ls = listen_lo(&port);
    pid_t pid = fork(); if (pid == 0){ close(rp[0]); fake_proxy(ls, mode, rp[1]); }
    close(rp[1]); close(ls);
    int fd = socks5_connect("127.0.0.1", port, "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion", 8333, user, pass, 1500, rep);
    if (fd >= 0){ (void)!write(fd, "hello", 5); /* a short write fails the echo check below */ unsigned char e[6]; int n = rd(fd, e, 6); if (n == 6 && e[0] == '>' && !memcmp(e + 1, "hello", 5)) fd = 100000 + fd; close(fd >= 100000 ? fd - 100000 : fd); }
    int st; waitpid(pid, &st, 0);
    *wl = 0; { int r; while ((r = (int)read(rp[0], wire + *wl, 600 - *wl)) > 0) *wl += r; } close(rp[0]);
    return fd;
}
int main(void){
    signal(SIGPIPE, SIG_IGN);
    unsigned char w[600]; int wl, rep;
    const char* H = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    printf("== no credentials: Core's greeting 05 01 00, request 05 01 00 03 <len> host <port> ==\n");
    int fd = run_case(0, NULL, NULL, w, &wl, &rep);
    ck("connected through the proxy and the tunnel carried bytes both ways", fd >= 100000);
    ck("greeting == 05 01 00", wl >= 3 && w[0] == 5 && w[1] == 1 && w[2] == 0);
    ck("request == 05 01 00 03 3e <onion name> 20 8d", wl == 3 + 5 + 62 + 2 && w[3] == 5 && w[4] == 1 && w[5] == 0 && w[6] == 3 && w[7] == 62 && !memcmp(w + 8, H, 62) && w[70] == 0x20 && w[71] == 0x8d);
    printf("\n== credentials: greeting 05 02 00 02, RFC 1929 subnegotiation ==\n");
    fd = run_case(1, "bmc-7f3a", "x", w, &wl, &rep);
    ck("connected with user/pass", fd >= 100000);
    ck("greeting == 05 02 00 02 (NOAUTH and USER_PASS offered, Core's order)", wl >= 4 && w[0] == 5 && w[1] == 2 && w[2] == 0 && w[3] == 2);
    ck("auth == 01 08 'bmc-7f3a' 01 'x'", wl >= 4 + 3 + 8 + 1 && w[4] == 1 && w[5] == 8 && !memcmp(w + 6, "bmc-7f3a", 8) && w[14] == 1 && w[15] == 'x');
    printf("\n== failures map to distinct codes ==\n");
    fd = run_case(2, NULL, NULL, w, &wl, &rep);
    ck("proxy REP=5 (connection refused) -> -3, code reported", fd == -3 && rep == 5);
    fd = run_case(4, "u", "p", w, &wl, &rep);
    ck("rejected password -> -4", fd == -4);
    fd = run_case(3, NULL, NULL, w, &wl, &rep);
    ck("silent proxy -> -5 within the timeout", fd == -5);
    { char big[300]; memset(big, 'a', 299); big[299] = 0;
      ck("a 256+ char hostname is refused before any I/O (Core's limit)", socks5_connect("127.0.0.1", 1, big, 1, NULL, NULL, 100, &rep) == -2); }
    printf(fails ? "\nFAILURES %d\n" : "\nALL TESTS PASSED (0 failures)\n", fails);
    return fails ? 1 : 0;
}
