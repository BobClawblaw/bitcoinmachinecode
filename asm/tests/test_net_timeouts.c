/* tests/test_net_timeouts.c -- the socket timeouts tcp_connect_ip sets are
 * REAL.
 *
 * bitcoin_net.asm has set SO_RCVTIMEO on every outbound socket since
 * 2026-08-15 so a peer that stops replying cannot hold a reader for ever.
 * The option never took: the timeval pointer was loaded into RCX, and the
 * kernel takes a syscall's fourth argument in R10, so every setsockopt
 * returned EFAULT into a deliberately ignored result. Reads had no bound,
 * connect() had none either, and a blackholed peer wedged the download
 * worker for the kernel's two-minute SYN schedule per address (2026-09-01).
 *
 * This test connects to a local server that accepts and says nothing, and
 * requires the read to give up within the 10 s bound (with a margin) -- it
 * used to hang until the test harness killed it. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
extern int  tcp_connect_ip(unsigned ip_netorder, unsigned short port_be);
extern long fd_read_full(int fd, void* buf, unsigned long n);
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
int main(void){
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); sa.sin_port = 0;
    if (bind(l, (struct sockaddr*)&sa, sizeof sa) != 0 || listen(l, 4) != 0){ perror("listen"); return 1; }
    socklen_t al = sizeof sa; getsockname(l, (struct sockaddr*)&sa, &al);
    printf("== a silent server on 127.0.0.1:%d ==\n", ntohs(sa.sin_port));
    struct timespec a, b; clock_gettime(CLOCK_MONOTONIC, &a);
    int fd = tcp_connect_ip(sa.sin_addr.s_addr, sa.sin_port);
    ck("tcp_connect_ip connects", fd >= 0);
    struct timeval tv; socklen_t tl = sizeof tv;
    ck("SO_RCVTIMEO is set on the socket (10 s)", getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, &tl) == 0 && tv.tv_sec == 10);
    ck("SO_SNDTIMEO is set on the socket (10 s)", getsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, &tl) == 0 && tv.tv_sec == 10);
    unsigned char buf[8];
    clock_gettime(CLOCK_MONOTONIC, &a);
    long r = fd_read_full(fd, buf, 1);
    clock_gettime(CLOCK_MONOTONIC, &b);
    double secs = (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;
    printf("  read of a silent peer returned %ld after %.1f s\n", r, secs);
    ck("the read gives up (no bytes)", r < 1);
    ck("...within the 10 s bound plus margin, not forever", secs >= 9.0 && secs <= 14.0);
    close(fd); close(l);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
