/* tests/test_peer_timeout.c -- CC-7 / DMN-14: a peer that opens a socket and
 * never completes the handshake is dropped at -peertimeout, not held for the
 * 20-minute idle bound. Mechanism test on a socketpair; the wiring is two
 * lines in main.c named in the commit. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include "peer_timeout.h"
static int checks, fails;
static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }
static double now_s(void){ struct timeval t; gettimeofday(&t,0); return t.tv_sec + t.tv_usec/1e6; }
/* recv on a silent socket; returns seconds waited, or -1 if it did not return within `guard` s */
static double silent_recv(int fd, int guard){
    fflush(stdout);
    pid_t p = fork();
    if (p == 0){ char b[8]; alarm(guard+2); ssize_t r = recv(fd, b, sizeof b, 0); _exit(r < 0 && (errno==EAGAIN||errno==EWOULDBLOCK) ? 0 : 3); }
    double t0 = now_s();
    for (int i = 0; i < guard*10; i++){ int st; if (waitpid(p, &st, WNOHANG) == p) return (WIFEXITED(st) && WEXITSTATUS(st)==0) ? now_s()-t0 : -2; usleep(100000); }
    kill(p, SIGKILL); waitpid(p, 0, 0); return -1;
}
int main(void){
    printf("== clamp ==\n");
    ok(peer_handshake_secs(0)==60,   "0 -> Core default 60");
    ok(peer_handshake_secs(-5)==60,  "negative -> 60");
    ok(peer_handshake_secs(5)==5,    "5 stays 5");
    ok(peer_handshake_secs(9999)==600, "9999 clamps to 600");
    int sv[2];
    printf("== with the deadline: a silent peer is dropped at -peertimeout ==\n");
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0){ perror("socketpair"); return 2; }
    ok(peer_handshake_deadline(sv[0], 1) == 0, "deadline set (1 s)");
    double w = silent_recv(sv[0], 4);
    ok(w >= 0.9 && w <= 2.5, "recv returned EAGAIN after ~1 s (silent peer dropped)");
    printf("      waited %.2f s\n", w);
    close(sv[0]); close(sv[1]);
    printf("== negative control: without it, the silent peer holds the socket ==\n");
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0){ perror("socketpair"); return 2; }
    w = silent_recv(sv[0], 3);
    ok(w == -1, "control: no deadline -> recv still blocked after 3 s (the DMN-14 behaviour)");
    close(sv[0]); close(sv[1]);
    ok(peer_handshake_deadline(-1, 60) == -1, "bad fd refused");
    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
