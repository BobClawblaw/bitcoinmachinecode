/* Regression test for the outbound_connect dial-budget hang.
 *
 * Forks a "trickle peer": it accepts a connection then dribbles one byte every
 * 2s forever. It never completes the handshake frame, but never idles long
 * enough to trip SO_RCVTIMEO either, so every individual read() succeeds and
 * resets the socket timer. That is exactly the shape of the production wedge
 * on 2026-08-18, where the download worker sat in tcp_recvmsg for 60+ minutes
 * and had to be SIGKILLed.
 *
 * Without the wall-clock dial budget this runs unbounded (measured at 46s here
 * and far longer against real peers); with it, outbound_connect gives up at
 * OUTBOUND_DIAL_BUDGET_SECS and returns -1.
 *
 * outbound_connect is static in daemon/main.c, so we include that TU directly
 * (renaming its main) rather than exporting the symbol just for a test. */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main

/* Dribbles a byte every 2s forever; never completes a frame, never goes quiet
 * long enough for SO_RCVTIMEO to fire. Runs in a forked child. */
static void trickle_peer(int lfd){
    int c = accept(lfd, NULL, NULL);
    if(c < 0) _exit(1);
    char junk[512];
    recv(c, junk, sizeof junk, 0);        /* swallow their version */
    for(;;){
        if(send(c, "\0", 1, MSG_NOSIGNAL) != 1) break;
        usleep(2000000);
    }
    close(c);
    _exit(0);
}

int main(void){
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if(lfd < 0){ perror("socket"); return 2; }
    int one = 1; setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if(bind(lfd,(struct sockaddr*)&a,sizeof a) != 0){ perror("bind"); return 2; }
    socklen_t al = sizeof a;
    if(getsockname(lfd,(struct sockaddr*)&a,&al) != 0){ perror("getsockname"); return 2; }
    int port = ntohs(a.sin_port);
    if(listen(lfd, 4) != 0){ perror("listen"); return 2; }

    pid_t kid = fork();
    if(kid == 0) trickle_peer(lfd);
    close(lfd);

    printf("---- outbound_connect dial budget (trickling peer on port %d) ----\n", port);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int fd = outbound_connect("127.0.0.1", 300, port);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double el = (t1.tv_sec-t0.tv_sec) + (t1.tv_nsec-t0.tv_nsec)/1e9;

    kill(kid, SIGKILL); waitpid(kid, NULL, 0);
    if(fd >= 0) close(fd);

    int failures = 0;
    if(fd >= 0){ printf("FAIL: expected -1 (the peer never completes a handshake)\n"); failures++; }
    else printf("PASS: rejected the trickling peer (got %.2fs)\n", el);

    /* The budget path must SAY it was the budget -- before this, every dial
     * failure logged the same bare "unreachable" regardless of cause. */
    if(fd < 0){
        const char* why = dial_fail_reason();
        if(strstr(why, "dial budget") == NULL){
            printf("FAIL: budget expiry reported as \"%s\", expected a dial-budget reason\n", why);
            failures++;
        } else printf("PASS: budget expiry is self-describing (\"%s\")\n", why);
    }

    /* Generous ceiling: we assert the budget BOUNDS the dial, not its exact
     * value. Unfixed, this call does not return anywhere near this quickly. */
    double ceiling = OUTBOUND_DIAL_BUDGET_SECS + 10.0;
    if(el > ceiling){ printf("FAIL: took %.2fs, over the %.0fs ceiling -- dial not bounded\n", el, ceiling); failures++; }
    else printf("PASS: dial bounded by the budget (got %.2fs, ceiling %.0fs)\n", el, ceiling);

    /* ---- a REFUSED dial carries its errno through ------------------------
     * tcp_connect_ip returns the raw -errno; the whole point of this change is
     * that outbound_connect no longer flattens it to -1. Bind a port, close it,
     * and dial the corpse: connect() gives ECONNREFUSED and the reason string
     * must say so. This is the case that would have made the 2026-08-27 dial
     * storm readable at a glance. */
    {
        int t = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in b; memset(&b,0,sizeof b);
        b.sin_family=AF_INET; b.sin_addr.s_addr=htonl(INADDR_LOOPBACK); b.sin_port=0;
        bind(t,(struct sockaddr*)&b,sizeof b);
        socklen_t bl=sizeof b; getsockname(t,(struct sockaddr*)&b,&bl);
        int dead_port = ntohs(b.sin_port);
        close(t);                       /* nothing listens there now */

        printf("\n---- a refused dial reports its errno (port %d) ----\n", dead_port);
        int rfd = outbound_connect("127.0.0.1", 300, dead_port);
        if(rfd >= 0){ printf("FAIL: expected the dial to fail\n"); failures++; close(rfd); }
        else {
            const char* why = dial_fail_reason();
            const char* want = strerror(ECONNREFUSED);
            if(strstr(why, want) == NULL){
                printf("FAIL: reported \"%s\", expected it to name \"%s\"\n", why, want);
                failures++;
            } else printf("PASS: refused dial names the errno (\"%s\")\n", why);
        }
    }

    if(failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures ? 1 : 0;
}
