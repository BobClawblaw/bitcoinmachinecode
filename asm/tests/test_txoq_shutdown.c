/* test_txoq_shutdown.c -- the gettxout channel must never hold the download
 * worker in send() (2026-09-24, the 10-minute m5ultra stop).
 *
 * The worker answers queued gettxout queries at its between-block service
 * point (txoq_service) with a blocking send. Replies to queries the RPC side
 * already timed out on are never read, and Darwin gives an AF_UNIX stream
 * 8 KB each way, so a burst of queries could leave the worker in send() on a
 * parent that stopped reading -- and at a stop, until that parent exited: a
 * shutdown() of the parent's end does not wake a Darwin sender.
 *
 * Shape: the parent end sends a burst of queries and never reads; a child
 * (the worker) runs the real txoq_service in a loop, reporting each round.
 * It must keep completing rounds, on a Darwin-default 8 KB channel and on
 * the channel as the daemon now tunes it (txoq_channel_tune). When it
 * blocks, the test also shows that a shutdown() of the parent's end does
 * not release it. An alarm() in the child bounds the hang.
 * main.c before the fix (this file built with -DTXOQ_PRE_FIX, which skips
 * the tune): both cases block within a few rounds, and the shutdown frees
 * neither. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main

static long drain_rounds(int fd){ char b[4096]; long n = 0; ssize_t r; while((r = read(fd, b, sizeof b)) > 0) n += r; return n; }

/* returns 1 when the worker kept servicing with the parent not reading */
static int run(int tuned, int* released_by_shutdown){
    int sv[2];
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0){ perror("socketpair"); exit(2); }
#ifndef TXOQ_PRE_FIX
    if(tuned) txoq_channel_tune(sv);
#endif
    g_txoq_parent = sv[0]; g_txoq_worker = sv[1];
    int pp[2]; if(pipe(pp) != 0){ perror("pipe"); exit(2); }
    pid_t w = fork();
    if(w == 0){
        close(pp[0]); close(sv[0]);
        alarm(8);
        for(;;){ txoq_service(); if(write(pp[1], "r", 1) != 1) _exit(3); usleep(1000); }
    }
    close(pp[1]); close(sv[1]);
    fcntl(pp[0], F_SETFL, fcntl(pp[0], F_GETFL) | O_NONBLOCK);
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);

    txoq_req q; memset(&q, 0, sizeof q); q.magic = TXOQ_MAGIC;
    int sent = 0;
    for(int i = 0; i < 2000; i++){
        q.vout = (unsigned)i;
        if(send(sv[0], &q, sizeof q, MSG_NOSIGNAL) != (ssize_t)sizeof q) break;
        sent++;
        if(i % 64 == 63) usleep(3000);                  /* the worker drains requests, fills replies */
    }
    usleep(300000);
    long a = drain_rounds(pp[0]);
    usleep(300000);
    long b = drain_rounds(pp[0]);
    int moving = b > 0;
    printf("  %s: %d queries sent, never read; worker rounds %ld, then +%ld in 300 ms (%s)\n",
           tuned ? "tuned" : "8 KB ", sent, a, b, moving ? "still servicing" : "BLOCKED in send");

    *released_by_shutdown = -1;
    if(!moving){
        shutdown(sv[0], SHUT_RDWR);
        usleep(500000);
        *released_by_shutdown = drain_rounds(pp[0]) > 0;
        printf("  %s: shutdown() of the parent's end %s the worker\n", tuned ? "tuned" : "8 KB ",
               *released_by_shutdown ? "released" : "did NOT release");
    }
    kill(w, SIGKILL); waitpid(w, NULL, 0);
    close(sv[0]); close(pp[0]);
    return moving;
}

int main(void){
    signal(SIGPIPE, SIG_IGN);                           /* as the daemon's main() */
    int fails = 0, rel = 0;
    if(!run(0, &rel)){ printf("FAIL: an 8 KB channel holds the worker in send()\n"); fails++; }
    if(!run(1, &rel)){ printf("FAIL: the tuned channel holds the worker in send()\n"); fails++; }
    printf("%s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
