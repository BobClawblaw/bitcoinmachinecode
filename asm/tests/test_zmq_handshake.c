/* tests/test_zmq_handshake.c -- RPC-27 (audit 2026-10-23): connections that
 * never finish the ZMTP handshake are dropped at a deadline.
 *
 * Each endpoint has 32 subscriber slots. Nothing timed out a connection
 * still waiting for its greeting, so 32 idle TCP connections held every slot
 * and each real subscriber after them was closed on accept. libzmq (Core's
 * publisher) drops a peer that has not completed the handshake within
 * ZMQ_HANDSHAKE_IVL, 30 s by default; this publisher now does the same. The
 * test shortens the interval to 2 s through a seam. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern int  zmqpub_add(const char* topic, const char* addr);
extern int  zmqpub_start(void);
extern int  zmqpub_live_subscribers(void);
extern void zmqpub_close(void);
/* weak: the watched-to-fail build links the old publisher, which has no seam */
void zmqpub_set_handshake_ivl_for_test(long secs) __attribute__((weak));

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static int g_port;
static int free_port(void){
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(s, (struct sockaddr*)&a, sizeof a);
    socklen_t al = sizeof a; getsockname(s, (struct sockaddr*)&a, &al);
    int p = ntohs(a.sin_port); close(s); return p;
}
static int dial(void){
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons((unsigned short)g_port); inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(s, (struct sockaddr*)&sa, sizeof sa) != 0){ close(s); return -1; }
    return s;
}
/* 1 if the server closed this socket within wait_ms (data before the close is drained) */
static int closed_within(int s, int wait_ms){
    for (int waited = 0; waited <= wait_ms; waited += 50){
        struct pollfd p = { s, POLLIN, 0 };
        if (poll(&p, 1, 50) > 0){ char b[256]; ssize_t r = recv(s, b, sizeof b, MSG_DONTWAIT); if (r == 0 || (r < 0 && p.revents & (POLLHUP | POLLERR))) return 1; }
    }
    return 0;
}

int main(void){
    char addr[64];
    signal(SIGPIPE, SIG_IGN);          /* a refused subscriber's writes must fail, not kill the test */
    g_port = free_port();
    snprintf(addr, sizeof addr, "tcp://127.0.0.1:%d", g_port);
    if (zmqpub_set_handshake_ivl_for_test) zmqpub_set_handshake_ivl_for_test(2);
    ck("endpoint added", zmqpub_add("hashblock", addr) == 1);
    ck("servicing thread started", zmqpub_start() == 1);

    printf("== 32 connections that never send a greeting fill the slots ==\n");
    int idle[32];
    for (int i = 0; i < 32; i++) idle[i] = dial();
    usleep(300 * 1000);
    { int s = dial(); ck("a 33rd connection is refused while they hold the slots", s >= 0 && closed_within(s, 1000)); if (s >= 0) close(s); }

    printf("== past the handshake deadline they are dropped ==\n");
    usleep(2500 * 1000);
    int gone = 0; for (int i = 0; i < 32; i++) if (closed_within(idle[i], i == 0 ? 2000 : 50)) gone++;
    ck("every connection still handshaking at the deadline was closed by the publisher", gone == 32);
    if (gone != 32) printf("      %d of 32 closed\n", gone);

    printf("== a real subscriber gets a slot (the idle sockets are still open on our side) and stays ==\n");
    { int s = dial();
      unsigned char g[64]; struct timeval tv = { 3, 0 }; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
      size_t got = 0; while (got < sizeof g){ ssize_t r = recv(s, g + got, sizeof g - got, 0); if (r <= 0) break; got += (size_t)r; }
      ck("it receives the publisher's greeting", got == 64 && g[0] == 0xff);
      /* our greeting (ZMTP 3.0, NULL, as-server 0) and READY with Socket-Type SUB */
      unsigned char mine[64]; memset(mine, 0, sizeof mine); mine[0] = 0xff; mine[9] = 0x7f; mine[10] = 3; mine[11] = 0; memcpy(mine + 12, "NULL", 4);
      unsigned char ready[] = { 0x04, 25, 5, 'R','E','A','D','Y', 11, 'S','o','c','k','e','t','-','T','y','p','e', 0,0,0,3, 'S','U','B' };
      unsigned char sub[] = { 0x00, 10, 0x01, 'h','a','s','h','b','l','o','c','k' };
      if (write(s, mine, sizeof mine) != (ssize_t)sizeof mine || write(s, ready, sizeof ready) != (ssize_t)sizeof ready || write(s, sub, sizeof sub) != (ssize_t)sizeof sub) ck("handshake written", 0);
      usleep(500 * 1000);
      ck("...and is live after its handshake", zmqpub_live_subscribers() == 1);
      ck("...and is not dropped past the deadline once live", !closed_within(s, 3000) && zmqpub_live_subscribers() == 1);
      close(s); }
    for (int i = 0; i < 32; i++) close(idle[i]);

    zmqpub_close();
    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
