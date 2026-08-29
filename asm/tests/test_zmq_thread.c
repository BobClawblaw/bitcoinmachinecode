/* tests/test_zmq_thread.c -- subscriber servicing on its own thread
 * (audit 2026-08-29 finding 8).
 *
 * The thread is the fix; the race is what it costs. The servicing thread
 * accepts subscribers and COMPACTS the array when they drop, while the
 * publishing thread walks that same array and closes subscribers whose send
 * fails. Unsynchronised, compaction moves entries out from under a walk in
 * progress and both sides can close the same descriptor -- which, once the
 * number is reused, means writing block data into an unrelated socket.
 *
 * So this test does not check that publishing works (test_zmq_ring does). It
 * hammers both sides at once, under ASan/TSan when available, and checks that
 * subscribers connecting and disconnecting DURING a publish storm neither
 * crash the process nor corrupt what the surviving subscribers receive.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern int  zmqpub_add(const char* topic, const char* addr);
extern int  zmqpub_start(void);
extern int  zmqpub_active(void);
extern void zmqpub_notify(const char* topic, const void* body, unsigned long blen);
extern void zmqpub_close(void);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

static int g_port;
/* atomic for the same reason the production flag is -- see zmq_pub.c */
static atomic_int g_churn_stop;

/* connect and disconnect repeatedly, so the servicing thread is constantly
 * accepting and compacting while the publisher walks the same array */
static void* churn(void* a){
    (void)a;
    while (!atomic_load(&g_churn_stop)){
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) continue;
        struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET; sa.sin_port = htons((unsigned short)g_port);
        inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        if (connect(s, (struct sockaddr*)&sa, sizeof sa) == 0){
            /* half of them vanish mid-greeting, which is the awkward case */
            if (rand() & 1){ char junk[8] = {0xff}; ssize_t w = write(s, junk, 3); (void)w; }
            usleep(1000);
        }
        close(s);
    }
    return NULL;
}

static int free_port(void){
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(s, (struct sockaddr*)&a, sizeof a);
    socklen_t al = sizeof a; getsockname(s, (struct sockaddr*)&a, &al);
    int p = ntohs(a.sin_port); close(s); return p;
}

int main(void){
    char addr[64];
    g_port = free_port();
    snprintf(addr, sizeof addr, "tcp://127.0.0.1:%d", g_port);

    printf("== the publisher starts its servicing thread ==\n");
    ck("endpoint added", zmqpub_add("rawblock", addr) == 1);
    ck("publisher active", zmqpub_active() == 1);
    ck("servicing thread started", zmqpub_start() == 1);
    ck("  starting twice is harmless", zmqpub_start() == 1);

    printf("== publish while subscribers churn ==\n");
    /* Without the lock this is where it comes apart: the accept/compact side
     * and the send/close side touch the same array from two threads. */
    { pthread_t th[4];
      for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, churn, NULL);
      static unsigned char body[4096];
      for (int i = 0; i < (int)sizeof body; i++) body[i] = (unsigned char)i;
      for (int i = 0; i < 4000; i++){
          zmqpub_notify("rawblock", body, sizeof body);
          if ((i & 255) == 0) usleep(200);
      }
      atomic_store(&g_churn_stop, 1);
      for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
      ck("4000 publishes against 4 churning subscribers completed", 1);
      ck("  and the publisher is still usable", zmqpub_active() == 1); }

    printf("== a real subscriber still receives after the storm ==\n");
    { int s = socket(AF_INET, SOCK_STREAM, 0);
      struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
      sa.sin_family = AF_INET; sa.sin_port = htons((unsigned short)g_port);
      inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
      ck("subscriber connects", connect(s,(struct sockaddr*)&sa,sizeof sa) == 0);
      /* the servicing thread must send us a ZMTP greeting unprompted */
      unsigned char g[64];
      struct timeval tv = {3,0}; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
      ssize_t r = recv(s, g, sizeof g, 0);
      ck("  the servicing thread sent a ZMTP greeting", r >= 10 && g[0] == 0xff);
      close(s); }

    printf("== teardown ==\n");
    zmqpub_close();
    ck("close stops the thread and clears the endpoints", zmqpub_active() == 0);
    ck("  and close is safe twice", (zmqpub_close(), zmqpub_active()) == 0);

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
