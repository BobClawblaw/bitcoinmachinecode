/* tests/test_zmq_queue.c -- the ZMQ publisher's per-subscriber queue
 * (MEM-22, closed 2026-09-19).
 *
 * Before this the publisher had no queue. It wrote the three frames with
 * non-blocking send into a kernel buffer sized hwm x 256 bytes (~256 KB), and
 * a subscriber that could not take the whole message was CLOSED. A rawblock
 * is 1-2 MB, so on production (2026-09-19 01:07Z) a real pyzmq subscriber got
 * 3,180 hashtx, 2 hashblock and ZERO rawblock over two blocks, and was
 * disconnected at every block.
 *
 * What Core does (libzmq PUB): each subscriber has a queue of at most SNDHWM
 * MESSAGES; when it is full the NEW message is discarded for that subscriber
 * alone and the connection is kept, so the subscriber sees a gap in the
 * per-topic sequence number. The checks here are that behaviour:
 *
 *   1. hwm is counted in MESSAGES: exactly hwm queue, whatever their size
 *   2. a full queue drops the new message for that subscriber, keeps the
 *      connection, and the next delivered message shows the sequence gap
 *   3. hwm=0 is "no limit", as in ZMQ
 *   4. the byte ceiling (this node's one stated divergence) drops the same way
 *   5. topic filtering is still applied publisher-side, on the wire
 *   6. a 2 MB rawblock arrives intact (the production failure)
 *   7. a stalled subscriber beside a live one: the live one gets everything,
 *      the stalled one gets a gap and STAYS CONNECTED, and the publish call
 *      never waits on either (timed)
 *
 * Sections 1-5 run WITHOUT the servicing thread and drive it by hand with
 * zmqpub_poll(), so nothing is written to a socket between publishes and the
 * queue counts are exact rather than blurred by what the kernel absorbed.
 *
 * The subscriber is a hand-rolled ZMTP reader, not libzmq: libzmq filters on
 * receive too and would hide a publisher that ignores subscriptions. The
 * framing it assumes is the one tests/zmq_interop.py confirms against real
 * libzmq.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef unsigned char u8;
typedef unsigned int  u32;

extern int  zmqpub_add(const char* topic, const char* addr);
extern int  zmqpub_start(void);
extern void zmqpub_poll(void);
extern void zmqpub_notify(const char* topic, const void* body, unsigned long blen);
extern void zmqpub_close(void);
extern void zmq_pub_set_hwm(const int* hwm5);
/* weak: the byte ceiling is new with the queue, and a build without it must
 * FAIL the check below rather than fail to link */
extern void zmq_pub_set_byte_cap(unsigned long b) __attribute__((weak));

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

static double now_ms(void){
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

static int free_port(void){
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(s, (struct sockaddr*)&a, sizeof a);
    socklen_t al = sizeof a; getsockname(s, (struct sockaddr*)&a, &al);
    int p = ntohs(a.sin_port); close(s); return p;
}

/* ---- a buffered raw ZMTP subscriber ------------------------------------- */
typedef struct {
    int    fd;
    u8*    b; size_t n, cap;
    int    eof, greeted;
} rsub;

typedef struct { char topic[32]; u32 seq; u8* body; size_t blen; } rmsg;

static int rsub_open(rsub* s, int port, const char* subscribe, int rcvbuf){
    memset(s, 0, sizeof *s);
    s->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (rcvbuf > 0) setsockopt(s->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(s->fd, (struct sockaddr*)&a, sizeof a) != 0) return 0;
    /* greeting + READY(SUB) + SUBSCRIBE in one write, so the publisher
     * consumes them in one pass */
    u8 out[256]; size_t n = 0;
    memset(out, 0, 64); out[0] = 0xff; out[9] = 0x7f; out[10] = 3; out[11] = 1;
    memcpy(out + 12, "NULL", 4); n = 64;
    static const u8 ready[] = { 5,'R','E','A','D','Y', 11,'S','o','c','k','e','t','-','T','y','p','e',
                                0,0,0,3,'S','U','B' };
    out[n++] = 0x04; out[n++] = (u8)sizeof ready; memcpy(out + n, ready, sizeof ready); n += sizeof ready;
    size_t tl = strlen(subscribe);
    out[n++] = 0x04; out[n++] = (u8)(10 + tl);
    out[n++] = 9; memcpy(out + n, "SUBSCRIBE", 9); n += 9;
    memcpy(out + n, subscribe, tl); n += tl;
    return write(s->fd, out, n) == (ssize_t)n;
}

/* read whatever is available within wait_ms */
static void rsub_pump(rsub* s, int wait_ms){
    struct pollfd pf = { s->fd, POLLIN, 0 };
    if (poll(&pf, 1, wait_ms) <= 0) return;
    for (;;){
        if (s->cap - s->n < 65536){
            s->cap = s->cap ? s->cap * 2 : (1 << 20);
            s->b = realloc(s->b, s->cap);
        }
        ssize_t r = recv(s->fd, s->b + s->n, s->cap - s->n, MSG_DONTWAIT);
        if (r > 0){ s->n += (size_t)r; continue; }
        if (r == 0) s->eof = 1;
        return;
    }
}

/* one whole [topic][body][seq] message from the buffer, or 0 */
static int rsub_next(rsub* s, rmsg* m){
    if (!s->greeted){                     /* the publisher's 64-byte greeting */
        if (s->n < 64) return 0;
        memmove(s->b, s->b + 64, s->n - 64); s->n -= 64;
        s->greeted = 1;
    }
    size_t off = 0;
    const u8* part[3]; size_t plen[3]; int np = 0;
    for (;;){
        if (s->n - off < 2) return 0;
        u8 fl = s->b[off]; size_t len, hn;
        if (fl & 2){
            if (s->n - off < 9) return 0;
            len = 0; for (int i = 0; i < 8; i++) len = (len << 8) | s->b[off + 1 + i];
            hn = 9;
        } else { len = s->b[off + 1]; hn = 2; }
        if (s->n - off < hn + len) return 0;
        const u8* body = s->b + off + hn;
        off += hn + len;
        if (fl & 4){
            /* a command (the publisher's READY), between messages: drop it */
            if (np == 0){ memmove(s->b, s->b + off, s->n - off); s->n -= off; off = 0; }
            continue;
        }
        if (np < 3){ part[np] = body; plen[np] = len; }
        np++;
        if (!(fl & 1)) break;
    }
    memset(m, 0, sizeof *m);
    if (np == 3 && plen[2] == 4){
        size_t tl = plen[0] < sizeof m->topic - 1 ? plen[0] : sizeof m->topic - 1;
        memcpy(m->topic, part[0], tl);
        m->blen = plen[1];
        m->body = malloc(plen[1] ? plen[1] : 1);
        memcpy(m->body, part[1], plen[1]);
        m->seq = (u32)part[2][0] | (u32)part[2][1] << 8 | (u32)part[2][2] << 16 | (u32)part[2][3] << 24;
    } else {
        snprintf(m->topic, sizeof m->topic, "<%d parts>", np);
    }
    memmove(s->b, s->b + off, s->n - off); s->n -= off;
    return 1;
}

/* Collect up to max messages, stopping after idle_ms with nothing new. With
 * drive=1 the publisher is serviced by hand (no servicing thread). */
static int rsub_collect(rsub* s, rmsg* out, int max, int idle_ms, int drive){
    int got = 0; double last = now_ms();
    while (got < max && now_ms() - last < idle_ms){
        if (drive) zmqpub_poll();
        rsub_pump(s, 5);
        while (got < max && rsub_next(s, &out[got])){ got++; last = now_ms(); }
        if (s->eof) break;
    }
    return got;
}

static void rsub_close(rsub* s){ close(s->fd); free(s->b); s->b = NULL; }
static void msgs_free(rmsg* m, int n){ for (int i = 0; i < n; i++){ free(m[i].body); m[i].body = NULL; } }

/* body i: a pattern that differs per message, first 4 bytes = the index */
static void fill(u8* b, size_t n, u32 idx){
    for (size_t i = 0; i < n; i++) b[i] = (u8)(i * 7 + idx * 13 + 3);
    if (n >= 4){ b[0] = (u8)idx; b[1] = (u8)(idx >> 8); b[2] = (u8)(idx >> 16); b[3] = (u8)(idx >> 24); }
}
static int body_ok(const rmsg* m, size_t n, u32 idx){
    if (m->blen != n) return 0;
    for (size_t i = 4; i < n; i++) if (m->body[i] != (u8)(i * 7 + idx * 13 + 3)) return 0;
    return n < 4 || (u32)(m->body[0] | m->body[1] << 8 | m->body[2] << 16 | (u32)m->body[3] << 24) == idx;
}

/* let the publisher take the subscriber's handshake (no servicing thread) */
static void drive_handshake(void){
    for (int i = 0; i < 40; i++){ zmqpub_poll(); usleep(5000); }
}

static int bind_topics(int port, const char* const* topics, int n){
    char addr[64]; snprintf(addr, sizeof addr, "tcp://127.0.0.1:%d", port);
    for (int i = 0; i < n; i++) if (!zmqpub_add(topics[i], addr)) return 0;
    return 1;
}

static void set_hwm_all(int h){ int v[5] = { h, h, h, h, h }; zmq_pub_set_hwm(v); }

static rmsg g_m[4096];

int main(void){
    static u8 body[2 * 1024 * 1024 + 4096];

    printf("== 1. hwm counts MESSAGES; a full queue drops for that subscriber, keeps it ==\n");
    { int port = free_port();
      static const char* const T[] = { "rawblock" };
      set_hwm_all(10);
      ck("publisher bound", bind_topics(port, T, 1));
      rsub s; ck("subscriber connected", rsub_open(&s, port, "rawblock", 0));
      drive_handshake();
      /* 50 x 64 KB with nobody servicing the socket: exactly 10 may queue */
      double worst = 0;
      for (u32 i = 0; i < 50; i++){
          fill(body, 65536, i);
          double t0 = now_ms();
          zmqpub_notify("rawblock", body, 65536);
          double dt = now_ms() - t0; if (dt > worst) worst = dt;
      }
      printf("  (50 publishes of 64 KB into a full queue: worst call %.3f ms)\n", worst);
      int got = rsub_collect(&s, g_m, 100, 300, 1);
      ck("exactly hwm=10 of 50 large messages were delivered", got == 10);
      int intact = 1;
      for (int i = 0; i < got; i++) intact &= !strcmp(g_m[i].topic, "rawblock") && g_m[i].seq == (u32)i && body_ok(&g_m[i], 65536, (u32)i);
      ck("  they are the FIRST ten, in order, intact (the new ones were dropped)", got > 0 && intact);
      ck("  the subscriber was NOT disconnected", !s.eof);
      msgs_free(g_m, got);

      /* the same count for tiny messages: the unit is messages, not bytes */
      for (u32 i = 0; i < 50; i++){ fill(body, 32, 100 + i); zmqpub_notify("rawblock", body, 32); }
      got = rsub_collect(&s, g_m, 100, 300, 1);
      ck("exactly hwm=10 of 50 32-byte messages were delivered (count, not bytes)", got == 10);
      ck("  and the first of them shows the gap: sequence 9 -> 50",
         got > 0 && g_m[0].seq == 50 && body_ok(&g_m[0], 32, 100));
      msgs_free(g_m, got);

      /* after the drops, the same connection still carries new messages */
      fill(body, 1000, 777); zmqpub_notify("rawblock", body, 1000);
      got = rsub_collect(&s, g_m, 10, 300, 1);
      ck("the same connection receives the next message (sequence 100)",
         got == 1 && g_m[0].seq == 100 && body_ok(&g_m[0], 1000, 777) && !s.eof);
      msgs_free(g_m, got);
      rsub_close(&s);
      zmqpub_close(); }

    printf("== 2. hwm=0 is \"no limit\", as in ZMQ ==\n");
    { int port = free_port();
      static const char* const T[] = { "hashtx" };
      set_hwm_all(0);
      ck("publisher bound", bind_topics(port, T, 1));
      rsub s; rsub_open(&s, port, "hashtx", 0); drive_handshake();
      for (u32 i = 0; i < 3000; i++){ fill(body, 32, i); zmqpub_notify("hashtx", body, 32); }
      int got = rsub_collect(&s, g_m, 4096, 400, 1);
      int contiguous = 1;
      for (int i = 0; i < got; i++) contiguous &= g_m[i].seq == (u32)i && body_ok(&g_m[i], 32, (u32)i);
      ck("all 3000 queued with hwm=0 were delivered, contiguous", got == 3000 && contiguous);
      msgs_free(g_m, got);
      rsub_close(&s);
      zmqpub_close(); }

    printf("== 3. the byte ceiling (a stated divergence) drops the same way ==\n");
    { int port = free_port();
      static const char* const T[] = { "rawblock" };
      set_hwm_all(0);
      ck("the byte ceiling exists", zmq_pub_set_byte_cap != NULL);
      if (zmq_pub_set_byte_cap) zmq_pub_set_byte_cap(1u << 20);   /* 1 MiB for the test */
      ck("publisher bound", bind_topics(port, T, 1));
      rsub s; rsub_open(&s, port, "rawblock", 0); drive_handshake();
      for (u32 i = 0; i < 10; i++){ fill(body, 300000, i); zmqpub_notify("rawblock", body, 300000); }
      int got = rsub_collect(&s, g_m, 100, 300, 1);
      ck("3 x 300 KB fit a 1 MiB ceiling, the other 7 dropped", got == 3);
      ck("  still connected", !s.eof);
      msgs_free(g_m, got);
      /* a message into an EMPTY queue is always taken, whatever its size */
      fill(body, 2u << 20, 42); zmqpub_notify("rawblock", body, 2u << 20);
      got = rsub_collect(&s, g_m, 10, 300, 1);
      ck("a 2 MiB message into an empty queue is delivered despite the 1 MiB ceiling",
         got == 1 && body_ok(&g_m[0], 2u << 20, 42) && g_m[0].seq == 10);
      msgs_free(g_m, got);
      if (zmq_pub_set_byte_cap) zmq_pub_set_byte_cap(0);          /* back to the default */
      rsub_close(&s);
      zmqpub_close(); }

    printf("== 4. topic filtering is still applied publisher-side ==\n");
    { int port = free_port();
      static const char* const T[] = { "hashblock", "hashtx", "rawblock", "rawtx" };
      set_hwm_all(1000);
      ck("publisher bound (4 topics, one endpoint)", bind_topics(port, T, 4));
      rsub s; rsub_open(&s, port, "hashtx", 0); drive_handshake();
      for (u32 i = 0; i < 5; i++){
          fill(body, 32, i);
          zmqpub_notify("hashblock", body, 32);
          zmqpub_notify("hashtx", body, 32);
          zmqpub_notify("rawblock", body, 5000);
          zmqpub_notify("rawtx", body, 300);
      }
      int got = rsub_collect(&s, g_m, 100, 300, 1);
      int only = 1;
      for (int i = 0; i < got; i++) only &= !strcmp(g_m[i].topic, "hashtx");
      ck("subscribed to hashtx: exactly its 5 messages crossed the wire, nothing else",
         got == 5 && only);
      msgs_free(g_m, got);
      rsub_close(&s);
      zmqpub_close(); }

    printf("== 5. 2 MB rawblocks arrive intact (production: ZERO were delivered) ==\n");
    { int port = free_port();
      static const char* const T[] = { "hashblock", "rawblock" };
      set_hwm_all(1000);
      ck("publisher bound", bind_topics(port, T, 2));
      ck("servicing thread started", zmqpub_start() == 1);
      rsub s; rsub_open(&s, port, "", 0);
      usleep(300000);                                  /* the thread takes the handshake */
      double worst = 0;
      for (u32 i = 0; i < 3; i++){
          fill(body, 2u << 20, i);
          double t0 = now_ms();
          zmqpub_notify("hashblock", body, 32);
          zmqpub_notify("rawblock", body, 2u << 20);
          double dt = now_ms() - t0; if (dt > worst) worst = dt;
      }
      printf("  (hashblock + 2 MB rawblock publish: worst %.3f ms)\n", worst);
      int got = rsub_collect(&s, g_m, 100, 1000, 0);
      int nraw = 0, nhash = 0, raw_ok = 1;
      for (int i = 0; i < got; i++){
          if (!strcmp(g_m[i].topic, "rawblock")){
              raw_ok &= g_m[i].seq == (u32)nraw && body_ok(&g_m[i], 2u << 20, (u32)nraw);
              nraw++;
          } else if (!strcmp(g_m[i].topic, "hashblock")) nhash++;
      }
      ck("all three 2 MB rawblocks delivered", nraw == 3);
      ck("  byte-exact, sequence 0,1,2", nraw == 3 && raw_ok);
      ck("  and the three hashblocks with them", nhash == 3);
      ck("  the subscriber is still connected", !s.eof);
      msgs_free(g_m, got);
      rsub_close(&s);
      zmqpub_close(); }

    printf("== 6. a stalled subscriber beside a live one; the publisher never waits ==\n");
    { int port = free_port();
      static const char* const T[] = { "rawblock" };
      set_hwm_all(5);
      ck("publisher bound", bind_topics(port, T, 1));
      ck("servicing thread started", zmqpub_start() == 1);
      rsub live, stalled;
      rsub_open(&live, port, "rawblock", 0);
      rsub_open(&stalled, port, "rawblock", 64 * 1024);   /* reads nothing until the end */
      usleep(300000);
      enum { N = 40, SZ = 1 << 20 };
      static double lat[N];
      static rmsg lm[N + 8];
      int lgot = 0;
      for (u32 i = 0; i < N; i++){
          fill(body, SZ, i);
          double t0 = now_ms();
          zmqpub_notify("rawblock", body, SZ);
          lat[i] = now_ms() - t0;
          /* the live subscriber keeps reading between publishes */
          double until = now_ms() + 20;
          while (now_ms() < until){
              rsub_pump(&live, 2);
              while (lgot < N + 8 && rsub_next(&live, &lm[lgot])) lgot++;
          }
      }
      lgot += rsub_collect(&live, lm + lgot, N + 8 - lgot, 500, 0);
      int lok = lgot == N;
      for (int i = 0; i < lgot && lok; i++) lok = lm[i].seq == (u32)i && body_ok(&lm[i], SZ, (u32)i);
      ck("the live subscriber got all 40 x 1 MB, contiguous and intact", lok);
      msgs_free(lm, lgot);

      int sgot = rsub_collect(&stalled, g_m, 100, 1000, 0);
      int gap = 0, sok = 1;
      for (int i = 0; i < sgot; i++){
          sok &= body_ok(&g_m[i], SZ, g_m[i].seq);
          if (i && g_m[i].seq != g_m[i-1].seq + 1) gap = 1;
      }
      if (sgot && g_m[sgot-1].seq != N - 1) gap = 1;
      printf("  (stalled subscriber received %d of %d)\n", sgot, N);
      ck("the stalled subscriber got fewer than all, each intact", sgot > 0 && sgot < N && sok);
      ck("  and the drops are visible as a sequence gap", gap);
      ck("  and it was NOT disconnected", !stalled.eof);
      msgs_free(g_m, sgot);
      /* it is still a working subscription */
      fill(body, 1000, 4242); zmqpub_notify("rawblock", body, 1000);
      sgot = rsub_collect(&stalled, g_m, 10, 1000, 0);
      ck("  the stalled subscriber's same connection takes the next message (sequence 40)",
         sgot == 1 && g_m[0].seq == N && body_ok(&g_m[0], 1000, 4242));
      msgs_free(g_m, sgot);

      double mx = 0, sum = 0;
      for (int i = 0; i < N; i++){ sum += lat[i]; if (lat[i] > mx) mx = lat[i]; }
      printf("  (1 MB publish with a stalled subscriber: mean %.3f ms, worst %.3f ms)\n", sum / N, mx);
      /* a copy of 1 MB is well under a millisecond; 50 ms is a bound that
       * only a publish WAITING on a socket could reach */
      ck("no publish call waited on a subscriber (worst < 50 ms)", mx < 50.0);
      rsub_close(&live); rsub_close(&stalled);
      zmqpub_close(); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
