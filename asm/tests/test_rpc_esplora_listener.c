/* tests/test_rpc_esplora_listener.c -- the Esplora facade's LISTENER
 * (rpc_server.c): its threads, its deadlines and what it writes, driven over
 * real loopback sockets with a canned rpc_dispatch (this file defines it).
 *
 * RPC-21 (audit 2026-10-23): a detached thread per connection, and the
 * handlers' per-thread heap scratch (static __thread buffers malloc'd on
 * first use) was never released when it exited. The canned handler below
 * keeps 1 MB of scratch the same way; 200 requests must not cost 200 MB.
 * RPC-22: 16 connection slots, a per-read timeout and no total deadline, so
 * 16 sockets dribbling their headers locked every client out; no total write
 * deadline either; and the header search rescanned the whole buffer on every
 * read. RPC-23: the wildcard Access-Control-Allow-Origin header. RPC-26: a
 * request target could carry a LF into the exec-lock log lines. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <malloc.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "../rpc_esplora.h"
#include "../rpc_json.h"
#include "../rpc_net.h"
#include "../rpc_server.h"
#include "../bmc_thread.h"
/* weak: the watched-to-fail build links the old listener, which has no seam */
void rpc_esplora_set_deadlines_for_test(long read_s, long write_s) __attribute__((weak));
void rpc_exec_current_label(char* out, size_t cap);

static int fails = 0, checks = 0;
static void ok(int c, const char* w){ checks++; printf("  %s %s\n", c ? "ok  " : "FAIL", w); if (!c) fails++; }

/* ---- the canned node -------------------------------------------------------- */
int wallet_validate_address(const char* a, int* t, unsigned char* v, unsigned char h[20], unsigned char p[32]){ (void)a; (void)t; (void)v; (void)h; (void)p; return 0; }
long axt_read_events(int type, const unsigned char hash[32], long min_height,
                     int (*cb)(void*, int, const unsigned char*, unsigned, unsigned long long, unsigned), void* ctx){
    (void)type; (void)hash; (void)min_height; (void)cb; (void)ctx; return 0; }
int rpc_chain_method_lane(const char* m){ (void)m; return 0; }
int rpc_chain_method_lane_p(const char* m, const rj_val* p){ (void)m; (void)p; return 0; }
#define SCRATCH (1u << 20)
static long g_big_ids = 0;                       /* getrawmempool's size: the write-deadline case */
int rpc_dispatch(const char* method, const rj_val* params, const rpc_wallet* w, rj_val** result, long* ec, const char** em){
    (void)params; (void)w;
    if (!strcmp(method, "getblockchaininfo")){
        /* the shape of rpc_chain's undo tables and the message decoder's
         * buffer: per-thread heap, allocated once per thread, never freed */
        static __thread char* scratch; BMC_TLS_BUF(scratch, SCRATCH);
        scratch[0] = 1;
        const char* j = "{\"blocks\":7,\"bestblockhash\":\"00\"}";
        *result = rj_parse(j, strlen(j)); return 1;
    }
    if (!strcmp(method, "getrawmempool") && g_big_ids){
        rj_val* a = rj_arr(); char id[65];
        for (long i = 0; i < g_big_ids; i++){ snprintf(id, sizeof id, "%064lx", i); rj_arr_push(a, rj_str(id)); }
        *result = a; return 1;
    }
    *ec = -32601; *em = "Method not found"; return 0;
}

/* ---- a client ------------------------------------------------------------------ */
static int g_port;
static int dial(int rcvbuf){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (rcvbuf > 0) setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = htons((unsigned short)g_port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr*)&a, sizeof a) != 0){ close(fd); return -1; }
    return fd;
}
static double now_s(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (double)t.tv_sec + (double)t.tv_nsec / 1e9; }
/* read until EOF or `wait_s` seconds pass; returns bytes read (into out, up to cap-1) or -1 on the timeout */
static long read_to_eof(int fd, char* out, long cap, double wait_s){
    long n = 0; double t0 = now_s();
    for (;;){
        double left = wait_s - (now_s() - t0); if (left <= 0) return -1;
        struct pollfd p = { fd, POLLIN, 0 };
        int r = poll(&p, 1, (int)(left * 1000) + 1);
        if (r <= 0) continue;
        char tmp[65536]; ssize_t k = read(fd, tmp, sizeof tmp);
        if (k <= 0) break;
        if (n + k < cap){ memcpy(out + n, tmp, (size_t)k); }
        n += k;
    }
    if (n < cap) out[n] = 0; else out[cap - 1] = 0;
    return n;
}
static int get(const char* path, char* out, long cap){
    int fd = dial(0); if (fd < 0) return -1;
    char req[512]; int l = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", path);
    if (write(fd, req, (size_t)l) != l){ close(fd); return -1; }
    long n = read_to_eof(fd, out, cap, 10); close(fd);
    return n < 0 ? -1 : 0;
}
static size_t heap_in_use(void){ struct mallinfo2 m = mallinfo2(); return m.uordblks + m.hblkhd; }

/* a connection that sends its header one byte per 400 ms and never ends it */
static volatile int g_dribble_stop = 0;
static void* dribbler(void* arg){
    int fd = (int)(long)arg;
    const char* h = "GET /blocks/tip/height HTTP/1.1\r\nX-Slow: ";
    if (write(fd, h, strlen(h)) < 0){ close(fd); return 0; }
    while (!g_dribble_stop){ if (write(fd, "a", 1) != 1) break; struct timespec ts = { 0, 400 * 1000 * 1000 }; nanosleep(&ts, 0); }
    close(fd); return 0;
}

int main(void){
    printf("---- the Esplora listener ----\n");
    /* RPC-26 at the parser: control bytes in the request line are malformed */
    { const char* a = "GET /a\nb HTTP/1.1\r\nHost: x\r\n\r\n"; const char* b = "GET /ok HTTP/1.1\r\nHost: x\r\n\r\n";
      ok(!http_request_parse(a, strlen(a), 0, 0, 0, 0, 0, 0), "http_request_parse refuses a LF inside the request target");
      const char* c = "GET /a\x1b[2J HTTP/1.1\r\nHost: x\r\n\r\n";
      ok(!http_request_parse(c, strlen(c), 0, 0, 0, 0, 0, 0), "...and an ESC");
      ok(http_request_parse(b, strlen(b), 0, 0, 0, 0, 0, 0) == 1, "...a plain one still parses"); }
    /* RPC-26 at the log: what reaches an exec-lock line is printable */
    { char lab[256]; rpc_exec_set_context("esplora", "GET", 3, "/x\n[rpc] forged\x01", 16); rpc_exec_current_label(lab, sizeof lab);
      int printable = 1; for (const char* q = lab; *q; q++) if ((unsigned char)*q < 0x20 || (unsigned char)*q >= 0x7f) printable = 0;
      ok(printable && strstr(lab, "/x\\x0a[rpc] forged\\x01") != NULL, "the exec-lock context escapes non-printable bytes as \\xNN");
      printf("      label: %s\n", lab);
      rpc_exec_set_context(NULL, NULL, 0, NULL, 0); }

    if (rpc_esplora_set_deadlines_for_test) rpc_esplora_set_deadlines_for_test(2, 3);
    /* a free port away from every service port (8331-8335, 21000/21001) */
    char err[256] = ""; int started = 0; srand((unsigned)(getpid() ^ time(0)));
    for (int tries = 0; tries < 50 && !started; tries++){ g_port = 40000 + rand() % 20000; started = rpc_esplora_start("127.0.0.1", g_port, err, sizeof err) == 0; }
    ok(started, "the facade listens");
    if (!started){ printf("      %s\n", err); return 1; }
    char* buf = malloc(64u << 20);

    /* ---- RPC-21: the threads' scratch is bounded, however many connections ---- */
    { get("/blocks/tip/height", buf, 1 << 20);                 /* warm-up */
      size_t h0 = heap_in_use();
      int good = 0;
      for (int i = 0; i < 200; i++) if (get("/blocks/tip/height", buf, 1 << 20) == 0 && strstr(buf, "\r\n\r\n7")) good++;
      struct timespec ts = { 0, 200 * 1000 * 1000 }; nanosleep(&ts, 0);   /* let exiting threads exit */
      size_t h1 = heap_in_use();
      long grew_mb = (long)((h1 > h0 ? h1 - h0 : 0) >> 20);
      ok(good == 200, "200 sequential requests answered");
      ok(grew_mb < 24, "...and the heap grew by less than 24 MB (1 MB of per-thread scratch each; a pool holds at most 16)");
      printf("      heap +%ld MB over 200 requests\n", grew_mb); }

    /* ---- RPC-23: no wildcard CORS ---- */
    { get("/blocks/tip/height", buf, 1 << 20);
      ok(strstr(buf, "HTTP/1.1 200") == buf && !strcasestr(buf, "Access-Control-Allow-Origin"), "no Access-Control-Allow-Origin on a facade response"); }

    /* ---- RPC-26 on the wire: a control byte in the target is a 400 ---- */
    { int fd = dial(0); const char* r = "GET /blocks/tip/height\n HTTP/1.1\r\nHost: x\r\n\r\n";
      if (write(fd, r, strlen(r)) < 0){} long n = read_to_eof(fd, buf, 1 << 20, 5); close(fd);
      ok(n > 0 && strstr(buf, "HTTP/1.1 400") == buf, "a request target with a LF in it is answered 400"); }

    /* ---- RPC-22: a total read deadline ---- */
    { int fd = dial(0); double t0 = now_s();
      pthread_t th; pthread_create(&th, 0, dribbler, (void*)(long)fd);
      /* the dribbler writes; this thread watches for the server's answer */
      struct pollfd p = { fd, POLLIN, 0 }; int r = poll(&p, 1, 8000);
      double took = now_s() - t0;
      char tmp[256] = ""; if (r > 0){ ssize_t k = recv(fd, tmp, sizeof tmp - 1, MSG_DONTWAIT); if (k > 0) tmp[k] = 0; }
      ok(r > 0 && took < 6.0 && strstr(tmp, "408") != NULL, "a request dribbled a byte per 400 ms is cut off at the read deadline (408)");
      printf("      answered after %.1f s: %.40s\n", took, tmp);
      g_dribble_stop = 1; pthread_join(th, 0); g_dribble_stop = 0; }
    { /* sixteen of them, then an honest client: it waits its turn, it is not refused */
      pthread_t th[16]; for (int i = 0; i < 16; i++){ int fd = dial(0); pthread_create(&th[i], 0, dribbler, (void*)(long)fd); }
      struct timespec ts = { 0, 300 * 1000 * 1000 }; nanosleep(&ts, 0);
      double t0 = now_s(); int rc = get("/blocks/tip/height", buf, 1 << 20); double took = now_s() - t0;
      ok(rc == 0 && strstr(buf, "HTTP/1.1 200") == buf && took < 8.0, "with 16 dribbling sockets an honest request is still answered (200), within the deadline");
      printf("      answered after %.1f s: %.30s\n", took, buf);
      g_dribble_stop = 1; for (int i = 0; i < 16; i++) pthread_join(th[i], 0); g_dribble_stop = 0; }

    /* ---- RPC-22: a total write deadline ---- */
    { g_big_ids = 300000;                                      /* ~20 MB of JSON */
      int fd = dial(4096);
      const char* r = "GET /mempool/txids HTTP/1.1\r\nHost: x\r\n\r\n"; if (write(fd, r, strlen(r)) < 0){}
      struct timespec ts = { 7, 0 }; nanosleep(&ts, 0);          /* read nothing for 7 s: past the 3 s write deadline */
      long n = read_to_eof(fd, buf, 64u << 20, 20); close(fd);
      long want = 300000L * 67 + 1;                              /* the body alone: 300,000 quoted ids, commas, brackets */
      ok(n > 0 && strstr(buf, "HTTP/1.1 200") == buf, "a 20 MB response starts out (200)");
      ok(n >= 0 && n < want, "...and a reader that stalls past the write deadline gets it cut, not the server's thread");
      printf("      received %ld of >= %ld bytes: %.20s\n", n, want, buf);
      g_big_ids = 0; }

    /* ---- RPC-22: the header scan resumes where the last read stopped ----
     * (it rescanned the whole buffer per read). glibc's vectorised strstr
     * kept the old rescan to 0.1-0.3 s of CPU for a 4-7 MB header on the
     * reference box, too little to assert on, so this checks the resumed
     * scan's edge instead: a terminator split across two reads is found. */
    { if (rpc_esplora_set_deadlines_for_test) rpc_esplora_set_deadlines_for_test(30, 30);
      int fd = dial(0);
      const char* h = "GET /blocks/tip/height HTTP/1.1\r\nHost: x\r\nX-Pad: "; if (write(fd, h, strlen(h)) < 0){}
      char chunk[1024]; memset(chunk, 'a', sizeof chunk);
      for (int i = 0; i < 4096; i++){                          /* 4 MB of header, 1 KB at a time */
          if (write(fd, chunk, sizeof chunk) != (ssize_t)sizeof chunk) break;
          struct timespec ts = { 0, 100 * 1000 }; nanosleep(&ts, 0); }
      if (write(fd, "\r\n\r", 3) < 0){}
      struct timespec ts = { 0, 200 * 1000 * 1000 }; nanosleep(&ts, 0);
      if (write(fd, "\n", 1) < 0){}
      long n = read_to_eof(fd, buf, 1 << 20, 30); close(fd);
      ok(n > 0 && strstr(buf, "HTTP/1.1 200") == buf, "a 4 MB header sent 1 KB at a time, its terminator split across two reads, is served"); }

    free(buf);
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
