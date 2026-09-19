/* test_rpc_responsive.c -- the trivial RPCs answer promptly whatever else the
 * server is doing (2026-09-19).
 *
 * THE DEFECT. Run 27 (IBD, 2026-09-19): `uptime` took 44 s and getblockcount,
 * getindexinfo and getchaintxstats each ran past a 60 s client timeout, where
 * Core answers instantly. Every handler but four ran under ONE write lock, so
 * a slow call -- getindexinfo rescanning a 61 GB index tail, getchaintxstats
 * re-walking the chain, waitfornewblock sleeping -- held up everything; the
 * few read-side methods queued behind the waiting writers (writer-preferring
 * rwlock); and the -rpcthreads workers themselves were the ones parked on the
 * lock, so the next connection was not even read.
 *
 * THE BOUND. Each of uptime, getblockcount, getblockchaininfo, getnetworkinfo,
 * getpeerinfo and getindexinfo must answer within 100 ms -- EVERY call of
 * three, not the best of them: a first draft took the best, and against the
 * pre-fix server the first call absorbed the whole stall and the next two ran
 * after it, so it passed. The bound applies while:
 *   A. more slow calls are in flight than there are RPC threads (six
 *      waitfornewblock waits, -rpcthreads 4), and
 *   B. the execution lock's write side is HELD for seconds -- the shape of a
 *      long write-locked handler, the apply path busy behind it.
 *
 * C. getindexinfo itself must cost O(1) in the size of an index tail. On
 *    run 27 it re-scanned a 61.6 GB txospender tail from byte 0 whenever the
 *    tail grew -- every block -- and the RPC process held 15.7 GB of it
 *    resident. Measured as the calling thread's CPU time (CLOCK_THREAD_CPUTIME_ID --
 *    the dispatch runs on this thread, and CPU time does not inflate when a
 *    loaded gate delays the thread): the old reader walked every record of
 *    the tail, the new one preads the last. (Page faults were the first
 *    instrument tried; fault-around and large page-cache folios map ~0.5 MB
 *    per fault, so the full walk showed only ~118 and the control could not
 *    fail.)
 *
 * The server runs in this process (rpc_server_start) over a synthetic archive;
 * requests are real HTTP over loopback. */
#include "../rpc_json.h"
#include "../rpc_chain.h"
#include "../rpc_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include "test_tmpdir.h"
#include "../daemon/txosp_format.h"

extern int  store_init(void* st);
extern long store_append(void* st, const unsigned char* hash32, const void* blk, long len);
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);
/* rpc_server.c test hook: hold / release the execution lock's write side */
extern void rpc_exec_hold_for_test(int take);

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }
static int g_port;

static double now_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e3 + t.tv_nsec / 1e6; }

/* "u:p" base64 */
#define AUTH "dTpw"
static int connect_port(void){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((unsigned short)g_port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr*)&a, sizeof a) < 0){ close(fd); return -1; }
    return fd;
}
static int send_call(int fd, const char* method, const char* params){
    char body[512], req[1024];
    int bl = snprintf(body, sizeof body, "{\"jsonrpc\":\"1.0\",\"id\":7,\"method\":\"%s\",\"params\":%s}", method, params);
    int rl = snprintf(req, sizeof req, "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic " AUTH "\r\n"
                      "Content-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", bl, body);
    return write(fd, req, (size_t)rl) == rl;
}
/* one blocking call; returns ms, fills out (HTTP response) */
static double call_ms(const char* method, const char* params, char* out, size_t cap){
    double t0 = now_ms();
    int fd = connect_port();
    if (fd < 0){ out[0] = 0; return 1e9; }
    send_call(fd, method, params);
    size_t got = 0;
    for (;;){ ssize_t n = read(fd, out + got, cap - 1 - got); if (n <= 0) break; got += (size_t)n; if (got >= cap - 1) break; }
    out[got] = 0; close(fd);
    return now_ms() - t0;
}

static const char* TRIVIAL[] = { "uptime", "getblockcount", "getblockchaininfo", "getnetworkinfo", "getpeerinfo", "getindexinfo" };
#define NTRIV (sizeof TRIVIAL / sizeof TRIVIAL[0])
/* One method, three calls, each timed; the WORST must be under the bound. */
static void probe_one(const char* scenario, const char* m){
    char out[65536]; double worst = 0; int ok200 = 1;
    for (int k = 0; k < 3; k++){
        double ms = call_ms(m, "[]", out, sizeof out);
        if (ms > worst) worst = ms;
        if (strncmp(out, "HTTP/1.1 200", 12) || !strstr(out, "\"result\"")) ok200 = 0;
    }
    char label[256];
    snprintf(label, sizeof label, "%s: %s answers in %.1f ms (worst of 3; bound 100 ms)", scenario, m, worst);
    ck(label, ok200 && worst < 100.0);
}

/* waitfornewblock in flight: send the request and keep the socket open */
#define WAIT_MS 800
typedef struct { int fd; double ms; char out[4096]; } slow_t;
static void* slow_wait(void* a){
    slow_t* s = a; double t0 = now_ms();
    s->fd = connect_port();
    if (s->fd >= 0){
        char p[32]; snprintf(p, sizeof p, "[%d]", WAIT_MS);
        send_call(s->fd, "waitfornewblock", p);
        size_t got = 0;
        for (;;){ ssize_t n = read(s->fd, s->out + got, sizeof s->out - 1 - got); if (n <= 0) break; got += (size_t)n; }
        s->out[got] = 0; close(s->fd);
    }
    s->ms = now_ms() - t0;
    return NULL;
}
static void* hold_lock(void* a){
    long ms = (long)a;
    rpc_exec_hold_for_test(1);
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L }; nanosleep(&ts, NULL);
    rpc_exec_hold_for_test(0);
    return NULL;
}

/* A FRESH stall for every method probed: with one shared stall the first
 * method absorbs it and the rest run after it ends. */
static void scenario_waits(const char* m, int check_waits){
    enum { NS = 6 };
    pthread_t th[NS]; static slow_t sl[NS];
    memset(sl, 0, sizeof sl);
    for (int i = 0; i < NS; i++) pthread_create(&th[i], NULL, slow_wait, &sl[i]);
    struct timespec settle = { 0, 150 * 1000000L }; nanosleep(&settle, NULL);
    probe_one("6 waitfornewblock in flight (4 RPC threads)", m);
    for (int i = 0; i < NS; i++) pthread_join(th[i], NULL);
    if (!check_waits) return;
    int answered = 0; double worst = 0;
    for (int i = 0; i < NS; i++){ if (strstr(sl[i].out, "\"height\":300")) answered++; if (sl[i].ms > worst) worst = sl[i].ms; }
    printf("      the six waits answered in at most %.0f ms (each waits %d ms)\n", worst, WAIT_MS);
    ck("every slow call still answered, with the tip", answered == NS);
    /* side by side (a thread each, as in Core), not one after another: two
     * rounds on four threads is ~1.6 s; serialised, 4.8 s */
    ck("...concurrently: all six done within 3 s, not 6 x 0.8 s", worst < 3000);
}
static void scenario_lock(const char* m){
    pthread_t th; pthread_create(&th, NULL, hold_lock, (void*)700L);
    struct timespec settle = { 0, 150 * 1000000L }; nanosleep(&settle, NULL);
    probe_one("execution lock held", m);
    pthread_join(th, NULL);
}

int main(void){
    tt_isolate();
    /* a small linked chain, written by another process as the daemon would */
    { pid_t pid = fork();
      if (pid == 0){
          static unsigned char st[4096]; memset(st, 0, sizeof st);
          if (store_init(st) != 1) _exit(2);
          unsigned char prev[32] = {0};
          for (unsigned h = 0; h <= 300; h++){
              unsigned char blk[81]; memset(blk, 0, sizeof blk);
              blk[0] = 1; memcpy(blk + 4, prev, 32);
              unsigned t = 1500000000u + 600u * h;
              for (int i = 0; i < 4; i++){ blk[68+i] = (unsigned char)(t >> (8*i)); blk[76+i] = (unsigned char)(h >> (8*i)); }
              blk[72] = 0xff; blk[73] = 0xff; blk[74] = 0x00; blk[75] = 0x1d; blk[80] = 1;
              unsigned char id[32]; sha256d(id, blk, 80);
              if (store_append(st, id, blk, 81) < 0) _exit(3);
              memcpy(prev, id, 32);
          }
          _exit(0);
      }
      int ws = 0; waitpid(pid, &ws, 0);
      ck("synthetic archive written", WIFEXITED(ws) && WEXITSTATUS(ws) == 0); }
    ck("chain view open", rpc_chain_open(NULL) == 1);

    static rpc_wallet w;                      /* no wallet: the calls here never need one */
    rpc_server_cfg cfg; memset(&cfg, 0, sizeof cfg);
    cfg.port = 0; cfg.user = "u"; cfg.pass = "p"; cfg.wallet = &w;
    cfg.threads = 4; cfg.workqueue = 64; cfg.timeout_s = 30;
    char err[256];
    ck("server started (-rpcthreads 4)", rpc_server_start(&cfg, &g_port, err, sizeof err) == 0 && g_port > 0);

    { char out[4096]; call_ms("getblockcount", "[]", out, sizeof out);
      ck("baseline: getblockcount answers 300", strstr(out, "\"result\":300") != NULL); }
    for (unsigned i = 0; i < NTRIV; i++) probe_one("idle", TRIVIAL[i]);

    /* ---- A. six slow calls in flight, four RPC threads ---- */
    for (unsigned i = 0; i < NTRIV; i++) scenario_waits(TRIVIAL[i], i == 0);

    /* ---- B. the execution lock's write side held ---- */
    for (unsigned i = 0; i < NTRIV; i++) scenario_lock(TRIVIAL[i]);

    /* ---- C. getindexinfo against a 67 MB txospender tail that keeps growing ---- */
    { extern void rpc_chain_set_index_config(int, int, int, int, int);
      rpc_chain_set_index_config(0, 1, 0, 0, 0);          /* txospenderindex=1 only */
      enum { NREC = 2400000 };
      uint8_t* buf = malloc((size_t)NREC * TSP_REC);
      for (long i = 0; i < NREC; i++){
          tsp_rec r; memset(&r, 0, sizeof r);
          r.height = (uint32_t)(i * 300 / NREC);          /* ascending, as the writer appends */
          r.prefix[0] = (uint8_t)i; r.vout = (uint32_t)i;
          tsp_pack(buf + i * TSP_REC, &r);
      }
      FILE* f = fopen(TSP_TAIL_FILE, "wb");
      ck("wrote a 67 MB txospender tail", f && fwrite(buf, TSP_REC, NREC, f) == NREC);
      if (f) fclose(f);
      free(buf);
      double worst_cpu_ms = 0; int right = 1;
      for (int round = 0; round < 3; round++){
          /* the tail grows by a block's records, as it does every block in IBD */
          tsp_rec r; memset(&r, 0, sizeof r); r.height = 300; uint8_t one[TSP_REC]; tsp_pack(one, &r);
          FILE* g = fopen(TSP_TAIL_FILE, "ab"); if (g){ fwrite(one, TSP_REC, 1, g); fclose(g); }
          struct timespec c0, c1; clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c0);
          rj_val* res = NULL; long ec = 0; const char* em = NULL;
          rpc_chain_dispatch("getindexinfo", NULL, &res, &ec, &em);
          clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c1);
          double cpu_ms = (c1.tv_sec - c0.tv_sec) * 1e3 + (c1.tv_nsec - c0.tv_nsec) / 1e6;
          if (cpu_ms > worst_cpu_ms) worst_cpu_ms = cpu_ms;
          rj_val* e = res ? rj_obj_get(res, "txospenderindex") : NULL;
          rj_val* bh = e ? rj_obj_get(e, "best_block_height") : NULL;
          rj_val* sy = e ? rj_obj_get(e, "synced") : NULL;
          if (!bh || !bh->str || strcmp(bh->str, "300") || !sy || !sy->str || sy->str[0] != '1') right = 0;
          if (res) rj_free(res);
      }
      printf("      getindexinfo on a growing 67 MB tail: at most %.3f ms of CPU per call\n", worst_cpu_ms);
      ck("getindexinfo reports the tail's coverage (300, synced)", right);
      ck("getindexinfo's cost does not scale with the tail: < 0.5 ms CPU per call", worst_cpu_ms < 0.5); }

    rpc_server_stop();
    printf(fails ? "\nTESTS FAILED (%d failures)\n" : "\nALL TESTS PASSED (%d failures)\n", fails);
    return fails ? 1 : 0;
}
