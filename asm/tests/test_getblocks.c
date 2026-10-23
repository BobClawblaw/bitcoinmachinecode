/* test_getblocks.c -- the serve loop's getblocks / getheaders answers, held to
 * Core v31.1 (net_processing.cpp GETBLOCKS, GETHEADERS, ProcessGetBlockData).
 *
 * A 520-block chain (more than one 500-entry getblocks batch) is stored and
 * indexed; every case forks its own node_serve_loop child on a fresh
 * connection, so per-connection state (the continuation block) and a
 * disconnect in one case cannot leak into the next. Each request is followed
 * by a ping with its own nonce: everything read before THAT pong is the
 * reply, so "nothing was sent" is observable and is not a timeout. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include "test_tmpdir.h"

extern long node_handshake(int fd);
extern int  node_accept_handshake(int fd);
extern long node_serve_loop(int fd, int lfd, void* st, void* ht_idx, void* out, long cap);
extern int  tcp_connect_ip(unsigned, unsigned short);
extern long store_init(void* st);
extern long store_append(void* st, const unsigned char h[32], const void* blk, long blen);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void sha256d(unsigned char o[32], const void* m, long l);
extern long p2p_write(int, const char*, unsigned, const void*, unsigned);
extern int  p2p_read(int, char[12], void*, unsigned, unsigned*);
extern void idx_init(void* idx, unsigned long slots);
extern int  idx_put(void* idx, const unsigned char hash[32], long height);

static int failures = 0;
static void cki(const char* l, long g, long e){
    if (g == e) printf("PASS %s (got %ld)\n", l, g);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, g, e); failures++; }
}
static void put_u32(unsigned char* p, unsigned v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void put_u64(unsigned char* p, unsigned long long v){ for (int i = 0; i < 8; i++) p[i] = v >> (8*i); }

#define NB  520                 /* heights 0..519: tip 519 */
#define TIP (NB - 1)
static unsigned char blk[NB][160];
static long blen[NB];
static unsigned char bhash[NB][32];

static void build_chain(void){
    unsigned char prev[32]; memset(prev, 0, 32);
    for (int i = 0; i < NB; i++){
        unsigned char* b = blk[i];
        unsigned char* t = b + 81; unsigned char* t0 = t;
        put_u32(t, 1); t += 4; t[0] = 1; t += 1; memset(t, 0, 32); t += 32; put_u32(t, 0xffffffff); t += 4;
        t[0] = 3; t[1] = (unsigned char)i; t[2] = (unsigned char)(i >> 8); t[3] = 0; t += 4; put_u32(t, 0xffffffff); t += 4;
        t[0] = 1; t += 1; put_u64(t, 5000000000ull); t += 8; t[0] = 1; t[1] = 0x51; t += 2; put_u32(t, 0); t += 4;
        put_u32(b, 1); memcpy(b + 4, prev, 32);
        { unsigned char seed[8]; for (int k = 0; k < 8; k++) seed[k] = (unsigned char)(i * 11 + k + (i >> 8)); sha256d(b + 36, seed, 8); }
        put_u32(b + 68, 1300000000u + (unsigned)i); put_u32(b + 72, 0x207fffff); put_u32(b + 76, (unsigned)i * 3);
        b[80] = 1;
        blen[i] = 81 + (t - t0);
        block_hash(bhash[i], b); memcpy(prev, bhash[i], 32);
    }
}

static unsigned char stbuf[4096];
static unsigned char idx[24 + 2048*48];
static unsigned char sout[1<<20];
static int ls; static struct sockaddr_in la;

/* one connection, served by its own forked node_serve_loop */
static pid_t srv_pid;
static int peer_open(void){
    srv_pid = fork();
    if (srv_pid == 0){
        int c = accept(ls, 0, 0);
        if (c < 0) _exit(3);
        if (node_accept_handshake(c) != 1) _exit(4);
        node_serve_loop(c, -1, stbuf, idx, sout, (long)sizeof sout);
        _exit(0);
    }
    int fd = tcp_connect_ip(htonl(INADDR_LOOPBACK), la.sin_port);
    if (fd < 0){ printf("FAIL connect\n"); exit(1); }
    struct timeval tv; tv.tv_sec = 4; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (node_handshake(fd) != 1){ printf("FAIL handshake\n"); exit(1); }
    char c[12]; static unsigned char b[64]; unsigned bl = 0;     /* the serve loop's leading feefilter */
    if (p2p_read(fd, c, b, sizeof b, &bl) <= 0 || strncmp(c, "feefilter", 9)){ printf("FAIL no leading feefilter\n"); exit(1); }
    return fd;
}
static void peer_close(int fd){ close(fd); waitpid(srv_pid, 0, 0); }

/* ---- the reply to one request: every message before the pong for `nonce` */
#define MAXM 16
typedef struct { char cmd[13]; unsigned len; unsigned char* p; } msg_t;
static msg_t rx[MAXM]; static int nrx;
static int rx_eof;               /* the server closed the connection */
static uint64_t g_nonce = 0x6762000000000000ull;
static int reply(int fd){        /* 1 = the pong arrived */
    for (int i = 0; i < nrx; i++) free(rx[i].p);
    nrx = 0; rx_eof = 0;
    uint64_t nonce = ++g_nonce;
    p2p_write(fd, "ping", 4, &nonce, 8);
    static unsigned char rb[1<<20];
    int timeouts = 0;
    for (;;){
        char c[12]; unsigned rl = 0;
        int r = p2p_read(fd, c, rb, sizeof rb, &rl);
        if (r == 0){ rx_eof = 1; return 0; }
        if (r < 0){ if (++timeouts < 4) continue; return 0; }
        if (!strncmp(c, "pong", 4) && rl == 8 && !memcmp(rb, &nonce, 8)) return 1;
        if (nrx < MAXM){
            memcpy(rx[nrx].cmd, c, 12); rx[nrx].cmd[12] = 0;
            rx[nrx].len = rl; rx[nrx].p = malloc(rl ? rl : 1); memcpy(rx[nrx].p, rb, rl); nrx++;
        }
    }
}
static int count_cmd(const char* cmd){ int n = 0; for (int i = 0; i < nrx; i++) if (!strcmp(rx[i].cmd, cmd)) n++; return n; }
static const msg_t* first_cmd(const char* cmd){ for (int i = 0; i < nrx; i++) if (!strcmp(rx[i].cmd, cmd)) return &rx[i]; return 0; }

/* a CompactSize count, then its entries (inv: 36 bytes, headers: 81) */
static long vec_count(const msg_t* m, unsigned* off){
    if (!m || m->len < 1) return -1;
    if (m->p[0] < 0xfd){ *off = 1; return m->p[0]; }
    if (m->p[0] == 0xfd && m->len >= 3){ *off = 3; return m->p[1] | (m->p[2] << 8); }
    return -1;
}
/* the height an inv entry's hash names, read exactly as it is on the wire */
static int inv_height(const msg_t* m, long i){
    unsigned off; long n = vec_count(m, &off);
    if (i >= n || m->len < off + (i + 1) * 36) return -2;
    const unsigned char* e = m->p + off + i * 36;
    if (e[0] != 2 || e[1] || e[2] || e[3]) return -3;           /* MSG_BLOCK */
    for (int h = 0; h < NB; h++) if (!memcmp(e + 4, bhash[h], 32)) return h;
    return -1;
}

/* the inv is exactly heights from..from+n-1, in order */
static int inv_is_range(const msg_t* m, long from, long n){
    unsigned off;
    if (vec_count(m, &off) != n) return 0;
    for (long i = 0; i < n; i++) if (inv_height(m, i) != from + i) return 0;
    return 1;
}

/* version | CompactSize n | n hashes | stop */
static unsigned char req[4 + 3 + 200*32 + 32];
static unsigned build_locator(const unsigned char (*loc)[32], int n, const unsigned char* stop){
    unsigned p = 0;
    put_u32(req, 70016); p = 4;
    if (n < 0xfd) req[p++] = (unsigned char)n;
    else { req[p++] = 0xfd; req[p++] = (unsigned char)n; req[p++] = (unsigned char)(n >> 8); }
    for (int i = 0; i < n; i++){ memcpy(req + p, loc[i], 32); p += 32; }
    if (stop) memcpy(req + p, stop, 32); else memset(req + p, 0, 32);
    return p + 32;
}
static void send_getblocks(int fd, const unsigned char (*loc)[32], int n, const unsigned char* stop){
    p2p_write(fd, "getblocks", 9, req, build_locator(loc, n, stop));
}

int main(void){
    tt_isolate();
    setbuf(stdout, NULL);
    build_chain();
    if (store_init(stbuf) != 1){ printf("FAIL store_init\n"); return 1; }
    for (int i = 0; i < NB; i++) store_append(stbuf, bhash[i], blk[i], blen[i]);
    idx_init(idx, 2048);
    for (int i = 0; i < NB; i++) idx_put(idx, bhash[i], i);

    ls = socket(AF_INET, SOCK_STREAM, 0);
    memset(&la, 0, sizeof la); la.sin_family = AF_INET; la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(ls, (struct sockaddr*)&la, sizeof la); socklen_t al = sizeof la; getsockname(ls, (struct sockaddr*)&la, &al);
    listen(ls, 4);

    /* ---- the inv hashes are in wire (internal) order ----
     * An inv carries block_hash's sha256d output as-is: the bytes the peer
     * puts in its getdata, and what this node's getdata path looks up. The
     * handler wrote each hash byte-reversed (display order), so every entry
     * named a block nobody has. Checked twice: against the hashes directly,
     * and by handing the received entry back as a getdata, which must serve
     * that block byte for byte. */
    { int fd = peer_open();
      unsigned char loc[1][32]; memcpy(loc[0], bhash[3], 32);
      send_getblocks(fd, (const unsigned char (*)[32])loc, 1, 0);
      int pong = reply(fd);
      const msg_t* inv = first_cmd("inv");
      cki("byte order: getblocks is answered with one inv before its pong", pong && count_cmd("inv") == 1, 1);
      cki("byte order: entry 0 is block 4's hash in wire order", inv_height(inv, 0), 4);
      cki("byte order: entry 1 is block 5's hash in wire order", inv_height(inv, 1), 5);
      unsigned char e0[36]; int have = 0;
      { unsigned off; if (inv && vec_count(inv, &off) > 0 && inv->len >= off + 36){ memcpy(e0, inv->p + off, 36); have = 1; } }
      if (have){
          unsigned char gd[37]; gd[0] = 1; memcpy(gd + 1, e0, 36);
          p2p_write(fd, "getdata", 7, gd, sizeof gd);
          pong = reply(fd);
          const msg_t* b = first_cmd("block");
          cki("byte order: the inv entry, sent back as a getdata, serves block 4 byte-exact",
              pong && b && b->len == (unsigned)blen[4] && !memcmp(b->p, blk[4], b->len) && !count_cmd("notfound"), 1);
      } else cki("byte order: the inv entry, sent back as a getdata, serves block 4 byte-exact", 0, 1);
      peer_close(fd); }

    /* ---- hashStop ----
     * Core walks from the fork point's successor and breaks BEFORE the block
     * whose hash is hashStop (exclusive), at most 500 entries. A stop at or
     * below the start height, or unknown, is never met: the full 500 go out.
     * The handler ignored hashStop. Locator [block 3] throughout: the walk
     * starts at 4. */
    { static const struct { int stop; const char* what; long n; } C[] = {
          {  7, "a stop at height 7 announces 4..6 (exclusive)",           3 },
          {  2, "a stop below the start height limits nothing (500)",     500 },
          {  3, "a stop AT the fork point limits nothing (500)",          500 },
          { -1, "an unknown stop hash limits nothing (500)",              500 } };
      for (unsigned k = 0; k < sizeof C / sizeof C[0]; k++){
          int fd = peer_open();
          unsigned char loc[1][32]; memcpy(loc[0], bhash[3], 32);
          unsigned char unk[32]; memset(unk, 0xee, 32);
          send_getblocks(fd, (const unsigned char (*)[32])loc, 1, C[k].stop >= 0 ? bhash[C[k].stop] : unk);
          int pong = reply(fd);
          char lbl[160]; snprintf(lbl, sizeof lbl, "hashStop: %s", C[k].what);
          cki(lbl, pong && count_cmd("inv") == 1 && inv_is_range(first_cmd("inv"), 4, C[k].n), 1);
          peer_close(fd);
      } }

    close(ls);
    printf("\n%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
