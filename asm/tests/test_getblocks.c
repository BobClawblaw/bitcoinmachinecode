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
#include <time.h>
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
extern void reorg_set_min_chain_work(const unsigned char be32[32]);
extern void serve_hdrctx_test_set_now(long t);

/* this connection's permissions, as main.c reports them to the serve gates */
static unsigned g_perms = 0;
unsigned serve_conn_perms(void){ return g_perms; }

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

static void send_getheaders(int fd, const unsigned char (*loc)[32], int n, const unsigned char* stop){
    p2p_write(fd, "getheaders", 10, req, build_locator(loc, n, stop));
}
/* the server hung up without a word: the next read is EOF (nothing was
 * written to it since, so the close is a FIN, not a reset) */
static int closed_silently(int fd){
    char c[12]; static unsigned char b[1<<16]; unsigned bl = 0;
    return p2p_read(fd, c, b, sizeof b, &bl) == 0;
}
static void send_getdata(int fd, unsigned type, const unsigned char* hash){
    unsigned char gd[37]; gd[0] = 1; put_u32(gd + 1, type); memcpy(gd + 5, hash, 32);
    p2p_write(fd, "getdata", 7, gd, sizeof gd);
}
/* the reply to a getdata for block h: [the block (in `form`), inv(tip)?] */
static int got_block_then(const char* form, int h, int want_tipinv){
    if (nrx < 1 || strcmp(rx[0].cmd, form)) return 0;
    if (!strcmp(form, "block") && (rx[0].len != (unsigned)blen[h] || memcmp(rx[0].p, blk[h], rx[0].len))) return 0;
    if (!strcmp(form, "cmpctblock") && (rx[0].len < 80 || memcmp(rx[0].p, blk[h], 80))) return 0;
    if (!want_tipinv) return nrx == 1;
    unsigned off;
    return nrx == 2 && !strcmp(rx[1].cmd, "inv") && vec_count(&rx[1], &off) == 1 && inv_height(&rx[1], 0) == TIP;
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

    /* ---- nothing to announce: no inv at all ----
     * With hashStop = the first block past the fork point, or a locator at
     * our tip, Core queues nothing, and SendMessages pushes no inv for an
     * empty m_blocks_for_inv_relay (net_processing.cpp 5965-6092). The
     * handler sent an empty inv (count 0). */
    { int fd = peer_open();
      unsigned char loc[1][32]; memcpy(loc[0], bhash[3], 32);
      send_getblocks(fd, (const unsigned char (*)[32])loc, 1, bhash[4]);
      int pong = reply(fd);
      cki("empty: hashStop = the first block past the fork point sends no inv", pong && count_cmd("inv") == 0, 1);
      memcpy(loc[0], bhash[TIP], 32);
      send_getblocks(fd, (const unsigned char (*)[32])loc, 1, 0);
      pong = reply(fd);
      cki("empty: a locator at our tip sends no inv", pong && count_cmd("inv") == 0, 1);
      peer_close(fd); }

    /* ---- the continuation inv (Core's m_continuation_block) ----
     * A getblocks that stops at the 500 limit remembers the 500th block;
     * when the peer asks for exactly that block, Core sends inv(MSG_BLOCK,
     * tip) right after it and forgets it (ProcessGetBlockData). That inv is
     * what makes an old-style getblocks sync ask for the next batch. The
     * handler never sent it. Locator [genesis]: the reply is 1..500. Each
     * request form the getdata path serves is covered: MSG_BLOCK (stripped),
     * MSG_WITNESS_BLOCK (full) and MSG_CMPCT_BLOCK -- which, for blocks 19
     * and 20 below the tip, Core answers with the full block (more than
     * MAX_CMPCTBLOCK_DEPTH deep; see "compact only near the tip" below). */
    { static const struct { unsigned type; const char* form; const char* name; } F[] = {
          { 2,          "block",      "MSG_BLOCK" },
          { 0x40000002, "block",      "MSG_WITNESS_BLOCK" },
          { 4,          "block",      "MSG_CMPCT_BLOCK" } };
      for (unsigned k = 0; k < sizeof F / sizeof F[0]; k++){
          int fd = peer_open();
          char lbl[200];
          if (F[k].type == 4){                     /* BIP152 v2, low-bandwidth */
              unsigned char sc[9]; sc[0] = 0; put_u64(sc + 1, 2);
              p2p_write(fd, "sendcmpct", 9, sc, 9);
          }
          unsigned char loc[1][32]; memcpy(loc[0], bhash[0], 32);
          send_getblocks(fd, (const unsigned char (*)[32])loc, 1, 0);
          int pong = reply(fd);
          snprintf(lbl, sizeof lbl, "continuation (%s): getblocks from genesis announces 1..500", F[k].name);
          cki(lbl, pong && count_cmd("inv") == 1 && inv_is_range(first_cmd("inv"), 1, 500), 1);
          send_getdata(fd, F[k].type, bhash[499]);
          pong = reply(fd);
          snprintf(lbl, sizeof lbl, "continuation (%s): getdata block 499 -> the block, no inv", F[k].name);
          cki(lbl, pong && got_block_then(F[k].form, 499, 0), 1);
          send_getdata(fd, F[k].type, bhash[500]);
          pong = reply(fd);
          snprintf(lbl, sizeof lbl, "continuation (%s): getdata block 500 -> the block, then inv(tip %d)", F[k].name, TIP);
          cki(lbl, pong && got_block_then(F[k].form, 500, 1), 1);
          send_getdata(fd, F[k].type, bhash[500]);
          pong = reply(fd);
          snprintf(lbl, sizeof lbl, "continuation (%s): block 500 again -> no inv (it was forgotten)", F[k].name);
          cki(lbl, pong && got_block_then(F[k].form, 500, 0), 1);
          peer_close(fd);
      } }
    /* a reply below the limit sets no continuation: locator [block 100]
     * announces 101..519 (419); neither its last block nor block 500 is
     * followed by an inv */
    { int fd = peer_open();
      unsigned char loc[1][32]; memcpy(loc[0], bhash[100], 32);
      send_getblocks(fd, (const unsigned char (*)[32])loc, 1, 0);
      int pong = reply(fd);
      cki("continuation: getblocks from 100 announces 101..519", pong && inv_is_range(first_cmd("inv"), 101, TIP - 100), 1);
      send_getdata(fd, 2, bhash[TIP]);
      pong = reply(fd);
      cki("continuation: below the limit, its last block is not followed by an inv", pong && got_block_then("block", TIP, 0), 1);
      send_getdata(fd, 2, bhash[500]);
      pong = reply(fd);
      cki("continuation: below the limit, block 500 is not followed by an inv", pong && got_block_then("block", 500, 0), 1);
      peer_close(fd); }

    /* ---- MAX_LOCATOR_SZ: a complete locator of 102 entries disconnects ----
     * Core (net_processing.cpp 4272 getblocks, 4399 getheaders) sets
     * fDisconnect for vHave.size() > 101, after the whole locator and the
     * stop hash have been read. Both handlers dropped the message and kept
     * the peer. 101 entries is still served; a count of 102 over a body too
     * short to hold it is a parse failure, dropped with the connection kept. */
    { static unsigned char many[102][32];
      for (int i = 0; i < 102; i++){ memset(many[i], 0xab, 32); many[i][0] = (unsigned char)i; }
      memcpy(many[100], bhash[3], 32);                  /* entry 101 of 101 is known */
      for (int kd = 0; kd < 2; kd++){
          const char* kind = kd ? "getheaders" : "getblocks";
          char lbl[200];
          int fd = peer_open();
          if (kd) send_getheaders(fd, (const unsigned char (*)[32])many, 102, 0);
          else    send_getblocks(fd, (const unsigned char (*)[32])many, 102, 0);
          snprintf(lbl, sizeof lbl, "MAX_LOCATOR_SZ: a %s with 102 locator entries is disconnected", kind);
          cki(lbl, closed_silently(fd), 1);
          peer_close(fd);

          fd = peer_open();
          if (kd) send_getheaders(fd, (const unsigned char (*)[32])many, 101, 0);
          else    send_getblocks(fd, (const unsigned char (*)[32])many, 101, 0);
          int pong = reply(fd);
          const msg_t* m = first_cmd(kd ? "headers" : "inv");
          unsigned off = 0; long n = vec_count(m, &off);
          int from4 = kd ? (n > 0 && m->len >= off + 80 && !memcmp(m->p + off, blk[4], 80))
                         : (n > 0 && inv_height(m, 0) == 4);
          snprintf(lbl, sizeof lbl, "MAX_LOCATOR_SZ: a %s with 101 entries is served (from height 4)", kind);
          cki(lbl, pong && from4, 1);
          /* count 102 over 3 hashes + stop: short, a parse failure */
          unsigned len = build_locator((const unsigned char (*)[32])many, 3, 0);
          req[4] = 102;
          p2p_write(fd, kind, (unsigned)strlen(kind), req, len);
          pong = reply(fd);
          snprintf(lbl, sizeof lbl, "MAX_LOCATOR_SZ: a %s claiming 102 entries in a short body is dropped, connection kept", kind);
          cki(lbl, pong && !rx_eof && count_cmd(kd ? "headers" : "inv") == 0, 1);
          peer_close(fd);
      } }

    /* ---- no locator entry known: served from height 1 ----
     * Core's FindForkInGlobalIndex returns genesis when no entry is on the
     * active chain (validation.cpp 127-143), and both handlers start at its
     * successor. bmc started at 0 and sent genesis first, a block every peer
     * has. An empty getblocks locator is the same case in Core. */
    { int fd = peer_open();
      unsigned char loc[2][32]; memset(loc[0], 0xab, 32); memset(loc[1], 0xac, 32);
      send_getblocks(fd, (const unsigned char (*)[32])loc, 2, 0);
      int pong = reply(fd);
      cki("unknown locator: getblocks announces 1..500", pong && inv_is_range(first_cmd("inv"), 1, 500), 1);
      send_getblocks(fd, (const unsigned char (*)[32])loc, 0, 0);
      pong = reply(fd);
      cki("empty locator: getblocks announces 1..500", pong && inv_is_range(first_cmd("inv"), 1, 500), 1);
      send_getheaders(fd, (const unsigned char (*)[32])loc, 2, 0);
      pong = reply(fd);
      const msg_t* m = first_cmd("headers"); unsigned off = 0; long n = vec_count(m, &off);
      cki("unknown locator: getheaders serves 1..519 (first header is block 1's)",
          pong && n == TIP && m->len >= off + 81 && !memcmp(m->p + off, blk[1], 80), 1);
      peer_close(fd); }

    /* ---- an EMPTY getheaders locator asks for the hashStop header alone ----
     * Core (GETHEADERS, net_processing.cpp 4426-4436): LookupBlockIndex
     * (hashStop); unknown -> no reply at all; known -> that header, and the
     * walk breaks on it. The handler served from the start of the chain. */
    { int fd = peer_open();
      unsigned char unk[32]; memset(unk, 0xee, 32);
      send_getheaders(fd, 0, 0, bhash[5]);
      int pong = reply(fd);
      const msg_t* m = first_cmd("headers"); unsigned off = 0; long n = vec_count(m, &off);
      cki("empty getheaders locator, stop = block 5: exactly block 5's header",
          pong && count_cmd("headers") == 1 && n == 1 && m->len == off + 81 && !memcmp(m->p + off, blk[5], 80), 1);
      send_getheaders(fd, 0, 0, unk);
      pong = reply(fd);
      cki("empty getheaders locator, unknown stop: no reply", pong && nrx == 0, 1);
      send_getheaders(fd, 0, 0, 0);
      pong = reply(fd);
      cki("empty getheaders locator, all-zero stop: no reply", pong && nrx == 0, 1);
      peer_close(fd); }

    /* ---- no stall after a getheaders ----
     * The handler logs each getheaders through node_log_event to the loop's
     * log fd, -1 here as in every serve harness. fd_write_all polled it
     * first, and poll(2) ignores a negative fd, so it waited its whole 10 s
     * timeout before failing: the next message was answered 10 s late. */
    { int fd = peer_open();
      unsigned char loc[1][32]; memcpy(loc[0], bhash[3], 32);
      struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
      send_getheaders(fd, (const unsigned char (*)[32])loc, 1, 0);
      int pong = reply(fd);
      clock_gettime(CLOCK_MONOTONIC, &t1);
      long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
      printf("      getheaders + ping answered in %ld ms\n", ms);
      cki("no stall: a getheaders and the ping after it are answered within 2 s (log fd -1)",
          pong && count_cmd("headers") == 1 && ms < 2000, 1);
      peer_close(fd); }

    /* ---- getdata(MSG_CMPCT_BLOCK): compact only near a fresh tip ----
     * Core (ProcessGetBlockData, net_processing.cpp 2463-2477): a compact
     * block only when CanDirectFetch() (the tip's nTime within 20 block
     * intervals, 12,000 s, of now) and the block is at most
     * MAX_CMPCTBLOCK_DEPTH (5) below the tip; otherwise the full block. bmc
     * built a compact block at any depth. The tip's nTime here is
     * 1300000000 + 519; the server's clock is set relative to it. */
    { const long tipt = 1300000000L + TIP;
      static const struct { long now_off; int h; const char* form; const char* what; } K[] = {
          { 60,        TIP - 5, "cmpctblock", "fresh tip, block 5 below it: cmpctblock" },
          { 60,        TIP - 6, "block",      "fresh tip, block 6 below it: the full block" },
          { 60,        TIP,     "cmpctblock", "fresh tip, the tip itself: cmpctblock" },
          { 12000 - 1, TIP,     "cmpctblock", "tip 11,999 s old (inside 20 intervals): cmpctblock" },
          { 12000,     TIP,     "block",      "tip 12,000 s old (CanDirectFetch false): the full block" } };
      for (unsigned k = 0; k < sizeof K / sizeof K[0]; k++){
          serve_hdrctx_test_set_now(tipt + K[k].now_off);
          int fd = peer_open();
          unsigned char sc[9]; sc[0] = 0; put_u64(sc + 1, 2);
          p2p_write(fd, "sendcmpct", 9, sc, 9);
          send_getdata(fd, 4, bhash[K[k].h]);
          int pong = reply(fd);
          char lbl[200]; snprintf(lbl, sizeof lbl, "compact near the tip: %s", K[k].what);
          cki(lbl, pong && got_block_then(K[k].form, K[k].h, 0), 1);
          peer_close(fd);
      }
      /* the compact path serves the block asked for, as the block path does
       * (STO-10): a hash the child's index maps to a height whose block is
       * another one (a reorg behind) is notfound, not that block */
      serve_hdrctx_test_set_now(tipt + 60);
      unsigned char ghost[32]; memcpy(ghost, bhash[TIP - 1], 32); ghost[0] ^= 0x77;
      idx_put(idx, ghost, TIP - 1);
      int fd = peer_open();
      unsigned char sc[9]; sc[0] = 0; put_u64(sc + 1, 2);
      p2p_write(fd, "sendcmpct", 9, sc, 9);
      send_getdata(fd, 4, ghost);
      int pong = reply(fd);
      cki("compact near the tip: a stale index entry is notfound, not the block now at that height",
          pong && count_cmd("cmpctblock") == 0 && count_cmd("block") == 0 && count_cmd("notfound") == 1, 1);
      peer_close(fd);
      serve_hdrctx_test_set_now(0); }

    /* ---- getheaders below -minimumchainwork: an empty headers message ----
     * Core (GETHEADERS, net_processing.cpp 4410-4422): while the active
     * chain's work is below the floor, and the peer lacks the download
     * permission, getheaders is answered with an empty headers message --
     * after the locator checks, before either walk, so an empty locator
     * gets it too. bmc served its headers regardless. chainwork.dat gets one
     * cumulative record per height, work h+1 at height h (16 bytes LE); the
     * tip's is 520. */
    { FILE* f = fopen("chainwork.dat", "wb");
      for (int h = 0; f && h < NB; h++){ unsigned char w[16]; memset(w, 0, 16); put_u32(w, (unsigned)h + 1); fwrite(w, 1, 16, f); }
      if (f) fclose(f);
      static const struct { unsigned floor; unsigned perms; int empty; const char* what; } W[] = {
          { 521, 0,                       1, "floor 521 above the tip's work 520: an empty headers message" },
          { 521, 1u << 4 /* download */,  0, "floor 521, peer with the download permission: served" },
          { 521, 1u << 0 /* noban */,     0, "floor 521, peer with noban (implies download): served" },
          { 520, 0,                       0, "floor 520 = the tip's work: served" } };
      for (unsigned k = 0; k < sizeof W / sizeof W[0]; k++){
          unsigned char be[32]; memset(be, 0, 32);
          be[28] = (unsigned char)(W[k].floor >> 24); be[29] = (unsigned char)(W[k].floor >> 16);
          be[30] = (unsigned char)(W[k].floor >> 8);  be[31] = (unsigned char)W[k].floor;
          reorg_set_min_chain_work(be);
          g_perms = W[k].perms & (1u << 0) ? (W[k].perms | (1u << 4)) : W[k].perms;   /* netperm: noban implies download */
          int fd = peer_open();
          unsigned char loc[1][32]; memcpy(loc[0], bhash[3], 32);
          send_getheaders(fd, (const unsigned char (*)[32])loc, 1, 0);
          int pong = reply(fd);
          const msg_t* m = first_cmd("headers"); unsigned off = 0; long n = vec_count(m, &off);
          char lbl[200]; snprintf(lbl, sizeof lbl, "min chain work: %s", W[k].what);
          cki(lbl, pong && count_cmd("headers") == 1 && (W[k].empty ? (n == 0 && m->len == 1) : n == TIP - 3), 1);
          if (k == 0){
              send_getheaders(fd, 0, 0, bhash[5]);
              pong = reply(fd);
              m = first_cmd("headers"); off = 0; n = vec_count(m, &off);
              cki("min chain work: an empty locator (stop = block 5) also gets the empty headers message",
                  pong && count_cmd("headers") == 1 && n == 0 && m->len == 1, 1);
          }
          peer_close(fd);
      }
      /* the record for the tip not written yet: the last one decides (work
       * only grows with height). Records 0..399, floor 400 = record 399's. */
      if (truncate("chainwork.dat", 400 * 16) != 0) printf("FAIL truncate chainwork.dat\n");
      unsigned char be[32]; memset(be, 0, 32); be[30] = 400 >> 8; be[31] = 400 & 0xff;
      reorg_set_min_chain_work(be); g_perms = 0;
      int fd = peer_open();
      unsigned char loc[1][32]; memcpy(loc[0], bhash[3], 32);
      send_getheaders(fd, (const unsigned char (*)[32])loc, 1, 0);
      int pong = reply(fd);
      const msg_t* m = first_cmd("headers"); unsigned off = 0; long n = vec_count(m, &off);
      cki("min chain work: chainwork.dat behind the tip, its last record clears the floor: served", pong && n == TIP - 3, 1);
      peer_close(fd);
      memset(be, 0, 32); reorg_set_min_chain_work(be);              /* no floor for what follows */
    }

    /* ---- a hash index a reorg behind: the archive decides ----
     * A serve child keeps its own hash index; after a reorg it maps the
     * losing branch's hashes to their heights until serve_reorg_check
     * rebuilds it, and getheaders reached that check only after the locator
     * walk. Here index.dat's records 510..519 are rewritten to another
     * branch's hashes and the child's index is left as it was. Core walks
     * the locator against its active chain (FindForkInGlobalIndex,
     * chain.Contains): an entry off it is skipped, a stop hash off it is
     * never met. getdata is untouched: it serves by height from the index.
     * Kept last: nothing after this needs the old records. */
    { FILE* f = fopen("index.dat", "r+b");
      int ok = f != 0;
      for (int h = 510; ok && h <= TIP; h++){
          unsigned char rec[48];
          ok = fseek(f, (long)h * 48, SEEK_SET) == 0 && fread(rec, 1, 48, f) == 48;
          rec[31] ^= 0x5a;                                /* branch B's block at h */
          ok = ok && fseek(f, (long)h * 48, SEEK_SET) == 0 && fwrite(rec, 1, 48, f) == 48;
      }
      if (f) fclose(f);
      cki("stale index: index.dat 510..519 rewritten to another branch", ok, 1);

      int fd = peer_open();
      unsigned char loc[2][32]; memcpy(loc[0], bhash[515], 32); memcpy(loc[1], bhash[505], 32);
      send_getheaders(fd, (const unsigned char (*)[32])loc, 2, 0);
      int pong = reply(fd);
      const msg_t* m = first_cmd("headers"); unsigned off = 0; long n = vec_count(m, &off);
      cki("stale index: locator [old 515, 505] serves from 506 (the stale entry skipped), 14 headers",
          pong && n == TIP - 505 && m->len >= off + 81 && !memcmp(m->p + off, blk[506], 80), 1);

      memcpy(loc[0], bhash[3], 32);
      send_getheaders(fd, (const unsigned char (*)[32])loc, 1, bhash[512]);
      pong = reply(fd);
      m = first_cmd("headers"); off = 0; n = vec_count(m, &off);
      cki("stale index: a stop hash off the active chain caps nothing (4..519, 516 headers)",
          pong && n == TIP - 3, 1);
      peer_close(fd); }

    close(ls);
    printf("\n%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
