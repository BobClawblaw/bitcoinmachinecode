/* tests/test_addrv2_serve.c -- BIP155 addrv2 NEGOTIATION and the getaddr
 * reply, both roles, against Bitcoin Core's own bytes.
 *
 * What it proves (2026-08-28):
 *   1. INBOUND role (node_accept_handshake): a 70016 peer is offered
 *      `sendaddrv2` after our version and BEFORE our verack -- the window
 *      Core requires -- and a 70015 peer is not (Core's courtesy gate).
 *   2. A peer that did NOT send sendaddrv2 gets a legacy `addr` reply to
 *      getaddr whose bytes equal Core's msg_addr for the same three records.
 *   3. A peer that DID send sendaddrv2 before verack gets `addrv2` instead,
 *      byte-equal to Core's msg_addrv2 -- Core never sends v1 to such a peer.
 *   4. A 1200-record book is answered with exactly 1000 (MAX_ADDR_TO_SEND,
 *      3-byte CompactSize count) and the server is still alive afterwards.
 *      Before this date the reply loop clobbered its own bound and never
 *      answered anyone; with a real book it would have overrun two buffers.
 *   5. OUTBOUND role (node_handshake): we offer sendaddrv2 to a 70016 peer
 *      once its version arrives, withhold it from a 70015 peer, and record
 *      the peer's own sendaddrv2 in g_peer_wants_addrv2.
 *   6. A sendaddrv2 or wtxidrelay arriving AFTER verack is a protocol
 *      violation (both are handshake-only); Core disconnects, and so does
 *      the serve loop -- the connection closes instead of being ignored.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include "block_vec.h"
#include "test_tmpdir.h"

extern long node_make_version(void* out);
extern long node_handshake(int fd);
extern int  node_accept_handshake(int fd);
extern long node_serve_loop(int fd, int lfd, void* st, void* ht_idx, void* out, long cap);
extern int  tcp_connect_ip(unsigned, unsigned short);
extern long store_init(void* st);
extern long store_append(void* st, const unsigned char h[32], const void* blk, long blen);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void idx_init(void* idx, unsigned long slots);
extern int  idx_put(void* idx, const unsigned char hash[32], long height);
extern long p2p_write(int, const char*, unsigned, const void*, unsigned);
extern int  p2p_read(int, char[12], void*, unsigned, unsigned*);
extern long g_peer_wants_addrv2;
#include "../daemon/addrbook.h"

static int failures=0;
static void ck(const char*l,int ok){ if(ok) printf("PASS %s\n",l); else{ printf("FAIL %s\n",l); failures++; } }
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }

/* Core's bytes for records (5.6.7.8:8333 svc 9 t 1700000000)
 * (9.10.11.12:8333 svc 1 t 1700000001) (200.1.2.3:8334 svc 0x409 t 1700000002):
 * test_framework/messages.py msg_addr / msg_addrv2. */
static const unsigned char CORE_V1_3[] = {
  0x03,
  0x00,0xf1,0x53,0x65, 0x09,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0xff,0xff, 5,6,7,8, 0x20,0x8d,
  0x01,0xf1,0x53,0x65, 0x01,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0xff,0xff, 9,10,11,12, 0x20,0x8d,
  0x02,0xf1,0x53,0x65, 0x09,0x04,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0xff,0xff, 200,1,2,3, 0x20,0x8e };
static const unsigned char CORE_V2_3[] = {
  0x03,
  0x00,0xf1,0x53,0x65, 0x09, 0x01, 0x04, 5,6,7,8, 0x20,0x8d,
  0x01,0xf1,0x53,0x65, 0x01, 0x01, 0x04, 9,10,11,12, 0x20,0x8d,
  0x02,0xf1,0x53,0x65, 0xfd,0x09,0x04, 0x01, 0x04, 200,1,2,3, 0x20,0x8e };

static unsigned char stbuf[1<<16];
static unsigned char idx[24 + 64*48];
static struct sockaddr_in g_srv;
static int g_ls;

static void build_store(void){
    unsigned char bh[32];
    store_init(stbuf); block_hash(bh, BLOCK_RAW);
    store_append(stbuf, bh, BLOCK_RAW, (long)sizeof BLOCK_RAW);
    idx_init(idx, 64); idx_put(idx, bh, 0);
}
/* the version-2 book (peers2.dat) in the test's private CWD */
static void book_reset(void){ unlink("peers.dat"); unlink("peers2.dat"); }
static void book_add(const char* hostport, unsigned long long svc, unsigned seen){
    ab2_t* b = ab2_open(".", 1); bmc_addr_t a;
    if (b && bmc_addr_from_string_port(&a, hostport, 0)) ab2_add(b, &a, svc, seen);
    ab2_close(b);
}
static void book3(void){
    book_reset();
    book_add("5.6.7.8:8333", 9, 1700000000u);
    book_add("9.10.11.12:8333", 1, 1700000001u);
    book_add("200.1.2.3:8334", 0x409, 1700000002u);
}
static void book1200(void){
    book_reset();
    ab2_t* b = ab2_open(".", 1);
    for (unsigned k = 0; k < 1200; k++){
        bmc_addr_t a; memset(&a, 0, sizeof a); a.net = BMC_NET_IPV4; a.len = 4;
        a.addr[0] = 11; a.addr[1] = (unsigned char)(k >> 8); a.addr[2] = (unsigned char)k; a.addr[3] = 7; a.port = 8333;
        ab2_add(b, &a, 9, 1700000000u + k);
    }
    ab2_close(b);
}
/* a serve child for the NEXT connection */
static pid_t spawn_server(void){
    pid_t pid = fork();
    if (pid == 0){
        int c = accept(g_ls, 0, 0); if (c < 0) _exit(3);
        if (node_accept_handshake(c) != 1) _exit(4);
        static unsigned char so[1<<22];
        node_serve_loop(c, -1, stbuf, idx, so, (long)sizeof so);
        _exit(0);
    }
    return pid;
}
/* raw client handshake: send version (patched to `proto`), collect what the
 * server sends before its verack, optionally send sendaddrv2, then verack.
 * Returns fd; *offered = server sent sendaddrv2 pre-verack. */
static int g_saw_verack;   /* set by raw_client: the server completed its side */
static int raw_client(unsigned proto, int send_v2, int* offered, int* saw_wtxid){
    int fd = tcp_connect_ip(htonl(INADDR_LOOPBACK), g_srv.sin_port);
    struct timeval tv; tv.tv_sec = 8; tv.tv_usec = 0; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    unsigned char v[160]; long n = node_make_version(v);
    memcpy(v, &proto, 4);
    p2p_write(fd, "version", 7, v, (unsigned)n);
    *offered = 0; *saw_wtxid = 0; g_saw_verack = 0;
    char cmd[12]; static unsigned char buf[1<<16]; unsigned bl = 0;
    for (int i = 0; i < 8; i++){
        if (p2p_read(fd, cmd, buf, sizeof buf, &bl) <= 0) break;
        cmd[11] = 0;
        if (!strncmp(cmd, "sendaddrv2", 10)) *offered = 1;
        if (!strncmp(cmd, "wtxidrelay", 10)) *saw_wtxid = 1;
        if (!strncmp(cmd, "verack", 6)){ g_saw_verack = 1; break; }
    }
    if (send_v2) p2p_write(fd, "sendaddrv2", 10, "", 0);
    p2p_write(fd, "verack", 6, "", 0);
    /* the serve loop's first message is its feefilter; if it does not
     * arrive the server never entered node_serve_loop */
    if (p2p_read(fd, cmd, buf, sizeof buf, &bl) <= 0 || strncmp(cmd, "feefilter", 9)) g_saw_verack = 0;
    return fd;
}
static int getaddr_reply(int fd, char cmd[12], unsigned char* buf, unsigned cap, unsigned* bl){
    p2p_write(fd, "getaddr", 7, "", 0);
    int r = p2p_read(fd, cmd, buf, cap, bl);
    if (r > 0) cmd[11] = 0;
    return r;
}

/* ---- outbound role: a scripted peer that speaks `proto` and may send
 * sendaddrv2; exit bits report what it saw from us before our verack:
 * 1 = wtxidrelay, 2 = sendaddrv2 */
static void fake_peer(int c, unsigned proto, int send_v2){
    char cmd[12]; unsigned char rb[1<<12]; unsigned plen = 0; int seen = 0;
    if (p2p_read(c, cmd, rb, sizeof rb, &plen) <= 0) _exit(0x40);   /* our version */
    unsigned char v[160]; long n = node_make_version(v); memcpy(v, &proto, 4);
    p2p_write(c, "version", 7, v, (unsigned)n);
    if (send_v2) p2p_write(c, "sendaddrv2", 10, "", 0);
    p2p_write(c, "verack", 6, "", 0);
    for (int i = 0; i < 8; i++){
        if (p2p_read(c, cmd, rb, sizeof rb, &plen) <= 0) break;
        cmd[11] = 0;
        if (!strncmp(cmd, "wtxidrelay", 10)) seen |= 1;
        if (!strncmp(cmd, "sendaddrv2", 10)) seen |= 2;
        if (!strncmp(cmd, "verack", 6)) break;
    }
    _exit(seen);
}
static int outbound_case(unsigned proto, int peer_sends_v2, long* wants){
    pid_t pid = fork();
    if (pid == 0){ int c = accept(g_ls, 0, 0); fake_peer(c, proto, peer_sends_v2); }
    int fd = tcp_connect_ip(htonl(INADDR_LOOPBACK), g_srv.sin_port);
    struct timeval tv; tv.tv_sec = 8; tv.tv_usec = 0; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    long hk = node_handshake(fd);
    *wants = g_peer_wants_addrv2;
    close(fd);
    int st = 0; waitpid(pid, &st, 0);
    return hk == 1 ? (WIFEXITED(st) ? WEXITSTATUS(st) : 0x80) : 0x100;
}

int main(void){
    tt_isolate();
    setbuf(stdout, NULL);
    build_store();
    g_ls = socket(AF_INET, SOCK_STREAM, 0);
    memset(&g_srv, 0, sizeof g_srv); g_srv.sin_family = AF_INET; g_srv.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(g_ls, (struct sockaddr*)&g_srv, sizeof g_srv);
    socklen_t al = sizeof g_srv; getsockname(g_ls, (struct sockaddr*)&g_srv, &al); listen(g_ls, 4);
    char cmd[12]; static unsigned char buf[1<<16]; unsigned bl = 0; int off, wt;

    printf("== 1. inbound handshake offers sendaddrv2 to a 70016 peer, before verack ==\n");
    book3();
    pid_t s1 = spawn_server();
    int fdA = raw_client(70016, 0, &off, &wt);
    ck("wtxidrelay offered (BIP339, unchanged)", wt == 1);
    ck("sendaddrv2 offered before verack (BIP155)", off == 1 && g_saw_verack == 1);

    printf("\n== 2. peer WITHOUT sendaddrv2: legacy addr, byte-equal to Core's msg_addr ==\n");
    int r = getaddr_reply(fdA, cmd, buf, sizeof buf, &bl);
    ck("getaddr answered", r > 0);
    ck("command is addr (not addrv2)", r > 0 && !strcmp(cmd, "addr"));
    cki("payload length == Core's", (long)bl, (long)sizeof CORE_V1_3);
    ck("payload bytes == Core msg_addr (::ffff: mapped IPv4)", bl == sizeof CORE_V1_3 && memcmp(buf, CORE_V1_3, bl) == 0);
    close(fdA); kill(s1, 9); waitpid(s1, 0, 0);

    printf("\n== 3. peer WITH sendaddrv2 before verack: addrv2, byte-equal to Core's msg_addrv2 ==\n");
    pid_t s2 = spawn_server();
    int fdB = raw_client(70016, 1, &off, &wt);
    r = getaddr_reply(fdB, cmd, buf, sizeof buf, &bl);
    ck("getaddr answered", r > 0);
    ck("command is addrv2", r > 0 && !strcmp(cmd, "addrv2"));
    cki("payload length == Core's", (long)bl, (long)sizeof CORE_V2_3);
    ck("payload bytes == Core msg_addrv2", bl == sizeof CORE_V2_3 && memcmp(buf, CORE_V2_3, bl) == 0);
    close(fdB); kill(s2, 9); waitpid(s2, 0, 0);

    printf("\n== 4. a 70015 peer is not offered sendaddrv2 (Core's courtesy gate) ==\n");
    pid_t s3 = spawn_server();
    int fdC = raw_client(70015, 0, &off, &wt);
    ck("handshake still completes for a 70015 peer (verack seen, then feefilter)", g_saw_verack == 1);
    ck("no sendaddrv2 offered to a 70015 peer", off == 0);
    close(fdC); kill(s3, 9); waitpid(s3, 0, 0);

    printf("\n== 5. 1200-record book: exactly 1000 answered, 3-byte count, server survives ==\n");
    book1200();
    pid_t s4 = spawn_server();
    int fdD = raw_client(70016, 0, &off, &wt);
    r = getaddr_reply(fdD, cmd, buf, sizeof buf, &bl);
    ck("getaddr answered from a 1200-record book", r > 0 && !strcmp(cmd, "addr"));
    ck("count prefix fd e8 03 (= 1000)", bl >= 3 && buf[0] == 0xfd && buf[1] == 0xe8 && buf[2] == 0x03);
    cki("payload length 3 + 1000*30", (long)bl, 3 + 1000*30);
    /* every one of the 1000 records must be a DISTINCT planted entry whose
     * timestamp matches its address (the walk starts at a random offset when
     * the book exceeds 1000, as Core's reply is randomised, so order is not
     * pinned -- membership, consistency and uniqueness are) */
    { int bad = 0; static unsigned char seen[1200]; memset(seen, 0, sizeof seen);
      for (unsigned k = 0; k < 1000 && bl == 3 + 1000*30; k++){
          const unsigned char* rr = buf + 3 + k*30;
          unsigned t = (unsigned)rr[0] | ((unsigned)rr[1]<<8) | ((unsigned)rr[2]<<16) | ((unsigned)rr[3]<<24);
          unsigned idx = ((unsigned)rr[25] << 8) | rr[26];
          int okrec = idx < 1200 && !seen[idx] && t == 1700000000u + idx && rr[4] == 9 && rr[11] == 0
                   && rr[22] == 0xff && rr[23] == 0xff && rr[24] == 11 && rr[27] == 7
                   && rr[28] == 0x20 && rr[29] == 0x8d;
          if (okrec) seen[idx] = 1; else bad++;
      }
      ck("all 1000 records are distinct planted entries with consistent timestamps, ports 20 8d", bl == 3 + 1000*30 && bad == 0); }
    /* Core answers getaddr once per connection and ignores repeats: a second
     * getaddr followed by a ping must yield the pong FIRST, not another addr */
    { unsigned char nonce[8] = {9,8,7,6,5,4,3,2};
      p2p_write(fdD, "getaddr", 7, "", 0);
      p2p_write(fdD, "ping", 4, nonce, 8);
      r = p2p_read(fdD, cmd, buf, sizeof buf, &bl);
      ck("repeat getaddr ignored (Core m_getaddr_recvd): next message is the pong", r > 0 && !strncmp(cmd, "pong", 4) && bl >= 8 && memcmp(buf, nonce, 8) == 0); }
    close(fdD); kill(s4, 9); waitpid(s4, 0, 0);

    printf("\n== 6. outbound role (node_handshake) ==\n");
    long wants = -1;
    int seen = outbound_case(70016, 1, &wants);
    ck("outbound handshake completed", seen < 0x100);
    ck("we sent wtxidrelay before our verack", (seen & 1) == 1);
    ck("we sent sendaddrv2 before our verack (70016 peer)", (seen & 2) == 2);
    cki("peer's sendaddrv2 recorded in g_peer_wants_addrv2", wants, 1);
    seen = outbound_case(70015, 0, &wants);
    ck("outbound handshake completed (70015 peer)", seen < 0x100);
    ck("no sendaddrv2 sent to a 70015 peer", (seen & 2) == 0);
    cki("g_peer_wants_addrv2 reset to 0 for a peer that did not ask", wants, 0);
    seen = outbound_case(70016, 0, &wants);
    ck("70016 peer that stays silent: offered, not recorded", (seen & 2) == 2 && wants == 0);

    printf("\n== 7. sendaddrv2 / wtxidrelay AFTER verack: disconnect, as Core does ==\n");
    book3();
    for (int which = 0; which < 2; which++){
        const char* late = which ? "wtxidrelay" : "sendaddrv2";
        pid_t sp = spawn_server();
        int fdE = raw_client(70016, 0, &off, &wt);
        p2p_write(fdE, late, 10, "", 0);
        unsigned char nonce[8] = {1,1,2,3,5,8,13,21};
        p2p_write(fdE, "ping", 4, nonce, 8);
        r = p2p_read(fdE, cmd, buf, sizeof buf, &bl);
        char l[96]; snprintf(l, sizeof l, "late %s: connection closed (no pong, read <= 0)", late);
        ck(l, r <= 0);
        /* the serve child must LEAVE its loop on its own; bounded wait so a
         * loop that keeps serving (the pre-2026-08-28 behaviour) fails here
         * instead of hanging the harness */
        int st = 0, exited = 0;
        for (int w = 0; w < 30 && !exited; w++){ if (waitpid(sp, &st, WNOHANG) == sp) exited = 1; else usleep(100000); }
        if (!exited){ kill(sp, 9); waitpid(sp, 0, 0); }
        snprintf(l, sizeof l, "late %s: serve child left its loop on its own (exit 0)", late);
        ck(l, exited && WIFEXITED(st) && WEXITSTATUS(st) == 0);
        close(fdE);
    }
    /* and the same two messages BEFORE verack are, of course, fine: section
     * 3 already proved sendaddrv2 there; wtxidrelay is what section 1 saw */

    printf("\n== 8. non-IPv4 entries: addrv2 carries them, legacy addr does not (Core IsAddrCompatible) ==\n");
    /* Core's msg_addrv2 for the 3-record book plus onion pg6mm...:8335 and i2p c4gfn...:0 */
    static const unsigned char CORE_V2_5[] = { 0x05,0x00,0xf1,0x53,0x65,0x09,0x01,0x04,0x05,0x06,0x07,0x08,0x20,0x8d,0x01,0xf1,0x53,0x65,0x01,0x01,0x04,0x09,0x0a,0x0b,0x0c,0x20,0x8d,0x02,0xf1,0x53,0x65,0xfd,0x09,0x04,0x01,0x04,0xc8,0x01,0x02,0x03,0x20,0x8e,0x03,0xf1,0x53,0x65,0x09,0x04,0x20,0x79,0xbc,0xc6,0x25,0x18,0x4b,0x05,0x19,0x49,0x75,0xc2,0x8b,0x66,0xb6,0x6b,0x04,0x69,0xf7,0xf6,0x55,0x6f,0xb1,0xac,0x31,0x89,0xa7,0x9b,0x40,0xdd,0xa3,0x2f,0x1f,0x20,0x8f,0x04,0xf1,0x53,0x65,0x09,0x05,0x20,0x17,0x0c,0x56,0xce,0x72,0xa5,0xa0,0xe6,0x23,0x06,0xa3,0xc7,0x08,0x43,0x18,0xee,0x3a,0x46,0x35,0x5d,0x17,0xf6,0x78,0x96,0xa0,0x9c,0x51,0xef,0xbe,0x23,0xfd,0x71,0x00,0x00 };
    book3();
    book_add("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8335", 9, 1700000003u);
    book_add("c4gfnttsuwqomiygupdqqqyy5y5emnk5c73hrfvatri67prd7vyq.b32.i2p", 9, 1700000004u);
    { pid_t sp = spawn_server(); int fdF = raw_client(70016, 0, &off, &wt);
      r = getaddr_reply(fdF, cmd, buf, sizeof buf, &bl);
      ck("legacy peer: addr with ONLY the 3 IPv4 records (== Core msg_addr)", r > 0 && !strcmp(cmd, "addr") && bl == sizeof CORE_V1_3 && !memcmp(buf, CORE_V1_3, bl));
      close(fdF); kill(sp, 9); waitpid(sp, 0, 0); }
    { pid_t sp = spawn_server(); int fdG = raw_client(70016, 1, &off, &wt);
      r = getaddr_reply(fdG, cmd, buf, sizeof buf, &bl);
      cki("addrv2 peer: all 5 entries, length == Core's", (long)bl, (long)sizeof CORE_V2_5);
      ck("addrv2 bytes == Core msg_addrv2 (ipv4 x3, onion, i2p)", r > 0 && !strcmp(cmd, "addrv2") && bl == sizeof CORE_V2_5 && !memcmp(buf, CORE_V2_5, bl));
      close(fdG); kill(sp, 9); waitpid(sp, 0, 0); }

    close(g_ls);
    printf(failures ? "\nFAILURES %d\n" : "\nALL TESTS PASSED (0 failures)\n", failures);
    return failures ? 1 : 0;
}
