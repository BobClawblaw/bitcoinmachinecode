/* tests/test_private_broadcast.c -- daemon/private_broadcast.c: the queue and
 * the wire exchange, driven over loopback against a fake peer that behaves
 * like a Core node on the receiving end of a PRIVATE_BROADCAST connection.
 *
 * What the fake peer asserts about US (the whole point of the feature):
 *   - our version carries services 0, time 0, height 0, relay 0, zero
 *     addresses and the user agent "/pynode:0.0.1/" -- nothing identifying;
 *   - we send exactly one inv(MSG_TX, txid) after verack;
 *   - we answer its getdata with the tx bytes, then a ping;
 *   - we NEVER reply to its ping, sendaddrv2, wtxidrelay or sendheaders
 *     (Core's outbound whitelist: version, verack, inv, tx, ping only);
 *   - a getdata for a hash we did not announce ends the conversation;
 *   - the pong is what we count as the receipt. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../daemon/private_broadcast.h"
typedef unsigned char u8;
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
extern int  p2p_read(int fd, char cmd[12], void* payload, unsigned cap, unsigned* plen);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* scratch, unsigned long scratchcap);
extern void tx_wtxid(u8 out[32], const u8* tx, unsigned long txlen);

static int failures = 0;
static void ck(const char* l, long got, long exp){ if (got == exp) printf("PASS %s (got %ld)\n", l, got); else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; } }
static void put32(u8* p, unsigned v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void put64(u8* p, unsigned long long v){ for (int i = 0; i < 8; i++){ p[i] = v & 0xff; v >>= 8; } }

/* a well-formed non-witness tx: 1 input, 1 output (its txid == wtxid) */
static long mk_tx(u8* out, unsigned tag){
    u8* q = out;
    put32(q, 2); q += 4; *q++ = 1;
    for (int i = 0; i < 32; i++) *q++ = (u8)(tag + i);
    put32(q, tag & 3); q += 4;
    *q++ = 0; put32(q, 0xfffffffe); q += 4;
    *q++ = 1; put64(q, 12345 + tag); q += 8; *q++ = 1; *q++ = 0x51;
    put32(q, 0); q += 4;
    return q - out;
}

/* ---------------------------------------------------------------- queue */
static void test_queue(void){
    printf("---- queue ----\n");
    pb_queue_init();
    static u8 t1[200], t2[200], t3[200]; long l1 = mk_tx(t1, 1), l2 = mk_tx(t2, 2), l3 = mk_tx(t3, 3);
    u8 id1[32], id2[32]; static u8 scratch[8192];
    tx_txid(id1, t1, l1, scratch, sizeof scratch); tx_txid(id2, t2, l2, scratch, sizeof scratch);
    ck("add #1", pb_queue_add(t1, l1, 1000), 1);
    ck("add #1 again is a no-op (already present)", pb_queue_add(t1, l1, 1001), 0);
    ck("add #2", pb_queue_add(t2, l2, 1002), 1);
    ck("count", pb_queue_count(), 2);
    ck("garbage is refused", pb_queue_add((const u8*)"xx", 2, 1003), -2);
    /* pick: fewest sends first; the peer entry is recorded */
    int slot = -1;
    int a = pb_queue_pick("peerA:8333", 1010, &slot);
    ck("first pick takes a tx", a >= 0, 1);
    const pb_tx_t* ta = pb_queue_at(a);
    ck("...and records the peer", ta->npeers, 1);
    ck("...with sent time", (long)ta->peers[0].sent, 1010);
    int b = pb_queue_pick("peerB:8333", 1011, &slot);
    ck("second pick takes the OTHER tx (fewest sends)", b != a, 1);
    int c = pb_queue_pick("peerC:8333", 1012, &slot);
    ck("third pick returns to a tx with one send", (c == a || c == b), 1);
    pb_queue_mark_received(c, slot, 1020);
    ck("receipt recorded", (long)pb_queue_at(c)->peers[slot].received, 1020);
    /* unpick drops a phantom attempt */
    int d = pb_queue_pick("peerD:8333", 1013, &slot);
    int before = pb_queue_at(d)->npeers;
    pb_queue_unpick(d, slot);
    ck("unpick removes the peer entry", pb_queue_at(d)->npeers, before - 1);
    /* stale: never sent + older than INITIAL; sent + older than STALE */
    ck("add #3", pb_queue_add(t3, l3, 2000), 1);
    int st[PB_MAX_TX]; int ns = pb_queue_stale(2000 + PB_INITIAL_STALE_S - 1, st, PB_MAX_TX);
    /* #1/#2 were last sent at ~1012: stale by now; #3 is not yet */
    int has3 = 0; for (int i = 0; i < ns; i++){ const pb_tx_t* t = pb_queue_at(st[i]); if (t && t->npeers == 0) has3 = 1; }
    ck("a never-sent tx is not stale before INITIAL_STALE", has3, 0);
    ns = pb_queue_stale(2000 + PB_INITIAL_STALE_S, st, PB_MAX_TX);
    has3 = 0; for (int i = 0; i < ns; i++){ const pb_tx_t* t = pb_queue_at(st[i]); if (t && t->npeers == 0) has3 = 1; }
    ck("...and is stale after it", has3, 1);
    /* snapshot round-trip */
    static char snap[65536]; long n = pb_queue_snapshot(snap, sizeof snap);
    ck("snapshot has one line per tx", (long)(n > 0) + (long)0, 1);
    { int lines = 0; for (long i = 0; i < n; i++) lines += snap[i] == '\n'; ck("three lines", lines, 3); }
    ck("snapshot carries the tx hex", strstr(snap, "0200000001") != NULL, 1);
    /* remove returns the acknowledgement count */
    long acks = pb_queue_remove(pb_queue_at(c)->txid);
    ck("remove returns acks (1)", acks, 1);
    ck("remove of an unknown txid is -1", pb_queue_remove(id1) == -1 || pb_queue_remove(id2) == -1, 1);
    /* abort by txid or wtxid */
    pb_queue_init();
    pb_queue_add(t1, l1, 1); pb_queue_add(t2, l2, 2);
    u8 rt[4][32], rw[4][32];
    u8 w1[32]; tx_wtxid(w1, t1, l1);
    ck("abort by wtxid removes exactly one", pb_queue_abort(w1, rt, rw, 4), 1);
    ck("...the right one", memcmp(rt[0], id1, 32), 0);
    ck("abort by an unknown id removes none", pb_queue_abort(w1, rt, rw, 4), 0);
    ck("queue left with #2", pb_queue_count(), 1);
    /* capacity */
    pb_queue_init();
    int added = 0; static u8 big[200];
    for (unsigned k = 0; k < PB_MAX_TX + 5; k++){ long bl = mk_tx(big, 100 + k); if (pb_queue_add(big, bl, k) == 1) added++; }
    ck("queue is capped", added, PB_MAX_TX);
    pb_queue_init();
}

/* ------------------------------------------------------------ fake peer */
typedef struct {
    int send_bad_getdata;      /* getdata for a different hash */
    int never_getdata;         /* just sit there */
    int no_pong;               /* take the tx, never pong */
    int close_after_version;   /* hang up before verack */
} peer_mode_t;
typedef struct {
    int version_ok;            /* our version had services 0, time 0, height 0, relay 0, pynode UA */
    int got_inv, got_tx, got_ping, tx_len_match;
    int forbidden_replies;     /* we answered its ping/sendaddrv2/etc: must stay 0 */
    int tx_bytes_ok;
} peer_report_t;

static int listen_on(unsigned short* port){
    int ls = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(0x7f000001); sa.sin_port = 0;
    if (bind(ls, (struct sockaddr*)&sa, sizeof sa) != 0 || listen(ls, 4) != 0) return -1;
    socklen_t sl = sizeof sa; getsockname(ls, (struct sockaddr*)&sa, &sl); *port = ntohs(sa.sin_port);
    return ls;
}
/* runs in a forked child; writes its report to `rep_fd` */
static void fake_peer(int ls, const u8* tx, long len, const u8 txid[32], peer_mode_t m, int rep_fd){
    peer_report_t rep; memset(&rep, 0, sizeof rep);
    int fd = accept(ls, NULL, NULL); if (fd < 0) _exit(3);
    struct timeval tv = { 8, 0 }; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    static u8 rb[1<<20]; char cmd[12]; unsigned plen = 0;
    /* 1. their version */
    if (p2p_read(fd, cmd, rb, sizeof rb, &plen) <= 0 || strncmp(cmd, "version", 7)) goto done;
    { unsigned ver = rb[0]|rb[1]<<8|rb[2]<<16|((unsigned)rb[3]<<24);
      unsigned long long svc = 0, tm = 0; memcpy(&svc, rb+4, 8); memcpy(&tm, rb+12, 8);
      int zero_addrs = 1; for (int i = 20; i < 20+26+26; i++) if (rb[i]) zero_addrs = 0;
      unsigned ual = rb[80]; const char* ua = (const char*)rb + 81;
      unsigned height; memcpy(&height, rb + 81 + ual, 4); u8 relay = rb[81 + ual + 4];
      rep.version_ok = ver == 70016 && svc == 0 && tm == 0 && zero_addrs && ual == strlen(PB_USER_AGENT) &&
                       !memcmp(ua, PB_USER_AGENT, ual) && height == 0 && relay == 0 && plen == 81 + ual + 5; }
    if (m.close_after_version){ close(fd); goto done; }
    /* 2. our version + things a Core peer says pre-verack (we must not echo any) */
    { u8 v[120]; memset(v, 0, sizeof v); put32(v, 70016); put64(v+4, 1); put64(v+12, 1700000000ULL); v[80] = 0; put32(v+81, 800000); v[85] = 1;
      p2p_write(fd, "version", 7, v, 86); }
    p2p_write(fd, "wtxidrelay", 10, "", 0);
    p2p_write(fd, "sendaddrv2", 10, "", 0);
    p2p_write(fd, "verack", 6, "", 0);
    p2p_write(fd, "sendheaders", 11, "", 0);
    { u8 pn[8] = {1,2,3,4,5,6,7,8}; p2p_write(fd, "ping", 4, pn, 8); }   /* a real Core pings right after verack */
    /* 3. read until their inv, counting forbidden replies */
    int have_verack = 0, deadline = 40;
    while (deadline-- > 0){
        int r = p2p_read(fd, cmd, rb, sizeof rb, &plen); if (r <= 0) goto done; cmd[11] = 0;
        if (!strncmp(cmd, "verack", 12)){ have_verack = 1; continue; }
        if (!strncmp(cmd, "inv", 12)){
            rep.got_inv = plen == 37 && rb[0] == 1 && rb[1] == 1 && !rb[2] && !rb[3] && !rb[4] && !memcmp(rb+5, txid, 32);
            break;
        }
        rep.forbidden_replies++;          /* pong / sendaddrv2 / wtxidrelay / sendheaders echoes */
    }
    if (!have_verack || !rep.got_inv) goto done;
    if (m.never_getdata){ sleep(4); goto done; }
    /* 4. getdata (MSG_WITNESS_TX like a modern Core) */
    { u8 gd[37]; gd[0] = 1; put32(gd+1, m.send_bad_getdata ? 1u : 0x40000001u);
      memcpy(gd+5, txid, 32); if (m.send_bad_getdata) gd[5] ^= 0xff;
      p2p_write(fd, "getdata", 7, gd, 37); }
    /* 5. their tx, then their ping */
    while (deadline-- > 0){
        int r = p2p_read(fd, cmd, rb, sizeof rb, &plen); if (r <= 0) goto done; cmd[11] = 0;
        if (!strncmp(cmd, "tx", 12)){ rep.got_tx = 1; rep.tx_len_match = (long)plen == len; rep.tx_bytes_ok = rep.tx_len_match && !memcmp(rb, tx, len); continue; }
        if (!strncmp(cmd, "ping", 12) && plen == 8){ rep.got_ping = 1; if (!m.no_pong) p2p_write(fd, "pong", 4, rb, 8); break; }
        rep.forbidden_replies++;
    }
    /* linger so their pong read completes */
    { struct timeval t2 = { 2, 0 }; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &t2, sizeof t2); p2p_read(fd, cmd, rb, sizeof rb, &plen); }
    close(fd);
done:
    (void)!write(rep_fd, &rep, sizeof rep);
    _exit(0);
}

static int run_case(const char* name, peer_mode_t m, int expect_rc, int deadline_s, peer_report_t* rep_out, char* why, long whycap){
    static u8 tx[200]; long len = mk_tx(tx, 77); u8 txid[32]; static u8 scratch[8192]; tx_txid(txid, tx, len, scratch, sizeof scratch);
    unsigned short port = 0; int ls = listen_on(&port); if (ls < 0){ printf("FAIL listen\n"); failures++; return -1; }
    int rp[2]; if (pipe(rp) != 0) return -1;
    pid_t pid = fork();
    if (pid == 0){ close(rp[0]); fake_peer(ls, tx, len, txid, m, rp[1]); }
    close(rp[1]); close(ls);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(0x7f000001); sa.sin_port = htons(port);
    if (connect(fd, (struct sockaddr*)&sa, sizeof sa) != 0){ printf("FAIL connect\n"); failures++; return -1; }
    int rc = pb_exchange(fd, tx, len, txid, deadline_s, why, whycap);
    close(fd);
    peer_report_t rep; memset(&rep, 0, sizeof rep);
    (void)!read(rp[0], &rep, sizeof rep); close(rp[0]);
    int st; waitpid(pid, &st, 0);
    if (rep_out) *rep_out = rep;
    printf("---- %s: rc=%d why=\"%s\"\n", name, rc, why);
    ck(name, rc, expect_rc);
    return rc;
}

int main(void){
    signal(SIGPIPE, SIG_IGN);
    test_queue();
    printf("---- version payload ----\n");
    { u8 v[160]; long n = pb_build_version(v, sizeof v);
      ck("version payload length (4+8+8+26+26+8+1+14+4+1)", n, 100);
      unsigned long long svc; memcpy(&svc, v+4, 8); ck("services 0", (long)svc, 0);
      unsigned long long tm; memcpy(&tm, v+12, 8); ck("time 0", (long)tm, 0);
      ck("user agent is /pynode:0.0.1/", v[80] == 14 && !memcmp(v+81, "/pynode:0.0.1/", 14), 1);
      unsigned h; memcpy(&h, v+95, 4); ck("height 0", h, 0);
      ck("relay 0", v[99], 0);
      u8 v2[160]; pb_build_version(v2, sizeof v2); ck("nonce differs between builds", memcmp(v+72, v2+72, 8) != 0, 1); }
    printf("---- wire ----\n");
    char why[128]; peer_report_t rep;
    peer_mode_t ok = {0};
    run_case("happy path: inv, getdata, tx, ping, pong -> confirmed (2)", ok, 2, 20, &rep, why, sizeof why);
    ck("  peer saw an anonymous version", rep.version_ok, 1);
    ck("  peer got our inv(MSG_TX, txid)", rep.got_inv, 1);
    ck("  peer got the tx bytes verbatim", rep.tx_bytes_ok, 1);
    ck("  peer got our ping", rep.got_ping, 1);
    ck("  we never answered its ping/sendaddrv2/wtxidrelay/sendheaders", rep.forbidden_replies, 0);
    peer_mode_t bad = {0}; bad.send_bad_getdata = 1;
    run_case("getdata for a hash we never announced -> fail (0)", bad, 0, 20, &rep, why, sizeof why);
    ck("  reason names it", strstr(why, "never announced") != NULL, 1);
    peer_mode_t nopong = {0}; nopong.no_pong = 1;
    run_case("tx delivered but no pong -> delivered (1)", nopong, 1, 4, &rep, why, sizeof why);
    ck("  peer got the tx", rep.got_tx, 1);
    peer_mode_t silent = {0}; silent.never_getdata = 1;
    run_case("peer never asks for the tx -> fail (0) at the deadline", silent, 0, 3, &rep, why, sizeof why);
    ck("  reason: no getdata", strstr(why, "no getdata") != NULL, 1);
    peer_mode_t hang = {0}; hang.close_after_version = 1;
    run_case("peer hangs up before verack -> fail (0)", hang, 0, 10, &rep, why, sizeof why);
    printf("%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL PASS", failures);
    return failures ? 1 : 0;
}
