/* tests/test_addr_self.c -- self-address advertisement (daemon/addr_self.c).
 *
 * Pinned: one peer's view is NOT trusted; two agreeing views are; the
 * announced `addr` message carries the exact time/services/mapped-IP/port
 * layout a Core peer parses; unroutable views never count; and the 24h
 * cadence means a second immediate announce is a no-op.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <time.h>

typedef unsigned char u8;

extern void addrself_init(unsigned short listen_port, int listen_enabled);
extern void addrself_note_peer_view(const u8* payload, long len);
extern long addrself_build(u8 out[64], long now);
extern long addrself_maybe_announce(const int* fds, int nfds);

static int fails = 0;
static void ck(const char* l, int cond){
    if (cond) printf("  ok  %s\n", l);
    else { printf("  FAIL %s\n", l); fails++; }
}

/* a minimal version payload whose addr_recv.ip is the given IPv4 */
static void mk_version(u8* v, const u8 ip[4]){
    memset(v, 0, 102);
    v[0]=0x80; v[1]=0x11; v[2]=0x01;                 /* protocol */
    v[4]=9;                                          /* services */
    v[38]=0xff; v[39]=0xff; memcpy(v+40, ip, 4);     /* addr_recv ip16: ::ffff:a.b.c.d at offset 28 */
    v[44]=0x20; v[45]=0x8d;                          /* addr_recv port (ignored by the module) */
}

static int read_n(int fd, u8* buf, int n){
    int got = 0;
    while (got < n){ int r = (int)read(fd, buf+got, n-got); if (r <= 0) break; got += r; }
    return got;
}

int main(void){
    u8 v[102];
    u8 pub[4]  = { 203, 0, 113, 77 };     /* TEST-NET-3 (RFC 5737) */
    u8 pub2[4] = { 198, 51, 100, 9 };
    u8 rfc1918[4] = { 192, 168, 1, 5 };

    addrself_init(8332, 1);

    printf("== confidence: two agreeing routable views ==\n");
    mk_version(v, rfc1918); addrself_note_peer_view(v, 102);
    mk_version(v, pub2);    addrself_note_peer_view(v, 102);
    mk_version(v, pub);     addrself_note_peer_view(v, 102);
    { int none[1] = { -1 };
      ck("one vote (plus noise) is not confidence", addrself_maybe_announce(none, 1) == 0); }
    mk_version(v, pub);     addrself_note_peer_view(v, 102);   /* second agreeing peer */

    printf("\n== the announced message, byte for byte ==\n");
    int sp[2];
    ck("socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    long before = (long)time(NULL);
    { int fds[2] = { sp[0], -1 };
      ck("announce to the one live leg", addrself_maybe_announce(fds, 2) == 1); }
    u8 hdr[24], pl[64];
    ck("p2p header read", read_n(sp[1], hdr, 24) == 24);
    ck("command addr", memcmp(hdr+4, "addr\0\0\0\0\0\0\0\0", 12) == 0);
    unsigned plen = (unsigned)hdr[16] | ((unsigned)hdr[17]<<8) | ((unsigned)hdr[18]<<16) | ((unsigned)hdr[19]<<24);
    ck("payload length 31", plen == 31 && read_n(sp[1], pl, 31) == 31);
    ck("count 1", pl[0] == 1);
    { unsigned t = (unsigned)pl[1] | ((unsigned)pl[2]<<8) | ((unsigned)pl[3]<<16) | ((unsigned)pl[4]<<24);
      ck("timestamp is now-ish", (long)t >= before && (long)t <= before + 60); }
    ck("services NETWORK|WITNESS", pl[5] == 9 && pl[6] == 0 && pl[12] == 0);
    ck("IPv4-mapped prefix", pl[13+10] == 0xff && pl[13+11] == 0xff);
    ck("the CONFIRMED ip, not the noise ip", memcmp(pl+25, pub, 4) == 0);
    ck("configured port 8332, big-endian", pl[29] == 0x20 && pl[30] == 0x8c);

    printf("\n== cadence: an immediate re-announce is a no-op ==\n");
    { int fds[1] = { sp[0] };
      ck("within 24h -> nothing sent", addrself_maybe_announce(fds, 1) == 0); }
    { int fl = fcntl(sp[1], F_GETFL, 0); fcntl(sp[1], F_SETFL, fl | O_NONBLOCK);
      u8 junk[8];
      ck("no wire bytes", read(sp[1], junk, sizeof junk) <= 0); }

    close(sp[0]); close(sp[1]);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
