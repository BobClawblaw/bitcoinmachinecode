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
extern long addrself_build_v2(u8 out[64], long now);
extern int  addrself_set_onion(const char* onion_str, unsigned short port);
extern long addrself_build_v2_onion(u8 out[64], long now);
extern int  addrself_set_external(const unsigned char ip4[4]);
extern long addrself_maybe_announce(const int* fds, const u8* wants_v2, int nfds);

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
      ck("one vote (plus noise) is not confidence", addrself_maybe_announce(none, NULL, 1) == 0); }
    mk_version(v, pub);     addrself_note_peer_view(v, 102);   /* second agreeing peer */

    printf("\n== the announced message, byte for byte ==\n");
    int sp[2], sq[2];
    ck("socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    ck("socketpair (addrv2 leg)", socketpair(AF_UNIX, SOCK_STREAM, 0, sq) == 0);
    long before = (long)time(NULL);
    /* three legs: one legacy, one dead, one that sent sendaddrv2 */
    { int fds[3] = { sp[0], -1, sq[0] }; u8 wants[3] = { 0, 0, 1 };
      ck("announce to the two live legs", addrself_maybe_announce(fds, wants, 3) == 2); }
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

    printf("\n== the addrv2 leg gets the BIP155 form (Core's MaybeSendAddr never sends v1 to it) ==\n");
    ck("p2p header read (v2 leg)", read_n(sq[1], hdr, 24) == 24);
    ck("command addrv2", memcmp(hdr+4, "addrv2\0\0\0\0\0\0", 12) == 0);
    plen = (unsigned)hdr[16] | ((unsigned)hdr[17]<<8) | ((unsigned)hdr[18]<<16) | ((unsigned)hdr[19]<<24);
    ck("payload length 14 (count, time, services CompactSize, net, len, ip4, port)", plen == 14 && read_n(sq[1], pl, 14) == 14);
    ck("count 1", pl[0] == 1);
    { unsigned t = (unsigned)pl[1] | ((unsigned)pl[2]<<8) | ((unsigned)pl[3]<<16) | ((unsigned)pl[4]<<24);
      ck("timestamp is now-ish", (long)t >= before && (long)t <= before + 60); }
    ck("services 9 as a one-byte CompactSize", pl[5] == 9);
    ck("network id 1 (IPv4), address length 4", pl[6] == 1 && pl[7] == 4);
    ck("the CONFIRMED ip", memcmp(pl+8, pub, 4) == 0);
    ck("configured port 8332, big-endian", pl[12] == 0x20 && pl[13] == 0x8c);
    /* and the builder's bytes match Core's CAddress.serialize_v2 shape for
     * (t, svc 9, 203.0.113.77, 8332) apart from the live timestamp */
    { u8 b[64]; long n = addrself_build_v2(b, 0x65535300L);
      static const u8 CORE[] = { 0x01, 0x00,0x53,0x53,0x65, 0x09, 0x01, 0x04, 203,0,113,77, 0x20,0x8c };
      ck("addrself_build_v2 == Core serialize_v2 bytes", n == (long)sizeof CORE && memcmp(b, CORE, n) == 0); }

    printf("\n== -externalip: the operator names the address, no peer votes needed ==\n");
    { /* the override on top of the learned address: a DIFFERENT address, and
       * it must reach both announcement forms */
      u8 ext[4] = { 198, 51, 100, 200 };
      ck("addrself_set_external accepts an IPv4", addrself_set_external(ext) == 1);
      u8 b[64]; long n = addrself_build(b, 0x65535300L);
      ck("the announcement carries the configured address", n == 31 && !memcmp(b + 25, ext, 4));
      u8 b2[64]; long n2 = addrself_build_v2(b2, 0x65535300L);
      ck("and so does the addrv2 form", n2 == 14 && !memcmp(b2 + 8, ext, 4));
      addrself_set_external(pub); }   /* restore, so the cadence check below is unchanged */

    printf("\n== cadence: an immediate re-announce is a no-op ==\n");
    { int fds[1] = { sp[0] };
      ck("within 24h -> nothing sent", addrself_maybe_announce(fds, NULL, 1) == 0); }
    { int fl = fcntl(sp[1], F_GETFL, 0); fcntl(sp[1], F_SETFL, fl | O_NONBLOCK);
      u8 junk[8];
      ck("no wire bytes", read(sp[1], junk, sizeof junk) <= 0); }

    printf("== onion self-address (inbound Tor) ==\n");
    /* a real v3 service id: Core's own p2p_addrv2_relay.py example */
    { const char* ON = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
      ck("a valid v3 onion is accepted", addrself_set_onion(ON, 8333) == 1);
      ck("a malformed onion is REFUSED (the checksum is validated, not assumed)",
         addrself_set_onion("notanonion.onion", 8333) == 0);
      ck("  and a truncated one too", addrself_set_onion("aaaa.onion", 8333) == 0);

      u8 b[64]; long n = addrself_build_v2_onion(b, 0x65535300L);
      ck("the onion record is built", n > 0);
      /* count(1) time(4) services(1) netid(1) len(1) addr(32) port(2) = 42 */
      ck("  and is exactly the BIP155 onion shape", n == 42);
      ck("  count is 1",                b[0] == 1);
      ck("  network id is 4 (TORV3)",   b[6] == 4);
      ck("  address length is 32",      b[7] == 32);
      ck("  port is big-endian 8333",   b[40] == 0x20 && b[41] == 0x8d);
      /* the 32 bytes must be the DECODED pubkey, not the base32 text */
      int looks_like_text = 1;
      for (int i = 0; i < 32; i++) if (b[8+i] < 'a' || b[8+i] > 'z') { looks_like_text = 0; break; }
      ck("  the address is the decoded pubkey, not the base32 string", !looks_like_text); }

    close(sp[0]); close(sp[1]); close(sq[0]); close(sq[1]);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
