/* tests/test_p2p_msgsize.c -- the framer's message-size bound (audit finding 6).
 *
 * Core rejects an oversized announcement in the header, and the comment beside
 * that check cites the 2024-07-03 disclosure where its absence let a peer make
 * a node allocate 32 MiB per connection. Here the cost is unbounded WORK: the
 * drain loop reads the excess 64 bytes at a time, so a peer announcing
 * 0xFFFFFFFF keeps a forked serve child busy for ~4 GB of socket reads.
 *
 * The test therefore checks two separate things, because the return code alone
 * would pass even if the drain still ran:
 *   - the call REJECTS with the distinct -3, and
 *   - it returns without consuming the bytes that follow the header, which is
 *     what proves the drain was skipped rather than merely reported.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>

extern int  p2p_read(int fd, char cmd_out[12], void* payload, unsigned cap, unsigned* plen_out);
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
extern unsigned int net_magic;

#define P2P_MAX_MSG 4000000u

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

/* hand-build a 24-byte v1 header announcing `len` bytes of payload */
static void put_header(unsigned char h[24], const char* cmd, unsigned len){
    memcpy(h, &net_magic, 4);
    memset(h + 4, 0, 12);
    memcpy(h + 4, cmd, strlen(cmd) < 12 ? strlen(cmd) : 12);
    h[16] = (unsigned char)len;        h[17] = (unsigned char)(len >> 8);
    h[18] = (unsigned char)(len >> 16); h[19] = (unsigned char)(len >> 24);
    memset(h + 20, 0, 4);              /* checksum: unchecked on this path */
}

static int try_len(unsigned announced, int* consumed_trailer){
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return -99;
    unsigned char h[24];
    put_header(h, "inv", announced);
    if (write(sv[1], h, 24) != 24) { close(sv[0]); close(sv[1]); return -99; }
    /* a recognisable trailer: if the framer drained, this is gone */
    static const unsigned char TRAILER[8] = {0xA5,0x5A,0xA5,0x5A,0xA5,0x5A,0xA5,0x5A};
    if (write(sv[1], TRAILER, 8) != 8) { close(sv[0]); close(sv[1]); return -99; }
    shutdown(sv[1], SHUT_WR);

    char cmd[12]; unsigned char buf[256]; unsigned plen = 0;
    int r = p2p_read(sv[0], cmd, buf, sizeof buf, &plen);

    unsigned char left[8];
    ssize_t n = recv(sv[0], left, sizeof left, MSG_DONTWAIT);
    *consumed_trailer = !(n == 8 && !memcmp(left, TRAILER, 8));
    close(sv[0]); close(sv[1]);
    return r;
}

int main(void){
    printf("== an oversized announcement is refused ==\n");
    { int drained = 0;
      int r = try_len(0xFFFFFFFFu, &drained);
      ck("0xFFFFFFFF returns -3, not -1/-2", r == -3);
      ck("  and the following bytes were NOT drained", !drained); }

    { int drained = 0;
      int r = try_len(P2P_MAX_MSG + 1, &drained);
      ck("one byte over the limit is refused", r == -3);
      ck("  and nothing was drained", !drained); }

    printf("== the boundary is not off by one ==\n");
    /* Exactly at the limit must still be ACCEPTED. A bound that also rejects
     * the largest legal message would silently break big blocks, and no
     * oversize test would notice. */
    { int drained = 0;
      int r = try_len(P2P_MAX_MSG, &drained);
      ck("exactly 4,000,000 is not rejected as oversize", r != -3);
      /* the peer never sent that much, so it reads as truncated/EOF -- the
       * point is only that it got past the size gate */
      ck("  (it fails later as a short read, which is correct)", r == -2 || r == 0); }

    printf("== ordinary messages are unaffected ==\n");
    { int sv[2];
      socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
      unsigned char pl[8] = {1,2,3,4,5,6,7,8};
      long w = p2p_write(sv[0], "ping", 4, pl, 8);
      char cmd[12]; unsigned char buf[64]; unsigned plen;
      int r = p2p_read(sv[1], cmd, buf, sizeof buf, &plen);
      ck("a normal frame still round-trips", w == 32 && r == 1
         && !strncmp(cmd, "ping", 4) && plen == 8 && !memcmp(buf, pl, 8));
      close(sv[0]); close(sv[1]); }

    printf("== the refusal is immediate, not a slow drain ==\n");
    /* Without the bound this call would read ~4 GB in 64-byte chunks. With it
     * the call must return essentially instantly even though the peer stays
     * open. Timing is a blunt instrument, but a two-order-of-magnitude gap
     * is unambiguous. */
    { int sv[2];
      socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
      unsigned char h[24];
      put_header(h, "inv", 0xFFFFFFFFu);
      ssize_t unused = write(sv[1], h, 24); (void)unused;
      /* deliberately leave sv[1] OPEN so a drain loop would block, not EOF */
      struct timeval tv = {2, 0};
      setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
      struct timespec a, b;
      clock_gettime(CLOCK_MONOTONIC, &a);
      char cmd[12]; unsigned char buf[64]; unsigned plen;
      int r = p2p_read(sv[0], cmd, buf, sizeof buf, &plen);
      clock_gettime(CLOCK_MONOTONIC, &b);
      double ms = (b.tv_sec - a.tv_sec) * 1000.0 + (b.tv_nsec - a.tv_nsec) / 1e6;
      char l[120];
      snprintf(l, sizeof l, "returned in %.1f ms without waiting on the peer", ms);
      ck(l, r == -3 && ms < 500.0);
      close(sv[0]); close(sv[1]); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
