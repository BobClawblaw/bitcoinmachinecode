/* daemon/serve_addr.c -- the getaddr reply, from the version-2 book.
 *
 * Replaces the assembly loop in bitcoin_serve.asm's .maybe_getaddr (which
 * read the legacy IPv4-only book). Reads peers2.dat read-only per request --
 * the serve child is forked per connection, so nothing is inherited stale
 * and nothing here needs a lock (the download worker is the only writer).
 *
 * Core's GetAddr returns min(1000, 23% of the table) addresses in random
 * order; we return up to 1000 walked from a random start when the book is
 * larger than that, and from the start otherwise (byte-exact replies for the
 * tests). A peer that negotiated BIP155 gets addrv2 with every network; a
 * legacy peer gets `addr` with only the addresses that format can carry
 * (IPv4/IPv6), exactly Core's IsAddrCompatible filter. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "netaddr.h"
#include "addrbook.h"

extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
#define SA_MAX 1000

static long put_csize(unsigned char* o, unsigned long long v){
    if (v < 0xfd){ o[0] = (unsigned char)v; return 1; }
    o[0] = 0xfd; o[1] = (unsigned char)v; o[2] = (unsigned char)(v >> 8); return 3;
}
/* returns the number of addresses sent (0 = nothing sent) */
long serve_getaddr(int fd, int wants_v2){
    ab2_t* b = ab2_open(".", 0);
    if (!b) return 0;
    long n = ab2_count(b);
    if (n <= 0){ ab2_close(b); return 0; }
    static unsigned char pl[3 + SA_MAX * 64];
    long start = n > SA_MAX ? (long)(((unsigned long)time(NULL) ^ (unsigned long)getpid()) % (unsigned long)n) : 0;
    long o = 3, sent = 0;                       /* reserve 3 bytes for the count */
    for (long k = 0; k < n && sent < SA_MAX; k++){
        ab2_rec_t r; if (!ab2_get(b, (start + k) % n, &r)) continue;
        long w = wants_v2 ? bmc_addr_encode_v2(pl + o, (long)sizeof pl - o, &r.a, r.services, r.last_seen)
                          : bmc_addr_encode_v1(pl + o, (long)sizeof pl - o, &r.a, r.services, r.last_seen);
        if (w <= 0) continue;                    /* not representable in this format */
        o += w; sent++;
    }
    ab2_close(b);
    if (!sent) return 0;
    unsigned char cnt[3]; long cl = put_csize(cnt, (unsigned long long)sent);
    unsigned char* body = pl + 3 - cl; memcpy(body, cnt, (size_t)cl);
    p2p_write(fd, wants_v2 ? "addrv2" : "addr", wants_v2 ? 6 : 4, body, (unsigned)(o - (3 - cl)));
    return sent;
}
