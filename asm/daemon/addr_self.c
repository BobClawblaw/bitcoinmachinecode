/* daemon/addr_self.c -- advertise our own address to the network.
 *
 * WHY: this node has never told anyone where it lives. Peers only learn a
 * node's address through addr gossip, and the one address we might have
 * gossiped -- the version message's addr_from -- both hardcoded the wrong
 * port and is ignored by modern Core anyway (it fills self-advertisement
 * from AdvertiseLocal, not addr_from). Result: zero inbound peers, ever.
 * This module is Core's AdvertiseLocal in miniature.
 *
 * HOW WE LEARN OUR OWN ADDRESS: each peer tells us. The version message a
 * peer sends carries addr_recv -- the address it is talking TO, i.e. us as
 * the world sees us. We already capture every peer's version payload
 * (g_peer_version_payload); this module tallies the IPv4s peers report and
 * trusts one once TWO DISTINCT peers agree (one peer could be lying or
 * behind its own NAT weirdness; two independent agreeing views is Core's
 * own "score >= 2" shape for locals learned this way).
 *
 * WHAT WE ANNOUNCE: one legacy `addr` entry -- time(4) services(8) ip(16,
 * IPv4-mapped) port(2 BE) -- with OUR services (NETWORK|WITNESS, the same
 * word the version message advertises) and the CONFIGURED listen port, not
 * a constant: this box's Core owns 8333, we listen on 8332, and
 * advertising 8333 sends every prospective peer to the wrong daemon.
 * Announced to every live leg when first learned and re-announced every
 * 24h (Core's own cadence); peers gossip it onward. Gated on listen=1.
 */
#include <stdio.h>
#include "log_ts.h"
#include <string.h>
#include <time.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);

#define ASELF_SERVICES 0x9ULL          /* NETWORK|WITNESS -- keep in sync with bitcoind.asm's version msg */
#define ASELF_CAND     8               /* distinct candidate IPs tallied */
#define ASELF_PERIOD_S (24*3600)

static struct { u8 ip[4]; int votes; } g_cand[ASELF_CAND];
static u8   g_ip[4];
static int  g_confident;
static long g_last_announce;           /* unix time of the last broadcast */
static unsigned short g_port;          /* host order */
static int  g_enabled;

void addrself_init(unsigned short listen_port, int listen_enabled){
    g_port = listen_port;
    g_enabled = listen_enabled;
}

/* Feed one captured peer version payload (the raw bytes node_handshake
 * snapshots). addr_recv sits at offset 20: services(8) ip(16) port(2); the
 * ip is IPv6-mapped -- an IPv4 view is ::ffff:a.b.c.d. Non-IPv4 or
 * unroutable views are ignored. */
void addrself_note_peer_view(const u8* payload, long len){
    if (!g_enabled || g_confident || len < 46) return;
    const u8* ip16 = payload + 28;
    static const u8 v4map[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    if (memcmp(ip16, v4map, 12) != 0) return;
    const u8* v4 = ip16 + 12;
    /* unroutable views teach us nothing: loopback, RFC1918, zero */
    if (v4[0] == 127 || v4[0] == 10 || v4[0] == 0) return;
    if (v4[0] == 192 && v4[1] == 168) return;
    if (v4[0] == 172 && (v4[1] & 0xf0) == 16) return;
    for (int i = 0; i < ASELF_CAND; i++){
        if (g_cand[i].votes && !memcmp(g_cand[i].ip, v4, 4)){
            if (++g_cand[i].votes >= 2){
                memcpy(g_ip, v4, 4);
                g_confident = 1;
                fprintf(stderr, "[addrself] external address confirmed by %d peers: %u.%u.%u.%u:%u\n",
                        g_cand[i].votes, v4[0], v4[1], v4[2], v4[3], g_port);
            }
            return;
        }
    }
    for (int i = 0; i < ASELF_CAND; i++){
        if (!g_cand[i].votes){ memcpy(g_cand[i].ip, v4, 4); g_cand[i].votes = 1; return; }
    }
}

/* Build the 31-byte legacy addr message for our address into out; returns
 * length. Exposed for the test. */
long addrself_build(u8 out[64], long now){
    u8* p = out;
    *p++ = 1;                                        /* count */
    u32 t = (u32)now;
    for (int i = 0; i < 4; i++) *p++ = (u8)(t >> (8*i));
    u64 sv = ASELF_SERVICES;
    for (int i = 0; i < 8; i++) *p++ = (u8)(sv >> (8*i));
    memset(p, 0, 10); p += 10; *p++ = 0xff; *p++ = 0xff;   /* IPv4-mapped */
    memcpy(p, g_ip, 4); p += 4;
    *p++ = (u8)(g_port >> 8); *p++ = (u8)(g_port & 0xff);  /* port, BE */
    return p - out;
}

/* Announce to every live leg when confident and due (first time, then every
 * 24h). Cheap no-op otherwise; called once per worker rotation. */
long addrself_maybe_announce(const int* fds, int nfds){
    if (!g_enabled || !g_confident) return 0;
    long now = (long)time(NULL);
    if (g_last_announce && now - g_last_announce < ASELF_PERIOD_S) return 0;
    u8 msg[64];
    long n = addrself_build(msg, now);
    long sent = 0;
    for (int i = 0; i < nfds; i++){
        if (fds[i] < 0) continue;
        if (p2p_write(fds[i], "addr", 4, msg, (unsigned)n) > 0) sent++;
    }
    if (sent){
        g_last_announce = now;
        fprintf(stderr, "[addrself] advertised %u.%u.%u.%u:%u to %ld peer(s)\n",
                g_ip[0], g_ip[1], g_ip[2], g_ip[3], g_port, sent);
    }
    return sent;
}
