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
 * WHAT WE ANNOUNCE: one address entry with OUR services (NETWORK|WITNESS,
 * the same word the version message advertises) and the CONFIGURED listen
 * port, not a constant: this box's Core owns 8333, we listen on 8332, and
 * advertising 8333 sends every prospective peer to the wrong daemon.
 * Announced to every live leg when first learned and re-announced every
 * 24h (Core's own cadence); peers gossip it onward. Gated on listen=1.
 *
 * ENCODING follows each leg's handshake (2026-08-28): a peer that sent
 * `sendaddrv2` before verack gets a BIP155 `addrv2` entry -- time(4)
 * services(CompactSize) net(1)=IPv4 len(1)=4 ip(4) port(2 BE) -- and every
 * other peer the legacy `addr` entry -- time(4) services(8) ip(16,
 * IPv4-mapped) port(2 BE). That is Core's MaybeSendAddr: it never sends v1
 * to a peer that asked for v2.
 */
#include <stdio.h>
#include "log_ts.h"
#include <string.h>
#include <time.h>
#include "netaddr.h"   /* onion v3 parsing + checksum validation */

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);

#define ASELF_SERVICES 0x9ULL          /* NETWORK|WITNESS -- keep in sync with bitcoind.asm's version msg */
#define ASELF_CAND     8               /* distinct candidate IPs tallied */
#define ASELF_PERIOD_S (24*3600)

static struct { u8 ip[4]; int votes; } g_cand[ASELF_CAND];
static u8   g_ip[4];
/* Our onion service address, once tor has created one. Kept apart from g_ip
 * because it is a DIFFERENT address for a different audience: the clearnet
 * IPv4 goes to clearnet peers and the onion goes to onion peers, and crossing
 * them is the exact linkage running over Tor exists to prevent. */
static u8   g_onion[32];
static int  g_have_onion;
static unsigned short g_onion_port;
static int  g_confident;
static long g_last_announce;           /* unix time of the last broadcast */
static unsigned short g_port;          /* host order */
static int  g_enabled;

void addrself_init(unsigned short listen_port, int listen_enabled){
    g_port = listen_port;
    g_enabled = listen_enabled;
}
/* Core -externalip: announce THIS address instead of one learned from peers.
 * An operator behind a NAT or a port-forward knows the reachable address and
 * this node cannot deduce it. Setting it also skips the two-agreeing-peers
 * wait, because the operator has already answered the question that wait
 * exists to answer. (2026-08-29: the key was parsed and documented but never
 * read -- a setting that does nothing is worse than one that is absent.) */
/* Record the onion service address tor just created. Parsed through
 * bmc_addr_from_string so the v3 checksum and version byte are validated
 * exactly as Core's SetTor does -- a malformed service id must not be
 * announced to the network. Unlike the clearnet address this needs no
 * two-peer agreement: tor told us, so we know. */
int addrself_set_onion(const char* onion_str, unsigned short port){
    bmc_addr_t a;
    if (!onion_str || !bmc_addr_from_string(&a, onion_str)) return 0;
    if (a.net != BMC_NET_TORV3 || a.len != 32) return 0;
    memcpy(g_onion, a.addr, 32);
    g_onion_port = port;
    g_have_onion = 1;
    return 1;
}

int addrself_set_external(const unsigned char ip4[4]){
    if (!ip4) return 0;
    memcpy(g_ip, ip4, 4);
    g_confident = 1;
    return 1;
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

/* The BIP155 `addrv2` form of the same announcement (14 bytes for an IPv4
 * entry with a one-byte services CompactSize). Exposed for the test. */
long addrself_build_v2(u8 out[64], long now){
    u8* p = out;
    *p++ = 1;                                        /* count */
    u32 t = (u32)now;
    for (int i = 0; i < 4; i++) *p++ = (u8)(t >> (8*i));
    u64 sv = ASELF_SERVICES;                         /* services as CompactSize */
    if (sv < 0xfd) *p++ = (u8)sv;
    else if (sv <= 0xffff){ *p++ = 0xfd; *p++ = (u8)sv; *p++ = (u8)(sv >> 8); }
    else if (sv <= 0xffffffffULL){ *p++ = 0xfe; for (int i = 0; i < 4; i++) *p++ = (u8)(sv >> (8*i)); }
    else { *p++ = 0xff; for (int i = 0; i < 8; i++) *p++ = (u8)(sv >> (8*i)); }
    *p++ = 1;                                        /* network id: IPv4 */
    *p++ = 4;                                        /* address length */
    memcpy(p, g_ip, 4); p += 4;
    *p++ = (u8)(g_port >> 8); *p++ = (u8)(g_port & 0xff);  /* port, BE */
    return p - out;
}

/* The BIP155 addrv2 record for our ONION address (net id 4, 32 bytes). There
 * is no legacy `addr` equivalent -- a 32-byte address does not fit the 16-byte
 * field -- so an onion peer that never negotiated addrv2 simply cannot be told
 * where we are, and is skipped rather than sent a truncated lie. */
long addrself_build_v2_onion(u8 out[64], long now){
    if (!g_have_onion) return 0;
    u8* p = out;
    *p++ = 1;                                        /* count */
    u32 t = (u32)now;
    for (int i = 0; i < 4; i++) *p++ = (u8)(t >> (8*i));
    u64 sv = ASELF_SERVICES;
    if (sv < 0xfd) *p++ = (u8)sv;
    else if (sv <= 0xffff){ *p++ = 0xfd; *p++ = (u8)sv; *p++ = (u8)(sv >> 8); }
    else if (sv <= 0xffffffffULL){ *p++ = 0xfe; for (int i = 0; i < 4; i++) *p++ = (u8)(sv >> (8*i)); }
    else { *p++ = 0xff; for (int i = 0; i < 8; i++) *p++ = (u8)(sv >> (8*i)); }
    *p++ = 4;                                        /* network id: TORV3 */
    *p++ = 32;                                       /* address length */
    memcpy(p, g_onion, 32); p += 32;
    *p++ = (u8)(g_onion_port >> 8); *p++ = (u8)(g_onion_port & 0xff);
    return p - out;
}

/* Announce to every live leg when confident and due (first time, then every
 * 24h). Cheap no-op otherwise; called once per worker rotation. wants_v2[i]
 * is that leg's handshake verdict (1 = it sent sendaddrv2); NULL = all v1. */
/* PRIVACY (2026-08-28 pre-deploy review). We announce ONE address: this
 * node's clearnet IPv4. Since the transports landed, a leg can be onion or
 * i2p -- and telling an onion peer our clearnet IPv4 links the two, which is
 * precisely what running over Tor is meant to prevent. Core's GetLocal has
 * the same guard: "don't advertise our privacy-network address to other
 * networks and don't advertise our other-network address to privacy
 * networks". `nets[i]` is each leg's BMC_NET_*; a NULL array means every leg
 * is clearnet (the callers that predate the transports). */
long addrself_maybe_announce_nets(const int* fds, const u8* wants_v2, const u8* nets, int nfds){
    /* Either address is enough of a reason to run: the clearnet one needs
     * g_confident (two peers agreeing on what they see), the onion one does
     * not -- tor created it, so it is not a guess. */
    int have_clearnet = g_enabled && g_confident;
    if (!have_clearnet && !g_have_onion) return 0;
    long now = (long)time(NULL);
    if (g_last_announce && now - g_last_announce < ASELF_PERIOD_S) return 0;
    u8 msg[64], msg2[64], msgo[64];
    long n = have_clearnet ? addrself_build(msg, now) : 0;
    long n2 = have_clearnet ? addrself_build_v2(msg2, now) : 0;
    long no = addrself_build_v2_onion(msgo, now);
    long sent = 0, sent_onion = 0;
    for (int i = 0; i < nfds; i++){
        if (fds[i] < 0) continue;
        int net = nets ? nets[i] : 1 /* callers predating the transports */;
        int v2 = wants_v2 && wants_v2[i];
        long w = 0;
        if (net == 4 /* BMC_NET_TORV3 */){
            /* tell an onion peer our ONION address -- never the clearnet one,
             * which would link the two. Requires addrv2; a 32-byte address
             * has no legacy encoding, so a v1-only onion peer learns nothing
             * rather than being sent something wrong. */
            if (no > 0 && v2){ w = p2p_write(fds[i], "addrv2", 6, msgo, (unsigned)no); if (w > 0) sent_onion++; }
        } else if (net == 1 /* IPV4 */ || net == 2 /* IPV6 */){
            if (!have_clearnet) continue;
            w = v2 ? p2p_write(fds[i], "addrv2", 6, msg2, (unsigned)n2)
                   : p2p_write(fds[i], "addr",   4, msg,  (unsigned)n);
        } else {
            continue;               /* i2p/cjdns: no address of theirs to give */
        }
        if (w > 0) sent++;
    }
    if (sent){
        g_last_announce = now;
        if (sent - sent_onion > 0)
            fprintf(stderr, "[addrself] advertised %u.%u.%u.%u:%u to %ld clearnet peer(s)\n",
                    g_ip[0], g_ip[1], g_ip[2], g_ip[3], g_port, sent - sent_onion);
        if (sent_onion)
            fprintf(stderr, "[addrself] advertised our onion address to %ld onion peer(s)\n", sent_onion);
    }
    return sent;
}

/* the pre-transport signature, for callers that have no per-leg networks */
long addrself_maybe_announce(const int* fds, const u8* wants_v2, int nfds){
    return addrself_maybe_announce_nets(fds, wants_v2, NULL, nfds);
}
