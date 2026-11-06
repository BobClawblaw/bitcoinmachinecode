/* daemon/net_policy.c -- outbound connection classes and address-source
 * policy, modelled on Bitcoin Core's:
 *
 *   full-relay        (8)  tx + block relay, addr gossip   [we already had this]
 *   block-relay-only  (2)  headers/blocks ONLY -- relay=0, never gossiped
 *                          (dialled by the dial helpers, main.c CC-4)
 *   feeler            (1)  short-lived, ~every 2 min, tests one book entry
 *
 * WHY BLOCK-RELAY-ONLY. Core 0.19 added these as an anti-eclipse measure. They
 * set relay=0 and are never advertised through addr gossip, so an attacker
 * enumerating the network by watching gossip cannot discover them and cannot
 * crowd them out. If all of a node's ordinary outbound peers are attacker
 * controlled, these still carry the real best chain. That matters more here
 * than it looks: Stage B acts on peer-supplied chainwork to decide reorgs, so
 * "who can we be eclipsed by" is now a consensus-relevant question.
 *
 * WHY FEELERS. They are the reason a healthy node's address book stays
 * reachable. Every ~2 minutes Core connects to one untested entry, confirms it
 * is alive, and disconnects. Without that, a book rots silently -- observed on
 * this node 2026-08-18: 1,974 entries, only ~4% still answering. Widening the
 * candidate pool and asking peers for more (563da15) treated the symptom;
 * continuous validation is the actual cure.
 *
 * WHY NETGROUPS. Core buckets addrman by source netgroup precisely so one
 * source cannot flood the table. Our address book is a flat list with no such
 * limit, and the getaddr support added in 563da15 will happily accept 838
 * addresses from ONE peer -- which is an eclipse vector introduced by that
 * commit. The caps here bound how much any single source, and any single /16,
 * can contribute.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

extern long p2p_write(int,const char*,unsigned,const void*,unsigned);
extern int  p2p_read(int,char[12],void*,unsigned,unsigned*);
extern void fd_close(int);

/* The version message every secondary connection sends (2026-11-06): the
 * feeler here and seednode address gathering (addr_ingest.c). Each used to
 * hand-build its own -- /Satoshi:25.0.0/ or /Satoshi:0.18.0/, services=1,
 * the constant nonce 0x11223344, start height 0 or 789000, port 8333 --
 * copies of the asm handshake from before its 2026-09-09 fixes, which they
 * never received. The full-relay and block-relay-only legs send
 * node_make_version's (bitcoind.asm: our user agent and -uacomment, our
 * service bits, a random nonce, our tip and listen port), and Core sends
 * the same version on every kind of connection. main.c registers that
 * builder and the chain's default port at boot; without a builder these
 * connections are not made. */
static long (*g_np_version)(unsigned char* out);
static unsigned short g_np_default_port = 8333;
void net_policy_set_version(long (*build)(unsigned char* out), unsigned short default_port){
    g_np_version = build;
    if(default_port) g_np_default_port = default_port;
}
/* The version payload into v (512 bytes: 81 + a 255-byte agent + 5). relay
 * 0/1 sets the fRelay byte, the payload's last; -1 keeps the builder's,
 * which is 0 under -blocksonly. Returns the length, or -1. */
long net_version_payload(unsigned char* v, int relay){
    if(!g_np_version) return -1;
    long n = g_np_version(v);
    if(n < 86 || n > 512) return -1;
    if(relay >= 0) v[n - 1] = (unsigned char)(relay ? 1 : 0);
    return n;
}
/* "a.b.c.d" or "a.b.c.d:port", the candidate pool's form; a bare address
 * takes the chain's default port. 1 / 0. The feeler used to hand the pool
 * entry straight to inet_pton, which refuses "a.b.c.d:port": every feeler
 * failed before dialing (production, 2026-09-27..11-05: 23,687 probes, 0
 * alive). */
int net_parse_v4(const char* s, unsigned* ip, unsigned short* port){
    char host[64]; const char* colon = strrchr(s, ':');
    size_t hl = colon ? (size_t)(colon - s) : strlen(s);
    if(hl == 0 || hl >= sizeof host) return 0;
    memcpy(host, s, hl); host[hl] = 0;
    if(inet_pton(AF_INET, host, ip) != 1) return 0;
    *port = g_np_default_port;
    if(colon){
        char* end; long p = strtol(colon + 1, &end, 10);
        if(end == colon + 1 || *end || p <= 0 || p > 65535) return 0;
        *port = (unsigned short)p;
    }
    return 1;
}

/* IPv4 netgroup == the /16, matching Core's grouping for IPv4. `ip` is in the
 * host-order-of-network-bytes form used throughout this daemon (see
 * dl_pool_from_book's comment on amr byte order): byte 0 is the first octet. */
unsigned net_netgroup_v4(unsigned ip){
    return ip & 0x0000FFFFu;      /* first two octets */
}

/* Version/verack handshake with an explicit relay flag, to "a.b.c.d[:port]".
 *   relay=1 -> the peer may send us transactions
 *   relay=0 -> it must not (Core: block-relay-only and feeler connections)
 * Returns a live post-verack fd, or -1. The feeler's path; the legs go
 * through the dial helpers' node_handshake. */
int net_handshake_relay(const char* ip_str, int relay, int rcv_secs){
    unsigned ip; unsigned short port;
    if(!net_parse_v4(ip_str, &ip, &port)) return -1;
    unsigned char v[512]; long vl = net_version_payload(v, relay);
    if(vl < 0) return -1;

    /* NON-BLOCKING connect with a bounded wait. tcp_connect_ip() is a plain
     * blocking connect() with NO connect-phase timeout (SO_RCVTIMEO only
     * bounds reads afterwards), so a black-holed address stalls for the OS
     * timeout -- minutes. That is fatal here: feelers run on the download
     * worker's rotation loop, so one dead address would freeze block sync.
     * Caught by the first run of tests/test_net_policy, which hung on
     * 192.0.2.1 (TEST-NET-1, deliberately unroutable). Same technique as
     * dlc_probe_round. */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) return -1;
    int fl = fcntl(fd,F_GETFL,0); fcntl(fd,F_SETFL,fl|O_NONBLOCK);
    struct sockaddr_in sa; memset(&sa,0,sizeof sa);
    sa.sin_family=AF_INET; sa.sin_addr.s_addr=ip; sa.sin_port=(unsigned short)htons(port);
    int rc = connect(fd,(struct sockaddr*)&sa,sizeof sa);
    if(rc!=0 && errno!=EINPROGRESS){ close(fd); return -1; }
    if(rc!=0){
        struct pollfd pf = { fd, POLLOUT, 0 };
        int pr = poll(&pf, 1, (rcv_secs>0?rcv_secs:6)*1000);
        if(pr<=0 || !(pf.revents & POLLOUT)){ close(fd); return -1; }
        int soerr=0; socklen_t sl=sizeof soerr;
        if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&soerr,&sl)<0 || soerr!=0){ close(fd); return -1; }
    }
    fcntl(fd,F_SETFL,fl);                       /* back to blocking for the handshake */
    struct timeval tv; tv.tv_sec = rcv_secs>0?rcv_secs:6; tv.tv_usec=0;
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);

    if(p2p_write(fd,"version",7,v,(unsigned)vl)<=0){ fd_close(fd); return -1; }

    char cmd[12]; static unsigned char rb[1<<20]; unsigned plen=0; int va=0;
    for(int i=0;i<60;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0) break; cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(!strncmp(cmd,"sendheaders",11)||!strncmp(cmd,"wtxidrelay",10)||!strncmp(cmd,"sendcmpct",9)){
            p2p_write(fd,cmd,strlen(cmd),"",0); continue; }
        if(!strncmp(cmd,"sendaddrv2",10)){ p2p_write(fd,"sendaddrv2",10,"",0); continue; }
        if(!strncmp(cmd,"verack",6)){ va=1; break; }
    }
    if(!va){ fd_close(fd); return -1; }
    p2p_write(fd,"verack",6,"",0);
    /* Deliberately NO getaddr here. A block-relay-only peer must not be drawn
     * into addr gossip -- that is what keeps it undiscoverable. */
    return fd;
}

/* Feeler: connect, complete the handshake, drop immediately. Returns 1 if the
 * peer is genuinely alive (completed a version/verack exchange), else 0.
 * Short timeout -- a feeler is a liveness probe, not a download. */
int net_feeler_probe(const char* ip_str){
    int fd = net_handshake_relay(ip_str, 0, 4);   /* Core: RejectIncomingTxs is true for a feeler, so fRelay=0 */
    if(fd < 0) return 0;
    fd_close(fd);
    return 1;
}
