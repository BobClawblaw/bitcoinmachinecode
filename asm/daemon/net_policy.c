/* daemon/net_policy.c -- outbound connection classes and address-source
 * policy, modelled on Bitcoin Core's:
 *
 *   full-relay        (8)  tx + block relay, addr gossip   [we already had this]
 *   block-relay-only  (2)  headers/blocks ONLY -- relay=0, never gossiped
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

static void np_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void np_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static void np_u16(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}

/* IPv4 netgroup == the /16, matching Core's grouping for IPv4. `ip` is in the
 * host-order-of-network-bytes form used throughout this daemon (see
 * dl_pool_from_book's comment on amr byte order): byte 0 is the first octet. */
unsigned net_netgroup_v4(unsigned ip){
    return ip & 0x0000FFFFu;      /* first two octets */
}

/* Version/verack handshake with an explicit relay flag.
 *   relay=1 -> ordinary full-relay peer
 *   relay=0 -> block-relay-only: peer must not send us transactions
 * Returns a live post-verack fd, or -1. The asm node_handshake hardcodes
 * relay=1 (bitcoind.asm), so block-relay-only needs its own path; this also
 * keeps the flag visible at the call site instead of buried in the wire
 * layout. */
int net_handshake_relay(const char* ip_str, int relay, int rcv_secs){
    unsigned ip;
    if(inet_pton(AF_INET, ip_str, &ip)!=1) return -1;

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
    sa.sin_family=AF_INET; sa.sin_addr.s_addr=ip; sa.sin_port=(unsigned short)htons(8333);
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

    unsigned char v[102]; int o=0;
    np_u32(v+o,70016);o+=4; np_u64(v+o,1);o+=8; np_u64(v+o,(unsigned long long)time(NULL));o+=8;
    np_u64(v+o,1);o+=8; o+=16; np_u16(v+o,8333);o+=2; np_u64(v+o,1);o+=8; o+=16; np_u16(v+o,0);o+=2;
    np_u64(v+o,0x0000000011223344ULL);o+=8;
    const char* ua="/Satoshi:25.0.0/"; v[o]=(unsigned char)strlen(ua); o+=1;
    memcpy(v+o,ua,strlen(ua)); o+=strlen(ua);
    np_u32(v+o,0);o+=4;
    v[o] = (unsigned char)(relay?1:0); o+=1;          /* <-- the whole point */
    if(p2p_write(fd,"version",7,v,o)<=0){ fd_close(fd); return -1; }

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
    int fd = net_handshake_relay(ip_str, 1, 4);
    if(fd < 0) return 0;
    fd_close(fd);
    return 1;
}
