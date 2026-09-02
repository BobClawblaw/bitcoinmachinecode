/* daemon/addr_ingest.c -- ask real peers for more peers, and fold the replies
 * into the address book.
 *
 * WHY. The node was a net address SUPPLIER and never a consumer:
 * bitcoin_serve.asm answers inbound `getaddr` with a full `addr` reply, but
 * the daemon never sent `getaddr` itself and never parsed an inbound `addr`
 * into the book. The ONLY writer was dl_bootstrap resolving ~12 DNS seed
 * hostnames at startup. So the book was effectively fixed at whatever the
 * seeds returned and decayed as peers died -- observed 2026-08-18: a
 * 1,974-entry book yielding only ~4% reachable, with three of the last four
 * boots discovering "+0 peers". Exhausting the peer list had no recovery
 * path beyond re-probing the same dying set.
 *
 * The wire-format parsing here is lifted verbatim from daemon/addrgather.c,
 * which already did exactly this correctly but was never called from the
 * daemon and was not even in the Makefile -- an orphaned tool, the same shape
 * daemon/build_utxo was in. Rather than write a second addr parser, this
 * makes that logic reusable and wires it into the node.
 */
#include <stdio.h>
#include "log_ts.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "node_config.h"

extern int  tcp_connect_ip(unsigned, unsigned short);
extern long p2p_write(int,const char*,unsigned,const void*,unsigned);
extern int  p2p_read(int,char[12],void*,unsigned,unsigned*);
extern void fd_close(int);
extern long p2p_addr_count(const void* pl, long plen);
extern unsigned net_netgroup_v4(unsigned ip);           /* daemon/net_policy.c */

/* SOURCE LIMITS. Core buckets addrman by source netgroup so no single source
 * can flood the table. Our book is a flat list with no such protection, and
 * the getaddr support in 563da15 accepted 838 addresses from ONE peer -- an
 * eclipse vector that commit introduced. Bound both the total taken from one
 * response and how much of it may share a /16, so a hostile peer cannot fill
 * the book with addresses it controls. */
#define AI_MAX_PER_RESPONSE 256
#define AI_MAX_PER_NETGROUP 16

typedef struct { unsigned ng[AI_MAX_PER_RESPONSE]; int cnt[AI_MAX_PER_RESPONSE]; int n; int taken;
                 long limit; /* > 0: consider at most this many records (caller's token budget) */
                 int* viol;  /* audit 2026-09-02 N3: set to 1 when the payload is a protocol violation
                              * (malformed, or a count above MAX_ADDR_TO_SEND); NULL = nobody asked */ } ai_quota_t;
#define AI_VIOL(q) do { if ((q)->viol) *(q)->viol = 1; } while (0)


static void ai_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void ai_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static void ai_u16(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}


/* ---- the book and the parsers, version 2 (2026-08-28) ----------------------
 * Both parsers now go through daemon/netaddr.c (every BIP155 network) and
 * write to the version-2 book (daemon/addrbook.c, peers2.dat). The legacy
 * `void* ab` argument callers still pass is ignored: the book is opened
 * lazily, once per process, read-write (this code runs in the download
 * worker, the single writer). */
#include "netaddr.h"
#include "addrbook.h"
static ab2_t* g_book;
/* CompactSize reader (the addrv2 count); 1 ok / 0 truncated */
static int ai_compact(const unsigned char* pl, long plen, unsigned long long* pos, unsigned long long* v){
    if((long)*pos >= plen) return 0;
    unsigned char c = pl[*pos];
    if(c < 0xfd){ *v = c; *pos += 1; return 1; }
    if(c == 0xfd){ if((long)*pos + 3 > plen) return 0; *v = (unsigned long long)pl[*pos+1] | ((unsigned long long)pl[*pos+2] << 8); *pos += 3; return 1; }
    if(c == 0xfe){ if((long)*pos + 5 > plen) return 0; *v = 0; for(int i=0;i<4;i++) *v |= (unsigned long long)pl[*pos+1+i] << (8*i); *pos += 5; return 1; }
    if((long)*pos + 9 > plen) return 0;
    *v = 0; for(int i=0;i<8;i++) *v |= (unsigned long long)pl[*pos+1+i] << (8*i); *pos += 9; return 1;
}
ab2_t* addr_book(void){
    if(!g_book) g_book = ab2_open(".", 1);
    return g_book;
}
static int ai_quota_ok_addr(ai_quota_t* q, const bmc_addr_t* a){
    if(q->taken >= g_cfg.addr_max_per_response) return 0;
    unsigned long long g = bmc_addr_group(a);
    unsigned gk = (unsigned)(g ^ (g >> 32));
    for(int i=0;i<q->n;i++){
        if(q->ng[i]==gk){
            if(q->cnt[i] >= g_cfg.addr_max_per_netgroup) return 0;
            q->cnt[i]++; q->taken++; return 1;
        }
    }
    if(q->n < AI_MAX_PER_RESPONSE){ q->ng[q->n]=gk; q->cnt[q->n]=1; q->n++; }
    q->taken++;
    return 1;
}
static long ai_ingest_one(ab2_t* b, const bmc_addr_t* a, unsigned long long svc, unsigned tm, ai_quota_t* q){
    if(!bmc_addr_is_routable(a)) return 0;
    if(!ai_quota_ok_addr(q, a)) return 0;
    /* Core: a time in the future or before 2001 is replaced by now-5d */
    unsigned now = (unsigned)time(NULL);
    if(tm > now + 600 || tm < 100000000u) tm = now - 5*24*3600;
    return ab2_add(b, a, svc, tm) > 0 ? 1 : 0;
}
/* legacy `addr`: CompactSize count, then 30-byte records; IPv4 arrives
 * ::ffff:-mapped, IPv6 native (see netaddr.c). Before 2026-08-28 this read
 * the IPv4 from the wrong offset and fabricated addresses from timestamps. */
static long ai_ingest_addr1(void* unused, const unsigned char* pl, long plen, ai_quota_t* q){
    (void)unused;
    long cnt = p2p_addr_count(pl, plen);
    if(cnt < 0){ AI_VIOL(q); return 0; }                  /* count does not fit the payload: malformed */
    if(cnt == 0) return 0;
    if(cnt > 1000){ AI_VIOL(q); return 0; }               /* Core: MAX_ADDR_TO_SEND, misbehaving */
    long base = (pl[0]<0xfd)?1:(pl[0]==0xfd?3:(pl[0]==0xfe?5:9));
    ab2_t* b = addr_book(); if(!b) return 0;
    long added=0;
    for(long k=0;k<cnt;k++){
        if(q->limit > 0 && k >= q->limit) break;         /* token budget exhausted */
        if(base+k*30+30>plen) break;
        bmc_addr_t a; unsigned long long svc; unsigned tm;
        if(bmc_addr_decode_v1(&a, &svc, &tm, pl + base + k*30, 30) != 30) continue;
        added += ai_ingest_one(b, &a, svc, tm, q);
    }
    return added;
}
/* BIP155 `addrv2`: CompactSize count, then variable records for any network.
 * An entry of an unknown network id is skipped over (Core does the same). */
static long ai_ingest_addrv2(void* unused, const unsigned char* pl, long plen, ai_quota_t* q){
    (void)unused;
    if(plen < 1) return 0;
    unsigned long long pos = 0, cnt = 0;
    if(!ai_compact(pl, plen, &pos, &cnt)){ AI_VIOL(q); return 0; }   /* truncated count: malformed */
    if(cnt > 1000){ AI_VIOL(q); return 0; }               /* Core: MAX_ADDR_TO_SEND, misbehaving */
    ab2_t* b = addr_book(); if(!b) return 0;
    long added = 0;
    for(unsigned long long k=0; k<cnt && (long)pos < plen; k++){
        if(q->limit > 0 && (long)k >= q->limit) break;   /* token budget exhausted */
        bmc_addr_t a; unsigned long long svc; unsigned tm; long used = 0;
        long r = bmc_addr_decode_v2(&a, &svc, &tm, pl + pos, plen - (long)pos, &used);
        if(r == -1){ AI_VIOL(q); break; }                 /* malformed record: violation, stop */
        pos += (unsigned long long)used;
        if(r == -2) continue;                             /* unknown network: skipped */
        added += ai_ingest_one(b, &a, svc, tm, q);
    }
    return added;
}
/* Fold one received addr/addrv2 payload into the book, considering at most
 * `limit` records (0 = all; the caller's token budget). Public so the parsers
 * can be tested on Core's own bytes and so the outbound legs
 * (daemon/tx_relay.c) share them. The `ab` argument is legacy and ignored. */
long addr_ingest_msg_v(void* ab, const char* cmd, const unsigned char* pl, long plen, long limit, int* viol){
    (void)ab;
    ai_quota_t quota; memset(&quota,0,sizeof quota); quota.limit = limit; quota.viol = viol;
    if(viol) *viol = 0;
    if(!strncmp(cmd,"addrv2",6)) return ai_ingest_addrv2(NULL, pl, plen, &quota);
    if(!strncmp(cmd,"addr",4))   return ai_ingest_addr1(NULL, pl, plen, &quota);
    return 0;
}
long addr_ingest_msg_n(void* ab, const char* cmd, const unsigned char* pl, long plen, long limit){
    return addr_ingest_msg_v(ab, cmd, pl, plen, limit, NULL);
}
long addr_ingest_msg(void* ab, const char* cmd, const unsigned char* pl, long plen){
    return addr_ingest_msg_v(ab, cmd, pl, plen, 0, NULL);
}

/* Connect, handshake, send getaddr, and fold replies into `ab` for up to
 * wait_s seconds. Returns entries added (0 on any failure -- this is a
 * best-effort enrichment and must never be able to fail a boot). */
long addr_gather_from(void* ab, const char* ip_str, int wait_s){
    unsigned ip;
    if(inet_pton(AF_INET, ip_str, &ip)!=1) return 0;
    int fd = tcp_connect_ip(ip, (unsigned short)htons(8333));
    if(fd<0) return 0;
    struct timeval tv; tv.tv_sec=6; tv.tv_usec=0;
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);

    unsigned char v[102]; int o=0;
    ai_u32(v+o,70016);o+=4; ai_u64(v+o,1);o+=8; ai_u64(v+o,(unsigned long long)time(NULL));o+=8;
    ai_u64(v+o,1);o+=8; o+=16; ai_u16(v+o,8333);o+=2; ai_u64(v+o,1);o+=8; o+=16; ai_u16(v+o,0);o+=2;
    ai_u64(v+o,0x0000000011223344ULL);o+=8;
    const char* ua="/Satoshi:0.18.0/"; v[o]=(unsigned char)strlen(ua); o+=1; memcpy(v+o,ua,strlen(ua)); o+=strlen(ua);
    ai_u32(v+o,789000);o+=4; v[o]=1;o+=1;
    if(p2p_write(fd,"version",7,v,o)<=0){ fd_close(fd); return 0; }

    char cmd[12]; static unsigned char rb[4<<20]; unsigned plen=0; int va=0;
    for(int i=0;i<60;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0) break; cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(!strncmp(cmd,"sendheaders",11)||!strncmp(cmd,"wtxidrelay",10)||!strncmp(cmd,"sendcmpct",9)){ p2p_write(fd,cmd,strlen(cmd),"",0); continue; }
        if(!strncmp(cmd,"sendaddrv2",10)){ p2p_write(fd,"sendaddrv2",10,"",0); continue; }
        if(!strncmp(cmd,"verack",6)){ va=1; break; }
    }
    if(!va){ fd_close(fd); return 0; }
    p2p_write(fd,"verack",6,"",0);
    /* NO sendaddrv2 here. BIP155 requires it to be sent BEFORE verack -- Core
     * treats a late one as a protocol violation and drops the connection,
     * which is exactly what was happening: handshake succeeded, a few
     * messages arrived, then silence and zero addresses. We already echo the
     * peer's own sendaddrv2 during the handshake above, which is what
     * negotiates v2 properly. (daemon/addrgather.c has the same late send,
     * which is likely why that tool was never seen to work.) */
    p2p_write(fd,"getaddr",7,"",0);

    /* Read until the DEADLINE, not until the first quiet moment. A peer does
     * not answer getaddr immediately -- Core delays address relay, and the
     * observed reply landed only after sendcmpct/getheaders/feefilter and a
     * pause longer than the socket timeout. Treating a recv timeout (r<=0)
     * as fatal meant bailing out at that pause every time, which is why the
     * first live test harvested 0 peers from nodes that were in fact
     * answering correctly. Keep waiting; only the wall clock ends this. */
    ai_quota_t quota; memset(&quota,0,sizeof quota);   /* per-peer source limit */
    long added=0; time_t endt=time(NULL)+(wait_s>0?wait_s:5);
    while(time(NULL)<endt){
        plen=0; int r=p2p_read(fd,cmd,rb,sizeof rb,&plen);
        if(r<=0) continue;            /* recv timeout -- keep waiting */
        cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(!strncmp(cmd,"addrv2",6))     added += ai_ingest_addrv2(ab, rb, plen, &quota);
        else if(!strncmp(cmd,"addr",4))  added += ai_ingest_addr1(ab, rb, plen, &quota);
    }
    fd_close(fd);
    return added;
}

/* Ask several peers in turn; stops early once `target` new entries land so a
 * healthy book costs one round trip, not npeers of them. */
long addr_replenish(void* ab, char peers[][64], int npeers, int max_try, int wait_s, long target){
    long total=0, before=ab2_count(addr_book());
    for(int i=0;i<npeers && i<max_try; i++){
        total += addr_gather_from(ab, peers[i], wait_s);
        if(target>0 && total>=target) break;
    }
    if(total>0)
        fprintf(stderr,"[addr] getaddr: +%ld new peer(s) from %d peer(s) asked (book %ld -> %ld)\n",
                total, (int)(npeers<max_try?npeers:max_try), before, ab2_count(addr_book()));
    else
        fprintf(stderr,"[addr] getaddr: no new peers returned (book %ld)\n", before);
    return total;
}
