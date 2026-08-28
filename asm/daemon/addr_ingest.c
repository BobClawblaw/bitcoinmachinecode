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
extern int  amr_add(void* ab, unsigned ip, unsigned short port, unsigned long long svc, unsigned lastseen);
extern long amr_count(void* ab);
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

typedef struct { unsigned ng[AI_MAX_PER_RESPONSE]; int cnt[AI_MAX_PER_RESPONSE]; int n; int taken; } ai_quota_t;

static int ai_quota_ok(ai_quota_t* q, unsigned ip){
    if(q->taken >= g_cfg.addr_max_per_response) return 0;
    unsigned g = net_netgroup_v4(ip);
    for(int i=0;i<q->n;i++){
        if(q->ng[i]==g){
            if(q->cnt[i] >= g_cfg.addr_max_per_netgroup) return 0;
            q->cnt[i]++; q->taken++; return 1;
        }
    }
    if(q->n < AI_MAX_PER_RESPONSE){ q->ng[q->n]=g; q->cnt[q->n]=1; q->n++; }
    q->taken++;
    return 1;
}

static void ai_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void ai_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static void ai_u16(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}

static int ai_public_v4(const unsigned char* a){
    if(a[0]==0||a[0]==127||a[0]>=240) return 0;
    if(a[0]==10) return 0;
    if(a[0]==192&&a[1]==168) return 0;
    if(a[0]==172&&a[1]>=16&&a[1]<=31) return 0;
    if(a[0]==169&&a[1]==254) return 0;
    return 1;
}

/* v1 addr payload -> book. 30-byte records after the CompactSize count:
 * time(4) services(8) ip16(16) port(2 BE). An IPv4 is carried IPv4-MAPPED:
 * ten zero bytes, ff ff, then a.b.c.d at 24..27 of the record.
 *
 * FIXED 2026-08-28. This read the address from record offset 12 -- the
 * FIRST four bytes of the ip16 field, which are 00 00 00 00 for every mapped
 * IPv4 Core sends -- and then "fell back" to offset 0, the timestamp, so a
 * v1 reply either yielded nothing or wrote a FABRICATED address made of time
 * bytes (e.g. 60.154.176.104 for t=0x68b09a3c) with the real port into the
 * book. Found by an adversarial review that executed this function on
 * Core's own msg_addr bytes. Anything not in the mapped form is skipped. */
static long ai_ingest_addr1(void* ab, const unsigned char* pl, long plen, ai_quota_t* q){
    long cnt = p2p_addr_count(pl, plen); if(cnt<=0) return 0;
    long base = (pl[0]<0xfd)?1:(pl[0]==0xfd?3:(pl[0]==0xfe?5:9));
    long added=0;
    static const unsigned char v4map[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    for(long k=0;k<cnt;k++){
        const unsigned char* r = pl + base + k*30;
        if(base+k*30+30>plen) break;
        if(memcmp(r+12, v4map, 12)!=0) continue;        /* not an IPv4-mapped entry */
        const unsigned char* ipb = r+24;
        if(!ai_public_v4(ipb)) continue;
        /* the book stores the port BIG-ENDIAN, exactly as it sits on the
         * wire (see amr_add); this passed the host-order value, so every
         * gossip-learned port was stored byte-swapped and, once getaddr
         * replies worked, would have been served byte-swapped to Core */
        unsigned short port = htons((unsigned short)((r[28]<<8)|r[29]));
        unsigned long long svc = (unsigned long long)r[4] | (unsigned long long)r[5]<<8 |
            (unsigned long long)r[6]<<16 |(unsigned long long)r[7]<<24 | (unsigned long long)r[8]<<32 |
            (unsigned long long)r[9]<<40 |(unsigned long long)r[10]<<48 |(unsigned long long)r[11]<<56;
        unsigned ip = (unsigned)ipb[0]|(unsigned)ipb[1]<<8|(unsigned)ipb[2]<<16|(unsigned)ipb[3]<<24;
        if(!ai_quota_ok(q, ip)) continue;
        if(amr_add(ab, ip, port, svc, (unsigned)time(NULL))>0) added++;
    }
    return added;
}

/* Read a CompactSize at *pos. Returns 0 on truncation. */
static int ai_compact(const unsigned char* pl, long plen, unsigned long long* pos, unsigned long long* out){
    if(*pos >= (unsigned long long)plen) return 0;
    unsigned char c = pl[*pos];
    if(c < 0xfd){ *out = c; *pos += 1; return 1; }
    if(c == 0xfd){ if(*pos+3 > (unsigned long long)plen) return 0;
        *out = (unsigned long long)pl[*pos+1] | ((unsigned long long)pl[*pos+2]<<8); *pos += 3; return 1; }
    if(c == 0xfe){ if(*pos+5 > (unsigned long long)plen) return 0;
        *out = (unsigned long long)pl[*pos+1] | ((unsigned long long)pl[*pos+2]<<8)
             | ((unsigned long long)pl[*pos+3]<<16) | ((unsigned long long)pl[*pos+4]<<24); *pos += 5; return 1; }
    if(*pos+9 > (unsigned long long)plen) return 0;
    unsigned long long v=0; for(int i=0;i<8;i++) v |= (unsigned long long)pl[*pos+1+i]<<(8*i);
    *out = v; *pos += 9; return 1;
}

/* addrv2 payload -> book (BIP155).
 *
 * REWRITTEN. The version inherited from daemon/addrgather.c could not parse a
 * real reply, which is why the first live test harvested 0 peers from 4 nodes
 * that each answered correctly. Three separate framing bugs:
 *
 *   1. count was read as a SINGLE BYTE. It is a CompactSize. A ~1000-address
 *      reply encodes as 0xfd,lo,hi -- so count came out 253 and every field
 *      after it was offset by two bytes.
 *   2. services was skipped with a protobuf-style `while(b & 0x80)` loop.
 *      CompactSize is not that encoding: services=1037 is 0xfd,0x0d,0x04,
 *      which that loop consumes as 2 bytes instead of 3, desynchronising the
 *      rest of the record.
 *   3. the loop guard was `pos+30 < plen`, assuming v1's fixed 30-byte
 *      records. addrv2 records are variable length -- an IPv4 entry is ~16
 *      bytes -- so a small reply (observed: plen=16, one address) was
 *      rejected outright and a large one was truncated early.
 *
 * Record layout per BIP155: time u32le, services CompactSize, networkID u8,
 * addr (CompactSize len + bytes), port u16be. */
static long ai_ingest_addrv2(void* ab, const unsigned char* pl, long plen, ai_quota_t* q){
    if(plen < 1) return 0;
    unsigned long long pos = 0, cnt = 0;
    if(!ai_compact(pl, plen, &pos, &cnt)) return 0;
    long added = 0;
    for(unsigned long long k=0; k<cnt; k++){
        if(pos + 4 > (unsigned long long)plen) break;
        unsigned tm = (unsigned)pl[pos] | ((unsigned)pl[pos+1]<<8)
                    | ((unsigned)pl[pos+2]<<16) | ((unsigned)pl[pos+3]<<24);
        pos += 4;
        unsigned long long svc = 0;
        if(!ai_compact(pl, plen, &pos, &svc)) break;
        if(pos >= (unsigned long long)plen) break;
        unsigned net = pl[pos]; pos += 1;              /* networkID is a plain u8 */
        unsigned long long alen = 0;
        if(!ai_compact(pl, plen, &pos, &alen)) break;
        if(pos + alen + 2 > (unsigned long long)plen) break;
        const unsigned char* ad = pl + pos;
        pos += alen;
        unsigned short port = htons((unsigned short)((pl[pos]<<8) | pl[pos+1]));  /* book: BE on disk */
        pos += 2;
        if(net == 1 && alen == 4 && ai_public_v4(ad)){   /* 1 == IPv4 */
            unsigned ip = (unsigned)ad[0] | (unsigned)ad[1]<<8 | (unsigned)ad[2]<<16 | (unsigned)ad[3]<<24;
            if(!ai_quota_ok(q, ip)) continue;
            if(amr_add(ab, ip, port, svc, tm) > 0) added++;
        }
    }
    return added;
}

/* Fold one received addr/addrv2 payload into the book. Public so the
 * parsers above can be tested on Core's own bytes without a live peer;
 * addr_gather_from uses the same functions with its per-peer quota. */
long addr_ingest_msg(void* ab, const char* cmd, const unsigned char* pl, long plen){
    ai_quota_t quota; memset(&quota,0,sizeof quota);
    if(!strncmp(cmd,"addrv2",6)) return ai_ingest_addrv2(ab, pl, plen, &quota);
    if(!strncmp(cmd,"addr",4))   return ai_ingest_addr1(ab, pl, plen, &quota);
    return 0;
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
    long total=0, before=amr_count(ab);
    for(int i=0;i<npeers && i<max_try; i++){
        total += addr_gather_from(ab, peers[i], wait_s);
        if(target>0 && total>=target) break;
    }
    if(total>0)
        fprintf(stderr,"[addr] getaddr: +%ld new peer(s) from %d peer(s) asked (book %ld -> %ld)\n",
                total, (int)(npeers<max_try?npeers:max_try), before, amr_count(ab));
    else
        fprintf(stderr,"[addr] getaddr: no new peers returned (book %ld)\n", before);
    return total;
}
