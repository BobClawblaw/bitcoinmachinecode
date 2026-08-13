/* live_probe.c -- MANUAL/live diagnostic (NOT in make test). Tests whether a
 * live Bitcoin peer will serve REAL block bodies to this client, using a
 * realistic full-node-style handshake (Satoshi UA, plausible start_height,
 * wtxidrelay/sendaddrv2/feefilter completion) built on the assembly net/p2p
 * codecs. Goal: empirically determine if live-seed block serving is hittable by
 * presenting a full-node-shaped peer, which is the one wall between this node
 * and downloading the real chain.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>

extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd, const char *cmd, unsigned cmdlen, const void *pl, unsigned plen);
extern int  p2p_read(int fd, char cmd_out[12], void *pl, unsigned cap, unsigned *len_out);
extern void fd_close(int fd);
extern long p2p_getheaders(void* out, const void* locator, long count, const void* stop);
extern long p2p_headers_count(const void* payload, long plen);

#define PORT_BE ((unsigned short)htons(8333))
static void put_u16be(unsigned char* p, unsigned v){ p[0]=v>>8; p[1]=v&0xff; }
static void put_u32le(unsigned char* p, unsigned v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void put_u64le(unsigned char* p, unsigned long long v){ for(int i=0;i<8;i++){p[i]=v&0xff; v>>=8;} }

int main(int argc, char**argv){
    setbuf(stdout,NULL);
    const char* dns = argc>1? argv[1] : "seed.bitcoin.sipa.be";
    struct addrinfo hints,*res=0; memset(&hints,0,sizeof hints);
    hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
    if (getaddrinfo(dns,NULL,&hints,&res)!=0){ printf("FAIL getaddrinfo %s\n",dns); return 1; }
    unsigned ip = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    char ipstr[32]; strcpy(ipstr, inet_ntoa(((struct sockaddr_in*)res->ai_addr)->sin_addr));
    freeaddrinfo(res);
    printf("== %s -> %s ==\n", dns, ipstr);
    int fd = tcp_connect_ip(ip, PORT_BE);
    if (fd<0){ printf("FAIL connect fd=%d\n", fd); return 1; }
    printf("PASS connect\n");

    /* realistic version for current protocol (70016) */
    unsigned char v[102]; int o=0;
    put_u32le(v+o,70016); o+=4;
    put_u64le(v+o, 1); o+=8;                                  /* NODE_NETWORK */
    put_u64le(v+o,(unsigned long long)time(NULL)); o+=8;
    put_u64le(v+o,1); o+=8; o+=16;                            /* addr_recv */
    put_u16be(v+o,8333); o+=2;
    put_u64le(v+o,1); o+=8; o+=16;                            /* addr_from */
    put_u16be(v+o,0); o+=2;
    put_u64le(v+o,0x92e9c7d1f03a44bbULL); o+=8;               /* nonce */
    const char* ua="/Satoshi:0.18.0/";
    v[o]=strlen(ua); o+=1; memcpy(v+o,ua,strlen(ua)); o+=strlen(ua);
    put_u32le(v+o, 789000); o+=4;                            /* plausible start_height */
    v[o]=1; o+=1;                                            /* relay */
    if (p2p_write(fd,"version",7,v,o)<=0){ printf("FAIL send version\n"); return 1; }

    /* read until verack, echoing ping->pong and sending protocol-mandated msgs */
    char cmd[12]; static unsigned char rb[4<<20]; unsigned plen=0;
    int got_verack=0;
    for(int i=0;i<40;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen);
        if(r<=0){ printf("  peer closed (handshake)\n"); return 1; }
        cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"sendheaders",11)==0){ p2p_write(fd,"sendheaders",11,"",0); continue; }
        if(strncmp(cmd,"sendaddrv2",10)==0){ p2p_write(fd,"sendaddrv2",10,"",0); continue; }
        if(strncmp(cmd,"wtxidrelay",10)==0){ p2p_write(fd,"wtxidrelay",10,"",0); continue; }
        if(strncmp(cmd,"feefilter",9)==0){ p2p_write(fd,"feefilter",9, "\x00\x00",2); continue; }
        if(strncmp(cmd,"verack",6)==0){ got_verack=1; break; }
    }
    if(!got_verack){ printf("  no verack\n"); fd_close(fd); return 1; }
    /* after verack, send our wtxidrelay + sendaddrv2 (modern nodes expect them) */
    p2p_write(fd,"wtxidrelay",10,"",0);
    p2p_write(fd,"sendaddrv2",10,"",0);
    p2p_write(fd,"verack",6,"",0);
    printf("PASS handshake (verack)\n");

    /* learn tip */
    unsigned char loc[32]; memset(loc,0,32);
    unsigned char stop[32]={0}, gh[128];
    long glen = p2p_getheaders(gh, loc, 1, stop);
    if (p2p_write(fd,"getheaders",10,gh,glen)<=0){ printf("FAIL send getheaders\n"); return 1; }
    long nhdrs=-1; unsigned char hdrs[2000][81]; int got_headers=0;
    for(int i=0;i<80;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen);
        if(r<=0){ printf("  peer closed (waiting headers)\n"); break; }
        cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"sendheaders",11)==0){ p2p_write(fd,"sendheaders",11,"",0); continue; }
        if(strncmp(cmd,"headers",7)==0){
            nhdrs=p2p_headers_count(rb,plen); got_headers=1;
            unsigned char* base=(rb[0]==0xfd)?rb+3:rb+1;
            for(long k=0;k<nhdrs && k<2000;k++) memcpy(hdrs[k],base+k*81,81);
            break;
        }
    }
    if(!got_headers || nhdrs<=0){ printf("  no headers served (nhdrs=%ld)\n", nhdrs); fd_close(fd); return 1; }
    printf("PASS learned %ld headers to real tip\n", nhdrs);

    /* Try to grab the LAST N real block bodies (the head is served most
     * readily). N configurable via argv[2]. */
    int N = argc>2? atoi(argv[2]):3;
    if(N>nhdrs)N=(int)nhdrs;
    extern void sha256d(unsigned char o[32], const void*m, long l);
    static unsigned char gd[1+200*36]; gd[0]=(unsigned char)N; int p=1;
    for(long k=0;k<N;k++){ unsigned char* hdr=hdrs[nhdrs-N+k]; unsigned char hh[32]; sha256d(hh,hdr,80);
        gd[p]=2; gd[p+1]=0; gd[p+2]=0; gd[p+3]=0; p+=4; memcpy(gd+p,hh,32); p+=32; }
    if (p2p_write(fd,"getdata",7,gd,p)<=0){ printf("FAIL send getdata\n"); return 1; }
    printf("sent getdata for %d tip blocks (%d B)\n", N, p);

    long blocks=0, bytes=0;
    for(int i=0;i<200;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen);
        if(r<=0){ printf("  peer closed after %ld blocks\n", blocks); break; }
        cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"block",5)==0 && plen>80){ blocks++; bytes+=plen; if(blocks<=5) printf("  block %ld: %u B\n", blocks, plen); }
        if(strncmp(cmd,"notfound",8)==0){ printf("  notfound\n"); break; }
    }
    printf("RESULT: got %ld real block bodies, %ld bytes\n", blocks, bytes);
    fd_close(fd);
    return blocks>=1?0:1;
}
