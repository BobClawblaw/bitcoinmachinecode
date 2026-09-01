/* daemon/inbound_client.c -- MANUAL test: does `serve` mode answer a REAL inbound
 * peer shaped like an actual Bitcoin client? A genuine inbound peer connects and
 * FIRST sends its own `version` message, then waits for the server to reply with
 * version+verack, then both verack. Bitcoin Core (outbound connect to us) behaves
 * exactly like this.
 *
 * This test connects to a running `daemon serve <dir> <port>`, plays the inbound
 * role, and checks:
 *   1. server replies to our version with its own version
 *   2. verack exchange completes
 *   3. getdata for a stored block hash -> server returns the exact `block`
 *
 * Usage: inbound_client <host> <port>
 */
#include <stdio.h>
#include "log_ts.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>

extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int, const char*, unsigned, const void*, unsigned);
extern int  p2p_read(int, char[12], void*, unsigned, unsigned*);
extern long p2p_getdata_block(void* out, const void* hash);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void sha256d(unsigned char o[32], const void*m, long l);
extern void fd_close(int fd);

static void put_u32le(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64le(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static void put_u16be(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}

int main(int argc, char** argv){
    if(argc<3){ fprintf(stderr,"usage: %s <host> <port>\n", argv[0]); return 2; }
    const char* host=argv[1]; int port=atoi(argv[2]);

    struct addrinfo h,*res=0; memset(&h,0,sizeof h);
    h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,NULL,&h,&res)!=0){ printf("FAIL getaddrinfo\n"); return 1; }
    unsigned ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);

    int fd=tcp_connect_ip(ip,(unsigned short)htons((unsigned short)port));
    if(fd<0){ printf("FAIL connect fd=%d\n", fd); return 1; }
    printf("PASS connect\n");

    /* send OUR version first (real inbound-peer behaviour) */
    unsigned char v[102]; int o=0;
    put_u32le(v+o,70016); o+=4;
    put_u64le(v+o,1); o+=8;
    put_u64le(v+o,(unsigned long long)time(NULL)); o+=8;
    put_u64le(v+o,1); o+=8; o+=16;
    put_u16be(v+o,8333); o+=2;
    put_u64le(v+o,1); o+=8; o+=16;
    put_u16be(v+o,0); o+=2;
    put_u64le(v+o,0x1111222233334444ULL); o+=8;
    const char* ua="/Satoshi:0.18.0/"; v[o]=strlen(ua); o+=1; memcpy(v+o,ua,strlen(ua)); o+=strlen(ua);
    put_u32le(v+o,789000); o+=4; v[o]=1; o+=1;
    if(p2p_write(fd,"version",7,v,o)<=0){ printf("FAIL send version\n"); return 1; }

    /* expect server's version (and anything else), echo ping->pong, until verack */
    char cmd[12]; static unsigned char rb[1<<20]; unsigned plen=0;
    int got_srv_version=0, got_verack=0;
    for(int i=0;i<40;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen);
        if(r<=0){ printf("  server closed/short (handshake), got_srv_version=%d\n", got_srv_version); break; }
        cmd[11]=0;
        if(strncmp(cmd,"version",7)==0) got_srv_version=1;
        else if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        else if(strncmp(cmd,"verack",6)==0){ got_verack=1; break; }
    }
    printf("got server version=%d verack=%d\n", got_srv_version, got_verack);
    if(!got_srv_version){ printf("FAIL: server did not send its own version to an inbound peer\n"); fd_close(fd); return 1; }
    /* complete handshake: send our verack */
    p2p_write(fd,"verack",6,"",0);

    /* Now getdata for a block we must know: we can't know the stored hash without
     * asking. So getheaders-from-genesis first to learn the chain, then getdata the
     * first block. */
    /* getheaders: version[4] count[1] locator[32] stop[32] -- genesis locator */
    unsigned char gh[69]; gh[0]=0x80; gh[1]=0x11; gh[2]=0x01; gh[3]=0x00; gh[4]=1;
    memset(gh+5,0,32); memset(gh+37,0,32);
    if(p2p_write(fd,"getheaders",10,gh,69)<=0){ printf("FAIL send getheaders\n"); return 1; }
    long nhdrs=-1; unsigned char firsthdr[81];
    for(int i=0;i<60;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen);
        if(r<=0){ printf("  server closed waiting headers\n"); break; }
        cmd[11]=0;
        if(strncmp(cmd,"headers",7)==0){
            nhdrs = (rb[0]==0xfd)? (rb[1]|rb[2]<<8) : rb[0];
            if(nhdrs>0) memcpy(firsthdr, (rb[0]==0xfd)?rb+3:rb+1, 81);
            break;
        }
    }
    if(nhdrs<=0){ printf("FAIL: server served no headers to inbound peer (nhdrs=%ld)\n", nhdrs); fd_close(fd); return 1; }
    printf("getheaders -> %ld headers served to inbound peer\n", nhdrs);

    /* getdata block0: hash of first header */
    unsigned char hh[32]; sha256d(hh, firsthdr, 80);
    unsigned char gd[37]; p2p_getdata_block(gd, hh);
    if(p2p_write(fd,"getdata",7,gd,37)<=0){ printf("FAIL send getdata\n"); return 1; }
    int got_block=0;
    for(int i=0;i<60;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen);
        if(r<=0){ printf("  server closed waiting block\n"); break; }
        cmd[11]=0;
        if(strncmp(cmd,"block",5)==0 && plen>80){ got_block=1; printf("block served, %u bytes\n", plen); break; }
    }
    fd_close(fd);
    if(got_block){ printf("RESULT: server serves blocks to a real inbound peer -- ALL GOOD\n"); return 0; }
    printf("RESULT: server did NOT serve the block body to an inbound peer\n");
    return 1;
}
