/* live_getdata_form.c -- MANUAL/live. Determines the CORRECT Bitcoin getdata
 * inventory encoding by asking a REAL live peer for one block body in each of
 * the two candidate wire forms, then seeing which one it responds to:
 *   A) [count varint=1][type 4-byte int32 LE=2][hash32]  = 37 B, hash at +5
 *   B) [count varint=1][type varint=2][hash32]           = 34 B, hash at +2
 * The project's p2p_oracle (and the Bitcoin protocol) say (A). A prior LOG
 * entry "fixed" p2p_getdata_block to (B) under a mistaken assumption -- this
 * test settles it against the real wire so block bodies (if served at all) are
 * demanded with the encoding real nodes accept.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>

extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int, const char*, unsigned, const void*, unsigned);
extern int  p2p_read(int, char[12], void*, unsigned, unsigned*);
extern long p2p_getheaders(void*, const void*, long, const void*);
extern long p2p_headers_count(const void*, long);
extern void sha256d(unsigned char o[32], const void*m, long l);
extern void fd_close(int fd);

#define PORT_BE ((unsigned short)htons(8333))
static void put_u32le(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64le(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static void put_u16be(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}

/* returns fd on handshake+headers learned; writes first tip header hash to tip40 */
static int connect_learn(const char* dns, unsigned char* tip40){
    struct addrinfo h,*res=0; memset(&h,0,sizeof h);
    h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(dns,NULL,&h,&res)!=0) return -1;
    unsigned ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    int fd=tcp_connect_ip(ip,PORT_BE);
    if(fd<0) return -1;
    unsigned char v[102]; int o=0;
    put_u32le(v+o,70016); o+=4; put_u64le(v+o,1); o+=8;
    put_u64le(v+o,(unsigned long long)time(NULL)); o+=8;
    put_u64le(v+o,1); o+=8; o+=16; put_u16be(v+o,8333); o+=2;
    put_u64le(v+o,1); o+=8; o+=16; put_u16be(v+o,0); o+=2;
    put_u64le(v+o,0x1122334455667788ULL); o+=8;
    const char* ua="/Satoshi:0.18.0/"; v[o]=strlen(ua); o+=1; memcpy(v+o,ua,strlen(ua)); o+=strlen(ua);
    put_u32le(v+o,789000); o+=4; v[o]=1; o+=1;
    if(p2p_write(fd,"version",7,v,o)<=0){ fd_close(fd); return -1; }
    char cmd[12]; static unsigned char rb[1<<20]; unsigned plen=0;
    int va=0;
    for(int i=0;i<40;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0) break; cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"sendheaders",11)==0||strncmp(cmd,"sendaddrv2",10)==0||strncmp(cmd,"wtxidrelay",10)==0){ p2p_write(fd,cmd,strlen(cmd),"",0); continue; }
        if(strncmp(cmd,"verack",6)==0){ va=1; break; }
    }
    if(!va){ fd_close(fd); return -1; }
    p2p_write(fd,"verack",6,"",0); p2p_write(fd,"wtxidrelay",10,"",0); p2p_write(fd,"sendaddrv2",10,"",0);
    unsigned char loc[32], stop[32], gh[128]; memset(loc,0,32); memset(stop,0,32);
    long glen=p2p_getheaders(gh,loc,1,stop);
    if(p2p_write(fd,"getheaders",10,gh,glen)<=0){ fd_close(fd); return -1; }
    long nhdrs=-1;
    for(int i=0;i<60;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0) break; cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"headers",7)==0){ nhdrs=p2p_headers_count(rb,plen); if(nhdrs>0){ unsigned char* b=(rb[0]==0xfd)?rb+3:rb+1; sha256d(tip40,b+(nhdrs-1)*81,80);} break; }
    }
    if(nhdrs<=0){ fd_close(fd); return -1; }
    return fd;
}

int main(int argc,char**argv){
    setbuf(stdout,NULL);
    const char* dns=argc>1?argv[1]:"seed.bitcoin.sipa.be";
    unsigned char tip40[32];
    int fd=connect_learn(dns,tip40);
    if(fd<0){ printf("could not connect/handshake/learn tip\n"); return 2; }
    printf("connected+handshake+tip learned\n");

    /* Form A: canonical [count varint][type int32][hash] = 37B, hash at +5 */
    unsigned char ga[37]; ga[0]=1; put_u32le(ga+1,2); memcpy(ga+5,tip40,32);
    /* Form B: [count varint][type varint][hash] = 34B, hash at +2 */
    unsigned char gb[34]; gb[0]=1; gb[1]=2; memcpy(gb+2,tip40,32);

    char cmd[12]; static unsigned char rb[1<<20]; unsigned plen=0;

    printf("sending FORM A (canonical 37B, hash at +5)...\n");
    p2p_write(fd,"getdata",7,ga,37);
    int gotA=0, closedA=0;
    for(int i=0;i<40;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen);
        if(r<=0){ closedA=1; break; } cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"block",5)==0 && plen>80){ gotA=1; printf("  FORM A got block (%u B)\n",plen); break; }
        if(strncmp(cmd,"notfound",8)==0){ printf("  FORM A notfound (rejected?)\n"); break; }
    }
    printf("FORM A: block=%d closed=%d\n", gotA, closedA);

    /* brief pause, then Form B on the same connection */
    p2p_write(fd,"ping",4,"\x01\x02\x03\x04\x05\x06\x07\x08",8); /* keepalive */
    for(int i=0;i<8;i++){ int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0)break; cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0&&plen==8){ p2p_write(fd,"pong",4,rb,8);} }

    printf("sending FORM B (34B, hash at +2)...\n");
    p2p_write(fd,"getdata",7,gb,34);
    int gotB=0;
    for(int i=0;i<40;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen);
        if(r<=0){ printf("  FORM B connection closed\n"); break; } cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"block",5)==0 && plen>80){ gotB=1; printf("  FORM B got block (%u B)\n",plen); break; }
        if(strncmp(cmd,"notfound",8)==0){ printf("  FORM B notfound\n"); break; }
    }
    printf("FORM B: block=%d\n", gotB);
    fd_close(fd);
    printf("VERDICT: %s\n", (gotA&&!gotB)?"FORM A (37B, hash at +5) is correct":
           (!gotA&&gotB)?"FORM B (34B, hash at +2) is what peers answer":
           "inconclusive (peer policy may block block serving regardless)");
    return 0;
}
