/* fakepeer_headers.c -- deterministic loopback IBD test.  A small C fixture
 * plays a Bitcoin peer on 127.0.0.1; the CLIENT is the 100%-assembly code being
 * proven (bitcoin_net.asm + bitcoin_p2p.asm) through the whole message flow:
 *
 *   tcp_connect_ip -> send version -> read version/verack -> send getheaders
 *   -> read `headers` -> p2p_headers_count -> verify first header's prevhash
 *   chains to the requested locator block 750000.
 *
 * Real framing/checksums/sockets throughout; no network flakiness (loopback).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

/* ---- asm client API ---- */
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd, const char *cmd, unsigned cmdlen, const void *pl, unsigned plen);
extern int  p2p_read(int fd, char cmd_out[12], void *pl, unsigned cap, unsigned *len_out);
extern void fd_close(int fd);
extern long p2p_getheaders(void* out, const void* locator, long count, const void* stop);
extern long p2p_headers_count(const void* payload, long plen);

#define PORT_BE ((unsigned short)htons(8333))

/* Block 750000 hash, internal (LE) bytes. */
static unsigned char locator[32] = {
    0x8e,0xa5,0x76,0x34,0x1b,0xc1,0xc2,0xd5,0x97,0xa0,0xb4,0x8b,0x62,0x77,0xcb,0x87,
    0xf0,0xb9,0xb1,0x74,0xa9,0x92,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }
static void put_u16be(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}
static void put_u32le(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64le(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}

/* A raw 80-byte header built around a given prevhash */
static void mk_header(unsigned char* h, const unsigned char* prev){
    put_u32le(h+0, 0x20000000);            /* version */
    memcpy(h+4, prev, 32);                 /* prevhash */
    memset(h+36, 7, 32);                   /* merkle root (arbitrary) */
    put_u32le(h+68,(unsigned)time(NULL));  /* time */
    put_u32le(h+72, 0x1d00ffff);           /* bits */
    put_u32le(h+76, 0);                    /* nonce */
}

/* ---- fake peer: runs in a forked child. Announces version/verack, then
 * serves one `headers` message containing 2 headers that chain off locator. */
static void serve_peer(int cfd){
    unsigned char rbuf[4096]; char cmd[12]; unsigned plen=0;
    /* read our version, send peer version */
    if (p2p_read(cfd,cmd,rbuf,sizeof(rbuf),&plen)<=0) return;
    unsigned char v[102]; int o=0;
    put_u32le(v+o,70016);o+=4; put_u64le(v+o,9);o+=8; put_u64le(v+o,(unsigned long long)time(NULL));o+=8;
    put_u64le(v+o,1);o+=8; o+=16; put_u16be(v+o,8333);o+=2;
    put_u64le(v+o,1);o+=8; o+=16; put_u16be(v+o,0);o+=2;
    put_u64le(v+o,0x3333333333333333ULL);o+=8; const char*u="/fakepeer:0.1/"; v[o]=strlen(u);o++;memcpy(v+o,u,strlen(u));o+=strlen(u);
    put_u32le(v+o,750000);o+=4; v[o]=1;o++;
    p2p_write(cfd,"version",7,v,o);
    p2p_write(cfd,"verack",6,"",0);
    /* read our verack then our getheaders */
    for(int i=0;i<4;i++){
        if (p2p_read(cfd,cmd,rbuf,sizeof(rbuf),&plen)<=0) break;
        cmd[11]=0;
        if (strncmp(cmd,"getheaders",10)==0){
            /* two header entries; entry[0] chains off the locator (verified),
               entry[1] chains off entry[0] (unchecked) */
            unsigned char hdr[2][80];
            mk_header(hdr[0], locator);
            mk_header(hdr[1], hdr[0]+4);
            unsigned char msg[1+2*81];
            msg[0]=2;
            memcpy(msg+1, hdr[0], 80); memset(msg+1+80,0,1);
            memcpy(msg+1+81, hdr[1], 80); memset(msg+1+81+80,0,1);
            p2p_write(cfd,"headers",7,msg,2*81+1);
            break;
        }
    }
}

int main(void){
    /* listening socket on loopback, ephemeral port */
    int ls = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (bind(ls,(struct sockaddr*)&a,sizeof a)!=0){ printf("FAIL bind\n"); return 1; }
    socklen_t alen=sizeof a; getsockname(ls,(struct sockaddr*)&a,&alen);
    listen(ls,1);
    unsigned short port = ntohs(a.sin_port);

    pid_t pid = fork();
    if (pid==0){
        int cfd = accept(ls,0,0);
        serve_peer(cfd);
        _exit(0);
    }

    /* asm client connects to loopback:port */
    unsigned ip = htonl(INADDR_LOOPBACK);
    int fd = tcp_connect_ip(ip, htons(port));
    cki("tcp_connect_ip loopback", fd>=0, 1);
    if (fd<0) return 1;

    /* send version (asm framing) */
    unsigned char v[102]; int o=0;
    put_u32le(v+o,70016);o+=4; put_u64le(v+o,9);o+=8; put_u64le(v+o,(unsigned long long)time(NULL));o+=8;
    put_u64le(v+o,1);o+=8; o+=16; put_u16be(v+o,8333);o+=2;
    put_u64le(v+o,1);o+=8; o+=16; put_u16be(v+o,0);o+=2;
    put_u64le(v+o,0x4444444444444444ULL);o+=8; const char*ua="/btcasm:0.1/";v[o]=strlen(ua);o++;memcpy(v+o,ua,strlen(ua));o+=strlen(ua);
    put_u32le(v+o,0);o+=4; v[o]=1;o++;
    cki("send version", p2p_write(fd,"version",7,v,o)>0, 1);

    /* read peer version + verack */
    char cmd[12]; static unsigned char rbuf[4096]; unsigned plen=0;
    int gotv=0, gotva=0;
    for(int i=0;i<8;i++){
        int r=p2p_read(fd,cmd,rbuf,sizeof(rbuf),&plen); if(r<=0) break;
        cmd[11]=0;
        if(strncmp(cmd,"version",7)==0) gotv=1;
        if(strncmp(cmd,"verack",6)==0) { gotva=1; break; }
    }
    cki("got peer version", gotv, 1);
    cki("got peer verack", gotva, 1);

    /* send our verack + getheaders(locator=750000) */
    p2p_write(fd,"verack",6,"",0);
    unsigned char stop[32]={0}, gh[128];
    long glen=p2p_getheaders(gh,locator,1,stop);
    cki("getheaders len", glen, 69);
    cki("send getheaders", p2p_write(fd,"getheaders",10,gh,glen)>0, 1);

    /* read headers */
    int gotH=0; long hc=-1;
    for(int i=0;i<8;i++){
        int r=p2p_read(fd,cmd,rbuf,sizeof(rbuf),&plen); if(r<=0) break;
        cmd[11]=0;
        if(strncmp(cmd,"headers",7)==0){
            gotH=1; hc=p2p_headers_count(rbuf,plen);
            if(hc>0){
                unsigned char* e=(rbuf[0]==0xfd)?rbuf+3:rbuf+1;
                cki("1st header prevhash == locator 750000", memcmp(e+4,locator,32)==0, 1);
            }
            break;
        }
    }
    cki("got headers message", gotH, 1);
    cki("headers count == 2", hc, 2);

    fd_close(fd);
    waitpid(pid,0,0);
    close(ls);
    printf("\n%s (%d failures)\n", failures?"TEST FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
