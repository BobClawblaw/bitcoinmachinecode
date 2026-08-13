/* live_headers.c -- uses the ASSEMBLY codecs + networking to download real
 * chain headers from a live Bitcoin peer.  Manual/live test (not in make test).
 *
 * Flow: connect+handshake (asm), build getheaders(locator=genesis) with asm
 * p2p_getheaders, send with asm p2p_write, then read messages with asm
 * p2p_read until a `headers` message arrives, count entries with asm
 * p2p_headers_count, and check the 1st header's prevhash == genesis block hash.
 */
#include <stdio.h>
#include <string.h>
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
extern void block_hash(const void* hdr80, void* out32);

#define PORT_BE ((unsigned short)htons(8333))

/* Block 750,000 (permanently in the chain). Internal (LE) bytes of
 * 0000000000000000000592a974b1b9f087cb77628bb4a097d5c2c11b3476a58e */
static unsigned char locator[32] = {
    0x8e,0xa5,0x76,0x34,0x1b,0xc1,0xc2,0xd5,0x97,0xa0,0xb4,0x8b,0x62,0x77,0xcb,0x87,
    0xf0,0xb9,0xb1,0x74,0xa9,0x92,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

static int failures = 0;
static void cki(const char* lbl, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", lbl, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", lbl, got, exp); failures++; }
}
static void put_u16be(unsigned char* p, unsigned v){ p[0]=v>>8; p[1]=v&0xff; }
static void put_u32le(unsigned char* p, unsigned v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void put_u64le(unsigned char* p, unsigned long long v){ for(int i=0;i<8;i++){p[i]=v&0xff; v>>=8;} }

int main(void){
    struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if (getaddrinfo("seed.bitcoin.sipa.be",NULL,&h,&res)!=0){ printf("FAIL getaddrinfo\n"); return 1; }
    unsigned ip = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    int fd = tcp_connect_ip(ip, PORT_BE);
    if (fd<0){ printf("FAIL tcp_connect_ip %d\n", fd); return 1; }

    /* handshake: send version */
    unsigned char v[102]; int o=0;
    put_u32le(v+o,70016); o+=4;
    put_u64le(v+o,1); o+=8;
    put_u64le(v+o,(unsigned long long)time(NULL)); o+=8;
    put_u64le(v+o,1); o+=8;
    o+=16;
    put_u16be(v+o,8333); o+=2;
    put_u64le(v+o,1); o+=8;
    o+=16;
    put_u16be(v+o,0); o+=2;
    put_u64le(v+o,0x2222222222222222ULL); o+=8;
    const char *ua="/btcasm:0.1/"; v[o]=strlen(ua); o+=1; memcpy(v+o,ua,strlen(ua)); o+=strlen(ua);
    put_u32le(v+o,0); o+=4;
    v[o]=1; o+=1;
    if (p2p_write(fd,"version",7,v,o)<=0){ printf("FAIL send version\n"); return 1; }

    /* read until verack (drain address/support msgs) */
    char cmd[12]; static unsigned char rbuf[600000]; unsigned plen=0;
    for(int i=0;i<16;i++){
        int r=p2p_read(fd,cmd,rbuf,sizeof(rbuf),&plen); if(r<=0) break;
        cmd[11]=0;
        if(strncmp(cmd,"verack",6)==0) break;
    }

    /* complete our side of the handshake: send verack */
    p2p_write(fd, "verack", 6, "", 0);

    /* send getheaders(locator=block 750000) */
    unsigned char stop[32]={0};
    unsigned char gh[128];
    long glen = p2p_getheaders(gh, locator, 1, stop);
    if (p2p_write(fd,"getheaders",10,gh,glen)<=0){ printf("FAIL send getheaders\n"); return 1; }
    printf("sent getheaders (%ld B)\n", glen);

    /* read messages until headers arrives (respond to ping politely) */
    int got_headers=0; long hcount=-1;
    for(int i=0;i<32;i++){
        int r=p2p_read(fd,cmd,rbuf,sizeof(rbuf),&plen);
        if(r==0){ printf("  peer closed\n"); break; }
        if(r<0){ printf("  read err r=%d (len %u)\n", r, plen); continue; }
        cmd[11]=0;
        printf("  got '%s' (%u B)\n", cmd, plen);
        if(strncmp(cmd,"ping",4)==0 && plen==8){
            p2p_write(fd, "pong", 4, rbuf, 8);
            continue;
        }
        if(strncmp(cmd,"headers",7)==0){
            got_headers=1;
            hcount = p2p_headers_count(rbuf, plen);
            if (hcount>0){
                unsigned char* e = (rbuf[0]==0xfd) ? rbuf+3 : rbuf+1;
                /* 1st returned header is block 750001; its prevhash == block 750000 = locator */
                if (memcmp(e+4, locator, 32)==0) cki("1st header prevhash == locator block 750000", 1, 1);
                else cki("1st header prevhash == locator block 750000", 0, 1);
            }
            break;
        }
    }
    cki("got headers message", got_headers, 1);
    cki("headers count > 0", hcount>0, 1);
    printf("downloaded %ld chain headers from live peer\n", hcount);

    fd_close(fd);
    printf("\n%s (%d failures)\n", failures?"LIVE HEADERS TEST FAILED":"LIVE HEADERS DOWNLOAD OK", failures);
    return failures?1:0;
}
