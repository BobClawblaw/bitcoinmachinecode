/* live_blocks.c -- validates the ASSEMBLY full-block validator (cons_verify)
 * against REAL mainnet block BODIES served by a live peer. Manual/live test
 * (not in make test).
 *
 * Flow: connect+handshake (asm) -> getheaders(block 750000 locator) to learn
 * the real chain tip -> getdata for a handful of the most recent real blocks
 * (full nodes serve the tip readily; they tend to drop requests for ancient
 * blocks) -> for each real block run assembly cons_verify and require it
 * return 1 (real PoW, real merkle root, real tx structure, tx-count field).
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
extern int  cons_verify(const void* block, unsigned long len, void* scratch, unsigned long cap);

#define PORT_BE ((unsigned short)htons(8333))

static int failures = 0;
static void cki(const char* lbl, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", lbl, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", lbl, got, exp); failures++; }
}
static void put_u16be(unsigned char* p, unsigned v){ p[0]=v>>8; p[1]=v&0xff; }
static void put_u32le(unsigned char* p, unsigned v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void put_u64le(unsigned char* p, unsigned long long v){ for(int i=0;i<8;i++){p[i]=v&0xff; v>>=8;} }

/* real mainnet block 750000 internal hash (LE) as getheaders locator */
static unsigned char locator[32] = {
    0x8e,0xa5,0x76,0x34,0x1b,0xc1,0xc2,0xd5,0x97,0xa0,0xb4,0x8b,0x62,0x77,0xcb,0x87,
    0xf0,0xb9,0xb1,0x74,0xa9,0x92,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

static unsigned char hdrs[2000][81];
static long nhdrs=0;

int main(void){
    struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    const char* host = getenv("SEED")? getenv("SEED") : "seed.bitcoin.sipa.be";
    if (getaddrinfo(host,NULL,&h,&res)!=0){ printf("FAIL getaddrinfo %s\n", host); return 1; }
    unsigned ip = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    int fd = tcp_connect_ip(ip, PORT_BE);
    if (fd<0){ printf("FAIL tcp_connect_ip %d\n", fd); return 1; }

    unsigned char v[102]; int o=0;
    put_u32le(v+o,70016); o+=4; put_u64le(v+o,1); o+=8;
    put_u64le(v+o,(unsigned long long)time(NULL)); o+=8; put_u64le(v+o,1); o+=8; o+=16;
    put_u16be(v+o,8333); o+=2; put_u64le(v+o,1); o+=8; o+=16;
    put_u16be(v+o,0); o+=2; put_u64le(v+o,0x2222222222222222ULL); o+=8;
    const char *ua="/btcasm:0.1/"; v[o]=strlen(ua); o+=1; memcpy(v+o,ua,strlen(ua)); o+=strlen(ua);
    put_u32le(v+o,0); o+=4; v[o]=1; o+=1;
    if (p2p_write(fd,"version",7,v,o)<=0){ printf("FAIL send version\n"); return 1; }

    char cmd[12]; static unsigned char rbuf[4<<20]; unsigned plen=0;
    for(int i=0;i<16;i++){ int r=p2p_read(fd,cmd,rbuf,(unsigned)sizeof rbuf,&plen); if(r<=0) break; cmd[11]=0; if(strncmp(cmd,"verack",6)==0) break; }
    p2p_write(fd, "verack", 6, "", 0);

    /* learn the real tip via getheaders */
    unsigned char stop[32]={0}, gh[128];
    long glen = p2p_getheaders(gh, locator, 1, stop);
    if (p2p_write(fd,"getheaders",10,gh,glen)<=0){ printf("FAIL send getheaders\n"); return 1; }
    int got_headers=0;
    for(int i=0;i<64;i++){
        int r=p2p_read(fd,cmd,rbuf,(unsigned)sizeof rbuf,&plen);
        if(r==0){ printf("  peer closed\n"); break; }
        if(r<0){ continue; }
        cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rbuf,8); continue; }
        if(strncmp(cmd,"headers",7)==0){ got_headers=1; nhdrs=p2p_headers_count(rbuf,plen);
            unsigned char* base=(rbuf[0]==0xfd)?rbuf+3:rbuf+1;
            for(long k=0;k<nhdrs && k<2000;k++) memcpy(hdrs[k],base+k*81,81);
            break; }
    }
    cki("got tip headers", got_headers, 1);
    printf("learned %ld real chain headers\n", nhdrs);
    if(nhdrs<=0){ fd_close(fd); printf("\nLIVE BLOCK TEST FAILED (no headers)\n"); return 1; }

    /* the LAST returned header is the chain tip (or as close as the peer gave).
     * Request the 3 blocks just before the tip (full nodes serve these). */
    long N= 1;    /* just the tip -- peers serve the head most readily */
    printf("requesting %ld real block ending at height 750000+%ld\n", N, nhdrs);
    /* build a getdata with N inventory entries: count varint + N*(type=2 + 32B hash).
     * The entries' hashes are the block hashes of hdrs[nhdrs-N .. nhdrs-1]; we do
     * not have them directly, so request by the header hash instead (server maps
     * header hash -> block). Use asm-free: compute block hash by sha256d of the
     * 80-byte header (double sha256), which is exactly block_hash. */
    extern void sha256d(unsigned char o[32], const void*m, long l);
    static unsigned char gd[1 + 200*36];   /* count varint + N*(int32 type + hash32) */
    gd[0]=(unsigned char)N;                     /* count (N<=200) 1-byte varint */
    int p=1;
    for(long k=0;k<N;k++){
        unsigned char* hdr = hdrs[nhdrs-N+k];   /* last N headers */
        unsigned char hh[32]; sha256d(hh, hdr, 80);   /* real block hash (LE) */
        gd[p]=2; gd[p+1]=0; gd[p+2]=0; gd[p+3]=0; p+=4;   /* MSG_BLOCK type int32 LE */
        memcpy(gd+p, hh, 32); p+=32;
    }
    if (p2p_write(fd,"getdata",7,gd,p)<=0){ printf("FAIL send getdata\n"); return 1; }
    printf("sent getdata (%d B)\n", p);

    /* receive `block` messages; run asm cons_verify on each. */
    long verified=0, blocks_seen=0;
    for(int i=0;i<64;i++){
        int r=p2p_read(fd,cmd,rbuf,(unsigned)sizeof rbuf,&plen);
        if(r==0){ printf("  peer closed after %ld blocks\n", verified); break; }
        if(r<0){ continue; }
        cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rbuf,8); continue; }
        if(strncmp(cmd,"block",5)==0 && plen>80){
            blocks_seen++;
            static unsigned char scratch[64*2000];
            int ok = cons_verify(rbuf, plen, scratch, 2000);
            printf("  real block %u bytes: cons_verify=%d\n", plen, ok);
            if(ok==1) verified++; else { printf("    REJECTED (real block!)\n"); failures++; }
        }
        if(strncmp(cmd,"notfound",8)==0){ printf("  got notfound\n"); break; }
    }
    cki("received >=1 real block body", blocks_seen>=1, 1);
    cki("every real block cons_verify==1", verified==blocks_seen && blocks_seen>=1, 1);
    printf("asm cons_verify accepted %ld/%ld real mainnet block bodies\n", verified, blocks_seen);

    fd_close(fd);
    printf("\n%s (%d failures)\n", failures?"LIVE BLOCK TEST FAILED":"LIVE BLOCK IBD OK", failures);
    return failures?1:0;
}
