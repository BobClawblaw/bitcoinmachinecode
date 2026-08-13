/* live_pow.c -- validates the ASSEMBLY PoW/difficulty stack (diff_target +
 * pow_check) against REAL mainnet chain-work. Manual/live test (not in make
 * test) -- needs a reachable Bitcoin peer.
 *
 * Flow: connect+handshake (asm), getheaders(block 750000 locator) -> real
 * headers for 750001+ carrying REAL nBits. Then, using assembly ONLY:
 *   (a) diff_target must map the real mainnet genesis nBits 0x1d00ffff to the
 *       famous difficulty-1 target 00000000FFFF0000...  (pins the algorithm)
 *   (b) pow_check(real_header) must return 1 for EVERY downloaded real header:
 *       each is a valid mainnet block, so its real hash <= its real target.
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
extern int  pow_check(const void* hdr80);
extern void diff_target(void* out32, unsigned bits);

#define PORT_BE ((unsigned short)htons(8333))

static int failures = 0;
static void cki(const char* lbl, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", lbl, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", lbl, got, exp); failures++; }
}
static void put_u16be(unsigned char* p, unsigned v){ p[0]=v>>8; p[1]=v&0xff; }
static void put_u32le(unsigned char* p, unsigned v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void put_u64le(unsigned char* p, unsigned long long v){ for(int i=0;i<8;i++){p[i]=v&0xff; v>>=8;} }

/* real mainnet block 750000 internal hash (LE) */
static unsigned char locator[32] = {
    0x8e,0xa5,0x76,0x34,0x1b,0xc1,0xc2,0xd5,0x97,0xa0,0xb4,0x8b,0x62,0x77,0xcb,0x87,
    0xf0,0xb9,0xb1,0x74,0xa9,0x92,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

int main(void){
    /* (a) diff_target on real genesis nBits -> difficulty-1 target.
     *     nBits 0x1d00ffff => mantissa 0x00ffff, exponent 0x1d
     *     target = 0x00ffff << (8*(0x1d-3)) = 0x00000000FFFF0000... (be) */
    unsigned char tgt[32]; diff_target(tgt, 0x1d00ffffu);
    unsigned char exp1[32] = {
        0x00,0x00,0x00,0x00,0xff,0xff,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    cki("diff_target(0x1d00ffff)==difficulty-1 target", memcmp(tgt,exp1,32)==0, 1);

    struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if (getaddrinfo("seed.bitcoin.sipa.be",NULL,&h,&res)!=0){ printf("FAIL getaddrinfo\n"); return 1; }
    unsigned ip = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    int fd = tcp_connect_ip(ip, PORT_BE);
    if (fd<0){ printf("FAIL tcp_connect_ip %d\n", fd); return 1; }

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

    char cmd[12]; static unsigned char rbuf[600000]; unsigned plen=0;
    for(int i=0;i<16;i++){
        int r=p2p_read(fd,cmd,rbuf,sizeof(rbuf),&plen); if(r<=0) break;
        cmd[11]=0;
        if(strncmp(cmd,"verack",6)==0) break;
    }
    p2p_write(fd, "verack", 6, "", 0);

    unsigned char stop[32]={0}, gh[128];
    long glen = p2p_getheaders(gh, locator, 1, stop);
    if (p2p_write(fd,"getheaders",10,gh,glen)<=0){ printf("FAIL send getheaders\n"); return 1; }

    int got_headers=0; long hcount=-1;
    for(int i=0;i<64;i++){
        int r=p2p_read(fd,cmd,rbuf,sizeof(rbuf),&plen);
        if(r==0){ printf("  peer closed\n"); break; }
        if(r<0){ continue; }
        cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd, "pong", 4, rbuf, 8); continue; }
        if(strncmp(cmd,"headers",7)==0){ got_headers=1; hcount=p2p_headers_count(rbuf, plen); break; }
    }
    cki("got headers message", got_headers, 1);
    printf("downloaded %ld real headers from live peer\n", hcount);
    if(hcount<=0){ fd_close(fd); printf("\nLIVE POW TEST FAILED (no headers)\n"); return 1; }

    /* (b) assembly pow_check must ACCEPT every real mainnet header (real nBits).
     *     entry base handles 1-byte and 0xfd count varints. */
    unsigned char* base = (rbuf[0]==0xfd) ? rbuf+3 : rbuf+1;
    long bad=0, checked=0;
    for(long k=0;k<hcount;k++){
        unsigned char* h = base + k*81;       /* 80-byte hdr + 1 txcount */
        unsigned bits = *(unsigned*)(h+72);
        if (pow_check(h)!=1){ printf("  REAL header %ld FAILS pow_check (nBits=%08x)\n", k+750001, bits); bad++; }
        checked++;
    }
    cki("pow_check accepts ALL real headers", bad==0, 1);
    printf("checked asm pow_check on %ld real mainnet blocks (real nBits, incl 750001+)\n", checked);

    fd_close(fd);
    printf("\n%s (%d failures)\n", failures?"LIVE POW TEST FAILED":"LIVE POW DOWNLOAD OK", failures);
    return failures?1:0;
}
