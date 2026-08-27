/* live_download.c -- native AArch64 Bitcoin P2P HEADER download proof.
 * Uses ONLY the ported assembly modules (bitcoin_net, bitcoin_p2p,
 * bitcoin_headers, bitcoin_hash) against a REAL Bitcoin peer on the live
 * network: connect -> version/verack -> getheaders(genesis locator) ->
 * parse/verify/store every returned header into headers.dat, paging with
 * successive locators until the peer returns nothing more.
 *
 * Build:
 *   gcc -no-pie -O2 -o live_download live_download.c \
 *       bitcoin_net.o bitcoin_p2p.o bitcoin_headers.o bitcoin_hash.o sha256.o
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>

extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd, const char *cmd, unsigned cmdlen, const void *payload, unsigned plen);
extern int  p2p_read (int fd, char cmd_out[12], void *payload, unsigned cap, unsigned *plen_out);
extern void fd_close(int fd);
extern long p2p_getheaders(void *out, const void *locator, long count, const void *stop);
extern long p2p_headers_count(const void *payload, long plen);
extern int  hst_init(void *hst);
extern long hst_append(void *hst, const void *hdr, const void *hash);
extern void block_hash(void *out, const void *hdr);

static void p16be(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}
static void p32le(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void p64le(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}

int main(int argc, char**argv){
    /* data directory: default ./data (per repo layout), override with
       BITCOIN_DATA_DIR or argv[2]. Created + chdir'd so headers.dat (and
       later the full block store) land there. */
    const char *dd = getenv("BITCOIN_DATA_DIR");
    if (!dd) dd = (argc>2) ? argv[2] : "data";
    mkdir(dd, 0755);
    chdir(dd);

    /* genesis: header used for the first locator. */
    unsigned char genesis[80]; int go=0;
    unsigned char gh_ser[80];  /* full 80-byte genesis header */
    /* version 1, prev=0, merkle=4a5e...a33b (display) reversed */
    p32le(gh_ser+0, 1);
    memset(gh_ser+4,0,32);
    unsigned char mroot[32]={0x4a,0x5e,0x1e,0x4b,0xaa,0xb8,0x9f,0x3a,0x32,0x51,0x8a,0x88,0xc3,0x1b,0xc8,0x7f,0x61,0x8f,0x76,0x67,0x3e,0x2c,0xc7,0x7a,0xb2,0x12,0x7b,0x7a,0xfd,0xed,0xa3,0x3b};
    for(int i=0;i<32;i++) gh_ser[36+i]=mroot[31-i]; /* merkle LE in header */
    p32le(gh_ser+68, 1231006505u);
    p32le(gh_ser+72, 0x1d00ffffu);
    p32le(gh_ser+76, 2083236893u);
    unsigned char genesis_hash[32];
    block_hash(genesis_hash, gh_ser);           /* = 6fe28c0a... digest bytes */

    /* resolve peer */
    unsigned ip=0;
    const char *host = argc>1 ? argv[1] : "seed.bitcoinstats.com";
    if (!(argc>1)) {
        struct addrinfo hints, *res=NULL; memset(&hints,0,sizeof(hints));
        hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
        if (getaddrinfo(host, NULL, &hints, &res)==0 && res){
            ip = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
            printf("resolved %s -> %s\n", host, inet_ntoa(((struct sockaddr_in*)res->ai_addr)->sin_addr));
            freeaddrinfo(res);
        }
    } else {
        struct in_addr a; inet_pton(AF_INET, host, &a); ip=a.s_addr;
    }
    if(!ip){ ip = inet_addr("185.157.161.1"); printf("fallback peer 185.157.161.1\n"); }

    int fd = tcp_connect_ip(ip, (unsigned short)htons(8333));
    if (fd<0){ printf("FAIL connect fd=%d\n", fd); return 1; }
    printf("PASS connect fd=%d\n", fd);

    /* send version */
    unsigned char v[256]; int o=0;
    p32le(v+o,70016); o+=4;
    p64le(v+o,1); o+=8;
    p64le(v+o,(unsigned long long)time(NULL)); o+=8;
    p64le(v+o,1); o+=8; o+=16;
    p16be(v+o,8333); o+=2;
    p64le(v+o,1); o+=8; o+=16;
    p16be(v+o,0); o+=2;
    p64le(v+o,0x1111111111111111ULL); o+=8;
    const char *ua="/Satoshi:0.18.0/"; v[o]=strlen(ua);o++;memcpy(v+o,ua,strlen(ua));o+=strlen(ua);
    p32le(v+o,0); o+=4;
    v[o]=1; o+=1;
    if (p2p_write(fd,"version",7,v,o)<=0){ printf("FAIL send version\n"); return 1; }
    printf("PASS sent version (%d bytes)\n", o);

    /* handshake: read peer version, respond verack, wait for our verack */
    static unsigned char rbuf[220000];
    char cmd[12]; unsigned plen=0;
    int sent_verack=0, got_verack=0;
    for(int i=0;i<20 && !(sent_verack&&got_verack);i++){
        int r = p2p_read(fd, cmd, rbuf, sizeof(rbuf), &plen);
        if (r<=0) { printf("handshake read r=%d (peer closed?)\n", r); break; }
        cmd[11]=0;
        if(strncmp(cmd,"version",7)==0 && !sent_verack){
            if(p2p_write(fd,"verack",6,rbuf,0)<=0) break;
            sent_verack=1;
            printf("  <- version (%u B) -> verack\n", plen);
        } else if(strncmp(cmd,"verack",6)==0){ got_verack=1; printf("  <- verack\n"); }
    }
    if(!sent_verack || !got_verack){ printf("FAIL handshake (sent_verack=%d got_verack=%d)\n",sent_verack,got_verack); fd_close(fd); return 1; }
    printf("PASS handshake\n");

    /* persistent header store */
    unsigned char hst[32]={0};
    if(hst_init(hst)!=1){ printf("FAIL hst_init\n"); return 1; }

    unsigned char loc[32]; memcpy(loc, genesis_hash, 32);
    unsigned char stop[32]={0};
    long total=0;
    unsigned char fetch[256];
    for(int page=0; page<5000; page++){
        long fsz = p2p_getheaders(fetch, loc, 1, stop);
        if (fsz<0){ printf("FAIL getheaders\n"); break; }
        if (p2p_write(fd,"getheaders",10,fetch,fsz)<=0){ printf("FAIL send getheaders\n"); break; }
        /* read messages until we get a headers message */
        int got_headers=0;
        for(int iter=0; iter<32 && !got_headers; iter++){
            int r = p2p_read(fd, cmd, rbuf, sizeof(rbuf), &plen);
            if (r==-2){ printf("truncated read plen=%u\n", plen); break; }
            if (r!=1){ printf("headers read r=%d (done)\n", r); got_headers=-1; break; }
            cmd[11]=0;
            if(strncmp(cmd,"headers",7)==0){ got_headers=1; break; }
            if(strncmp(cmd,"ping",4)==0)   { p2p_write(fd,"pong",4,rbuf,plen); }
            /* ignore sendcmpct/feefilter/inv/addr/wtxidrelay/sendheaders etc. */
        }
        if(got_headers!=1) break;
        /* parse CompactSize count varint */
        long n; int vlen; unsigned char *p=rbuf;
        unsigned long lo=0;
        if(((unsigned long)p[0])<0xfd){ n=p[0]; vlen=1; }
        else if(p[0]==0xfd){ n=p[1] | ((long)p[2]<<8); vlen=3; }
        else if(p[0]==0xfe){ n=p[1]|((long)p[2]<<8)|((long)p[3]<<16)|((long)p[4]<<24); vlen=5; }
        else { n=0; vlen=9; }
        if (n<0 || vlen+ n*81 > plen) { printf("bad headers payload\n"); break; }
        if (n==0){ printf("peer returned 0 headers\n"); break; }
        unsigned char *base = rbuf+vlen;
        for(long k=0;k<n;k++){
            unsigned char *hdr = base + k*81;
            if(hdr[80]!=0){ printf("  header %ld txcount=%u (bad)\n", k, hdr[80]); goto done; }
            unsigned char hh[32];
            block_hash(hh, hdr);
            if (total==0){
                /* page 1 entry0 (the block after genesis): prev must equal genesis */
                if(memcmp(hdr+4, genesis_hash, 32)!=0){ printf("  ERROR: block1 prev != genesis!\n"); goto done; }
                printf("  OK: block 1 chained off genesis (hash 6fe28c0a..)\n");
            } else {
                if(memcmp(hdr+4, loc, 32)!=0){ printf("  ERROR: header %ld prev link broken\n", total); goto done; }
            }
            hst_append(hst, hdr, hh);
            memcpy(loc, hh, 32);
            total++;
        }
        if (page % 20 == 0 || n < 2000) printf("page %d: +%ld (total %ld)\n", page, n, total);
        if (n < 2000) break;          /* peer sent the whole continuing set */
    }
done:
    fd_close(fd);
    printf("\nDOWNLOADED %ld mainnet block headers from a live peer via native AArch64 assembly\n", total);
    printf("deepest block hash: ");
    for(int i=31;i>=0;i--) printf("%02x", loc[i]);
    printf("\n");
    return total>0 ? 0 : 1;
}
