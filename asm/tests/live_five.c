/* live_five.c -- download exactly 5 REAL mainnet blocks from a live peer and
 * store them with the ASM store (store_append -> blk%05u.dat + index.dat), then
 * dump the on-disk layout so we can SEE how the chain "stacks up" in block files.
 *
 * Manual/live test (not in make test). Heavy use of PROVEN asm primitives:
 *   node_handshake (bitcoind.asm), p2p_getheaders/p2p_headers_count (p2p.asm),
 *   sha256d/block_hash (bitcoin_hash.asm), cons_verify (bitcoin_cons.asm),
 *   store_init/store_append (bitcoin_store.asm).
 *
 * Usage: SEED=<host> ./live_five   (default SEED=192.168.5.69)
 * Prints, per stored block: real height, block bytes, and its index record
 * (file_no, data_pos, data_size); then lists the resulting blk*.dat files.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd, const char *cmd, unsigned cmdlen, const void *pl, unsigned plen);
extern int  p2p_read(int fd, char cmd_out[12], void *pl, unsigned cap, unsigned *len_out);
extern void fd_close(int fd);
extern long p2p_getheaders(void* out, const void* locator, long count, const void* stop);
extern long p2p_headers_count(const void* payload, long plen);
extern int  node_handshake(int fd);
extern void sha256d(unsigned char o[32], const void *m, long l);
extern int  cons_verify(const void* block, unsigned long len, void* scratch, unsigned long cap);
extern int  store_init(void* st);
extern long store_append(void* st, const void* hash32, const void* raw, unsigned long long len);
extern int  store_get_at(void* st, unsigned long long height, unsigned long long* out_meta);

#define PORT_BE ((unsigned short)htons(8333))
#define NB 5

static void put_u32le(unsigned char* p, unsigned v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void put_u64le(unsigned char* p, unsigned long long v){ for(int i=0;i<8;i++){p[i]=v&0xff; v>>=8;} }

/* real mainnet block 900000 internal (LE) hash as a getheaders locator */
static unsigned char locator[32] = {
    0x01,0x71,0x8a,0x9a,0x76,0xa9,0x4b,0xa2,0x93,0xea,0x53,0xb7,0x25,0xb2,0x8d,0x59,
    0x2a,0x22,0xd0,0xcc,0x2c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

int main(void){
    int failures=0;
    mkdir("/tmp/fivedl",0777); chdir("/tmp/fivedl");
    unlink("blk00000.dat"); unlink("index.dat");

    struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    const char* host = getenv("SEED")? getenv("SEED") : "192.168.5.69";
    if (getaddrinfo(host,NULL,&h,&res)!=0){ printf("FAIL getaddrinfo %s\n", host); return 1; }
    unsigned ip = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    int fd = tcp_connect_ip(ip, PORT_BE);
    if (fd<0){ printf("FAIL tcp_connect_ip %d\n", fd); return 1; }
    printf("connected to %s, handshaking...\n", host);
    if (node_handshake(fd)!=1){ printf("FAIL node_handshake\n"); fd_close(fd); return 1; }
    printf("handshake OK, learning chain tip...\n");

    /* learn tip headers */
    unsigned char stop[32]={0}, gh[128];
    long glen = p2p_getheaders(gh, locator, 1, stop);
    if (p2p_write(fd,"getheaders",10,gh,glen)<=0){ printf("FAIL getheaders\n"); return 1; }
    char cmd[12]; static unsigned char rbuf[24<<20]; unsigned plen=0;
    static unsigned char hdrs[2000][81]; long nhdrs=0; int got=0;
    for(int i=0;i<64;i++){
        int r=p2p_read(fd,cmd,rbuf,(unsigned)sizeof rbuf,&plen); if(r<=0) break; cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&plen==8){ p2p_write(fd,"pong",4,rbuf,8); continue; }
        if(!strncmp(cmd,"headers",7)){ nhdrs=p2p_headers_count(rbuf,plen);
            unsigned char* base=(rbuf[0]==0xfd)?rbuf+3:rbuf+1;
            for(long k=0;k<nhdrs && k<2000;k++) memcpy(hdrs[k],base+k*81,81);
            got=1; break; }
    }
    if(!got || nhdrs<=0){ printf("FAIL learn headers (%ld)\n", nhdrs); return 1; }
    printf("learned %ld headers ending at height 900000+%ld\n", nhdrs, nhdrs);
    long H = 900000 + (nhdrs - NB);   /* real height of the first of the NB blocks */

    /* getdata for the last NB block hashes */
    static unsigned char gd[1+200*36]; gd[0]=(unsigned char)NB; int p=1;
    static unsigned char hashes[NB][32];
    for(long k=0;k<NB;k++){
        sha256d(hashes[k], hdrs[nhdrs-NB+k], 80);   /* real block hash (LE) */
        gd[p]=2; gd[p+1]=0; gd[p+2]=0; gd[p+3]=0; p+=4;
        memcpy(gd+p, hashes[k], 32); p+=32;
    }
    if (p2p_write(fd,"getdata",7,gd,p)<=0){ printf("FAIL getdata\n"); return 1; }
    printf("requested %d real blocks starting at height %ld\n", NB, H);

    /* receive blocks, validate, store */
    static unsigned char scratch[8<<20];
    static unsigned char st[4096];
    store_init(st);
    long stored=0;
    for(int i=0;i<128;i++){
        int r=p2p_read(fd,cmd,rbuf,(unsigned)sizeof rbuf,&plen); if(r<=0){ printf("  peer closed after %ld\n", stored); break; }
        cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&plen==8){ p2p_write(fd,"pong",4,rbuf,8); continue; }
        if(!strncmp(cmd,"block",5)&&plen>80){
            int ok=cons_verify(rbuf, plen, scratch, (unsigned)(sizeof scratch/32));
            printf("  got real block %u bytes, cons_verify=%d\n", plen, ok);
            if(ok!=1){ printf("    REJECTED real block!\n"); continue; }
            long h = store_append(st, hashes[stored], rbuf, plen);
            if(h<0){ printf("    store_append failed\n"); failures++; }
            else printf("    -> stored at height %ld\n", h);
            stored++;
            if(stored>=NB) break;
        }
        if(!strncmp(cmd,"notfound",8)){ printf("  got notfound\n"); break; }
    }
    printf("\n=== on-disk layout after storing %ld real blocks ===\n", stored);
    printf("index.dat records (height -> file_no, data_pos, data_size):\n");
    for(long k=0;k<stored;k++){
        unsigned long long meta[3];
        int r=store_get_at(st, k, meta);
        printf("  height %ld (real %ld): file_no=%llu data_pos=%llu data_size=%llu (get_at=%d)\n",
               k, H+k, meta[2], meta[0], meta[1], r);
    }
    printf("block files present:\n");
    int cc=0; while(1){
        char nm[64]; snprintf(nm,sizeof nm,"blk%05u.dat",cc);
        struct stat sb; if(stat(nm,&sb)!=0) break;
        printf("  %s : %lld bytes\n", nm, (long long)sb.st_size);
        cc++;
    }
    printf("index.dat : %lld bytes\n", (long long)(({struct stat s; stat("index.dat",&s); s.st_size;})));
    fd_close(fd);
    printf("\n%s (%d failures)\n", failures?"LIVE FIVE FAILED":"LIVE FIVE OK", failures);
    return failures?1:0;
}
