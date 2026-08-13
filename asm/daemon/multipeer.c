/* multipeer.c -- DISTRIBUTED download: fork up to N peers, each running the
 * ASM per-peer download loop (node_drain) against a real mainnet seed, all
 * writing into ONE shared on-disk store. Resolve seeds, connect+handshake (asm
 * net/p2p), then run node_drain in each child. This C file is only orchestration
 * (resolve DNS, fork, print); every byte moved + validated is asm.
 * Usage: multipeer <num_peers> <storedir>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int,const char*,unsigned,const void*,unsigned);
extern int  p2p_read(int,char[12],void*,unsigned,unsigned*);
extern long node_drain(int fd, void* st, void* buf, long buflen);

static const char* seeds[] = {
  "seed.bitcoin.sipa.be",
  "dnsseed.bluematt.me",
  "seed.bitcoinstats.com",
  "seed.bitcoin.jonasschnelli.ch",
  "seed.btc.petertodd.net",
  "seed.bitcharcoal.com",
  "seed.bitcoin.wiz.biz",
  "seed.bitcoin.sprovoost.nl"
};

static void put_u32le(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64le(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static void put_u16be(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}

static int connect_and_handshake(const char* host, int* fd_out){
    struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if (getaddrinfo(host,NULL,&h,&res)!=0) return -1;
    unsigned ip = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    int fd = tcp_connect_ip(ip, (unsigned short)htons(8333));   /* mainnet p2p port */
    if (fd<0) return -1;
    unsigned char v[102]; int o=0;
    put_u32le(v+o,70016); o+=4; put_u64le(v+o,1); o+=8;
    put_u64le(v+o,(unsigned long long)time(NULL)); o+=8; put_u64le(v+o,1); o+=8; o+=16;
    put_u16be(v+o,8333); o+=2; put_u64le(v+o,1); o+=8; o+=16;
    put_u16be(v+o,0); o+=2; put_u64le(v+o,0x2222222222222222ULL); o+=8;
    const char* ua="/btcasm:0.1/"; v[o]=strlen(ua); o+=1; memcpy(v+o,ua,strlen(ua)); o+=strlen(ua);
    put_u32le(v+o,0); o+=4; v[o]=1; o+=1;
    if (p2p_write(fd,"version",7,v,o)<=0){ close(fd); return -1; }
    char cmd[12]; static unsigned char rbuf[1<<20]; unsigned plen=0;
    for(int i=0;i<16;i++){ int r=p2p_read(fd,cmd,rbuf,sizeof rbuf,&plen); if(r<=0) break; cmd[11]=0; if(strncmp(cmd,"verack",6)==0) break; }
    p2p_write(fd,"verack",6,"",0);
    *fd_out = fd; return 0;
}

static long run_child(const char* host, const char* dir, int idx){
    if (chdir(dir)!=0){ return -2; }
    int fd=-1;
    if (connect_and_handshake(host, &fd)!=0){ printf("[p%d] %-28s connect/handshake fail\n", idx, host); fflush(stdout); return 0; }
    printf("[p%d] %-28s connected\n", idx, host); fflush(stdout);
    static unsigned char store[4096]; static unsigned char bigbuf[4<<20];
    extern long store_init(void*); extern long store_reload(void*);
    store_init(store); store_reload(store);
    long n = node_drain(fd, store, bigbuf, sizeof bigbuf);
    printf("[p%d] %-28s drain done, blocks stored by this child: %ld\n", idx, host, n);
    fflush(stdout);
    return n;
}

int main(int argc,char**argv){
    int np = argc>1? atoi(argv[1]) : 4; if(np>8) np=8; if(np<1) np=1;
    const char* dir = argc>2? argv[2] : "/tmp/multi";
    mkdir(dir,0755);
    extern long store_init(void*);
    static unsigned char store[4096]; if(chdir(dir)!=0){perror("chdir");return 1;} store_init(store);
    time_t t0=time(NULL);
    printf("starting DISTRIBUTED download: %d peers -> store %s\n", np, dir); fflush(stdout);
    pid_t kids[8];
    for(int i=0;i<np;i++){ kids[i]=fork(); if(kids[i]==0){ long n=run_child(seeds[i], dir, i); _exit(n>=0?0:1); } sleep(1); }
    int rc=0;
    for(int i=0;i<np;i++){ int st; waitpid(kids[i],&st,0); if(!WIFEXITED(st)||WEXITSTATUS(st)!=0)rc=1; }
    printf("distributed download done after %lds (rc=%d in %s)\n", (long)(time(NULL)-t0), rc, dir);
    return rc;
}
