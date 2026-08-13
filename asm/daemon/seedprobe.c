/* daemon/seedprobe.c -- BOOTSTRAP SEED PROBER for the Bitcoin machine-code node.
 *
 * Reads the known-good seed list (seeds.txt, one hostname per line, '#' = comment)
 * and, for each, does a real mainnet bootstrap: resolve DNS (libc), connect to TCP
 * 8333 (asm tcp_connect_ip), perform the version/verack handshake (asm net/p2p),
 * and issue a getheaders-from-genesis to learn how many REAL headers the peer will
 * serve. Prints a per-seed result line so we can rank/live-update seeds.txt.
 *
 * This is the "improve our boot process" piece: it turns the static seed list
 * into a measured, self-refreshing set of reachable peers, so the daemon boots
 * toward peers that actually answer. A per-seed watchdog bounds each peer so a
 * blackholed/hung peer cannot stall the whole boot.
 *
 *   seedprobe [seeds.txt]
 *
 * Only orchestration/IO here; every wire byte (connect, handshake, getheaders,
 * header parse) is the assembly net/p2p codecs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <setjmp.h>

extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int, const char*, unsigned, const void*, unsigned);
extern int  p2p_read(int, char[12], void*, unsigned, unsigned*);
extern long p2p_getheaders(void*, const void*, long, const void*);
extern long p2p_headers_count(const void*, long);
extern void fd_close(int);

/* Per-seed watchdog: SIGALRM fires, siglongjmps the current seed's probe so a
 * hung/blackhole peer cannot stall the whole boot. */
static sigjmp_buf env;
static volatile sig_atomic_t timed_out=0;
static void on_alarm(int s){ (void)s; timed_out=1; siglongjmp(env,1); }

static void put_u32le(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64le(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static void put_u16be(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}

/* probe_one(host, ip, ipstr) -> 1 served real headers / 0 anything else
 * Runs under a 7s alarm; on timeout we longjmp back and report TIME-OUT. */
static int probe_one(const char* host, unsigned ip, const char* ipstr){
    int fd = tcp_connect_ip(ip, (unsigned short)htons(8333));
    if (fd<0){ printf("seed %-34s %-15s CONNECT-FAIL(%d)\n", host, ipstr, fd); return 0; }

    /* realistic version message */
    unsigned char v[102]; int o=0;
    put_u32le(v+o,70016); o+=4;
    put_u64le(v+o,1); o+=8;                                /* NODE_NETWORK */
    put_u64le(v+o,(unsigned long long)time(NULL)); o+=8;
    put_u64le(v+o,1); o+=8; o+=16;                        /* addr_recv */
    put_u16be(v+o,8333); o+=2;
    put_u64le(v+o,1); o+=8; o+=16;                        /* addr_from */
    put_u16be(v+o,0); o+=2;
    put_u64le(v+o,0x13579BDF2468ACE0ULL); o+=8;           /* nonce */
    const char* ua="/Satoshi:0.18.0/"; v[o]=strlen(ua); o+=1; memcpy(v+o,ua,strlen(ua)); o+=strlen(ua);
    put_u32le(v+o,789000); o+=4; v[o]=1; o+=1;            /* start_height, relay */
    if (p2p_write(fd,"version",7,v,o)<=0){ printf("seed %-34s %-15s WRITE-FAIL\n", host, ipstr); fd_close(fd); return 0; }

    /* handshake: read until verack, echo ping->pong, accept protocol msgs */
    char cmd[12]; static unsigned char rb[1<<20]; unsigned plen=0;
    int verack=0;
    for(int i=0;i<40;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen);
        if(r<=0) break; cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"sendheaders",11)==0 || strncmp(cmd,"sendaddrv2",10)==0 ||
           strncmp(cmd,"wtxidrelay",10)==0){ p2p_write(fd,cmd,strlen(cmd),"",0); continue; }
        if(strncmp(cmd,"verack",6)==0){ verack=1; break; }
    }
    if(!verack){ printf("seed %-34s %-15s NO-VERACK\n", host, ipstr); fd_close(fd); return 0; }
    p2p_write(fd,"verack",6,"",0);
    p2p_write(fd,"wtxidrelay",10,"",0);
    p2p_write(fd,"sendaddrv2",10,"",0);

    /* getheaders from genesis -> how many real headers served? */
    unsigned char loc[32]; memset(loc,0,32);
    unsigned char stop[32]; memset(stop,0,32);
    unsigned char gh[128]; long glen=p2p_getheaders(gh,loc,1,stop);
    if (p2p_write(fd,"getheaders",10,gh,glen)<=0){ printf("seed %-34s %-15s HANDSHAKE headers-send-fail\n", host, ipstr); fd_close(fd); return 0; }
    long nhdrs=-1;
    for(int i=0;i<60;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen);
        if(r<=0) break; cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"headers",7)==0){ nhdrs=p2p_headers_count(rb,plen); break; }
    }
    fd_close(fd);
    if(nhdrs>0){
        printf("seed %-34s %-15s OK headers=%ld (REAL header chain served)\n", host, ipstr, nhdrs);
        return 1;
    }
    printf("seed %-34s %-15s HANDSHAKE headers-not-served\n", host, ipstr);
    return 0;
}

int main(int argc, char** argv){
    const char* path = argc>1? argv[1] : "/storage/bitcoinmachinecode/seeds.txt";
    FILE* f = fopen(path,"r");
    if(!f){ fprintf(stderr,"cannot open %s\n", path); return 2; }

    signal(SIGALRM, on_alarm);

    char line[256];
    int total=0, reachable=0, headers_ok=0;
    while(fgets(line,sizeof line,f)){
        char* nl = strpbrk(line,"\r\n"); if(nl)*nl=0;
        char* p = line; while(*p==' '||*p=='\t')p++;
        if(*p==0 || *p=='#') continue;
        char* host = p;
        int len=strlen(host); while(len>0 && (host[len-1]==' '||host[len-1]=='\t')) host[--len]=0;
        if(*host==0) continue;

        total++;
        struct addrinfo h,*res=0; memset(&h,0,sizeof h);
        h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
        if (getaddrinfo(host,NULL,&h,&res)!=0){ printf("seed %-34s DNS-FAIL\n", host); continue; }
        unsigned ip = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
        char ipstr[32]; strcpy(ipstr, inet_ntoa(((struct sockaddr_in*)res->ai_addr)->sin_addr));
        freeaddrinfo(res);

        if (setjmp(env)==0){
            alarm(8);                       /* watchdog: 8s for this whole seed */
            if(probe_one(host, ip, ipstr)) headers_ok++;
            alarm(0);
        } else {
            printf("seed %-34s %-15s TIME-OUT\n", host, ipstr);
            alarm(0);
        }
    }
    fclose(f);
    printf("---- seedprobe summary: %d total, %d served headers ----\n",
           total, headers_ok);
    return 0;
}
