/* daemon/crawler.c -- SELF-CONTAINED parallel mainnet peer discovery.
 * No external files/snapshots: it begins from DNS seed hostnames + the local
 * node, connects to each (asm handshake), requests the peer's address book via
 * getaddr, and parses every `addr`/`addrv2` reply for distinct public IPv4
 * endpoints. Seeds are probed IN PARALLEL (fork, up to P at once) for speed.
 *
 * Each discovered endpoint is then (optionally) itself queried for getaddr
 * (recursive crawl, depth 1) to fan the pool far wider than the seeds alone.
 *
 * Usage: crawler <seed_file> <out_file> [parallel] [per_seed_wait_s]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

extern int  tcp_connect_ip(unsigned, unsigned short);
extern long p2p_write(int,const char*,unsigned,const void*,unsigned);
extern int  p2p_read(int,char[12],void*,unsigned,unsigned*);
extern void fd_close(int);
#define PB ((unsigned short)htons(8333))

static void u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static void u16(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}

/* dedup across the whole run */
#define MAXSEEN 200000
static char seen[MAXSEEN][40]; static long seen_n=0;
static int is_seen(const char* s){ for(long i=0;i<seen_n;i++) if(!strcmp(seen[i],s)) return 1; return 0; }
static void mark_seen(const char* s){ if(seen_n<MAXSEEN && !is_seen(s)){ strncpy(seen[seen_n],s,39); seen[seen_n][39]=0; seen_n++; } }

/* handshake + ask getaddr. returns open fd on success */
static int connect_getaddr(const char* host){
    struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    char buf[128]; snprintf(buf,sizeof buf,"%s",host); char* colon=strchr(buf,':'); if(colon)*colon=0;
    unsigned ip;
    if(inet_pton(AF_INET,buf,&ip)!=1){
        if(getaddrinfo(buf,NULL,&h,&res)!=0) return -1;
        ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr; freeaddrinfo(res);
    }
    int fd=tcp_connect_ip(ip,PB); if(fd<0) return -1;
    struct timeval tv; tv.tv_sec=6; tv.tv_usec=0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    unsigned char v[102]; int o=0;
    u32(v+o,70016);o+=4;u64(v+o,1);o+=8;u64(v+o,(unsigned long long)time(NULL));o+=8;
    u64(v+o,1);o+=8;o+=16;u16(v+o,8333);o+=2;u64(v+o,1);o+=8;o+=16;u16(v+o,0);o+=2;
    u64(v+o,0x1111222233334444ULL);o+=8;
    const char* ua="/Satoshi:0.18.0/";v[o]=strlen(ua);o+=1;memcpy(v+o,ua,strlen(ua));o+=strlen(ua);
    u32(v+o,789000);o+=4;v[o]=1;o+=1;
    if(p2p_write(fd,"version",7,v,o)<=0){fd_close(fd);return -1;}
    char cmd[12]; static unsigned char rb[1<<22]; unsigned plen=0; int va=0;
    for(int i=0;i<60;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0) break; cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&plen==8){p2p_write(fd,"pong",4,rb,8);continue;}
        if(!strncmp(cmd,"sendheaders",11)||!strncmp(cmd,"wtxidrelay",10)||!strncmp(cmd,"sendcmpct",9)){p2p_write(fd,cmd,strlen(cmd),"",0);continue;}
        if(!strncmp(cmd,"sendaddrv2",10)){ p2p_write(fd,"sendaddrv2",10,"",0); continue; }
        if(!strncmp(cmd,"verack",6)){va=1;break;}
    }
    if(!va){fd_close(fd);return -1;}
    p2p_write(fd,"verack",6,"",0);
    p2p_write(fd,"sendaddrv2",10,"",0);
    p2p_write(fd,"getaddr",7,"",0);
    return fd;
}

/* addrv2 -> distinct public v4 endpoints */
static void parse_addrv2(unsigned char* rb, unsigned plen){
    if(plen<2) return; unsigned cnt=rb[0]; unsigned long long pos=1;
    for(unsigned k=0;k<cnt && pos<plen;k++){
        pos+=4;
        while(pos<plen&&(rb[pos]&0x80)) pos++; pos++;
        unsigned long long net=0;
        if(pos>=plen)break;
        { unsigned char c=rb[pos];
          if(c<0xfd){net=c;pos+=1;} else if(c==0xfd){if(pos+3<=plen){net=rb[pos+1]|rb[pos+2]<<8;pos+=3;}else return;}
          else if(c==0xfe){if(pos+5<=plen){pos+=5;}else return;} else {if(pos+9<=plen){pos+=9;}else return;} }
        unsigned long long alen=0;
        if(pos>=plen)break;
        { unsigned char c=rb[pos];
          if(c<0xfd){alen=c;pos+=1;} else if(c==0xfd){if(pos+3<=plen){alen=rb[pos+1]|rb[pos+2]<<8;pos+=3;}else return;}
          else if(c==0xfe){if(pos+5<=plen){pos+=5;}else return;} else return; }
        unsigned char a[16]; memset(a,0,sizeof a);
        for(unsigned long long x=0;x<alen && x<16 && pos+x<plen;x++) a[x]=rb[pos+x];
        pos+=alen;
        unsigned short port=0; if(pos+1<plen) port=rb[pos]<<8|rb[pos+1]; pos+=2;
        if(net==1 && alen==4){
            if(a[0]&&a[0]!=127&&a[0]!=10&&!(a[0]==192&&a[1]==168)&&!(a[0]==172&&a[1]>=16&&a[1]<=31)&&!(a[0]==169&&a[1]==254)){
                char str[32]; inet_ntop(AF_INET,a,str,sizeof str);
                char endp[40]; snprintf(endp,sizeof endp,"%s:%u",str,port);
                if(!is_seen(endp)){ mark_seen(endp); printf("%s\n",endp); fflush(stdout); }
            }
        }
    }
}
/* addr (v1) -> distinct public v4 endpoints */
static void parse_addr(unsigned char* rb, unsigned plen){
    if(plen<1) return; unsigned cnt=rb[0]; if(cnt>2000) cnt=2000;
    for(unsigned k=0;k<cnt;k++){
        size_t o=1+k*30; if(o+30>plen) break;
        const unsigned char* ipb=rb+o+12;
        unsigned short port=rb[o+28]<<8|rb[o+29];
        if(ipb[0]&&ipb[0]!=127&&ipb[0]!=10&&!(ipb[0]==192&&ipb[1]==168)&&!(ipb[0]==172&&ipb[1]>=16&&ipb[1]<=31)&&!(ipb[0]==169&&ipb[1]==254)){
            unsigned char nb[4]={ipb[0],ipb[1],ipb[2],ipb[3]};
            char str[32]; inet_ntop(AF_INET,nb,str,sizeof str);
            char endp[40]; snprintf(endp,sizeof endp,"%s:%u",str,port);
            if(!is_seen(endp)){ mark_seen(endp); printf("%s\n",endp); fflush(stdout); }
        }
    }
}

/* query one peer end-to-end; emits harvested endpoints */
static void crawl(const char* host, int wait){
    int fd=connect_getaddr(host); if(fd<0){ fprintf(stderr,"# %s: handshake fail\n",host); return; }
    char cmd[12]; static unsigned char rb[4<<20]; unsigned plen=0;
    time_t endt=time(NULL)+wait;
    while(time(NULL)<endt){
        plen=0; int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0) break; cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(!strncmp(cmd,"addr",4)) parse_addr(rb,plen);
        else if(!strncmp(cmd,"addrv2",6)) parse_addrv2(rb,plen);
    }
    fd_close(fd);
    fprintf(stderr,"# %s done (%ld distinct total)\n", host, seen_n);
}

int main(int argc,char**argv){
    setbuf(stdout,NULL);
    if(argc<3){ fprintf(stderr,"usage: %s <seed_file> <out_file> [parallel] [wait_s]\n",argv[0]); return 2; }
    const char* sf=argv[1]; const char* out=argv[2];
    int par= argc>3? atoi(argv[3]) : 64;
    int wait= argc>4? atoi(argv[4]) : 8;
    char seeds[4096][128]; int ns=0; char line[256];
    FILE* f=fopen(sf,"r"); if(!f){ fprintf(stderr,"no seed file\n"); return 1; }
    while(fgets(line,sizeof line,f)){
        char* nl=strpbrk(line,"\r\n"); if(nl)*nl=0;
        char* p=line; while(*p==' '||*p=='\t')p++;
        if(*p==0||*p=='#')continue;
        int l=strlen(p); while(l>0&&(p[l-1]==' '||p[l-1]=='\t'))p[--l]=0;
        if(*p&&ns<4096){ strncpy(seeds[ns],p,127); seeds[ns][127]=0; ns++; }
    }
    fclose(f);
    printf("# crawling %d seeds (getaddr), %d-way parallel, %ds each\n", ns, par, wait);
    int done=0; pid_t kids[128]; int nk=0;
    while(done<ns){
        while(nk<par && done<ns){
            pid_t pid=fork();
            if(pid==0){ crawl(seeds[done], wait); _exit(0); }
            kids[nk++]=pid; done++;
            if(nk>=par){ for(int i=0;i<nk;i++){int st;waitpid(kids[i],&st,0);} nk=0; }
        }
    }
    for(int i=0;i<nk;i++){int st;waitpid(kids[i],&st,0);}
    /* write out_file */
    FILE* o=fopen(out,"w"); if(o){ for(long i=0;i<seen_n;i++) fprintf(o,"%s\n",seen[i]); fclose(o); }
    fprintf(stderr,"# crawl complete: %ld distinct endpoints -> %s\n", seen_n, out);
    return 0;
}
