/* daemon/discover.c -- actively SEARCH for mainnet peers upon connecting.
 *
 * Connects to each seed, performs the version/verack handshake with sendaddrv2,
 * then actively requests the peer's address book via `getaddr` and collects the
 * `addr` / `addrv2` responses (as well as passively received addrs). Aggregates
 * distinct IPv4 host:port endpoints to stdout (one per line) for use as download
 * peers. This is the standard Bitcoin peer-discovery flow (getaddr).
 *
 * Usage: discover <peers.txt> [per-seed-wait-sec] [verbose]
 */
#include <stdio.h>
#include "log_ts.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

extern int  tcp_connect_ip(unsigned, unsigned short);
extern long p2p_write(int,const char*,unsigned,const void*,unsigned);
extern int  p2p_read(int,char[12],void*,unsigned,unsigned*);
extern void fd_close(int);
#define PB ((unsigned short)htons(8333))
static void u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static void u16(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}

/* keep a dedup bitmap of seen ip:port (~4GB ipv4 space -> too big; use a simple
 * table of last 64k seen endpoints) */
static char seen[65536][24]; static int seen_n=0;
static int is_seen(const char* s){ for(int i=0;i<seen_n;i++) if(!strcmp(seen[i],s)) return 1; return 0; }
static void mark_seen(const char* s){ if(seen_n<65536 && !is_seen(s)){ strncpy(seen[seen_n],s,23); seen[seen_n][23]=0; seen_n++; } }

static int connect_handshake(const char* host, int verbose){
    struct addrinfo h,*res=0; memset(&h,0,sizeof h);
    h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    unsigned ip;
    if(inet_pton(AF_INET,host,&ip)==1) goto gotip;
    if(getaddrinfo(host,NULL,&h,&res)!=0) return -1;
    ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
gotip:
    int fd=tcp_connect_ip(ip,PB); if(fd<0) return -1;
    struct timeval tv; tv.tv_sec=4; tv.tv_usec=0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    unsigned char v[102]; int o=0;
    u32(v+o,70016);o+=4;u64(v+o,1);o+=8;u64(v+o,(unsigned long long)time(NULL));o+=8;
    u64(v+o,1);o+=8;o+=16;u16(v+o,8333);o+=2;u64(v+o,1);o+=8;o+=16;u16(v+o,0);o+=2;
    u64(v+o,0xF00D ^ (unsigned long long)time(NULL));o+=8;
    const char* ua="/Satoshi:0.18.0/";v[o]=strlen(ua);o+=1;memcpy(v+o,ua,strlen(ua));o+=strlen(ua);
    u32(v+o,789000);o+=4;v[o]=1;o+=1;
    if(p2p_write(fd,"version",7,v,o)<=0){fd_close(fd);return -1;}
    char cmd[12]; static unsigned char rb[1<<22]; unsigned plen=0; int va=0;
    for(int i=0;i<40;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0) break; cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&plen==8){p2p_write(fd,"pong",4,rb,8);continue;}
        if(!strncmp(cmd,"sendheaders",11)||!strncmp(cmd,"wtxidrelay",10)||!strncmp(cmd,"sendcmpct",9)){p2p_write(fd,cmd,strlen(cmd),"",0);continue;}
        if(!strncmp(cmd,"sendaddrv2",10)){ p2p_write(fd,"sendaddrv2",10,"",0); continue; }
        if(!strncmp(cmd,"verack",6)){va=1;break;}
    }
    if(!va){fd_close(fd);return -1;}
    p2p_write(fd,"verack",6,"",0);
    p2p_write(fd,"sendaddrv2",10,"",0);
    p2p_write(fd,"getaddr",7,"",0);     /* actively request the address book */
    return fd;
}

/* addrv2 payload parser -> prints distinct v4 endpoints; returns count printed */
static void parse_addrv2(unsigned char* rb, unsigned plen, int verbose){
    if(plen<2) return;
    unsigned cnt=rb[0];
    unsigned long long pos=1;
    for(unsigned k=0;k<cnt && pos<plen;k++){
        pos+=4;                    /* time */
        while(pos<plen&&(rb[pos]&0x80)) pos++; pos++;  /* services varint */
        /* net varint */
        unsigned long long net=0;
        if(pos>=plen)break;
        { unsigned char c=rb[pos];
          if(c<0xfd){net=c;pos+=1;}
          else if(c==0xfd){if(pos+3<=plen){net=rb[pos+1]|rb[pos+2]<<8;pos+=3;}else return;}
          else if(c==0xfe){if(pos+5<=plen){net=(unsigned long long)rb[pos+1]|(unsigned long long)rb[pos+2]<<8|(unsigned long long)rb[pos+3]<<16|(unsigned long long)rb[pos+4]<<24;pos+=5;}else return;}
          else { if(pos+9<=plen){pos+=9;} else return; }
        }
        /* addrlen varint */
        unsigned long long alen=0;
        if(pos>=plen)break;
        { unsigned char c=rb[pos];
          if(c<0xfd){alen=c;pos+=1;}
          else if(c==0xfd){if(pos+3<=plen){alen=rb[pos+1]|rb[pos+2]<<8;pos+=3;}else return;}
          else if(c==0xfe){if(pos+5<=plen){alen=(unsigned long long)rb[pos+1]|(unsigned long long)rb[pos+2]<<8|(unsigned long long)rb[pos+3]<<16|(unsigned long long)rb[pos+4]<<24;pos+=5;}else return;}
          else return;
        }
        unsigned char a[32]; memset(a,0,sizeof a);
        for(unsigned long long x=0;x<alen && pos+x<plen;x++) a[x]=rb[pos+x];
        pos+=alen;
        unsigned short port=0;
        if(pos+1<plen) port=rb[pos]<<8|rb[pos+1]; pos+=2;
        if(net==1 && alen==4){   /* IPv4 */
            if(a[0]&&a[0]!=127&&a[0]!=10&&!(a[0]==192&&a[1]==168)&&
               !(a[0]==172&&a[1]>=16&&a[1]<=31)&&!(a[0]==169&&a[1]==254)){
                unsigned char nb[4]={a[0],a[1],a[2],a[3]};
                char str[32]; inet_ntop(AF_INET,nb,str,sizeof str);
                char endp[64]; snprintf(endp,sizeof endp,"%s:%u",str,port);
                if(!is_seen(endp)){ mark_seen(endp); printf("%s\n",endp); fflush(stdout); }
            } else if(verbose){ printf("#   (skip reserved v4 %d.%d.%d.%d)\n",a[0],a[1],a[2],a[3]); }
        }
    }
}

/* addr (v1) payload parser: count varint, then 30B each: time u32, svc u64, ip16, port u16 BE */
static void parse_addr(unsigned char* rb, unsigned plen, int verbose){
    if(plen<1) return;
    unsigned cnt=rb[0]; if(cnt>2000) cnt=2000;
    for(unsigned k=0;k<cnt;k++){
        size_t o=1+k*30; if(o+30>plen) break;
        const unsigned char* ipb=rb+o+12;       /* ip at +12 (after time4+svc8) */
        unsigned short port=rb[o+28]<<8|rb[o+29];
        if(ipb[0]&&ipb[0]!=127&&ipb[0]!=10&&!(ipb[0]==192&&ipb[1]==168)&&
           !(ipb[0]==172&&ipb[1]>=16&&ipb[1]<=31)&&!(ipb[0]==169&&ipb[1]==254)){
            unsigned char nb[4]={ipb[0],ipb[1],ipb[2],ipb[3]};
            char str[32]; inet_ntop(AF_INET,nb,str,sizeof str);
            char endp[64]; snprintf(endp,sizeof endp,"%s:%u",str,port);
            if(!is_seen(endp)){ mark_seen(endp); printf("%s\n",endp); fflush(stdout); }
        } else if(verbose){ printf("#   (skip reserved)\n"); }
    }
}

int main(int argc,char**argv){
    setbuf(stdout,NULL);
    const char* sf=argc>1?argv[1]:"/storage/bitcoinmachinecode/seeds.txt";
    int wait=argc>2?atoi(argv[2]):12;
    int verbose=argc>3;
    FILE* f=fopen(sf,"r"); if(!f){fprintf(stderr,"no seeds file\n");return 1;}
    char seeds[80][128]; int ns=0; char line[256];
    while(fgets(line,sizeof line,f)){
        char* nl=strpbrk(line,"\r\n"); if(nl)*nl=0;
        char* p=line; while(*p==' '||*p=='\t')p++;
        if(*p==0||*p=='#')continue;
        int l=strlen(p); while(l>0&&(p[l-1]==' '||p[l-1]=='\t'))p[--l]=0;
        if(*p&&ns<80){strncpy(seeds[ns],p,127);seeds[ns][127]=0;ns++;}
    }
    fclose(f);
    printf("# discovering peers via %d seeds (getaddr + addr/addr2), %ds each\n", ns, wait);
    for(int s=0;s<ns;s++){
        int fd=connect_handshake(seeds[s], verbose);
        if(fd<0){ printf("# %s: no handshake\n", seeds[s]); continue; }
        if(verbose) printf("# %s: connected+getaddr sent\n", seeds[s]);
        char cmd[12]; static unsigned char rb[1<<22]; unsigned plen=0;
        time_t endt=time(NULL)+wait;
        while(time(NULL)<endt){
            plen=0;
            int r=p2p_read(fd,cmd,rb,sizeof rb,&plen);
            if(r<=0) break;                 /* timeout/eof */
            cmd[11]=0;
            if(!strncmp(cmd,"ping",4)&&plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
            if(!strncmp(cmd,"addr",4)){ parse_addr(rb,plen,verbose); }
            else if(!strncmp(cmd,"addrv2",6)){ parse_addrv2(rb,plen,verbose); }
            else if(verbose){ printf("#   msg %s (%u B)\n",cmd,plen); }
        }
        fd_close(fd);
        printf("# %s done (%d distinct so far)\n", seeds[s], seen_n);
    }
    printf("# discovery complete: %d distinct endpoints\n", seen_n);
    return 0;
}
