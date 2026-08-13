/* daemon/addrgather.c -- full-client peer DISCOVERY using the ASM address
 * manager. Connects to seed/local peers, handshakes, sends `getaddr`, parses
 * every `addr`/`addrv2` reply with the asm codecs, and adds each distinct
 * public IPv4 endpoint into the persisted peers.dat address book. Rerunning
 * grows the book across runs -- true recursive peer discovery, no external
 * snapshots.
 *
 * addr v1 wire record: [time u32][services u64][ip16 (v4@12..15)][port u16 BE]
 * addrv2 record:       [time u32][services varint][net varint][len varint][ip][port]
 *
 * Usage: addrgather <seed_file> [parallel] [per_seed_wait_s]
 *   appends discovered peers to ./peers.dat
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
extern int  amr_init(void* ab);
extern int  amr_add  (void* ab, unsigned ip, unsigned short port, unsigned long long svc, unsigned lastseen);
extern long amr_count(void* ab);
extern long p2p_addr_count(const void* pl, long plen);
#define PB ((unsigned short)htons(8333))

static void u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static void u16(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}

static unsigned char ab[4096];

static int is_public_v4(const unsigned char*a){
    if(!a[0]) return 0;                 /* 0.0.0.0 */
    if(a[0]==127||a[0]==10) return 0;
    if(a[0]==192&&a[1]==168) return 0;
    if(a[0]==172&&a[1]>=16&&a[1]<=31) return 0;
    if(a[0]==169&&a[1]==254) return 0;
    return 1;
}

/* parse a v1 addr payload and fold every distinct public v4 into the book */
static void ingest_addr1(const unsigned char* pl, long plen){
    long cnt = p2p_addr_count(pl, plen); if(cnt<=0) return;
    long base = (pl[0]<0xfd)?1:(pl[0]==0xfd?3:(pl[0]==0xfe?5:9));
    for(long k=0;k<cnt;k++){
        const unsigned char* r = pl + base + k*30;
        if(base+k*30+30>plen) break;
        /* v4 is in the last 4 bytes (12..15) of the 16-byte ip field; some
         * peers put it at 0..3, so accept either local form. */
        const unsigned char* ipb = r+12;
        if(!is_public_v4(ipb)) ipb = r;               /* try the 0..3 form */
        if(!is_public_v4(ipb)) continue;
        unsigned short port = (r[28]<<8)|r[29];      /* BE */
        unsigned last = (unsigned)time(NULL);
        unsigned long long svc = (unsigned long long)r[4] | (unsigned long long)r[5]<<8 |
            (unsigned long long)r[6]<<16 |(unsigned long long)r[7]<<24 | (unsigned long long)r[8]<<32 |
            (unsigned long long)r[9]<<40 |(unsigned long long)r[10]<<48 |(unsigned long long)r[11]<<56;
        unsigned ip = (unsigned)ipb[0]|(unsigned)ipb[1]<<8|(unsigned)ipb[2]<<16|(unsigned)ipb[3]<<24;
        amr_add(ab, ip, port, svc, last);
    }
}

/* parse an addrv2 payload and fold distinct public v4 into the book */
static void ingest_addrv2(const unsigned char* pl, long plen){
    if(plen<2) return;
    unsigned cnt=pl[0]; unsigned long long pos=1;
    for(unsigned k=0;k<cnt && pos+30<plen;k++){
        unsigned long long time;
        { unsigned long long t=0; for(int x=0;x<4 && pos<plen;x++){ t|= (unsigned long long)pl[pos++ ]<<(8*x);} time=t; }
        /* services varint */
        while(pos<plen && (pl[pos]&0x80)) pos++; pos++;
        /* net varint */
        unsigned long long net=0;
        if(pos>=plen)break;
        { unsigned char c=pl[pos];
          if(c<0xfd){net=c;pos+=1;} else if(c==0xfd){if(pos+3<=plen){pos+=3;}else return;}
          else if(c==0xfe){if(pos+5<=plen){pos+=5;}else return;} else {if(pos+9<=plen){pos+=9;}else return;} }
        /* addrlen varint */
        unsigned long long alen=0;
        if(pos>=plen)break;
        { unsigned char c=pl[pos];
          if(c<0xfd){alen=c;pos+=1;} else if(c==0xfd){if(pos+3<=plen){pos+=3;}else return;}
          else if(c==0xfe){if(pos+5<=plen){pos+=5;}else return;} else return; }
        unsigned char a[4]={0,0,0,0};
        if(alen<=4){ for(unsigned long long x=0;x<alen&&pos<plen;x++) a[x]=pl[pos+x]; }
        pos+=alen;
        unsigned short port=0; if(pos+1<plen) port=pl[pos]<<8|pl[pos+1]; pos+=2;
        if(net==1 && alen==4 && is_public_v4(a)){
            unsigned ip=(unsigned)a[0]|(unsigned)a[1]<<8|(unsigned)a[2]<<16|(unsigned)a[3]<<24;
            amr_add(ab, ip, port, 1, (unsigned)time);
        }
    }
}

static int handshake_getaddr(const char* host){
    struct timeval tv; tv.tv_sec=6; tv.tv_usec=0;
    struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    char buf[128]; snprintf(buf,sizeof buf,"%s",host); char* col=strchr(buf,':'); if(col)*col=0;
    unsigned ip;
    if(inet_pton(AF_INET,buf,&ip)!=1){
        if(getaddrinfo(buf,NULL,&h,&res)!=0) return -1;
        ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr; freeaddrinfo(res);
    }
    int fd=tcp_connect_ip(ip,PB); if(fd<0) return -1;
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    unsigned char v[102]; int o=0;
    u32(v+o,70016);o+=4;u64(v+o,1);o+=8;u64(v+o,(unsigned long long)time(NULL));o+=8;
    u64(v+o,1);o+=8;o+=16;u16(v+o,8333);o+=2;u64(v+o,1);o+=8;o+=16;u16(v+o,0);o+=2;
    u64(v+o,0x0000000011223344ULL);o+=8;
    const char* ua="/Satoshi:0.18.0/";v[o]=strlen(ua);o+=1;memcpy(v+o,ua,strlen(ua));o+=strlen(ua);
    u32(v+o,789000);o+=4;v[o]=1;o+=1;
    if(p2p_write(fd,"version",7,v,o)<=0){ fd_close(fd); return -1; }
    char cmd[12]; static unsigned char rb[4<<20]; unsigned plen=0; int va=0;
    for(int i=0;i<60;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0) break; cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&plen==8){p2p_write(fd,"pong",4,rb,8);continue;}
        if(!strncmp(cmd,"sendheaders",11)||!strncmp(cmd,"wtxidrelay",10)||!strncmp(cmd,"sendcmpct",9)){p2p_write(fd,cmd,strlen(cmd),"",0);continue;}
        if(!strncmp(cmd,"sendaddrv2",10)){ p2p_write(fd,"sendaddrv2",10,"",0); continue; }
        if(!strncmp(cmd,"verack",6)){va=1;break;}
    }
    if(!va){ fd_close(fd); return -1; }
    p2p_write(fd,"verack",6,"",0);
    p2p_write(fd,"sendaddrv2",10,"",0);
    p2p_write(fd,"getaddr",7,"",0);
    return fd;
}

static void gather(const char* host, int wait){
    int fd=handshake_getaddr(host); if(fd<0) return;
    char cmd[12]; static unsigned char rb[4<<20]; unsigned plen=0;
    time_t endt=time(NULL)+wait;
    while(time(NULL)<endt){
        plen=0; int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0) break; cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(!strncmp(cmd,"addr",4)) ingest_addr1(rb,plen);
        else if(!strncmp(cmd,"addrv2",6)) ingest_addrv2(rb,plen);
    }
    fd_close(fd);
}

int main(int argc,char**argv){
    if(argc<2){ fprintf(stderr,"usage: %s <seed_file> [parallel] [wait_s]\n",argv[0]); return 2; }
    const char* sf=argv[1];
    int par= argc>2? atoi(argv[2]) : 32;
    int wait= argc>3? atoi(argv[3]) : 8;
    amr_init(ab);
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
    long before = amr_count(ab);
    fprintf(stderr,"# gathering from %d seeds (%d-way parallel, %ds each); book had %ld\n", ns, par, wait, before);
    int done=0; pid_t kids[128]; int nk=0;
    while(done<ns){
        while(nk<par && done<ns){
            pid_t pid=fork();
            if(pid==0){ gather(seeds[done], wait); _exit(0); }
            kids[nk++]=pid; done++;
            if(nk>=par){ for(int i=0;i<nk;i++){int st;waitpid(kids[i],&st,0);} nk=0; }
        }
    }
    for(int i=0;i<nk;i++){int st;waitpid(kids[i],&st,0);}
    long after = amr_count(ab);
    fprintf(stderr,"# done: book grew %ld -> %ld peers (peers.dat)\n", before, after);
    return 0;
}
