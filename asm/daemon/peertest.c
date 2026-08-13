/* daemon/peertest.c -- test a list of internet peers for block-BODY serving.
 * For each host (ip:port), connect (asm tcp_connect_ip), handshake (asm p2p),
 * getheaders to learn a recent header, getdata that block hash via the asm
 * p2p_getdata_block (canonical 37B form), and report whether a `block` body
 * arrives. Start a few test connections in parallel (fork) to keep it fast.
 *
 * Usage: peertest <peers_file> <max_tested> <out_good_file>
 * Output: the first <n>-good distinct hosts that served a block body.
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
extern long p2p_getheaders(void*,const void*,long,const void*);
extern long p2p_headers_count(const void*,long);
extern long p2p_getdata_block(void*, const void*);
extern void sha256d(unsigned char*,const void*,long);
extern void fd_close(int);
static void u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static void u16(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}

static unsigned resolve(const char* host){
    unsigned ip4=0; if(inet_pton(AF_INET,host,&ip4)==1) return ip4;
    struct addrinfo h,*res=0; memset(&h,0,sizeof h);
    h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,NULL,&h,&res)!=0) return 0;
    unsigned ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res); return ip;
}

/* returns 1 if the peer serves a real block body (getheaders + getdata), else 0 */
static int test_one(const char* host, unsigned short port){
    unsigned ip=resolve(host); if(ip==0) return 0;
    int fd=tcp_connect_ip(ip, (unsigned short)htons(port==0?8333:port));
    if(fd<0) return 0;
    struct timeval tv; tv.tv_sec=3; tv.tv_usec=0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    unsigned char v[102]; int o=0;
    u32(v+o,70016);o+=4;u64(v+o,1);o+=8;u64(v+o,(unsigned long long)time(NULL));o+=8;
    u64(v+o,1);o+=8;o+=16;u16(v+o,8333);o+=2;u64(v+o,1);o+=8;o+=16;u16(v+o,0);o+=2;
    u64(v+o,0xABCDEF0123456789ULL);o+=8;
    const char* ua="/Satoshi:0.18.0/";v[o]=strlen(ua);o+=1;memcpy(v+o,ua,strlen(ua));o+=strlen(ua);
    u32(v+o,789000);o+=4;v[o]=1;o+=1;
    if(p2p_write(fd,"version",7,v,o)<=0){ fd_close(fd); return 0; }
    char cmd[12]; static unsigned char rb[24<<20]; unsigned plen=0; int va=0;
    for(int i=0;i<40;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0) break; cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(!strncmp(cmd,"sendheaders",11)||!strncmp(cmd,"sendaddrv2",10)||!strncmp(cmd,"wtxidrelay",10)||!strncmp(cmd,"sendcmpct",9)){ p2p_write(fd,cmd,strlen(cmd),"",0); continue; }
        if(!strncmp(cmd,"verack",6)){ va=1; break; }
    }
    if(!va){ fd_close(fd); return 0; }
    p2p_write(fd,"verack",6,"",0);

    /* getheaders from genesis to learn a recent header */
    unsigned char loc[32],stop[32],gh[128]; memset(loc,0,32); memset(stop,0,32);
    long gl=p2p_getheaders(gh,loc,1,stop);
    if(p2p_write(fd,"getheaders",10,gh,gl)<=0){ fd_close(fd); return 0; }
    unsigned char tip40[32]; long nhdrs=-1;
    for(int i=0;i<120;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0) break; cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(!strncmp(cmd,"sendheaders",11)||!strncmp(cmd,"sendaddrv2",10)||!strncmp(cmd,"sendcmpct",9)||!strncmp(cmd,"wtxidrelay",10)){ p2p_write(fd,cmd,strlen(cmd),"",0); continue; }
        if(!strncmp(cmd,"headers",7)){ nhdrs=p2p_headers_count(rb,plen);
            if(nhdrs>0){ unsigned char* b=(rb[0]==0xfd)?rb+3:rb+1; sha256d(tip40, b+(nhdrs-1)*81, 80); } break; }
    }
    if(nhdrs<=0){ fd_close(fd); return 0; }

    /* getdata the tip block */
    unsigned char gd[64]; long gdl=p2p_getdata_block(gd,tip40);
    if(p2p_write(fd,"getdata",7,gd,gdl)<=0){ fd_close(fd); return 0; }
    int got=0;
    for(int i=0;i<200;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0) break; cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(!strncmp(cmd,"block",5)&&plen>80){ got=1; break; }
        if(!strncmp(cmd,"notfound",8)) break;
    }
    fd_close(fd);
    return got;
}

int main(int argc,char**argv){
    const char* pf=argc>1?argv[1]:"/storage/bitcoinmachinecode/internet_peers.txt";
    int max=argc>2?atoi(argv[2]):200;
    const char* outgood=argc>3?argv[3]:"/tmp/goodpeers.txt";
    char hosts[4096][128]; int n=0;
    FILE* f=fopen(pf,"r"); if(!f){fprintf(stderr,"no peers file\n");return 1;}
    char line[256];
    while(fgets(line,sizeof line,f)&&n<4096){
        char* nl=strpbrk(line,"\r\n"); if(nl)*nl=0;
        if(*line && strchr(line,':')){ strncpy(hosts[n],line,127); hosts[n][127]=0; n++; }
    }
    fclose(f);
    if(n>max) n=max;
    printf("# testing %d internet peers for block-body serving (parallel)\n", n);

    /* fork up to 48 at a time, collect results into a shared file via append */
    FILE* g=fopen(outgood,"w"); fclose(g);
    const char* results="/tmp/peertest_results.txt";
    FILE* rf=fopen(results,"w"); fclose(rf);
    pid_t kids[64]; int nk=0;
    time_t t0=time(NULL);
    int done=0;
    while(done<n){
        /* spawn up to (something) concurrently */
        int batch=0;
        while(batch<48 && done<n){
            char host[128],*portp;
            strncpy(host,hosts[done],127); host[127]=0;
            done++;
            char* colon=strrchr(host,':');
            unsigned short port=8333;
            if(colon){ *colon=0; port=(unsigned short)atoi(colon+1); }
            pid_t pid=fork();
            if(pid==0){
                int ok=test_one(host,port);
                char res[256]; snprintf(res,sizeof res,"%s %s\n", ok?"GOOD":"bad", hosts[done-1]);
                /* append to shared result file */
                FILE* rf2=fopen(results,"a"); if(rf2){ fwrite(res,1,strlen(res),rf2); fclose(rf2);}
                _exit(ok?0:1);
            }
            kids[nk++]=pid; batch++;
        }
        /* reap this batch */
        for(int i=0;i<nk;i++){ int st; waitpid(kids[i],&st,0); }
        nk=0;
        /* if testing takes a while, print progress */
        printf("# tested %d (%.0fs)\n", done, difftime(time(NULL),t0));
    }
    /* report good peers */
    int goodn=0;
    g=fopen(outgood,"w");
    FILE* rf2=fopen(results,"r"); char rline[256];
    while(rf2 && fgets(rline,sizeof rline,rf2)){
        if(strncmp(rline,"GOOD",4)==0){
            char* sp=strchr(rline,' '); 
            if(sp){ fputs(sp+1,g); goodn++; }
        }
    }
    if(rf2)fclose(rf2);
    fclose(g);
    printf("# %d good peers written to %s\n", goodn, outgood);
    return 0;
}
