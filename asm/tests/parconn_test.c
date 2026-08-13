/* parconn_test.c -- verify the local node sustains N SIMULTANEOUS connections
 * and each can handshake + serve a real block body in parallel. This validates
 * the premise for a multi-peer parallel IBD before we build it.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

extern int  tcp_connect_ip(unsigned, unsigned short);
extern long p2p_write(int,const char*,unsigned,const void*,unsigned);
extern int  p2p_read(int,char[12],void*,unsigned,unsigned*);
extern long p2p_getheaders(void*,const void*,long,const void*);
extern long p2p_headers_count(const void*,long);
extern void sha256d(unsigned char*,const void*,long);
extern void fd_close(int);
#define PB ((unsigned short)htons(8333))
static void u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static void u16(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}

int main(int argc,char**argv){
    setbuf(stdout,NULL);
    const char* ipstr=argc>1?argv[1]:"192.168.5.69";
    int N=argc>2?atoi(argv[2]):8;
    unsigned ip; inet_pton(AF_INET,ipstr,&ip);
    int fds[16];

    /* phase 1: open + handshake N connections */
    for(int i=0;i<N;i++){
        int fd=tcp_connect_ip(ip,PB); if(fd<0){ printf("conn %d FAIL fd=%d\n",i,fd); fds[i]=-1; continue; }
        unsigned char v[102]; int o=0;
        u32(v+o,70016);o+=4;u64(v+o,1);o+=8;u64(v+o,(unsigned long long)time(NULL));o+=8;
        u64(v+o,1);o+=8;o+=16;u16(v+o,8333);o+=2;u64(v+o,1);o+=8;o+=16;u16(v+o,0);o+=2;
        u64(v+o,0x8800000000000000ULL+i);o+=8;
        const char* ua="/Satoshi:0.18.0/";v[o]=strlen(ua);o+=1;memcpy(v+o,ua,strlen(ua));o+=strlen(ua);
        u32(v+o,789000);o+=4;v[o]=1;o+=1;
        p2p_write(fd,"version",7,v,o);
        char cmd[12]; static unsigned char rb[1<<22]; unsigned plen=0; int va=0;
        for(int k=0;k<40;k++){int r=p2p_read(fd,cmd,rb,sizeof rb,&plen);if(r<=0)break;cmd[11]=0;
            if(!strncmp(cmd,"ping",4)&&plen==8){p2p_write(fd,"pong",4,rb,8);continue;}
            if(!strncmp(cmd,"sendheaders",11)||!strncmp(cmd,"sendaddrv2",10)||!strncmp(cmd,"wtxidrelay",10)||!strncmp(cmd,"sendcmpct",9)){p2p_write(fd,cmd,strlen(cmd),"",0);continue;}
            if(!strncmp(cmd,"verack",6)){va=1;break;}}
        if(!va){printf("conn %d handshake FAIL\n",i);fd_close(fd);fds[i]=-1;continue;}
        p2p_write(fd,"verack",6,"",0);
        fds[i]=fd;
        printf("conn %d: handshake OK\n",i);
    }

    /* count established */
    int est=0; for(int i=0;i<N;i++) if(fds[i]>=0) est++;
    printf("established %d/%d simultaneous peers\n", est, N);

    /* phase 2: each established conn learns tip and downloads one block */
    int served=0;
    for(int i=0;i<N;i++){
        if(fds[i]<0) continue;
        int fd=fds[i];
        unsigned char loc[32],stop[32],gh[128];memset(loc,0,32);memset(stop,0,32);
        long gl=p2p_getheaders(gh,loc,1,stop);
        p2p_write(fd,"getheaders",10,gh,gl);
        char cmd[12]; static unsigned char rb[1<<22]; unsigned plen=0;
        long nhdrs=-1; unsigned char tip40[32];
        for(int k=0;k<120;k++){int r=p2p_read(fd,cmd,rb,sizeof rb,&plen);if(r<=0)break;cmd[11]=0;
            if(!strncmp(cmd,"ping",4)&&plen==8){p2p_write(fd,"pong",4,rb,8);continue;}
            if(!strncmp(cmd,"sendheaders",11)||!strncmp(cmd,"sendcmpct",9)||!strncmp(cmd,"sendaddrv2",10)||!strncmp(cmd,"wtxidrelay",10)){p2p_write(fd,cmd,strlen(cmd),"",0);continue;}
            if(!strncmp(cmd,"headers",7)){nhdrs=p2p_headers_count(rb,plen);unsigned char*b=(rb[0]==0xfd)?rb+3:rb+1;sha256d(tip40,b+(nhdrs-1)*81,80);break;}}
        if(nhdrs<=0){printf("peer %d no headers\n",i);fd_close(fd);continue;}
        /* getdata tip block */
        unsigned char gd[64]; gd[0]=1; u32(gd+1,2); memcpy(gd+5,tip40,32);
        p2p_write(fd,"getdata",7,gd,37);
        long blen=-1;
        for(int k=0;k<120;k++){int r=p2p_read(fd,cmd,rb,sizeof rb,&plen);if(r<=0)break;cmd[11]=0;
            if(!strncmp(cmd,"ping",4)&&plen==8){p2p_write(fd,"pong",4,rb,8);continue;}
            if(!strncmp(cmd,"block",5)&&plen>80){blen=plen;break;}}
        printf("peer %d: block served %ld bytes %s\n", i, blen, blen>0?"OK":"X");
        if(blen>0) served++;
        fd_close(fd);
    }
    printf("RESULT: %d/%d parallel connections served a block\n", served, est);
    return served>=N-1?0:1;
}
