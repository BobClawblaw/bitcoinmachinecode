/* gh_client.c -- connect to a running serve port, getheaders for a locator, dump
 * how many headers come back. Pure p2p/asm primitives. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long node_handshake(int fd);
extern long p2p_write(int fd,const char*cmd,unsigned cmdlen,const void*pl,unsigned plen);
extern int  p2p_read(int fd,char cmd[12],void*pl,unsigned cap,unsigned*len);
int main(int argc,char**argv){
    if(argc<4){ fprintf(stderr,"usage: %s <port> <locator-hex> <expect-count-hint>\n",argv[0]); return 2; }
    int port=atoi(argv[1]);
    unsigned char lbe[32]; for(int i=0;i<32;i++){unsigned v;sscanf(argv[2]+i*2,"%2x",&v);lbe[i]=(unsigned char)v;}
    unsigned char loc[32]; for(int i=0;i<32;i++) loc[i]=lbe[31-i]; /* wire LE */
    int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK),htons((unsigned short)port));
    if(fd<0){fprintf(stderr,"connect fail\n");return 1;}
    if(node_handshake(fd)!=1){fprintf(stderr,"hs fail\n");return 1;}
    unsigned char gh[69]; memset(gh,0,69);
    gh[0]=0x7f; gh[2]=0x01; gh[3]=0x00; gh[4]=1;
    memcpy(gh+5,loc,32); memset(gh+37,0,32);
    if(p2p_write(fd,"getheaders",10,gh,69)<=0){fprintf(stderr,"write fail\n");return 1;}
    struct timeval tv; tv.tv_sec=8; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    char cmd[12]; static unsigned char hp[300000]; unsigned hplen=0;
    int r=p2p_read(fd,cmd,hp,sizeof hp,&hplen);
    if(r<=0){fprintf(stderr,"NO headers reply r=%d\n",r); return 1;}
    if(strncmp(cmd,"headers",7)!=0){fprintf(stderr,"got cmd '%.7s' len=%u\n",cmd,hplen); return 1;}
    printf("headers len=%u count-varint=%u -> %d headers (first hdr prev? ..)\n", hplen, hplen?hp[0]:0, hplen? (hplen-1)/81 : -1);
    return 0;
}
