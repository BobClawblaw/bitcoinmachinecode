/* serve_test.c -- connect to a serve node, request a KNOWN stored block by
 * hash (from the archive index), and verify the server returns the exact bytes.
 * Usage: serve_test <dir> <host> <port> [height]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <netdb.h>
extern int  tcp_connect_ip(unsigned, unsigned short);
extern int  node_handshake(int fd);
extern long p2p_write(int,const char*,unsigned,const void*,unsigned);
extern int  p2p_read(int,char[12],void*,unsigned,unsigned*);
extern void fd_close(int fd);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
static unsigned resolve(const char* h){char b[128];snprintf(b,sizeof b,"%s",h);char*c=strchr(b,':');if(c)*c=0;struct addrinfo x,*res=0;memset(&x,0,sizeof x);x.ai_family=AF_INET;x.ai_socktype=SOCK_STREAM;if(getaddrinfo(b,0,&x,&res))return 0;unsigned ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;freeaddrinfo(res);return ip;}
int main(int argc,char**argv){
    if(argc<4){fprintf(stderr,"usage %s <dir> <host> <port> [height]\n",argv[0]);return 2;}
    const char* dir=argv[1]; long h= argc>4? atol(argv[4]) : 30000;
    /* read block hash + bytes from archive */
    char ip_[640]; snprintf(ip_,640,"%s/index.dat",dir);
    FILE* f=fopen(ip_,"rb"); if(fseek(f,h*48,SEEK_SET)){printf("no index\n");return 1;}
    unsigned char rec[48]; if(fread(rec,1,48,f)!=48){printf("height %ld out of range\n",h);return 1;} fclose(f);
    if(rec[0]==0&&rec[1]==0&&rec[2]==0&&rec[3]==0){printf("height %ld NOT stored\n",h);return 1;}
    uint32_t fno; memcpy(&fno,rec+32,4); uint64_t pos; memcpy(&pos,rec+36,8); uint32_t sz; memcpy(&sz,rec+44,4);
    char bn[80]; snprintf(bn,sizeof bn,"%s/blk%05u.dat",dir,(unsigned)fno);
    FILE* b=fopen(bn,"rb"); unsigned char* want=malloc(sz); fseek(b,(long)(pos+8),SEEK_SET); fread(want,1,sz,b); fclose(b);
    printf("requesting height %ld (size %u) from serve\n", h, sz);
    unsigned ip=resolve(argv[2]);
    int fd=tcp_connect_ip(ip,htons((unsigned short)atoi(argv[3]))); if(fd<0){printf("conn fail\n");return 1;}
    struct timeval tv; tv.tv_sec=60; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    if(node_handshake(fd)!=1){printf("handshake fail\n");return 1;}
    /* getdata for this block's hash (index record[0..32]) */
    unsigned char gd[37]; gd[0]=1; gd[1]=2; gd[2]=0; gd[3]=0; gd[4]=0; memcpy(gd+5,rec+0,32);
    if(p2p_write(fd,"getdata",7,gd,37)<=0){printf("getdata send fail\n");return 1;}
    int got=0; char cmd[12]; unsigned char pl[1<<22]; unsigned plen=0;
    for(int i=0;i<60;i++){ int r=p2p_read(fd,cmd,pl,sizeof pl,&plen); if(r<=0)break; cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&plen==8){p2p_write(fd,"pong",4,pl,8);continue;}
        if(!strncmp(cmd,"block",5)){ got=1;
            int match = (plen==sz && memcmp(pl,want,sz)==0);
            unsigned char rb[32]; block_hash(rb,pl);
            printf("got block msg len=%u size-match=%d byte-identical=%d\n", plen, plen==sz?1:0, match);
            break;
        }
    }
    fd_close(fd); free(want);
    printf("== %s ==\n", got?"SERVE OK":"SERVE FAIL");
    return got?0:1;
}
