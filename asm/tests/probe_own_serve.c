#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd, const char* c, unsigned cl, const void* pl, unsigned plen);
extern int  p2p_read(int fd, char cmd[12], void* pl, unsigned cap, unsigned* len);
extern int  node_handshake(int fd);
static void put_u32le(unsigned char* p, unsigned v){ p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24; }
int main(int argc, char** argv){
    /* The hash argument is taken in the byte order the server's on-disk index
     * uses: pass the 32 bytes exactly as they appear in a 48-byte index.dat
     * record (bytes 0..31). This is a DIAGNOSTIC tool for proving the serve
     * daemon answers getdata; it is NOT trying to be a canonical-BE-hash CLI.
     * The getdata wire hash we send is reverse(arg), which matches the form
     * build_hash_index() stored (le[k]=rec[31-k]) so the O(1) idx_get hits. */
    if(argc<4){ fprintf(stderr,"usage: %s <host> <port> <hash_bytes_hex64_in_index-order>\n", argv[0]); return 2; }
    fprintf(stderr,"[p] getaddrinfo\n");
    struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(argv[1],NULL,&h,&res)!=0){ perror("gai"); return 1; }
    unsigned ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    int port=atoi(argv[2]); freeaddrinfo(res);
    fprintf(stderr,"[p] connect\n");
    int fd=tcp_connect_ip(ip,(unsigned short)htons((unsigned short)port)); { struct timeval tv; tv.tv_sec=8; tv.tv_usec=0; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv); }
    if(fd<0){ fprintf(stderr,"connect failed\n"); return 1; }
    fprintf(stderr,"[p] handshake\n");
    if(node_handshake(fd)!=1){ fprintf(stderr,"handshake failed\n"); return 1; }
    fprintf(stderr,"[p] handshake ok\n");
    unsigned char hash_be[32], hash_le[32];
    if(strlen(argv[3])!=64){ fprintf(stderr,"hash 64\n"); return 1; }
    for(int i=0;i<32;i++){ unsigned v; sscanf(argv[3]+2*i,"%2x",&v); hash_be[i]=(unsigned char)v; }
    for(int i=0;i<32;i++) hash_le[i]=hash_be[31-i];
    unsigned char gd[37]; gd[0]=1; put_u32le(gd+1,2); memcpy(gd+5, hash_le, 32);
    fprintf(stderr,"[p] send getdata\n");
    if(p2p_write(fd,"getdata",7,gd,37)<0){ fprintf(stderr,"write fail\n"); return 1; }
    char cmd[12]; static unsigned char buf[8<<20]; unsigned len=0;
    for(int tries=0; tries<8; tries++){
        int r=p2p_read(fd,cmd,buf,sizeof buf,&len);
        if(r<=0){ fprintf(stderr,"[p] read r=%d\n",r); continue; }
        cmd[11]=0;
        fprintf(stderr,"[p] got cmd '%.11s' len=%u\n", cmd, len);
        if(strncmp(cmd,"block",5)==0){ printf("GOT block len=%u\n",len); return 0; }
    }
    fprintf(stderr,"no block\n"); return 1;
}
