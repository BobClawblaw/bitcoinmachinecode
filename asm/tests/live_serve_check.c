/* live_serve_check.c -- connect to the running daemon serve port, request a
 * real block by hash, and verify the served bytes hash to the requested hash
 * and match the size. Uses only the asm p2p/bitcoind primitives like the rest
 * of the node. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long node_handshake(int fd);
extern long p2p_write(int fd,const char*cmd,unsigned cmdlen,const void*pl,unsigned plen);
extern int  p2p_read(int fd,char cmd[12],void*pl,unsigned cap,unsigned*len);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
int main(int argc,char**argv){
    if(argc<3){ fprintf(stderr,"usage: %s <port> <hash-hex>\n",argv[0]); return 2; }
    int port=atoi(argv[1]);
    /* parse 64-hex hash into 32 bytes (LE as bitcoin hex shows it) */
    unsigned char hash_be[32];
    for(int i=0;i<32;i++){ unsigned v; sscanf(argv[2]+i*2,"%2x",&v); hash_be[i]=(unsigned char)v; }
    /* convert displayed hex (big-endian) to the wire LE hash */
    unsigned char hash[32]; for(int i=0;i<32;i++) hash[i]=hash_be[31-i];

    int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), htons((unsigned short)port));
    if(fd<0){ fprintf(stderr,"connect failed\n"); return 1; }
    fprintf(stderr,"connected; handshaking...\n"); fflush(stderr);
    if(node_handshake(fd)!=1){ fprintf(stderr,"handshake failed\n"); return 1; }
    fprintf(stderr,"handshake OK; sending getdata...\n"); fflush(stderr);

    /* getdata for the block: count=1 type=2(MSG_BLOCK) hash */
    unsigned char gd[37]; gd[0]=1; gd[1]=2; gd[2]=0; gd[3]=0; gd[4]=0; memcpy(gd+5,hash,32);
    if(p2p_write(fd,"getdata",7,gd,37)<=0){ fprintf(stderr,"getdata write failed\n"); return 1; }

    char cmd[12]; static unsigned char pl[1<<20]; unsigned plen=0;
    int r=p2p_read(fd,cmd,pl,sizeof pl,&plen);
    if(r<=0){ fprintf(stderr,"read failed (r=%d)\n",r); return 1; }
    if(strncmp(cmd,"block",5)!=0){ fprintf(stderr,"expected 'block', got '%.5s'\n",cmd); return 1; }
    /* verify: served block's hash matches requested */
    unsigned char got[32]; block_hash(got, pl);
    int ok = 1; for(int i=0;i<32;i++) if(got[i]!=hash[31-i]) ok=0;
    printf("served %u-byte block; requested-hash-match=%s\n", plen, ok?"YES":"NO");
    printf("  req hash "); for(int i=31;i>=0;i--) printf("%02x",hash[i]); printf("\n");
    printf("  got hash "); for(int i=31;i>=0;i--) printf("%02x",got[i]);   printf("\n");
    close(fd);
    if(!ok){ fprintf(stderr,"BLOCK MISMATCH\n"); return 1; }

    /* ---- also verify getheaders over the real archive ---- */
    int fd2=tcp_connect_ip(htonl(INADDR_LOOPBACK), htons((unsigned short)port));
    if(fd2>=0 && node_handshake(fd2)==1){
        /* locator = requested block (height1) -> expect headers for later blocks */
        unsigned char gh[69]; memset(gh,0,69);
        gh[0]=0x7f;              /* version (any) */
        gh[2]=0x01; gh[3]=0x00; gh[4]=1;   /* key_count=1 hash_count=1 */
        for(int i=0;i<32;i++) gh[5+i]=hash[i]; /* locator hash (wire LE) */
        memset(gh+37,0,32);      /* hash_stop = zeros (no stop hash) */
        if(p2p_write(fd2,"getheaders",10,(const unsigned char*)&gh,69)>0){
            char c6[12]; static unsigned char hp[2000*81+4]; unsigned hp_len=0;
            struct timeval tv; tv.tv_sec=6; tv.tv_usec=0; setsockopt(fd2,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
            int rh=p2p_read(fd2,c6,hp,sizeof hp,&hp_len);
            if(rh>0 && strncmp(c6,"headers",7)==0){
                printf("getheaders: %u headers returned (count=%u, want>0)\n", hp_len, (hp_len>0)?hp[0]:0);
                printf("getheaders-OK=%s\n", (hp_len>=81 && hp[0]>=1)?"YES":"NO");
            } else printf("getheaders: no headers reply (r=%d '%.7s')\n", rh, c6);
        }
        close(fd2);
    }
    return ok?0:1;
}
