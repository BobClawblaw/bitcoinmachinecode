/* daemon/liveclient.c -- real network client: connects to the running serve
 * daemon, handshakes (asm node_handshake), requests a block by hash via the
 * real asm codec, and verifies it receives a block back. Proves the node
 * serves real peers on a real TCP port. */
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long node_handshake(int fd);
extern long p2p_write(int fd,const char*cmd,unsigned cmdlen,const void*pl,unsigned plen);
extern int  p2p_read(int fd,char cmd[12],void*pl,unsigned cap,unsigned*len);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void sha256d(unsigned char o[32],const void*m,long l);

static void p32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
int main(void){
    int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), htons(18333));
    if(fd<0){ printf("FAIL connect\n"); return 1; }
    if(node_handshake(fd)!=1){ printf("FAIL handshake\n"); return 1; }
    printf("handshake OK\n");
    /* request block by a known hash: we don't know the store's hashes here, so
     * first getheaders(genesis) to learn the tip headers, then getdata the tip. */
    unsigned char gh[69]; gh[0]=0; gh[1]=0x11; gh[2]=0x01; gh[3]=0; gh[4]=0;
    memset(gh+5,0,64);   /* empty locator + stop => serve from genesis */
    p2p_write(fd,"getheaders",10,gh,69);
    char cmd[12]; unsigned char hp[5000]; unsigned hp_len=0;
    int r=p2p_read(fd,cmd,hp,sizeof hp,&hp_len);
    if(r<=0||strncmp(cmd,"headers",7)!=0){ printf("FAIL headers (r=%d cmd=%.*s)\n",r,10,cmd); return 1; }
    printf("got headers count=%d bytes=%u\n", (int)hp[0], hp_len);
    /* hash of the LAST returned header (the tip) and getdata it */
    /* headers payload: count(1) + per-hdr [80 hdr][1 txcount] */
    long n=(long)hp[0]; unsigned char tip_hdr[80];
    memcpy(tip_hdr, hp+1+(n-1)*81, 80);
    unsigned char tip_hash[32]; block_hash(tip_hash, tip_hdr);
    unsigned char gd[37]; gd[0]=1; gd[1]=2; gd[2]=0; gd[3]=0; gd[4]=0; memcpy(gd+5,tip_hash,32);
    p2p_write(fd,"getdata",7,gd,37);
    unsigned char blk[65536]; unsigned bl=0;
    r=p2p_read(fd,cmd,blk,sizeof blk,&bl);
    if(r<=0||strncmp(cmd,"block",5)!=0){ printf("FAIL block\n"); return 1; }
    unsigned char got[32]; block_hash(got, blk);  /* hash received header */
    int match=(memcmp(got,tip_hash,32)==0);
    printf("received block %u bytes, hash-match=%d\n", bl, match);
    printf("%s\n", match?"LIVE SERVE OK":"LIVE SERVE MISMATCH");
    return match?0:1;
}
