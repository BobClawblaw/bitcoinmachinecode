/* live_block_dl.c -- MANUAL/live. Download a REAL mainnet block body from the
 * cooperative local node (192.168.5.69) using the ASSEMBLY node primitives end
 * to end:
 *   - tcp_connect_ip + asm p2p framing (bitcoin_net.asm)
 *   - version/verack handshake + getheaders (bitcoin_p2p.asm)
 *   - getdata via the FIXED asm p2p_getdata_block (37 B, hash at +5)
 *   - cons_verify (asm) on the received real block
 *   - block_hash (asm) + store_append (asm) to persist it
 * This is the actual "receive the blockchain" path working against a real node
 * that COOPERATIVELY serves block bodies (unlike the drop-everything seeds).
 * Usage: live_block_dl <ipv4> [block_offset_from_tip]
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>

extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int, const char*, unsigned, const void*, unsigned);
extern int  p2p_read(int, char[12], void*, unsigned, unsigned*);
extern long p2p_getheaders(void*, const void*, long, const void*);
extern long p2p_headers_count(const void*, long);
extern long p2p_getdata_block(void* out, const void* hash);
extern void sha256d(unsigned char o[32], const void*m, long l);
extern int  cons_verify(const void* block, long len, void* scratch, unsigned cap);
extern long store_append(void* st, const unsigned char* hash32, const void* blk, long len);
extern long store_init(void* st);
extern void fd_close(int fd);

#define PORT_BE ((unsigned short)htons(8333))
static void put_u32le(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64le(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static void put_u16be(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}

int main(int argc,char**argv){
    setbuf(stdout,NULL);
    const char* ipstr = argc>1? argv[1] : "192.168.5.69";
    int back = argc>2? atoi(argv[2]) : 0;   /* offset back from tip (0=tip) */
    unsigned ip; inet_pton(AF_INET, ipstr, &ip);
    int fd = tcp_connect_ip(ip, PORT_BE);
    if(fd<0){ printf("connect fail fd=%d\n", fd); return 2; }
    printf("PASS connect %s\n", ipstr);

    unsigned char v[102]; int o=0;
    put_u32le(v+o,70016); o+=4; put_u64le(v+o,1); o+=8;
    put_u64le(v+o,(unsigned long long)time(NULL)); o+=8;
    put_u64le(v+o,1); o+=8; o+=16; put_u16be(v+o,8333); o+=2;
    put_u64le(v+o,1); o+=8; o+=16; put_u16be(v+o,0); o+=2;
    put_u64le(v+o,0x1122334455667788ULL); o+=8;
    const char* ua="/Satoshi:0.18.0/"; v[o]=strlen(ua); o+=1; memcpy(v+o,ua,strlen(ua)); o+=strlen(ua);
    put_u32le(v+o,789000); o+=4; v[o]=1; o+=1;
    if(p2p_write(fd,"version",7,v,o)<=0){ printf("version send fail\n"); return 1; }
    char cmd[12]; static unsigned char rb[1<<24]; unsigned plen=0;
    int va=0;
    for(int i=0;i<40;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0){ printf("closed awaiting verack\n"); fd_close(fd); return 1; } cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"sendheaders",11)==0||strncmp(cmd,"sendaddrv2",10)==0||strncmp(cmd,"wtxidrelay",10)==0||strncmp(cmd,"sendcmpct",9)==0){ p2p_write(fd,cmd,strlen(cmd),"",0); continue; }
        if(strncmp(cmd,"version",7)==0) continue;
        if(strncmp(cmd,"verack",6)==0){ va=1; break; }
    }
    if(!va){ printf("no verack\n"); fd_close(fd); return 1; }
    p2p_write(fd,"verack",6,"",0);
    printf("PASS handshake\n");

    /* learn tip */
    unsigned char loc[32], stop[32], gh[128]; memset(loc,0,32); memset(stop,0,32);
    long glen=p2p_getheaders(gh,loc,1,stop);
    if(p2p_write(fd,"getheaders",10,gh,glen)<=0){ printf("getheaders send fail\n"); fd_close(fd); return 1; }
    unsigned char hdrs[2000][81]; long nhdrs=-1;
    for(int i=0;i<200;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0){ printf("closed waiting headers\n"); fd_close(fd); return 1; } cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"sendheaders",11)==0||strncmp(cmd,"sendaddrv2",10)==0||strncmp(cmd,"sendcmpct",9)==0||strncmp(cmd,"wtxidrelay",10)==0){ p2p_write(fd,cmd,strlen(cmd),"",0); continue; }
        if(strncmp(cmd,"headers",7)==0){ nhdrs=p2p_headers_count(rb,plen);
            unsigned char* b=(rb[0]==0xfd)?rb+3:rb+1;
            for(long k=0;k<nhdrs && k<2000;k++) memcpy(hdrs[k], b+k*81, 81);
            break; }
    }
    if(nhdrs<=0){ printf("no headers (nhdrs=%ld)\n", nhdrs); fd_close(fd); return 1; }
    printf("PASS learned %ld headers; tip height=%lu\n", nhdrs, 789000+nhdrs-1);

    /* pick the block: back from tip. getdata via the FIXED asm p2p_getdata_block */
    long which = nhdrs-1-back; if(which<0) which=0;
    unsigned char hdr80[80]; memcpy(hdr80, hdrs[which], 80);
    unsigned char bh[32]; sha256d(bh, hdr80, 80);          /* real block hash (LE) */
    printf("requesting block at height %lu (hash %02x%02x..) via asm getdata\n",
           789000+which, bh[31], bh[30]);

    unsigned char gd[64]; long gdl = p2p_getdata_block(gd, bh);
    if(p2p_write(fd,"getdata",7,gd,gdl)<=0){ printf("getdata send fail\n"); fd_close(fd); return 1; }
    printf("sent getdata (%ld B, asm p2p_getdata_block -- 37B hash@+5)\n", gdl);

    /* receive block */
    long blen=-1;
    for(int i=0;i<200;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0){ printf("closed waiting block\n"); fd_close(fd); return 1; } cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"sendheaders",11)==0||strncmp(cmd,"sendaddrv2",10)==0||strncmp(cmd,"sendcmpct",9)==0||strncmp(cmd,"wtxidrelay",10)==0){ p2p_write(fd,cmd,strlen(cmd),"",0); continue; }
        if(strncmp(cmd,"block",5)==0 && plen>80){ blen=plen; break; }
        if(strncmp(cmd,"notfound",8)==0){ printf("  notfound\n"); break; }
    }
    if(blen<=0){ printf("no block body received\n"); fd_close(fd); return 1; }
    printf("PASS got real block body, %ld bytes\n", blen);

    /* validate with asm cons_verify (PoW + tx walk + merkle) */
    static unsigned char scratch[64*1024];
    int ok = cons_verify(rb, blen, scratch, 1024);
    printf("asm cons_verify on real block: %s\n", ok?"VALID":"INVALID");
    if(!ok){ fd_close(fd); return 1; }

    /* persist with asm block_hash + store_append */
    static unsigned char store[4096]; store_init(store);
    unsigned char hh[32]; sha256d(hh, rb, 80);             /* header hash of stored block */
    long app = store_append(store, hh, rb, blen);
    printf("asm store_append: %ld (persisted real block %02x%02x..)\n", app, hh[31], hh[30]);
    fd_close(fd);
    return (ok==1 && app>=0)?0:1;
}
