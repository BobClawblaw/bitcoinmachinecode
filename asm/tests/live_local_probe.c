/* live_local_probe.c -- MANUAL/live. Directly probe the local cooperative node
 * at a raw IPv4 (no DNS) to settle the getdata wire-format question definitively:
 * handshake, learn the tip via getheaders, then send the SAME block hash in
 * Form A (canonical 37B: [count varint][type int32 LE][hash at +5]) vs Form B
 * (34B: [count varint][type varint][hash at +2]) and see which is answered.
 * Usage: live_local_probe <ipv4>
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
extern void sha256d(unsigned char o[32], const void*m, long l);
extern void fd_close(int fd);

#define PORT_BE ((unsigned short)htons(8333))
static void put_u32le(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64le(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static void put_u16be(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}

int main(int argc,char**argv){
    setbuf(stdout,NULL);
    const char* ipstr = argc>1? argv[1] : "192.168.5.69";
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
    char cmd[12]; static unsigned char rb[1<<20]; unsigned plen=0;
    int va=0;
    for(int i=0;i<40;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0){ printf("closed awaiting verack\n"); fd_close(fd); return 1; } cmd[11]=0;
        printf("  hshk got %s (%u B)\n", cmd, plen);
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"sendheaders",11)==0||strncmp(cmd,"sendaddrv2",10)==0||strncmp(cmd,"wtxidrelay",10)==0){ p2p_write(fd,cmd,strlen(cmd),"",0); continue; }
        if(strncmp(cmd,"version",7)==0){ printf("  got peer version\n"); continue; }
        if(strncmp(cmd,"verack",6)==0){ va=1; break; }
    }
    if(!va){ printf("no verack\n"); fd_close(fd); return 1; }
    p2p_write(fd,"verack",6,"",0);
    printf("sent verack\n");

    /* learn tip: getheaders from genesis */
    unsigned char loc[32], stop[32], gh[128]; memset(loc,0,32); memset(stop,0,32);
    long glen=p2p_getheaders(gh,loc,1,stop);
    printf("getheaders payload %ld B\n", glen);
    if(p2p_write(fd,"getheaders",10,gh,glen)<=0){ printf("getheaders send fail\n"); fd_close(fd); return 1; }
    long nhdrs=-1; unsigned char tip40[32];
    for(int i=0;i<120;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0){ printf("closed waiting headers\n"); fd_close(fd); return 1; } cmd[11]=0;
        printf("  got %s (%u B)\n", cmd, plen);
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"sendheaders",11)==0||strncmp(cmd,"sendaddrv2",10)==0||strncmp(cmd,"wtxidrelay",10)==0||strncmp(cmd,"sendcmpct",9)==0){ p2p_write(fd,cmd,strlen(cmd),"",0); continue; }
        if(strncmp(cmd,"headers",7)==0){ nhdrs=p2p_headers_count(rb,plen);
            if(nhdrs>0){ unsigned char* b=(rb[0]==0xfd)?rb+3:rb+1; sha256d(tip40,b+(nhdrs-1)*81,80);} break; }
    }
    if(nhdrs<=0){ printf("no headers (nhdrs=%ld)\n", nhdrs); fd_close(fd); return 1; }
    printf("PASS learned %ld headers to tip\n", nhdrs);

    /* Form A: canonical 37B, hash at +5 */
    unsigned char ga[37]; ga[0]=1; put_u32le(ga+1,2); memcpy(ga+5,tip40,32);
    printf("send FORM A 37B hash@+5...\n"); fflush(stdout);
    p2p_write(fd,"getdata",7,ga,37);
    int gotA=0,notA=0;
    for(int i=0;i<120;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0){ printf("  A: closed\n"); break; } cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"block",5)==0 && plen>80){ gotA=1; printf("  FORM A got block (%u B)\n",plen); break; }
        if(strncmp(cmd,"notfound",8)==0){ notA=1; printf("  FORM A notfound\n"); break; }
    }
    printf("FORM A: block=%d notfound=%d\n", gotA, notA);

    /* Form B: 34B, hash at +2 */
    unsigned char gb[34]; gb[0]=1; gb[1]=2; memcpy(gb+2,tip40,32);
    printf("send FORM B 34B hash@+2...\n"); fflush(stdout);
    p2p_write(fd,"getdata",7,gb,34);
    int gotB=0,notB=0;
    for(int i=0;i<120;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0){ printf("  B: closed\n"); break; } cmd[11]=0;
        if(strncmp(cmd,"ping",4)==0 && plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(strncmp(cmd,"block",5)==0 && plen>80){ gotB=1; printf("  FORM B got block (%u B)\n",plen); break; }
        if(strncmp(cmd,"notfound",8)==0){ notB=1; printf("  FORM B notfound\n"); break; }
    }
    printf("FORM B: block=%d notfound=%d\n", gotB, notB);
    fd_close(fd);
    printf("VERDICT: A=%d B=%d\n", gotA, gotB);
    return 0;
}
