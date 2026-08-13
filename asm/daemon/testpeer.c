/* daemon/testpeer.c -- listener on 18444 that serves a 2-block chain to a
 * connecting daemon (handshake -> getheaders -> getdata -> blocks).
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern long p2p_write(int fd,const char*cmd,unsigned cmdlen,const void*pl,unsigned plen);
extern int  p2p_read(int fd,char cmd[12],void*pl,unsigned cap,unsigned*len);
extern long p2p_getheaders(void* out, const unsigned char loc[32], unsigned nloc, const unsigned char stop[32]);

extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void sha256d(unsigned char o[32],const void*m,long l);
extern int  pow_check(const unsigned char h[80]);
static void put_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++)p[i]=v>>(8*i);}
static unsigned char blocks[2][4096]; static long blen[2]; static unsigned char bh[2][32];
static int NB=0;
static long mk(unsigned char* b, const unsigned char prev[32], unsigned hgt){
    unsigned char* o=b; unsigned char t[200]; memset(t,0,200); unsigned char* q=t;
    put_u32(q,1);q+=4; q[0]=1;q+=1; memset(q,0,32);q+=32; put_u32(q,0xffffffff);q+=4;
    q[0]=3; q[1]=(unsigned char)hgt; q[2]=0; q[3]=0; q+=4; put_u32(q,0xffffffff);q+=4;
    q[0]=1;q+=1; put_u64(q,8*1000000);q+=8; q[0]=1;q[1]=0x51;q+=2; put_u32(q,0);q+=4;
    long tl=q-t; unsigned char mr[32]; sha256d(mr,t,tl);
    put_u32(o,1);o+=4; memcpy(o,prev,32);o+=32; memcpy(o,mr,32);o+=32;
    put_u32(o,1300000000u);o+=4; put_u32(o,0x207fffff);o+=4; put_u32(o,0);o+=4;
    o[0]=1;o+=1;                 /* tx-count varint: 1 tx (wire field!) */
    memcpy(o,t,tl);o+=tl; return o-b;
}
static void serve(int cfd){
    char cmd[12]; unsigned char pl[65536]; unsigned plen=0;
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen);
    unsigned char v[102]; memset(v,0,sizeof v); v[4]=1; p2p_write(cfd,"version",7,v,86);
    p2p_write(cfd,"verack",6,"",0);
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen);
    for(int n=0;n<50;n++){
        plen=0; if(p2p_read(cfd,cmd,pl,sizeof pl,&plen)<=0) return; cmd[11]=0;
        if(strncmp(cmd,"getheaders",10)==0){
            int zero=1; for(int z=0;z<32;z++) if(pl[5+z]){zero=0;break;}
            int from=0; if(zero) from=0; else { from=NB; for(int i=0;i<NB;i++) if(memcmp(pl+5,bh[i],32)==0) from=i+1; }
            int cnt=NB-from; if(cnt<0)cnt=0;
            if(cnt>0){ unsigned char hp[300]; hp[0]=cnt; int p=1; for(int i=from;i<NB;i++){memcpy(hp+p,blocks[i],80);hp[p+80]=0;p+=81;} p2p_write(cfd,"headers",7,hp,p);}
            else p2p_write(cfd,"headers",7,"\x00",1);
            break;
        }
    }
    /* after headers are sent, the sync loop will send getdata per header */
    for(int n=0;n<10;n++){
        plen=0; if(p2p_read(cfd,cmd,pl,sizeof pl,&plen)<=0) return; cmd[11]=0;
        if(strncmp(cmd,"getdata",7)==0){
            int found=-1; for(int i=0;i<NB;i++) if(memcmp(pl+5,bh[i],32)==0) found=i;
            if(found>=0) p2p_write(cfd,"block",5,blocks[found],(unsigned)blen[found]);
            else p2p_write(cfd,"block",5,"",0);
        }
    }
}
int main(void){
    unsigned char prev[32]; memset(prev,0,32);
    for(int i=0;i<2;i++){ blen[i]=mk(blocks[i],prev,i); unsigned nz=0; while(!pow_check(blocks[i])){nz++;put_u32(blocks[i]+76,nz);} block_hash(bh[i],blocks[i]); memcpy(prev,bh[i],32); NB++; }
    int l=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_port=htons(18444); a.sin_addr.s_addr=htonl(INADDR_ANY);
    int one=1; setsockopt(l,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    bind(l,(struct sockaddr*)&a,sizeof a); listen(l,4);
    fprintf(stderr,"testpeer listening 18444 (NB=%d)\n", NB);
    for(;;){ int c=accept(l,0,0); serve(c); close(c); }
    return 0;
}
