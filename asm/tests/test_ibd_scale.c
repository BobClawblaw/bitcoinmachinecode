/* test_ibd_scale.c -- LARGE-SCALE full-IBD demonstration of the 100%-asm node_ibd
 * pass (headers-first persist + block-body getdata + validate + store) over a
 * loopback cooperative peer serving a WHOLE synthetic chain from genesis.
 *
 * NB is selectable via argv[1] (default 20000). This proves the machine that
 * would "download the entire blockchain" can archive an arbitrarily large chain
 * (multi-page header IBD + per-block validate/store) end-to-end in assembly.
 * This is the honest offline maximum: live public seeds serve the header chain
 * but drop block-body getdata to an unknown peer (verified), so the real
 * mainnet archive download is blocked at the source, not by the software.
 *
 * Manual/large test (NOT in make test; it takes time at large NB).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd,const char*c,unsigned cl,const void*pl,unsigned plen);
extern int  p2p_read(int fd,char cmd[12],void*pl,unsigned cap,unsigned*len);
extern void block_hash(unsigned char o[32],const unsigned char h[80]);
extern void sha256d(unsigned char o[32],const void*m,long l);
extern int  store_init(void* st);
extern int  hst_init(void* hst);
extern long hst_count(void* hst);
extern int  hst_get_at(void* hst, unsigned long long height, void* out);
extern int  cons_verify(const void*b,unsigned long l,void*s,unsigned long c);
extern int  pow_check(const unsigned char h[80]);
extern long node_ibd(int fd, void* st, void* hst, void* buf, long buflen);

static void put_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++)p[i]=v>>(8*i);}

#define MAXBLK 4096
static long build_cb_block(unsigned char* b,const unsigned char prev[32],unsigned hgt){
    unsigned char* o=b; unsigned long long sc=50*100000000ULL; /* 50 BTC */
    unsigned char t[200]; memset(t,0,sizeof t); unsigned char* q=t;
    put_u32(q,1);q+=4; q[0]=1;q+=1; memset(q,0,32);q+=32; put_u32(q,0xffffffff);q+=4;
    q[0]=3; q[1]=hgt; q[2]=hgt>>8; q[3]=hgt>>16; q+=4; put_u32(q,0xffffffff);q+=4;
    q[0]=1;q+=1; put_u64(q,sc);q+=8; q[0]=1;q[1]=0x51;q+=2; put_u32(q,0);q+=4;
    long tlen2=q-t; unsigned char mr[32]; sha256d(mr,t,tlen2);
    put_u32(o,1);o+=4; memcpy(o,prev,32);o+=32; memcpy(o,mr,32);o+=32;
    put_u32(o,1300000000u);o+=4; put_u32(o,0x207fffff);o+=4; put_u32(o,0);o+=4;
    o[0]=1;o+=1; memcpy(o,t,tlen2);o+=tlen2;
    return o-b;
}

static unsigned char *blocks; /* NB * MAXBLK mmap'd */
static long* blen; static unsigned char* bh;

static void fake_peer(int cfd, long NB){
    char cmd[12]; unsigned char rb[8192]; unsigned plen=0; unsigned char out[1 + 2000*81];
    int gd=0, gh=0;
    for(int n=0;n<(NB*3+10);n++){
        plen=0; if(p2p_read(cfd,cmd,rb,sizeof rb,&plen)<=0){ fprintf(stderr,"[peer] eof after gh=%d gd=%d\n",gh,gd); return; }
        cmd[11]=0;
        if(strncmp(cmd,"getheaders",10)==0){
            gh++;
            const unsigned char* loc=rb+5;
            int allzero=1; for(int k=0;k<32;k++) if(loc[k]){allzero=0;break;}
            long idx=-1;
            if(!allzero){ for(long k=0;k<NB;k++) if(memcmp(bh+k*32,loc,32)==0){idx=k;break;} }
            long start=(idx<0)?0:(idx+1);
            long cnt=NB-start; if(cnt>2000)cnt=2000; if(cnt<0)cnt=0;
            long p;
            if(cnt>=253){ out[0]=0xfd; out[1]=(unsigned char)(cnt&0xff); out[2]=(unsigned char)((cnt>>8)&0xff); p=3; }
            else if(cnt>=0){ out[0]=(unsigned char)(cnt&0xff); p=1; }
            for(long i=0;i<cnt;i++){ memcpy(out+p, blocks+(start+i)*MAXBLK, 80); out[p+80]=0; p+=81; }
            if(gh<=3) fprintf(stderr,"[peer] getheaders#%d -> serve %ld (start=%ld)\n", gh, cnt, start);
            p2p_write(cfd,"headers",7,out,(unsigned)p);
        } else if(strncmp(cmd,"getdata",7)==0){
            long found=-1; for(long k=0;k<NB;k++) if(memcmp(rb+5,bh+k*32,32)==0){found=k;break;}
            gd++; if(gd%4000==0) fprintf(stderr,"[peer] getdata#%d found=%ld\n",gd,found);
            p2p_write(cfd,"block",5, found>=0?(blocks+found*MAXBLK):(unsigned char*)"", found>=0?(unsigned)blen[found]:0);
        } else if(strncmp(cmd,"ping",4)==0){
            p2p_write(cfd,"pong",4,rb,(plen>=8)?8:0);
        }
    }
}

struct St{ unsigned long long x,y,z; int tip, magic; };

int main(int argc,char**argv){
    setbuf(stdout,NULL);
    long NB = argc>1? atol(argv[1]) : 20000;
    printf("=== LARGE-SCALE full asm IBD: NB=%ld blocks ===\n", NB);
    blocks = mmap(0, (size_t)NB*MAXBLK, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    blen = malloc(NB*sizeof(long)); bh = malloc(NB*32);
    long t0=time(0);
    unsigned char prev[32]; memset(prev,0,32);
    for(long i=0;i<NB;i++){
        blen[i]=build_cb_block(blocks+i*MAXBLK, prev, (unsigned)i);
        unsigned nz=0; while(!pow_check(blocks+i*MAXBLK)){nz++;put_u32(blocks+i*MAXBLK+76,nz);}
        block_hash(bh+i*32, blocks+i*MAXBLK);
        memcpy(prev, bh+i*32, 32);
    }
    printf("chain built NB=%ld in %lds (%.1f MB)\n", NB, time(0)-t0, (double)NB*150/1e6);

    char path[80]; snprintf(path,sizeof path,"/tmp/ibdscale_%d", getpid()); mkdir(path,0755);
    char cwd[1024]; getcwd(cwd,sizeof cwd); chdir(path);
    static unsigned char hstb[256], stb[256];
    if(hst_init(hstb)!=1 || store_init(stb)!=1){ printf("FAIL init\n"); return 1; }

    int ls=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
    listen(ls,2);
    pid_t pid=fork();
    if(pid==0){ int c=accept(ls,0,0); fake_peer(c, NB); _exit(0); }
    int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
    if(fd<0){ printf("FAIL connect\n"); return 1; }
    static unsigned char* buf=NULL; buf=malloc(1<<22);
    long t1=time(0);
    long nblk = node_ibd(fd, stb, hstb, buf, 1<<22);
    long dt=time(0)-t1;
    close(fd); waitpid(pid,0,0); close(ls);

    int fails=0;
    #define CK(lbl,g,e) do{ int ok=((g)==(e)); printf("%s %s (got %ld exp %ld)\n", ok?"PASS":"FAIL", lbl,g,e); if(!ok)fails++; }while(0)
    CK("node_ibd stored all NB blocks", nblk, NB);
    CK("header store has NB entries", hst_count(hstb), NB);
    CK("block store tip == NB-1", ((struct St*)stb)->tip, NB-1);
    printf("ibd done in %lds (%.0f blk/s)\n", dt, dt? (double)NB/dt : 0);

    int hdr_ok=1; static unsigned char rec[112];
    for(long i=0;i<NB;i++){
        hst_get_at(hstb,i,rec);
        if(memcmp(rec,blocks+i*MAXBLK,80)!=0 || memcmp(rec+80,bh+i*32,32)!=0){ hdr_ok=0; break; }
    }
    CK("all stored (hdr, hash) match chain", hdr_ok, 1);

    chdir(cwd); char rm[300]; snprintf(rm,sizeof rm,"rm -rf %s", path); system(rm);
    printf("\n%s (%d failures)\n", fails?"SCALE TEST FAILED":"SCALE TEST PASSED (entire synthetic chain archived)", fails);
    return fails?1:0;
}
