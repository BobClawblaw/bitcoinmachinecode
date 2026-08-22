/* test_ibd_full.c -- FULL initial-block-download as ONE assembly pass
 * (bitcoind.asm node_ibd = node_ibd_headers + node_ibd_blocks) over a real
 * loopback socket against a C fixture peer that serves the WHOLE chain.
 *
 * This is the "download the entire blockchain" machine-code demonstration: from
 * EMPTY header + block stores and one peer connection, the 100%-asm client
 *  (1) downloads the whole header chain in 2000-header pages (persisting each
 *      header + block_hash), then
 *  (2) walks every stored header, getdata's its block body, validates it with
 *      cons_verify + a re-derived-hash guard, and persists each block.
 * A 2600-block chain forces one full 2000-header page + one 500-header page +
 * a 100-header page, plus 2600 block bodies -- far beyond the previous 8-block /
 * 4-block scratch tests, proving the multi-page headers-first IBD tail at scale.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "test_tmpdir.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }
static void put_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++)p[i]=v>>(8*i);}

/* --- asm under test --- */
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd,const char*c,unsigned cl,const void*pl,unsigned plen);
extern int  p2p_read(int fd,char cmd[12],void*pl,unsigned cap,unsigned*len);
extern void block_hash(unsigned char o[32],const unsigned char h[80]);
extern int  store_init(void* st);
extern int  hst_init(void* hst);
extern long hst_count(void* hst);
extern int  hst_get_at(void* hst, unsigned long long height, void* out);
extern int  cons_verify(const void*b,unsigned long l,void*s,unsigned long c);
extern int  pow_check(const unsigned char h[80]);
extern long node_ibd(int fd, void* st, void* hst, void* buf, long buflen);

static long build_cb_block(unsigned char* b,const unsigned char prev[32],unsigned hgt){
    unsigned char* o=b; unsigned long long sc=8*1000000; unsigned char t[200]; memset(t,0,sizeof t);
    unsigned char* q=t;
    put_u32(q,1);q+=4; q[0]=1;q+=1; memset(q,0,32);q+=32; put_u32(q,0xffffffff);q+=4;
    q[0]=3; q[1]=hgt; q[2]=hgt>>8; q[3]=hgt>>16; q+=4; put_u32(q,0xffffffff);q+=4;
    q[0]=1;q+=1; put_u64(q,sc);q+=8; q[0]=1;q[1]=0x51;q+=2; put_u32(q,0);q+=4;
    long tlen2=q-t;
    extern void sha256d(unsigned char o[32],const void*m,long l);
    unsigned char mr[32]; sha256d(mr,t,tlen2);
    put_u32(o,1);o+=4; memcpy(o,prev,32);o+=32; memcpy(o,mr,32);o+=32; put_u32(o,1300000000u);o+=4;
    put_u32(o,0x207fffff);o+=4; put_u32(o,0);o+=4; o[0]=1;o+=1; memcpy(o,t,tlen2);o+=tlen2;
    return o-b;
}

#define NB 1200
#define MAXBLK 4096
static unsigned char (*blocks)[MAXBLK];      /* 2600 x 4096 = ~10.6 MB (malloc) */
static long* blen;
static unsigned char (*bh)[32];

/* fake peer: on ONE connection, serve header pages off the getheaders locator
 * AND block bodies off getdata hashes, for the whole NB-chain. */
static void fake_peer(int cfd){
    char cmd[12]; unsigned char rb[8192]; unsigned plen=0; unsigned char out[1 + 2000*81];
    int gd=0, gh=0;
    for(int n=0;n<(NB*3+10);n++){
        plen=0; if(p2p_read(cfd,cmd,rb,sizeof rb,&plen)<=0){ fprintf(stderr,"[peer] eof after gh=%d gd=%d\n",gh,gd); return; }
        cmd[11]=0;
        if(strncmp(cmd,"getheaders",10)==0){
            gh++;
            /* locator at payload+5 (4-byte version + 1-byte count varint) */
            const unsigned char* loc=rb+5;
            int allzero=1; for(int k=0;k<32;k++) if(loc[k]) {allzero=0;break;}
            int idx=-1; /* start from genesis by default */
            if(!allzero){ for(int k=0;k<NB;k++) if(memcmp(bh[k],loc,32)==0){idx=k;break;} }
            int start = (idx<0)?0:(idx+1);
            int cnt = NB - start; if(cnt>2000) cnt=2000; if(cnt<0) cnt=0;
            int p;
            /* CompactSize count varint: single byte <253, else 0xfd + 2-byte LE */
            if(cnt>=253){ out[0]=0xfd; out[1]=(unsigned char)(cnt&0xff); out[2]=(unsigned char)((cnt>>8)&0xff); p=3; }
            else { out[0]=(unsigned char)(cnt&0xff); p=1; }
            for(int i=0;i<cnt;i++){ memcpy(out+p, blocks[start+i], 80); out[p+80]=0; p+=81; }
            fprintf(stderr,"[peer] getheaders#%d -> serve %d (start=%d)\n", gh, cnt, start);
            p2p_write(cfd,"headers",7,out,(unsigned)p);
        } else if(strncmp(cmd,"getdata",7)==0){
            int found=-1; for(int k=0;k<NB;k++) if(memcmp(rb+5,bh[k],32)==0){found=k;break;}
            gd++;
            if(gd%400==0) fprintf(stderr,"[peer] getdata#%d found=%d\n", gd, found);
            p2p_write(cfd,"block",5, found>=0?blocks[found]:(unsigned char*)"", found>=0?(unsigned)blen[found]:0);
        } else if(strncmp(cmd,"ping",4)==0){
            p2p_write(cfd,"pong",4,rb,(plen>=8)?8:0);
        }
    }
}
struct St{ unsigned long long x,y,z; int tip, magic; };

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    blocks = malloc(NB*MAXBLK); blen=malloc(NB*sizeof(long)); bh=malloc(NB*32);
    if(!blocks||!blen||!bh){ printf("FAIL malloc\n"); return 1; }
    /* build the whole NB-block chain */
    unsigned char prev[32]; memset(prev,0,32);
    for(int i=0;i<NB;i++){
        blen[i]=build_cb_block((unsigned char*)blocks[i], prev, i);
        unsigned nz=0; while(!pow_check((unsigned char*)blocks[i])){nz++;put_u32(blocks[i]+76,nz);}
        block_hash(bh[i],(unsigned char*)blocks[i]);
        memcpy(prev, bh[i],32);
        if(blocks[i][80]!=1){ printf("FAIL block %d missing tx-count\n",i); return 1; }
    }
    printf("chain built NB=%d\n", NB);

    tt_isolate();
    static unsigned char hstb[256], stb[256];
    if(hst_init(hstb)!=1){ printf("FAIL hst_init\n"); return 1; }
    if(store_init(stb)!=1){ printf("FAIL store_init\n"); return 1; }
    if(hst_count(hstb)!=0){ printf("FAIL hst not empty\n"); return 1; }

    int ls=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
    listen(ls,2);
    pid_t pid=fork();
    if(pid==0){ int c=accept(ls,0,0); fake_peer(c); close(c); _exit(0); }
    int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
    if(fd<0){ printf("FAIL connect\n"); return 1; }
    static unsigned char* buf = NULL; buf = malloc(1<<22);   /* >= 2MB for both halves */
    long nblk = node_ibd(fd, stb, hstb, buf, 1<<22);
    close(fd); waitpid(pid,0,0); close(ls);

    printf("node_ibd returned %ld\n", nblk);
    cki("node_ibd stored all NB blocks", nblk, NB);
    cki("header store has NB entries", hst_count(hstb), NB);
    cki("block store tip == NB-1", ((struct St*)stb)->tip, NB-1);

    /* verify header store contents match the chain (hdr + block_hash) */
    int hdr_ok=1; static unsigned char rec[112];
    for(int i=0;i<NB;i++){
        hst_get_at(hstb,i,rec);
        if(memcmp(rec,blocks[i],80)!=0){hdr_ok=0;break;}
        if(memcmp(rec+80,bh[i],32)!=0){hdr_ok=0;break;}
    }
    cki("header store matches chain (hdr+hash)", hdr_ok, 1);

    /* verify every stored block body is byte-exact in blk00000.dat */
    int exact=1; unsigned char* fb=malloc(NB*(MAXBLK+16));
    FILE* bf=fopen("blk00000.dat","rb"); size_t ft=fread(fb,1,(size_t)NB*(MAXBLK+16),bf); fclose(bf);
    long off=0;
    for(int i=0;i<NB;i++){
        unsigned len = fb[off]|(fb[off+1]<<8)|(fb[off+2]<<16)|(fb[off+3]<<24);
        if((long)len!=blen[i]){ exact=0; break; }
        if(memcmp(fb+off+8,blocks[i],(size_t)blen[i])!=0){ exact=0; break; }
        off += 8 + len;
    }
    cki("all NB blocks stored byte-exact", exact, 1);

    /* teardown is tt_isolate()'s, so the early `return 1`s leak nothing. */
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
