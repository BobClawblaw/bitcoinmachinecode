/* test_ibd_blocks.c -- loopback test of the BLOCK-BODY download-off-persisted-
 * header-chain path (asm node_ibd_blocks in bitcoind.asm): after a header chain
 * has been persisted (bitcoin_headers.asm), node_ibd_blocks walks each stored
 * header, getdata's its block_hash, receives+validates the `block`, requires the
 * received block's block_hash to match the stored header hash, and store_appends
 * it to the block store.
 *
 * A C fixture peer serves the block bodies for an N-block chain; the node side is
 * 100% assembly. Also verifies a NEGATIVE: a peer that serves a WRONG block body
 * (whose block_hash != the stored header hash) is rejected by the hash-mismatch
 * guard, not blindly stored.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "test_tmpdir.h"

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }
static void put_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++)p[i]=v>>(8*i);}

/* --- asm exports --- */
extern long node_ibd_blocks(int fd, void* st, void* hst, long start_h, void* buf, long buflen);
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd,const char*cmd,unsigned cmdlen,const void*pl,unsigned plen);
extern int  p2p_read(int fd,char cmd[12],void*pl,unsigned cap,unsigned*len);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern int  store_init(void* st);
extern int  hst_init(void* hst);
extern long hst_append(void* hst, const void* hdr, const void* hash);
extern long hst_count(void* hst);
extern int  cons_verify(const void* b, unsigned long l, void* s, unsigned long c);
extern int  pow_check(const unsigned char h[80]);

/* --- block builder (single-coinbase, valid; from test_bitcoind_sync) --- */

static long build_cb_block(unsigned char* b, const unsigned char prev[32], unsigned hgt){
    unsigned char* o=b;
    unsigned long long sc=8*1000000;
    unsigned char t[200]; memset(t,0,sizeof t);
    unsigned char* q=t;
    put_u32(q,1); q+=4;
    q[0]=1; q+=1;
    memset(q,0,32); q+=32;
    put_u32(q,0xffffffff); q+=4;
    q[0]=3; q[1]=(unsigned char)hgt; q[2]=(unsigned char)(hgt>>8); q[3]=(unsigned char)(hgt>>16); q+=4;
    put_u32(q,0xffffffff); q+=4;
    q[0]=1; q+=1;
    put_u64(q, sc); q+=8;
    q[0]=1; q[1]=0x51; q+=2;
    put_u32(q,0); q+=4;
    long tlen2 = q - t;
    extern void sha256d(unsigned char o[32],const void*m,long l);
    unsigned char mr[32]; sha256d(mr, t, tlen2);
    put_u32(o,1); o+=4;
    memcpy(o,prev,32); o+=32;
    memcpy(o,mr,32); o+=32;
    put_u32(o,1300000000u); o+=4;
    put_u32(o,0x207fffff); o+=4;
    put_u32(o,0); o+=4;
    o[0]=1; o+=1;
    memcpy(o,t,tlen2); o+=tlen2;
    return (long)(o - b);
}

#define NB 4
static unsigned char blocks[NB][4096];
static long blen[NB];
static unsigned char bh[NB][32];
static int evil_which = -1;   /* if >=0, peer serves blocks[evil_which^?] for that hash */

/* fake peer: read getdata, serve the block whose hash matches (or a WRONG block
 * for evil_which). Also sends one ping at the start to prove chatter-draining. */
static void fake_peer(int cfd, int do_ping){
    if(do_ping){
        unsigned char n[8]={0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
        p2p_write(cfd,"ping",4,n,8);
    }
    char cmd[12]; unsigned char pl[8192]; unsigned plen=0;
    for(int i=0;i<40;i++){
        plen=0; if(p2p_read(cfd,cmd,pl,sizeof pl,&plen)<=0) return;
        cmd[11]=0;
        if(strncmp(cmd,"getdata",7)==0){
            /* payload [count][type int32 0x02][hash32] -> hash at +5 */
            int found=-1;
            for(int k=0;k<NB;k++) if(memcmp(pl+5,bh[k],32)==0){found=k;break;}
            if(found>=0){
                int serve=found;
                if(evil_which>=0 && found==evil_which) serve = (found+1)%NB; /* wrong block */
                p2p_write(cfd,"block",5,blocks[serve],(unsigned)blen[serve]);
            } else {
                p2p_write(cfd,"block",5,"",0);
            }
        }
    }
}

struct St { unsigned long long blk_fd, idx_fd, next_offset; int tip, magic; };

int main(void){
    /* build a valid NB-block chain */
    unsigned char prev[32]; memset(prev,0,32);
    for(int i=0;i<NB;i++){
        blen[i]=build_cb_block(blocks[i], prev, i);
        unsigned int nz=0; while(!pow_check(blocks[i])){ nz++; put_u32(blocks[i]+76,nz); }
        block_hash(bh[i], blocks[i]);
        memcpy(prev, bh[i], 32);
        if(blocks[i][80]!=1){ printf("FAIL block %d missing tx-count\n",i); return 1; }
    }

    /* one private temp dir; block store + header store share the CWD, as the
     * daemon's datadir layout does */
    tt_isolate();

    /* header store `hdr.dat` + block store `blk00000.dat` both in this dir */
    static unsigned char hstb[256], stb[256];
    if(hst_init(hstb)!=1){ printf("FAIL hst_init\n"); return 1; }
    if(store_init(stb)!=1){ printf("FAIL store_init\n"); return 1; }
    /* persist the header chain (header[0..80] ++ block_hash[80..112]) */
    for(int i=0;i<NB;i++) if(hst_append(hstb, blocks[i], bh[i])!=i+1){ printf("FAIL hst_append %d\n",i); return 1; }
    if(hst_count(hstb)!=NB){ printf("FAIL hst_count\n"); return 1; }

    /* loopback socket + fork the serving peer (evil off for the happy path) */
    int ls=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
    listen(ls,2);
    pid_t pid=fork();
    if(pid==0){ int c=accept(ls,0,0); fake_peer(c,0); close(c); _exit(0); }

    int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
    if(fd<0){ printf("FAIL connect\n"); return 1; }
    static unsigned char buf[65536];
    long nst = node_ibd_blocks(fd, stb, hstb, 0, buf, sizeof buf);
    close(fd); waitpid(pid,0,0); close(ls);
    cki("node_ibd_blocks stored all NB", nst, NB);

    /* verify each stored block came back byte-exact: read blk00000.dat directly */
    int exact=1;
    FILE* bf=fopen("blk00000.dat","rb"); unsigned char fb[65536];
    size_t ft=fread(fb,1,sizeof fb,bf); fclose(bf);
    /* framing: [u32 len][u32 magic][raw] per block */
    long off=0; struct St* s=(struct St*)stb;
    for(int i=0;i<NB;i++){
        if(off+8>(long)ft){ exact=0; break; }          /* the file must hold every frame it claims */
        unsigned len = fb[off]|(fb[off+1]<<8)|(fb[off+2]<<16)|(fb[off+3]<<24);
        if(len!=(unsigned)blen[i]){ exact=0; break; }
        if(off+8+(long)len>(long)ft){ exact=0; break; }
        if(memcmp(fb+off+8, blocks[i], (size_t)blen[i])!=0){ exact=0; break; }
        off += 8 + len;
    }
    cki("all NB blocks stored byte-exact", exact, 1);
    cki("store tip_height == NB-1", s->tip, NB-1);

    /* ---- NEGATIVE: wrong block body served -> must be rejected (hash mismatch) ---- */
    /* fresh stores + peer that serves a wrong block for height 1 */
    static unsigned char stb2[256], hstb2[256];
    hst_init(hstb2); store_init(stb2);
    for(int i=0;i<NB;i++) hst_append(hstb2, blocks[i], bh[i]);
    evil_which = 1;
    int ls2=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a2; memset(&a2,0,sizeof a2); a2.sin_family=AF_INET; a2.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(ls2,(struct sockaddr*)&a2,sizeof a2); socklen_t al2=sizeof a2; getsockname(ls2,(struct sockaddr*)&a2,&al2);
    listen(ls2,2);
    pid_t pid2=fork();
    if(pid2==0){ int c=accept(ls2,0,0); fake_peer(c,0); close(c); _exit(0); }
    int fd2=tcp_connect_ip(htonl(INADDR_LOOPBACK), a2.sin_port);
    static unsigned char buf2[65536];
    long nst2 = node_ibd_blocks(fd2, stb2, hstb2, 0, buf2, sizeof buf2);
    close(fd2); waitpid(pid2,0,0); close(ls2);
    cki("evil wrong-block -> -1 rejected", nst2, -1);
    /* only the leading valid block(s) before the mismatch get stored (block0 ok) */
    cki("evil: only leading blocks stored", ((struct St*)stb2)->tip, 0);

    /* ---- NEGATIVE (REORG): peer feeds a block whose prevhash does NOT chain
     * ---- from our stored chain (a divergent branch) -> node must reject it,
     * ---- never store out-of-chain data. Build a fake 'forked' block at height
     * ---- 2 whose prevhash != stored block-1's hash. */
    {
        static unsigned char stb3[256], hstb3[256];
        hst_init(hstb3); store_init(stb3);
        for(int i=0;i<3;i++) hst_append(hstb3, blocks[i], bh[i]);  /* chain: blocks 0,1,2 */
        /* a forked height-2 block using a bogus prevhash (NOT bh[1]) */
        static unsigned char forkb[256];
        unsigned char bogusprev[32]; memset(bogusprev,0xAB,32);
        long fblen = build_cb_block(forkb, bogusprev, 2);
        /* peer: read each getdata, serve the block matching the requested hash,
         * EXCEPT serve the forked (non-chaining) blob for the height-2 hash. */
        int ls3=socket(AF_INET,SOCK_STREAM,0);
        struct sockaddr_in a3; memset(&a3,0,sizeof a3); a3.sin_family=AF_INET; a3.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        bind(ls3,(struct sockaddr*)&a3,sizeof a3); socklen_t al3=sizeof a3; getsockname(ls3,(struct sockaddr*)&a3,&al3);
        listen(ls3,2);
        pid_t pid3=fork();
        if(pid3==0){ int c=accept(ls3,0,0);
            char cmd[12]; static unsigned char pl[4096]; unsigned plen=0;
            while(p2p_read(c,cmd,pl,sizeof pl,&plen)>0){
                if(strncmp(cmd,"getdata",7)==0){
                    /* requested hash at pl+5 */
                    unsigned char rh[32]; memcpy(rh,pl+5,32);
                    if(memcmp(rh,bh[0],32)==0) p2p_write(c,"block",5,blocks[0],blen[0]);
                    else if(memcmp(rh,bh[1],32)==0) p2p_write(c,"block",5,blocks[1],blen[1]);
                    else p2p_write(c,"block",5,forkb,(unsigned)fblen);  /* h2 -> forked */
                }
            }
            close(c); _exit(0); }
        int fd3=tcp_connect_ip(htonl(INADDR_LOOPBACK), a3.sin_port);
        static unsigned char buf3[65536];
        long nst3 = node_ibd_blocks(fd3, stb3, hstb3, 0, buf3, sizeof buf3);
        close(fd3); waitpid(pid3,0,0); close(ls3);
        cki("reorg divergent prevhash -> rejected (-1)", nst3, -1);
        cki("reorg: forked block NOT stored (store tip stays 1)", ((struct St*)stb3)->tip, 1);
    }

    /* teardown is tt_isolate()'s; the old rm -rf ran only on this success
     * path, so every early `return 1` above used to leak the directory. */
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
