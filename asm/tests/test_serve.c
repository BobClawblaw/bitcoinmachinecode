/* test_serve.c -- harness for asm bitcoin_serve.asm (node_serve_loop).
 * Builds a small store + asm hash index, forks a server that does
 * node_accept_handshake then node_serve_loop, and a client that handshakes,
 * sends getdata/ping, and verifies the served blocks are byte-exact and pong
 * echoes the nonce. Proves the all-asm server answers a real peer connection. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>

extern long node_handshake(int fd);
extern int  node_accept_handshake(int fd);
extern long node_serve_loop(int fd, int lfd, void* st, void* ht_idx, void* out, long cap);
extern int  tcp_connect_ip(unsigned, unsigned short);
extern long store_init(void* st);
extern long store_append(void* st, const unsigned char h[32], const void* blk, long blen);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void sha256d(unsigned char o[32], const void* m, long l);
extern long p2p_getdata_block(unsigned char* out, const unsigned char hash[32]);
extern long p2p_write(int, const char*, unsigned, const void*, unsigned);
extern int  p2p_read(int, char[12], void*, unsigned, unsigned*);
extern void idx_init(void* idx, unsigned long slots);
extern int  idx_put(void* idx, const unsigned char hash[32], long height);
extern long p2p_ping(unsigned char* out, uint64_t nonce);

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }
static void put_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++)p[i]=v>>(8*i);}

#define NB 8
static int TEST_NB = 8;   /* full: all 8 blocks */
static unsigned char blk[NB][600];
static long blen[NB];
static unsigned char bhash[NB][32];

static void build_chain(void){
    unsigned char prev[32]; memset(prev,0,32);
    for(int i=0;i<NB;i++){
        unsigned char* b=blk[i];
        /* build the coinbase tx at blk+81 (after the 80-byte header + tx-count) */
        unsigned char* t=blk[i]+81; unsigned char* t0=t;
        put_u32(t,1);t+=4; t[0]=1;t+=1; memset(t,0,32);t+=32; put_u32(t,0xffffffff);t+=4;
        t[0]=3; t[1]=(unsigned char)i; t[2]=0; t[3]=0; t+=4; put_u32(t,0xffffffff);t+=4;
        t[0]=1;t+=1; put_u64(t,5000000000ull);t+=8; t[0]=1;t[1]=0x51;t+=2; put_u32(t,0);t+=4;
        long txlen = t-t0;
        /* header (80 bytes) */
        unsigned char* h=blk[i];
        put_u32(h,1); memcpy(h+4,prev,32);
        { unsigned char seed[8]; for(int k=0;k<8;k++) seed[k]=(unsigned char)(i*11+k); sha256d(h+36,seed,8); }
        put_u32(h+68,1300000000u); put_u32(h+72,0x207fffff); put_u32(h+76,(unsigned)i*3);
        /* tx-count varint (1) then the coinbase */
        b[80]=1;
        blen[i]=81+txlen;
        block_hash(bhash[i], blk[i]); memcpy(prev,bhash[i],32);
    }
}

int main(void){
    setbuf(stdout,NULL);
    build_chain();
    static unsigned char stbuf[4096];
    if(store_init(stbuf)!=1){ printf("FAIL store_init\n"); return 1; }
    for(int i=0;i<TEST_NB;i++) store_append(stbuf, bhash[i], blk[i], blen[i]);

    /* build asm hash->height index over the block hashes */
    static unsigned char idx[24 + 256*48];
    idx_init(idx, 256);
    for(int i=0;i<TEST_NB;i++) idx_put(idx, bhash[i], i);

    static unsigned char out[1<<20];
    /* loopback TCP */
    int ls=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
    listen(ls,2);

    pid_t pid=fork();
    if(pid==0){
        int c=accept(ls,0,0);
        if(c<0) _exit(3);
        if(node_accept_handshake(c)!=1) _exit(4);
        long served = node_serve_loop(c, -1, stbuf, idx, out, (long)sizeof out);
        _exit(served>=0?(int)served:9);
    }
    int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
    if(fd<0){ printf("FAIL connect\n"); return 1; }
    struct timeval tv; tv.tv_sec=8; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    cki("handshake", node_handshake(fd), 1);

    /* the serve loop advertises its min-relay-feerate (a `feefilter`) as the
       first post-handshake message (as Core does after verack); drain it so the
       getdata/ping reads below sync to the reply stream. */
    {
        char dc[12]; static unsigned char db[64]; unsigned dbl=0;
        cki("drain leading feefilter", p2p_read(fd,dc,db,sizeof db,&dbl)>0 && !strncmp(dc,"feefilter",9) && dbl==8, 1);
    }

    /* ping -> pong */
    unsigned char pg[8]; uint64_t nonce=0xdeadbeefcafebabeull;
    p2p_ping(pg, nonce);
    long w = p2p_write(fd,"ping",4, pg, 8); cki("ping write", w>0?1:0, 1);
    char c2[12]; static unsigned char rp[1024]; unsigned rl=0;
    int rr=p2p_read(fd,c2,rp,sizeof rp,&rl);
    cki("recv pong", rr>0 && !strncmp(c2,"pong",4)?1:0, 1);
    cki("pong echoes nonce", (rr>0 && rl>=8 && memcmp(rp,pg,8)==0)?1:0, 1);

    /* getdata for each block -> byte-exact block back */
    int allok=1;
    for(int i=0;i<TEST_NB;i++){
        unsigned char gd[64]; long l=p2p_getdata_block(gd, bhash[i]);
        p2p_write(fd,"getdata",7, gd, (unsigned)l);
        char c3[12]; static unsigned char blkbuf[1<<20]; unsigned bl=0;
        int r2=p2p_read(fd,c3,blkbuf,sizeof blkbuf,&bl);
        if(r2<=0 || strncmp(c3,"block",5)!=0 || (long)bl!=blen[i] || memcmp(blkbuf,blk[i],(size_t)bl)!=0){
            if(allok){ printf("  served block %d mismatch (r=%d cmd=%.5s len=%u exp=%ld) first8=%02x%02x%02x%02x%02x%02x%02x%02x\n", i, r2, c3, bl, blen[i], blkbuf[0],blkbuf[1],blkbuf[2],blkbuf[3],blkbuf[4],blkbuf[5],blkbuf[6],blkbuf[7]); }
            allok=0;
        }
    }
    cki("all served blocks byte-exact via asm server", allok, 1);

    /* ---- STRESS: multi-inv getdata (one message requests several blocks) ---- */
    /* build getdata with TEST_NB inv items: varint(TEST_NB) + TEST_NB*(u32 type, 32B hash) */
    static unsigned char mget[1<<12];
    int mp = 0; mget[mp++] = (unsigned char)TEST_NB;         /* single-byte varint (<=252) */
    for(int i=0;i<TEST_NB;i++){ unsigned char iv[36]; memset(iv,0,4); iv[0]=2; /* MSG_BLOCK */
                                iv[4]|=bhash[i][0]; memcpy(iv+4,bhash[i],32); memcpy(mget+mp,iv,36); mp+=36; }
    p2p_write(fd,"getdata",7,mget,(unsigned)mp);
    int mall=1;
    for(int i=0;i<TEST_NB;i++){
        char c4[12]; static unsigned char blkbuf2[1<<20]; unsigned bl2=0;
        int rr2=p2p_read(fd,c4,blkbuf2,sizeof blkbuf2,&bl2);
        /* compare to the matching block by length then bytes */
        if(rr2<=0||strncmp(c4,"block",5)!=0){ mall=0; break; }
        int matched=-1;
        for(int j=0;j<TEST_NB;j++) if((long)bl2==blen[j]&&memcmp(blkbuf2,blk[j],(size_t)bl2)==0){matched=j;break;}
        if(matched<0) mall=0;
    }
    cki("multi-inv getdata: all blocks byte-exact", mall, 1);

    /* ---- STRESS: repeated ping/pong after serving (loop-continuation sanity) ---- */
    int pingok=1;
    for(int k=0;k<25;k++){
        uint64_t n2=0x1234abcd00000001ull+k;
        p2p_ping(pg,n2); long w2=p2p_write(fd,"ping",4,pg,8);
        char c5[12]; static unsigned char rp2[1024]; unsigned rl2=0;
        int rr3=p2p_read(fd,c5,rp2,sizeof rp2,&rl2);
        if(w2<=0||rr3<=0||strncmp(c5,"pong",4)!=0||rl2<8||memcmp(rp2,pg,8)!=0) pingok=0;
    }
    cki("25x ping/pong after multi-getdata (loop stable)", pingok, 1);

    close(fd); waitpid(pid,0,0); close(ls);
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
