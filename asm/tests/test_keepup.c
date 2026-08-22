/* test_keepup.c -- harness for asm bitcoin_serve.asm node_serve_loop's
 * INBOUND BLOCK keep-up path (.do_block): a peer pushes a `block` message the
 * server has not yet downloaded; the server must cons_verify it, store_append
 * it, index it, and then be able to serve it back byte-exact -- i.e. the node
 * advances its own store from peer-pushed data, not just relays.
 *
 * This is the receive half of the "keep up to date as new blocks are generated"
 * requirement that the serve loop previously lacked (it relayed inv/getdata but
 * dropped the block response). Models the client/server fork used by test_serve.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include "test_tmpdir.h"

extern long node_handshake(int fd);
extern int  node_accept_handshake(int fd);
extern long node_serve_loop(int fd, int lfd, void* st, void* ht_idx, void* out, long cap);
extern int  tcp_connect_ip(unsigned, unsigned short);
extern long store_init(void* st);
extern long store_append(void* st, const unsigned char h[32], const void* blk, long blen);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void sha256d(unsigned char o[32], const void* m, long l);
extern int  pow_check(const unsigned char hdr[80]);
extern long p2p_getdata_block(unsigned char* out, const unsigned char hash[32]);
extern long p2p_write(int, const char*, unsigned, const void*, unsigned);
extern int  p2p_read(int, char[12], void*, unsigned, unsigned*);
extern void idx_init(void* idx, unsigned long slots);
extern int  idx_put(void* idx, const unsigned char hash[32], long height);

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }
static void put_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++)p[i]=v>>(8*i);}

#define NB 8
/* server starts with only the first NB-1 blocks; block NB-1 is the "new" one
 * the peer will push. */
static int HAVE = NB-1;
static unsigned char blk[NB][600];
static long blen[NB];
static unsigned char bhash[NB][32];

static void build_chain(void){
    unsigned char prev[32]; memset(prev,0,32);
    for(int i=0;i<NB;i++){
        unsigned char* b=blk[i];
        unsigned char* t=b+81; unsigned char* t0=t;
        put_u32(t,1);t+=4; t[0]=1;t+=1; memset(t,0,32);t+=32; put_u32(t,0xffffffff);t+=4;
        t[0]=3; t[1]=(unsigned char)i; t[2]=0; t[3]=0; t+=4; put_u32(t,0xffffffff);t+=4;
        t[0]=1;t+=1; put_u64(t,5000000000ull);t+=8; t[0]=1;t[1]=0x51;t+=2; put_u32(t,0);t+=4;
        long txlen=t-t0;
        /* header (80 bytes): version, prev, MERKLE ROOT = the coinbase's real
         * txid (sha256d of the raw coinbase) -- cons_verify recomputes this and
         * REQUIRES it to match, so the pushed block must be consensus-valid. */
        unsigned char mr[32]; sha256d(mr, t0, txlen);
        unsigned char* h=b;
        put_u32(h,1); memcpy(h+4,prev,32); memcpy(h+36,mr,32);
        put_u32(h+68,1300000000u); put_u32(h+72,0x207fffff);
        /* PoW nonce: 0x207fffff is the easiest target, but pow_check still
         * needs hash < target. Bump nonce until it passes (deterministic). */
        unsigned nz=0; while(!pow_check(b)){ nz++; put_u32(b+76,nz); if(nz>1000000){ nz=0; break; } }
        b[80]=1;
        blen[i]=81+txlen;
        block_hash(bhash[i], b); memcpy(prev,bhash[i],32);
    }
}

int main(void){
    tt_isolate();   /* private working dir: the store below writes index.dat/blk00000.dat by bare name */
    setbuf(stdout,NULL);
    signal(SIGPIPE, SIG_IGN);   /* as the daemon does (main.c): a broken peer
                                   socket must not kill the node mid-write */
    build_chain();
    static unsigned char stbuf[4096];
    if(store_init(stbuf)!=1){ printf("FAIL store_init\n"); return 1; }
    /* server stores only HAVE blocks (the chain minus the "new" last block) */
    for(int i=0;i<HAVE;i++) store_append(stbuf, bhash[i], blk[i], blen[i]);
    /* hash index over the stored set */
    static unsigned char idx[24 + 256*48];
    idx_init(idx, 256);
    for(int i=0;i<HAVE;i++) idx_put(idx, bhash[i], i);

    static unsigned char out[1<<20];
    int ls=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
    listen(ls,2);

    pid_t pid=fork();
    if(pid==0){
        int c=accept(ls,0,0);
        if(c<0) _exit(3);
        if(node_accept_handshake(c)!=1) _exit(4);
        /* lfd=-1 (no logger). LONG-RUNNING loop now: exits only on close. */
        long served = node_serve_loop(c, -1, stbuf, idx, out, (long)sizeof out);
        _exit(served>=0?(int)served:9);
    }
    int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
    if(fd<0){ printf("FAIL connect\n"); return 1; }
    struct timeval tv; tv.tv_sec=8; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    cki("handshake", node_handshake(fd), 1);
    /* drain the leading feefilter the serve loop advertises post-handshake */
    {
        char dc[12]; static unsigned char db[64]; unsigned dbl=0;
        cki("drain leading feefilter", p2p_read(fd,dc,db,sizeof db,&dbl)>0 && !strncmp(dc,"feefilter",9) && dbl==8, 1);
    }

    int newidx = HAVE;   /* height of the last block = the one the peer pushes */

    /* 0) minimal: confirm the connection is alive right now (ping->pong) */
    {
        uint64_t nn=0x0a0b0c0d0e0f1011ull; unsigned char pp[8]; memcpy(pp,&nn,8); p2p_write(fd,"ping",4,pp,8);
        char cc[12]; static unsigned char rq[64]; unsigned rql=0;
        int rr=p2p_read(fd,cc,rq,sizeof rq,&rql);
        cki("probe ping->pong", rr>0 && !strncmp(cc,"pong",4)?1:0, 1);
    }

    /* 1) before the push, getdata for the new block's hash must FAIL (server
     *    does not have it yet) -> verifies the precondition. */
    {
        unsigned char gd[64]; long l=p2p_getdata_block(gd, bhash[newidx]);
        p2p_write(fd,"getdata",7, gd, (unsigned)l);
        char c3[12]; static unsigned char r1[1<<20]; unsigned n1=0;
        int r=p2p_read(fd,c3,r1,sizeof r1,&n1);
        /* server should NOT answer with a block (it lacks it) -> read would time
         * out / EOF. We detect "no block" by the read not returning a block. */
        cki("new block absent before push", (r<=0 || strncmp(c3,"block",5)!=0)?1:0, 1);
        /* confirm the connection is STILL alive after the absent-getdata */
        uint64_t nn=0x2222333344445555ull; unsigned char pp[8]; memcpy(pp,&nn,8); p2p_write(fd,"ping",4,pp,8);
        char cc[12]; static unsigned char rq[64]; unsigned rql=0;
        int rr=p2p_read(fd,cc,rq,sizeof rq,&rql);
        cki("server alive after absent-getdata", rr>0 && !strncmp(cc,"pong",4)?1:0, 1);
    }

    /* 2) peer PUSHES the new block as an inbound `block` message */
    {
        long w=p2p_write(fd,"block",5, blk[newidx], (unsigned)blen[newidx]);
        cki("push new block", w>0?1:0, 1);
    }

    /* 3) now getdata for the new block's hash must SUCCEED byte-exact: proves
     *    the server validated, stored, AND indexed the pushed block. NOTE: the
     *    serve loop's tip-watch announces the new tip (inv/headers) right after
     *    storing it, so we must drain non-`block` frames and keep reading until
     *    the requested block (or a hard failure) arrives. */
    {
        unsigned char gd[64]; long l=p2p_getdata_block(gd, bhash[newidx]);
        p2p_write(fd,"getdata",7, gd, (unsigned)l);
        int got=0;
        for(int tries=0; tries<16 && !got; tries++){
            char c3[12]; static unsigned char r1[1<<20]; unsigned n1=0;
            int r=p2p_read(fd,c3,r1,sizeof r1,&n1);
            if(r<=0) break;
            if(!strncmp(c3,"block",5) && (long)n1==blen[newidx] &&
               memcmp(r1,blk[newidx],(size_t)n1)==0){ got=1; break; }
            /* else: drain an announcement (inv/headers/pong/etc) and retry */
        }
        cki("pushed block now served byte-exact", got, 1);
    }

    /* 4) pushing the SAME block again is a no-op (duplicate guard): server must
     *    not crash and must still answer a ping afterwards. Drain any tip
     *    announcement first, then expect only the pong. */
    {
        p2p_write(fd,"block",5, blk[newidx], (unsigned)blen[newidx]);
        uint64_t nonce=0x1112223334445555ull;
        unsigned char pg[8]; memcpy(pg,&nonce,8); p2p_write(fd,"ping",4,pg,8);
        int pong=0;
        for(int tries=0; tries<16 && !pong; tries++){
            char c5[12]; static unsigned char rp[64]; unsigned rl=0;
            int rr=p2p_read(fd,c5,rp,sizeof rp,&rl);
            if(rr<=0) break;
            if(!strncmp(c5,"pong",4)){ pong=1; break; }
            /* drain announcement frame */
        }
        cki("loop alive after duplicate push (ping->pong)", pong, 1);
    }

    close(fd); waitpid(pid,0,0); close(ls);
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
