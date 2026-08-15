/* test_sendheaders_fee.c -- loopback + unit verification of the sendheaders
 * (BIP130) and feefilter P2P features in the asm serve loop.
 *
 * What it proves:
 *   1. node_announce_tip(fd,st,idx,0) advertises the stored tip block as an
 *      `inv`(MSG_BLOCK): byte-exact [count=1][type u32 LE=2][hash32 in wire
 *      order]. (The non-sendheaders form.)
 *   2. node_announce_tip(fd,st,idx,1) advertises the SAME block as a
 *      `headers` message instead: byte-exact [count varint=1][80-byte block
 *      header][tx-count 0]. (The sendheaders form -- this is the whole point:
 *      one 80-byte header replaces one 36-byte inv entry per block.)
 *   3. A forked node_serve_loop sends its OWN `feefilter` (min-relay-feerate,
 *      8-byte int64 LE) to the peer on connect, and then accepts inbound
 *      `sendheaders` + `feefilter` negotiation messages and keeps serving
 *      (ping->pong proves the connection is still live).
 *
 * The stored block is a real Bitcoin Core regtest block (tests/block_vec.h),
 * so the announcement wire bytes are compared against a real block's header
 * and hash -- byte-for-byte with what Core v31.99 would relay.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#include "block_vec.h"

extern long node_handshake(int fd);
extern int  node_accept_handshake(int fd);
extern long node_serve_loop(int fd, int lfd, void* st, void* ht_idx, void* out, long cap);
extern long node_announce_tip(int fd, void* st, void* ht_idx, long use_headers);
extern int  tcp_connect_ip(unsigned, unsigned short);
extern long store_init(void* st);
extern long store_append(void* st, const unsigned char h[32], const void* blk, long blen);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void idx_init(void* idx, unsigned long slots);
extern int  idx_put(void* idx, const unsigned char hash[32], long height);
extern long p2p_write(int, const char*, unsigned, const void*, unsigned);
extern int  p2p_read(int, char[12], void*, unsigned, unsigned*);

static int failures=0;
static void ck(const char*l,int ok){ if(ok) printf("PASS %s\n",l); else{ printf("FAIL %s\n",l); failures++; } }
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }

static unsigned char stbuf[1<<16];
static unsigned char blkhash[32];   /* internal-order header hash */
static unsigned char wk[80];        /* BLOCK_RAW's 80-byte header */

static void build_store(void* idx){
    /* store BLOCK_RAW at height 0 as the tip */
    store_init(stbuf);
    block_hash(blkhash, BLOCK_RAW);
    store_append(stbuf, blkhash, BLOCK_RAW, (long)sizeof BLOCK_RAW);
    idx_init(idx, 64);
    idx_put(idx, blkhash, 0);
    memcpy(wk, BLOCK_RAW, 80);
}

int main(void){
    setbuf(stdout,NULL);
    static unsigned char idx[24 + 64*48];
    build_store(idx);

    /* ================= Part A: node_announce_tip direct (socketpair) ===== */
    int sv[2];
    if(socketpair(AF_UNIX,SOCK_STREAM,0,sv)!=0){ printf("FAIL socketpair\n"); return 1; }
    struct timeval tv; tv.tv_sec=8; tv.tv_usec=0; setsockopt(sv[1],SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);

    /* A1: default form -> inv(MSG_BLOCK) */
    long r1 = node_announce_tip(sv[0], stbuf, idx, 0);
    cki("announce_tip(inv) returns 1", r1, 1);
    char cmd[12]; unsigned char buf[512]; unsigned bl=0;
    int rr = p2p_read(sv[1],cmd,buf,sizeof buf,&bl);
    ck("recv inv", rr>0 && !strncmp(cmd,"inv",3));
    if(rr>0 && !strncmp(cmd,"inv",3)){
        ck("inv count==1", buf[0]==1);
        ck("inv type==MSG_BLOCK(2)", (buf[1]|(buf[2]<<8)|(buf[3]<<16)|(buf[4]<<24))==2);
        /* wire-order hash = reverse of internal blkhash */
        ck("inv len==37", (int)bl==37);
        int m=1;
        for(int k=0;k<32;k++) if(buf[5+k]!=blkhash[31-k]) m=0;
        ck("inv hash == block tip (wire order)", m);
        /* wire hash must equal reversed block-hash; cross-check against header */
        unsigned char rh[32]; for(int k=0;k<32;k++) rh[k]=buf[5+k];  /* wire order */
        unsigned char hr[32]; for(int k=0;k<32;k++) hr[31-k]=rh[k];  /* -> internal */
        ck("inv hash == stored tip hash", memcmp(hr,blkhash,32)==0);
    }

    /* A2: sendheaders form -> headers message with the 80-byte header */
    long r2 = node_announce_tip(sv[0], stbuf, idx, 1);
    cki("announce_tip(headers) returns 1", r2, 1);
    rr = p2p_read(sv[1],cmd,buf,sizeof buf,&bl);
    ck("recv headers", rr>0 && !strncmp(cmd,"headers",7));
    if(rr>0 && !strncmp(cmd,"headers",7)){
        ck("headers count==1", buf[0]==1);
        ck("headers payload len==82", (int)bl==82);
        ck("headers[1..81] == block header 80B", memcmp(buf+1, wk, 80)==0);
        ck("headers[81] tx-count==0", buf[81]==0);
    }
    close(sv[0]); close(sv[1]);

    /* ============ Part B: forked serve loop, outbound feefilter + parsing == */
    int ls=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t alen=sizeof a; getsockname(ls,(struct sockaddr*)&a,&alen);
    listen(ls,2);
    pid_t pid=fork();
    if(pid==0){
        int c=accept(ls,0,0);
        if(c<0) _exit(3);
        if(node_accept_handshake(c)!=1) _exit(4);
        static unsigned char so[1<<22];
        long served=node_serve_loop(c, -1, stbuf, idx, so, (long)sizeof so);
        _exit(served>=0?0:9);
    }
    int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
    if(fd<0){ printf("FAIL connect\n"); return 1; }
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    ck("handshake", node_handshake(fd)==1);

    /* B1: the serve loop's FIRST outbound message is our feefilter */
    rr = p2p_read(fd,cmd,buf,sizeof buf,&bl);
    ck("serve sends feefilter first", rr>0 && !strncmp(cmd,"feefilter",9));
    unsigned long long expect_fee = 1000ULL;   /* s_myfee: 1000 sat/kB */
    int feem=1;
    if(rr>0 && bl==8){ for(int k=0;k<8;k++) if(buf[k]!=((expect_fee>>(8*k))&0xff)) feem=0; }
    else feem=0;
    ck("feefilter payload == min-relay-feerate 1000 (int64 LE)", feem);
    ck("feefilter len==8", (int)bl==8);

    /* B2: client negotiates sendheaders + feefilter; server must not error */
    rr = p2p_write(fd,"sendheaders",11,"",0);
    ck("write sendheaders", rr>0);
    unsigned char ff[8]; for(int k=0;k<8;k++) ff[k]=((5000ULL>>(8*k))&0xff);
    rr = p2p_write(fd,"feefilter",9,ff,8);
    ck("write feefilter(5000)", rr>0);
    /* server stays alive: ping->pong */
    unsigned char nonce[8]={1,2,3,4,5,6,7,8};
    rr = p2p_write(fd,"ping",4,nonce,8);
    ck("write ping", rr>0);
    rr = p2p_read(fd,cmd,buf,sizeof buf,&bl);
    ck("ping->pong after sendheaders+feefilter", rr>0 && !strncmp(cmd,"pong",4));
    if(rr>0 && !strncmp(cmd,"pong",4)) ck("pong echoes nonce", bl>=8 && memcmp(buf,nonce,8)==0);

    close(fd); waitpid(pid,0,0); close(ls);

    printf(failures? "\nFAILURES %d\n" : "\nALL TESTS PASSED (0 failures)\n", failures);
    return failures?1:0;
}
