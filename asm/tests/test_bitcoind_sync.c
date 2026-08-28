/* test_bitcoind_sync.c -- loopback fake-peer IBD: the assembly node_sync must
 * download, PoW/merkle-validate, and persistent-store a real 2-block chain.
 * Uses verified asm (cons_verify/store_append/block_hash) on the node side and
 * the same block-builder oracle in C for the peer-side chain.
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
#include "test_tmpdir.h"

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }

/* --- asm exports --- */
extern long node_handshake(int fd);
extern long node_sync(int fd, void* st, void* locator, void* buf, long buflen, long* out_count);
extern long node_serve_block(void* st, long height, void* out, long cap);
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd,const char*cmd,unsigned cmdlen,const void*pl,unsigned plen);
extern int  p2p_read(int fd,char cmd[12],void*pl,unsigned cap,unsigned*len);
extern long store_init(void* st);
extern long store_get_tip(void* st);
extern long p2p_getheaders(void* out, const unsigned char loc[32], unsigned nloc, const unsigned char stop[32]);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern long store_append(void* st, const unsigned char h[32], const void* blk, long blen);
extern int  cons_verify(const void* b, unsigned long l, void* s, unsigned long c);
extern int  pow_check(const unsigned char h[80]);
extern long tx_parse(unsigned long long info[8],const void*tx,unsigned long long tl);

static void put_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++)p[i]=v>>(8*i);}
static unsigned long long varint(unsigned char*p,unsigned long long v){
    if(v<0xfd){p[0]=v&0xff;return 1;} if(v<=0xffff){p[0]=0xfd;p[1]=v;p[2]=v>>8;return 3;}
    p[0]=0xfe;for(int i=0;i<4;i++)p[4+i]=v>>(8*i);return 5;
}
static unsigned char big_sc[32]={
0x59,0xb2,0x66,0x6b,0x17,0x34,0x3a,0xf4,0xd4,0x6e,0x4f,0x5c,0x1d,0x58,0x9c,0x0b,
0xb8,0x7a,0xdb,0x8f,0x9d,0xd1,0x2a,0x6b,0x1b,0x45,0xcc,0x34,0x9c,0x03,0xad,0x9b};

/* build a single-coinbase block (1 tx), the simplest valid block. */
static long build_cb_block(unsigned char* b, const unsigned char prev[32], unsigned char mh[32], unsigned hgt){
    unsigned char* o=b;
    unsigned long long sc=8*1000000;  /* 8 BTC */
    unsigned char t[200]; memset(t,0,sizeof t);
    unsigned char* q=t;
    put_u32(q,1); q+=4;                       /* version 1 */
    q[0]=1; q+=1;                              /* n_in=1 */
    memset(q,0,32); q+=32;                     /* prevhash=0 */
    put_u32(q,0xffffffff); q+=4;               /* prev index */
    q[0]=3; q[1]=(unsigned char)hgt; q[2]=(unsigned char)(hgt>>8); q[3]=(unsigned char)(hgt>>16); q+=4; /* script+len */
    put_u32(q,0xffffffff); q+=4;               /* nSequence (required 4-byte field!) */
    q[0]=1; q+=1;                              /* n_out=1 */
    put_u64(q, sc); q+=8;                      /* value */
    q[0]=1; q[1]=0x51; q+=2;                   /* scriptPubKey: len 1 + OP_TRUE */
    put_u32(q,0); q+=4;                        /* locktime 0 */
    long tlen2 = q - t;
    extern void sha256d(unsigned char o[32],const void*m,long l);
    unsigned char mr[32]; sha256d(mr, t, tlen2);   /* single tx: merkle root == sha256d(t) */
    /* header: version, prev, merkle, time, bits, nonce */
    put_u32(o,1); o+=4;
    memcpy(o,prev,32); o+=32;
    memcpy(o,mr,32); o+=32;
    put_u32(o,1300000000u); o+=4;
    put_u32(o,0x207fffff); o+=4;
    put_u32(o,0); o+=4;                        /* nonce 0 -> passes pow_check */
    o[0]=1; o+=1;                              /* tx-count varint: 1 tx (wire field!) */
    memcpy(o,t,tlen2); o+=tlen2;
    if(mh) memcpy(mh,mr,32);
    return (long)(o - b);
}

#define MAXB 4096
static unsigned char blocks[2][MAXB];
static long blen[2];
static unsigned char bh[2][32];
static int NB=0;

static void fake_peer(int cfd){
    char cmd[12]; unsigned char pl[4096]; unsigned plen=0;
    /* handshake: read client version, then send our version + verack,
     * then read+discard the client's verack. */
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen); cmd[11]=0;
    unsigned char v[102]; memset(v,0,sizeof v); v[4]=9; p2p_write(cfd,"version",7,v,86);
    p2p_write(cfd,"verack",6,"",0);
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen); cmd[11]=0;
    /* serve: strictly one command at a time, response per command */
    int nreq = 0;
    while (nreq < 40) {
        plen=0; if(p2p_read(cfd,cmd,pl,sizeof pl,&plen)<=0) return;
        cmd[11]=0; nreq++;
        if(strncmp(cmd,"getheaders",10)==0){
            int from=0, zero=1;
            for(int z=0;z<32;z++) if(pl[5+z]) { zero=0; break; }
            if(zero){ from=0; } else { from=NB; if(plen>=37) for(int i=0;i<NB;i++) if(memcmp(pl+5,bh[i],32)==0) from=i+1; }
            int cnt = NB - from; if(cnt<0)cnt=0;
            if(cnt>0){ unsigned char hp[3+81*cnt]; hp[0]=cnt; int p=1; for(int i=from;i<NB;i++){ memcpy(hp+p, blocks[i], 80); hp[p+80]=0; p+=81; }
              p2p_write(cfd,"headers",7,hp,p); }
            else p2p_write(cfd,"headers",7,"\x00",1);
        } else if(strncmp(cmd,"getdata",7)==0){
            int found=-1; for(int i=0;i<NB;i++) if(memcmp(pl+5,bh[i],32)==0) found=i;
            if(found>=0) p2p_write(cfd,"block",5,blocks[found],(unsigned)blen[found]);
            else p2p_write(cfd,"block",5,"",0);
        } else if(strncmp(cmd,"verack",6)==0 || strncmp(cmd,"wtxidrelay",10)==0
                  || strncmp(cmd,"sendaddrv2",10)==0){
            /* BIP339/BIP155: our node sends wtxidrelay and sendaddrv2 after
             * version, before verack -- the handshake's single post-version
             * read (above) consumes one of them, leaving the rest for this
             * loop. All are ignorable handshake trailers, not a reason to
             * drop. */
            nreq--;   /* don't count handshake trailers against the budget */
            continue;
        } else {
            /* got a non-serve command mid-session; just drop the session */
            return;
        }
    }
}

int main(void){
    /* build chain of 2 single-coinbase blocks */
    unsigned char prev[32]; memset(prev,0,32);
    for(int i=0;i<2;i++){
        unsigned char mh[32];
        blen[i]=build_cb_block(blocks[i], prev, mh, i);
        unsigned int nz=0; while(!pow_check(blocks[i])){ nz++; put_u32(blocks[i]+76,nz); }
        block_hash(bh[i], blocks[i]);
        memcpy(prev, bh[i], 32);
        NB++;
    }

    /* wire-validity guard: every stored block must carry the tx-count varint at
     * offset 80 (the whole pipeline now REQUIRES it). Prevents silent regression
     * to the old missing-count layout that cons_verify/tx_parse would reject. */
    for(int i=0;i<NB;i++) if(blocks[i][80]!=1){ printf("FAIL block %d missing tx-count byte\n",i); return 1; }

    /* store in a fresh private temp dir (store_init uses CWD-relative
     * filenames), removed on every exit path including a crash. */
    tt_isolate();
    static unsigned char stbuf[4096];
    if(store_init(stbuf)!=1){ printf("FAIL store_init\n"); return 1; }

    /* socketpair-free loopback */
    int ls=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
    listen(ls,2);
    pid_t pid=fork();
    if(pid==0){ int c=accept(ls,0,0); fake_peer(c); close(c); _exit(0); }
    int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
    if(fd<0){ printf("FAIL connect\n"); return 1; }
    int hs=node_handshake(fd); if(hs!=1){ printf("FAIL handshake=%d\n",hs); failures++; }

    unsigned char gen_loc[32]; memset(gen_loc,0,32);
    static unsigned char buf[65536];
    long cnt=0;
    long sr=node_sync(fd, stbuf, gen_loc, buf, sizeof buf, &cnt);
    cki("node_sync download+validate+store OK", sr, 1);
    cki("all blocks stored", cnt, NB);
    int tip = *(int*)(stbuf+24);   /* 0-indexed tip height */
    cki("store tip_height == NB-1", tip, NB-1);
    cki("locator advanced to tip hash", (gen_loc[0]==bh[NB-1][0])?1:0, 1);
    /* serve back every downloaded block and verify byte-exact */
    { static unsigned char sb[4096]; int ok=1;
      for(int h=0; h<NB; h++){ long gl = node_serve_block(stbuf, h, sb, sizeof sb);
        if(gl != blen[h] || memcmp(sb, blocks[h], (size_t)gl)!=0){ ok=0; break; } }
      cki("serve back all stored blocks byte-exact", ok, 1); }
    close(fd); waitpid(pid,0,0); close(ls);

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
