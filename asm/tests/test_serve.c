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
#include "test_tmpdir.h"

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
    tt_isolate();   /* private working dir: the store below writes index.dat/blk00000.dat by bare name */
    setbuf(stdout,NULL);
    build_chain();
    static unsigned char stbuf[4096];
    if(store_init(stbuf)!=1){ printf("FAIL store_init\n"); return 1; }
    for(int i=0;i<TEST_NB;i++) store_append(stbuf, bhash[i], blk[i], blen[i]);

    /* build asm hash->height index over the block hashes */
    static unsigned char idx[24 + 256*48];
    idx_init(idx, 256);
    for(int i=0;i<TEST_NB;i++) idx_put(idx, bhash[i], i);

    /* THE INDEX PRODUCTION ACTUALLY USES. daemon/main.c builds the serve
     * loop's table with idx_build_from_file over index.dat, not with the
     * idx_put loop above -- so this test proved the serve loop worked against
     * an index nobody builds that way. Both constructions must agree, and the
     * key must be the hash AS IT ARRIVES ON THE WIRE, because that is what
     * the getdata handler passes to idx_get.
     * (2026-08-27: they did not agree. index.dat stores wire order, and
     * idx_build_from_file byte-reversed every record on the belief that it
     * held display order, leaving the live node unable to serve any block
     * requested by hash.) */
    { extern long idx_build_from_file(void* idx, const char* path);
      extern int  idx_get(void* idx, const unsigned char hash[32], long* height);
      static unsigned char pidx[24 + 256*48];
      idx_init(pidx, 256);
      if (idx_build_from_file(pidx, "index.dat") < 0){
          printf("FAIL idx_build_from_file could not read index.dat\n"); return 1; }
      int bad = 0;
      for (int i = 0; i < TEST_NB; i++){
          long h = -1;
          int found = idx_get(pidx, bhash[i], &h);
          if (found != 1 || h != i){
              if (!bad) printf("      first mismatch: block %d found=%d h=%ld\n", i, found, h);
              bad++;
          }
      }
      if (bad) printf("FAIL the production index (idx_build_from_file) misses %d/%d wire-order lookups\n", bad, TEST_NB);
      else     printf("ok  : the production index construction answers wire-order lookups\n");
      if (bad) return 1; }

    static unsigned char out[1<<20];
    /* loopback TCP */
    int ls=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
    listen(ls,2);

    /* ---- STO-10 fixture: a STALE hash -> height mapping, installed BEFORE the
     * fork. It has to be here: the serve side runs in a forked child, so an
     * idx_put made afterwards lands only in the parent's copy-on-write pages
     * and the child never sees it. The first version of this test did exactly
     * that -- the fixture assertions passed in the parent, the child answered
     * notfound because the entry was simply ABSENT, and the case passed with
     * the fix reverted. A vacuous test, caught by reverting.
     *
     * `ghost` is not any stored block's hash, mapped to height 0: exactly the
     * shape a serve child's table has after a reorg it never learned about. */
    static unsigned char ghost[32];
    memset(ghost, 0xd0, sizeof ghost);
    ghost[0] = 0xd1;
    { int collides = 0;
      for (int i = 0; i < TEST_NB; i++) if (!memcmp(ghost, bhash[i], 32)) collides = 1;
      cki("STO-10 fixture: the ghost hash is not a real block hash", collides, 0); }
    idx_put(idx, ghost, 0);
    { long gh = -1; extern int idx_get(void* ix, const unsigned char h[32], long* height);
      cki("STO-10 fixture: the stale mapping is in the index BEFORE the fork",
          idx_get(idx, ghost, &gh) == 1 && gh == 0, 1); }

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

    /* ---- STO-10: never serve a block that is not the one requested --------
     * ht_idx maps hash -> height and is built once, at process start.
     * serve_idx_topup only ADDS heights, so a serve child forked before a
     * reorg still maps the LOSING branch's hashes to fork+1..old_tip and
     * never learns the replacements. The lookup then succeeds with a stale
     * height and the archive returns whatever block now occupies it -- the
     * WRONG block for the requested hash. Core drops a block it did not ask
     * for and may score the peer for sending it.
     *
     * The stale mapping is reproduced directly: a hash that is NOT any stored
     * block's hash is inserted pointing at height 0, which is exactly the
     * shape a post-reorg child's table has. The request must come back
     * notfound, not as block 0.
     *
     * This leaves the real entries untouched, so the assertions above keep
     * their meaning. */
    {
      unsigned char gd[64]; long l = p2p_getdata_block(gd, ghost);
      p2p_write(fd, "getdata", 7, gd, (unsigned)l);
      char c5[12]; static unsigned char nbuf[1<<20]; unsigned nl = 0;
      int r5 = p2p_read(fd, c5, nbuf, sizeof nbuf, &nl);
      cki("STO-10: a hash whose index entry is stale is answered notfound",
          r5 > 0 && strncmp(c5, "notfound", 8) == 0, 1);
      if (r5 > 0 && strncmp(c5, "notfound", 8) != 0)
          printf("      got cmd=%.8s len=%u (block 0 len=%ld) -- served the WRONG block\n",
                 c5, nl, blen[0]);
      cki("STO-10: and specifically NOT block 0's bytes",
          !(nl == (unsigned)blen[0] && !memcmp(nbuf, blk[0], nl)), 1); }


    /* ---- NET-8: getheaders must walk the WHOLE locator ----
     * The handler used to look up only the FIRST locator hash and, on a miss,
     * serve from height 0 -- ignoring every other entry. A peer one block
     * ahead of us starts its locator with a hash we do not have, which is the
     * common case, not the rare one, so every getheaders was answered with
     * 2000 headers from genesis that a Core peer discards as already known.
     *
     * The locator here is [unknown, bhash[3], bhash[0]] -- newest-first, as
     * Core builds them. The first entry is a hash that cannot exist; the
     * second is real. A correct walk serves from height 4. The old one served
     * from 0.
     *
     * Asserting the FIRST HEADER'S BYTES rather than a count: serving from
     * genesis also returns headers, just the wrong ones, so a count check
     * would pass against the defect. */
    {
        unsigned char gh[4 + 1 + 3*32 + 32];
        int gp = 0;
        gh[gp++]=1; gh[gp++]=0; gh[gp++]=0; gh[gp++]=0;   /* nVersion */
        gh[gp++]=3;                                        /* locator count */
        memset(gh+gp, 0xAB, 32); gp += 32;                 /* unknown */
        memcpy(gh+gp, bhash[3], 32); gp += 32;             /* known: height 3 */
        memcpy(gh+gp, bhash[0], 32); gp += 32;             /* known: height 0 */
        memset(gh+gp, 0, 32); gp += 32;                    /* hashStop = none */
        p2p_write(fd, "getheaders", 10, gh, (unsigned)gp);

        char c7[12]; static unsigned char hb[1<<20]; unsigned hl = 0;
        int rr = p2p_read(fd, c7, hb, sizeof hb, &hl);
        int ok8 = 0;
        if (rr > 0 && !strncmp(c7, "headers", 7) && hl >= 1 + 81){
            /* count varint (small here), then 80-byte headers each followed
             * by a 0 txn_count byte */
            unsigned off = (hb[0] < 0xfd) ? 1u : 3u;
            if (hl >= off + 80)
                ok8 = (memcmp(hb + off, blk[4], 80) == 0);   /* height 4 first */
        }
        cki("NET-8 a locator whose first hash is unknown serves from the next "
            "KNOWN one, not from genesis", ok8, 1);

        /* resync, for the same reason NET-7 does: leave the stream where the
         * next case expects it regardless of what the server chose to send. */
        { uint64_t nonce = 0x4e455438beefull;
          p2p_write(fd, "ping", 4, &nonce, 8);
          for (int k = 0; k < 64; k++){
              char c8[12]; static unsigned char rb8[1<<20]; unsigned rl8 = 0;
              if (p2p_read(fd, c8, rb8, sizeof rb8, &rl8) <= 0) break;
              if (!strncmp(c8, "pong", 4)) break;
          } }
    }

    /* ---- NET-7: a getdata whose count needs a 3-byte CompactSize ----
     * Core's MAX_GETDATA_SZ is 1000, so it routinely asks for 253 or more
     * items in one message -- and 253 is the first count that does not fit a
     * single byte. The handler used to read `movzx rax, byte [pl_buf]`, so
     * the 0xfd prefix was taken AS the count and every entry after it was
     * misaligned by two bytes: this node answered ~50 notfounds for garbage
     * hashes and served nothing. Every large getdata from every Core peer.
     *
     * The request below asks for 253 items: the TEST_NB real blocks followed
     * by filler entries with hashes that cannot exist. A correct parser
     * serves the real ones and reports the rest notfound. The old one-byte
     * parser cannot even find the first entry.
     *
     * What is asserted is that the REAL blocks come back byte-exact -- not a
     * count of replies -- because a misaligned walk still produces replies,
     * just about the wrong hashes.
     *
     * It RESYNCS the stream afterwards with a ping, discarding whatever
     * notfound replies remain, so its position among the other cases does not
     * matter. The first draft left them queued and broke the ping/pong check
     * that followed; moving it to the end then broke ITSELF, because the
     * checks before it leave their own state. A test whose result depends on
     * where it sits is not pinning what it claims to. */
    {
        enum { GD_N = 253 };
        static unsigned char big[8 + GD_N*36];
        int bp = 0;
        big[bp++] = 0xfd;                       /* CompactSize: 3-byte form */
        big[bp++] = (unsigned char)(GD_N & 0xff);
        big[bp++] = (unsigned char)(GD_N >> 8);
        for (int i = 0; i < GD_N; i++){
            unsigned char iv[36]; memset(iv, 0, 36);
            iv[0] = 2;                          /* MSG_BLOCK */
            if (i < TEST_NB) memcpy(iv+4, bhash[i], 32);
            else { iv[4] = 0xee; iv[5] = (unsigned char)i; }   /* cannot exist */
            memcpy(big+bp, iv, 36); bp += 36;
        }
        p2p_write(fd, "getdata", 7, big, (unsigned)bp);

        int got_real = 0, got_nf = 0;
        for (int r = 0; r < GD_N + 8; r++){
            char c5[12]; static unsigned char rb[1<<20]; unsigned rl = 0;
            if (p2p_read(fd, c5, rb, sizeof rb, &rl) <= 0) break;
            if (!strncmp(c5, "block", 5)){
                for (int j = 0; j < TEST_NB; j++)
                    if ((long)rl == blen[j] && !memcmp(rb, blk[j], (size_t)rl)){ got_real++; break; }
            } else if (!strncmp(c5, "notfound", 8)) got_nf++;
            if (got_real >= TEST_NB) break;
        }
        cki("NET-7 a 253-entry getdata (3-byte CompactSize) serves the real blocks",
            got_real, TEST_NB);

        /* resync: ping, then discard everything until the pong comes back */
        { uint64_t nonce = 0x4e455437beefull;
          p2p_write(fd, "ping", 4, &nonce, 8);
          for (int k = 0; k < GD_N + 16; k++){
              char c6[12]; static unsigned char rb6[1<<20]; unsigned rl6 = 0;
              if (p2p_read(fd, c6, rb6, sizeof rb6, &rl6) <= 0) break;
              if (!strncmp(c6, "pong", 4)) break;
          } }
    }

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
