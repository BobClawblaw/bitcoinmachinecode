/* test_bip152_loop.c -- loopback e2e for BIP152 compact-block serving.
 * Forks the asm server (node_serve_loop) with a real 5-tx Core block, then a
 * client exercises:
 *   - sendcmpct negotiation (low and high bandwidth)
 *   - getblocktxn  -> blocktxn  (server returns exactly the requested txs)
 *   - getdata(MSG_CMPCT_BLOCK) -> cmpctblock (server builds a compact block).
 * The blocktxn reply's txs must be byte-identical to the stored block's txs;
 * the cmpctblock must parse with the expected header/nonce/shortid layout.
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

#include "block_vec.h"
#include "cmpct_expected.h"
#include "test_tmpdir.h"

extern long node_handshake(int fd);
extern int  node_accept_handshake(int fd);
extern long node_serve_loop(int fd, int lfd, void* st, void* ht_idx, void* out, long cap);
extern int  tcp_connect_ip(unsigned, unsigned short);
extern long store_init(void* st);
extern long store_append(void* st, const unsigned char h[32], const void* blk, long blen);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern long p2p_write(int, const char*, unsigned, const void*, unsigned);
extern int  p2p_read(int, char[12], void*, unsigned, unsigned*);
extern void idx_init(void* idx, unsigned long slots);
extern int  idx_put(void* idx, const unsigned char hash[32], long height);
extern unsigned long long bip152_shortid(unsigned char out[6], const unsigned char hdr[80],
                                      unsigned long long nonce, const unsigned char wtxid[32]);

static int failures=0;
static void ck(const char*l,int ok){ if(ok) printf("PASS %s\n",l); else{ printf("FAIL %s\n",l); failures++; } }

static void put_u64(unsigned char*p, unsigned long long v){ for(int i=0;i<8;i++) p[i]=(unsigned char)(v>>(8*i)); }
static void put_varint(unsigned char**p, unsigned long long v){
    if(v<0xfd){*(*p)++=(unsigned char)v; return;}
    if(v<=0xffff){*(*p)++=0xfd; *(*p)++=(unsigned char)(v&0xff); *(*p)++=(unsigned char)(v>>8); return;}
    *(*p)++=0xfe; for(int i=0;i<4;i++) *(*p)++=(unsigned char)(v>>(8*i));
}

static unsigned char stbuf[1<<16];
static unsigned char blkhash[32];

int main(void){
    tt_isolate();   /* private working dir: the store below writes index.dat/blk00000.dat by bare name */
    setbuf(stdout,NULL);
    /* store the real Core block */
    block_hash(blkhash, BLOCK_RAW);
    if(store_init(stbuf)!=1){ printf("FAIL store_init\n"); return 1; }
    store_append(stbuf, blkhash, BLOCK_RAW, (long)sizeof BLOCK_RAW);
    static unsigned char idx[24 + 256*48];
    idx_init(idx, 256);
    idx_put(idx, blkhash, 0);

    /* loopback server */
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
        _exit(served>=0?(int)served:9);
    }
    int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
    if(fd<0){ printf("FAIL connect\n"); return 1; }
    struct timeval tv; tv.tv_sec=8; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    ck("handshake", node_handshake(fd)==1);

    /* the asm serve loop advertises our min-relay-feerate (a `feefilter`) as
       its first post-handshake message (like Core after verack); drain it so
       subsequent reads sync to the reply stream. */
    {
        char dcmd[12]; unsigned char dbuf[64]; unsigned dbl=0;
        int dr=p2p_read(fd,dcmd,dbuf,sizeof dbuf,&dbl);
        ck("drain leading feefilter", dr>0 && !strncmp(dcmd,"feefilter",9) && dbl==8);
    }

    /* ---- sendcmpct low-bandwidth negotiation ---- */
    {
        unsigned char sc[16]; sc[0]=0; put_u64(sc+1,2);
        ck("write sendcmpct(0,2)", p2p_write(fd,"sendcmpct",9,sc,9)>0);
    }

    /* ---- getblocktxn for indexes [1,3] -> blocktxn ---- */
    {
        unsigned char req[128]; unsigned char* p=req;
        memcpy(p, blkhash, 32); p+=32;
        /* memory-block hashes are stored in internal order; the wire request uses
           the wire order hash. blkhash from block_hash is internal-order; Bitcoin
           wire uses the same 32 bytes (they're matched by idx_get). Use blkhash. */
        put_varint(&p, 2);                       /* 2 indexes */
        put_varint(&p, 1);                       /* first index diff = 1  -> idx 1 */
        put_varint(&p, 1);                       /* shift now 2; need 3 -> diff 3-2 = 1 */
        ck("write getblocktxn", p2p_write(fd,"getblocktxn",11,req,(unsigned)(p-req))>0);
        char cmd[12]; unsigned char buf[1<<20]; unsigned bl=0;
        int r=p2p_read(fd,cmd,buf,sizeof buf,&bl);
        ck("recv blocktxn", r>0 && !strncmp(cmd,"blocktxn",8));
        if(r>0 && !strncmp(cmd,"blocktxn",8)){
            ck("blocktxn blockhash echoed", memcmp(buf, blkhash, 32)==0);
            ck("blocktxn count==2", buf[32]==2);
            /* buf+33.. : tx1 then tx3. Verify tx1 equals BLOCK_RAW's 2nd tx and
               tx3 equals BLOCK_RAW's 4th tx. Compute expected via block offset:
               tx1 at BLOCK_TX_LEN[0]+ ... walk. We'll compare to the known lens. */
            /* tx1 length = BLOCK_TX_LEN[1], tx3 length = BLOCK_TX_LEN[3] */
            /* recompute the block's tx byte offsets */
            int start1=81, start2=start1+BLOCK_TX_LEN[0], start3=start2+BLOCK_TX_LEN[1], start4=start3+BLOCK_TX_LEN[2];
            /* tx bytes follow count at buf+33 */
            ck("blocktxn tx1 bytes match block tx[1]",
                memcmp(buf+33, BLOCK_RAW+start2, (size_t)BLOCK_TX_LEN[1])==0);
            ck("blocktxn tx3 bytes match block tx[3]",
                memcmp(buf+33+BLOCK_TX_LEN[1], BLOCK_RAW+start4, (size_t)BLOCK_TX_LEN[3])==0);
            ck("blocktxn total len", (long)bl==33L+BLOCK_TX_LEN[1]+BLOCK_TX_LEN[3]);
        }
    }

    /* ---- getdata(MSG_CMPCT_BLOCK) -> cmpctblock (high-bandwidth) ---- */
    {
        /* send sendcmpct high-bandwidth first */
        unsigned char sc[16]; sc[0]=1; put_u64(sc+1,2);
        ck("write sendcmpct(1,2)", p2p_write(fd,"sendcmpct",9,sc,9)>0);
        /* build getdata: count=1, type=4 (MSG_CMPCT_BLOCK), hash */
        unsigned char gd[37]; gd[0]=1;
        *(unsigned*)(gd+1)=4;                     /* MSG_CMPCT_BLOCK */
        memcpy(gd+5, blkhash, 32);
        ck("write getdata cmpct", p2p_write(fd,"getdata",7,gd,37)>0);
        char cmd[12]; unsigned char buf[1<<22]; unsigned bl=0;
        int r=p2p_read(fd,cmd,buf,sizeof buf,&bl);
        ck("recv cmpctblock", r>0 && !strncmp(cmd,"cmpctblock",10));
        if(r>0 && !strncmp(cmd,"cmpctblock",10)){
            ck("cmpctblock header matches block header", memcmp(buf, BLOCK_RAW, 80)==0);
            ck("cmpctblock nonce set (nonzero)", *(unsigned long long*)(buf+80)!=0);
            /* shorttxids count; block has BLOCK_NTX txs -> nshort = BLOCK_NTX-1 */
            ck("cmpctblock nshorttxids == ntx-1", buf[88]==(unsigned char)(BLOCK_NTX-1));
            /* verify the first shortid equals bip152_shortid(header,nonce,wtxid(tx1)) */
            unsigned char wtxid[32];
            /* wtxid of tx1 = sha256d of tx bytes at BLOCK_RAW+start2 */
            extern void sha256d(unsigned char[32],const void*,long);
            sha256d(wtxid, BLOCK_RAW+81+BLOCK_TX_LEN[0], (long)BLOCK_TX_LEN[1]);
            unsigned long long nonce = *(unsigned long long*)(buf+80);
            unsigned char sid[6];
            bip152_shortid(sid, BLOCK_RAW, nonce, wtxid);
            ck("cmpctblock shortid[0] == bip152_shortid(wtxid(tx1))", memcmp(buf+89, sid, 6)==0);
            ck("cmpctblock has coinbase prefilled (nprefill=1)", buf[89+6*(BLOCK_NTX-1)]==1);

            /* ---- NET-14 (audit 2026-09-03): the nonce must be FRESH ----
             * s_cmpct_nonce was the constant 0x0123456789abcdef, drawn once
             * and cached for the connection, so every compact block shared
             * one SipHash key and an adversary could precompute colliding
             * short ids. "nonzero" above cannot see that; asking for the SAME
             * block twice and comparing can. */
            unsigned long long nonce1 = *(unsigned long long*)(buf+80);
            ck("NET-14 the nonce is not the old fixed constant",
               nonce1 != 0x0123456789abcdefULL);
            ck("write getdata cmpct (second time)", p2p_write(fd,"getdata",7,gd,37)>0);
            unsigned bl2=0; char cmd2[12];
            int r2=p2p_read(fd,cmd2,buf,sizeof buf,&bl2);
            ck("recv second cmpctblock", r2>0 && !strncmp(cmd2,"cmpctblock",10));
            if(r2>0 && !strncmp(cmd2,"cmpctblock",10)){
                unsigned long long nonce2 = *(unsigned long long*)(buf+80);
                ck("NET-14 a second cmpctblock uses a DIFFERENT nonce", nonce2 != nonce1);
                if (nonce2 == nonce1)
                    printf("        both were %016llx\n", nonce1);
            }
        }
    }

    close(fd); waitpid(pid,0,0); close(ls);
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
