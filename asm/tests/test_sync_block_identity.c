/* tests/test_sync_block_identity.c -- P2P-1 (audit 2026-10-23): the keep-up
 * pass (node_sync_multi) stores a block only if it IS the block it asked for,
 * and only if its header passes the contextual rules for the next height.
 *
 * The pass precomputes each requested hash from the peer's own `headers`
 * reply and, until the fix, stored whatever `block` came back under that
 * hash: idxscan_append_locked checks only that the body extends our tip, and
 * cons_verify checks PoW against the body's OWN nBits. A peer could answer a
 * getdata with a different block -- one at the easiest target -- and the
 * archive then recorded hash X over body Y. The applier compares the two
 * before connecting, so the node stopped at that height for good.
 *
 * A fake peer on a loopback socket serves a chain A0, A1, A2.
 *   1. A0 is synced normally (the store's first block).
 *   2. Asked for A1 it first sends a DIFFERENT block (B1: same parent, its
 *      own valid PoW), then A1. B1 must be passed over; A1 is stored, and the
 *      index hash at height 1 is the body's hash.
 *   3. Asked for A2 it sends only different blocks, many of them: the pass
 *      fails (where=11) and stores nothing.
 *   4. With the header rules armed (the daemon's chain parameters, here a
 *      no-retarget chain), it serves C2 -- the block the headers name, but
 *      with nBits that are not the schedule's: the pass fails (where=12,
 *      Core's bad-diffbits, a punishable header) and stores nothing.
 *   5. The block that does follow the schedule is stored.
 *   6. P2P-3: asked for a compact block, the peer answers with one that has
 *      no transactions at all (Core's READ_STATUS_INVALID): the pass fails
 *      where=14, the code pass_fail_bookkeeping scores.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "test_tmpdir.h"
extern long node_handshake(int fd);
extern long node_sync(int fd, void* st, void* locator, void* buf, long buflen, long* out_count);
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd,const char*cmd,unsigned cmdlen,const void*pl,unsigned plen);
extern int  p2p_read(int fd,char cmd[12],void*pl,unsigned cap,unsigned*len);
extern long store_init(void* st);
extern long node_serve_block(void* st, long height, void* out, long cap);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern int  pow_check(const unsigned char h[80]);
extern void sha256d(unsigned char o[32],const void*m,long l);
extern int  sync_fail_code;
extern long g_peer_sendcmpct; extern void* g_sync_mp;
extern void* g_block_ctx_hook;
extern int  hdr_accept_check(void* st, const unsigned char* hdr80);
extern void serve_set_header_rules(int no_retarget, int allow_min_diff, int enforce_bip94, unsigned int pow_limit_bits, long bip34_height);
extern void* g_cmpct_hook_type; extern void* g_cmpct_hook_cmpct; extern void* g_cmpct_hook_blocktxn;
extern unsigned cmpct_getdata_type(int);
extern long cmpct_recv_cmpctblock(int, void*, const unsigned char*, unsigned long, unsigned char*, unsigned long, const unsigned char*);
extern long cmpct_recv_blocktxn(int, const unsigned char*, unsigned long, unsigned char*, unsigned long, const unsigned char*);
static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }
static void put_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++)p[i]=v>>(8*i);}
#define MAXB 1024
typedef struct { unsigned char b[MAXB]; long len; unsigned char h[32]; } blk_t;
/* a coinbase-only block on `prev`; `tag` makes blocks on the same parent differ */
static void mk(blk_t* o, const unsigned char prev[32], unsigned hgt, unsigned tag, unsigned ntime, unsigned bits){
    unsigned char t[200]; unsigned char* q=t;
    put_u32(q,1); q+=4; q[0]=1; q+=1; memset(q,0,32); q+=32; put_u32(q,0xffffffff); q+=4;
    q[0]=7; q[1]=3; q[2]=(unsigned char)hgt; q[3]=(unsigned char)(hgt>>8); q[4]=(unsigned char)(hgt>>16); put_u32(q+4, tag); q+=8;
    put_u32(q,0xffffffff); q+=4; q[0]=1; q+=1; put_u64(q, 50*100000000ULL); q+=8; q[0]=1; q[1]=0x51; q+=2; put_u32(q,0); q+=4;
    long tl = q - t; unsigned char mr[32]; sha256d(mr, t, tl);
    unsigned char* p=o->b;
    put_u32(p,1); p+=4; memcpy(p,prev,32); p+=32; memcpy(p,mr,32); p+=32; put_u32(p,ntime); p+=4; put_u32(p,bits); p+=4; put_u32(p,0); p+=4;
    p[0]=1; p+=1; memcpy(p,t,tl); p+=tl; o->len = p - o->b;
    unsigned nz=0; while(!pow_check(o->b)){ nz++; put_u32(o->b+76,nz); }
    block_hash(o->h, o->b);
}
/* the peer: `hdrs` is the chain its getheaders answers walk; a getdata for
 * hdrs[i] is answered with ndecoy[i] copies of decoy[i] first, then (if
 * real[i]) the block itself */
#define NB 3
static blk_t* hdrs[NB]; static blk_t* decoy[NB]; static int ndecoy[NB], real[NB], nb = NB;
static void fake_peer(int cfd){
    char cmd[12]; static unsigned char pl[1<<16]; unsigned plen=0;
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen);
    unsigned char v[102]; memset(v,0,sizeof v); v[4]=9; p2p_write(cfd,"version",7,v,86); p2p_write(cfd,"verack",6,"",0);
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen);
    for (int nreq = 0; nreq < 40; nreq++){
        plen=0; if(p2p_read(cfd,cmd,pl,sizeof pl,&plen)<=0) return;
        cmd[11]=0;
        if(strncmp(cmd,"getheaders",10)==0){
            int from=0, zero=1; for(int z=0;z<32;z++) if(pl[5+z]) { zero=0; break; }
            if(!zero){ for(int i=0;i<nb;i++) if(memcmp(pl+5,hdrs[i]->h,32)==0) from=i+1; }   /* an unknown locator: from the start */
            int cnt = nb - from; if(cnt<0)cnt=0;
            if(cnt>0){ unsigned char hp[3+81*NB]; hp[0]=(unsigned char)cnt; int p=1; for(int i=from;i<nb;i++){ memcpy(hp+p, hdrs[i]->b, 80); hp[p+80]=0; p+=81; } p2p_write(cfd,"headers",7,hp,(unsigned)p); }
            else p2p_write(cfd,"headers",7,"\x00",1);
        } else if(strncmp(cmd,"getdata",7)==0){
            int found=-1; for(int i=0;i<nb;i++) if(memcmp(pl+5,hdrs[i]->h,32)==0) found=i;
            if(found<0) return;
            unsigned type; memcpy(&type, pl+1, 4);
            if(type == 4){ unsigned char cb[90]; memcpy(cb, hdrs[found]->b, 80); memset(cb+80, 0x5a, 8); cb[88] = 0; cb[89] = 0;   /* no short ids, no prefilled */
                           p2p_write(cfd,"cmpctblock",10,cb,90); continue; }
            for(int d=0; d<ndecoy[found]; d++) p2p_write(cfd,"block",5,decoy[found]->b,(unsigned)decoy[found]->len);
            if(real[found]) p2p_write(cfd,"block",5,hdrs[found]->b,(unsigned)hdrs[found]->len);
        } else if(strncmp(cmd,"verack",6)==0 || strncmp(cmd,"wtxidrelay",10)==0 || strncmp(cmd,"sendaddrv2",10)==0 || strncmp(cmd,"sendcmpct",9)==0){ nreq--; }
        else return;
    }
}
/* one pass against a fresh peer process; returns node_sync's verdict */
static long one_pass(void* st, const unsigned char loc[32], long* cnt){
    int ls=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al); listen(ls,2);
    pid_t pid=fork();
    if(pid==0){ int c=accept(ls,0,0); fake_peer(c); shutdown(c, SHUT_WR); { char sink[4096]; while(read(c,sink,sizeof sink)>0){} } close(c); _exit(0); }
    int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port); if(fd<0){ printf("FAIL connect\n"); exit(1); }
    if(node_handshake(fd)!=1){ printf("FAIL handshake\n"); exit(1); }
    static unsigned char buf[1<<16]; unsigned char l[32]; memcpy(l, loc, 32); *cnt=0; sync_fail_code=0;
    long r=node_sync(fd, st, l, buf, sizeof buf, cnt);
    close(fd); waitpid(pid,0,0); close(ls);
    return r;
}
static int index_hash_at(long h, unsigned char out[32]){
    int fd=open("index.dat", O_RDONLY); if(fd<0) return 0;
    long n=pread(fd, out, 32, (off_t)h*48); close(fd); return n==32;
}
/* does the stored body at height h hash to the hash the index records? */
static int body_is_index(void* st, long h, const unsigned char want[32]){
    static unsigned char sb[1<<16]; unsigned char ih[32], bh[32];
    long L=node_serve_block(st, h, sb, sizeof sb); if(L<80 || !index_hash_at(h, ih)) return 0;
    block_hash(bh, sb);
    return !memcmp(ih, bh, 32) && !memcmp(bh, want, 32);
}
int main(void){
    static blk_t A0, A1, A2, B1, B2, C2; unsigned char zero[32]; memset(zero,0,32);
    mk(&A0, zero, 0, 0, 1300000000u, 0x207fffff);
    mk(&A1, A0.h, 1, 0, 1300000600u, 0x207fffff);
    mk(&B1, A0.h, 1, 0xb1, 1300000601u, 0x207fffff);     /* a sibling of A1 */
    mk(&A2, A1.h, 2, 0, 1300001200u, 0x207fffff);
    mk(&B2, A1.h, 2, 0xb2, 1300001201u, 0x207fffff);     /* a sibling of A2 */
    mk(&C2, A1.h, 2, 0xc2, 1300001202u, 0x2007ffff);     /* on A1, nBits not the schedule's */
    tt_isolate();
    static unsigned char stbuf[4096]; if(store_init(stbuf)!=1){ printf("FAIL store_init\n"); return 1; }
    g_peer_sendcmpct = 0; g_sync_mp = 0;
    long cnt=0, r;

    printf("-- 1. the first block, synced normally\n");
    for(int i=0;i<NB;i++){ hdrs[i]=&A0; decoy[i]=0; ndecoy[i]=0; real[i]=1; }
    nb=1; hdrs[0]=&A0;                                     /* the peer's chain is one block, per pass */
    r=one_pass(stbuf, zero, &cnt);
    cki("A0 stored", *(int*)(stbuf+24), 0);
    cki("A0's body is the block its index names", body_is_index(stbuf, 0, A0.h), 1);

    printf("-- 2. asked for A1, the peer sends B1 first, then A1\n");
    hdrs[0]=&A1; real[0]=1; decoy[0]=&B1; ndecoy[0]=1;
    r=one_pass(stbuf, A0.h, &cnt);
    cki("height 1 stored", *(int*)(stbuf+24), 1);
    cki("the body at height 1 is A1, the block requested (not B1 under A1's hash)", body_is_index(stbuf, 1, A1.h), 1);

    printf("-- 3. asked for A2, the peer sends only other blocks\n");
    hdrs[0]=&A2; real[0]=0; decoy[0]=&B2; ndecoy[0]=40;
    r=one_pass(stbuf, A1.h, &cnt);
    cki("the pass fails", r, 0);
    cki("...where=11 (not the block requested)", sync_fail_code, 11);
    cki("nothing stored: the tip stays at 1", *(int*)(stbuf+24), 1);
    cki("the body at height 1 is still A1", body_is_index(stbuf, 1, A1.h), 1);

    printf("-- 4. header rules armed: C2 is the block its header names, with the wrong nBits\n");
    serve_set_header_rules(1, 0, 0, 0x207fffff, 1000000);
    g_block_ctx_hook = (void*)hdr_accept_check;
    hdrs[0]=&C2; real[0]=1; ndecoy[0]=0;
    r=one_pass(stbuf, A1.h, &cnt);
    cki("the pass fails", r, 0);
    cki("...where=12 (a header Core refuses: bad-diffbits)", sync_fail_code, 12);
    cki("nothing stored: the tip stays at 1", *(int*)(stbuf+24), 1);

    printf("-- 5. ...and the block that does follow the schedule is stored\n");
    hdrs[0]=&A2; real[0]=1; ndecoy[0]=0;
    r=one_pass(stbuf, A1.h, &cnt);
    cki("A2 stored", *(int*)(stbuf+24), 2);
    cki("the body at height 2 is A2", body_is_index(stbuf, 2, A2.h), 1);

    printf("-- 6. a compact block with no transactions at all (Core: READ_STATUS_INVALID)\n");
    g_cmpct_hook_type = (void*)cmpct_getdata_type; g_cmpct_hook_cmpct = (void*)cmpct_recv_cmpctblock; g_cmpct_hook_blocktxn = (void*)cmpct_recv_blocktxn;
    g_peer_sendcmpct = 1;
    static blk_t A3; mk(&A3, A2.h, 3, 0, 1300001800u, 0x207fffff);
    hdrs[0]=&A3; real[0]=1; ndecoy[0]=0;
    r=one_pass(stbuf, A2.h, &cnt);
    cki("the pass fails", r, 0);
    cki("...where=14 (an invalid compact block: the peer is scored)", sync_fail_code, 14);
    cki("nothing stored: the tip stays at 2", *(int*)(stbuf+24), 2);
    g_block_ctx_hook = 0; g_cmpct_hook_type = g_cmpct_hook_cmpct = g_cmpct_hook_blocktxn = 0; g_peer_sendcmpct = 0;

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
