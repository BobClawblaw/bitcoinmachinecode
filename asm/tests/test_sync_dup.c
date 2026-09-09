/* tests/test_sync_dup.c -- a duplicate of a block another leg just stored ends the sync pass well (split from test_sync_gate: the hash index is process-global). Was:
 * tests/test_sync_gate.c -- the sync pass asks the daemon before fetching a
 * block (g_block_fetch_hook, 2026-09-09): another leg already fetching that
 * hash ends this pass with what it has; a free hash is fetched as before.
 * Until today every leg's pass fetched the block the node lacked -- eight
 * requests per new block from eight legs. */
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
extern long node_handshake(int fd);
extern long node_sync(int fd, void* st, void* locator, void* buf, long buflen, long* out_count);
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd,const char*cmd,unsigned cmdlen,const void*pl,unsigned plen);
extern int  p2p_read(int fd,char cmd[12],void*pl,unsigned cap,unsigned*len);
extern long store_init(void* st);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern int  pow_check(const unsigned char h[80]);
extern void sha256d(unsigned char o[32],const void*m,long l);
extern void* g_block_fetch_hook;
static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }
static void put_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++)p[i]=v>>(8*i);}
static long build_cb_block(unsigned char* b, const unsigned char prev[32], unsigned hgt){
    unsigned char* o=b; unsigned char t[200]; memset(t,0,sizeof t); unsigned char* q=t;
    put_u32(q,1); q+=4; q[0]=1; q+=1; memset(q,0,32); q+=32; put_u32(q,0xffffffff); q+=4;
    q[0]=3; q[1]=(unsigned char)hgt; q[2]=(unsigned char)(hgt>>8); q[3]=(unsigned char)(hgt>>16); q+=4;
    put_u32(q,0xffffffff); q+=4; q[0]=1; q+=1; put_u64(q, 8*1000000ULL); q+=8; q[0]=1; q[1]=0x51; q+=2; put_u32(q,0); q+=4;
    long tl = q - t; unsigned char mr[32]; sha256d(mr, t, tl);
    put_u32(o,1); o+=4; memcpy(o,prev,32); o+=32; memcpy(o,mr,32); o+=32; put_u32(o,1300000000u); o+=4; put_u32(o,0x207fffff); o+=4; put_u32(o,0); o+=4;
    o[0]=1; o+=1; memcpy(o,t,tl); o+=tl; return (long)(o - b);
}
#define MAXB 4096
static unsigned char blocks[2][MAXB]; static long blen[2]; static unsigned char bh[2][32]; static int NB=0; static int g_serve_upto=2;
static void fake_peer(int cfd, int* ngetdata){
    char cmd[12]; unsigned char pl[8192]; unsigned plen=0;
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen);
    unsigned char v[102]; memset(v,0,sizeof v); v[4]=9; p2p_write(cfd,"version",7,v,86); p2p_write(cfd,"verack",6,"",0);
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen);
    int nreq = 0;
    while (nreq < 40) {
        plen=0; if(p2p_read(cfd,cmd,pl,sizeof pl,&plen)<=0) return;
        cmd[11]=0; nreq++;
        if(strncmp(cmd,"getheaders",10)==0){
            int from=0, zero=1; for(int z=0;z<32;z++) if(pl[5+z]) { zero=0; break; }
            if(zero) from=0; else { from=NB; if(plen>=37) for(int i=0;i<NB;i++) if(memcmp(pl+5,bh[i],32)==0) from=i+1; }
            int cnt = g_serve_upto - from; if(cnt<0)cnt=0;
            if(cnt>0){ unsigned char hp[3+81*cnt]; hp[0]=cnt; int p=1; for(int i=from;i<g_serve_upto;i++){ memcpy(hp+p, blocks[i], 80); hp[p+80]=0; p+=81; } p2p_write(cfd,"headers",7,hp,p); }
            else p2p_write(cfd,"headers",7,"\x00",1);
        } else if(strncmp(cmd,"getdata",7)==0){
            (*ngetdata)++; int found=-1; for(int i=0;i<NB;i++) if(memcmp(pl+5,bh[i],32)==0) found=i;
            if(found>=0) p2p_write(cfd,"block",5,blocks[found],(unsigned)blen[found]); else p2p_write(cfd,"block",5,"",0);
        } else if(strncmp(cmd,"verack",6)==0 || strncmp(cmd,"wtxidrelay",10)==0 || strncmp(cmd,"sendaddrv2",10)==0 || strncmp(cmd,"sendcmpct",9)==0){ nreq--; continue; }
        else return;
    }
}
static int g_gate_calls = 0; static int g_gate_answer = 1;
static long gate(const unsigned char* hash){ (void)hash; g_gate_calls++; return g_gate_answer; }
int main(void){
    unsigned char prev[32]; memset(prev,0,32);
    for(int i=0;i<2;i++){ blen[i]=build_cb_block(blocks[i], prev, i); unsigned nz=0; while(!pow_check(blocks[i])){ nz++; put_u32(blocks[i]+76,nz); } block_hash(bh[i], blocks[i]); memcpy(prev, bh[i], 32); NB++; }
    tt_isolate(); g_block_fetch_hook = (void*)gate;
    /* 2026-09-09 (production on snapshot n, where=10 six times an hour): a block
     * another leg stored moments ago is not the peer's fault. The append
     * refuses the duplicate (-2, not tip-linked) and the pass must END WELL
     * (ok=1) so the next rotation rebuilds the locator from the true tip --
     * not fail with where=10 and count a strike against the peer. */
    { static unsigned char st2[4096]; if(store_init(st2)!=1){ printf("FAIL store_init\n"); return 1; }
      g_gate_answer = 1;
      /* "another leg": a peer serving block 0 only, synced first */
      g_serve_upto = 1;
      { int ls=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al); listen(ls,2);
        pid_t pid=fork(); if(pid==0){ int c=accept(ls,0,0); int n=0; fake_peer(c, &n); close(c); _exit(0); }
        int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port); node_handshake(fd);
        unsigned char loc[32]; memset(loc,0,32); static unsigned char b0[65536]; long c0=0;
        node_sync(fd, st2, loc, b0, sizeof b0, &c0); cki("block 0 stored by 'another leg'", c0, 1);
        close(fd); waitpid(pid,0,0); close(ls); }
      /* this leg: its locator predates block 0, the peer serves both */
      g_serve_upto = 2; g_gate_calls = 0;
      int ls=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
      bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al); listen(ls,2);
      pid_t pid=fork(); if(pid==0){ int c=accept(ls,0,0); int n=0; fake_peer(c, &n); close(c); _exit(0); }
      int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port); node_handshake(fd);
      unsigned char loc[32]; memset(loc,0,32); static unsigned char buf2[65536]; long c2=0;
      long s2=node_sync(fd, st2, loc, buf2, sizeof buf2, &c2);
      cki("a duplicate of a block already stored ends the pass WELL (ok=1), not with where=10", s2, 1);
      cki("... nothing counted", c2, 0);
      memcpy(loc, bh[0], 32); c2=0; s2=node_sync(fd, st2, loc, buf2, sizeof buf2, &c2);
      { extern int sync_fail_code; if(c2 != 1) printf("     second pass: sr=%ld cnt=%ld where=%d\n", s2, c2, sync_fail_code); }
      cki("the next pass, from the true tip, fetches block 1", c2, 1);
      cki("store tip is block 1", *(int*)(st2+24), 1);
      close(fd); waitpid(pid,0,0); close(ls); }
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
