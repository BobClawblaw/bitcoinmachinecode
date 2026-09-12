/* tests/test_cmpct_fallback.c -- a compact block that reconstructs into a
 * block that fails verification is re-requested in FULL, once, as Core's
 * PartiallyDownloadedBlock fallback does -- the sync pass is not failed and
 * the block is not lost (2026-09-09: until today a bad reconstruction failed
 * the leg's pass with where=8 and cost the block, which is why the emergency
 * switch bmc.cmpctrecv existed; Core has no such switch because it has the
 * fallback).
 *
 * A fake peer serves two coinbase-only blocks. Asked for block 0 as a compact
 * block it answers with a cmpctblock whose prefilled coinbase is CORRUPTED
 * (one value byte flipped: the assembled block's merkle root no longer matches
 * its header); asked for block 1 it answers a correct one. The node must fetch
 * block 0 in full with a MSG_WITNESS_BLOCK getdata, store both, and count one
 * fallback and one reconstruction. */
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
extern int  sync_fail_code;
extern long g_peer_sendcmpct; extern void* g_sync_mp;
extern void* g_cmpct_hook_type; extern void* g_cmpct_hook_cmpct; extern void* g_cmpct_hook_blocktxn; extern void* g_cmpct_hook_fallback;
extern unsigned cmpct_getdata_type(int);
extern long cmpct_recv_cmpctblock(int, void*, const unsigned char*, unsigned long, unsigned char*, unsigned long, const unsigned char*);
extern long cmpct_recv_blocktxn(int, const unsigned char*, unsigned long, unsigned char*, unsigned long);
extern void cmpct_recv_note_fallback(void);
extern void cmpct_recv_stats(unsigned long* r, unsigned long* n, unsigned long* f);
static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }
static void put_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++)p[i]=v>>(8*i);}
static long build_cb_block(unsigned char* b, const unsigned char prev[32], unsigned hgt, long* txoff, long* txlen){
    unsigned char* o=b; unsigned char t[200]; memset(t,0,sizeof t); unsigned char* q=t;
    put_u32(q,1); q+=4; q[0]=1; q+=1; memset(q,0,32); q+=32; put_u32(q,0xffffffff); q+=4;
    q[0]=3; q[1]=(unsigned char)hgt; q[2]=(unsigned char)(hgt>>8); q[3]=(unsigned char)(hgt>>16); q+=4;
    put_u32(q,0xffffffff); q+=4; q[0]=1; q+=1; put_u64(q, 8*1000000ULL); q+=8; q[0]=1; q[1]=0x51; q+=2; put_u32(q,0); q+=4;
    long tl = q - t; unsigned char mr[32]; sha256d(mr, t, tl);
    put_u32(o,1); o+=4; memcpy(o,prev,32); o+=32; memcpy(o,mr,32); o+=32; put_u32(o,1300000000u); o+=4; put_u32(o,0x207fffff); o+=4; put_u32(o,0); o+=4;
    o[0]=1; o+=1; *txoff = o - b; *txlen = tl; memcpy(o,t,tl); o+=tl;
    return (long)(o - b);
}
#define MAXB 4096
static unsigned char blocks[2][MAXB]; static long blen[2], txoff[2], txlen[2]; static unsigned char bh[2][32]; static int NB=0;
/* cmpctblock: header(80) nonce(8) shortids(varint 0) prefilled(varint 1) [index varint 0][tx] */
static long build_cmpct(unsigned char* out, int i, int corrupt){
    unsigned char* o=out; memcpy(o, blocks[i], 80); o+=80; memset(o, 0x5a, 8); o+=8; *o++ = 0; *o++ = 1; *o++ = 0;
    memcpy(o, blocks[i]+txoff[i], txlen[i]); if(corrupt) o[txoff[i] - txoff[i] + 4 + 1 + 32 + 4 + 4 + 4 + 1] ^= 0x01;   /* the coinbase's value byte */
    o += txlen[i]; return o - out;
}
static void fake_peer(int cfd, int* saw_cmpct, int* saw_full){
    char cmd[12]; unsigned char pl[8192]; unsigned plen=0;
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen);
    unsigned char v[102]; memset(v,0,sizeof v); v[4]=9; p2p_write(cfd,"version",7,v,86); p2p_write(cfd,"verack",6,"",0);
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen);
    int nreq = 0; int served_cmpct[2] = {0,0};
    while (nreq < 40) {
        plen=0; if(p2p_read(cfd,cmd,pl,sizeof pl,&plen)<=0) return;
        cmd[11]=0; nreq++;
        if(strncmp(cmd,"getheaders",10)==0){
            int from=0, zero=1; for(int z=0;z<32;z++) if(pl[5+z]) { zero=0; break; }
            if(zero) from=0; else { from=NB; if(plen>=37) for(int i=0;i<NB;i++) if(memcmp(pl+5,bh[i],32)==0) from=i+1; }
            int cnt = NB - from; if(cnt<0)cnt=0;
            if(cnt>0){ unsigned char hp[3+81*cnt]; hp[0]=cnt; int p=1; for(int i=from;i<NB;i++){ memcpy(hp+p, blocks[i], 80); hp[p+80]=0; p+=81; } p2p_write(cfd,"headers",7,hp,p); }
            else p2p_write(cfd,"headers",7,"\x00",1);
        } else if(strncmp(cmd,"getdata",7)==0){
            unsigned type; memcpy(&type, pl+1, 4);
            int found=-1; for(int i=0;i<NB;i++) if(memcmp(pl+5,bh[i],32)==0) found=i;
            if(found<0){ p2p_write(cfd,"block",5,"",0); continue; }
            if(type == 4){ (*saw_cmpct)++; unsigned char cb[4096]; long l = build_cmpct(cb, found, found == 0 && !served_cmpct[found]); served_cmpct[found]=1; p2p_write(cfd,"cmpctblock",10,cb,(unsigned)l); }
            else { (*saw_full)++; p2p_write(cfd,"block",5,blocks[found],(unsigned)blen[found]); }
        } else if(strncmp(cmd,"verack",6)==0 || strncmp(cmd,"wtxidrelay",10)==0 || strncmp(cmd,"sendaddrv2",10)==0 || strncmp(cmd,"sendcmpct",9)==0){ nreq--; continue; }
        else return;
    }
}
int main(void){
    unsigned char prev[32]; memset(prev,0,32);
    for(int i=0;i<2;i++){ blen[i]=build_cb_block(blocks[i], prev, i, &txoff[i], &txlen[i]); unsigned nz=0; while(!pow_check(blocks[i])){ nz++; put_u32(blocks[i]+76,nz); } block_hash(bh[i], blocks[i]); memcpy(prev, bh[i], 32); NB++; }
    tt_isolate();
    static unsigned char stbuf[4096]; if(store_init(stbuf)!=1){ printf("FAIL store_init\n"); return 1; }
    g_cmpct_hook_type = (void*)cmpct_getdata_type; g_cmpct_hook_cmpct = (void*)cmpct_recv_cmpctblock; g_cmpct_hook_blocktxn = (void*)cmpct_recv_blocktxn; g_cmpct_hook_fallback = (void*)cmpct_recv_note_fallback;
    g_peer_sendcmpct = 1; g_sync_mp = 0;
    int ls=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al); listen(ls,2);
    int pfd[2]; if(pipe(pfd)!=0) return 1;
    pid_t pid=fork();
    if(pid==0){ close(pfd[0]); int c=accept(ls,0,0); int sc=0, sf=0; fake_peer(c, &sc, &sf); close(c); int r[2]={sc,sf}; (void)!write(pfd[1], r, sizeof r); _exit(0); }
    close(pfd[1]);
    int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port); if(fd<0){ printf("FAIL connect\n"); return 1; }
    cki("handshake", node_handshake(fd), 1);
    unsigned char gen_loc[32]; memset(gen_loc,0,32); static unsigned char buf[65536]; long cnt=0;
    long sr=node_sync(fd, stbuf, gen_loc, buf, sizeof buf, &cnt);
    cki("the sync pass succeeds although block 0's compact block reconstructed badly (a full-block fallback, not where=8)", sr, 1);
    if(sr != 1) printf("     where=%d\n", sync_fail_code);
    cki("both blocks stored", cnt, 2);
    cki("store tip is block 1", *(int*)(stbuf+24), 1);
    close(fd); waitpid(pid,0,0); close(ls);
    int r[2]={0,0}; (void)!read(pfd[0], r, sizeof r);
    cki("the peer was asked for compact blocks", r[0] >= 2, 1);
    cki("... and for exactly one full block (block 0, after the bad reconstruction)", r[1], 1);
    unsigned long rc=0, nd=0, fb=0; cmpct_recv_stats(&rc, &nd, &fb);
    cki("one fallback counted", (long)fb, 1);
    cki("one block reconstructed from the compact block alone (block 1)", (long)rc >= 1, 1);
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
