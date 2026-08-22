/* test_ibd_headers.c -- deterministic loopback test of the PERSISTENT paged
 * headers-first IBD loop: asm node_ibd_headers (bitcoind.asm) over a real
 * loopback socket against a C fixture peer, persisting into the asm header
 * store (bitcoin_headers.asm).
 *
 * The asm client under test:
 *   node_ibd_headers(fd, hst*, locator32, page_buf, buflen)
 * repeatedly (1) getheaders(locator), (2) drains to one `headers` page,
 * (3) verifies chain continuity for every header, (4) computes each block_hash
 * and hst_appends (header,hash), (5) advances the running locator to the last
 * appended hash. Multiple pages are exercised (a 2500-header chain forces a
 * full 2000-header page then a 500-header short page), plus tip-detection and
 * a continuity-break rejection.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <time.h>
#include "test_tmpdir.h"

/* ---- asm under test ---- */
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd, const char *cmd, unsigned cmdlen, const void *pl, unsigned plen);
extern int  p2p_read(int fd, char cmd_out[12], void *pl, unsigned cap, unsigned *len_out);
extern void fd_close(int fd);
extern int  node_handshake(int fd);
extern long node_ibd_headers(int fd, void* hst, void* locator32, void* page_buf, unsigned long buflen);
extern int  hst_init(void* hst);
extern int  hst_reload(void* hst);
extern long hst_count(void* hst);
extern int  hst_get_at(void* hst, unsigned long long height, void* out);
extern void block_hash(void* out, const void* hdr);

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }
static void put_u16be(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}
static void put_u32le(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64le(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}

#define NCHAIN 2500

/* precomputed header chain + hashes (hashes via the proven asm block_hash) */
static unsigned char chain[NCHAIN][80];
static unsigned char chainhash[NCHAIN][32];

static void build_chain(void){
    /* header 0: genesis-style (prev = 0) */
    put_u32le(chain[0]+0, 0x20000000);
    memset(chain[0]+4, 0, 32);
    memset(chain[0]+36, 7, 32);
    put_u32le(chain[0]+68, 1700000000u);
    put_u32le(chain[0]+72, 0x1d00ffff);
    put_u32le(chain[0]+76, 0);
    block_hash(chainhash[0], chain[0]);
    for(int i=1;i<NCHAIN;i++){
        put_u32le(chain[i]+0, 0x20000000);
        memcpy(chain[i]+4, chainhash[i-1], 32);   /* prevhash chains */
        memset(chain[i]+36, 7, 32);
        memset(chain[i]+68, i&0xff, 4);
        put_u32le(chain[i]+68, (unsigned)(1700000000u + i));
        put_u32le(chain[i]+72, 0x1d00ffff);
        put_u32le(chain[i]+76, (unsigned)i);
        block_hash(chainhash[i], chain[i]);
    }
}

/* serve a `headers` page after `idx` (up to 2000 entries starting at idx+1).
 * If idx == NCHAIN-1 (nothing after), serve an empty headers message. */
static long serve_headers_page(int cfd, int idx){
    int n = NCHAIN - (idx+1);
    if(n > 2000) n = 2000;
    if(n <= 0) n = 0;
    size_t msz;
    unsigned char msg[3 + 2000*81];
    int o = 0;
    if(n >= 253){ msg[o++]=0xfd; msg[o++]=(unsigned char)(n&0xff); msg[o++]=(unsigned char)(n>>8); }
    else { msg[o++]=(unsigned char)n; }
    for(int i=0;i<n;i++){
        int ci = idx+1+i;
        memcpy(msg+o, chain[ci], 80); o+=80;
        msg[o++]=0;                                   /* tx count = 0 */
    }
    msz = o;
    return p2p_write(cfd,"headers",7,msg,msz)>0 ? 1 : 0;
}

/* fake peer: handshake then serve paged headers off a locator index. */
static void serve_peer(int cfd, int evil){
    unsigned char rbuf[8192]; char cmd[12]; unsigned plen=0;
    /* handshake: read our version, answer version+verack */
    if (p2p_read(cfd,cmd,rbuf,sizeof(rbuf),&plen)<=0) return;
    unsigned char v[102]; int o=0;
    put_u32le(v+o,70016);o+=4; put_u64le(v+o,1);o+=8;
    put_u64le(v+o,(unsigned long long)time(NULL));o+=8;
    put_u64le(v+o,1);o+=8; memset(v+o,0,16);o+=16;
    put_u16be(v+o,8333);o+=2; put_u64le(v+o,1);o+=8; memset(v+o,0,16);o+=16;
    put_u16be(v+o,0);o+=2; put_u64le(v+o,0x9999999999999999ULL);o+=8;
    const char*ua="/peer:0.1/"; v[o]=strlen(ua);o++;memcpy(v+o,ua,strlen(ua));o+=strlen(ua);
    put_u32le(v+o,0);o+=4; v[o]=1;o++;
    p2p_write(cfd,"version",7,v,o);
    p2p_write(cfd,"verack",6,"",0);
    /* read our verack then loop serving getheaders pages */
    int idx = -1;                       /* not-a-header (start from genesis) */
    for(int i=0;i<200;i++){
        if (p2p_read(cfd,cmd,rbuf,sizeof(rbuf),&plen)<=0) break;
        cmd[11]=0;
        if (strncmp(cmd,"verack",6)==0) continue;
        if (strncmp(cmd,"ping",4)==0){ p2p_write(cfd,"pong",4,rbuf,8); continue; }
        if (strncmp(cmd,"getheaders",10)==0){
            /* getheaders payload (real wire): [version u32][count varint][hash..][stop].
               For count==1, the single locator hash is at +5 (4-byte version + 1-byte
               count). */
            const unsigned char* loc = rbuf+5;
            /* find locator index; zero locator => start from genesis (idx=-1) */
            int found=-1;
            int allzero=1; for(int b=0;b<32;b++) if(loc[b]!=0){allzero=0;break;}
            if(!allzero){
                for(int k=0;k<NCHAIN;k++) if(memcmp(chainhash[k],loc,32)==0){found=k;break;}
            }
            if(found<0) idx = -1; else idx = found;
            if (evil && idx==-1){
                /* evil peer: first page chained, 2nd header broken. Simulate by
                   serving 2 headers: header0 chains off locator, header1's
                   prevhash is wrong (does not chain header0). */
                unsigned char msg[3+2*81]; int oo=0;
                msg[oo++]=2;
                memcpy(msg+oo, chain[0],80); oo+=80; msg[oo++]=0;
                memcpy(msg+oo, chain[2],80); oo+=80; msg[oo++]=0;
                p2p_write(cfd,"headers",7,msg,oo);
                return;
            }
            if(!serve_headers_page(cfd, idx)) return;
        }
    }
}

struct Hst { unsigned long long fd, count; };

int run_case(int evil){
    /* listening socket, loopback ephemeral */
    int ls = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET;
    a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(ls,(struct sockaddr*)&a,sizeof a)!=0){ printf("FAIL bind\n"); return -1; }
    socklen_t alen=sizeof a; getsockname(ls,(struct sockaddr*)&a,&alen);
    listen(ls,1);
    unsigned short port = ntohs(a.sin_port);
    pid_t pid=fork();
    if(pid==0){ int cfd=accept(ls,0,0); serve_peer(cfd,evil); _exit(0); }

    tt_isolate();

    struct Hst hs; memset(&hs,0,sizeof hs);
    hst_init(&hs);
    unsigned ip=htonl(INADDR_LOOPBACK);
    int fd=tcp_connect_ip(ip,htons(port));
    if(fd<0){ printf("FAIL connect\n"); return -1; }
    int hk=node_handshake(fd);

    /* initial locator = zero (start from genesis) */
    static unsigned char loc[32]; memset(loc,0,32);
    /* 2MB+ page buffer (node_ibd_headers requires >= 2,000,000 cap, and
       node_fetch_headers internally caps reads at 2,000,000). */
    static unsigned char pagebuf[1<<22];
    long total = node_ibd_headers(fd, &hs, loc, pagebuf, sizeof pagebuf);
    fd_close(fd);
    waitpid(pid,0,0); close(ls);

    long expect = evil ? -1 : NCHAIN;
    cki(evil?"ibd evil -> -1":"ibd total == 2500", total, expect);
    if(!evil && total==NCHAIN){
        cki("hst_count == 2500", hst_count(&hs), NCHAIN);
        /* store chain continuity + tip hash */
        int cont=1;
        static unsigned char rec[112];
        for(int i=0;i<NCHAIN;i++){
            hst_get_at(&hs,i,rec);
            if(memcmp(rec, chain[i],80)!=0) cont=0;
            if(memcmp(rec+80, chainhash[i],32)!=0) cont=0;
        }
        cki("stored (hdr,hash) match chain", cont, 1);
        /* running locator (out) == tip hash */
        cki("locator advanced to tip hash", memcmp(loc, chainhash[NCHAIN-1],32)==0, 1);
        /* restart-resume: reload then re-run from tip -> 0 new, count stable */
        struct Hst hs2; memset(&hs2,0,sizeof hs2);
        hst_init(&hs2); hst_reload(&hs2);
        cki("reload count == 2500", hst_count(&hs2), NCHAIN);
        /* re-run against a peer that serves nothing after tip */
        int ls2=socket(AF_INET,SOCK_STREAM,0);
        struct sockaddr_in a2; memset(&a2,0,sizeof a2); a2.sin_family=AF_INET;
        a2.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        bind(ls2,(struct sockaddr*)&a2,sizeof a2);
        socklen_t a2len=sizeof a2; getsockname(ls2,(struct sockaddr*)&a2,&a2len);
        listen(ls2,1); unsigned short p2=ntohs(a2.sin_port);
        pid_t pid2=fork();
        if(pid2==0){ int c=accept(ls2,0,0);
            /* node_ibd_headers sends getheaders as its FIRST message (no separate
               handshake); serve the matching page (empty at tip) right away. */
            unsigned char rb[8192]; char cd[12]; unsigned pl=0;
            for(int i=0;i<100;i++){
                if(p2p_read(c,cd,rb,sizeof rb,&pl)<=0) _exit(0); cd[11]=0;
                if(strncmp(cd,"getheaders",10)==0){
                    const unsigned char* loc2=rb+5;   /* +4 version +1 count */
                    int fx=-1; for(int k=0;k<NCHAIN;k++) if(memcmp(chainhash[k],loc2,32)==0){fx=k;break;}
                    serve_headers_page(c, fx);   /* fx==NCHAIN-1 -> empty page */
                    break;
                }
            }
            _exit(0);
        }
        int fd2=tcp_connect_ip(ip,htons(p2));
        static unsigned char loc2[32];
        memcpy(loc2, chainhash[NCHAIN-1],32);
        long more = node_ibd_headers(fd2, &hs2, loc2, pagebuf, sizeof pagebuf);
        fd_close(fd2); waitpid(pid2,0,0); close(ls2);
        cki("rerun at tip -> 0 new", more, 0);
        cki("count stays 2500", hst_count(&hs2), NCHAIN);
    } else {
        /* evil peer should have stopped after the 1 valid header */
        cki("evil: only 1 header stored", hst_count(&hs), 1);
    }
    return 0;
}

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    build_chain();
    run_case(0);
    run_case(1);
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
