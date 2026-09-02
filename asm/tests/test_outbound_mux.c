/* test_outbound_mux.c -- loopback e2e for the OUTBOUND P2P MULTIPLEXER.
 *
 * Proves the RUNNING node (daemon/bitcoind serve-test) continuously downloads
 * newly "mined" blocks WITHOUT restart while still serving stored blocks to a
 * concurrent inbound peer -- the keep-current half the old fork-per-inbound
 * serve lacked. A persistent outbound connection polls getheaders-from-tip
 * (node_sync) and feeds discovered blocks through cons_verify -> store_append,
 * so the store advances on its own. All three roles are REAL processes on
 * loopback (no internet dependency).
 *
 * Flow:
 *   1. MINING-PEER child listens on OUT_PORT, serves the asm node_sync
 *      protocol (headers pages + getdata blocks) from a chain of NB=6 blocks,
 *      initially exposing only blocks 0..4.
 *   2. NODE child = exec daemon/bitcoind serve-test <dir> <SERVE> 127.0.0.1
 *      <OUT>: connects OUTBOUND to the peer, runs the poll() multiplexer
 *      (accept+inbound-fork + outbound node_sync). Pulls 0..4, then stays
 *      current polling for new ones while keeping its inbound listener open.
 *   3. Test connects INBOUND to the node and getdata's block 0 (already
 *      stored) -> served byte-exact => concurrent serving works.
 *   4. Test signals the peer to "mine" block 5 (expose one more).
 *   5. Node's next outbound node_sync pass pulls block 5 into its store (NO
 *      restart). Verified by (a) the node's blk file growing and (b) a second
 *      inbound getdata for block 5 returned byte-exact.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "test_tmpdir.h"

extern long p2p_write(int,const char*,unsigned,const void*,unsigned);
extern int  p2p_read(int,char[12],void*,unsigned,unsigned*);
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long node_handshake(int fd);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void sha256d(unsigned char o[32], const void* m, long l);
extern int  pow_check(const unsigned char h[80]);

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }

static void put_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++)p[i]=v>>(8*i);}

#define NB 6
static unsigned char blk[NB][2048];
static long blen[NB];
static unsigned char bh[NB][32];

static long build_cb_block(unsigned char* b, const unsigned char prev[32], unsigned hgt){
    unsigned char* o=b;
    unsigned char t[200]; memset(t,0,sizeof t); unsigned char* q=t;
    put_u32(q,1); q+=4; q[0]=1; q+=1; memset(q,0,32); q+=32;
    put_u32(q,0xffffffff); q+=4;
    q[0]=3; q[1]=(unsigned char)hgt; q[2]=0; q[3]=0; q+=4;
    put_u32(q,0xffffffff); q+=4;
    q[0]=1; q+=1; put_u64(q,8*1000000ull); q+=8;
    q[0]=1; q[1]=0x51; q+=2; put_u32(q,0); q+=4;
    long tlen=q-t; unsigned char mr[32]; sha256d(mr,t,tlen);
    put_u32(o,1); o+=4; memcpy(o,prev,32); o+=32; memcpy(o,mr,32); o+=32;
    put_u32(o,1300000000u); o+=4; put_u32(o,0x207fffff); o+=4; put_u32(o,0); o+=4;
    o[0]=1; o+=1; memcpy(o,t,tlen); o+=tlen;
    unsigned nz=0; while(!pow_check(b)){ nz++; put_u32(b+76,nz); }
    return (long)(o-b);
}

static void build_chain(void){
    unsigned char prev[32]; memset(prev,0,32);
    for(int i=0;i<NB;i++){
        blen[i]=build_cb_block(blk[i], prev,(unsigned)i);
        block_hash(bh[i], blk[i]); memcpy(prev,bh[i],32);
    }
}

/* MINING PEER: the node's OUTBOUND peer. Binds ephemeral listener in the
 * CHILD, writes the bound port to port_pipe, then serves node_sync on the
 * first accepted (the node's outbound) connection. Exposes GROW blocks; a
 * 'M' byte on grow_pipe "mines" the next one. */
static void mining_peer(int port_pipe, int grow_pipe, int stat_pipe){
    int ls=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(ls,(struct sockaddr*)&a,sizeof a)<0){ fprintf(stderr,"[peer] bind fail\n"); _exit(9); }
    socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
    unsigned short port=ntohs(a.sin_port);
    unsigned char pb[4]; pb[0]=port; pb[1]=port>>8; if(write(port_pipe,pb,2)!=2) _exit(9);
    listen(ls,4);
    int cfd=accept(ls,0,0);
    if(cfd<0) _exit(9);
    close(ls);
    /* handshake (we are the OUTBOUND target/peer; the node sends us its
     * version first as the outbound initiator via node_handshake) */
    char cmd[12]; unsigned char pl[4096]; unsigned plen=0;
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen); cmd[11]=0;      /* node version */
    /* speak 70016 and offer BIP155 before our verack, so the REAL daemon's
     * outbound handshake (a) offers sendaddrv2 back and (b) records our
     * offer per leg -- the mux log line then carries addrv2=1 */
    { unsigned char v[102]; memset(v,0,sizeof v); v[0]=0x80; v[1]=0x11; v[2]=0x01; v[4]=9;
      p2p_write(cfd,"version",7,v,86);
      p2p_write(cfd,"sendaddrv2",10,"",0);
      p2p_write(cfd,"verack",6,"",0); }
    /* the node's pre-verack messages: wtxidrelay, then sendaddrv2 once our
     * version arrived, then its verack */
    for(int i=0;i<6;i++){
        plen=0; if(p2p_read(cfd,cmd,pl,sizeof pl,&plen)<=0) break; cmd[11]=0;
        if(strncmp(cmd,"sendaddrv2",10)==0 && stat_pipe>=0) (void)!write(stat_pipe,"S",1);
        if(strncmp(cmd,"verack",6)==0) break;
    }
    int grow=5;
    int gfd=grow_pipe>=0? grow_pipe : -1;
    if(gfd>=0){ int fl=fcntl(gfd,F_GETFL); fcntl(gfd,F_SETFL, fl|O_NONBLOCK); }
    struct timeval tv; tv.tv_sec=0; tv.tv_usec=200000; setsockopt(cfd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    for(int n=0;n<100000;n++){
        if(gfd>=0){ char c; if(read(gfd,&c,1)==1 && c=='M' && grow<NB) grow++; }
        plen=0; int r=p2p_read(cfd,cmd,pl,sizeof pl,&plen);
        if(r<=0) continue;
        cmd[11]=0;
        if(strncmp(cmd,"getheaders",10)==0){
            int zero=1; for(int z=0;z<32;z++) if(pl[5+z]){zero=0;break;}
            int from=0; if(!zero){ from=grow; for(int i=0;i<grow;i++) if(memcmp(pl+5,bh[i],32)==0){from=i+1;break;} }
            int cnt=grow-from; if(cnt<0)cnt=0;
            if(cnt>0){ static unsigned char hp[3+81*NB]; hp[0]=(unsigned char)cnt; int p=1;
                for(int i=from;i<grow;i++){ memcpy(hp+p, blk[i],80); hp[p+80]=0; p+=81; }
                p2p_write(cfd,"headers",7,hp,p); }
            else p2p_write(cfd,"headers",7,"\x00",1);
        } else if(strncmp(cmd,"getdata",7)==0){
            int found=-1; for(int i=0;i<grow;i++) if(memcmp(pl+5,bh[i],32)==0) found=i;
            if(found>=0) p2p_write(cfd,"block",5,blk[found],(unsigned)blen[found]);
            else p2p_write(cfd,"block",5,"",0);
        } else if(strncmp(cmd,"ping",4)==0){
            p2p_write(cfd,"pong",4,pl,(plen>=8)?8:0);
        }
    }
    close(cfd); _exit(0);
}

/* connect to the node's INBOUND serve port and getdata block h; returns 1 if
 * the node served it byte-exact (draining non-block frames like announce inv
 * / pong), else 0. */
static int inbound_getdata(int port, int h){
    int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK),(unsigned short)htons((unsigned short)port));
    if(fd<0){ printf("[client] connect failed\n"); return 0; }
    struct timeval tv; tv.tv_sec=4; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    if(node_handshake(fd)!=1){ close(fd); printf("[client] handshake fail\n"); return 0; }
    /* drain the leading feefilter/sendheaders the serve loop advertises */
    { char dc[12]; unsigned char db[64]; unsigned dbl=0;
      int r=p2p_read(fd,dc,db,sizeof db,&dbl); (void)r; }
    /* getdata for block h */
    unsigned char gd[37]; gd[0]=1; gd[1]=2; gd[2]=0; gd[3]=0; gd[4]=0;
    memcpy(gd+5, bh[h], 32);
    p2p_write(fd,"getdata",7,gd,37);
    int got=0;
    for(int t=0;t<20 && !got;t++){
        char c[12]; static unsigned char r1[4096]; unsigned n1=0;
        int rr=p2p_read(fd,c,r1,sizeof r1,&n1);
        if(rr<=0) break;
        if(!strncmp(c,"block",5) && (long)n1==blen[h] && memcmp(r1,blk[h],(size_t)n1)==0) got=1;
    }
    close(fd);
    return got;
}

static long blkfile_size(const char* dir){
    char p[512]; snprintf(p,sizeof p,"%s/main/blk00000.dat",dir);   /* every chain in its own subdir now */
    struct stat st; if(stat(p,&st)!=0) return -1; return (long)st.st_size;
}

int main(int argc, char** argv){
    setbuf(stdout,NULL);
    signal(SIGPIPE,SIG_IGN);
    build_chain();
    if(argc<2){ fprintf(stderr,"usage: %s <path-to-daemon/bitcoind>\n",argv[0]); return 2; }
    tt_isolate();
    const char* daemon=tt_src(argv[1]);

    /* ---- node working dir ---- */
    /* The daemon takes its datadir as an argument, so hand it this test's
     * private directory rather than a pid-named /tmp path that nothing
     * ever removed. tt_isolate() also chdir()s, so the daemon path from
     * argv (a repo-relative ./daemon/bitcoind) is rebased with tt_src(). */
    const char* ndir = tt_workdir();

    /* ---- start MINING PEER, get its OUT_PORT via pipe ---- */
    int portpipe[2], growpipe[2], statpipe[2];
    if(pipe(portpipe)||pipe(growpipe)||pipe(statpipe)){ printf("FAIL pipe\n"); return 1; }
    pid_t peer=fork();
    if(peer==0){ close(portpipe[0]); close(growpipe[1]); close(statpipe[0]);
        mining_peer(portpipe[1], growpipe[0], statpipe[1]); _exit(9);
    }
    close(portpipe[1]); close(growpipe[0]); close(statpipe[1]);
    unsigned char pb[4]; unsigned short out_port=0;
    { int nr=read(portpipe[0],pb,2); if(nr==2) out_port=pb[0]|(pb[1]<<8); }
    close(portpipe[0]);
    if(out_port==0){ printf("FAIL: peer never published port\n"); return 1; }

    /* ---- SERVE_PORT for the node's inbound listener (pid-offset, avoid
     * collisions) ---- */
    int serve_port = 24000 + ((int)getpid()%18000);

    /* ---- start NODE (serve-test = outbound mux, loopback peer) ---- */
    char sport[16], oport[16];
    snprintf(sport,sizeof sport,"%d",serve_port);
    snprintf(oport,sizeof oport,"%d",(int)out_port);
    pid_t node=fork();
    if(node==0){
        /* the node's stderr goes to a file so the test can read its leg log */
        int ef=open("node.err", O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if(ef>=0){ dup2(ef,2); close(ef); }
        char* av[] = { (char*)daemon, "serve-test", (char*)ndir, sport, "127.0.0.1", oport, "1", NULL };
        execv(daemon, av);
        perror("execv node"); _exit(9);
    }
    /* give the node time to connect outbound + pull 0..4 (a few poll iters) */
    usleep(1200000);

    /* concurrent serving check: fetch block 0 (already stored) */
    int s0 = inbound_getdata(serve_port, 0);
    cki("concurrent inbound: stored block 0 served byte-exact", s0, 1);

    long size_before = blkfile_size(ndir);

    /* ---- mine block 5 ---- */
    if(write(growpipe[1],"M",1)!=1){ printf("FAIL growpipe write\n"); failures++; }

    /* give the node's next node_sync pass time to pull block 5 */
    for(int w=0; w<40; w++){
        usleep(50000);
        /* stop early once blk file grows (block 5 appended) */
        if(blkfile_size(ndir) > size_before) break;
    }

    long size_after = blkfile_size(ndir);
    cki("store grew after new block mined (blk file)", size_after>size_before?1:0, 1);
    printf("  (blk00000.dat %ld -> %ld)\n", size_before, size_after);

    /* ---- the node pulled + stored + now serves the NEW block ---- */
    int s5 = inbound_getdata(serve_port, 5);
    cki("node serves freshly-mined block 5 (no restart)", s5, 1);

    /* ---- BIP155 on a REAL outbound leg of the real daemon ---- */
    { char c=0; int fl=fcntl(statpipe[0],F_GETFL); fcntl(statpipe[0],F_SETFL,fl|O_NONBLOCK);
      int got = read(statpipe[0],&c,1)==1 && c=='S';
      cki("daemon offered sendaddrv2 on its outbound handshake (peer saw it pre-verack)", got, 1); }
    { FILE* f=fopen("node.err","r"); int seen=0, seen_v1=0; char line[512];
      if(f){ while(fgets(line,sizeof line,f)){
          if(strstr(line,"outbound 0 =") && strstr(line,"addrv2=1")) seen=1;
          if(strstr(line,"outbound 0 =") && strstr(line,"addrv2=0")) seen_v1=1; }
        fclose(f); }
      cki("leg log records the peer's offer: 'outbound 0 = ... addrv2=1'", seen && !seen_v1, 1); }

    /* cleanup */
    (void)!write(growpipe[1],"Q",1);   /* cleanup: the peer is killed next anyway */
    int st1,st2; kill(node,SIGTERM); waitpid(node,&st1,0); kill(peer,SIGTERM); waitpid(peer,&st2,0);
    close(growpipe[1]);
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
