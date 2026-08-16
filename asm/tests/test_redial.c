/* test_redial.c -- loopback e2e proving the OUTBOUND MUX re-dials a dead leg.
 *
 * Regression for soak-analysis defect D2: the old mux connected outbound legs
 * once up front and never re-dialed a leg that died or failed, leaving keep-up
 * silently single-seed-limited. This test proves the fix: after the outbound
 * peer drops its connection, the node's mux detects the dead fd (POLLHUP) in
 * its single poll() loop, closes it, and re-dials the peer pool. Recovery is
 * verified by the node pulling a block that only becomes available AFTER the
 * dead connection was replaced by a re-dialed one.
 *
 * Peer model: a single child binds OUT_PORT and accepts TWO successive
 * outbound connections (conn #1 = the node's initial leg, RIPPED down by
 * closing it; conn #2 = the node's re-dialed leg). A 'B' on grow_pipe exposes
 * block 5 to the SECOND connection only -- so if the re-dial never happens,
 * the node can never pull block 5 and the store never grows past block 4.
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
    for(int i=0;i<NB;i++){ blen[i]=build_cb_block(blk[i], prev,(unsigned)i);
        block_hash(bh[i], blk[i]); memcpy(prev,bh[i],32); }
}

/* Serve node_sync on cfd with `expose` current blocks; return after serving
 * `max_syncs` getheaders requests so the caller can RIP the connection. */
static void serve_conn(int cfd, int expose, int max_syncs){
    char cmd[12]; unsigned char pl[4096]; unsigned plen=0;
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen); cmd[11]=0;      /* node version */
    { unsigned char v[102]; memset(v,0,sizeof v); v[4]=1; p2p_write(cfd,"version",7,v,86);
      p2p_write(cfd,"verack",6,"",0); }
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen); cmd[11]=0;      /* node verack */
    struct timeval tv; tv.tv_sec=0; tv.tv_usec=100000; setsockopt(cfd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    int synced=0;
    for(int n=0;n<200000 && (max_syncs<0 || synced<max_syncs);n++){
        plen=0; int r=p2p_read(cfd,cmd,pl,sizeof pl,&plen);
        if(r<=0) continue; cmd[11]=0;
        if(strncmp(cmd,"getheaders",10)==0){
            synced++;
            int zero=1; for(int z=0;z<32;z++) if(pl[5+z]){zero=0;break;}
            int from=0; if(!zero){ from=expose; for(int i=0;i<expose;i++) if(memcmp(pl+5,bh[i],32)==0){from=i+1;break;} }
            int cnt=expose-from; if(cnt<0)cnt=0;
            if(cnt>0){ static unsigned char hp[3+81*NB]; hp[0]=(unsigned char)cnt; int p=1;
                for(int i=from;i<expose;i++){ memcpy(hp+p, blk[i],80); hp[p+80]=0; p+=81; }
                p2p_write(cfd,"headers",7,hp,p); }
            else p2p_write(cfd,"headers",7,"\x00",1);
        } else if(strncmp(cmd,"getdata",7)==0){
            int found=-1; for(int i=0;i<expose;i++) if(memcmp(pl+5,bh[i],32)==0) found=i;
            if(found>=0) p2p_write(cfd,"block",5,blk[found],(unsigned)blen[found]);
            else p2p_write(cfd,"block",5,"",0);
        } else if(strncmp(cmd,"ping",4)==0){
            p2p_write(cfd,"pong",4,pl,(plen>=8)?8:0);
        }
    }
}

/* PEER child: binds OUT_PORT (published via pipe), accepts conn #1 (the node's
 * initial leg, expose=5), closes it to RIP the leg, then accepts conn #2 (the
 * node's re-dialed leg; expose=5 until growpipe says 'B', then expose=6). */
static void peer(int port_pipe, int grow_pipe){
    int ls=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(ls,(struct sockaddr*)&a,sizeof a)<0){ _exit(9); }
    socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
    unsigned short port=ntohs(a.sin_port);
    unsigned char pb[2]; pb[0]=port; pb[1]=port>>8; write(port_pipe,pb,2);
    listen(ls,4);
    /* conn #1: initial leg. Serve blocks 0..4 through the node's first sync,
     * then return so we can RIP the connection (the D2 dead-leg trigger). */
    int c1=accept(ls,0,0);
    if(c1<0) _exit(9);
    serve_conn(c1, 5, 1);                               /* one sync, then return */
    close(c1);                                          /* RIP the leg */
    /* conn #2: the re-dialed leg (must arrive after the rip). */
    int c2=accept(ls,0,0);
    if(c2<0) _exit(9);
    /* once the re-dial lands, expose 6 so the node pulls block 5 ONLY via the
     * fresh leg (deterministic proof the re-dial recovered keep-up). */
    int gfd=grow_pipe>=0?grow_pipe:-1;
    if(gfd>=0){ int fl=fcntl(gfd,F_GETFL); fcntl(gfd,F_SETFL, fl|O_NONBLOCK); }
    int expose=5; int quit=0;
    char cmd2[12]; unsigned char pl2[4096]; unsigned plen2=0;
    plen2=0; p2p_read(c2,cmd2,pl2,sizeof pl2,&plen2); cmd2[11]=0;
    { unsigned char v[102]; memset(v,0,sizeof v); v[4]=1; p2p_write(c2,"version",7,v,86);
      p2p_write(c2,"verack",6,"",0); }
    plen2=0; p2p_read(c2,cmd2,pl2,sizeof pl2,&plen2); cmd2[11]=0;
    struct timeval tv2; tv2.tv_sec=0; tv2.tv_usec=100000; setsockopt(c2,SOL_SOCKET,SO_RCVTIMEO,&tv2,sizeof tv2);
    for(int n=0;n<200000 && !quit;n++){
        if(gfd>=0){ char c; if(read(gfd,&c,1)==1){ if(c=='B') expose=6; if(c=='Q') quit=1; } }
        if(quit) break;
        plen2=0; int r=p2p_read(c2,cmd2,pl2,sizeof pl2,&plen2);
        if(r<=0) continue; cmd2[11]=0;
        if(strncmp(cmd2,"getheaders",10)==0){
            int zero=1; for(int z=0;z<32;z++) if(pl2[5+z]){zero=0;break;}
            int from=0; if(!zero){ from=expose; for(int i=0;i<expose;i++) if(memcmp(pl2+5,bh[i],32)==0){from=i+1;break;} }
            int cnt=expose-from; if(cnt<0)cnt=0;
            if(cnt>0){ static unsigned char hp[3+81*NB]; hp[0]=(unsigned char)cnt; int p=1;
                for(int i=from;i<expose;i++){ memcpy(hp+p, blk[i],80); hp[p+80]=0; p+=81; }
                p2p_write(c2,"headers",7,hp,p); }
            else p2p_write(c2,"headers",7,"\x00",1);
        } else if(strncmp(cmd2,"getdata",7)==0){
            int found=-1; for(int i=0;i<expose;i++) if(memcmp(pl2+5,bh[i],32)==0) found=i;
            if(found>=0) p2p_write(c2,"block",5,blk[found],(unsigned)blen[found]);
            else p2p_write(c2,"block",5,"",0);
        } else if(strncmp(cmd2,"ping",4)==0){ p2p_write(c2,"pong",4,pl2,(plen2>=8)?8:0); }
    }
    close(c2); close(ls); _exit(0);
}

static int inbound_getdata(int port, int h){
    int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK),(unsigned short)htons((unsigned short)port));
    if(fd<0){ printf("[client] connect failed\n"); return 0; }
    struct timeval tv; tv.tv_sec=4; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    if(node_handshake(fd)!=1){ close(fd); printf("[client] handshake fail\n"); return 0; }
    { char dc[12]; unsigned char db[64]; unsigned dbl=0; int r=p2p_read(fd,dc,db,sizeof db,&dbl); (void)r; }
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
    char p[512]; snprintf(p,sizeof p,"%s/blk00000.dat",dir);
    struct stat st; if(stat(p,&st)!=0) return -1; return (long)st.st_size;
}

int main(int argc, char** argv){
    setbuf(stdout,NULL);
    signal(SIGPIPE,SIG_IGN);
    build_chain();
    if(argc<2){ fprintf(stderr,"usage: %s <path-to-daemon/bitcoind>\n",argv[0]); return 2; }
    const char* daemon=argv[1];
    char ndir[128]; snprintf(ndir,sizeof ndir,"/tmp/redial_%d",(int)getpid());
    mkdir(ndir,0755);

    int portpipe[2], growpipe[2];
    if(pipe(portpipe)||pipe(growpipe)){ printf("FAIL pipe\n"); return 1; }
    pid_t peer_pid=fork();
    if(peer_pid==0){ close(portpipe[0]); close(growpipe[1]);
        peer(portpipe[1], growpipe[0]); _exit(9); }
    close(portpipe[1]); close(growpipe[0]);
    unsigned char pb[4]; unsigned short out_port=0;
    { int nr=read(portpipe[0],pb,2); if(nr==2) out_port=pb[0]|(pb[1]<<8); }
    close(portpipe[0]);
    if(out_port==0){ printf("FAIL: peer never published port\n"); return 1; }

    int serve_port = 24000 + ((int)getpid()%18000);
    char sport[16], oport[16];
    snprintf(sport,sizeof sport,"%d",serve_port);
    snprintf(oport,sizeof oport,"%d",(int)out_port);
    pid_t node=fork();
    if(node==0){
        char* av[] = { (char*)daemon, "serve-test", ndir, sport, "127.0.0.1", oport, "1", NULL };
        execv(daemon, av);
        perror("execv node"); _exit(9);
    }
    /* let the node connect leg #1 + pull 0..4 (the peer then rips the leg) */
    usleep(1500000);

    /* give the mux time to detect the RIP (POLLHUP) and re-dial leg #2 */
    usleep(1500000);

    /* expose block 5 to the RE-DIALED leg only, then let it be pulled */
    write(growpipe[1],"B",1);
    for(int w=0; w<60; w++){
        usleep(50000);
    }

    int s0 = inbound_getdata(serve_port, 0);
    cki("node serves stored block 0 (mux alive through leg loss)", s0, 1);

    /* the crux: block 5 exists but was only exposed to the RE-DIALED leg. */
    int s5 = inbound_getdata(serve_port, 5);
    cki("node pulls block 5 via RE-DIALED leg (recovery proven)", s5, 1);

    long sz = blkfile_size(ndir);
    cki("store grew (block 5 appended after re-dial)", sz>765?1:0, 1);

    write(growpipe[1],"Q",1);
    int st1,st2; kill(node,SIGTERM); waitpid(node,&st1,0); kill(peer_pid,SIGTERM); waitpid(peer_pid,&st2,0);
    close(growpipe[1]);
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
