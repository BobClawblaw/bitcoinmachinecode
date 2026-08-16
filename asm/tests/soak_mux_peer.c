/* soak_mux_peer.c -- CONTROLED MINING PEER for the outbound-mux soak harness.
 *
 * This is the soak variant of the mining-peer role from
 * tests/test_outbound_mux.c, extended for unattended long runs:
 *
 *   - Binds an ephemeral loopback listener, publishes the port on a pipe.
 *   - Accepts ONE inbound connection = the NODE's outbound mux leg.
 *   - Serves the asm node_sync protocol (getheaders-from-locator + getdata)
 *     from a GROWING chain. "Real tip advance" = it keeps mining a new
 *     block every --mine-every seconds (default 15s), so the node's
 *     outbound mux must continuously pull + store new blocks to keep up.
 *   - Periodically RE-CONNECTS to the node's INBOUND serve port and
 *     getdata's the latest stored block -- proving the node serves
 *     concurrently while downloading (the mux must not starve serving).
 *
 * Wire protocol is identical to test_outbound_mux.c's mining_peer:
 *   node_sync: getheaders(locator) -> headers page; getdata(hash) -> block.
 *   ping is answered with pong. Unknown/other messages are ignored.
 *
 * The peer itself is instrumented: every poll iteration it samples its own
 * poll() latency + poll count (the peer mirrors the node's poll loop shape)
 * and appends a JSONL line to the metrics file. If the node's outbound leg
 * closes, the peer exits with a distinct code so the controller can detect
 * "mux stopped" independently of the node process dying.
 *
 * Exit codes:
 *   0 = clean shutdown (received 'Q' on control pipe)
 *   3 = node closed its outbound leg (mux peer gone)
 *   9 = internal bind/pipe failure
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
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern long p2p_write(int,const char*,unsigned,const void*,unsigned);
extern int  p2p_read(int,char[12],void*,unsigned,unsigned*);
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long node_handshake(int fd);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void sha256d(unsigned char o[32], const void* m, long l);
extern int  pow_check(const unsigned char h[80]);

/* ---- dynamic chain (linked list of growing blocks) ----
 * Blocks are ~2048 bytes each; a 24h run at 15s mining = 5760 blocks.
 * We keep them in a growable heap array, exposed count = chain_len. */
#define BLOCK_CAP 2048
#define NB_MAX 49152            /* ~115 days of 15s mining; 49152*2048B=96MB chain */
static unsigned char* chain_blk = 0;    /* [chain_cap * BLOCK_CAP] */
static long chain_cap = 0;
static long chain_len = 0;              /* exposed (mined) blocks */
static unsigned long chain_blklen[NB_MAX]; /* actual serialized length per block */
static unsigned char* chain_hash = 0;   /* [chain_cap * 32] */
static long mine_every = 15;            /* seconds between mined blocks */
static int serve_port = 0;              /* node's inbound serve port */
static int probe_every = 10;            /* inbound probe every N poll iters */

static void put_u32x(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64x(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++)p[i]=v>>(8*i);}

static long build_cb_block(unsigned char* b, const unsigned char prev[32], unsigned hgt){
    /* Same shape as test_outbound_mux: minimal block, difficulty 0x207fffff,
     * nonce searched until pow_check passes. Deterministic per (prev,hgt). */
    unsigned char* o=b;
    unsigned char t[200]; memset(t,0,sizeof t); unsigned char* q=t;
    put_u32x(q,1); q+=4; q[0]=1; q+=1; memset(q,0,32); q+=32;
    put_u32x(q,0xffffffff); q+=4;
    q[0]=3; q[1]=(unsigned char)hgt; q[2]=0; q[3]=0; q+=4;
    put_u32x(q,0xffffffff); q+=4;
    q[0]=1; q+=1; put_u64x(q,8*1000000ull); q+=8;
    q[0]=1; q[1]=0x51; q+=2; put_u32x(q,0); q+=4;
    long tlen=q-t; unsigned char mr[32]; sha256d(mr,t,tlen);
    put_u32x(o,1); o+=4; memcpy(o,prev,32); o+=32; memcpy(o,mr,32); o+=32;
    put_u32x(o,1300000000u); o+=4; put_u32x(o,0x207fffff); o+=4; put_u32x(o,0); o+=4;
    o[0]=1; o+=1; memcpy(o,t,tlen); o+=tlen;
    unsigned nz=0; while(!pow_check(b)){ nz++; put_u32x(b+76,nz); }
    return (long)(o-b);
}

static int chain_reserve(long need){
    if(need <= chain_cap) return 1;
    if(need > NB_MAX){ fprintf(stderr,"[soakpeer] chain cap reached\n"); return 0; }
    long nc = chain_cap ? chain_cap*2 : 1024;
    while(nc < need) nc *= 2;
    if(nc > NB_MAX) nc = NB_MAX;
    unsigned char* nb = realloc(chain_blk, (size_t)nc*BLOCK_CAP);
    unsigned char* nh = realloc(chain_hash, (size_t)nc*32);
    if(!nb||!nh){ free(nb); free(nh); return 0; }
    chain_blk = nb; chain_hash = nh; chain_cap = nc;
    return 1;
}

static void mine_block(void){
    if(chain_len >= NB_MAX){ fprintf(stderr,"[soakpeer] chain cap reached (len=%ld cap=%ld)\n", chain_len, (long)NB_MAX); exit(9); }
    if(!chain_reserve(chain_len+1)){ fprintf(stderr,"[soakpeer] chain alloc fail (len=%ld need=%ld)\n", chain_len, (long)chain_len+1); exit(9); }
    unsigned char prev[32];
    if(chain_len==0) memset(prev,0,32);
    else memcpy(prev, chain_hash+(chain_len-1)*32, 32);
    long blen = build_cb_block(chain_blk + chain_len*BLOCK_CAP, prev, (unsigned)chain_len);
    chain_blklen[chain_len] = (unsigned long)blen;
    block_hash(chain_hash + chain_len*32, chain_blk + chain_len*BLOCK_CAP);
    (void)blen;
    chain_len++;
}

/* ---- metrics: peer-side JSONL (peer's own poll loop shape) ---- */
static FILE* mlog = 0;
static void metrics_line(long poll_iters, long long poll_us_total, long long tip){
    if(!mlog) return;
    double now = 0; { struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts); now = ts.tv_sec + ts.tv_nsec/1e9; }
    fprintf(mlog, "{\"ts\":%.3f,\"role\":\"peer\",\"poll_iters\":%ld,\"poll_avg_us\":%lld,"
                  "\"chain_len\":%lld}\n",
            now, poll_iters, poll_us_total? poll_us_total/poll_iters : 0, tip);
    fflush(mlog);
}

/* ---- inbound serve probe: prove the node serves while downloading ---- */
static int probe_serve(long tip_height){
    int fd = tcp_connect_ip(htonl(INADDR_LOOPBACK), (unsigned short)htons((unsigned short)serve_port));
    if(fd<0) return -1;
    struct timeval tv; tv.tv_sec=8; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    long ok = node_handshake(fd);
    if(ok!=1){ close(fd); return -1; }
    /* drain leading chatter (feefilter/sendheaders) */
    { char dc[12]; unsigned char db[512]; unsigned dbl=0; int r=p2p_read(fd,dc,db,sizeof db,&dbl); (void)r; }
    /* getdata for the tip block by hash */
    if(tip_height < 0 || tip_height >= chain_len){ close(fd); return 0; } /* chain not there yet; neutral */
    unsigned char gd[37]; memset(gd,0,sizeof gd);
    gd[0]=1; gd[1]=2; gd[2]=0; gd[3]=0; gd[4]=0;
    memcpy(gd+5, chain_hash + tip_height*32, 32);
    if(p2p_write(fd,"getdata",7,gd,37) < 24){ close(fd); return -1; }
    long got = 0;
    for(int t=0;t<30 && !got;t++){
        char c[12]; static unsigned char r1[8192]; unsigned n1=0;
        int rr=p2p_read(fd,c,r1,sizeof r1,&n1);
        if(rr<=0) break;
        if(!strncmp(c,"block",5) && n1>80){
            unsigned char want[32]; block_hash(want, r1);
            if(memcmp(want, chain_hash + tip_height*32, 32)==0) got=1;
        }
    }
    close(fd);
    return got; /* 1 = byte-exact tip served, 0 = not served, -1 = error */
}

int main(int argc, char** argv){
    setbuf(stdout,NULL);
    signal(SIGPIPE,SIG_IGN);
    if(argc<7){ fprintf(stderr,"usage: %s <metrics.jsonl> [mine_every_s] [serve_port] "
                    "[probe_every] [initial_blocks] <port_pipe> <ctrl_pipe>\n",argv[0]); return 2; }
    /* The pipe fds go LAST: glibc's dynamic loader consumes the early argv
     * slots during startup, so passing them first made atoi() see garbage. */
    int port_pipe = atoi(argv[argc-2]);
    int ctrl_pipe = atoi(argv[argc-1]);
    if(port_pipe<3 || ctrl_pipe<3){ fprintf(stderr,"[soakpeer] bad pipe fds (port=%d ctrl=%d)\n", port_pipe, ctrl_pipe); return 2; }
    mlog = fopen(argv[1], "w");
    if(!mlog){ fprintf(stderr,"[soakpeer] metrics open fail\n"); return 9; }
    mine_every = argc>2 ? atoi(argv[2]) : 15;
    serve_port = argc>3 ? atoi(argv[3]) : 0;
    probe_every = argc>4 ? atoi(argv[4]) : 10;
    long initial = argc>5 ? atol(argv[5]) : 5;

    for(long i=0;i<initial;i++) mine_block();

    /* publish bound port */
    int ls=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET;
    a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(ls,(struct sockaddr*)&a,sizeof a)<0){ fprintf(stderr,"[soakpeer] bind fail\n"); return 9; }
    socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
    unsigned short port=ntohs(a.sin_port);
    if(mlog) { fprintf(mlog, "{\"ts\":%.3f,\"role\":\"peer\",\"event\":\"listening\",\"port\":%d,\"initial_chain\":%ld}\n", (double)time(0), (int)port, chain_len); fflush(mlog); }
    unsigned char pb[4]; pb[0]=port&0xff; pb[1]=(port>>8)&0xff;
    int wp=-1;
    for(int t=0;t<50;t++){
        wp=write(port_pipe,pb,2);
        if(wp==2) break;
        if(errno==EINTR){ continue; }
        usleep(20000);
    }
    if(wp!=2){ fprintf(stderr,"[soakpeer] FATAL: port publish fail (write rc=%d errno=%d pipe=%d); parent must keep the pipe read-end OPEN while waiting\n", wp, errno, port_pipe); fflush(stderr); return 9; }
    listen(ls,16);
    fprintf(stderr,"[soakpeer] listening on %d, initial chain %ld, mine every %ds, serve_port %d\n",
            (int)port, chain_len, (int)mine_every, (int)serve_port);

    /* poll(2) returns immediately with -1/EINTR when it is interrupted by a
     * signal, so a blocked accept() would never block when SIGINT/SIGTERM are
     * pending. Block them here so the listener genuinely blocks on accept and
     * the poll loop stays deterministic (the harness sends the peer its port
     * and control fds over pipes, never signals). */
    { sigset_t ss; sigemptyset(&ss); sigaddset(&ss, SIGINT); sigaddset(&ss, SIGTERM);
      pthread_sigmask(SIG_BLOCK, &ss, 0); }
    int cfd=accept(ls,0,0);
    if(cfd<0){ fprintf(stderr,"[soakpeer] accept fail\n"); return 9; }
    close(ls);

    /* handshake: the NODE sends us its version first (it is the outbound
     * initiator). Mirror test_outbound_mux mining_peer. */
    char cmd[12]; unsigned char pl[16384]; unsigned plen=0;
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen); cmd[11]=0;   /* node version */
    { unsigned char v[102]; memset(v,0,sizeof v); v[4]=1;
      p2p_write(cfd,"version",7,v,86);
      p2p_write(cfd,"verack",6,"",0); }
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen); cmd[11]=0;   /* node verack */

    int fl=fcntl(ctrl_pipe,F_GETFL); fcntl(ctrl_pipe,F_SETFL, fl|O_NONBLOCK);
    struct timeval tv; tv.tv_sec=0; tv.tv_usec=300000;
    setsockopt(cfd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);

    struct pollfd pfds[2];
    pfds[0].fd=cfd; pfds[0].events=POLLIN;
    pfds[1].fd=ctrl_pipe; pfds[1].events=POLLIN;
    long last_mine = 0; { time_t t=time(0); last_mine=t; }
    long poll_iters=0, probe_next=probe_every;
    long long poll_us=0;
    int exit_code=0;

    for(;;){
        struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
        int pr=poll(pfds,2,300);
        clock_gettime(CLOCK_MONOTONIC,&t1);
        poll_us += (t1.tv_sec-t0.tv_sec)*1000000LL + (t1.tv_nsec-t0.tv_nsec)/1000;
        poll_iters++;
        if(pr<0 && errno!=EINTR) break;
        if(pr<0) continue;  /* EINTR: a signal (e.g. SIGCHLD from the node's
                              fork-per-serve child) interrupted the poll.
                              Re-arm poll IMMEDIATELY instead of dropping into
                              the 300ms-timeout path: a 300ms timeout with a
                              pending signal returns -EINTR AGAIN, which would
                              spin the loop at ~3x poll rate (poll_us/poll_iters
                              would report ~300us "latency" and ctx_delta would
                              balloon) for as long as any signal stays pending. */

        /* control pipe: 'M' = force-mine now, 'Q' = quit */
        if(pfds[1].revents & POLLIN){
            char c; while(read(ctrl_pipe,&c,1)==1){
                if(c=='M'){ if(time(0)-last_mine < mine_every/2) continue; mine_block(); last_mine=time(0);
                             fprintf(stderr,"[soakpeer] mined block %ld (manual)\n", chain_len); }
                else if(c=='Q'){ exit_code=0; goto done; }
            }
        }
        /* periodic mining: advance the tip so the mux must keep pulling */
        if(time(0) - last_mine >= mine_every){
            mine_block(); last_mine=time(0);
            fprintf(stderr,"[soakpeer] mined block %ld (periodic)\n", chain_len);
        }
        /* node leg readable -> serve node_sync */
        if(pfds[0].revents & (POLLIN|POLLHUP|POLLERR)){
            plen=0; int r=p2p_read(cfd,cmd,pl,sizeof pl,&plen);
            if(r<=0){
                /* leg closed: if it's EOF and we got data before, the node
                 * closed -- mux peer gone. */
                fprintf(stderr,"[soakpeer] node leg closed (p2p_read rc=%d) poll_iters=%ld\n", r, poll_iters);
                exit_code=3; goto done;
            }
            cmd[11]=0;
            if(!strncmp(cmd,"getheaders",10)){
                /* Wire-correct locator handling (matches test_outbound_mux):
                 * - zero locator (empty store) -> serve from block 0 (full sync)
                 * - known locator hash -> serve strictly after it
                 * - unknown locator -> serve nothing (we don't have the fork point) */
                int zero=1; for(int z=0;z<32;z++) if(pl[5+z]){zero=0;break;}
                int from;
                if(zero) from=0;
                else {
                    int found=-1;
                    for(int i=0;i<chain_len;i++) if(!memcmp(pl+5,chain_hash+i*32,32)){found=i;break;}
                    from = (found>=0) ? found+1 : chain_len;
                }
                int cnt=chain_len-from; if(cnt<0) cnt=0; if(cnt>2000) cnt=2000;
                if(cnt>0){
                    unsigned char* hp = malloc(1 + (size_t)cnt*81);
                    hp[0]=(unsigned char)(cnt>255?255:cnt);
                    int p=1;
                    for(int i=from;i<from+cnt;i++){ memcpy(hp+p, chain_blk+i*BLOCK_CAP, 80); hp[p+80]=0; p+=81; }
                    p2p_write(cfd,"headers",7,hp,(unsigned)p);
                    free(hp);
                } else p2p_write(cfd,"headers",7, (unsigned char*)"\x00", 1);
            } else if(!strncmp(cmd,"getdata",7)){
                int found=-1;
                for(int i=0;i<chain_len;i++) if(memcmp(pl+5,chain_hash+i*32,32)==0){found=i;break;}
                if(found>=0) p2p_write(cfd,"block",5,chain_blk+found*BLOCK_CAP,
                                       (unsigned)chain_blklen[found]);
                else p2p_write(cfd,"block",5,"",0);
            } else if(!strncmp(cmd,"ping",4)){
                p2p_write(cfd,"pong",4,pl,(plen>=8)?8:0);
            }
        }
        /* periodic inbound serve probe: the node must serve the tip while
         * also downloading it from us (mux concurrency proof). */
        if(serve_port>0 && poll_iters>=probe_next){
            probe_next = poll_iters + probe_every;
            long tip = chain_len-1;
            int res = probe_serve(tip);
            double now=0; { struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts); now=ts.tv_sec+ts.tv_nsec/1e9; }
            fprintf(mlog, "{\"ts\":%.3f,\"role\":\"probe\",\"probe_tip\":%ld,"
                          "\"probe_result\":%d,\"chain_len\":%ld}\n", (double)now, tip, (int)res, chain_len);
            fflush(mlog);
        }
        if(poll_iters % 20 == 0) metrics_line(poll_iters, poll_us, chain_len);
    }
done:
    close(cfd);
    if(mlog) fclose(mlog);
    fprintf(stderr,"[soakpeer] exit (code %d), chain_len=%ld\n", exit_code, chain_len);
    exit(exit_code);
}
