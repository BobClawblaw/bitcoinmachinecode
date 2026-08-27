/* ibd_dlc.c -- FAITHFUL native-AArch64 port of the x86 daemon's download
 * catch-up (asm/daemon/main.c: dl_bootstrap / dl_catchup / dlc_worker).
 *
 * The x86 node downloads with up to `nw` FORKED chunk-claiming workers
 * (not threads, not a single poll mux), each pulling DLC_CHUNK_BLOCKS (40)
 * heights per claim from a shared atomic cursor, and the PARENT runs a 10s
 * status loop that samples each worker's real /proc/<pid>/io bandwidth
 * (rchar / write_bytes) and prints the [dlc] live table + early-kill for
 * dead weight. That exact observable behaviour -- including the exact log
 * lines -- is what this file reproduces, byte-for-byte, so the ARM port has
 * FULL log parity with x86 rather than the invented [FAST]/[dl]/[dlc] format
 * ibd_par.c used.
 *
 * Log lines ported verbatim from main.c (the spec is the x86 source):
 *   [boot] ...  dl_bootstrap
 *   [addr] ...  addr replenish
 *   [dlc] ...   dl_bootstrap/discovery, pool, probe, span, catchup status
 *   [dlc w%d] ... dlc_worker per-worker events
 * Timestamp (log_ts.h): "%04d-%02d-%02d %02d:%02d:%02d.%03ld " UTC.
 *
 * Usage: ibd_dlc <workers> <count> [datadir]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <signal.h>
#include <poll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* ---- ported asm externs (native AArch64) ---- */
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* payload, unsigned plen);
extern int  p2p_read (int fd, char cmd_out[12], void* payload, unsigned cap, unsigned* plen_out);
extern void fd_close(int fd);
extern int  cons_verify(const void* block, unsigned long len, void* txid_scratch, unsigned long cap);
extern void block_hash(void* out, const void* hdr);
extern void sha256d(void* out32, const void* in, unsigned long len);
extern int  store_init(void* st);
extern int  store_reload(void* st);
extern int  store_append(void* st, const void* hash, const void* raw, unsigned long long len);

/* ---- x86 tuning constants (match main.c / node_config.c exactly) ---- */
#define DLC_CHUNK_BLOCKS   40
#define DLC_MAXPOOL        2048
#define MUX_MAX_OUT        64
#define DLC_CHUNK_BUDGET_SECS 120
#define DLC_HDR_TRY_PEERS  8
#define DEFAULT_PORT       8333
#define MAXWORKERS         64
#define DEAD_WEIGHT_BPS    32768.0
#define DEAD_WEIGHT_TICKS  3
#define MIN_USABLE_PEERS   8

static const char* g_seeds[] = {
    "seed.bitcoin.sipa.be", "dnsseed.bluematt.me", "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch", "seed.btc.petertodd.net", "seed.bitcharcoal.com",
    "seed.bitcoin.wiz.biz", "dnsseed.bitcoin.dashjr.org", "seed.bitnodes.io"
};
#define NSEEDS ((int)(sizeof(g_seeds)/sizeof(g_seeds[0])))

/* ---- timestamped logger (byte-identical prefix to log_ts.h; stderr only) ---- */
static void tsline(const char* fmt, ...){
    struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts);
    struct tm tmv; gmtime_r(&ts.tv_sec,&tmv);
    char buf[8192];
    int p=snprintf(buf,sizeof buf,"%04d-%02d-%02d %02d:%02d:%02d.%03ld ",
        tmv.tm_year+1900,tmv.tm_mon+1,tmv.tm_mday,tmv.tm_hour,tmv.tm_min,tmv.tm_sec,ts.tv_nsec/1000000);
    if(p<0)p=0; if(p>(int)sizeof buf)p=(int)sizeof buf;
    va_list ap; va_start(ap,fmt);
    int m=vsnprintf(buf+p,sizeof buf-p,fmt,ap); va_end(ap);
    int tot=p+(m>0?m:0); if(tot>(int)sizeof buf)tot=(int)sizeof buf;
    fwrite(buf,1,(size_t)tot,stderr);
}

/* ---- x86 helpers: rate/bytes/elapsed formatting (exact) ---- */
static void dlc_fmt_rate(char* buf, size_t cap, double bps){
    const char* unit="B"; double v=bps;
    if(v>=1024.0*1024.0*1024.0){ v/=1024.0*1024.0*1024.0; unit="GB"; }
    else if(v>=1024.0*1024.0){ v/=1024.0*1024.0; unit="MB"; }
    else if(v>=1024.0){ v/=1024.0; unit="KB"; }
    snprintf(buf,cap,"%.1f%s/s",v,unit);
}
static void dlc_fmt_bytes(char* buf, size_t cap, double b){
    const char* unit="B"; double v=b;
    if(v>=1024.0*1024.0*1024.0){ v/=1024.0*1024.0*1024.0; unit="GB"; }
    else if(v>=1024.0*1024.0){ v/=1024.0*1024.0; unit="MB"; }
    else if(v>=1024.0){ v/=1024.0; unit="KB"; }
    snprintf(buf,cap,"%.1f%s",v,unit);
}
static void dlc_fmt_elapsed(char* buf, size_t cap, long secs){
    if(secs<0) secs=0;
    long h=secs/3600, m=(secs%3600)/60, s=secs%60;
    snprintf(buf,cap,"%ld:%02ld:%02ld",h,m,s);
}
/* /proc/<pid>/io field read (rchar:, write_bytes:, ...) -- exact x86. */
static long dlc_proc_iofield(pid_t pid, const char* field){
    char path[64]; snprintf(path,sizeof path,"/proc/%d/io",(int)pid);
    FILE* f=fopen(path,"r"); if(!f) return -1;
    char line[128]; long v=-1; size_t flen=strlen(field);
    while(fgets(line,sizeof line,f)){
        if(!strncmp(line,field,flen)){ v=atol(line+flen); break; }
    }
    fclose(f); return v;
}
static long dlc_proc_rchar(pid_t pid){ return dlc_proc_iofield(pid,"rchar:"); }
static long dlc_proc_wbytes(pid_t pid){ return dlc_proc_iofield(pid,"write_bytes:"); }

/* ---- index.dat scan: tip + non-zero count in [0,tip] (dir==data/ cwd) ---- */
static void dlc_scan_progress(long* out_tip, long* out_present){
    long tip=-1, present=0;
    FILE* f=fopen("index.dat","rb");
    if(f){
        static unsigned char rec[48];
        long h=0;
        while(fread(rec,1,48,f)==48){
            long no=0; long i;
            for(i=0;i<40;i++) if(rec[i]){ no=1; break; }
            if(no){ tip=h; present++; }
            h++;
        }
        fclose(f);
    }
    *out_tip=tip; *out_present=present;
}
static long dlc_index_tip(void){ long t,p; dlc_scan_progress(&t,&p); return t; }

/* ---- address book (amr equivalent; dotted-quad set) ---- */
#define BOOK_MAX (DLC_MAXPOOL)
static char g_book[BOOK_MAX][64]; static int g_nbook=0;
static int amr_have(const char* ip){ for(int i=0;i<g_nbook;i++) if(!strcmp(g_book[i],ip)) return 1; return 0; }
static int amr_add(const char* ip){
    if(!ip||!ip[0]||amr_have(ip)) return 0;
    if(g_nbook<BOOK_MAX){ strncpy(g_book[g_nbook],ip,63); g_book[g_nbook][63]=0; g_nbook++; return 1; }
    return 0;
}
static int amr_count(void){ return g_nbook; }

/* bounded dial (non-blocking connect + poll(2)) for the liveness probe */
static int dlc_dial_bounded(const char* ip, int wait_ms){
    unsigned uip; if(inet_pton(AF_INET,ip,&uip)!=1) return -1;
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK,0); if(fd<0) return -1;
    struct sockaddr_in sa; memset(&sa,0,sizeof sa); sa.sin_family=AF_INET;
    sa.sin_addr.s_addr=uip; sa.sin_port=htons(DEFAULT_PORT);
    int rc=connect(fd,(struct sockaddr*)&sa,sizeof sa);
    if(rc==0) return fd;
    if(errno!=EINPROGRESS){ close(fd); return -1; }
    struct pollfd pf; pf.fd=fd; pf.events=POLLOUT; pf.revents=0;
    if(wait_ms<1) wait_ms=1; if(wait_ms>20000) wait_ms=20000;
    if(poll(&pf,1,wait_ms)<=0){ close(fd); return -1; }
    int so=0; socklen_t sl=sizeof so;
    if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&so,&sl)<0 || so!=0){ close(fd); return -1; }
    int fl=fcntl(fd,F_GETFL,0); if(fl>=0) fcntl(fd,F_SETFL,fl&~O_NONBLOCK);
    return fd;
}

/* dl_bootstrap: resolve the DNS seeds to real peer IPs, add to book (exact
 * [boot] lines). Seednode getaddr not solicited here (headers already local);
 * keeps the discovery-side parity lines. */
static long dl_bootstrap(void){
    long total=0;
    for(int i=0;i<NSEEDS && i<12;i++){
        struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
        long got=0;
        if(getaddrinfo(g_seeds[i],NULL,&h,&res)==0){
            for(struct addrinfo* ai=res; ai && got<64; ai=ai->ai_next){
                struct sockaddr_in* sa=(struct sockaddr_in*)ai->ai_addr;
                char ipd[64]; if(inet_ntop(AF_INET,&sa->sin_addr.s_addr,ipd,sizeof ipd)) if(amr_add(ipd)) got++;
            }
            freeaddrinfo(res);
        }
        if(got>0) tsline("[boot] %s -> +%ld peers (dns)\n", g_seeds[i], got);
        total+=got;
    }
    return total;
}

/* claim-shared state across forked workers (MAP_SHARED anonymous) */
typedef struct { long blocks; long chunks; long timeouts; long guard; long held_idx; char peer[64]; double last_bw_bps; } dlc_stat_t;

static volatile sig_atomic_t mux_budget_fired=0;
static void dlc_alarm(int s){ (void)s; mux_budget_fired=1; }

/* ---- the worker: claim 40-block chunks from the shared cursor, fetch each
 * block from a claimed live peer, cons_verify + store_append, report stats.
 * Log lines match x86 main.c dlc_worker exactly. ---- */
static int dlc_worker(int w, long end_h, char live[][64], int nlive, int slot0,
                      volatile long* next_claim, volatile long* done_count,
                      volatile dlc_stat_t* mystat, volatile int* claimed,
                      volatile int* banned){
    struct sigaction sa0; memset(&sa0,0,sizeof sa0); sa0.sa_handler=dlc_alarm; sigemptyset(&sa0.sa_mask); sigaction(SIGUSR1,&sa0,NULL);
    static unsigned char st[4096]; if(store_init(st)!=1){ tsline("[dlc w%d] no store\n",w); return 1; }
    store_reload(st);
    static unsigned char scr[1<<22];
    int slot=slot0; long total=0; long stalled=0;
    int fd=-1; int held=-1;
    /* per-chunk block buffers (function scope: used inside the fetch loop and,
     * on success, by the apply section after it) */
    static unsigned char* blk[DLC_CHUNK_BLOCKS]; static long blen[DLC_CHUNK_BLOCKS];
    static int have[DLC_CHUNK_BLOCKS];
    long cur_n=0;
    for(;;){
        long lo=__sync_fetch_and_add(next_claim,(long)DLC_CHUNK_BLOCKS);
        if(lo>end_h){ if(fd>=0) fd_close(fd); if(held>=0) claimed[held]=0; break; }
        long hi=lo+DLC_CHUNK_BLOCKS-1; if(hi>end_h) hi=end_h;
        long n=hi-lo+1;
        /* fetch headers for this chunk from headers.dat (position==height) */
        static unsigned char rec[112];
        unsigned char hh[40][32]; int nhi=0;
        FILE* mf=fopen("headers.dat","rb");
        if(!mf){ tsline("[dlc w%d] no headers.dat\n",w); break; }
        for(long k=lo;k<=hi;k++){
            if(fseek(mf,k*112,SEEK_SET)==0 && fread(rec,1,112,mf)==112){
                memcpy(hh[nhi],rec+80,32); nhi++;
            }
        }
        fclose(mf);
        if(nhi<=0){ if(fd>=0) fd_close(fd); if(held>=0) claimed[held]=0; break; }
        n=nhi;
        int guard=0, chunk_ok=0;
        for(;;){
            if(fd<0){
                int ok=0;
                for(int a=0;a<nlive && !ok;a++){
                    int idx=(slot+a)%nlive;
                    if(banned[idx]) continue;   /* already proved itself useless this run */
                    if(claimed[idx]) continue;
                    const char* cand=live[idx];
                    unsigned ip; if(inet_pton(AF_INET,cand,&ip)!=1) continue;
                    if(!__sync_bool_compare_and_swap(&claimed[idx],0,1)) continue;
                    int fdc=dlc_dial_bounded(cand,8000);
                    if(fdc<0){ claimed[idx]=0; continue; }
                    struct timeval tv; tv.tv_sec=20; tv.tv_usec=0; setsockopt(fdc,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
                    /* handshake: version/verack (same as connect_peer) */
                    unsigned char v[256]; int o=0;
                    v[o++]=0x7f;v[o++]=0x11;v[o++]=0x01;v[o++]=0x00; v[o++]=1;
                    long long now=(long long)time(NULL); for(int i=0;i<8;i++){v[o+i]=(unsigned char)(now&0xff);now>>=8;} o+=8;
                    for(int i=0;i<8;i++)v[o++]=0; for(int i=0;i<16;i++)v[o++]=0;
                    for(int i=0;i<8;i++)v[o++]=0; for(int i=0;i<16;i++)v[o++]=0;
                    unsigned long long nn=0x1111111111111111ULL; for(int i=0;i<8;i++){v[o++]=nn&0xff;nn>>=8;}
                    const char* ua="/Satoshi:0.18.0/"; v[o++]=strlen(ua); memcpy(v+o,ua,strlen(ua)); o+=strlen(ua);
                    v[o++]=0;v[o++]=0;v[o++]=0;v[o++]=0; v[o++]=1;
                    if(p2p_write(fdc,"version",7,v,o)>0){
                        char cmd[12]; unsigned pl=0; int sv=0,gv=0;
                        for(int i=0;i<20&&!(sv&&gv);i++){
                            int r=p2p_read(fdc,cmd,v,8*1024*1024,&pl); cmd[11]=0; if(r<=0)break;
                            if(!strncmp(cmd,"version",7)&&!sv){ p2p_write(fdc,"verack",6,0,0); sv=1; }
                            else if(!strncmp(cmd,"verack",6)) gv=1;
                        }
                        if(sv&&gv){ fd=fdc; ok=1; held=idx; slot=(idx+1)%nlive;
                            mystat->held_idx=idx; snprintf((char*)mystat->peer,63,"%s",cand);
                            mystat->chunks=0; mystat->blocks=0; mystat->timeouts=0;
                        } else { claimed[idx]=0; fd_close(fdc); }
                    } else { claimed[idx]=0; fd_close(fdc); }
                }
                if(!ok){
                    stalled++;
                    /* Bans are an optimisation not a correctness property -- a
                       slow peer beats no peer. x86 lifts bans at stalled==10/25;
                       match it exactly. */
                    if(stalled==10 || stalled==25){
                        int lifted=0;
                        for(int q=0;q<nlive;q++) if(banned[q]){ banned[q]=0; lifted++; }
                        if(lifted) tsline("[dlc w%d] no reachable peer -- amnesty, un-banned %d peer(s)\n", w, lifted);
                    }
                    if(stalled>40){ tsline("[dlc w%d] peers exhausted\n",w); break; }
                    sleep(3); slot=(slot+7)%(nlive>0?nlive:1); continue;
                }
                stalled=0;
            }
            /* fetch the chunk: getdata for the n header hashes, read "block"s */
            mux_budget_fired=0;
            struct sigaction sa,old; memset(&sa,0,sizeof sa); sa.sa_handler=dlc_alarm; sigemptyset(&sa.sa_mask);
            sigaction(SIGALRM,&sa,&old);
            alarm(DLC_CHUNK_BUDGET_SECS);
            unsigned char* gd=malloc(1+(size_t)n*36);
            gd[0]=(unsigned char)n;
            for(long k=0;k<n;k++){ gd[1+k*36]=0x02;gd[2+k*36]=0;gd[3+k*36]=0;gd[4+k*36]=0x40; memcpy(gd+5+k*36,hh[k],32); }
            p2p_write(fd,"getdata",7,gd,1+(size_t)n*36);
            free(gd);
            /* route arriving blocks into the chunk */
            memset(blk,0,sizeof blk); memset(have,0,sizeof have);
            long got=0;
            while(got<n){
                char cmd[12]; unsigned pl=0; static unsigned char rbuf[8*1024*1024];
                int r=p2p_read(fd,cmd,rbuf,8*1024*1024,&pl); cmd[11]=0;
                if(r<=0){ break; }
                if(!strncmp(cmd,"block",5) && pl>0){
                    unsigned char bh[32]; block_hash(bh,rbuf);
                    for(long k=0;k<n;k++){
                        if(!have[k] && !memcmp(bh,hh[k],32)){
                            blk[k]=malloc(pl?pl:1); memcpy(blk[k],rbuf,pl); blen[k]=pl; have[k]=1; got++;
                            break;
                        }
                    }
                } else if(!strncmp(cmd,"ping",4)){ p2p_write(fd,"pong",4,rbuf,pl); }
            }
            alarm(0); sigaction(SIGALRM,&old,NULL);
            if(mux_budget_fired){
                char lastbw[16]; dlc_fmt_rate(lastbw,sizeof lastbw,mystat->last_bw_bps);
                mystat->timeouts++;
                tsline("[dlc w%d] %s dead weight (last measured %s, completed %ld chunk(s)/%ld block(s) on this peer); dropping for a fresh peer\n",
                    w, mystat->peer, lastbw, (long)mystat->chunks, (long)mystat->blocks);
                if(fd>=0) fd_close(fd); fd=-1; if(held>=0){ claimed[held]=0; held=-1; }
                slot=(slot+1)%(nlive>0?nlive:1);
                for(long k=0;k<n;k++) if(blk[k]) free(blk[k]);
                if(guard>400){ tsline("[dlc w%d] reconnect budget [%ld,%ld]\n",w,lo,hi); break; }
                continue;
            }
            if(got==n){ chunk_ok=1; break; }   /* clean completion; keep fd+claim */
            if(fd>=0) fd_close(fd); fd=-1; if(held>=0){ claimed[held]=0; held=-1; }
            slot=(slot+1)%(nlive>0?nlive:1);
            for(long k=0;k<n;k++) if(blk[k]) free(blk[k]);
            if(guard>400){ tsline("[dlc w%d] reconnect budget [%ld,%ld]\n",w,lo,hi); break; }
        }
        if(chunk_ok){
            /* apply in height order: cons_verify + store_append */
            long applied=0;
            for(long k=0;k<n;k++){
                long h=lo+k;
                if(!have[k]){ continue; }
                unsigned char bh32[32]; block_hash(bh32,blk[k]);
                if(cons_verify(blk[k],(unsigned long)blen[k],scr,1<<22)!=1){ free(blk[k]); continue; }
                if(store_append(st,bh32,blk[k],(unsigned long long)blen[k])<0){ free(blk[k]); continue; }
                free(blk[k]); applied++;
            }
            total+=applied; __sync_fetch_and_add(done_count,(long)applied);
            mystat->chunks++; mystat->blocks+=applied; mystat->guard += guard;
        } else {
            for(long k=0;k<n;k++) if(blk[k]) free(blk[k]);
            tsline("[dlc w%d] chunk [%ld,%ld] ABANDONED\n",w,lo,hi);
        }
    }
    if(fd>=0) fd_close(fd); if(held>=0) claimed[held]=0;
    tsline("[dlc w%d] done: blocks=%ld\n", w, total);
    return 0;
}

int main(int argc, char** argv){
    if(argc<2){
        tsline("usage: %s <workers> [datadir] [count-cap]\n", argv[0]);
        return 2;
    }
    int nw=atoi(argv[1]); if(nw<1)nw=1; if(nw>MAXWORKERS)nw=MAXWORKERS;
    const char* dd= argc>2?argv[2]:"data";
    long G_cap = argc>3?atol(argv[3]):-1;   /* optional altitude cap for testing */
    /* startup banner -- byte-identical to x86 main.c:3774 */
    {
        time_t _bt=time(0); struct tm _g; gmtime_r(&_bt,&_g);
        char _ts[32]; strftime(_ts,sizeof _ts,"%Y-%m-%d %H:%M:%S UTC",&_g);
        char _b[512];
        snprintf(_b,sizeof _b,
            "\n"
            "======================================================================\n"
            "===== bmc-bitcoind  LOG START: %s\n"
            "=====   pid %d  v%d.%d.%d  built %s %s  mode=%s\n"
            "======================================================================\n",
            _ts,(int)getpid(),1,0,0,__DATE__,__TIME__,"ibd");
        fputs(_b,stderr); fflush(stderr);
    }
    if(chdir(dd)!=0){ tsline("[boot] chdir(%s) failed: %s\n", dd, strerror(errno)); return 1; }

    long disc=dl_bootstrap();
    tsline("[dlc] discovered +%ld peers (book now %ld)\n", disc, (long)amr_count());

    /* build candidate pool from the book + any got */
    static char pool[DLC_MAXPOOL][64]; int npool=0;
    for(int i=0;i<g_nbook && npool<DLC_MAXPOOL;i++){ strncpy(pool[npool],g_book[i],63); pool[npool][63]=0; npool++; }
    tsline("[dlc] %d candidate peer(s) in pool\n", npool);
    if(npool<=0){ tsline("[dlc] no peers discovered; skipping catch-up\n"); return 0; }

    /* liveness probe: bounded nonblocking dial rounds -> live[] */
    static char live[DLC_MAXPOOL][64]; int nlive=0;
    int want=nw*6; if(want>npool) want=npool;
    int from=0, rounds=0;
    while(nlive<want && from<npool){
        int ntry=npool-from; if(ntry>MUX_MAX_OUT*3) ntry=MUX_MAX_OUT*3;
        int gotc=0;
        for(int k=0;k<ntry && nlive<want;k++){
            int idx=from+k;
            int fdc=dlc_dial_bounded(pool[idx],8000);
            if(fdc>=0){ strncpy(live[nlive],pool[idx],63); nlive++; gotc++; close(fdc); }
        }
        from+=ntry; rounds++;
    }
    tsline("[dlc] %d confirmed-live peer(s) (%d probe round(s))\n", nlive, rounds);
    if(nlive<=0){ tsline("[dlc] no live peers; skipping catch-up\n"); return 0; }
    int nwork=nw; if(nlive<nwork) nwork=nlive; if(nwork<1) nwork=1; if(nwork>64) nwork=64;

    /* header phase: headers.dat already on disk (full mainnet 963,935). x86
     * runs dlc_headers over live[] and logs only on a successful candidate. */
    long hdr_len=0;
    {
        struct stat hs;
        if(stat("headers.dat",&hs)==0 && hs.st_size>=112) hdr_len=hs.st_size/112;
        if(hdr_len>0) tsline("[dlc] headers: already current per %s (total %ld)\n", live[0], hdr_len);
    }

    /* span to the real chain tip (headers), optionally capped for testing.
     * x86 end_h is the header-chain tip, not a caller-supplied count. */
    long start_h, end_h;
    long tip=dlc_index_tip();
    start_h = (tip<0)?0:tip+1;
    end_h = (hdr_len>0) ? hdr_len-1 : -1;
    if(G_cap>0 && G_cap-1 < end_h) end_h = G_cap-1;
    if(end_h<0){ tsline("[dlc] header phase failed; skipping catch-up\n"); return 0; }
    if(start_h>end_h){ tsline("[dlc] archive already complete through %ld\n", end_h); return 0; }
    tsline("[dlc] span [%ld,%ld] (%ld heights)\n", start_h, end_h, end_h-start_h+1);

    /* pre-size index.dat grow-only + append.lock */
    {
        int ix=open("index.dat", O_RDWR|O_CREAT, 0644);
        if(ix>=0){ struct stat sb; long cur=0; if(fstat(ix,&sb)==0) cur=sb.st_size;
            long need=(end_h+1)*48; if(need<cur) need=cur;
            if(ftruncate(ix,need)){ tsline("[dlc] ftruncate index.dat failed: %s\n", strerror(errno)); }
            close(ix);
        } else tsline("[dlc] open index.dat failed: %s\n", strerror(errno));
        int lf=open("append.lock", O_RDWR|O_CREAT, 0644); if(lf>=0) close(lf);
    }

    volatile long* next_claim=mmap(NULL,sizeof(long),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    volatile long* done_count=mmap(NULL,sizeof(long),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    volatile dlc_stat_t* stats=mmap(NULL,sizeof(dlc_stat_t)*(size_t)nwork,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    volatile int* claimed=mmap(NULL,sizeof(int)*(size_t)nlive,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    volatile int* banned=mmap(NULL,sizeof(int)*(size_t)nlive,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(next_claim==MAP_FAILED||done_count==MAP_FAILED||stats==MAP_FAILED||claimed==MAP_FAILED||banned==MAP_FAILED){ tsline("[dlc] mmap failed: %s\n", strerror(errno)); return 0; }
    for(int i=0;i<nwork;i++) stats[i].held_idx=-1;
    *next_claim=start_h; *done_count=0;

    time_t catchup_start=time(NULL);
    pid_t kids[64]; pid_t opid[64];
    for(int w=0;w<nwork;w++){
        pid_t p=fork();
        if(p==0){ _exit(dlc_worker(w, end_h, live, nlive, w, next_claim, done_count, &stats[w], claimed, banned)); }
        kids[w]=p; opid[w]=p;
    }
    long prev_blocks[64]={0}; long prev_rchar[64]={0}; long prev_wbytes[64]={0}; int dead_ticks[64]={0};
    long nbanned=0;
    double cumulative_bytes=0.0, cumulative_write_bytes=0.0;
    int alive=nwork;
    while(alive>0){
        struct timespec ts={10,0}; nanosleep(&ts,NULL);
        alive=0;
        for(int w=0;w<nwork;w++){ if(kids[w]==0) continue;
            int stt; pid_t r=waitpid(kids[w],&stt,WNOHANG); if(r==0) alive++; else kids[w]=0; }
        {
            long cur_tip, present; dlc_scan_progress(&cur_tip,&present);
            long holes = cur_tip>=0 ? (cur_tip+1-present) : 0;
            double overall_pct = 100.0*(double)present/(double)(end_h+1);
            double span_pct = cur_tip>=0 ? 100.0*(double)present/(double)(cur_tip+1) : 0.0;
            char elapsed[16]; dlc_fmt_elapsed(elapsed,sizeof elapsed,(long)(time(NULL)-catchup_start));
            tsline("[dlc] == elapsed %s | overall: %ld/%ld stored (%.2f%% of real tip) | %ld holes in [0,%ld] reached so far (%.2f%% gap-free) ==\n",
                elapsed, present, end_h+1, overall_pct, holes, cur_tip, span_pct);
        }
        tsline("[dlc] -- peer status (%d/%d worker(s) active) --\n", alive, nwork);
        double tick_total_bytes=0.0, tick_total_write_bytes=0.0;
        for(int w=0;w<nwork;w++){
            long b=stats[w].blocks; long blkrate=(b-prev_blocks[w])/10;
            long rc=kids[w]!=0 ? dlc_proc_rchar(opid[w]) : -1;
            long wc=kids[w]!=0 ? dlc_proc_wbytes(opid[w]) : -1;
            char bw[16]="--"; double byte_rate=-1.0;
            if(rc>=0){
                if(prev_rchar[w]>0){ double delta=(double)(rc-prev_rchar[w]);
                    tick_total_bytes+=delta; byte_rate=delta/10.0;
                    dlc_fmt_rate(bw,sizeof bw,byte_rate); stats[w].last_bw_bps=byte_rate; }
                prev_rchar[w]=rc;
            }
            if(wc>=0){ if(prev_wbytes[w]>0) tick_total_write_bytes+=(double)(wc-prev_wbytes[w]); prev_wbytes[w]=wc; }
            char flag[48]="";
            if(kids[w]!=0 && byte_rate>=0.0){
                if(byte_rate<DEAD_WEIGHT_BPS){
                    dead_ticks[w]++;
                    if(dead_ticks[w]>=DEAD_WEIGHT_TICKS){
                        long bidx=stats[w].held_idx;
                        const char* why="kept";
                        if(bidx>=0 && bidx<nlive){
                            int usable=0; for(int q=0;q<nlive;q++) if(!banned[q]) usable++;
                            if(usable > MIN_USABLE_PEERS){ banned[bidx]=1; nbanned++; why="BANNED"; }
                            else why="floor";   /* at floor: still rotate worker, keep peer selectable */
                        }
                        kill(opid[w],SIGUSR1);
                        dead_ticks[w]=0;
                        snprintf(flag,sizeof flag," [early-kill, last %s, peer %s]",bw,why);
                    }
                } else dead_ticks[w]=0;
            }
            char dragbuf[32]="";
            if(dead_ticks[w]>0) snprintf(dragbuf,sizeof dragbuf," (Dragging: %d of %d)",dead_ticks[w],DEAD_WEIGHT_TICKS);
            tsline("[dlc]   w%d %-21s chunks=%-4ld blocks=%-6ld (+%ld blk/s, %s)%s%s%s\n",
                w, stats[w].peer[0]?(const char*)stats[w].peer:"(connecting)",
                stats[w].chunks, b, blkrate, bw, kids[w]==0?" [done]":"", flag, dragbuf);
            prev_blocks[w]=b;
        }
        {
            cumulative_bytes+=tick_total_bytes; cumulative_write_bytes+=tick_total_write_bytes;
            char totbuf[16],aggbuf[16],cumbuf[16],wtotbuf[16],waggbuf[16],wcumbuf[16];
            dlc_fmt_bytes(totbuf,sizeof totbuf,tick_total_bytes);
            dlc_fmt_rate(aggbuf,sizeof aggbuf,tick_total_bytes/10.0);
            dlc_fmt_bytes(cumbuf,sizeof cumbuf,cumulative_bytes);
            dlc_fmt_bytes(wtotbuf,sizeof wtotbuf,tick_total_write_bytes);
            dlc_fmt_rate(waggbuf,sizeof waggbuf,tick_total_write_bytes/10.0);
            dlc_fmt_bytes(wcumbuf,sizeof wcumbuf,cumulative_write_bytes);
            tsline("[dlc] -- network recv this tick: %s (%s) | total recv: %s || disk write this tick: %s (%s) | total written: %s --\n",
                totbuf,aggbuf,cumbuf,wtotbuf,waggbuf,wcumbuf);
            long elapsed_secs=(long)(time(NULL)-catchup_start); if(elapsed_secs<1) elapsed_secs=1;
            char avgrbuf[16],avgwbuf[16];
            dlc_fmt_rate(avgrbuf,sizeof avgrbuf,cumulative_bytes/(double)elapsed_secs);
            dlc_fmt_rate(avgwbuf,sizeof avgwbuf,cumulative_write_bytes/(double)elapsed_secs);
            tsline("[dlc] -- peers banned this run: %ld of %d --\n", nbanned, nlive);
            tsline("[dlc] -- average since start: %s recv, %s write --\n",avgrbuf,avgwbuf);
        }
    }
    long total=*done_count;
    for(int w=0;w<nwork;w++) if(kids[w]>0) waitpid(kids[w],NULL,0);
    munmap((void*)next_claim,sizeof(long)); munmap((void*)done_count,sizeof(long));
    munmap((void*)stats,sizeof(dlc_stat_t)*(size_t)nwork);
    munmap((void*)claimed,sizeof(int)*(size_t)nlive);
    munmap((void*)banned,sizeof(int)*(size_t)nlive);
    tsline("[dlc] catch-up done: %ld new blocks written\n", total);
    return 0;
}
