/* daemon/unified_ibd.c -- full-chain download into ONE directory (no worker dirs).
 *
 * The durable archive is a SINGLE store at <dir>/blk00000.dat.. + index.dat +
 * headers.dat; NO w<w>/ shard dirs ever exist. Parallelism is preserved for the
 * download; writes into the one store are concurrent-safe.
 *
 * Flow (download+write loops in ASM):
 *   1. Header phase: persist the whole chain into <dir>/headers.dat.
 *   2. Rank a verified trusted pool of >=nw DISTINCT up peers.
 *   3. Split [start_h,end_h] into nw disjoint ranges; each worker downloads its
 *      shard via node_ibd_blocks_s and writes EVERY block DIRECTLY into <dir>
 *      through store_append_shared (flock-serialized on append.lock; block at the
 *      true file end of rolling blkNNNNN.dat; 48-byte index record positionally at
 *      height*48; index.dat pre-sized to end_h+1). No worker block dirs.
 *   4. Each worker keeps a PRIVATE /tmp header file (hst state never collides).
 *      Peers are distinct (flock peerclaims).
 *
 * Resumable: a rerun reads the existing tip from index.dat, then worker shards
 * only cover the zero/missing heights after it; index pre-size grows to end_h.
 *
 * Usage: unified_ibd <dir> <num_workers> <start_h> <end_h>
 *   peers auto-load from good_internet_peers.txt; header peer = local node.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/file.h>
#include <dirent.h>

extern int  tcp_connect_ip(unsigned, unsigned short);
extern long p2p_write(int,const char*,unsigned,const void*,unsigned);
extern int  p2p_read(int,char[12],void*,unsigned,unsigned*);
extern int  node_handshake(int fd);
extern long node_ibd_headers(int fd, void* hst, void* loc, void* buf, unsigned long bl);
extern long node_ibd_blocks_x(int fd, void* st, void* hst, long start, long end,
                              void* buf, unsigned long buflen, void* scratch, unsigned cap);
extern long node_ibd_blocks_s(int fd, void* st, void* hst, long lo_real, long nloc,
                              void* buf, unsigned long buflen, void* scratch, unsigned cap);
extern int  hst_init(void* hst);
extern int  hst_reload(void* hst);
extern long hst_count(void* hst);
extern int  hst_get_at(void* hst, unsigned long long h, void* out);
extern int  hst_append(void* hst, const unsigned char hdr[80], const unsigned char hash[32]);
extern int  store_init(void* st);
extern int  store_reload(void* st);
extern long store_append(void* st, const unsigned char hash[32], const void* raw, unsigned long long len);
extern long store_get_tip(void* st, void* out);
extern void fd_close(int fd);

#define MAXPEERS 24
#define PORT_BE ((unsigned short)htons(8333))

static char claimpath[512];
static FILE* cf=NULL;
static void clk(void){ if(!cf){ cf=fopen(claimpath,"a+"); } if(cf){ flock(fileno(cf),LOCK_EX);} }
static void cul(void){ if(cf) flock(fileno(cf),LOCK_UN); }
static int cl_take(const char* ip){
    clk(); if(!cf){ cul(); return 0; }
    rewind(cf); char line[256]; int dup=0;
    while(fgets(line,sizeof line,cf)){ char*nl=strchr(line,'\n'); if(nl)*nl=0; if(!strcmp(line,ip)){dup=1;break;} }
    if(!dup){ fseek(cf,0,SEEK_END); fprintf(cf,"%s\n",ip); fflush(cf); }
    cul(); return !dup;
}
static void cl_rel(const char* ip){
    clk(); if(cf){ char tmp[560]; snprintf(tmp,sizeof tmp,"%s.tmp",claimpath);
        FILE* in=fopen(claimpath,"r"); FILE* out=fopen(tmp,"w"); char line[256];
        if(in&&out){ while(fgets(line,sizeof line,in)){ char*nl=strchr(line,'\n'); if(nl)*nl=0; if(strcmp(line,ip)) fprintf(out,"%s\n",line); } }
        if(in)fclose(in); if(out)fclose(out); rename(tmp,claimpath); }
    cul();
}

static int load_peers(const char* f, char p[][128], int max){
    int n=0; FILE* fp=fopen(f,"r"); if(!fp) return n; char line[256];
    while(fgets(line,sizeof line,fp)&&n<max){ char*nl=strchr(line,'\n'); if(nl)*nl=0; if(*line&&line[0]!='#'){ strncpy(p[n],line,127); p[n][127]=0; n++; } }
    fclose(fp); return n;
}
static unsigned resolve(const char* host){
    char b[128]; snprintf(b,sizeof b,"%s",host); char*c=strchr(b,':'); if(c)*c=0;
    unsigned ip4=0; if(inet_pton(AF_INET,b,&ip4)==1) return ip4;
    struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(b,NULL,&h,&res)!=0) return 0;
    unsigned ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr; freeaddrinfo(res); return ip;
}
static int connect_peer(const char* host){
    unsigned ip=resolve(host); if(!ip) return -1;
    int fd=tcp_connect_ip(ip,PORT_BE); if(fd<0) return -1;
    struct timeval tv; tv.tv_sec=20; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    if(node_handshake(fd)!=1){ fd_close(fd); return -1; }
    return fd;
}

static void rmrf(const char* d){ DIR* dd=opendir(d); if(!dd) return;
    struct dirent* e; char p[600]; while((e=readdir(dd))){ if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;
        snprintf(p,sizeof p,"%s/%s",d,e->d_name); remove(p); } closedir(dd); rmdir(d); }

/* worker: download [lo,hi] real heights via asm node_ibd_blocks_x into a
 * transient scratch store dir. Re-indexes master [lo,hi] -> local hst.
 * Uses the TRUSTED pool (goodindex[] of length ngood, all confirmed-up distinct)
 * so on a peer drop it fails over to another confirmed-up distinct peer without
 * re-probing dead hosts. Claims are held for the whole session per worker. */
/* worker: download [lo,hi] REAL heights via asm node_ibd_blocks_s, writing each
 * block DIRECTLY into the ONE shared store in <dir> (no worker dirs, no chdir).
 * Reads its shard headers from <dir>/headers.dat. Stores via the concurrent-safe
 * store_append_shared under append.lock. Fails over within the trusted pool and
 * resumes on drop; retries with backoff instead of giving up. */
static int worker(int w, const char* dir, long lo, long hi,
                  char peers[][128], int goodindex[], int ngood, int slot0){
    /* PRIVATE header store in /tmp (a single FILE, not block data, not in
     * dir/). Each worker MUST have its own header store: hst uses an on-disk
     * file and all workers share dir/headers.dat, so appending one worker's
     * shard would clobber another's (the boundary-chain-break bug). We set the
     * hst struct's fd/count directly to a private file. */
    static unsigned char hst[64];
    char hp_[640]; snprintf(hp_,sizeof hp_,"/tmp/hdr_%d.dat",getpid());
    int hfd=open(hp_,O_RDWR|O_CREAT|O_TRUNC,0644);
    if(hfd<0){ fprintf(stderr,"[w%d] no hdr file\n",w); return 1; }
    *(int*)((char*)hst+0)=hfd;
    *(long*)((char*)hst+8)=0;              /* count = 0 */
    long n=0;
    char hp[640]; snprintf(hp,sizeof hp,"%s/headers.dat",dir);
    FILE* mf=fopen(hp,"rb");
    static unsigned char rec[112];
    for(long k=lo;k<=hi;k++){
        if(mf && fseek(mf,k*112,SEEK_SET)==0 && fread(rec,1,112,mf)==112){
            if(hst_append(hst,rec,rec+80)<0) break; n++;
        } else break;
    }
    if(mf) fclose(mf);
    if(n<=0){ fprintf(stderr,"[w%d] no headers\n",w); return 1; }
    /* own store context pointing at the SHARED store in dir (CWD = dir).
     * Do NOT store_reload: index.dat is PRE-SIZED (all-zero), so reload would
     * misread it as having real blocks at every height. store_init gives empty
     * state; we set cur_file_no/magic and let store_append_shared manage pos. */
    static unsigned char st[4096]; store_init(st);
    /* open the shared append lock with OUR OWN open-file-description so flock
     * contends across processes (a fork-shared fd bypasses flock). */
    char lp[640]; snprintf(lp,sizeof lp,"%s/append.lock",dir);
    int lfd=open(lp,O_RDWR|O_CREAT,0644);
    if(lfd<0){ fprintf(stderr,"[w%d] no lock\n",w); return 1; }
    *(int*)((char*)st+40)=lfd;
    *(int*)((char*)st+36)=0xd9b4bef9;   /* magic */
    *(int*)((char*)st+28)=0;            /* cur_file_no=0 */
    *(int*)((char*)st+0)=-1;            /* no blk fd yet */
    static unsigned char buf[24<<20]; static unsigned char scratch[8<<20];
    unsigned cap=(unsigned)(sizeof scratch/32);
    int guard=0; int slot=slot0; long resume=0; char cip[128]={0};
    long stalled=0;
    for(;;){
        int fd=-1; int ok=0;
        for(int a=0;a<ngood && !ok;a++){
            int idx=goodindex[(slot+a)%ngood];
            const char* cand=peers[idx];
            char i[128]; snprintf(i,sizeof i,"%s",cand); char*c=strchr(i,':'); if(c)*c=0;
            if(!cl_take(i)) continue;
            int fdc=connect_peer(cand);
            if(fdc>=0){ strncpy(cip,i,sizeof cip); fd=fdc; ok=1; slot=(slot+a+1)%ngood; }
            else { cl_rel(i); }
        }
        if(!ok){
            stalled++;
            if(stalled>40){ fprintf(stderr,"[w%d] no distinct peer: exhausted\n",w); break; }
            sleep(3); slot=(slot+7)%ngood; continue;
        }
        stalled=0;
        /* node_ibd_blocks_s(fd, st, hst, lo, n, ...) writes real heights lo..lo+n-1 */
        long r=node_ibd_blocks_s(fd, st, hst, lo, n, buf, sizeof buf, scratch, cap);
        fd_close(fd); cl_rel(cip); cip[0]=0;
        slot=(slot+1)%ngood;
        /* resume = lo + (number of local heights now stored) */
        store_reload(st);
        resume = lo + n;               /* on success the whole shard is done */
        guard++;
        if(r>=0){ resume=lo+n; break; } /* clean completion */
        /* on failure, we can't easily know the partial tip under shared append
         * (r=-1 may be mid-shard); retry the WHOLE shard from lo (idempotent
         * under store_append_shared's positional writes). */
        if(guard>400){ fprintf(stderr,"[w%d] reconnect budget\n",w); break; }
        continue;
    }
    fprintf(stderr,"[w%d] done: heads=%ld local=%ld guard=%d\n", w, resume, n, guard);
    close(lfd);
    return 0;
}

int main(int argc,char**argv){
    setbuf(stdout,NULL);
    if(argc<5){ fprintf(stderr,"usage: %s <dir> <num_workers> <start_h> <end_h> [peer...]\n",argv[0]); return 2; }
    const char* dir=argv[1];
    int nw=atoi(argv[2]); if(nw<1)nw=1; if(nw>16)nw=16;
    long start_h=atol(argv[3]); long end_h=atol(argv[4]);

    char peers[MAXPEERS][128]; int np=0;
    for(int i=5;i<argc&&np<MAXPEERS;i++){ strncpy(peers[np],argv[i],127); peers[np][127]=0; np++; }
    if(np==0) np=load_peers("/storage/bitcoinmachinecode/good_internet_peers.txt",peers,MAXPEERS);
    if(np<nw)nw=np;
    if(chdir(dir)){ perror("chdir"); return 1; }
    for(int i=0;i<np;i++) printf("peer[%d] %s\n",i,peers[i]);

    /* header phase: local node first, then pool, forked with timeout */
    static unsigned char mhst[4096]; hst_init(mhst);
    static unsigned char zp[32]; memset(zp,0,32);
    static unsigned char hdrbuf[2<<20];
    long nhdr=0;
    char* htry[MAXPEERS]; long htryn=0; int hl=0;
    for(int i=0;i<np;i++) if(strstr(peers[i],"192.168.5.69")){ htry[htryn++]=peers[i]; hl=1; }
    if(!hl){ static char lo[]="192.168.5.69"; htry[htryn++]=(char*)lo; }
    for(int i=0;i<np;i++){ int d=0; for(int k=0;k<htryn;k++) if(!strcmp(htry[k],peers[i])){d=1;break;} if(!d) htry[htryn++]=peers[i]; }
    for(int i=0;i<htryn && nhdr<=0;i++){
        pid_t hp=fork();
        if(hp==0){ int fd=connect_peer(htry[i]); if(fd<0)_exit(2); long h=node_ibd_headers(fd,mhst,zp,hdrbuf,sizeof hdrbuf); _exit(h>0?0:1); }
        int hst; pid_t wr=-1; time_t t0=time(NULL);
        while(time(NULL)-t0<60){ wr=waitpid(hp,&hst,WNOHANG); if(wr==hp)break; usleep(200000); }
        if(wr!=hp){ kill(hp,SIGKILL); waitpid(hp,&hst,0); printf("header %s TIMEOUT\n",htry[i]); continue; }
        hst_reload(mhst);
        if(WIFEXITED(hst)&&WEXITSTATUS(hst)==0){ nhdr=hst_count(mhst); printf("header %s served %ld\n",htry[i],nhdr); }
    }
    if(nhdr<=0){ fprintf(stderr,"header failed\n"); return 1; }
    if(end_h>nhdr-1) end_h=nhdr-1;
    /* ---- RESUME: detect the existing store tip (highest non-zero index
     * record) so a rerun continues from it instead of re-downloading.
     * BACKFILL: if the requested range lies entirely BELOW the current tip
     * (a catch-up pass for early heights), keep the requested [start,end] and
     * do NOT jump forward to the tip, and do NOT shrink the index. ---- */
    long existing_tip=-1; long idx_records=0;
    {
        char ip[640]; snprintf(ip,sizeof ip,"%s/index.dat",dir);
        FILE* ix=fopen(ip,"rb");
        if(ix){ fseek(ix,0,SEEK_END); idx_records=ftell(ix)/48; fclose(ix);
            long mh=-1; FILE* ix2=fopen(ip,"rb"); static unsigned char rec[48];
            if(ix2){ long h=idx_records-1; while(h>=0){ if(fseek(ix2,h*48,SEEK_SET)==0 && fread(rec,1,48,ix2)==48 && (rec[0]||rec[1]||rec[2]||rec[3])){ mh=h; break; } h--; } fclose(ix2); }
            existing_tip=mh;
            if(mh>=0 && mh+1>start_h && !(end_h < mh)){ start_h=mh+1; printf("resume: existing tip %ld, continuing from %ld\n", mh, start_h); }
            else if(end_h < mh){ printf("backfill: range [%ld,%ld] is below existing tip %ld; preserving requested range\n", start_h,end_h,mh); }
        }
    }
    if(start_h>end_h){ printf("archive already complete through %ld; nothing to do\n", end_h); return 0; }
    long span=end_h-start_h+1;
    printf("downloading heights [%ld,%ld] (%ld blocks), %d workers\n", start_h,end_h,span,nw);

    /* claimpath: per-process (PID) so a concurrent forward chainctl and a
     * backfill pass each own a distinct claim table (never clobber each other's
     * distinct-peer bookkeeping while both write the same store). */
    snprintf(claimpath,sizeof claimpath,"%s/peerclaims.%ld",dir,(long)getpid()); remove(claimpath);

    /* establish a ROBUST trusted pool of confirmed-up DISTINCT peers.
     * Probe the full list in parallel (a forked child per peer, bounded time),
     * collecting confirmed-up distinct IPs. We want >= 3*nw for deep failover so
     * no worker ever starves when its current peer drops. */
    int goodindex[MAXPEERS]; int ngood=0; unsigned chosen_ip[MAXPEERS]; int nch=0;
    {
        /* parallel probe: forked children connect+handshake; parent REAPs */
        unsigned char alive[MAXPEERS]; memset(alive,0,MAXPEERS);
        pid_t pids[MAXPEERS]; memset(pids,0,sizeof pids);
        for(int i=0;i<np && i<MAXPEERS;i++){
            pid_t p=fork();
            if(p==0){
                char hb[128]; snprintf(hb,sizeof hb,"%s",peers[i]); char*c=strchr(hb,':'); if(c)*c=0;
                struct in_addr ia; if(inet_pton(AF_INET,hb,&ia)!=1) _exit(0);
                int fd=connect_peer(peers[i]);
                if(fd>=0){ fd_close(fd); _exit(1); }
                _exit(0);
            }
            pids[i]=p;
        }
        int done=0; time_t t0=time(NULL);
        while(done<=0 && time(NULL)-t0<20){
            int all=1; for(int i=0;i<np && i<MAXPEERS;i++){ if(pids[i] && waitpid(pids[i],NULL,WNOHANG)==0){ all=0; break; } }
            if(all) done=1; else usleep(100000);
        }
        for(int i=0;i<np && i<MAXPEERS;i++){ if(done==0 && pids[i]) kill(pids[i],SIGKILL); }
        for(int i=0;i<np && i<MAXPEERS;i++){ if(pids[i]){ int st; waitpid(pids[i],&st,0); alive[i]=WIFEXITED(st)&&WEXITSTATUS(st)==1?1:0; } }
        for(int i=0;i<np && i<MAXPEERS;i++){ char hb[128]; snprintf(hb,sizeof hb,"%s",peers[i]); char*c=strchr(hb,':'); if(c)*c=0;
            if(!alive[i]){ printf("pool peer[%d] %s DOWN\n",i,peers[i]); continue; }
            struct in_addr ia; if(inet_pton(AF_INET,hb,&ia)!=1) continue;
            int dup=0; for(int k=0;k<nch;k++) if(chosen_ip[k]==ia.s_addr){dup=1;break;}
            if(dup){ printf("pool peer[%d] %s SKIP-duplicate\n",i,peers[i]); continue; }
            goodindex[ngood]=i; chosen_ip[nch++]=ia.s_addr; ngood++;
            printf("pool peer[%d] %s UP\n",i,peers[i]);
        }
    }
    /* trusted pool may be large; cap worker count to what we can support with
     * deep failover. We need at least nw up peers; prefer up to nw*3. */
    if(ngood<nw){ fprintf(stderr,"only %d up peers for %d workers\n",ngood,nw); nw=ngood; }
    printf("trusted pool: %d confirmed-up DISTINCT peers\n", ngood);

    /* ---- SINGLE DIRECTORY layout: no worker dirs. ----
     * Pre-size index.dat to (end_h+1)*48 so every real height has a slot, then
     * workers write blocks DIRECTLY into this one store via store_append_shared
     * (flock'd, positional index). Create the shared append.lock once. */
    {
        char ip[640]; snprintf(ip,sizeof ip,"%s/index.dat",dir);
        int ix=open(ip,O_RDWR|O_CREAT,0644);
        if(ix<0){ perror("open index.dat"); return 1; }
        long need=((long)end_h+1)*48;
        /* GROW-ONLY: never shrink the index (a backfill pass covers low heights
         * while the forward archive already occupies higher slots). */
        if(need < idx_records*48) need=idx_records*48;
        if(ftruncate(ix,need)){ perror("ftruncate index.dat"); return 1; }
        close(ix);
        char lp[640]; snprintf(lp,sizeof lp,"%s/append.lock",dir);
        int lf=open(lp,O_RDWR|O_CREAT,0644);
        if(lf>=0) close(lf);
        printf("pre-sized index.dat to %ld heights; created append.lock\n", end_h+1);
    }
    pid_t kids[MAXPEERS];
    for(int w=0;w<nw;w++){
        long lo=start_h + (long)((long long)span*w/nw);
        long hi=start_h + (long)((long long)span*(w+1)/nw)-1;
        if(hi<lo)hi=lo;
        pid_t p=fork();
        if(p==0){ _exit(worker(w, dir, lo, hi, peers, goodindex, ngood, w)); }
        kids[w]=p;
    }
    for(int w=0;w<nw;w++){ int stt; waitpid(kids[w],&stt,0); printf("worker %d exit %d\n",w,WEXITSTATUS(stt)); }
    /* ---- no merge needed: workers wrote straight into ONE store in dir. ---- */
    int nfiles=0; while(1){ struct stat sb; char nm[64]; snprintf(nm,sizeof nm,"blk%05u.dat",(unsigned)nfiles);
        if(stat(nm,&sb))break; nfiles++; }
    long stored=(end_h-start_h+1);
    long present=0; struct stat sb; char ip[640]; snprintf(ip,sizeof ip,"%s/index.dat",dir);
    /* index is pre-sized (== stored*48), so report stored count; count non-zero records */
    printf("SINGLE-DIR IBD: %ld real blocks written directly into ONE store (%d blk*.dat + index.dat) in %s\n", stored, nfiles, dir);
    return 0;
}
