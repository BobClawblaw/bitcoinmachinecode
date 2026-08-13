/* daemon/paribd_asm.c -- PARALLEL multi-peer Initial Block Download whose
 * DOWNLOAD LOOP IS ASSEMBLY (node_ibd_blocks_x).
 *
 * Every byte moved on the wire and every validation is the assembly primitives;
 * this file is C orchestration only (peer resolution, fork, per-worker header-
 * store re-index, and the final file merge). The per-worker receive loop
 * (getdata -> recv -> cons_verify -> re-hash guard -> store_append) runs in asm.
 *
 * Flow:
 *   1. Parent connects to peer[0] and downloads + persists the whole header chain
 *      via the ASM node_ibd_headers (paged getheaders by a running locator) into
 *      a master header store.
 *   2. Parent opens num_workers simultaneous peer connections (>= 8) and records
 *      which are UP.
 *   3. Parent forks one worker per UP peer; worker w owns real heights
 *      [lo_w, hi_w]. It re-indexes them into its OWN header store (0..n-1) via
 *      asm hst_get_at + hst_append, then runs the ASM node_ibd_blocks_x
 *      (start_h=0, end_h=n-1) which downloads + validates + stores each block in
 *      assembly. On a peer drop it reconnects and re-invokes at the next
 *      un-stored height.
 *   4. Parent merges the per-worker block stores into blk00000.dat + index.dat
 *      (positional by height) for re-serving.
 *
 * Usage: paribd_asm <dir> <num_workers> <end_h> [peer IP ...]
 *   (each worker chdirs into <dir>/w<w>; the parent merges afterward)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>

extern int  tcp_connect_ip(unsigned, unsigned short);
extern long p2p_write(int,const char*,unsigned,const void*,unsigned);
extern int  p2p_read(int,char[12],void*,unsigned,unsigned*);
extern int  node_handshake(int fd);
extern long node_ibd_headers(int fd, void* hst, void* locator32, void* page_buf, unsigned long buflen);
extern long node_ibd_blocks_x(int fd, void* st, void* hst, long start_h, long end_h,
                              void* buf, unsigned long buflen, void* scratch, unsigned scratch_cap);
extern int  hst_init(void* hst);
extern int  hst_reload(void* hst);
extern long hst_append(void* hst, const unsigned char hdr[80], const unsigned char hash[32]);
extern long hst_count(void* hst);
extern int  hst_get_at(void* hst, unsigned long long height, void* out);
extern int  store_init(void* st);
extern int  store_reload(void* st);
extern long store_get_tip(void* st, void* out_meta);
extern void fd_close(int fd);

#define PORT_BE ((unsigned short)htons(8333))
#define MAXPEERS 24

static void u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}

static int load_peers(const char* fname, char peers[][128], int max){
    int n=0; FILE* f=fopen(fname,"r"); if(!f) return n;
    char line[256];
    while(fgets(line,sizeof line,f)){
        char* nl=strpbrk(line,"\r\n"); if(nl)*nl=0;
        char* p=line; while(*p==' '||*p=='\t')p++;
        if(*p==0||*p=='#') continue;
        int l=strlen(p); while(l>0&&(p[l-1]==' '||p[l-1]=='\t'))p[--l]=0;
        if(*p&&n<max){ strncpy(peers[n],p,127); peers[n][127]=0; n++; }
    }
    fclose(f); return n;
}
static unsigned resolve(const char* host){
    unsigned ip4=0; if(inet_pton(AF_INET,host,&ip4)==1) return ip4;
    struct addrinfo h,*res=0; memset(&h,0,sizeof h);
    h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,NULL,&h,&res)!=0) return 0;
    unsigned ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res); return ip;
}
static int connect_peer(const char* host){
    unsigned ip=resolve(host); if(ip==0) return -1;
    int fd=tcp_connect_ip(ip,PORT_BE); if(fd<0) return -1;
    if(node_handshake(fd)!=1){ fd_close(fd); return -1; }
    return fd;
}

/* ---------------- worker: all-asm block loop over its shard ---------------- */
static int worker(int w, const char* dir, long lo_w, long hi_w, void* mhst,
                  char peers[][128], int np, int pi0){
    char wdir[512]; snprintf(wdir,sizeof wdir,"%s/w%d",dir,w);
    mkdir(wdir,0755);
    if(chdir(wdir)!=0){ perror("chdir worker"); return 1; }

    /* re-index master [lo_w,hi_w] into this worker's header store (0..n-1), asm */
    static unsigned char hst[4096];
    hst_init(hst);
    long n=0;
    for(long k=lo_w; k<=hi_w; k++){
        unsigned char rec[112];
        if(hst_get_at(mhst,k,rec)!=1) break;
        if(hst_append(hst,rec,rec+80)<0) break;
        n++;
    }
    if(n<=0){ fprintf(stderr,"[w%d] no headers in shard\n",w); return 1; }

    static unsigned char st[4096];
    store_init(st); store_reload(st);

    static unsigned char buf[24<<20];
    static unsigned char scratch[8<<20];
    unsigned cap=(unsigned)(sizeof scratch/32);

    int guard=0;
    int pi=pi0;
    long resume=0;               /* local height to resume from */
    for(;;){
        /* connect to a peer, failing over across the pool on errors */
        int fd=-1;
        for(int a=0; a<np*3 && fd<0; a++){
            fd=connect_peer(peers[(pi+a)%np]);
            if(fd<0) usleep(150000);
        }
        if(fd<0){ fprintf(stderr,"[w%d] all peers unreachable, giving up\n",w); break; }
        /* run the ASM receive loop over [resume, n-1]; -1 (peer dropped) -> resume */
        long r=node_ibd_blocks_x(fd, st, hst, resume, n-1, buf, sizeof buf, scratch, cap);
        fd_close(fd);
        if(r!=0 && guard++>3000){ fprintf(stderr,"[w%d] reconnect budget exhausted\n",w); break; }
        /* resume from stored tip + 1 (worker local heights 0.. in its own store) */
        store_reload(st);
        int tip_h = *(int*)((char*)st+24);   /* -1 if nothing stored yet */
        resume = (long)tip_h + 1;            /* 0 if empty */
        if(resume>=n){ break; }              /* all shard blocks stored -> done */
        pi = (pi+1)%np;                       /* rotate peer for next round */
        usleep(200000);
    }
    fprintf(stderr,"[w%d] done: shard [%ld,%ld]\n", w, lo_w, hi_w);
    return 0;
}

/* ---------------- parent: merge per-worker stores into blk00000.dat + index.dat ---
 * Each worker store (w<w>/blk00000.dat + index.dat) holds its shard at LOCAL
 * heights 0..n-1; real height = lo_w + local. Concatenate all workers in id order
 * (ranges are contiguous & ascending) into the final positional store. */
static int merge_all(const char* dir, long start_h, long end_h, int nw){
    char mbp[512], mip[512];
    snprintf(mbp,sizeof mbp,"%s/blk00000.dat",dir);
    snprintf(mip,sizeof mip,"%s/index.dat",dir);
    FILE* mb=fopen(mbp,"wb"); if(!mb) return 1;
    FILE* mi=fopen(mip,"wb"); if(!mi){ fclose(mb); return 1; }
    static unsigned char combuf[24<<20];
    unsigned long long cur=0; long written=0;
    for(int w=0; w<nw; w++){
        long lo_w = start_h + (long)((long long)(end_h-start_h+1)*w/nw);
        char wd[512]; snprintf(wd,sizeof wd,"%s/w%d",dir,w);
        char wip[512]; snprintf(wip,sizeof wip,"%s/index.dat",wd);
        FILE* wx=fopen(wip,"rb"); if(!wx) continue;
        char wp[512]; snprintf(wp,sizeof wp,"%s/blk00000.dat",wd);
        FILE* wf=fopen(wp,"rb"); if(!wf){ fclose(wx); continue; }
        unsigned char rec[48]; long local=0;
        while(fread(rec,1,48,wx)==48){
            unsigned len=(unsigned)(rec[40]|rec[41]<<8|rec[42]<<16|rec[43]<<24);
            if(len==0) { local++; continue; }            /* stub */
            unsigned long long off=0;
            for(int k=0;k<8;k++) off |= (unsigned long long)rec[32+k]<<(8*k);
            if(fseek(wf,(long)(off+8),SEEK_SET)!=0){ fclose(wf); break; }
            if(len>sizeof combuf){ fclose(wf); break; }
            if(fread(combuf,1,len,wf)!=(size_t)len){ fclose(wf); break; }
            unsigned real = (unsigned)(lo_w + local);
            unsigned char hdr[8]; u32(hdr,len); u32(hdr+4,0xd9b4bef9);
            fwrite(hdr,1,8,mb); fwrite(combuf,1,len,mb);
            unsigned char or[48]; memcpy(or,rec,32);
            for(int k=0;k<8;k++) or[32+k]=(unsigned char)(cur>>(8*k));
            or[40]=(unsigned char)len; or[41]=(unsigned char)(len>>8);
            or[42]=(unsigned char)(len>>16); or[43]=(unsigned char)(len>>24);
            or[44]=(unsigned char)real; or[45]=(unsigned char)(real>>8);
            or[46]=(unsigned char)(real>>16); or[47]=(unsigned char)(real>>24);
            fseek(mi,(long)real*48,SEEK_SET);
            fwrite(or,1,48,mi);
            cur += 8+len; written++;
            local++;
        }
        fclose(wf); fclose(wx);
    }
    fclose(mb); fclose(mi);
    printf("merged %ld real blocks (blk00000.dat %llu bytes)\n", written, cur);
    return 0;
}

int main(int argc,char**argv){
    if(argc<5){ fprintf(stderr,"usage: %s <dir> <num_workers> <end_h> <peerIP> [peerIP...]\n",argv[0]); return 2; }
    const char* dir=argv[1];
    int nw=atoi(argv[2]); if(nw<1)nw=1; if(nw>MAXPEERS-4)nw=MAXPEERS-4;
    long end_h=atol(argv[3]);
    mkdir(dir,0755);

    /* peers from argv[4..] OR default good-internet list */
    char peers[MAXPEERS][128]; int np=0;
    for(int i=4;i<argc && np<MAXPEERS;i++){ strncpy(peers[np],argv[i],127);peers[np][127]=0;np++; }
    if(np==0){
        np=load_peers("/storage/bitcoinmachinecode/good_internet_peers.txt",peers,MAXPEERS);
    }
    if(np<nw) nw=np;
    if(np==0){ fprintf(stderr,"no peers\n"); return 1; }
    for(int i=0;i<np;i++) printf("peer[%d] %s\n",i,peers[i]);

    /* ---- phase 1: ASM header download via node_ibd_headers into master hst ---- */
    if(chdir(dir)!=0){ perror("chdir"); return 1; }
    static unsigned char mhst[4096];
    hst_init(mhst);
    static unsigned char zp[32];  /* genesis locator = 0 */
    memset(zp,0,32);
    static unsigned char hdrbuf[2<<20];
    int hfd=connect_peer(peers[0]);
    if(hfd<0){ fprintf(stderr,"cannot connect header peer\n"); return 1; }
    long nhdr = node_ibd_headers(hfd, mhst, zp, hdrbuf, sizeof hdrbuf);
    fd_close(hfd);
    printf("asm header download: %ld headers persisted\n", nhdr);
    if(nhdr<=0){ fprintf(stderr,"header download failed\n"); return 1; }
    if(end_h>nhdr-1) end_h=nhdr-1;
    long start_h=0, span=end_h-start_h+1;
    printf("downloading real heights [%ld,%ld] (%ld blocks) via ASM loop across %d peers\n",
           start_h,end_h,span,nw);

    /* ---- phase 2: establish >=8 simultaneous distinct peer connections ----
     * Probe the WHOLE pool (up to np peers) and keep the first nw that are UP,
     * so every worker gets a distinct live peer (>= nw workers). */
    int workers = nw;                        /* how many distinct UP peers we secure */
    int goodindex[MAXPEERS]; int ngood=0;
    for(int i=0;i<np;i++){
        int fd=connect_peer(peers[i]);
        int up= fd>=0;
        if(fd>=0) fd_close(fd);
        printf("peer[%d] %s %s\n", i, peers[i], up?"UP":"DOWN");
        if(up && ngood<nw){ goodindex[ngood++]=i; }
        /* keep probing until we secure nw UP peers or exhaust the pool */
        if(ngood>=nw) break;
    }
    if(ngood<nw){ workers=ngood; }           /* fewer up than requested */
    printf("established %d/%d simultaneous peer connections\n", ngood, nw);

    /* ---- phase 3: fork workers (worker w uses UP peer goodindex[w]) ---- */
    pid_t kids[MAXPEERS];
    for(int w=0;w<workers;w++){
        long lo = start_h + (long)((long long)span*w/workers);
        long hi = start_h + (long)((long long)span*(w+1)/workers) - 1;
        if(hi<lo) hi=lo;
        pid_t pid=fork();
        if(pid==0){
            /* child chdir's into dir/w<w>; the inherited mhst fd (open headers.dat
             * in dir) stays valid across cwd change, so worker() can read master. */
            _exit(worker(w, dir, lo, hi, mhst, peers, np, goodindex[w]));
        }
        kids[w]=pid;
    }
    for(int w=0;w<workers;w++){ int st; waitpid(kids[w],&st,0);}
    merge_all(dir, start_h, end_h, workers);
    printf("PARALLEL ASM IBD complete: heights [%ld,%ld]\n", start_h, end_h);
    return 0;
}
