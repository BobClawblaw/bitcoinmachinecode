/* daemon/unified_ibd.c -- full-chain download into a SINGLE unified store.
 *
 * Addresses the "w0..w7 shard-dir clutter" concern: the durable archive is ONE
 * store at <dir>/blk00000.dat.. + index.dat, and NO w<w>/ shard dirs are ever
 * left behind. Parallelism is preserved for the network download; the write(s)
 * into the unified store are sequential (correct for a height-ordered archive).
 *
 * Flow (all block loop + append in ASM):
 *   1. Connect >=8 DISTINCT peers (claim table) + persist the whole header
 *      chain into <dir>/headers.dat via asm node_ibd_headers.
 *   2. Split [start_h, end_h] into 8 disjoint ranges; each worker runs the asm
 *      node_ibd_blocks_x loop into a TRANSIENT scratch dir /tmp/<run>_w<w>
 *      (used only for the download, rolled blk files inside).
 *   3. A single sequential merge re-appends every worker shard into <dir> via
 *      the asm store_append in real-height order (continuing from the store's
 *      existing tip +1 -- so it resumes into the same unified archive).
 *   4. Delete the transient scratch dirs.
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
    struct timeval tv; tv.tv_sec=5; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    if(node_handshake(fd)!=1){ fd_close(fd); return -1; }
    return fd;
}

static void rmrf(const char* d){ DIR* dd=opendir(d); if(!dd) return;
    struct dirent* e; char p[600]; while((e=readdir(dd))){ if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;
        snprintf(p,sizeof p,"%s/%s",d,e->d_name); remove(p); } closedir(dd); rmdir(d); }

/* worker: download [lo,hi] real heights via asm node_ibd_blocks_x into a
 * transient scratch store dir. Re-indexes master [lo,hi] -> local hst. */
static int worker(int w, const char* scratchbase, long lo, long hi, void* mhst,
                  char peers[][128], int np, int pi0){
    char wdir[512]; snprintf(wdir,sizeof wdir,"%s_w%d",scratchbase,w);
    mkdir(wdir,0755); if(chdir(wdir)) return 1;
    static unsigned char hst[4096]; hst_init(hst);
    long n=0;
    for(long k=lo;k<=hi;k++){ unsigned char rec[112];
        if(hst_get_at(mhst,k,rec)!=1) break;
        if(hst_append(hst,rec,rec+80)<0) break; n++; }
    if(n<=0){ fprintf(stderr,"[w%d] no headers\n",w); return 1; }
    static unsigned char st[4096]; store_init(st); store_reload(st);
    static unsigned char buf[24<<20]; static unsigned char scratch[8<<20];
    unsigned cap=(unsigned)(sizeof scratch/32);
    int guard=0; int pi=pi0; long resume=0; char cip[128]={0};
    for(;;){
        int fd=-1; int ok=0;
        for(int a=0;a<np*3+40 && !ok;a++){
            const char* cand=peers[(pi+a)%np];
            char i[128]; snprintf(i,sizeof i,"%s",cand); char*c=strchr(i,':'); if(c)*c=0;
            if(!cl_take(i)) continue;
            int fdc=connect_peer(cand);
            if(fdc>=0){ strncpy(cip,i,sizeof cip); fd=fdc; ok=1; } else { cl_rel(i); }
        }
        if(!ok){ fprintf(stderr,"[w%d] no distinct peer\n",w); break; }
        long r=node_ibd_blocks_x(fd, st, hst, resume, n-1, buf, sizeof buf, scratch, cap);
        fd_close(fd); cl_rel(cip); cip[0]=0;
        if(r!=0 && guard++>3000){ fprintf(stderr,"[w%d] reconnect budget\n",w); break; }
        store_reload(st);
        int tip_h=*(int*)((char*)st+24);
        resume=(long)tip_h+1;
        if(resume>=n) break;
        pi=(pi+1)%np;
    }
    fprintf(stderr,"[w%d] done %ld/%ld\n", w, resume, n);
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
    long span=end_h-start_h+1;
    printf("downloading heights [%ld,%ld] (%ld blocks), %d workers\n", start_h,end_h,span,nw);

    /* claimpath */
    snprintf(claimpath,sizeof claimpath,"%s/peerclaims",dir); remove(claimpath);

    /* establish nw DISTINCT up peers */
    int goodindex[MAXPEERS]; int ngood=0; unsigned chosen_ip[MAXPEERS]; int nch=0;
    for(int i=0;i<np && ngood<nw;i++){
        char hb[128]; snprintf(hb,sizeof hb,"%s",peers[i]); char*c=strchr(hb,':'); if(c)*c=0;
        struct in_addr ia; if(inet_pton(AF_INET,hb,&ia)!=1) continue;
        int dup=0; for(int k=0;k<nch;k++) if(chosen_ip[k]==ia.s_addr){dup=1;break;}
        if(dup){ printf("peer[%d] %s SKIP-duplicate\n",i,peers[i]); continue; }
        int fd=connect_peer(peers[i]); int up=fd>=0; if(fd>=0) fd_close(fd);
        printf("peer[%d] %s %s\n",i,peers[i],up?"UP":"DOWN");
        if(up){ goodindex[ngood++]=i; chosen_ip[nch++]=ia.s_addr; }
    }
    if(ngood<nw)nw=ngood;
    printf("established %d/%d DISTINCT\n",ngood,nw);

    char scratchbase[512]; snprintf(scratchbase,sizeof scratchbase,"%s/_work",dir);
    pid_t kids[MAXPEERS];
    for(int w=0;w<nw;w++){
        long lo=start_h + (long)((long long)span*w/nw);
        long hi=start_h + (long)((long long)span*(w+1)/nw)-1;
        if(hi<lo)hi=lo;
        pid_t p=fork();
        if(p==0){ _exit(worker(w,scratchbase,lo,hi,mhst,peers,np,goodindex[w])); }
        kids[w]=p;
    }
    for(int w=0;w<nw;w++){ int stt; waitpid(kids[w],&stt,0); printf("worker %d exit %d\n",w,WEXITSTATUS(stt)); }

    /* ---- sequential merge into the unified store in dir ----
     * Each worker shard store (_work_w<w>/blk+index) holds local heights 0..n,
     * real height = lo_w + local; ranges are contiguous & ascending, so append
     * workers in id order -> real-height-ordered unified archive. */
    static unsigned char mst[4096]; store_init(mst); store_reload(mst);
    static unsigned char combuf[64<<20];
    long written=0;
    for(int w=0;w<nw;w++){
        long lo_w=start_h + (long)((long long)span*w/nw);
        char wip[512]; snprintf(wip,sizeof wip,"%s_w%d/index.dat",scratchbase,w);
        FILE* wx=fopen(wip,"rb"); if(!wx) continue;
        char wp[512]; snprintf(wp,sizeof wp,"%s_w%d/blk00000.dat",scratchbase,w);
        FILE* wf=fopen(wp,"rb"); if(!wf){ fclose(wx); continue; }
        unsigned char rec[48]; long local=0;
        while(fread(rec,1,48,wx)==48){
            unsigned len=(unsigned)(rec[44]|rec[45]<<8|rec[46]<<16|rec[47]<<24);
            if(len==0||len>64u<<20){ local++; continue; }
            unsigned long long off=0; for(int k=0;k<8;k++) off |= (unsigned long long)rec[36+k]<<(8*k);
            if(fseek(wf,(long)(off+8),SEEK_SET)){ local++; continue; }
            if(fread(combuf,1,len,wf)!=(size_t)len){ local++; continue; }
            if(store_append(mst,rec,combuf,len)<0){ fprintf(stderr,"append fail w%d/%ld\n",w,local); break; }
            written++; local++;
        }
        fclose(wf); fclose(wx);
    }
    /* cleanup transient scratch */
    for(int w=0;w<nw;w++){ char wd[512]; snprintf(wd,sizeof wd,"%s_w%d",scratchbase,w); rmrf(wd); }
    int nfiles=0; while(1){ struct stat sb; char nm[64]; snprintf(nm,sizeof nm,"blk%05u.dat",(unsigned)nfiles);
        if(stat(nm,&sb))break; nfiles++; }
    printf("UNIFIED IBD: appended %ld real blocks; archive has %d blk*.dat + index.dat in %s\n", written,nfiles,dir);
    return 0;
}
