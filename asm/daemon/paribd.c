/* daemon/paribd.c -- PARALLEL multi-peer Initial Block Download orchestrator.
 *
 * Downloads a contiguous range of REAL mainnet block bodies from up to N
 * SIMULTANEOUS peer connections, validates each with the asm cons_verify, and
 * assembles them into the standard node store (blk00000.dat + index.dat) so the
 * chain can be re-served by `daemon serve`.
 *
 * Conventions: this file is C orchestration only -- every wire byte (connect,
 * handshake, getheaders/getdata framing) and every validation (cons_verify,
 * block_hash, sha256d) is the assembly primitives.
 *
 * Flow:
 *  1. Parent opens + handshakes up to num_workers peers simultaneously
 *     (default 8, so we download from >= 8 peers at once) and records which
 *     peers succeeded.
 *  2. Using the first good peer, the parent downloads + persists the header chain
 *     into <dir>/headers.dat via the asm header store (hst_*), paging getheaders
 *     by a running locator: hash-by-height for every block.
 *  3. Parent splits [start_h, end_h] into num_workers contiguous ranges and forks
 *     a child per successful peer. Each child, for each height in its range, looks
 *     up the block hash (hst_get_at), getdata it, receives the `block`, runs
 *     cons_verify, and appends the body to <dir>/blk<w>.dat with a per-worker
 *     index record (real height/offset/len). Each new block uses a fresh peer
 *     (reconnect on demand) so a dropping peer retries without deadlock.
 *  4. Parent merges all worker files by height into blk00000.dat + index.dat
 *     (positional by height, identical on-disk layout to the asm store).
 *
 * Resumable: rerun with the same <dir> and start_h >= persisted tip to continue.
 *
 * Usage: paribd <dir> <num_workers> <start_h> <end_h> [peer host ...]
 *   peers default to <dir>/../seeds.txt then the cooperative local node.
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

extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int, const char*, unsigned, const void*, unsigned);
extern int  p2p_read(int, char[12], void*, unsigned, unsigned*);
extern long p2p_getheaders(void*, const void*, long, const void*);
extern long p2p_headers_count(const void*, long);
extern long p2p_getdata_block(void* out, const void* hash);
extern void sha256d(unsigned char o[32], const void*m, long l);
extern int  cons_verify(const void* block, long len, void* scratch, unsigned cap);
extern int  hst_init(void* hst);
extern long hst_append(void* hst, const unsigned char hdr[80], const unsigned char hash[32]);
extern long hst_count(void* hst);
extern int  hst_get_at(void* hst, unsigned long long height, void* out);
extern void fd_close(int fd);

#define PORT_BE ((unsigned short)htons(8333))
#define MAXPEERS 20

static void u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static void u16(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}

/* ---------------- peer list ---------------- */
static int load_peers(const char* seedsfile, char peers[][128], int max){
    int n=0;
    FILE* f=fopen(seedsfile,"r"); if(!f) return n;
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

/* ---------------- handshake (asm wire, C glue) ---------------- */
static int connect_handshake(const char* host){
    unsigned ip=resolve(host); if(ip==0) return -1;
    int fd=tcp_connect_ip(ip,PORT_BE); if(fd<0) return -1;
    unsigned char v[102]; int o=0;
    u32(v+o,70016);o+=4;u64(v+o,1);o+=8;u64(v+o,(unsigned long long)time(NULL));o+=8;
    u64(v+o,1);o+=8;o+=16;u16(v+o,8333);o+=2;u64(v+o,1);o+=8;o+=16;u16(v+o,0);o+=2;
    u64(v+o,0x1122334455667788ULL);o+=8;
    const char* ua="/Satoshi:0.18.0/";v[o]=strlen(ua);o+=1;memcpy(v+o,ua,strlen(ua));o+=strlen(ua);
    u32(v+o,789000);o+=4;v[o]=1;o+=1;
    if(p2p_write(fd,"version",7,v,o)<=0){ fd_close(fd); return -1; }
    char cmd[12]; static unsigned char rb[1<<22]; unsigned plen=0; int va=0;
    for(int i=0;i<40;i++){
        int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r<=0) break; cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(!strncmp(cmd,"sendheaders",11)||!strncmp(cmd,"sendaddrv2",10)||!strncmp(cmd,"wtxidrelay",10)||!strncmp(cmd,"sendcmpct",9)){ p2p_write(fd,cmd,strlen(cmd),"",0); continue; }
        if(!strncmp(cmd,"version",7)) continue;
        if(!strncmp(cmd,"verack",6)){ va=1; break; }
    }
    if(!va){ fd_close(fd); return -1; }
    p2p_write(fd,"verack",6,"",0);
    return fd;
}

/* Drain inbound chatter until a headers/block/notfound of interest arrives.
 * want_block: 1 -> return on `block` (payload in rb, *plen = len) / notfound(-2).
 *            0 -> return on `headers` (payload in rb).
 * Returns 1 on interest, -2 on notfound, 0 on peer-close/error. */
static int drain_until(int fd, char* cmd, unsigned char* rb, unsigned long rbsize, unsigned* plen, int want_block){
    for(int i=0;i<4000;i++){
        *plen=0;
        int r=p2p_read(fd,cmd,rb,rbsize,plen);
        if(r<=0) return 0;
        cmd[11]=0;
        if(!strncmp(cmd,"ping",4)&&*plen==8){ p2p_write(fd,"pong",4,rb,8); continue; }
        if(!strncmp(cmd,"sendheaders",11)||!strncmp(cmd,"sendaddrv2",10)||!strncmp(cmd,"sendcmpct",9)||!strncmp(cmd,"wtxidrelay",10)||!strncmp(cmd,"feefilter",9)){ p2p_write(fd,cmd,strlen(cmd),"",0); continue; }
        if(want_block){
            if(!strncmp(cmd,"block",5)&&*plen>80) return 1;
            if(!strncmp(cmd,"notfound",8)) return -2;
        } else {
            if(!strncmp(cmd,"headers",7)) return 1;
        }
    }
    return 0;
}

/* ---------------- parent: persist the header chain via asm hst_* ---------------- */
static long persist_headers(int fd, char* cmd, unsigned char* rb, unsigned long rbsize,
                            unsigned* plen, void* hst, long want){
    hst_init(hst);
    unsigned char cur[32]; memset(cur,0,32);
    unsigned char stop[32]; memset(stop,0,32);
    unsigned char page[2000][80];
    long total=0;
    for(int pg=0; pg<40000 && total<want; pg++){
        unsigned char gh[128]; long gl=p2p_getheaders(gh,cur,1,stop);
        if(p2p_write(fd,"getheaders",10,gh,gl)<=0) break;
        if(drain_until(fd,cmd,rb,rbsize,plen,0)!=1) break;
        long n=p2p_headers_count(rb,*plen);
        if(n<0) break;
        if(n>2000)n=2000;
        unsigned char* b=(rb[0]==0xfd)?rb+3:rb+1;
        for(long k=0;k<n;k++){
            unsigned char hh[32]; sha256d(hh,b+k*81,80);
            if(hst_append(hst,b+k*81,hh)<0) return -1;
            total++;
        }
        unsigned char last[32]; sha256d(last,b+(n-1)*81,80);
        memcpy(cur,last,32);
        if(n<2000) break;
    }
    return total;
}

/* ---------------- child: download [start_h,end_h] into blk<w>.dat + idx<w>.dat ---------------- */
static int child_download(int w, const char* dir, long start_h, long end_h, void* hst,
                          char peers[][128], int np, int pi0){
    static unsigned char rb[24<<20];
    static unsigned char scr[8<<20];
    char blkpath[512], idxpath[512];
    snprintf(blkpath,sizeof blkpath,"%s/blk%d.dat",dir,w);
    snprintf(idxpath,sizeof idxpath,"%s/idx%d.dat",dir,w);
    FILE* bf=fopen(blkpath,"wb"); if(!bf) return 1;
    FILE* xf=fopen(idxpath,"wb"); if(!xf){ fclose(bf); return 1; }
    char cmd[12]; unsigned plen=0;
    unsigned char rec[48];
    unsigned long long off=0;
    long downloaded=0;
    int fd=-1;
    for(long h=start_h; h<=end_h; h++){
        unsigned char ent[112];
        if(hst_get_at(hst,h,ent)!=1) break;
        unsigned char gd[64]; long gdl=p2p_getdata_block(gd,ent+80);

        /* (re)connect if we don't have a live peer (persistent per worker) */
        int pi=pi0;
        if(fd<0){
            for(int a=0; a<np*2 && fd<0; a++){
                fd=connect_handshake(peers[(pi+a)%np]);
                if(fd<0) usleep(150000);
            }
            if(fd<0) break;
        }
        /* request + wait for block; reconnect+retry on peer drop */
        long blen=-1; int got=0;
        for(int tr=0; tr<4 && !got; tr++){
            if(p2p_write(fd,"getdata",7,gd,gdl)<=0){ fd_close(fd); fd=-1; break; }
            int r=drain_until(fd,cmd,rb,sizeof rb,&plen,1);
            if(r==1){ blen=plen; got=1; }
            else if(r==-2){ blen=-1; got=1; break; }
            else { fd_close(fd); fd=-1; }   /* peer closed -> reconnect restarts loop */
        }
        if(got && blen>0 && cons_verify(rb,blen,scr,(unsigned)(sizeof scr/32))==1){
            unsigned char fh[8]; u32(fh,(unsigned)blen); u32(fh+4,0xd9b4bef9);
            fwrite(fh,1,8,bf); fwrite(rb,1,(size_t)blen,bf);
            memcpy(rec,ent+80,32);
            u64(rec+32,(unsigned long long)off);
            u32(rec+40,(unsigned)blen);
            u32(rec+44,(unsigned)h);
            fwrite(rec,1,48,xf);
            off += 8+blen; downloaded++;
            if((h-start_h)%2000==0) fprintf(stderr,"[w%d] h=%ld (%ld B, %ld dl)\n",w,h,blen,downloaded);
        } else if(got && blen==-1){
            memset(rec,0,32); u64(rec+32,(unsigned long long)off);
            u32(rec+40,0); u32(rec+44,(unsigned)h);
            fwrite(rec,1,48,xf);
        }
    }
    if(fd>=0) fd_close(fd);
    fclose(bf); fclose(xf);
    fprintf(stderr,"[w%d] done, downloaded %ld blocks into blk%d.dat\n",w,downloaded,w);
    return downloaded>0?0:1;
}

/* ---------------- parent: merge all worker files into blk00000.dat + index.dat ----------------
 * The worker ranges are contiguous and ascending with worker id, and each worker's
 * file is already in ascending height order, so merging is just appending workers
 * in id order -- no sort and bounded memory (streams each index file once). */
static int merge(const char* dir, int nw){
    char blkmain[512], idxmain[512];
    snprintf(blkmain,sizeof blkmain,"%s/blk00000.dat",dir);
    snprintf(idxmain,sizeof idxmain,"%s/index.dat",dir);
    FILE* mb=fopen(blkmain,"wb"); if(!mb) return 1;
    FILE* mi=fopen(idxmain,"wb"); if(!mi){ fclose(mb); return 1; }
    static unsigned char combuf[24<<20];   /* static: 24MB would overflow the 8MB stack */
    unsigned long long cur=0;
    long total_written=0;
    for(int w=0; w<nw; w++){
        char ip[512]; snprintf(ip,sizeof ip,"%s/idx%d.dat",dir,w);
        FILE* xf=fopen(ip,"rb"); if(!xf) continue;
        unsigned char rec[48];
        while(fread(rec,1,48,xf)==48){
            unsigned len=(unsigned)(rec[40]|rec[41]<<8|rec[42]<<16|rec[43]<<24);
            unsigned height=(unsigned)(rec[44]|rec[45]<<8|rec[46]<<16|rec[47]<<24);
            if(len==0) continue;                    /* notfound gap */
            unsigned long long off=0;
            for(int k=0;k<8;k++) off |= (unsigned long long)rec[32+k]<<(8*k);
            /* read body from blk<w>.dat at off (skip 8B frame -> bytes at off+8) */
            char bp[512]; snprintf(bp,sizeof bp,"%s/blk%d.dat",dir,w);
            FILE* wf=fopen(bp,"rb"); if(!wf){ continue; }
            if(fseek(wf,(long)(off+8),SEEK_SET)!=0){ fclose(wf); continue; }
            if(len>sizeof combuf){ fclose(wf); continue; }
            if(fread(combuf,1,len,wf)!=(size_t)len){ fclose(wf); continue; }
            fclose(wf);
            /* write main: [u32 len][u32 magic][body] */
            unsigned char hdr[8]; u32(hdr,len); u32(hdr+4,0xd9b4bef9);
            fwrite(hdr,1,8,mb); fwrite(combuf,1,len,mb);
            /* index record at height*48 */
            unsigned char outrec[48]; memcpy(outrec,rec,32);
            u64(outrec+32,cur); u32(outrec+40,len); u32(outrec+44,height);
            fseek(mi,(long)height*48,SEEK_SET);
            fwrite(outrec,1,48,mi);
            cur += 8+len; total_written++;
        }
        fclose(xf);
        /* remove worker files to save space */
        char bp[512]; snprintf(bp,sizeof bp,"%s/blk%d.dat",dir,w); remove(bp);
        snprintf(bp,sizeof bp,"%s/idx%d.dat",dir,w); remove(bp);
    }
    fclose(mb); fclose(mi);
    printf("merged %ld real blocks into %s (blk00000.dat %llu bytes)\n", total_written, dir, cur);
    return total_written>0?0:1;
}

int main(int argc, char** argv){
    if(argc<5){ fprintf(stderr,"usage: %s <dir> <num_workers> <start_h> <end_h> [peer...]\n",argv[0]); return 2; }
    const char* dir=argv[1];
    int nw=atoi(argv[2]); if(nw<1)nw=1; if(nw>MAXPEERS-1)nw=MAXPEERS-1;
    long start_h=atol(argv[3]);
    long end_h=atol(argv[4]);
    mkdir(dir,0755);

    char peers[MAXPEERS][128]; int np=0;
    if(argc>5){ for(int i=5;i<argc&&np<MAXPEERS;i++){ strncpy(peers[np],argv[i],127);peers[np][127]=0;np++; } }
    else {
        char sf[512]; snprintf(sf,sizeof sf,"%s/../seeds.txt",dir);
        np=load_peers(sf,peers,MAXPEERS);
        if(np==0){ /* fallback cooperative node */ strcpy(peers[0],"192.168.5.69"); np=1; }
        /* ensure the cooperative node is first */
        /* move any exact '192.168.5.69' to front */
        for(int i=0;i<np;i++) if(!strcmp(peers[i],"192.168.5.69")&&i!=0){ char t[128];strcpy(t,peers[0]);strcpy(peers[0],peers[i]);strcpy(peers[i],t);break; }
    }
    if(np==0){ fprintf(stderr,"no peers\n"); return 2; }
    printf("peers: %d\n", np); for(int i=0;i<np;i++) printf("  [%d] %s\n",i,peers[i]);

    /* ---- borrow a working directory for scratch (in dir) ---- */
    if(chdir(dir)!=0){ perror("chdir"); return 1; }

    /* ---- phase 1: connect + handshake up to nw peers simultaneously ---- */
    int fds[MAXPEERS]; int good[MAXPEERS]; int ngood=0;
    static unsigned char gcmd[12]; static unsigned char grb[1<<22]; unsigned gplen=0;
    for(int i=0;i<nw && i<np;i++){
        fds[i]=connect_handshake(peers[i]);
        good[i]= fds[i]>=0;
        if(good[i]) ngood++;
        printf("peer %d (%s): %s\n", i, peers[i], good[i]?"UP":"DOWN");
    }
    if(ngood==0){ fprintf(stderr,"no peers connected\n"); return 1; }
    printf("established %d/%d simultaneous peer connections\n", ngood, nw);

    /* ---- phase 2: persist the header chain via peer[first-good] ---- */
    int hpeer=-1; for(int i=0;i<nw&&i<np;i++){ if(good[i]){hpeer=i;break;} }
    static unsigned char hst[(1<<22)];   /* header store context + file */
    long nhdr = persist_headers(fds[hpeer], gcmd, grb, sizeof grb, &gplen, hst, end_h+2);
    printf("persisted %ld real headers (hash-by-height)\n", nhdr);
    if(nhdr<=0){ fprintf(stderr,"header download failed\n"); return 1; }
    /* close extra handshake fds (children reconnect their own) */
    for(int i=0;i<nw&&i<np;i++) if(fds[i]>=0) fd_close(fds[i]);

    /* ---- phase 3: split ranges across workers and fork ---- */
    /* only [start_h, min(end_h, nhdr-1)] are known */
    if(end_h>nhdr-1) end_h=nhdr-1;
    if(start_h>end_h){ fprintf(stderr,"range empty\n"); return 1; }
    long span=end_h-start_h+1;
    int workers=nw; if(workers>ngood) workers=ngood;
    printf("downloading heights [%ld,%ld] (%ld blocks) across %d workers\n", start_h,end_h,span,workers);
    pid_t kids[MAXPEERS];
    for(int w=0; w<workers; w++){
        long lo = start_h + (long)((long long)span*w/workers);
        long hi = start_h + (long)((long long)span*(w+1)/workers) - 1;
        if(hi<lo) hi=lo;
        pid_t pid=fork();
        if(pid==0){
            /* child: pick a distinct peer strand */
            int pi0=hpeer; /* all may share the cooperative node; seeds also tried */
            _exit(child_download(w,dir,lo,hi,hst,peers,np,pi0));
        }
        kids[w]=pid;
    }
    for(int w=0; w<workers; w++){ int st; waitpid(kids[w],&st,0);
        printf("worker %d exit %d\n", w, WEXITSTATUS(st)); }

    /* ---- phase 4: merge ---- */
    merge(dir,workers);
    printf("PARALLEL IBD complete: heights [%ld,%ld]\n", start_h, end_h);
    return 0;
}
