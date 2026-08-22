/* daemon/pverify.c -- PARALLEL block-chain verifier with runtime machine-adaptive
 * sizing. Verifies the same four properties as daemon/verify.c (hash-match,
 * chain-link, PoW, full cons_verify via the assembly primitives) but splits the
 * expensive per-block work -- block_hash, pow_check, cons_verify -- across a
 * worker pool sized from the running machine, leaving only the cheap serial
 * chain-link comparison to a single pass.
 *
 * Machine-adaptive sizing (detected at startup, nothing hardcoded):
 *   - worker count = sysconf(_SC_NPROCESSORS_ONLN), clamped and bounded by
 *     available RAM below so we never oversubscribe on small boxes.
 *   - per-worker block buffer + cons_verify scratch are sized once and reused.
 *
 * Thread safety: block_hash / pow_check / cons_verify are pure; cons_verify
 * writes only to a caller-provided scratch buffer -- every worker gets its own
 * block buffer + scratch and its own FILE handles, so no shared-state locks.
 *
 * Usage: pverify <dir> [start] [end]
 *   exit 0 "CHAIN VERIFIED"      1 "CHAIN HAS ERRORS"
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include "../bmc_thread.h"
#include <signal.h>

extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern int  pow_check(const unsigned char hdr[80]);
extern int  cons_verify(const void* block, long len, void* scratch, unsigned cap_slots);

#define MAX_WORKERS 256
#define MAX_BLK     (4u<<20)    /* per-worker block buffer (modern 4MB blocks) */
#define MAX_SCRATCH (16u<<20)   /* per-worker cons_verify scratch */

/* shared results */
static long g_start, g_end;
static unsigned char* g_hash;   /* n*32 : authoritative record hash per block */
static unsigned char* g_prev;   /* n*32 : stored prevhash per block */
static volatile long g_bad=0;   /* atomic count of per-block errors */

struct WArg {
    const char* dir;
    long lo, hi;
    unsigned char* blkbuf;
    unsigned char* scratch;
};

static FILE* open_blk(const char* dir, int fno, char* p, size_t pcap){
    snprintf(p,pcap,"%s/blk%05u.dat",dir,(unsigned)fno);
    return fopen(p,"rb");
}

/* process one contiguous range serially; sets per-block records + atomics */
static int process_range(struct WArg* w){
    char idxp[640]; snprintf(idxp,sizeof idxp,"%s/index.dat",w->dir);
    char blkp[640] __attribute__((aligned(32)));
    unsigned char rec[48] __attribute__((aligned(32)));
    int cur_fno=-1; FILE* blk=NULL;
    FILE* ix=fopen(idxp,"rb");
    if(!ix) return 1;
    for(long h=w->lo; h<=w->hi; h++){
        if(fseek(ix,(long)h*48,SEEK_SET)!=0 || fread(rec,1,48,ix)!=48){ __sync_fetch_and_add(&g_bad,1); break; }
        unsigned len; memcpy(&len,rec+44,4);
        unsigned long long off; memcpy(&off,rec+36,8);
        int fno; memcpy(&fno,rec+32,4);
        const long idx=h-g_start;
        if(len==0 || len>MAX_BLK-64){ __sync_fetch_and_add(&g_bad,1); continue; }
        if(fno!=cur_fno){ if(blk)fclose(blk); blk=open_blk(w->dir,fno,blkp,sizeof blkp); cur_fno=fno; }
        if(!blk){ __sync_fetch_and_add(&g_bad,1); continue; }
        if(fseek(blk,(long)(off+8),SEEK_SET)!=0 || (long)fread(w->blkbuf,1,len,blk)!=(long)len){ __sync_fetch_and_add(&g_bad,1); continue; }

        /* record public fields for the serial chain-link pass */
        /* NOTE: byte-wise copy -- gcc -O2 vectorizes a plain memcpy(...,32)
         * into movdqa loads which fault when the source (blkbuf+4, the block's
         * prevhash field) is not 16-byte aligned. */
        { unsigned char* dst=g_prev+idx*32; const unsigned char* src=w->blkbuf+4;
          for(int k=0;k<32;k++) dst[k]=src[k]; }
        memcpy(g_hash+idx*32, rec, 32);              /* authoritative hash = index record */

        /* hash-match: compute block hash and compare to record */
        unsigned char hh[32] __attribute__((aligned(32)));
        block_hash(hh,w->blkbuf);
        if(memcmp(rec,hh,32)!=0){ __sync_fetch_and_add(&g_bad,1); }

        if(pow_check(w->blkbuf)!=1){ __sync_fetch_and_add(&g_bad,1); }
#ifndef NO_CONS
        if(cons_verify(w->blkbuf,(long)len,w->scratch,(unsigned)(MAX_SCRATCH/32))!=1){ __sync_fetch_and_add(&g_bad,1); }
#endif
    }
    fclose(ix);
    if(blk)fclose(blk);
    return 0;
}

static void* range_thread(void* a){ struct WArg* w=(struct WArg*)a; process_range(w); return NULL; }

int main(int argc,char**argv){
    if(argc<2){ fprintf(stderr,"usage: %s <dir> [start] [end]\n",argv[0]); return 2; }
    const char* dir=argv[1];
    long start_h= argc>2? atol(argv[2]) : 0;
    long end_h  = argc>3? atol(argv[3]) : -1;

    /* ---- machine-adaptive sizing ---- */
    long ncpu=sysconf(_SC_NPROCESSORS_ONLN); if(ncpu<1)ncpu=1; if(ncpu>MAX_WORKERS)ncpu=MAX_WORKERS;
    long l2=sysconf(_SC_LEVEL2_CACHE_SIZE); if(l2<0)l2=0;
    long l3=sysconf(_SC_LEVEL3_CACHE_SIZE); if(l3<0)l3=0;
    long pages=sysconf(_SC_PHYS_PAGES), pgsz=sysconf(_SC_PAGESIZE);
    long mem= pages>0&&pgsz>0? pages*pgsz : 0;

    char idxp[640]; snprintf(idxp,sizeof idxp,"%s/index.dat",dir);
    FILE* ix0=fopen(idxp,"rb"); if(!ix0){ perror("open index.dat"); return 1; }
    fseek(ix0,0,SEEK_END); long tot=ftell(ix0)/48; fclose(ix0);
    if(end_h<0||end_h>tot-1) end_h=tot-1;
    g_start=start_h; g_end=end_h; long n=end_h-start_h+1;
    if(n<1){ fprintf(stderr,"nothing to verify\n"); return 0; }

    /* workers: no more than ncpu, no more than blocks, and bounded by RAM so
     * (workers * (MAX_BLK+MAX_SCRATCH)) stays comfortably under physical memory. */
    long workers=ncpu;
    long per_worker_bytes = MAX_BLK + MAX_SCRATCH + (1u<<20);
    if(mem>0){
        long by_ram = mem/(2*per_worker_bytes);
        if(by_ram<1) by_ram=1;
        if(workers>by_ram) workers=by_ram;
    }
    if(workers>n) workers = n?n:1;
    if(workers<1) workers=1;

    printf("== pverify: %ld workers (ncpu=%ld, L2=%ldK L3=%ldK, ram=%ldMB), heights [%ld,%ld] (%ld blocks) ==\n",
           workers,ncpu,l2/1024,l3/1024, mem/(1024*1024), start_h,end_h,n);

    g_hash=calloc((size_t)n,32); g_prev=calloc((size_t)n,32);
    if(!g_hash||!g_prev){ fprintf(stderr,"alloc fail\n"); return 1; }
    signal(SIGPIPE,SIG_IGN);

    pthread_t th[MAX_WORKERS];
    struct WArg* args=calloc((size_t)workers,sizeof *args);
    long base=n/workers, rem=n%workers, next=start_h;
    long spawned=0;
    for(long w=0; w<workers; w++){
        long cnt=base+(w<rem?1:0);
        args[w].dir=dir; args[w].lo=next; args[w].hi=next+cnt-1;
        args[w].blkbuf=malloc(MAX_BLK); args[w].scratch=malloc(MAX_SCRATCH);
        if(!args[w].blkbuf||!args[w].scratch){ fprintf(stderr,"alloc fail\n"); return 1; }
        next+=cnt;
    }
    for(long w=0; w<workers; w++){
        if(bmc_pthread_create(&th[w],range_thread,&args[w])!=0){ fprintf(stderr,"pthread_create fail\n"); return 1; }
        spawned++;
    }
    for(long w=0; w<spawned; w++) pthread_join(th[w],NULL);

    /* serial chain-link pass */
    long chain_ok=0, chain_bad=0;
    long first_break=-1;
    for(long h=g_start; h<g_end; h++){
        long i=h-g_start;
        if(memcmp(g_prev+(i+1)*32, g_hash+i*32, 32)==0) chain_ok++;
        else { if(chain_bad==0) first_break=h+1; chain_bad++; }
    }
    long expect=n>0?n-1:0;
    int pass = (g_bad==0) && (chain_bad==0);
    printf("== parallel verify summary (heights %ld..%ld, %ld blocks) ==\n", g_start,g_end,n);
    printf("  per-block atomic errors : %ld\n", (long)g_bad);
    printf("  chain-link OK           : %ld/%ld   breaks: %ld\n", chain_ok, expect, chain_bad);
    printf("  first chain problem     : %ld\n", first_break);
    printf("== %s ==\n", pass? "CHAIN VERIFIED (contiguous, valid mainnet blocks)":"CHAIN HAS ERRORS");
    return pass?0:1;
}
