/* tests/bench_ibd_fetch.c -- what a round trip per block costs.
 *
 * A real peer over a real socket, with a fixed one-way delay standing in for
 * the network. The SAME fetcher runs twice: wave=1 is the serial shape
 * node_ibd_blocks_s had (ask for one block, wait for it, ask for the next),
 * wave=0 puts the whole chunk in one getdata. The difference is the round
 * trips, which is the only thing that changes between the two runs.
 *
 * Chunk size is DLC_CHUNK_BLOCKS (40), the size the downloader actually uses.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include "ibd_pipeline.h"

#define NB 40
#define BLKLEN 400000            /* ~400 KB, a mid-chain block */
static unsigned char hdr[NB][80];

static void hash_of(unsigned char out[32], int i){ memset(out, (unsigned char)(0xA0 + i), 32); }
/* the fetcher's externs: a socket peer on the other end of `g_fd` */
static int g_fd;
long p2p_write(int fd, const char* cmd, unsigned cl, const void* pv, unsigned len){
    const unsigned char* p = pv; (void)cl; char h[16]; memset(h,0,16); strncpy(h,cmd,11);
    if (write(fd,h,16)!=16) return -1;
    if (write(fd,&len,4)!=4) return -1;
    unsigned off=0; while(off<len){ long w=write(fd,p+off,len-off); if(w<=0) return -1; off+=(unsigned)w; }
    return (long)len;
}
int p2p_read(int fd, char cmd[12], void* pv, unsigned cap, unsigned* outlen){
    unsigned char* buf = pv;
    char h[16]; unsigned len; unsigned off=0;
    long r=read(fd,h,16);
    if(r!=16) return -1;
    if(read(fd,&len,4)!=4) return -1;
    if(len>cap) return -1;
    while(off<len){ long q=read(fd,buf+off,len-off); if(q<=0) return -1; off+=(unsigned)q; }
    memset(cmd,0,12); memcpy(cmd,h,11); *outlen=len; return (long)len;
}
int hst_get_at(void* hst, unsigned long long i, void* rec){ (void)hst; if(i>=NB) return 0;
    unsigned char* r=rec; memset(r,0,112); memcpy(r,hdr[i],80); hash_of(r+80,(int)i); return 1; }
int cons_verify(const void* b, long l, void* sc, unsigned cap){ (void)b;(void)l;(void)sc;(void)cap; return 1; }
void block_hash(unsigned char o[32], const unsigned char* h){ hash_of(o,h[76]); }
long store_append_shared(void* st,long h,const unsigned char* hs,const unsigned char* raw,unsigned l){
    (void)st;(void)h;(void)hs;(void)raw;(void)l; return h; }

static double now_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1000.0+t.tv_nsec/1e6; }

/* the peer: answers each getdata entry after `delay_us`, in order */
static void peer(int fd, long delay_us){
    static unsigned char blk[BLKLEN];
    for(;;){
        char cmd[12]; static unsigned char rb[1<<16]; unsigned len;
        if (p2p_read(fd, cmd, rb, sizeof rb, &len) <= 0) return;
        if (strncmp(cmd,"getdata",7)) continue;
        unsigned cnt = rb[0];
        if (delay_us) usleep((useconds_t)delay_us);      /* the request's flight time, paid once per message */
        for (unsigned k=0;k<cnt;k++){
            int idx = rb[1+k*36+4] - 0xA0;               /* the hash pattern names the block */
            if (idx<0||idx>=NB) continue;
            memset(blk,0,80); memcpy(blk,hdr[idx],80);
            p2p_write(fd,"block",5,blk,BLKLEN);
        }
    }
}

static double run(long wave, long delay_us){
    int sv[2]; if (socketpair(AF_UNIX,SOCK_STREAM,0,sv)) { perror("socketpair"); exit(2); }
    pid_t p = fork();
    if (p==0){ close(sv[0]); peer(sv[1], delay_us); _exit(0); }
    close(sv[1]); g_fd = sv[0];
    ibd_pipeline_set_wave(wave);
    static unsigned char buf[BLKLEN+1024];
    double t0 = now_ms();
    long r = ibd_fetch_chunk_pipelined(sv[0], NULL, NULL, 500000, NB, buf, (unsigned)sizeof buf, NULL, 0);
    double dt = now_ms()-t0;
    close(sv[0]); kill(p,15); waitpid(p,0,0);
    if (r != NB){ printf("FAIL: fetched %ld of %d\n", r, NB); exit(2); }
    return dt;
}

int main(int argc, char** argv){
    long delay_us = argc>1 ? atol(argv[1]) : 20000;      /* 20 ms: a modest real-peer round trip */
    for (int i=0;i<NB;i++){ memset(hdr[i],0,80); hdr[i][0]=1; if(i) hash_of(hdr[i]+4,i-1); hdr[i][76]=(unsigned char)i; }
    printf("chunk=%d blocks of %d KB, peer delay %ld ms per getdata\n", NB, BLKLEN/1024, delay_us/1000);
    double best_s=1e9, best_p=1e9;
    for (int rep=0; rep<3; rep++){
        double s = run(1, delay_us);  if (s<best_s) best_s=s;
        double q = run(0, delay_us);  if (q<best_p) best_p=q;
    }
    printf("  serial  (1 hash  per getdata): %8.1f ms   %6.1f blk/s  %6.1f MB/s\n",
           best_s, NB*1000.0/best_s, NB*(double)BLKLEN/1048576.0*1000.0/best_s);
    printf("  chunked (%d hashes per getdata): %8.1f ms   %6.1f blk/s  %6.1f MB/s\n",
           NB, best_p, NB*1000.0/best_p, NB*(double)BLKLEN/1048576.0*1000.0/best_p);
    printf("  speedup: %.2fx\n", best_s/best_p);
    return 0;
}
